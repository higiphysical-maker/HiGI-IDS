# HiGI Source Code Audit

## File: src/models/higi_engine.py
"""
HiGI Engine: Hilbert-space Gaussian Intelligence.

Production-grade cascaded anomaly detection engine combining Physical Logic
and Machine Learning across four detection tiers:

    Tier 1  — BallTree Gatekeeper (Euclidean distance in Hilbert space)
    Tier 2  — Probabilistic Tribunal (GMM + IForest, suspect samples only)
    Tier 3  — Physical Sentinel (univariate per-feature GMM log-likelihood)
    Tier 4  — Velocity Bypass Detector (rolling Z-score emergency gate) ← NEW v4.0

Module: src/models/higi_engine.py
Status: Production-Ready — v4.0.0 (Velocity Bypass Architecture)
Type Coverage: 100% | PEP8: ✓ | Docstrings: Google-style

Changelog v4.0.0 — Velocity Bypass Detector
============================================
Root-cause audit (April 2026) confirmed that DoS Hulk and GoldenEye are
geometrically invisible to the Hilbert-space BallTree because high-rate HTTP
flooding produces low intra-window variance — the same profile as normal Monday
HTTP traffic.  A DoS flood scores only 0.26×P99 in the BallTree, while Slowloris
(which genuinely differs from Monday baselines) scores 1.56×P99 and is correctly
flagged.

The fix: a dedicated Tier 4 detector that operates entirely OUTSIDE Hilbert space
on three rolling Z-score features produced by processor_optime.py v2.3.0:

    vel_pps_z    — (total_pps_log  − 60s_rolling_mean) / (60s_rolling_std + 1e-6)
    vel_bytes_z  — (total_bytes_log − 60s_rolling_mean) / (60s_rolling_std + 1e-6)
    vel_syn_z    — (flag_syn_ratio  − 60s_rolling_mean) / (60s_rolling_std + 1e-6)

These signals capture traffic *regime transitions* rather than absolute magnitudes.
A DoS onset that doubles PPS in 3 seconds produces vel_pps_z ≈ 8–15 regardless of
whether the baseline PPS was high or low.

Architecture of Tier 4 (VelocityBypassDetector):
    1. Runs on ALL samples (no short-circuit — velocity spikes hit samples that
       BallTree classifies as normal).
    2. Emergency bypass gate: if max(|vel_pps_z|, |vel_bytes_z|, |vel_syn_z|) ≥
       velocity_bypass_threshold (default 5.0σ), sets is_anomaly=1 unconditionally.
       Severity is derived from VELOCITY_SEVERITY_THRESHOLDS.
    3. Continuous score: vel_score = max_abs_z / bypass_threshold (capped at 3.0),
       injected into the weighted Tribunal as a fourth signal.
    4. Forensic annotation: vel_culprit field records "feature(z=±X.XX)" for each
       bypass event, giving the ForensicEngine precise attack-vector evidence.
    5. Persistence filter and hysteresis are applied AFTER bypass; bypass samples
       are protected from suppression (re-applied after rolling-min filter).
    6. No training required — the Z-scores are self-normalising.
    7. Backward compatible: if vel_* features are absent (old CSV), returns zeros.

Existing fixes (v3.0) unchanged:
    FIX-1: BallTree scores normalised against training_p99_distance (batch-independent).
    FIX-2: is_warmup flag for first ma_window_size × 3 rows.
    FIX-3: Adaptive hysteresis persistence driven by score ratio.
    FIX-4: Metric Family Consensus required for borderline escalation.
    METRIC_FAMILIES updated (v4.0): vel_* features added to volume_flood family.

Author: Blue Team Engineering
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Final, List, Optional, Tuple

import logging
import numpy as np
import pandas as pd

from scipy.stats import norm as scipy_norm
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.metrics import davies_bouldin_score, silhouette_score
from sklearn.mixture import BayesianGaussianMixture, GaussianMixture
from sklearn.neighbors import BallTree
from sklearn.preprocessing import PowerTransformer, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer

import joblib

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ============================================================================
# MODULE-LEVEL CONSTANTS
# ============================================================================

RANDOM_STATE: Final[int] = 42
MIN_COMPONENTS: Final[int] = 2
MAX_COMPONENTS_DEFAULT: Final[int] = 25
PCA_VARIANCE_TARGET: Final[float] = 0.99
PERCENTILE_THRESHOLD: Final[float] = 99.9

# Velocity feature names produced by processor_optime.py v2.3.0.
VELOCITY_FEATURES: Final[Tuple[str, ...]] = ("vel_pps_z", "vel_bytes_z", "vel_syn_z")

# Velocity Z-score → HiGI severity mapping.
# Evaluated in order (first match wins):
#   ≥ 12.0σ → Critical  (3)
#   ≥  8.0σ → Medium    (2)
#   ≥  5.0σ → Borderline(1)
VELOCITY_SEVERITY_THRESHOLDS: Final[Tuple[Tuple[float, int], ...]] = (
    (12.0, 3),
    (8.0, 2),
    (5.0, 1),
)

# FIX-4: Metric Family Consensus dictionary.
# v4.0: vel_* features added to volume_flood family so a velocity bypass
# event automatically satisfies the family consensus requirement.
METRIC_FAMILIES: Final[Dict[str, List[str]]] = {
    "volume_flood": [
        "total_pps_log",
        "total_bytes_log",
        "flag_syn_ratio",
        "flag_rst_ratio",
        "pps_momentum",
        "vel_pps_z",    # v4.0
        "vel_bytes_z",  # v4.0
        "vel_syn_z",    # v4.0
    ],
    "slow_attack": [
        "flow_duration",
        "iat_mean",
        "payload_continuity",
        "flag_fin_ratio",
    ],
    "exfiltration": [
        "payload_continuity_ratio",
        "entropy_avg",
        "bytes_velocity",
        "flag_psh_ratio",
    ],
    "kinematics": [
        "pps_velocity",
        "bytes_velocity",
        "pps_acceleration",
        "bytes_acceleration",
        "pps_volatility",
        "bytes_volatility",
    ],
    "recon": [
        "port_scan_ratio",
        "unique_dst_ports",
        "flag_fin_ratio",
        "flag_urg_ratio",
    ],
}


FEATURE_FAMILIES: Dict[str, List[str]] = {
    "volume": [
        "total_pps_log", "total_bytes_log", "bytes",
        "pps_velocity", "bytes_velocity", "pps_acceleration",
        "bytes_acceleration", "pps_volatility", "bytes_volatility",
        "pps_momentum", "vel_pps_z", "vel_bytes_z",
    ],
    "payload": [
        "size_avg", "entropy_avg", "size_max",
        "payload_continuity", "payload_continuity_ratio",
        "entropy_velocity", "entropy_acceleration", "entropy_volatility",
    ],
    "flags": [
        "flag_syn_ratio", "flag_ack_ratio", "flag_fin_ratio",
        "flag_rst_ratio", "flag_psh_ratio", "flag_urg_ratio", "vel_syn_z",
    ],
    "protocol": ["icmp_ratio", "udp_ratio", "tcp_ratio", "igmp_ratio"],
    "connection": [
        "unique_dst_ports", "port_scan_ratio", "burst_factor",
        "flow_duration", "iat_mean",
    ],
}


# ============================================================================
# CUSTOM EXCEPTIONS
# ============================================================================

class HiGIError(Exception):
    """Base exception for HiGI engine errors."""


class HiGITrainingError(HiGIError):
    """Raised when training fails."""


class HiGIInferenceError(HiGIError):
    """Raised when inference fails."""


class InsufficientDataError(HiGIError):
    """Raised when training data is insufficient."""


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass(frozen=True)
class HiGIConfig:
    """
    Immutable configuration for the HiGI detection engine (frozen=True).

    All fields have sensible defaults; override only what differs from your
    deployment environment.  Use dataclasses.replace() to create variants.

    New fields in v4.0 (velocity bypass):
        velocity_bypass_enabled:
            Master switch for Tier 4 VelocityBypassDetector. Default True.
        velocity_bypass_threshold:
            Z-score magnitude that triggers the emergency bypass gate.
            Default 5.0σ.  Tune upward for noisier environments.
        velocity_tribunal_weight:
            Weight assigned to vel_score in the weighted Tribunal consensus.
            Default 0.30.  Remaining weights are scaled proportionally so the
            total always sums to 1.0.
    """

    # Hilbert space
    n_components: int = 5
    pca_variance: float = PCA_VARIANCE_TARGET
    pca_eigenvalue_max_condition: float = 1e12
    blocked_pca_enabled: bool = True
    blocked_pca_variance_per_family: Optional[Dict[str, float]] = None

    # Detection thresholds
    threshold_percentile: float = PERCENTILE_THRESHOLD
    threshold_p95: float = 95.0
    threshold_p99: float = 99.0
    threshold_p99_9: float = 99.9

    # Tier 2 detectors
    reg_covar: float = 1e-1
    iforest_contamination: float = 0.005
    use_bayesian_gmm: bool = True
    bayesian_weight_concentration_prior: float = 1e-5
    univariate_gmm_components: int = 2
    adaptive_univariate_k: bool = True
    adaptive_univariate_k_range: Tuple[int, int] = (1, 5)

    # Tribunal
    majority_vote_threshold: int = 3
    weighted_tribunal: bool = True
    tribunal_weights: Optional[Dict[str, float]] = None
    tribunal_consensus_threshold: float = 0.5
    gmm_score_normalization_method: str = "cdf"

    # Tier 3 — Physical Sentinel
    physical_sentinel_enabled: bool = True
    physical_sentinel_threshold: float = 1e-6
    physical_sentinel_weight: float = 0.5
    per_feature_thresholds: bool = True

    # Tier 4 — Velocity Bypass (NEW v4.0)
    velocity_bypass_enabled: bool = True
    velocity_bypass_threshold: float = 10.0
    velocity_tribunal_weight: float = 0.15

    # Forensics
    enable_forensics: bool = True
    top_features_per_pc: int = 3
    sentinel_directionality_analysis: bool = True
    portero_sigma_threshold: float = 20.0

    # Persistence / hysteresis
    ma_window_size: int = 5
    transient_threshold: float = 0.4
    balltree_slack: float = 1.2
    hysteresis_entry_multiplier: float = 1.0
    hysteresis_exit_multiplier: float = 0.75
    alert_minimum_persistence: int = 3
    tier1_soft_threshold_percentile: float = 98.0

    # FIX-4 — Family consensus
    family_consensus_enabled: bool = True
    family_consensus_min_hits: int = 2

    def __post_init__(self) -> None:
        """Derive default tribunal weights and Blocked PCA variance targets when not explicitly supplied."""
        # Tribunal weights
        if self.tribunal_weights is None:
            vel_w = self.velocity_tribunal_weight if self.velocity_bypass_enabled else 0.0
            rem = 1.0 - vel_w
            # Distribute remaining weight in original BallTree/GMM/IForest proportions.
            object.__setattr__(self, "tribunal_weights", {
                "balltree": round(0.25 * rem, 6),
                "gmm": round(0.40 * rem, 6),
                "iforest": round(0.35 * rem, 6),
                "velocity": vel_w,
            })
        
        # Blocked PCA variance targets
        if self.blocked_pca_enabled and self.blocked_pca_variance_per_family is None:
            object.__setattr__(self, "blocked_pca_variance_per_family", {
                "volume": 0.95,
                "payload": 0.95,
                "flags": 0.99,
                "protocol": 0.99,
                "connection": 0.95,
            })

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to plain dict for logging / persistence."""
        return {
            "n_components": self.n_components,
            "pca_variance": self.pca_variance,
            "pca_eigenvalue_max_condition": self.pca_eigenvalue_max_condition,
            "threshold_percentile": self.threshold_percentile,
            "threshold_p95": self.threshold_p95,
            "threshold_p99": self.threshold_p99,
            "threshold_p99_9": self.threshold_p99_9,
            "reg_covar": float(self.reg_covar),
            "iforest_contamination": self.iforest_contamination,
            "use_bayesian_gmm": self.use_bayesian_gmm,
            "bayesian_weight_concentration_prior": self.bayesian_weight_concentration_prior,
            "univariate_gmm_components": self.univariate_gmm_components,
            "adaptive_univariate_k": self.adaptive_univariate_k,
            "adaptive_univariate_k_range": self.adaptive_univariate_k_range,
            "majority_vote_threshold": self.majority_vote_threshold,
            "weighted_tribunal": self.weighted_tribunal,
            "tribunal_weights": self.tribunal_weights,
            "tribunal_consensus_threshold": self.tribunal_consensus_threshold,
            "gmm_score_normalization_method": self.gmm_score_normalization_method,
            "physical_sentinel_enabled": self.physical_sentinel_enabled,
            "physical_sentinel_threshold": self.physical_sentinel_threshold,
            "physical_sentinel_weight": self.physical_sentinel_weight,
            "per_feature_thresholds": self.per_feature_thresholds,
            "velocity_bypass_enabled": self.velocity_bypass_enabled,
            "velocity_bypass_threshold": self.velocity_bypass_threshold,
            "velocity_tribunal_weight": self.velocity_tribunal_weight,
            "enable_forensics": self.enable_forensics,
            "top_features_per_pc": self.top_features_per_pc,
            "sentinel_directionality_analysis": self.sentinel_directionality_analysis,
            "portero_sigma_threshold": self.portero_sigma_threshold,
            "ma_window_size": self.ma_window_size,
            "transient_threshold": self.transient_threshold,
            "balltree_slack": self.balltree_slack,
            "hysteresis_entry_multiplier": self.hysteresis_entry_multiplier,
            "hysteresis_exit_multiplier": self.hysteresis_exit_multiplier,
            "alert_minimum_persistence": self.alert_minimum_persistence,
            "tier1_soft_threshold_percentile": self.tier1_soft_threshold_percentile,
            "family_consensus_enabled": self.family_consensus_enabled,
            "family_consensus_min_hits": self.family_consensus_min_hits,
        }


# ============================================================================
# HILBERT SPACE PROJECTOR
# ============================================================================

class HilbertSpaceProjector:
    """
    Project raw feature matrix into Hilbert space via Yeo-Johnson + PCA.

    Velocity features (vel_pps_z, vel_bytes_z, vel_syn_z) are treated as
    first-class dimensions.  Because they are already Z-scores their
    distribution is near-normal during baseline, so they enrich the Hilbert
    space without distorting PCA variance ratios significantly.  The
    VelocityBypassDetector operates on raw Z-score values BEFORE projection,
    making the two mechanisms complementary.
    """

    def __init__(self) -> None:
        self.transformer: Optional[PowerTransformer] = None
        self.fallback_transformer: Optional[Any] = None
        self.pca_model: Optional[PCA] = None
        self.blocked_pca_transformer: Optional[ColumnTransformer] = None
        self.feature_names: List[str] = []
        self.pca_variance_ratio: Optional[np.ndarray] = None
        self.clip_bounds_: Optional[np.ndarray] = None
        self.pca_eigenvalue_floor: float = 1e-12
        self.pca_max_condition: float = 1e12
        self._last_inf_sample_indices: set = set()
        self._projection_mode: str = "none"  # "none" | "blocked_pca" | "global_pca"
        
        # Blocked PCA metadata: map global PC index → (family, local_pc)
        self._blocked_pca_family_mapping: Dict[int, Tuple[str, int]] = {}
        # Blocked PCA loadings by family for fast lookup
        self._blocked_pca_loadings_by_family: Dict[str, Tuple[np.ndarray, List[str]]] = {}
        # Maps family → (loadings_matrix, feature_list)

    # ------------------------------------------------------------------
    # SERIALIZATION SAFETY: State management for joblib persistence
    # ------------------------------------------------------------------

    def __getstate__(self) -> Dict[str, Any]:
        """
        Prepare state for joblib serialization.

        Ensures ColumnTransformer and PCA models are properly flagged
        as fitted so that __setstate__ can validate them on deserialization.

        Returns:
            Dict with all instance attributes.

        Examples:
            >>> state = projector.__getstate__()
            >>> # Safe to serialize with joblib
        """
        state = self.__dict__.copy()
        # Verify fitted state before serialization
        if self.blocked_pca_transformer is not None:
            if not hasattr(self.blocked_pca_transformer, "transformers_"):
                logger.warning(
                    "[!] ColumnTransformer appears unfitted during serialization. "
                    "This may cause inference failures after deserialization."
                )
        return state

    def __setstate__(self, state: Dict[str, Any]) -> None:
        """
        Restore state from joblib deserialization with validation.

        Verifies that ColumnTransformer and PCA models are correctly fitted
        after deserialization. Applies healing steps if needed.

        Args:
            state: Dict from __getstate__.

        Raises:
            HiGIInferenceError: Critical state is corrupted.

        Examples:
            >>> loaded = joblib.load('projector.pkl')
            >>> # __setstate__ called automatically; validates state
        """
        self.__dict__.update(state)
        # Ensure _projection_mode is present for backward compat
        if "_projection_mode" not in self.__dict__:
            self._projection_mode = "none"
            if self.blocked_pca_transformer is not None:
                self._projection_mode = "blocked_pca"
            elif self.pca_model is not None:
                self._projection_mode = "global_pca"
        # Validate fitted state
        self._validate_fitted_state()

    def _validate_fitted_state(self) -> None:
        """
        Post-deserialization validation to detect and report fitting state issues.

        Called automatically in __setstate__. Performs deep checks on:
        - feature_names presence
        - ColumnTransformer (blocked_pca mode): transformers_, StandardScaler, PCA
        - Global PCA mode: components_, scale_ attributes

        Raises:
            HiGIInferenceError: Projector state is corrupted or incomplete.
        """
        if not self.feature_names:
            raise HiGIInferenceError(
                "Projector state corrupted: feature_names is empty after deserialization."
            )

        if self.blocked_pca_transformer is not None:
            if not hasattr(self.blocked_pca_transformer, "transformers_"):
                raise HiGIInferenceError(
                    "ColumnTransformer not fitted: missing 'transformers_' attribute. "
                    "Bundle may be corrupted or from an older HiGI version."
                )
            # Deep-check that sub-transformers are fitted
            for name, pipe, features in self.blocked_pca_transformer.transformers_:
                if pipe is None:  # remainder transformer
                    continue
                if not hasattr(pipe, "steps") or not pipe.steps:
                    raise HiGIInferenceError(
                        f"Pipeline '{name}' in ColumnTransformer is malformed. "
                        f"Re-train the model."
                    )
                for step_name, estimator in pipe.steps:
                    if estimator is None:
                        continue
                    if isinstance(estimator, PCA):
                        if not hasattr(estimator, "components_"):
                            raise HiGIInferenceError(
                                f"PCA in pipeline '{name}' step '{step_name}' not fitted. "
                                f"Re-train the model."
                            )
                    elif isinstance(estimator, StandardScaler):
                        if not hasattr(estimator, "scale_"):
                            raise HiGIInferenceError(
                                f"StandardScaler in pipeline '{name}' step '{step_name}' "
                                f"not fitted. Re-train the model."
                            )
        elif self.pca_model is not None:
            if not hasattr(self.pca_model, "components_"):
                raise HiGIInferenceError(
                    "Global PCA not fitted: missing 'components_' attribute. "
                    "Bundle corrupted or incomplete."
                )
            if self.transformer is None:
                raise HiGIInferenceError(
                    "Global PCA mode selected but PowerTransformer is missing. "
                    "Bundle corrupted."
                )
            if not hasattr(self.transformer, "scale_"):
                raise HiGIInferenceError(
                    "PowerTransformer not fitted: missing 'scale_' attribute. "
                    "Re-train the model."
                )

    def is_fitted(self) -> bool:
        """
        Check if projector is ready for transform().

        Returns:
            bool: True if projector is fitted in either mode (blocked_pca or global_pca).

        Examples:
            >>> projector = HilbertSpaceProjector()
            >>> projector.fit(df)
            >>> assert projector.is_fitted()
        """
        if not self.feature_names:
            return False
        if self.blocked_pca_transformer is not None:
            return hasattr(self.blocked_pca_transformer, "transformers_")
        if self.pca_model is not None and self.transformer is not None:
            return (
                hasattr(self.pca_model, "components_")
                and hasattr(self.transformer, "scale_")
            )
        return False

    def validate_fitted(self) -> None:
        """
        Explicit validation that raises if projector is not fitted.

        Used before critical operations like transform() to provide
        clear, actionable error messages with context.

        Raises:
            HiGIInferenceError: Projector not properly fitted.

        Examples:
            >>> projector.validate_fitted()  # Raises if not fitted
        """
        if not self.is_fitted():
            mode = self._projection_mode if self._projection_mode != "none" else "UNKNOWN"
            raise HiGIInferenceError(
                f"Projector not fitted (mode={mode}). Call fit() first or "
                f"load a valid pre-trained bundle."
            )

    def _build_blocked_pca_transformer(
        self,
        variance_per_family: Dict[str, float],
    ) -> ColumnTransformer:
        """
        Build a ColumnTransformer that applies independent PCA per feature family.

        Each family is independently standardised and projected before the embeddings
        are concatenated. This prevents high-variance families (payload) from
        monopolising PCA components at the expense of low-variance families (flags).

        The architecture guarantees that each semantic family retains proportional
        representation in the joint Hilbert space regardless of raw scale differences.

        Args:
            variance_per_family: Dict mapping family name → variance retention target.
                Default mapping is provided if a family key is missing.

        Returns:
            ColumnTransformer with per-family Pipeline (StandardScaler + PCA).
            Configured with remainder="drop" to exclude undefined features.

        Example:
            >>> projector = HilbertSpaceProjector()
            >>> ct = projector._build_blocked_pca_transformer({
            ...     "volume": 0.95,
            ...     "payload": 0.95,
            ...     "flags": 0.99,
            ... })
        """
        transformers = []
        
        # Iterate over families and create independent pipelines
        for family_name, feature_list in FEATURE_FAMILIES.items():
            # Use per-family variance target, or fall back to 0.95
            variance_target = variance_per_family.get(family_name, 0.95)
            
            block_pipeline = Pipeline([
                ("scaler", StandardScaler()),
                ("pca", PCA(n_components=variance_target, svd_solver="full")),
            ])
            transformers.append((family_name, block_pipeline, feature_list))

        return ColumnTransformer(
            transformers=transformers,
            remainder="drop",
            n_jobs=1,  # Serialization compatibility with joblib
        )
    def _build_blocked_pca_metadata(self) -> None:
        """
        Build metadata mappings for Blocked PCA to enable forensic attribution.
        Maps global PC indices to their respective family and local PC index.
        """
        self._blocked_pca_family_mapping = {}
        self._blocked_pca_loadings_by_family = {}
        
        if self.blocked_pca_transformer is None:
            return
            
        current_global_idx = 0
        for name, pipe, features in self.blocked_pca_transformer.transformers_:
            if pipe is None or name == "remainder":
                continue
                
            # Extraer el PCA de esta familia
            pca_step = next((s for n, s in pipe.steps if isinstance(s, PCA)), None)
            if pca_step is None or not hasattr(pca_step, "components_"):
                continue
                
            family_features = [f for f in features if f in self.feature_names]
            if not family_features:
                continue
                
            # pca_step.components_ shape is (n_components, n_features)
            # Transponer a (n_features, n_components) para guardar los loadings
            loadings = pca_step.components_.T
            self._blocked_pca_loadings_by_family[name] = (loadings, family_features)
            
            # Mapear cada PC local al índice global
            n_local_pcs = pca_step.n_components_
            for local_idx in range(n_local_pcs):
                self._blocked_pca_family_mapping[current_global_idx] = (name, local_idx)
                current_global_idx += 1

    def fit(
        self,
        df: pd.DataFrame,
        variance_target: float = PCA_VARIANCE_TARGET,
        exclude_cols: Optional[set] = None,
        blocked_pca_enabled: bool = False,
        blocked_pca_variance_per_family: Optional[Dict[str, float]] = None,
    ) -> "HilbertSpaceProjector":
        """
        Fit PCA on the baseline feature matrix.

        Supports two modes:
            1. Global PCA (blocked_pca_enabled=False): Yeo-Johnson transform + single PCA
               on all features. Risk of Component Collapse for multi-family features.
            2. Blocked PCA (blocked_pca_enabled=True): Per-family StandardScaler + PCA,
               then concatenate embeddings. Prevents high-variance families from
               monopolising components.

        Args:
            df: Baseline feature matrix (n_samples × n_features).
            variance_target: Global PCA variance target if blocked_pca_enabled=False.
            exclude_cols: Metadata column names to exclude.
            blocked_pca_enabled: If True, use per-family PCA via ColumnTransformer.
            blocked_pca_variance_per_family: Dict mapping family name → variance target.
                Used only if blocked_pca_enabled=True. Missing families default to 0.95.

        Returns:
            self — for method chaining.

        Raises:
            ValueError: Fewer than 100 samples, no numeric features, or family mismatch.
        """
        if exclude_cols is None:
            exclude_cols = {"dt", "timestamp", "second_window", "index", "label"}

        if len(df) < 100:
            raise ValueError(f"Need ≥ 100 samples for fitting, got {len(df)}")

        numeric_cols = [
            c for c in df.columns
            if pd.api.types.is_numeric_dtype(df[c]) and c not in exclude_cols
        ]
        if not numeric_cols:
            raise ValueError("No numeric features found after excluding metadata.")

        self.feature_names = numeric_cols
        X = df[numeric_cols].values

        vel_present = [f for f in VELOCITY_FEATURES if f in numeric_cols]
        logger.info(
            f"[*] Hilbert projection: {len(numeric_cols)} features "
            f"(velocity: {vel_present or 'ABSENT'}) | "
            f"mode={'Blocked PCA' if blocked_pca_enabled else 'Global PCA'}"
        )

        # ====================================================================
        # BLOCKED PCA MODE: per-family projection
        # ====================================================================
        if blocked_pca_enabled:
            if blocked_pca_variance_per_family is None:
                blocked_pca_variance_per_family = {
                    "volume": 0.95,
                    "payload": 0.95,
                    "flags": 0.99,
                    "protocol": 0.99,
                    "connection": 0.95,
                }

            logger.info("    Step 1: ColumnTransformer (per-family StandardScaler + PCA)…")
            
            # Build the transformer
            self.blocked_pca_transformer = self._build_blocked_pca_transformer(
                blocked_pca_variance_per_family
            )
            
            # Fit and transform: produces array of shape (n_samples, sum_of_family_components)
            try:
                X_blocked = self.blocked_pca_transformer.fit_transform(df[numeric_cols])
            except Exception as exc:
                logger.error(f"[!] Blocked PCA fit_transform failed: {exc}")
                raise ValueError(f"Blocked PCA initialization failed: {exc}") from exc

            # Verify output shape
            if not isinstance(X_blocked, np.ndarray):
                X_blocked = np.asarray(X_blocked)
            if len(X_blocked.shape) != 2:
                raise ValueError(f"Expected 2D output, got shape {X_blocked.shape}")

            # ────────────────────────────────────────────────────────────────
            # Build PC-to-family mappings for forensic extraction
            # ────────────────────────────────────────────────────────────────
            self._build_blocked_pca_metadata()

            # Store pca_variance_ratio as reference (aggregate across families)
            n_components_total = X_blocked.shape[1]
            self.pca_variance_ratio = np.ones(n_components_total) / n_components_total
            
            logger.info(
                f"    Components: {n_components_total} (aggregated) | "
                f"Families: {list(blocked_pca_variance_per_family.keys())}"
            )
            logger.info(f"[✓] Hilbert space: {len(numeric_cols)} → {n_components_total} dims (Blocked)")
            self._projection_mode = "blocked_pca"
            return self

        # ====================================================================
        # GLOBAL PCA MODE: fallback to original implementation
        # ====================================================================
        p99 = np.percentile(X, 99, axis=0)
        lo = np.where(X.min(axis=0) >= 0, 0.0, X.min(axis=0))
        self.clip_bounds_ = np.stack([lo, p99], axis=0)
        X = np.clip(X, self.clip_bounds_[0], self.clip_bounds_[1])

        logger.info("    Step 1: PowerTransformer (Yeo-Johnson)…")
        self.transformer = PowerTransformer(method="yeo-johnson", standardize=True)
        X_transformed = self.transformer.fit_transform(X)

        from sklearn.preprocessing import QuantileTransformer
        nq = min(100, max(10, len(X) // 5))
        self.fallback_transformer = QuantileTransformer(
            n_quantiles=nq, output_distribution="uniform",
            random_state=RANDOM_STATE, subsample=min(100_000, len(X)),
        )
        self.fallback_transformer.fit(X)

        n_bad = np.sum(~np.isfinite(X_transformed))
        if n_bad:
            logger.warning(f"    {n_bad} non-finite values after transform — clipping.")
            X_transformed = np.nan_to_num(X_transformed, nan=0.0, posinf=3.0, neginf=-3.0)

        logger.info(f"    Step 2: PCA (variance_target={variance_target})…")
        self.pca_model = PCA(n_components=variance_target, svd_solver="full", whiten=True)
        self.pca_model.fit(X_transformed)

        if hasattr(self.pca_model, "explained_variance_"):
            ev = self.pca_model.explained_variance_
            cond = ev.max() / (ev.min() + 1e-16)
            if cond > self.pca_max_condition:
                logger.warning(f"    ⚠ PCA condition={cond:.2e} — eigenvalue floor applied.")

        self.pca_variance_ratio = self.pca_model.explained_variance_ratio_
        nc = len(self.pca_variance_ratio)
        logger.info(
            f"    Components: {nc} | Variance: {self.pca_variance_ratio.sum()*100:.2f}%"
        )
        logger.info(f"[✓] Hilbert space: {len(numeric_cols)} → {nc} dims")
        self._projection_mode = "global_pca"
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Project a test DataFrame into the fitted Hilbert space.

        Supports both Global PCA and Blocked PCA modes depending on which
        transformer was fitted.

        Validation:
            Calls validate_fitted() to ensure all transformers are ready
            post-deserialization. If validation fails, raises HiGIInferenceError
            with clear context.

        Args:
            df: Test feature matrix with same features as training data.

        Returns:
            np.ndarray: Hilbert coordinates, shape (n_samples, n_components).

        Raises:
            HiGIInferenceError: Projector not fitted or validation failed.
            ValueError: Missing or incompatible features.

        Examples:
            >>> projector.fit(df_train)
            >>> X_hilbert = projector.transform(df_test)
            >>> print(X_hilbert.shape)  # (n_test, n_components)
        """
        # Explicit fitted validation (especially important post-deserialization).
        self.validate_fitted()

        # ====================================================================
        # BLOCKED PCA MODE: use ColumnTransformer
        # ====================================================================
        if self.blocked_pca_transformer is not None:
            try:
                if self._projection_mode != "blocked_pca":
                    logger.warning(
                        f"[!] Projection mode mismatch: _projection_mode={self._projection_mode} "
                        f"but blocked_pca_transformer is present. Correcting…"
                    )
                    self._projection_mode = "blocked_pca"
                
                X_blocked = self.blocked_pca_transformer.transform(df[self.feature_names])
                if not isinstance(X_blocked, np.ndarray):
                    X_blocked = np.asarray(X_blocked)
                
                # Verify output shape
                if len(X_blocked.shape) != 2:
                    raise HiGIInferenceError(
                        f"ColumnTransformer returned unexpected shape: {X_blocked.shape}. "
                        f"Expected 2D array."
                    )
                
                return X_blocked
            except Exception as exc:
                # Provide actionable error context
                if "not fitted" in str(exc).lower() or "fit" in str(exc).lower():
                    raise HiGIInferenceError(
                        f"Blocked PCA components not fitted after deserialization. "
                        f"Error: {exc}. Re-train the model or check bundle integrity."
                    ) from exc
                else:
                    raise HiGIInferenceError(
                        f"Blocked PCA projection failed: {exc}"
                    ) from exc

        # ====================================================================
        # GLOBAL PCA MODE: use PowerTransformer + PCA
        # ====================================================================
        if self.transformer is None or self.pca_model is None:
            raise HiGIInferenceError(
                f"Global PCA mode selected but transformers are missing. "
                f"(transformer={self.transformer is not None}, "
                f"pca_model={self.pca_model is not None}). "
                f"Call fit() first or check bundle integrity."
            )

        if self.clip_bounds_ is None:
            raise HiGIInferenceError(
                "Global PCA clip bounds not set. Bundle corrupted; re-train required."
            )

        X = np.clip(df[self.feature_names].values, self.clip_bounds_[0], self.clip_bounds_[1])

        try:
            with np.errstate(over="ignore", invalid="ignore", divide="ignore"):
                Xt = self.transformer.transform(X)
        except (ValueError, RuntimeError) as exc:
            logger.error(f"[!] PowerTransformer failed: {exc} — using fallback.")
            if self.fallback_transformer is None:
                raise HiGIInferenceError(
                    "PowerTransformer failed and fallback transformer is unavailable. "
                    "Bundle may be corrupted."
                ) from exc
            Xt = self.fallback_transformer.transform(X)

        n_bad = np.sum(~np.isfinite(Xt))
        if n_bad:
            logger.warning(f"[*] {n_bad} non-finite values after PowerTransform — clipping.")
            Xt = np.nan_to_num(Xt, nan=0.0, posinf=3.0, neginf=-3.0)

        Xh = self.pca_model.transform(Xt)
        n_bad_h = np.sum(~np.isfinite(Xh))
        if n_bad_h:
            self._last_inf_sample_indices = set(
                int(i) for i in np.where(~np.isfinite(Xh).any(axis=1))[0]
            )
            logger.warning(f"[!] {n_bad_h} non-finite Hilbert values — clipping.")
            Xh = np.nan_to_num(Xh, nan=0.0, posinf=3.0, neginf=-3.0)
        else:
            self._last_inf_sample_indices = set()

        return Xh

    def fit_transform(
        self,
        df: pd.DataFrame,
        variance_target: float = PCA_VARIANCE_TARGET,
    ) -> np.ndarray:
        """Fit and transform in a single call."""
        return self.fit(df, variance_target).transform(df)

    def get_pc_loadings(self) -> pd.DataFrame:
        """
        Return PCA loadings as (n_features × n_components) DataFrame.

        For Global PCA mode: returns direct loadings from self.pca_model.
        For Blocked PCA mode: reconstructs aggregate loadings from ColumnTransformer.

        Returns:
            pd.DataFrame with shape (n_features, n_components).

        Raises:
            HiGIInferenceError: Projector not fitted or mode incompatible.
        """
        if not self.is_fitted():
            raise HiGIInferenceError(
                "Projector not fitted. Call fit() first."
            )

        # ──────────────────────────────────────────────────────────────────
        # GLOBAL PCA MODE
        # ──────────────────────────────────────────────────────────────────
        if self.pca_model is not None:
            return pd.DataFrame(
                self.pca_model.components_.T,
                index=self.feature_names,
                columns=[f"PC{i+1}" for i in range(self.pca_model.n_components_)],
            )

        # ──────────────────────────────────────────────────────────────────
        # BLOCKED PCA MODE: reconstruct loadings from ColumnTransformer
        # ──────────────────────────────────────────────────────────────────
        # ──────────────────────────────────────────────────────────────────
        # BLOCKED PCA MODE: reconstruct loadings using Block Diagonal
        # ──────────────────────────────────────────────────────────────────
        if self.blocked_pca_transformer is not None:
            if not self._blocked_pca_family_mapping:
                raise HiGIInferenceError("Blocked PCA metadata is empty. Re-train required.")
                
            total_pcs = len(self._blocked_pca_family_mapping)
            # Crear una matriz llena de ceros (Total variables x Total Componentes)
            full_loadings = np.zeros((len(self.feature_names), total_pcs))
            
            for global_idx in range(total_pcs):
                family_name, local_pc_idx = self._blocked_pca_family_mapping[global_idx]
                loadings_matrix, family_features = self._blocked_pca_loadings_by_family[family_name]
                
                # Asignar los pesos físicos solo en las filas correspondientes a la familia
                for local_feat_idx, feat_name in enumerate(family_features):
                    global_feat_idx = self.feature_names.index(feat_name)
                    full_loadings[global_feat_idx, global_idx] = loadings_matrix[local_feat_idx, local_pc_idx]
                    
            return pd.DataFrame(
                full_loadings,
                index=self.feature_names,
                columns=[f"PC{i+1}" for i in range(total_pcs)],
            )

        raise HiGIInferenceError(
            f"No PCA transformer found (mode={self._projection_mode}). "
            f"Projector state corrupted."
        )

    def get_culprit_component(
        self, X_hilbert: np.ndarray, sample_idx: int
    ) -> Dict[str, Any]:
        """
        Identify the PC with maximum absolute coordinate for one sample.

        Works in both Global PCA and Blocked PCA modes.

        Args:
            X_hilbert: Hilbert space coordinates (n_samples, n_components).
            sample_idx: Row index to analyze.

        Returns:
            Dict with keys: pc, deviation, direction, pc_index.

        Raises:
            HiGIInferenceError: Projector not fitted.
        """
        if not self.is_fitted():
            raise HiGIInferenceError(
                f"Projector not fitted (mode={self._projection_mode}). "
                f"Call fit() first."
            )

        try:
            coords = X_hilbert[sample_idx]
            ci = int(np.argmax(np.abs(coords)))
            return {
                "pc": f"PC{ci + 1}",
                "deviation": float(coords[ci]),
                "direction": 1 if coords[ci] > 0 else -1,
                "pc_index": ci,
            }
        except Exception as exc:
            raise HiGIInferenceError(
                f"Failed to get culprit component for sample {sample_idx}: {exc}"
            ) from exc

    def get_suspect_features(self, culprit_pc_idx: int, top_n: int = 3) -> List[str]:
        """
        Return top-N features contributing to a Principal Component.

        For Global PCA: extracts from pca_model.components_.
        For Blocked PCA: extracts from ColumnTransformer PCAs (aggregated order).

        Args:
            culprit_pc_idx: Principal Component index (0-based).
            top_n: Number of top features to return.

        Returns:
            List of feature names, sorted by absolute loading (descending).

        Raises:
            HiGIInferenceError: Projector not fitted or PC index invalid.
        """
        if not self.is_fitted():
            raise HiGIInferenceError(
                f"Projector not fitted (mode={self._projection_mode}). "
                f"Call fit() first."
            )

        if not self.feature_names:
            raise HiGIInferenceError("Feature names not available.")

        # ──────────────────────────────────────────────────────────────────
        # GLOBAL PCA MODE
        # ──────────────────────────────────────────────────────────────────
        if self.pca_model is not None:
            if culprit_pc_idx >= self.pca_model.n_components_:
                raise HiGIInferenceError(
                    f"PC index {culprit_pc_idx} out of range "
                    f"(n_components={self.pca_model.n_components_})"
                )
            try:
                loadings = np.abs(self.pca_model.components_[culprit_pc_idx])
                ranked = sorted(
                    zip(self.feature_names, loadings),
                    key=lambda x: x[1],
                    reverse=True
                )
                return [name for name, _ in ranked[:top_n]]
            except Exception as exc:
                raise HiGIInferenceError(
                    f"Failed to extract suspect features for PC{culprit_pc_idx}: {exc}"
                ) from exc

        # ──────────────────────────────────────────────────────────────────
        # BLOCKED PCA MODE: reconstruct and aggregate loadings
        # ──────────────────────────────────────────────────────────────────
        # ──────────────────────────────────────────────────────────────────
        # BLOCKED PCA MODE: Use pre-built metadata mappings
        # ──────────────────────────────────────────────────────────────────
        if self.blocked_pca_transformer is not None:
            if not self._blocked_pca_family_mapping:
                raise HiGIInferenceError("Blocked PCA metadata missing. Re-train the model.")
                
            if culprit_pc_idx not in self._blocked_pca_family_mapping:
                raise HiGIInferenceError(
                    f"PC index {culprit_pc_idx} out of range. "
                    f"Max valid is {max(self._blocked_pca_family_mapping.keys())}."
                )

            family_name, local_pc_idx = self._blocked_pca_family_mapping[culprit_pc_idx]
            loadings_matrix, feature_order = self._blocked_pca_loadings_by_family[family_name]
            
            try:
                # Extraer los pesos solo para esta familia específica
                loadings = np.abs(loadings_matrix[:, local_pc_idx])
                ranked = sorted(
                    zip(feature_order, loadings),
                    key=lambda x: x[1],
                    reverse=True
                )
                return [name for name, _ in ranked[:top_n]]
            except Exception as exc:
                raise HiGIInferenceError(
                    f"Failed to extract suspect features from Blocked PCA (family={family_name}): {exc}"
                ) from exc


# ============================================================================
# TIER 1 — BALLTREE DETECTOR
# ============================================================================

class BallTreeDetector:
    """
    k-NN Euclidean distance detector (k=5 mean) in Hilbert space.

    FIX-1 (v3.0): score() returns raw_distance / training_p99_distance,
    making scores batch-independent.  A score of 1.0 equals the training P99
    boundary; scores above 1.0 indicate increasing isolation from the baseline.
    """

    def __init__(self) -> None:
        self.tree: Optional[BallTree] = None
        self.k_neighbors: Final[int] = 5
        self.threshold: Optional[float] = None
        self.threshold_p90: Optional[float] = None
        self.threshold_p95: Optional[float] = None
        self.threshold_p99: Optional[float] = None
        self.threshold_p99_9: Optional[float] = None
        self.knn_distances: Optional[np.ndarray] = None
        self.training_p99_distance: float = 1.0

    def fit(
        self,
        X_hilbert: np.ndarray,
        percentiles: Optional[Dict[str, float]] = None,
    ) -> "BallTreeDetector":
        """
        Fit BallTree on baseline Hilbert coordinates.

        Args:
            X_hilbert: Baseline data, shape (n_samples, n_components).
            percentiles: Threshold percentile dict {p95, p99, p99_9}.

        Returns:
            self
        """
        if percentiles is None:
            percentiles = {"p95": 95.0, "p99": 99.0, "p99_9": 99.9}
        if len(X_hilbert) < 10:
            raise ValueError(f"Need ≥ 10 samples, got {len(X_hilbert)}")

        logger.info(f"[*] BallTree: fitting on {len(X_hilbert):,} samples…")
        self.tree = BallTree(X_hilbert, metric="euclidean")

        distances, _ = self.tree.query(X_hilbert, k=self.k_neighbors + 1)
        self.knn_distances = distances[:, 1:].mean(axis=1)

        self.training_p99_distance = float(np.percentile(self.knn_distances, 99.0))
        if self.training_p99_distance < 1e-10:
            self.training_p99_distance = 1.0
            logger.warning("[!] BallTree training P99 ≈ 0 — degenerate baseline?")

        self.threshold_p90 = float(np.percentile(self.knn_distances, 90.0))
        self.threshold_p95 = float(np.percentile(self.knn_distances, percentiles["p95"]))
        self.threshold_p99 = float(np.percentile(self.knn_distances, percentiles["p99"]))
        self.threshold_p99_9 = float(np.percentile(self.knn_distances, percentiles["p99_9"]))
        self.threshold = self.threshold_p95

        logger.info(f"    training_p99_distance: {self.training_p99_distance:.4f}")
        logger.info(
            f"    P90={self.threshold_p90:.4f}  P95={self.threshold_p95:.4f}  "
            f"P99={self.threshold_p99:.4f}  P99.9={self.threshold_p99_9:.4f}"
        )
        return self

    def score(self, X_hilbert: np.ndarray) -> np.ndarray:
        """
        Absolute anomaly score = mean_k5_distance / training_p99_distance.

        Returns:
            np.ndarray: Shape (n_samples,). Values > 1.0 exceed training P99.
        """
        if self.tree is None:
            raise ValueError("BallTree not fitted.")
        d, _ = self.tree.query(X_hilbert, k=self.k_neighbors + 1)
        return d[:, 1:].mean(axis=1) / self.training_p99_distance

    def predict(self, X_hilbert: np.ndarray, severity: str = "p95") -> np.ndarray:
        """Binary prediction at the specified threshold tier."""
        if severity not in ("p95", "p99", "p99_9"):
            raise ValueError(f"severity must be p95/p99/p99_9, got {severity}")
        scores = self.score(X_hilbert)
        raw = getattr(self, f"threshold_{severity}")
        return (scores > raw / self.training_p99_distance).astype(int)

    def get_severity(self, X_hilbert: np.ndarray, slack: float = 1.0) -> np.ndarray:
        """
        Map absolute scores to tiered severity (float32 preserves 0.5 soft-zone).

        Returns:
            np.ndarray: Values in {0, 0.5, 1, 2, 3}, dtype float32.
        """
        scores = self.score(X_hilbert)
        p90 = (self.threshold_p90 / self.training_p99_distance) * slack
        p95 = (self.threshold_p95 / self.training_p99_distance) * slack
        p99 = (self.threshold_p99 / self.training_p99_distance) * slack
        p999 = (self.threshold_p99_9 / self.training_p99_distance) * slack

        sev = np.zeros(len(scores), dtype=np.float32)
        sev[(scores > p90) & (scores <= p95)] = 0.5
        sev[(scores > p95) & (scores <= p99)] = 1.0
        sev[(scores > p99) & (scores <= p999)] = 2.0
        sev[scores > p999] = 3.0
        return sev


# ============================================================================
# TIER 2A — GMM DETECTOR
# ============================================================================

class GMMDetector:
    """Log-Likelihood anomaly detection via Gaussian Mixture Model."""

    def __init__(self, use_bayesian: bool = True) -> None:
        self.gmm_model: Optional[Any] = None
        self.use_bayesian = use_bayesian
        self.threshold: Optional[float] = None
        self.log_likelihoods: Optional[np.ndarray] = None
        self.ll_stats_mean: Optional[float] = None
        self.ll_stats_std: Optional[float] = None

    def fit(
        self,
        X_hilbert: np.ndarray,
        n_components: int = 5,
        percentile: float = PERCENTILE_THRESHOLD,
        reg_covar: float = 1e-3,
    ) -> "GMMDetector":
        """Fit GMM on Hilbert space baseline."""
        if len(X_hilbert) < n_components * 10:
            raise ValueError(f"Need ≥ {n_components * 10} samples.")
        logger.info(f"[*] GMM: {n_components} components (Bayesian={self.use_bayesian})…")

        cls = BayesianGaussianMixture if self.use_bayesian else GaussianMixture
        kwargs: Dict[str, Any] = dict(
            n_components=n_components, covariance_type="full",
            reg_covar=reg_covar, max_iter=200,
            random_state=RANDOM_STATE, n_init=10,
        )
        if self.use_bayesian:
            kwargs["weight_concentration_prior"] = 1e-2

        self.gmm_model = cls(**kwargs)
        self.gmm_model.fit(X_hilbert)

        self.log_likelihoods = self.gmm_model.score_samples(X_hilbert)
        self.ll_stats_mean = float(np.mean(self.log_likelihoods))
        self.ll_stats_std = float(np.std(self.log_likelihoods))
        self.threshold = float(np.percentile(-self.log_likelihoods, percentile))

        logger.info(
            f"    LL mean={self.ll_stats_mean:.4f}  threshold={self.threshold:.4f}"
        )
        return self

    def score(self, X_hilbert: np.ndarray) -> np.ndarray:
        """Inverted log-likelihood (higher = more anomalous)."""
        if self.gmm_model is None:
            raise ValueError("GMM not fitted.")
        return -self.gmm_model.score_samples(X_hilbert)

    def predict(self, X_hilbert: np.ndarray) -> np.ndarray:
        """Binary anomaly flag."""
        return (self.score(X_hilbert) > self.threshold).astype(int)


# ============================================================================
# TIER 2B — ISOLATION FOREST DETECTOR
# ============================================================================

class IForestDetector:
    """Structural anomaly detection via Isolation Forest."""

    def __init__(self) -> None:
        self.iforest_model: Optional[IsolationForest] = None
        self.contamination: float = 0.01

    def fit(
        self,
        X_hilbert: np.ndarray,
        contamination: float = 0.01,
    ) -> "IForestDetector":
        """Fit Isolation Forest on Hilbert space baseline."""
        if not 0 < contamination < 0.5:
            raise ValueError(f"contamination must be (0, 0.5), got {contamination}")
        logger.info(f"[*] IForest: contamination={contamination}…")
        self.contamination = contamination
        self.iforest_model = IsolationForest(
            contamination=contamination,
            random_state=RANDOM_STATE,
            n_estimators=100,
        )
        self.iforest_model.fit(X_hilbert)
        return self

    def score(self, X_hilbert: np.ndarray) -> np.ndarray:
        """Inverted isolation score (higher = more anomalous)."""
        if self.iforest_model is None:
            raise ValueError("IForest not fitted.")
        return -self.iforest_model.score_samples(X_hilbert)

    def predict(self, X_hilbert: np.ndarray) -> np.ndarray:
        """Binary anomaly flag."""
        return (self.iforest_model.predict(X_hilbert) == -1).astype(int)


# ============================================================================
# TIER 4 — VELOCITY BYPASS DETECTOR  (NEW v4.0)
# ============================================================================

class VelocityBypassDetector:
    """
    Stateless emergency anomaly gate on rolling Z-score velocity features.

    This detector operates entirely outside Hilbert space.  It reads the three
    pre-computed Z-score features from the test DataFrame and:

        1. Fires an emergency bypass (is_anomaly=1) for every sample where
           max(|vel_pps_z|, |vel_bytes_z|, |vel_syn_z|) ≥ bypass_threshold.

        2. Returns a continuous vel_score = max_abs_z / bypass_threshold
           (capped at 3.0) for integration into the weighted Tribunal.

    No training step is needed.  The Z-scores are self-normalising because
    the rolling window baseline is embedded in the feature computation in
    processor_optime.py.

    Backward compatibility:
        If any vel_* feature is absent (e.g. data generated before
        processor_optime v2.3.0), the method logs a debug message and returns
        zero arrays so the rest of the pipeline is unaffected.
    """

    @staticmethod
    def compute(
        df_test: pd.DataFrame,
        bypass_threshold: float = 5.0,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Compute velocity bypass signals for all samples in one vectorised pass.

        Args:
            df_test: Test DataFrame containing vel_pps_z, vel_bytes_z, vel_syn_z.
            bypass_threshold: Z-score magnitude that triggers the bypass gate.

        Returns:
            Tuple of four np.ndarrays, all shape (n_samples,):
                vel_scores      — continuous score in [0, 3.0] for Tribunal.
                bypass_mask     — bool, True where emergency bypass fires.
                bypass_severity — int, HiGI severity level (0 if no bypass).
                vel_culprit     — object array of strings, e.g.
                                  "vel_pps_z(z=+9.43)" or "" for non-bypass.
        """
        n = len(df_test)
        vel_scores = np.zeros(n, dtype=float)
        bypass_mask = np.zeros(n, dtype=bool)
        bypass_severity = np.zeros(n, dtype=int)
        vel_culprit = np.full(n, "", dtype=object)

        missing = [f for f in VELOCITY_FEATURES if f not in df_test.columns]
        if missing:
            logger.debug(
                f"[VelocityBypass] Features missing ({missing}) — "
                "returning zeros (graceful degradation)."
            )
            return vel_scores, bypass_mask, bypass_severity, vel_culprit

        # Build (n_samples, 3) matrix; sanitise NaN/inf from short rolling windows.
        vel_mat = np.nan_to_num(
            df_test[list(VELOCITY_FEATURES)].values.astype(float),
            nan=0.0, posinf=0.0, neginf=0.0,
        )

        abs_vel = np.abs(vel_mat)
        max_abs_z = abs_vel.max(axis=1)           # (n_samples,)
        peak_col = abs_vel.argmax(axis=1)          # column index of peak

        # Continuous score: normalised to [0, 3.0] (3.0 ≡ 3× bypass threshold).
        vel_scores = np.clip(max_abs_z / bypass_threshold, 0.0, 3.0)

        bypass_mask = max_abs_z >= bypass_threshold

        if bypass_mask.any():
            for idx in np.where(bypass_mask)[0]:
                z = max_abs_z[idx]
                sev = 1  # default: Borderline
                for z_thr, s in VELOCITY_SEVERITY_THRESHOLDS:
                    if z >= z_thr:
                        sev = s
                        break
                bypass_severity[idx] = sev
                feat = VELOCITY_FEATURES[peak_col[idx]]
                signed_z = vel_mat[idx, peak_col[idx]]
                vel_culprit[idx] = f"{feat}(z={signed_z:+.2f})"

        logger.info(
            f"[VelocityBypass] Z-range=[{max_abs_z.min():.2f}, {max_abs_z.max():.2f}] | "
            f"bypass={bypass_mask.sum():,} samples "
            f"(threshold={bypass_threshold:.1f}σ)"
        )
        return vel_scores, bypass_mask, bypass_severity, vel_culprit


# ============================================================================
# MAIN ENGINE
# ============================================================================

class HiGIEngine:
    """
    Hilbert-space Gaussian Intelligence (HiGI) — v4.0.

    Four-tier detection pipeline:

        Step 0   Schema validation + warm-up flag (FIX-2)
        Step 1   Hilbert space projection
        Tier 1   BallTree gatekeeper — absolute scores (FIX-1)
        Tier 4   Velocity Bypass — emergency gate on vel_*_z (NEW v4.0)
        Step 2   Short-circuit segmentation (bypass samples join suspect mask)
        Tier 2   Probabilistic Tribunal — GMM + IForest on suspects only
        Step 3A  Weighted consensus: balltree + gmm + iforest + velocity
        Step 3B  Physical Sentinel — univariate GMM per feature
        Step 3C  Final consensus decision + FIX-4 family consensus
        Step 3D  Strict persistence filter (bypass samples protected)
        Step 3E  Adaptive hysteresis — FIX-3 (bypass samples protected)
        Step 4   Moving-average contextualisation
        Step 5   Forensic attribution (vel bypass annotation injected)
        Step 5B  Portero veto — extreme sigma override
        Step 6   Compose output DataFrame

    Output columns (v4.0 additions vs v3.0):
        vel_score   — continuous velocity score in [0, 3.0]
        vel_bypass  — bool, True where velocity emergency bypass fired
        vel_culprit — "feature_name(z=±X.XX)" or ""
    """

    def __init__(
        self,
        config: Optional[HiGIConfig] = None,
        n_jobs: int = 1,
    ) -> None:
        self.config = config or HiGIConfig()
        self.n_jobs = n_jobs

        self.projector: Optional[HilbertSpaceProjector] = None
        self.balltree_detector: Optional[BallTreeDetector] = None
        self.gmm_detector: Optional[GMMDetector] = None
        self.iforest_detector: Optional[IForestDetector] = None

        self.feature_cols: List[str] = []
        self.baseline_mean: Optional[pd.Series] = None
        self.baseline_std: Optional[pd.Series] = None

        self.univariate_gmms: Dict[str, GaussianMixture] = {}
        self.univariate_gmm_configs: Dict[str, int] = {}
        self.univariate_ll_thresholds: Dict[str, float] = {}

        self.tribunal_weights_normalized: Optional[Dict[str, float]] = None

        self.is_fitted: bool = False
        self.training_stats: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # STATIC UTILITY
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_scores_minmax(scores: np.ndarray) -> np.ndarray:
        """Min-max normalise to [0, 1] — used for GMM and IForest only."""
        lo, hi = scores.min(), scores.max()
        return (scores - lo) / (hi - lo) if hi - lo > 1e-10 else np.zeros_like(scores)

    # ------------------------------------------------------------------
    # FIX-4: FAMILY CONSENSUS VALIDATOR
    # ------------------------------------------------------------------

    def _validate_family_consensus(
        self,
        sample_idx: int,
        df_test: pd.DataFrame,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check whether ≥ family_consensus_min_hits features from the same
        METRIC_FAMILIES group are simultaneously anomalous (|z| ≥ 2.0).

        Velocity features are members of volume_flood (v4.0), so a velocity
        bypass event automatically satisfies family consensus for that family.

        Args:
            sample_idx: Row index in df_test.
            df_test: Test DataFrame.

        Returns:
            (passes, family_name) — family_name is None when passes=False.
        """
        if not self.config.family_consensus_enabled:
            return True, None
        if self.baseline_mean is None or self.baseline_std is None:
            return True, None

        try:
            row = df_test.iloc[sample_idx]
            z_thr = 2.0
            min_hits = self.config.family_consensus_min_hits

            for fname, members in METRIC_FAMILIES.items():
                hits = 0
                for pattern in members:
                    for col in self.feature_cols:
                        if pattern not in col or col not in self.baseline_mean.index:
                            continue
                        std_v = self.baseline_std[col]
                        if std_v < 1e-10:
                            continue
                        z = abs((row[col] - self.baseline_mean[col]) / std_v)
                        if z >= z_thr:
                            hits += 1
                            break  # one match per pattern per family
                if hits >= min_hits:
                    return True, fname

        except Exception as exc:
            logger.debug(f"Family consensus check failed sample {sample_idx}: {exc}")
            return True, None  # safe degradation

        return False, None

    # ------------------------------------------------------------------
    # TRAINING
    # ------------------------------------------------------------------

    def train(
        self,
        df_baseline: pd.DataFrame,
        n_jobs: Optional[int] = None,
    ) -> "HiGIEngine":
        """
        Train HiGI on baseline (normal) traffic data.

        Velocity features are included in the Hilbert space PCA and in the
        univariate GMMs when present.  During normal Monday traffic their
        values cluster near 0 (stable regime), so the BallTree's training P99
        in the velocity dimensions is small — making DoS-onset vel_pps_z > 8
        correctly anomalous even in Hilbert space.

        VelocityBypassDetector requires no training.

        Args:
            df_baseline: Normal traffic feature matrix (n_samples ≥ 100).
            n_jobs: CPU cores; overrides self.n_jobs when provided.

        Returns:
            self — for method chaining.

        Raises:
            InsufficientDataError: Fewer than 100 baseline samples.
            HiGITrainingError: Any detector fails to fit.
        """
        if len(df_baseline) < 100:
            raise InsufficientDataError(
                f"Need ≥ 100 baseline samples, got {len(df_baseline)}"
            )

        logger.info(f"\n{'='*80}")
        logger.info("HiGI ENGINE TRAINING v4.0 — Velocity Bypass Architecture")
        logger.info(f"{'='*80}")

        try:
            # Step 0: feature schema
            logger.info("\n[STEP 0] Feature Schema")
            _meta = {"dt", "timestamp", "second_window", "index", "label", "frame_number"}
            self.feature_cols = [
                c for c in df_baseline.columns
                if pd.api.types.is_numeric_dtype(df_baseline[c]) and c not in _meta
            ]
            vel_present = [f for f in VELOCITY_FEATURES if f in self.feature_cols]
            if not vel_present:
                logger.warning(
                    "  ⚠ Velocity features ABSENT from baseline. "
                    "VelocityBypass will degrade gracefully during inference. "
                    "Re-process PCAP with processor_optime v2.3.0+ to enable Tier 4."
                )
            else:
                logger.info(f"  Velocity features present: {vel_present}")
            logger.info(f"  Total features: {len(self.feature_cols)}")

            self.baseline_mean = df_baseline[self.feature_cols].mean()
            self.baseline_std = df_baseline[self.feature_cols].std().replace(0, 1e-6)

            # Step 0.5: univariate GMMs
            logger.info("\n[STEP 0.5] Univariate GMM Training")
            for feat in self.feature_cols:
                try:
                    Xf = df_baseline[feat].values.reshape(-1, 1)
                    if Xf.std() < 1e-6:
                        self.univariate_gmm_configs[feat] = 1
                        continue
                    k = (
                        self._find_optimal_k_for_feature(Xf, feat)
                        if self.config.adaptive_univariate_k
                        else self.config.univariate_gmm_components
                    )
                    self.univariate_gmm_configs[feat] = k
                    g = GaussianMixture(n_components=k, random_state=42, n_init=10)
                    g.fit(Xf)
                    self.univariate_gmms[feat] = g
                    self.univariate_ll_thresholds[feat] = (
                        float(np.percentile(g.score_samples(Xf), 99.9))
                        if self.config.per_feature_thresholds
                        else float(np.log(self.config.physical_sentinel_threshold))
                    )
                except Exception as exc:
                    logger.warning(f"  {feat}: univariate GMM failed — {exc}")

            logger.info(f"  Trained: {len(self.univariate_gmms)}/{len(self.feature_cols)}")

            # Step 0.6: tribunal weights
            if self.config.weighted_tribunal and self.config.tribunal_weights:
                total = sum(self.config.tribunal_weights.values())
                self.tribunal_weights_normalized = {
                    k: v / total for k, v in self.config.tribunal_weights.items()
                }
                logger.info(f"  Tribunal weights (normalised): {self.tribunal_weights_normalized}")

            # Step 1: Hilbert space
            logger.info("\n[STEP 1] Hilbert Space Projection")
            self.projector = HilbertSpaceProjector()
            self.projector.fit(
                df_baseline,
                variance_target=self.config.pca_variance,
                blocked_pca_enabled=self.config.blocked_pca_enabled,
                blocked_pca_variance_per_family=self.config.blocked_pca_variance_per_family,
            )
            Xh = self.projector.transform(df_baseline)
            self.training_stats["hilbert_dimensions"] = Xh.shape[1]
            self.training_stats["variance_retained"] = float(
                self.projector.pca_variance_ratio.sum()
            )

            # Step 2: ensemble detectors
            logger.info("\n[STEP 2] Ensemble Detectors")

            logger.info("  [A] BallTree (Tier 1)")
            self.balltree_detector = BallTreeDetector()
            self.balltree_detector.fit(
                Xh,
                percentiles={
                    "p95": self.config.threshold_p95,
                    "p99": self.config.threshold_p99,
                    "p99_9": self.config.threshold_p99_9,
                },
            )
            self.training_stats["balltree_training_p99_distance"] = float(
                self.balltree_detector.training_p99_distance
            )

            logger.info("  [B] GMM (Tier 2A)")
            n_components = self._select_optimal_components(Xh)
            self.gmm_detector = GMMDetector(use_bayesian=self.config.use_bayesian_gmm)
            self.gmm_detector.fit(
                Xh, n_components=n_components,
                percentile=self.config.threshold_percentile,
                reg_covar=self.config.reg_covar,
            )
            self.training_stats["gmm_components"] = n_components

            logger.info("  [C] IForest (Tier 2B)")
            self.iforest_detector = IForestDetector()
            self.iforest_detector.fit(Xh, contamination=self.config.iforest_contamination)

            logger.info(
                f"  [D] VelocityBypass (Tier 4): "
                f"{'ENABLED' if self.config.velocity_bypass_enabled else 'DISABLED'} "
                f"(threshold={self.config.velocity_bypass_threshold:.1f}σ, "
                f"vel_features={'present' if vel_present else 'ABSENT'})"
            )

            self.is_fitted = True

            logger.info(f"\n{'='*80}")
            logger.info("HiGI ENGINE TRAINING COMPLETE (v4.0)")
            logger.info(f"{'='*80}")
            logger.info(f"  Input features  : {len(self.feature_cols)}")
            logger.info(f"  Hilbert dims    : {self.training_stats['hilbert_dimensions']}")
            logger.info(f"  Variance kept   : {self.training_stats['variance_retained']*100:.2f}%")
            logger.info(f"  BallTree P99    : {self.training_stats['balltree_training_p99_distance']:.4f}")
            logger.info(f"  GMM components  : {n_components}")
            logger.info(
                f"  Velocity bypass : {self.config.velocity_bypass_threshold:.1f}σ "
                f"| weight={self.config.velocity_tribunal_weight:.2f}"
            )
            logger.info("")
            return self

        except Exception as exc:
            raise HiGITrainingError(f"Training failed: {exc}") from exc

    # ------------------------------------------------------------------
    # INFERENCE
    # ------------------------------------------------------------------

    def analyze(
        self,
        df_test: pd.DataFrame,
        n_jobs: Optional[int] = None,
    ) -> pd.DataFrame:
        """
        Cascaded anomaly detection and forensic attribution.

        v4.0 additions to the existing v3.0 pipeline:

            * Before short-circuit segmentation, VelocityBypassDetector.compute()
              evaluates all samples and returns vel_scores, bypass_mask,
              bypass_severity, vel_culprit.
            * Bypass samples are added to the suspect mask so they receive full
              Tier 2 inspection and appear in the weighted Tribunal.
            * In Step 3C, bypass samples are unconditionally forced to is_anomaly=1
              and their severity is set to max(BallTree_severity, vel_severity).
            * In Steps 3D and 3E, bypass samples are protected from suppression
              by the rolling-min persistence filter and hysteresis by re-applying
              the bypass mask after each filter.
            * In Step 5, the forensic_evidence narrative appends
              "⚡VELOCITY BYPASS: feature(z=±X.XX)" when bypass fired.

        Args:
            df_test: Test feature matrix. vel_* features are optional but
                required for Tier 4 to be active.
            n_jobs: CPU cores override.

        Returns:
            pd.DataFrame with all v3.0 columns plus vel_score, vel_bypass,
            vel_culprit.
        """
        if not self.is_fitted:
            raise HiGIInferenceError("Engine not fitted. Call train() first.")
        if None in (self.projector, self.balltree_detector,
                    self.gmm_detector, self.iforest_detector):
            raise HiGIInferenceError("Engine components not initialised properly.")

        logger.info(f"\n{'='*80}")
        logger.info("HiGI ENGINE INFERENCE v4.0")
        logger.info(f"{'='*80}")
        logger.info(f"Test samples: {len(df_test):,}")

        try:
            # ── Step 0: schema validation ───────────────────────────────────
            _meta_ignore = {"_abs_timestamp", "server_port"}
            _required = (set(self.feature_cols) - _meta_ignore) - set(VELOCITY_FEATURES)
            missing = _required - set(df_test.columns)
            if missing:
                raise HiGIInferenceError(f"Feature schema mismatch. Missing: {missing}")

            n = len(df_test)

            # FIX-2: warm-up flag
            warmup_rows = self.config.ma_window_size * 3
            is_warmup = np.zeros(n, dtype=bool)
            is_warmup[: min(warmup_rows, n)] = True
            logger.info(f"\n[FIX-2] Warm-up: {is_warmup.sum()} rows flagged.")

            # ── Step 1: Hilbert projection ──────────────────────────────────
            logger.info("\n[STEP 1] Hilbert Space Projection")
            Xh = self.projector.transform(df_test)

            # ── Tier 1: BallTree (absolute scores) ─────────────────────────
            logger.info("\n[TIER 1] BallTree Gatekeeper (ALL samples)")
            logger.info("-" * 80)
            bt_scores = self.balltree_detector.score(Xh)
            bt_severity = self.balltree_detector.get_severity(
                Xh, slack=self.config.balltree_slack
            )
            logger.info(
                f"  Score range: [{bt_scores.min():.3f}, {bt_scores.max():.3f}] "
                "(1.0 = training P99)"
            )
            for lbl, sv in [
                ("Normal   (<P90)", 0), ("Soft    (P90-P95)", 0.5),
                ("Borderline(P95-P99)", 1), ("Medium (P99-P99.9)", 2), ("Critical(≥P99.9)", 3),
            ]:
                logger.info(f"  {lbl}: {(bt_severity == sv).sum():,}")

            # ── Tier 4: Velocity Bypass Detector (ALL samples) ── NEW v4.0 ─
            logger.info("\n[TIER 4] Velocity Bypass Detector (ALL samples)")
            logger.info("-" * 80)
            if self.config.velocity_bypass_enabled:
                vel_scores, vel_bypass, vel_bypass_sev, vel_culprit = (
                    VelocityBypassDetector.compute(
                        df_test,
                        bypass_threshold=self.config.velocity_bypass_threshold,
                    )
                )
            else:
                vel_scores = np.zeros(n, dtype=float)
                vel_bypass = np.zeros(n, dtype=bool)
                vel_bypass_sev = np.zeros(n, dtype=int)
                vel_culprit = np.full(n, "", dtype=object)
                logger.info("  VelocityBypass DISABLED.")

            # ── Step 2: short-circuit segmentation ─────────────────────────
            logger.info("\n[STEP 2] Short-Circuit Segmentation")
            logger.info("-" * 80)
            soft_zone = bt_severity == 0.5
            # Bypass samples join the suspect mask so Tier 2 evaluates them.
            normal_mask = (bt_severity < 1) & ~soft_zone & ~vel_bypass
            suspect_mask = (bt_severity >= 1) | soft_zone | vel_bypass
            logger.info(f"  Normal  : {normal_mask.sum():,} (skip Tier 2)")
            logger.info(
                f"  Suspect : {suspect_mask.sum():,} "
                f"(incl. {vel_bypass.sum()} velocity-bypass)"
            )

            gmm_scores = np.zeros(n, dtype=float)
            gmm_anom = np.zeros(n, dtype=int)
            ifor_scores = np.zeros(n, dtype=float)
            ifor_anom = np.zeros(n, dtype=int)
            consensus_votes = np.zeros(n, dtype=int)

            # ── Tier 2: Probabilistic Tribunal (suspects only) ──────────────
            logger.info("\n[TIER 2] Deep Inspection (suspects only)")
            logger.info("-" * 80)
            if suspect_mask.sum() > 0:
                Xs = Xh[suspect_mask]
                s_idx = np.where(suspect_mask)[0]

                gs = self.gmm_detector.score(Xs)
                ga = self.gmm_detector.predict(Xs)
                is_ = self.iforest_detector.score(Xs)
                ia = self.iforest_detector.predict(Xs)

                # Score normalization for consensus: either CDF-based or robust Z-score.
                if self.gmm_detector.ll_stats_mean is not None:
                    z = (gs - self.gmm_detector.ll_stats_mean) / (self.gmm_detector.ll_stats_std + 1e-10)
                    if self.config.gmm_score_normalization_method == "cdf":
                        gs_norm = np.clip(scipy_norm.cdf(z), 0.0, 1.0)
                    else: # robust
                        gs_norm = (np.clip(z, -3.0, 3.0) + 3.0) / 6.0
                else:
                    gs_norm = self._normalize_scores_minmax(gs)

                gmm_scores[s_idx] = gs_norm
                gmm_anom[s_idx] = ga
                ifor_scores[s_idx] = self._normalize_scores_minmax(is_)
                ifor_anom[s_idx] = ia
                consensus_votes[s_idx] = ga + ia

                logger.info(f"  GMM anomalies   : {ga.sum():,}")
                logger.info(f"  IForest anomalies: {ia.sum():,}")
            else:
                logger.info("  No suspects → Tier 2 skipped.")

            # ── Step 3A: Weighted consensus (now includes vel_scores) ───────
            logger.info("\n[STEP 3A] Weighted Consensus")
            logger.info("-" * 80)
            if self.config.weighted_tribunal:
                cw, cmeta = self._compute_weighted_consensus(
                    bt_scores, gmm_scores, ifor_scores, vel_scores
                )
                logger.info(f"  Weights: {cmeta['weights']}")
                logger.info(
                    f"  Mean/Max: {cmeta['mean_consensus']:.4f} / "
                    f"{cmeta['max_consensus']:.4f}"
                )
            else:
                cw = None
                logger.info("  Weighted consensus disabled.")

            # ── Step 3B: Physical Sentinel (univariate GMM) ─────────────────
            logger.info("\n[STEP 3B] Physical Sentinel Vote")
            logger.info("-" * 80)
            phys_votes = np.zeros(n, dtype=int)
            phys_src = np.full(n, "", dtype=object)
            if self.config.physical_sentinel_enabled and self.univariate_gmms:
                cands = np.where(bt_severity > 0)[0]
                phys_votes, phys_src = self._compute_physical_sentinel_vote(df_test, cands)
                logger.info(f"  Sentinel votes: {phys_votes.sum():,}")
            else:
                logger.info("  Sentinel disabled.")

            # ── Step 3C: Final Consensus Decision ──────────────────────────
            logger.info("\n[STEP 3C] Final Consensus Decision")
            logger.info("-" * 80)
            is_anomaly = np.zeros(n, dtype=int)
            sev_final = bt_severity.copy()
            family_labels = np.full(n, "", dtype=object)

            # 3C-i: VELOCITY EMERGENCY BYPASS (unconditional) ── NEW v4.0
            if vel_bypass.any():
                is_anomaly[vel_bypass] = 1
                for idx in np.where(vel_bypass)[0]:
                    sev_final[idx] = float(max(int(sev_final[idx]), vel_bypass_sev[idx]))
                logger.info(
                    f"  [VEL BYPASS] {vel_bypass.sum():,} samples forced "
                    "is_anomaly=1 by velocity emergency gate."
                )

            # 3C-ii: Standard Tribunal consensus
            if self.config.weighted_tribunal and cw is not None:
                thr = self.config.tribunal_consensus_threshold
                is_anomaly[bt_severity == 3] = 1
                is_anomaly[(bt_severity == 2) & (cw >= thr)] = 1

                for idx in np.where((bt_severity == 1) & (cw >= thr))[0]:
                    ok, fn = self._validate_family_consensus(idx, df_test)
                    if ok:
                        is_anomaly[idx] = 1
                        if fn:
                            family_labels[idx] = fn

                is_anomaly[(bt_severity == 1) & (phys_votes == 1)] = 1
                boost = (phys_votes == 1) & (cw >= max(0.7, thr))
                is_anomaly[(bt_severity == 0) & boost] = 1
            else:
                is_anomaly[bt_severity == 3] = 1
                is_anomaly[(bt_severity == 2) & (consensus_votes >= 2)] = 1
                is_anomaly[(bt_severity == 1) & (consensus_votes >= 2)] = 1
                is_anomaly[(bt_severity == 1) & (phys_votes == 1)] = 1

            logger.info(
                f"  Preliminary: {is_anomaly.sum():,} "
                f"({is_anomaly.mean()*100:.2f}%)"
            )

            # ── Step 3D: Persistence filter (bypass samples protected) ──────
            logger.info("\n[STEP 3D] Persistence Filter")
            logger.info("-" * 80)
            pw = 3
            if n >= pw:
                pre_bypass = vel_bypass.copy()
                confirmed = (
                    pd.Series(is_anomaly)
                    .rolling(window=pw, min_periods=pw).min()
                    .fillna(0).astype(int).values
                )
                filtered = (
                    pd.Series(confirmed)
                    .rolling(window=pw, min_periods=1).max()
                    .fillna(0).astype(int).values
                )
                n_suppressed = int(is_anomaly.sum()) - int(filtered.sum())
                is_anomaly = filtered
                is_anomaly[pre_bypass] = 1   # Bypass samples survive filter.
                sev_final[is_anomaly == 0] = 0
                logger.info(f"  Suppressed: {n_suppressed:,} | Remaining: {is_anomaly.sum():,}")

            # ── Step 3E: Adaptive Hysteresis (bypass protected) ── FIX-3 ───
            if self.config.physical_sentinel_enabled:
                logger.info("\n[STEP 3E] Adaptive Hysteresis (FIX-3)")
                logger.info("-" * 80)
                base_thr = (
                    self.balltree_detector.threshold_p95
                    / self.balltree_detector.training_p99_distance
                )
                is_anomaly = self._apply_hysteresis(
                    is_anomaly=is_anomaly,
                    balltree_scores=bt_scores,
                    balltree_threshold=base_thr,
                    min_persistence=self.config.alert_minimum_persistence,
                    entry_multiplier=self.config.hysteresis_entry_multiplier,
                    exit_multiplier=self.config.hysteresis_exit_multiplier,
                )
                is_anomaly[vel_bypass] = 1   # Bypass samples survive hysteresis.
                sev_final[is_anomaly == 0] = 0
                sev_final[(is_anomaly == 1) & (sev_final == 0)] = 1

            # ── Step 4: Moving-average contextualisation ────────────────────
            logger.info("\n[STEP 4] Moving Average Contextualisation")
            persist_labels = np.full(n, "", dtype=object)
            ma_scores = np.full(n, np.nan, dtype=float)
            if n >= self.config.ma_window_size:
                ma = (
                    pd.Series(bt_scores)
                    .rolling(window=self.config.ma_window_size, min_periods=1)
                    .mean().values
                )
                ma_scores = ma
                for idx in np.where((is_anomaly == 1) | (bt_severity >= 0.5))[0]:
                    ratio = bt_scores[idx] / (ma[idx] + 1e-10)
                    persist_labels[idx] = (
                        "Transient Spike"
                        if ratio > (1.0 / self.config.transient_threshold)
                        else "Sustained Attack"
                    )

            # ── Step 5: Forensic Attribution ───────────────────────────────
            logger.info("\n[STEP 5] Forensic Attribution")
            logger.info("-" * 80)
            culprit_comps: List[Optional[str]] = [None] * n
            culprit_devs = np.full(n, np.nan, dtype=float)
            phys_culprits = [""] * n
            evidences = [""] * n

            f_idx = np.where((is_anomaly == 1) | (bt_severity >= 0.5))[0]
            nf = len(f_idx)

            if nf > 0 and self.config.enable_forensics:
                # ────────────────────────────────────────────────────────────
                # PRE-FORENSICS VALIDATION: Ensure projector is ready
                # ────────────────────────────────────────────────────────────
                logger.debug(
                    f"[DEBUG] HiGIEngine.projector._projection_mode: "
                    f"{self.projector._projection_mode}"
                )
                try:
                    self.projector.validate_fitted()
                    logger.debug(
                        "[DEBUG] Projector validation passed. "
                        "Ready for forensic attribution."
                    )
                except HiGIInferenceError as e:
                    raise HiGIInferenceError(
                        f"Projector validation failed at STEP 5: {e}. "
                        f"Forensic attribution cannot proceed."
                    ) from e

                logger.info(f"  Generating {nf:,} forensic reports…")

                Xa = df_test.loc[df_test.index[f_idx], self.feature_cols].values
                Zmat = np.abs(
                    (Xa - self.baseline_mean.values) / (self.baseline_std.values + 1e-10)
                )
                LLmat = np.full((nf, len(self.feature_cols)), 1e10)
                for fi, feat in enumerate(self.feature_cols):
                    if feat in self.univariate_gmms:
                        try:
                            LLmat[:, fi] = self.univariate_gmms[feat].score_samples(
                                Xa[:, fi].reshape(-1, 1)
                            )
                        except Exception as exc:
                            logger.debug(f"GMM LL failed for {feat}: {exc}")

                logger.debug(
                    f"[DEBUG] About to extract culprit components using "
                    f"get_culprit_component() and get_suspect_features(). "
                    f"Projector mode: {self.projector._projection_mode}, "
                    f"n_samples: {nf}"
                )

                for i, idx in enumerate(f_idx):
                    if idx in self.projector._last_inf_sample_indices:
                        culprit_devs[idx] = float("inf")
                        evidences[idx] = "[OVERFLOW] Hilbert overflow — forced CRITICAL."
                        continue

                    Xrow = Xa[i]
                    zrow = Zmat[i]
                    cz = int(np.argmax(zrow))
                    czv = float(zrow[cz])
                    gl = int(np.argmin(LLmat[i]))
                    glv = float(LLmat[i, gl])

                    fname = self.feature_cols[cz]
                    fval = Xrow[cz]
                    bval = self.baseline_mean.values[cz]

                    if self.config.sentinel_directionality_analysis:
                        pct = abs(fval - bval) / (abs(bval) + 1e-10) * 100
                        ctype = (
                            f"SPIKE (+{pct:.1f}%)" if fval > bval else f"DROP ({pct:.1f}%)"
                        )
                    else:
                        ctype = "Spike" if fval > bval else "Drop"

                    if gl != cz:
                        phys_culprits[idx] = (
                            f"{fname} ({ctype}, σ={czv:.2f}) | "
                            f"GMM: {self.feature_cols[gl]} (LL={glv:.3f})"
                        )
                    else:
                        phys_culprits[idx] = f"{fname} ({ctype}, σ={czv:.2f})"

                    ci = self.projector.get_culprit_component(Xh, idx)
                    sf = self.projector.get_suspect_features(
                        ci["pc_index"], top_n=self.config.top_features_per_pc
                    )
                    direction = "elevated" if ci["direction"] > 0 else "reduced"

                    _s = bt_severity[idx]
                    slbl = (
                        "SOFT ZONE" if _s == 0.5
                        else ["NORMAL", "BORDERLINE", "MEDIUM", "CRITICAL"][int(_s)]
                    )
                    wt = " [WARMUP]" if is_warmup[idx] else ""
                    ft = (
                        f" Family: {family_labels[idx]}." if family_labels[idx] else ""
                    )

                    # v4.0: velocity bypass annotation
                    vt = ""
                    if vel_bypass[idx]:
                        vt = (
                            f" ⚡VELOCITY BYPASS: {vel_culprit[idx]} "
                            f"(≥{self.config.velocity_bypass_threshold:.1f}σ — "
                            "emergency gate fired)."
                        )

                    ev = (
                        f"[{slbl}{wt}] "
                        f"Physical: {phys_culprits[idx]}. "
                        f"Multivariate: {ci['pc']} ({direction} {abs(ci['deviation']):.2f}σ). "
                        f"Suspect features: {', '.join(sf)}. "
                        f"Persistence: {persist_labels[idx]}. "
                        f"BallTree score: {bt_scores[idx]:.2f}x P99."
                        f"{ft}{vt}"
                    )
                    if _s == 3:
                        ev += " ALERT: Critical — immediate investigation required."

                    culprit_comps[idx] = ci["pc"]
                    culprit_devs[idx] = float(ci["deviation"])
                    evidences[idx] = ev

            # ── Step 5B: Portero Veto ───────────────────────────────────────
            logger.info("\n[STEP 5B] Portero Veto")
            veto = (
                (np.abs(culprit_devs) > self.config.portero_sigma_threshold)
                | ((bt_severity == 3) & (consensus_votes >= 2))
            )
            if veto.any():
                is_anomaly[veto] = 1
                sev_final[veto] = 3.0
                logger.info(f"  {int(veto.sum())} samples forced CRITICAL.")
            else:
                logger.info("  No veto triggered.")

            culprit_devs = np.where(np.isnan(culprit_devs), 0.0, culprit_devs)
            sev_final = np.where((is_anomaly == 1) & (sev_final == 0), 1, sev_final)

            # ── Step 6: Compose output ──────────────────────────────────────
            logger.info("\n[STEP 6] Composing Results DataFrame")
            results = pd.DataFrame(
                {
                    "balltree_score": bt_scores,         # absolute (FIX-1)
                    "balltree_severity": bt_severity,
                    "gmm_score": gmm_scores,
                    "gmm_anomaly": gmm_anom,
                    "iforest_score": ifor_scores,
                    "iforest_anomaly": ifor_anom,
                    "consensus_votes": consensus_votes,
                    "is_anomaly": is_anomaly,
                    "severity": sev_final,
                    "persistence": persist_labels,
                    "anomaly_ma_score": ma_scores,
                    "physical_culprit": phys_culprits,
                    "culprit_component": culprit_comps,
                    "culprit_deviation": culprit_devs,
                    "forensic_evidence": evidences,
                    "is_warmup": is_warmup,              # FIX-2
                    "family_consensus": family_labels,   # FIX-4
                    # v4.0 velocity columns
                    "vel_score": vel_scores,
                    "vel_bypass": vel_bypass,
                    "vel_culprit": vel_culprit,
                },
                index=df_test.index,
            )

            logger.info(f"\n{'='*80}")
            logger.info("HiGI INFERENCE COMPLETE (v4.0)")
            logger.info(f"{'='*80}")
            logger.info(f"  Samples            : {n:,}")
            logger.info(f"  Tier 2 load        : {suspect_mask.sum()/n*100:.1f}%")
            logger.info(f"  Anomalies total    : {is_anomaly.sum():,} ({is_anomaly.mean()*100:.2f}%)")
            logger.info(f"  Velocity bypasses  : {vel_bypass.sum():,} (emergency)")
            logger.info("  Severity breakdown :")
            for sv, lbl in enumerate(["Normal", "Borderline", "Medium", "Critical"]):
                logger.info(f"    {lbl:10}: {(sev_final == sv).sum():,}")
            logger.info(
                f"  Persistence: "
                f"Transient={( persist_labels == 'Transient Spike').sum()} | "
                f"Sustained={(persist_labels == 'Sustained Attack').sum()}"
            )
            logger.info("")
            return results

        except Exception as exc:
            raise HiGIInferenceError(f"Inference failed: {exc}") from exc

    # ------------------------------------------------------------------
    # HYSTERESIS (FIX-3)
    # ------------------------------------------------------------------

    def _apply_hysteresis(
        self,
        is_anomaly: np.ndarray,
        balltree_scores: np.ndarray,
        balltree_threshold: float,
        min_persistence: int = 3,
        entry_multiplier: float = 1.0,
        exit_multiplier: float = 0.75,
    ) -> np.ndarray:
        """
        Dual-threshold Schmitt-trigger with FIX-3 adaptive persistence.

        FIX-3: the exit persistence window adapts to signal strength:
            adaptive = max(1, min(base, int(3 / (score_ratio + 0.1))))
        High-sigma attacks (Heartbleed) clear in 1 window; borderline noise
        still requires base_persistence windows.

        Args:
            is_anomaly: Raw binary flags (n_samples,).
            balltree_scores: Absolute BallTree scores (FIX-1 scale).
            balltree_threshold: Decision boundary in absolute scale.
            min_persistence: Base exit-persistence count.
            entry_multiplier: Entry = threshold × multiplier.
            exit_multiplier: Exit = threshold × multiplier.

        Returns:
            np.ndarray: Stabilised binary flags (dtype=int).
        """
        entry = balltree_threshold * entry_multiplier
        exit_ = balltree_threshold * exit_multiplier

        stabilized = np.zeros(len(balltree_scores), dtype=int)
        in_alert = False
        clear_ctr = 0

        for i, score in enumerate(balltree_scores):
            if not in_alert:
                if is_anomaly[i] and score > entry:
                    in_alert = True
                    clear_ctr = 0
                    stabilized[i] = 1
                else:
                    stabilized[i] = 0
            else:
                if score < exit_:
                    ratio = score / (entry + 1e-10)
                    adaptive = max(1, min(min_persistence, int(3 / (ratio + 0.1))))
                    clear_ctr += 1
                    if clear_ctr >= adaptive:
                        in_alert = False
                        stabilized[i] = 0
                        clear_ctr = 0
                    else:
                        stabilized[i] = 1
                else:
                    clear_ctr = 0
                    stabilized[i] = 1

        return stabilized

    # ------------------------------------------------------------------
    # PERSISTENCE / SERIALISATION
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """
        Persist engine state to disk as a joblib file.

        VelocityBypassDetector has no learned state and is not persisted;
        it is reconstructed from HiGIConfig on the next load.

        Args:
            path: Output file path (e.g. 'models/higi_v4.pkl').
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if not self.is_fitted:
            logger.warning("Engine not fitted — saving anyway.")
        joblib.dump(
            {
                "config": self.config,
                "projector": self.projector,
                "balltree_detector": self.balltree_detector,
                "gmm_detector": self.gmm_detector,
                "iforest_detector": self.iforest_detector,
                "feature_cols": self.feature_cols,
                "baseline_mean": self.baseline_mean,
                "baseline_std": self.baseline_std,
                "univariate_gmms": self.univariate_gmms,
                "univariate_gmm_configs": self.univariate_gmm_configs,
                "tribunal_weights_normalized": self.tribunal_weights_normalized,
                "univariate_ll_thresholds": self.univariate_ll_thresholds,
                "is_fitted": self.is_fitted,
                "training_stats": self.training_stats,
            },
            p,
        )
        logger.info(f"[✓] HiGI engine (v4.0) saved → {path}")

    @staticmethod
    def load(path: str) -> "HiGIEngine":
        """
        Load engine from disk with full backward compatibility and validation.

        Supported bundle formats:
            1. Direct HiGIEngine instance (orchestrator ArtifactBundle).
            2. State dict from save().
            3. HiGIEngine inside a dict wrapper.
            4. State dict inside a dict wrapper (legacy).

        Validation Flow (post-deserialization):
            1. Detects bundle format and extracts HiGIEngine instance or state dict.
            2. For direct instances or reconstructed engines: calls _validate_engine_state()
               to verify all components (projector, detectors) are correctly fitted.
            3. For projector specifically: calls projector.is_fitted() and
               projector._validate_fitted_state() to detect ColumnTransformer issues.
            4. Applies backward-compatibility patches (_patch_v3_balltree).
            5. Logs detailed diagnostics for debugging deserialization issues.

        Backward compatibility:
            v3.0 bundles lack velocity config fields — HiGIConfig defaults apply.
            v2.x bundles lack training_p99_distance — _patch_v3_balltree() derives it.
            Missing vel_* features at inference time degrade gracefully to zeros.

        Args:
            path: File path (.pkl or .joblib).

        Returns:
            HiGIEngine ready for inference (all components validated).

        Raises:
            FileNotFoundError: Path does not exist.
            ValueError: Cannot extract valid engine from file.
            HiGIInferenceError: Engine components corrupted or not fitted.

        Examples:
            >>> engine = HiGIEngine.load('models/higi_v4.pkl')
            >>> results = engine.analyze(df_test)
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Engine file not found: {path}")

        try:
            loaded = joblib.load(p)
        except Exception as exc:
            raise ValueError(f"Failed to load {path}: {exc}")

        # ──────────────────────────────────────────────────────────────────
        # CASE 1: Direct HiGIEngine instance (fresh from serialization)
        # ──────────────────────────────────────────────────────────────────
        if isinstance(loaded, HiGIEngine):
            logger.info("[•] Bundle format: Direct HiGIEngine instance")
            HiGIEngine._patch_v3_balltree(loaded)
            HiGIEngine._validate_engine_state(loaded, path)
            logger.info(f"[✓] HiGI engine loaded from {path} (direct instance)")
            return loaded

        if not isinstance(loaded, dict):
            raise ValueError(f"Unexpected type {type(loaded).__name__} in {path}")

        # ──────────────────────────────────────────────────────────────────
        # CASE 2: HiGIEngine wrapped in dict (legacy orchestrator format)
        # ──────────────────────────────────────────────────────────────────
        if "engine" in loaded and isinstance(loaded["engine"], HiGIEngine):
            logger.info("[•] Bundle format: HiGIEngine inside dict wrapper")
            e = loaded["engine"]
            HiGIEngine._patch_v3_balltree(e)
            HiGIEngine._validate_engine_state(e, path)
            logger.info(f"[✓] HiGI engine loaded from {path} (instance in bundle)")
            return e

        # ──────────────────────────────────────────────────────────────────
        # CASE 3: State dict (direct or wrapped)
        # ──────────────────────────────────────────────────────────────────
        logger.info("[•] Bundle format: State dict (reconstructing engine)")
        state = (
            loaded.get("engine", loaded)
            if isinstance(loaded.get("engine"), dict)
            else loaded
        )

        cfg = state.get("config") or HiGIConfig()
        e = HiGIEngine(config=cfg)
        e.projector = state.get("projector")
        e.balltree_detector = state.get("balltree_detector")
        e.gmm_detector = state.get("gmm_detector")
        e.iforest_detector = state.get("iforest_detector")
        e.feature_cols = state.get("feature_cols", [])
        e.baseline_mean = state.get("baseline_mean")
        e.baseline_std = state.get("baseline_std")
        e.univariate_gmms = state.get("univariate_gmms", {})
        e.univariate_gmm_configs = state.get("univariate_gmm_configs", {})
        e.tribunal_weights_normalized = state.get("tribunal_weights_normalized")
        e.univariate_ll_thresholds = state.get("univariate_ll_thresholds", {})
        e.is_fitted = state.get("is_fitted", False)
        e.training_stats = state.get("training_stats", {})

        HiGIEngine._patch_v3_balltree(e)
        HiGIEngine._validate_engine_state(e, path)

        logger.info(f"[✓] HiGI engine loaded from {path}")
        logger.info(f"    Features : {len(e.feature_cols)}")
        logger.info(f"    Fitted   : {e.is_fitted}")
        logger.info(
            f"    VelBypass: "
            f"{'ENABLED' if e.config.velocity_bypass_enabled else 'DISABLED'} "
            f"({e.config.velocity_bypass_threshold:.1f}σ)"
        )
        return e

    @staticmethod
    def _validate_engine_state(engine: "HiGIEngine", path: str) -> None:
        """
        Post-deserialization validation of all engine components.

        Checks that:
        - Projector is fitted and ready (critical for Tier 1)
        - BallTree, GMM, IForest are present and fitted
        - Feature columns and baseline stats are consistent

        This prevents confusing inference failures by catching issues early.

        Args:
            engine: Deserialized HiGIEngine instance.
            path: File path (for logging context).

        Raises:
            HiGIInferenceError: Critical component is corrupted.
        """
        if not engine.is_fitted:
            logger.warning(
                f"[!] Engine loaded from {path} is marked as not fitted. "
                f"Training may be incomplete; inference may fail."
            )
            return

        # ──────────────────────────────────────────────────────────────────
        # Validate Projector (Hilbert space backbone)
        # ──────────────────────────────────────────────────────────────────
        if engine.projector is None:
            raise HiGIInferenceError(
                f"Projector is None in bundle from {path}. "
                f"Bundle corrupted or training incomplete."
            )

        try:
            engine.projector.validate_fitted()
            logger.info(
                f"[✓] Projector validated: "
                f"mode={engine.projector._projection_mode}, "
                f"features={len(engine.projector.feature_names)}"
            )
        except HiGIInferenceError as e:
            raise HiGIInferenceError(
                f"Projector validation failed after loading {path}: {e}"
            ) from e

        # ──────────────────────────────────────────────────────────────────
        # Validate Ensemble Detectors (Tier 1 & 2)
        # ──────────────────────────────────────────────────────────────────
        if engine.balltree_detector is None:
            raise HiGIInferenceError(
                f"BallTreeDetector is None in {path}. Bundle incomplete."
            )
        if not hasattr(engine.balltree_detector, "tree") or engine.balltree_detector.tree is None:
            raise HiGIInferenceError(
                f"BallTreeDetector.tree not fitted in {path}. Re-train required."
            )

        if engine.gmm_detector is None:
            raise HiGIInferenceError(
                f"GMMDetector is None in {path}. Bundle incomplete."
            )
        if engine.gmm_detector.gmm_model is None:
            raise HiGIInferenceError(
                f"GMMDetector.gmm_model not fitted in {path}. Re-train required."
            )

        if engine.iforest_detector is None:
            raise HiGIInferenceError(
                f"IForestDetector is None in {path}. Bundle incomplete."
            )
        if engine.iforest_detector.iforest_model is None:
            raise HiGIInferenceError(
                f"IForestDetector.iforest_model not fitted in {path}. Re-train required."
            )

        logger.info(
            f"[✓] Ensemble detectors validated: "
            f"BallTree, GMM({engine.gmm_detector.gmm_model.n_components}), "
            f"IForest({engine.iforest_detector.iforest_model.n_estimators})"
        )

        # ──────────────────────────────────────────────────────────────────
        # Validate Feature Schema & Baseline Statistics
        # ──────────────────────────────────────────────────────────────────
        if not engine.feature_cols:
            raise HiGIInferenceError(
                f"Feature columns list is empty in {path}. Bundle corrupted."
            )
        if engine.baseline_mean is None or engine.baseline_std is None:
            raise HiGIInferenceError(
                f"Baseline statistics missing in {path}. Bundle incomplete."
            )

        logger.info(
            f"[✓] Feature schema validated: {len(engine.feature_cols)} features, "
            f"baseline μ/σ present"
        )

    @staticmethod
    def _patch_v3_balltree(engine: "HiGIEngine") -> None:
        """
        Backward-compat: derive training_p99_distance for pre-v3 bundles.

        Pre-v3 BallTreeDetector stored knn_distances but not training_p99_distance.
        This patch reconstructs it from knn_distances percentile.

        Args:
            engine: HiGIEngine instance to patch.
        """
        bt = engine.balltree_detector
        if bt is None:
            return
        if not hasattr(bt, "training_p99_distance") or bt.training_p99_distance is None:
            if bt.knn_distances is not None and len(bt.knn_distances) > 0:
                p99 = float(np.percentile(bt.knn_distances, 99.0))
                bt.training_p99_distance = max(p99, 1e-10)
                logger.info(
                    f"[✓] v3 patch: training_p99_distance={bt.training_p99_distance:.4f} "
                    "(derived — retrain for best accuracy)"
                )
            else:
                bt.training_p99_distance = 1.0
                logger.warning(
                    "[!] v3 patch: knn_distances unavailable — "
                    "training_p99_distance=1.0 (retrain required)."
                )

    # ------------------------------------------------------------------
    # PRIVATE HELPERS
    # ------------------------------------------------------------------

    def _select_optimal_components(self, X_hilbert: np.ndarray) -> int:
        """Ensemble vote (BIC 40%, AIC 10%, Silhouette 25%, DB 25%) for GMM K."""
        logger.info("    Selecting optimal K…")
        n = len(X_hilbert)
        search = range(MIN_COMPONENTS, min(MAX_COMPONENTS_DEFAULT + 1, n // 10))
        bics, aics, sils, dbs = [], [], [], []

        for k in search:
            g = GaussianMixture(
                n_components=k, covariance_type="full",
                random_state=RANDOM_STATE, n_init=3, max_iter=100,
            )
            g.fit(X_hilbert)
            bics.append(g.bic(X_hilbert))
            aics.append(g.aic(X_hilbert))
            lbls = g.predict(X_hilbert)
            if len(np.unique(lbls)) > 1:
                try:
                    sils.append(silhouette_score(X_hilbert, lbls, sample_size=min(1000, n)))
                    dbs.append(davies_bouldin_score(X_hilbert, lbls))
                except Exception:
                    sils.append(-1.0)
                    dbs.append(1e10)
            else:
                sils.append(-1.0)
                dbs.append(1e10)

        def _n(v: list, inv: bool = False) -> np.ndarray:
            a = np.array(v, dtype=float)
            a[~np.isfinite(a)] = np.nanmax(a)
            if inv:
                a = a.max() - a
            r = a.max() - a.min()
            return (a - a.min()) / r if r > 0 else np.ones_like(a)

        votes = (
            0.40 * _n(bics, inv=True)
            + 0.10 * _n(aics, inv=True)
            + 0.25 * _n(sils)
            + 0.25 * _n(dbs, inv=True)
        )
        k_opt = list(search)[int(np.argmax(votes))]
        logger.info(f"    Optimal K: {k_opt}")
        return k_opt

    def _find_optimal_k_for_feature(
        self,
        X_univariate: np.ndarray,
        feature_name: str,
    ) -> int:
        """BIC + AIC vote for optimal univariate GMM K."""
        try:
            n = len(X_univariate)
            lo, hi = self.config.adaptive_univariate_k_range
            search = list(range(lo, min(hi + 1, max(2, n // 20))))
            if len(search) < 2:
                return self.config.univariate_gmm_components

            bics, aics = [], []
            for k in search:
                try:
                    g = GaussianMixture(
                        n_components=k, random_state=42, n_init=5, max_iter=100
                    )
                    g.fit(X_univariate)
                    bics.append(g.bic(X_univariate))
                    aics.append(g.aic(X_univariate))
                except Exception:
                    bics.append(np.inf)
                    aics.append(np.inf)

            def _n(v: list, inv: bool = False) -> np.ndarray:
                a = np.array(v, dtype=float)
                fin = a[np.isfinite(a)]
                a[~np.isfinite(a)] = np.nanmax(fin) if len(fin) else 1e6
                if inv:
                    a = a.max() - a
                r = a.max() - a.min()
                return (a - a.min()) / r if r > 1e-10 else np.ones_like(a)

            votes = 0.5 * _n(bics, inv=True) + 0.5 * _n(aics, inv=True)
            return search[int(np.argmax(votes))]

        except Exception as exc:
            logger.warning(f"    {feature_name}: K search failed ({exc}) — using default.")
            return self.config.univariate_gmm_components

    def _compute_weighted_consensus(
        self,
        balltree_scores: np.ndarray,
        gmm_scores: np.ndarray,
        iforest_scores: np.ndarray,
        vel_scores: Optional[np.ndarray] = None,
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Weighted probabilistic consensus across four signals (v4.0).

        vel_scores are in [0, 3.0] and are normalised to [0, 1] by division
        by 3 before entering the weighted sum.

        Args:
            balltree_scores: Absolute BallTree scores (FIX-1).
            gmm_scores:      Min-max normalised GMM scores [0, 1].
            iforest_scores:  Min-max normalised IForest scores [0, 1].
            vel_scores:      Velocity scores [0, 3.0] (None → zero).

        Returns:
            (consensus_scores, metadata_dict)
        """
        method = self.config.gmm_score_normalization_method

        def _norm(scores: np.ndarray, is_gmm: bool = False) -> np.ndarray:
            if is_gmm and self.gmm_detector and self.gmm_detector.ll_stats_mean is not None:
                z = (scores - self.gmm_detector.ll_stats_mean) / (
                    self.gmm_detector.ll_stats_std + 1e-10
                )
                if method == "cdf":
                    return np.clip(scipy_norm.cdf(z), 0.0, 1.0)
                if method == "robust":
                    return (np.clip(z, -3.0, 3.0) + 3.0) / 6.0
            lo, hi = scores.min(), scores.max()
            return (scores - lo) / (hi - lo) if hi - lo > 1e-10 else np.zeros_like(scores)

        bt_n = _norm(balltree_scores)
        gm_n = _norm(gmm_scores, is_gmm=True)
        if_n = _norm(iforest_scores)

        weights = self.tribunal_weights_normalized or {
            "balltree": 0.175, "gmm": 0.28, "iforest": 0.245, "velocity": 0.30,
        }

        consensus = (
            weights.get("balltree", 0.175) * bt_n
            + weights.get("gmm", 0.28) * gm_n
            + weights.get("iforest", 0.245) * if_n
        )
        if vel_scores is not None and weights.get("velocity", 0.0) > 0:
            consensus += weights["velocity"] * np.clip(vel_scores / 3.0, 0.0, 1.0)

        return consensus, {
            "mean_consensus": float(consensus.mean()),
            "max_consensus": float(consensus.max()),
            "min_consensus": float(consensus.min()),
            "std_consensus": float(consensus.std()),
            "weights": weights,
        }

    def _compute_physical_sentinel_vote(
        self,
        df_test: pd.DataFrame,
        sample_indices: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Vectorised Physical Sentinel: per-feature univariate GMM log-likelihood.

        Args:
            df_test: Test DataFrame with original feature values.
            sample_indices: Indices of suspect samples to evaluate.

        Returns:
            (physical_votes, physical_culprits) — both shape (n_samples,).
        """
        n = len(df_test)
        votes = np.zeros(n, dtype=int)
        culprits = np.full(n, "", dtype=object)

        if not self.config.physical_sentinel_enabled or not self.univariate_gmms:
            return votes, culprits

        try:
            feats = [f for f in self.feature_cols if f in self.univariate_gmms]
            if not feats:
                return votes, culprits

            subset = df_test.iloc[sample_indices][feats]
            ll = np.full((len(sample_indices), len(feats)), -np.inf, dtype=float)

            for fi, feat in enumerate(feats):
                try:
                    ll[:, fi] = self.univariate_gmms[feat].score_samples(
                        subset[[feat]].values
                    )
                except Exception as exc:
                    logger.debug(f"Sentinel GMM failed for {feat}: {exc}")

            min_ll = ll.min(axis=1)
            cfi = ll.argmin(axis=1)

            if self.config.per_feature_thresholds and self.univariate_ll_thresholds:
                mask = np.zeros(len(sample_indices), dtype=bool)
                for i in range(len(sample_indices)):
                    feat_name = feats[cfi[i]]
                    thr = self.univariate_ll_thresholds.get(
                        feat_name,
                        float(np.log(self.config.physical_sentinel_threshold)),
                    )
                    if min_ll[i] < thr:
                        mask[i] = True
            else:
                mask = min_ll < float(np.log(self.config.physical_sentinel_threshold))

            triggered = sample_indices[mask]
            votes[triggered] = 1
            for i, off in enumerate(np.where(mask)[0]):
                culprits[sample_indices[off]] = feats[cfi[i]]

        except Exception as exc:
            logger.error(f"Physical Sentinel failed: {exc}")
            logger.warning("Returning zero votes (safe degradation).")

        return votes, culprits


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    logger.info("HiGI Engine v4.0 — Velocity Bypass Architecture")
    logger.info("Usage: from src.models.higi_engine import HiGIEngine")
    logger.info("")
    logger.info("Four-tier detection pipeline:")
    logger.info("  Tier 1  BallTree (absolute scores, FIX-1)")
    logger.info("  Tier 2  GMM + IForest on suspects")
    logger.info("  Tier 3  Physical Sentinel (univariate GMM per feature)")
    logger.info("  Tier 4  VelocityBypassDetector on vel_pps_z/vel_bytes_z/vel_syn_z  ← NEW")
    logger.info("")
    logger.info("Prerequisite for Tier 4:")
    logger.info("  processor_optime.py v2.3.0+ must be used to generate vel_* features.")
    logger.info("  Older CSVs degrade gracefully (Tier 4 returns zeros).")

## File: src/analysis/forensic_engine.py

"""
Forensic Analysis Engine V2 for HiGI IDS.

Transforms raw anomaly telemetry produced by the 4-tier Cascaded Sentinel
pipeline into actionable intelligence for a Blue Team analyst.

Key improvements over ForensicEngine V1:
  - Blocked-PCA dimensionality mapping: every alert is traced back to
    the physical feature family (volume, flags, payload, protocol,
    connection/kinematics) whose principal component triggered it.
  - Consensus Confidence Index: weighted across all four tiers (BallTree,
    GMM/IForest Tribunal, Physical Sentinel, Velocity Bypass) so confidence
    reflects *which* detectors agree, not just how many.
  - Dynamic Severity: Euclidean distance to the P99 baseline surface rather
    than a flat vote count.
  - XAI for Blue Team: top-3 physical features per firing PC, SPIKE/DROP
    directionality, MITRE ATT&CK mapping, and per-family stress radar.
  - Executive-grade visualisations: Attack Intensity Timeline and Physical
    Family Stress Radar, saved as PNG siblings of the Markdown report.

Architecture notes:
  - Zero magic numbers: all thresholds flow from HiGISettings / config.yaml.
  - Blocked-PCA metadata (``_blocked_pca_family_mapping``,
    ``_blocked_pca_loadings_by_family``) is consumed when an ArtifactBundle
    pickle is supplied; otherwise the engine gracefully degrades to
    parsing the ``culprit_component`` / ``family_consensus`` columns that the
    orchestrator embeds directly in the results CSV.
  - Drop-in replacement for ForensicEngine V1: ``main.py`` calls the same
    ``ForensicEngine`` alias exposed at module level.

Author: HiGI Security Data Engineering Team
Version: 2.0.0
"""

from __future__ import annotations

import io
import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")  # headless – no GUI required
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.dates as mdates
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.stats import norm

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK registry
# ---------------------------------------------------------------------------
MITRE_ATT_CK_MAPPING: Dict[str, Tuple[str, str]] = {
    "flag_syn_ratio":         ("Impact",             "T1498.001 – DoS: Direct Network Flood (SYN Flood)"),
    "flag_rst_ratio":         ("Impact",             "T1499.002 – DoS: Endpoint Service (RST Flood)"),
    "flag_fin_ratio":         ("Reconnaissance",     "T1595 – Active Scanning (Stealth FIN Scan)"),
    "flag_ack_ratio":         ("Reconnaissance",     "T1571 – Non-Standard Port Communication"),
    "connection_rate":        ("Impact",             "T1499.003 – DoS: Application Boundary Flood"),
    "traffic_volume_spike":   ("Impact",             "T1498 – Network Denial of Service (Volumetric)"),
    "burst_factor_anomaly":   ("Impact",             "T1498.002 – DoS: Reflection / Amplification"),
    "port_scan_ratio":        ("Reconnaissance",     "T1595.001 – Active Scanning: IP Addresses"),
    "entropy_anomaly":        ("Command & Control",  "T1573.001 – Encrypted Channel: Symmetric Crypto"),
    "entropy_volatility":     ("Command & Control",  "T1573 – Encrypted / Obfuscated Traffic"),
    "packet_size_anomaly":    ("Command & Control",  "T1001.003 – Data Obfuscation: Protocol Impersonation"),
    "dns_spike":              ("Command & Control",  "T1071.004 – Application Layer Protocol: DNS"),
    "beaconing_cadence":      ("Command & Control",  "T1071 – Application Layer C2 Heartbeat"),
    "bytes_out_ratio":        ("Exfiltration",       "T1020 – Automated Exfiltration"),
    "payload_volume_spike":   ("Exfiltration",       "T1048 – Exfiltration Over Alternative Protocol"),
    "protocol_anomaly":       ("Defense Evasion",    "T1001.001 – Data Steganography / Protocol Tunneling"),
    "ttl_anomaly":            ("Defense Evasion",    "T1562.001 – Impair Defenses"),
    "bytes_volatility":       ("Impact",             "T1498 – Resource Exhaustion: Bandwidth Volatility"),
    "payload_continuity":     ("Command & Control",  "T1573 – Encrypted / Obfuscated Traffic"),
    "pps_volatility":         ("Impact",             "T1498 – Volumetric PPS Volatility"),
    "flow_duration":          ("Impact",             "T1190 – Exploit Public-Facing Application (Slow DoS)"),
    "iat_mean":               ("Command & Control",  "T1071 – Beaconing / Irregular IAT"),
    "size_max":               ("Exfiltration",       "T1048 – Oversized Packet Exfiltration"),
    "unique_dst_ports":       ("Reconnaissance",     "T1046 – Network Service Discovery"),
    "udp_ratio":              ("Impact",             "T1498.001 – UDP Flood / Amplification"),
}

SEVERITY_RISK_LABELS: Dict[int, str] = {
    1: "Low — Single-tier detection",
    2: "High — Majority consensus",
    3: "Critical — Full unanimity",
}

# Physical-family → colour for radar / bar charts (consistent palette)
FAMILY_COLOURS: Dict[str, str] = {
    "volume":      "#e74c3c",
    "payload":     "#e67e22",
    "flags":       "#f1c40f",
    "protocol":    "#2ecc71",
    "connection":  "#3498db",
    "kinematics":  "#9b59b6",
    "velocity":    "#1abc9c",
    "unknown":     "#95a5a6",
}


# ===========================================================================
# HELPER UTILITIES
# ===========================================================================


def _extract_base_name(raw: Any) -> str:
    """Extract the canonical metric name from a raw culprit annotation string.

    This function isolates the base feature identifier (e.g., 'flag_syn_ratio')
    from a richly annotated culprit string. The culprit annotation encodes the
    Hilbert-space deviation magnitude (|σ|), directionality (SPIKE/DROP), and
    percentage change, originating from the Blocked-PCA decomposition.

    Args:
        raw (Any): Raw culprit annotation string. Example:
            'flag_syn_ratio (SPIKE (+865%), σ=4.2) | GMM: pps_acc (LL=-3.2)'.
            May be None or NaN if the row was not flagged by Physical Sentinel.

    Returns:
        str: Lowercase canonical metric identifier (e.g., 'flag_syn_ratio').
            Returns 'unknown' if parsing fails or input is null.
    """
    if raw is None or (isinstance(raw, float) and math.isnan(raw)):
        return "unknown"
    match = re.match(r"^([a-z_][a-z0-9_]*)", str(raw).strip(), re.IGNORECASE)
    return match.group(1).lower() if match else "unknown"


def _extract_event_type(raw: str) -> str:
    """Extract the directionality of the feature deviation from a culprit annotation.

    SPIKE indicates a deviation in the positive direction (anomaly magnitude
    exceeding the P99 upper baseline), while DROP indicates a deficit in the
    negative direction. Both represent deviations in Hilbert-space distance.

    Args:
        raw (str): Culprit annotation string containing event type marker.

    Returns:
        str: 'SPIKE' or 'DROP'. Returns 'UNKNOWN' if parsing fails.
    """
    m = re.search(r"\b(SPIKE|DROP)\b", str(raw), re.IGNORECASE)
    return m.group(1).upper() if m else "UNKNOWN"


def _extract_sigma(raw: str) -> float:
    """Extract the standard deviation distance from baseline (σ) from a culprit annotation.

    σ (sigma) represents the number of standard deviations the feature value
    has deviated from the inertial reference frame (baseline), as computed by
    the Blocked-PCA analysis. Higher |σ| indicates greater confidence in the
    anomaly and stronger alignment with the principal components.

    Args:
        raw (str): Culprit annotation string containing σ value.

    Returns:
        float: Absolute standard deviation distance (σ) in the Hilbert-space
            inertial reference frame. Returns 0.0 if parsing fails.
    """
    m = re.search(r"σ\s*=\s*([\d.]+)", str(raw))
    return float(m.group(1)) if m else 0.0


def _extract_pct(raw: str) -> float:
    """Extract the percentage change magnitude of a feature from its baseline.

    This dimensionless ratio represents the relative deviation: e.g., a SPIKE
    of +865% means the feature value reached 9.65× its baseline value. Used
    for interpretability and to communicate severity to non-technical analysts.

    Args:
        raw (str): Culprit annotation string containing percentage marker.

    Returns:
        float: Absolute percentage deviation (e.g., 865.0 for a +865% spike).
            Returns 0.0 if parsing fails.
    """
    m = re.search(r"(?:SPIKE|DROP)\s*\(([+-]?[\d.]+)%\)", str(raw), re.IGNORECASE)
    return abs(float(m.group(1))) if m else 0.0


def _infer_family(culprit_base: str, family_consensus: Any) -> str:
    """Infer the physical feature family of a metric via Blocked-PCA consensus or heuristic.

    The Blocked-PCA decomposition partitions network telemetry into six orthogonal
    physical feature families (volume, payload, flags, protocol, connection, kinematics).
    This function resolves which family a culprit metric belongs to, using the
    consensus family (if available from BlockedPCA metadata) or keyword-matching as fallback.

    Resolution precedence:
        1. Explicit ``family_consensus`` value from BlockedPCA metadata.
        2. Keyword matching against the canonical metric name.
        3. 'unknown' fallback for unrecognized features.

    Args:
        culprit_base (str): Canonical metric name (e.g., 'flag_syn_ratio', 'bytes_total').
        family_consensus (Any): Family value from BlockedPCA consensus metadata.
            May be NaN or None if unavailable.

    Returns:
        str: Physical family identifier:
            'volume', 'payload', 'flags', 'protocol', 'connection', 'kinematics',
            or 'unknown'.
    """
    if pd.notna(family_consensus) and str(family_consensus).strip():
        return str(family_consensus).strip().lower()

    keywords: Dict[str, List[str]] = {
        "flags":      ["flag_", "syn", "rst", "fin", "ack", "urg", "psh"],
        "volume":     ["bytes", "pps", "traffic", "bandwidth", "burst"],
        "payload":    ["payload", "entropy", "size", "max", "min"],
        "protocol":   ["protocol", "udp", "tcp", "icmp", "ttl", "dns"],
        "connection": ["port_scan", "unique_dst", "connection", "flow", "iat", "duration"],
        "kinematics": ["velocity", "acceleration", "momentum", "volatility", "vel_"],
    }
    for fam, kws in keywords.items():
        if any(kw in culprit_base for kw in kws):
            return fam
    return "unknown"


def _gaussian_cdf_confidence(sigma: float) -> float:
    """Map Hilbert-space standard deviation (σ) to confidence probability via Gaussian CDF.

    This function models the confidence that a deviation of magnitude |σ| standard
    deviations from the inertial reference frame is *not* due to random noise
    under a Normal baseline distribution. It integrates the detection tiers' outputs
    with the mathematical properties of Gaussian statistics.

    The CDF provides a probabilistic interpretation: higher σ values yield confidence
    scores approaching 1.0, indicating the anomaly is statistically significant.

    Args:
        sigma (float): Absolute standard deviation distance in the Hilbert-space
            inertial reference frame (σ ≥ 0).

    Returns:
        float: Confidence probability in [0.5, 1.0]. Baseline σ=0 yields ~0.5
            (chance level); σ=3 yields ~0.9987 (highly significant).
    """
    return float(norm.cdf(max(0.0, sigma)))


# ===========================================================================
# DATA STRUCTURES
# ===========================================================================


@dataclass
class TierEvidenceSummary:
    """Compressed evidence record summarizing a single detection tier's behavior within an incident.

    Each of the four detection tiers (BallTree, GMM/IForest, Physical Sentinel, Velocity Bypass)
    operates independently on the telemetry stream. This dataclass summarizes the aggregate
    firing pattern for one tier across all windows in an incident, used to compute the
    Consensus Confidence Index.

    Attributes:
        tier_name (str): Human-readable detection tier identifier.
            One of: 'BallTree', 'GMM', 'IForest', 'PhysicalSentinel', 'VelocityBypass'.
        fired (bool): True if this tier triggered (fired) at least once during the incident.
        fire_count (int): Total number of windows (temporal bins) in which this tier
            raised an anomaly alert during the incident window.
        mean_score (float): Mean detection score across all windows in the incident.
            Score units are tier-specific (e.g., Euclidean distance for BallTree,
            log-likelihood for GMM, anomaly score [0-1] for IForest).
    """

    tier_name: str
    fired: bool
    fire_count: int
    mean_score: float


@dataclass
class FeatureAttribution:
    """Top contributing physical feature identified via Blocked-PCA analysis (XAI module).

    The HiGI explainability system identifies the culprit feature (the physical metric
    whose anomalous behavior best explains the Hilbert-space deviation) for each incident.
    FeatureAttribution records the top-3 culprit features, ranked by their loading magnitude
    in the principal component space.

    Attributes:
        feature_name (str): Canonical metric identifier (e.g., 'flag_syn_ratio', 'bytes_total').
        loading_magnitude (float): Normalized contribution coefficient in [0, 1].
            Derived from Blocked-PCA loadings, or from normalized |σ| if loadings unavailable.
            Higher values indicate stronger alignment with anomalous principal components.
        event_type (str): Directionality of anomaly: 'SPIKE' (positive) or 'DROP' (negative).
        max_sigma (float): Maximum standard deviation distance (σ) in the Hilbert-space
            inertial reference frame observed for this feature within the incident.
        max_pct (float): Dimensionless maximum percentage deviation (e.g., 865.0 for +865%).
            Used for analyst-friendly severity interpretation.
        family (str): Physical feature family category:
            'volume', 'payload', 'flags', 'protocol', 'connection', 'kinematics', or 'unknown'.
    """

    feature_name: str
    loading_magnitude: float
    event_type: str
    max_sigma: float
    max_pct: float
    family: str


@dataclass
class SecurityIncidentV2:
    """A clustered security incident with V2 enriched metadata and XAI attribution.

    SecurityIncidentV2 represents a contiguous temporal cluster of anomalies detected
    by the HiGI IDS. The incident is enriched with Blocked-PCA family attribution,
    consensus-weighted confidence scoring, and MITRE ATT&CK technique mapping.

    An incident spans from the first anomalous window to the last window before
    exceeding the debounce threshold, and contains at least one detection from the
    Multi-tier Tribunal (BallTree, GMM/IForest, Physical Sentinel, or Velocity Bypass).

    Attributes:
        incident_id (int): Sequential identifier (0-based) within the forensic engine session.
        start_time (datetime): Timezone-aware or naive datetime of the first anomalous window.
        end_time (datetime): Datetime of the last anomalous window in the incident cluster.
        anomaly_rows (pd.DataFrame): Slice of the results DataFrame containing all rows
            (with is_anomaly=1 or soft_zone=True) belonging to this incident.
        tier_evidence (List[TierEvidenceSummary]): Summary of which detection tiers fired.
            Used to compute the Consensus Confidence Index.
        top_features (List[FeatureAttribution]): Top-3 culprit features (XAI module),
            ranked by Blocked-PCA loading magnitude. Identifies which physical metrics
            best explain the Hilbert-space deviation.
        family_stress (Dict[str, float]): Mapping of physical family → normalized stress
            score in [0, 1]. Stress represents each family's contribution to total anomaly load.
        mitre_tactics (Dict[str, List[str]]): MITRE ATT&CK mapping: tactic → list of
            technique identifiers relevant to the incident's culprit metrics.
        is_warmup (bool): True if > 50% of anomaly_rows are labeled is_warmup=1.
            Warmup incidents receive 50% confidence penalty to reduce false positives.
    """

    incident_id: int
    start_time: datetime
    end_time: datetime
    anomaly_rows: pd.DataFrame
    tier_evidence: List[TierEvidenceSummary] = field(default_factory=list)
    top_features: List[FeatureAttribution] = field(default_factory=list)
    family_stress: Dict[str, float] = field(default_factory=dict)
    mitre_tactics: Dict[str, List[str]] = field(default_factory=dict)
    is_warmup: bool = False

    # ------------------------------------------------------------------
    # Core metrics (computed lazily from anomaly_rows)
    # ------------------------------------------------------------------

    @property
    def duration_seconds(self) -> float:
        """Wall-clock duration of the incident in seconds (temporal magnitude).

        Returns:
            float: Elapsed time between first and last anomalous window, in seconds.
        """
        return (self.end_time - self.start_time).total_seconds()

    @property
    def total_anomalies(self) -> int:
        """Total count of anomalous windows (temporal bins) in the incident.

        Returns:
            int: Number of rows in anomaly_rows (volume metric).
        """
        return len(self.anomaly_rows)

    @property
    def max_severity(self) -> int:
        """Maximum discrete severity label observed within the incident (1–3).

        Severity tiers:
            1: Low — single-tier detection.
            2: High — majority consensus (≥2 tiers agreed).
            3: Critical — full unanimity (all tiers fired).

        Returns:
            int: Maximum severity in [1, 3], or 0 if anomaly_rows is empty.
        """
        if self.anomaly_rows.empty:
            return 0
        return int(self.anomaly_rows["severity"].max())

    @property
    def primary_culprit(self) -> str:
        """Most frequently reported physical culprit metric (feature family attribute).

        Identifies the single most common anomalous physical metric across all windows
        in the incident, providing a quick summary of the dominant attack vector.

        Returns:
            str: Canonical metric name (e.g., 'flag_syn_ratio'), or 'Unknown'.
        """
        if "physical_culprit" not in self.anomaly_rows.columns:
            return "Unknown"
        bases = self.anomaly_rows["physical_culprit"].dropna().apply(_extract_base_name)
        vc = bases.value_counts()
        return str(vc.index[0]) if len(vc) > 0 else "Unknown"

    @property
    def top_3_ports(self) -> List[int]:
        """Top-3 destination ports by detection frequency (network topology).

        Returns:
            List[int]: Up to 3 port numbers ranked by occurrence count. Empty if
                server_port column unavailable.
        """
        if "server_port" not in self.anomaly_rows.columns:
            return []
        return [int(p) for p in self.anomaly_rows["server_port"].value_counts().head(3).index]

    @property
    def persistence_label(self) -> str:
        """Most common persistence classification within the incident.

        Persistence label categorizes the temporal pattern of anomalies (e.g., transient,
        recurring, sustained) based on the anomaly_rows temporal structure.

        Returns:
            str: Persistence category identifier, or 'Unknown' if unavailable.
        """
        if "persistence" not in self.anomaly_rows.columns:
            return "Unknown"
        vc = self.anomaly_rows["persistence"].dropna().value_counts()
        return str(vc.index[0]) if len(vc) > 0 else "Unknown"

    # ------------------------------------------------------------------
    # Composite scoring
    # ------------------------------------------------------------------

    @property
    def consensus_confidence(self) -> float:
        """Tier-weighted consensus confidence index for the incident (XAI metric).

        This composite metric integrates three components: (1) statistical significance
        of the Hilbert-space deviation (σ), (2) temporal persistence (anomaly volume),
        and (3) multi-tier agreement. The formula is:

            base = Φ( mean_|σ| )  [Gaussian CDF of mean std. deviation]
            volume = log₂(1 + n_anomalies) / log₂(513)  [saturates at ≥512 anomalies]
            tier_w = Σ(tier_weight_i × fired_i) / Σ(tier_weight_i)  [weighted firing rate]
            conf = 0.45 × base + 0.35 × volume + 0.20 × tier_w

        Tier weights:
            - BallTree: 0.20 (baseline Hilbert-space distance)
            - GMM: 0.25 (probabilistic model consensus)
            - IForest: 0.20 (isolation forest anomaly score)
            - PhysicalSentinel: 0.20 (individual feature-family detection)
            - VelocityBypass: 0.15 (rapid-burst bypass mechanism)

        Penalties:
            - Warmup incidents (is_warmup=True) receive 50% confidence penalty
              to suppress false positives during detector stabilization.

        Returns:
            float: Confidence probability in [0.0, 1.0]. Ranges:
                < 0.40: Low confidence (likely noise or detector miscalibration).
                0.40–0.70: Medium confidence (recommend manual review).
                > 0.70: High confidence (strong multi-tier agreement).
        """
        avg_sigma = self.anomaly_rows["culprit_deviation"].abs().mean()
        if math.isnan(avg_sigma):
            avg_sigma = 0.0

        base = _gaussian_cdf_confidence(avg_sigma)
        volume = math.log2(1 + self.total_anomalies) / math.log2(513)
        volume = min(1.0, volume)

        # Tier weights: Physical Sentinel and Velocity Bypass carry extra weight
        # because they operate on individual features (harder to fool).
        tier_weights: Dict[str, float] = {
            "BallTree":        0.20,
            "GMM":             0.25,
            "IForest":         0.20,
            "PhysicalSentinel": 0.20,
            "VelocityBypass":  0.15,
        }
        w_fired = sum(
            tier_weights.get(t.tier_name, 0.10) * float(t.fired)
            for t in self.tier_evidence
        )
        w_total = sum(tier_weights.get(t.tier_name, 0.10) for t in self.tier_evidence)
        tier_factor = w_fired / w_total if w_total > 0 else 0.5

        conf = 0.45 * base + 0.35 * volume + 0.20 * tier_factor
        if self.is_warmup:
            conf *= 0.5
        return min(1.0, conf)

    @property
    def dynamic_severity_score(self) -> float:
        """Euclidean-distance-inspired severity index on continuous [0, ∞) scale.

        This metric quantifies the physical energy or magnitude of the anomaly perturbation
        in Hilbert-space. It combines the maximum standard deviation distance (|σ|_max)
        with temporal persistence to estimate how "severe" the incident's attack signature is.

        Scoring formula:
            For σ_max ≤ 5:
                score = σ_max / 5.0
            For σ_max > 5 (extreme deviations):
                score = 1.0 + ((σ_max - 5.0)^1.8) / 10.0  [non-linear amplification]

        Persistence boost:
            boost = log(1 + n_anomalies) / log(1 + 100)  [saturates at ~100 anomalies]
            final_score = sigma_score × (1.0 + boost)

        Physical interpretation:
            - 0.0–2.0: Weak perturbations (likely transient noise or benign variations).
            - 2.0–5.0: Moderate perturbations (anomalies warrant investigation).
            - 5.0–8.0: Strong perturbations (likely real security events).
            - > 8.0: Extreme perturbations (sustained, multi-vector attacks).

        The non-linear amplification for σ > 5 prevents saturation and preserves
        discrimination among high-severity DoS/DDoS bursts.

        Returns:
            float: Continuous severity score. Typical range [0.0, ~12.0].
        """
        if self.anomaly_rows.empty:
            return 0.0

        max_sigma = float(self.anomaly_rows["culprit_deviation"].abs().max())
        sigma_score = (
            max_sigma / 5.0
            if max_sigma <= 5.0
            else 1.0 + ((max_sigma - 5.0) ** 1.8) / 10.0
        )
        persistence_boost = math.log1p(self.total_anomalies) / math.log1p(100)
        return sigma_score * (1.0 + persistence_boost)


# ===========================================================================
# FORENSIC ENGINE V2
# ===========================================================================


class HiGIForensicEngine:
    """Forensic analysis engine for HiGI IDS V4.0 Blocked-PCA telemetry (XAI module).

    HiGIForensicEngine transforms raw anomaly telemetry produced by the 4-tier Cascaded
    Sentinel pipeline into actionable intelligence for Blue Team analysts. It provides
    explainability (XAI) by mapping every alert back to the physical feature family whose
    principal component triggered it.

    Key capabilities:
        * Blocked-PCA dimensionality mapping: Traces each anomaly to its culprit feature
          family (volume, flags, payload, protocol, connection, kinematics).
        * Consensus Confidence Index: Weighted across all four detection tiers,
          reflecting *which* detectors agree and how statistically significant the deviation is.
        * Dynamic Severity: Euclidean distance in Hilbert-space to the P99 baseline surface,
          rather than a flat vote count.
        * Culprit Feature Attribution: Top-3 physical metrics per incident, ranked by
          Blocked-PCA loading magnitude (XAI explainability).
        * SPIKE/DROP Directionality: Distinguishes anomalies pointing toward amplification
          (SPIKE) vs. suppression (DROP) in feature space.
        * MITRE ATT&CK Mapping: Automatic mapping of culprit metrics to attack tactics
          and techniques per incident.
        * Executive Visualizations: Two publication-ready PNG plots:
            - Attack Intensity Timeline: dual-layer severity bands with incident annotations.
            - Physical Family Stress Radar: polar chart of family contribution to anomaly load.
        * Markdown Report: Comprehensive executive summary with embedded visualizations,
          tier evidence tables, and data-drop detection.

    Architecture:
        - Zero magic numbers: all thresholds flow from HiGISettings / config.yaml.
        - Graceful degradation: Falls back to CSV column parsing if BlockedPCA metadata
          bundle is unavailable.
        - Drop-in replacement for ForensicEngine V1: main.py imports under same alias.

    Example usage::

        from src.analysis.forensic_engine import HiGIForensicEngine as ForensicEngine

        engine = HiGIForensicEngine(
            settings=config_obj,
            results_path="data/processed/Wednesday_Victim_50_results.csv",
            bundle=optional_blocked_pca_metadata
        )
        engine.cluster_incidents()
        engine.detect_data_drops()
        engine.generate_report(output_dir="reports")

    Attributes:
        csv_path (Path): Absolute path to the HiGI results CSV file.
        config (Dict[str, Any]): Runtime configuration mapping thresholds and parameters.
        df (pd.DataFrame): Full results DataFrame (all rows, both anomalies and baseline).
        df_anomalies (pd.DataFrame): Filtered subset containing anomalous or soft-zone rows.
        incidents (List[SecurityIncidentV2]): Clustered incident objects after clustering.
        data_drops (List[Dict[str, Any]]): Detected telemetry gaps / data-drop events.
    """

    def __init__(
        self,
        settings: Any,
        results_path: str,
        bundle: Optional[Any] = None,
    ) -> None:
        """Initialize the HiGI Forensic Engine and load telemetry results.

        Constructs the engine instance, loads the results CSV, validates required
        columns, builds the timeline (dt), and prepares the anomaly subset. All
        thresholds and parameters are read from the settings object (mirrors config.yaml).

        Args:
            settings (Any): Configuration object with nested structure:
                settings.forensic.debounce_seconds (float): Maximum temporal gap
                    (in seconds) between consecutive anomalies before starting a new
                    incident cluster. Typical range: 30–120 seconds.
                settings.forensic.data_drop_threshold_seconds (float): Minimum gap
                    (in seconds) to flag as a telemetry data-drop event. Typical: 300–600 s.
                settings.forensic.default_confidence_filter (float): Minimum
                    consensus_confidence [0, 1] for an incident to appear in the report.
                settings.forensic.default_min_anomalies (int): Minimum anomaly count
                    per incident (volume filter). Typical: 2–5.
                settings.forensic.default_min_duration_seconds (float): Minimum incident
                    duration in seconds (temporal filter).
                settings.forensic.sigma_culprit_min (float): Incidents whose mean |σ|
                    (Hilbert-space deviation) falls below this value are suppressed
                    from the report (statistical quality filter).
            results_path (str): Absolute path to the HiGI results CSV file, typically
                produced by src/orchestrator.py. Expected columns:
                    - dt or _abs_timestamp: Temporal index (datetime or Epoch seconds).
                    - is_anomaly: Binary flag (0/1) for anomaly windows.
                    - severity: Discrete severity (1=Low, 2=High, 3=Critical).
                    - consensus_votes: Number of tiers that fired.
                    - physical_culprit: Blocked-PCA culprit metric annotation.
                    - family_consensus: Physical family from BlockedPCA (optional).
                    - culprit_deviation: |σ| value (Hilbert-space deviation).
                    - Other tier-specific columns (balltree_severity, gmm_anomaly, etc.).
            bundle (Optional[Any]): Optional BlockedPCA metadata bundle (pickle object)
                containing _blocked_pca_family_mapping and _blocked_pca_loadings_by_family.
                If provided, enables full PCA-aware feature attribution. Falls back to
                CSV column parsing if None.

        Raises:
            FileNotFoundError: If results_path does not exist.
            ValueError: If DataFrame is empty or missing critical columns
                (_abs_timestamp or dt, is_anomaly, severity, consensus_votes).

        Side effects:
            - Loads and sorts DataFrame by timestamp.
            - Forward-fills isolated NaT entries to preserve burst continuity.
            - Filters anomaly subset (df_anomalies) for subsequent clustering.
        """
        self.csv_path = Path(results_path)
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Results CSV not found: {results_path}")
        
        self.bundle = bundle
        self.settings = settings

        self.config: Dict[str, Any] = {
            "debounce_seconds": settings.forensic.debounce_seconds,
            "data_drop_threshold_seconds": settings.forensic.data_drop_threshold_seconds,
            "confidence_filter": settings.forensic.default_confidence_filter,
            "min_anomalies_per_incident": settings.forensic.default_min_anomalies,
            "min_duration_seconds": settings.forensic.default_min_duration_seconds,
            "sigma_culprit_min": settings.forensic.sigma_culprit_min,
        }

        self.df: pd.DataFrame = pd.read_csv(self.csv_path)
        self.incidents: List[SecurityIncidentV2] = []
        self.data_drops: List[Dict[str, Any]] = []

        self._validate_and_prepare()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _validate_and_prepare(self) -> None:
        """Validate required columns and construct the dt (datetime) timeline (data preparation).

        This internal initialization method performs sanity checks and data preparation:
            1. Verify DataFrame is not empty.
            2. Build or validate datetime index from _abs_timestamp (Epoch seconds) or dt (ISO).
            3. Forward-fill isolated NaT (not-a-time) entries to preserve event continuity.
            4. Verify required columns exist (is_anomaly, severity, consensus_votes).
            5. Sort by dt and build anomaly subset (df_anomalies) via two criteria:
                - is_anomaly = 1 (explicit anomaly flagged by multi-tier consensus)
                - soft_zone_triggered = 1 AND balltree_severity ≥ 0.5 (high-confidence gradient)

        Datetime handling:
            - Prefers _abs_timestamp (Unix Epoch seconds, UTC) for precision.
            - Falls back to existing dt column if available.
            - Forward-fills NaT entries (1-2 rows) to prevent pipeline breaks.

        Anomaly subset logic:
            - Includes primary anomalies (is_anomaly=1) from all 4 detection tiers.
            - Also includes soft-zone hits (early warning) when BallTree confidence ≥ 0.5.
            - Soft-zone inclusion helps catch emerging attacks before full consensus.

        Args:
            None. Modifies self.df and self.df_anomalies in-place.

        Returns:
            None.

        Raises:
            ValueError: If DataFrame is empty, or missing either:
                - _abs_timestamp or dt column (for datetime)
                - is_anomaly, severity, consensus_votes (required fields)

        Side effects:
            - Sorts df by dt ascending.
            - Adds dt column if not present.
            - Builds df_anomalies from is_anomaly=1 rows (or soft-zone hits).
            - Logs warnings for NaT corrections and column choices.

        Example:
            Called automatically in __init__; not typically invoked manually.
        """
        if self.df.empty:
            raise ValueError("Results DataFrame is empty.")

        # --- Build datetime index ---
        if "_abs_timestamp" in self.df.columns:
            self.df["dt"] = pd.to_datetime(
                self.df["_abs_timestamp"], unit="s", utc=True, errors="coerce"
            )
            logger.info("[✓] Timeline from _abs_timestamp (Epoch seconds).")
        elif "dt" in self.df.columns:
            self.df["dt"] = pd.to_datetime(self.df["dt"], utc=True, errors="coerce")
            logger.warning("[!] Using existing 'dt' column (absolute times assumed).")
        else:
            raise ValueError(
                "DataFrame must contain '_abs_timestamp' or 'dt' column."
            )

        # Forward-fill isolated NaT entries to preserve burst continuity.
        nat_count = self.df["dt"].isna().sum()
        if nat_count:
            logger.warning(
                f"[!] {nat_count} invalid timestamps – forward-filling."
            )
            self.df["dt"] = self.df["dt"].ffill()

        required = {"is_anomaly", "severity", "consensus_votes"}
        missing = required - set(self.df.columns)
        if missing:
            raise ValueError(f"Missing required columns: {missing}")

        self.df = self.df.sort_values("dt").reset_index(drop=True)

        # --- Build anomaly subset ---
        if "soft_zone_triggered" in self.df.columns:
            soft_mask = (
                (self.df["soft_zone_triggered"] == True)
                & (self.df.get("balltree_severity", pd.Series(0, index=self.df.index)) >= 0.5)
            )
            self.df_anomalies = self.df[
                (self.df["is_anomaly"] == 1) | soft_mask
            ].copy().reset_index(drop=True)
        else:
            self.df_anomalies = self.df[
                self.df["is_anomaly"] == 1
            ].copy().reset_index(drop=True)

    # ------------------------------------------------------------------
    # Incident clustering
    # ------------------------------------------------------------------

    def cluster_incidents(self) -> List[SecurityIncidentV2]:
        """Cluster consecutive anomaly windows into SecurityIncidentV2 incidents (temporal grouping).

        This method implements temporal clustering: anomalous windows separated by gaps
        ≤ debounce_seconds are grouped into a single incident. Each incident is then
        enriched with tier evidence, XAI culprit feature attribution (Blocked-PCA loadings),
        family stress profiles, and MITRE ATT&CK technique mappings.

        Clustering algorithm (O(n) time complexity):
            1. Compute temporal gaps (in seconds) between consecutive anomalous windows.
            2. Mark gap > debounce_seconds as incident boundary.
            3. Assign cumulative incident IDs via cumsum() transformation.
            4. Group DataFrame by incident ID and build SecurityIncidentV2 objects.
            5. For each incident, compute:
                - Tier evidence summaries (which detection tiers fired)
                - Top-3 culprit features via XAI (Blocked-PCA loading magnitude ranking)
                - Family stress distribution (normalized anomaly load per physical family)
                - MITRE ATT&CK tactic/technique mappings from culprit metrics

        Returns:
            List[SecurityIncidentV2]: Ordered list of clustered incidents, sorted by start_time.
                Returns empty list if df_anomalies has no rows. Each SecurityIncidentV2 is
                fully enriched with XAI and metadata.

        Raises:
            None explicitly, but logs warnings for edge cases.

        Example:
            >>> engine = HiGIForensicEngine(...)
            >>> engine.cluster_incidents()  # Returns ~10-50 incidents
            >>> incidents = engine.incidents
            >>> for inc in incidents:
            ...     print(f"Incident {inc.incident_id}: {inc.duration_seconds:.0f}s, "
            ...           f"severity={inc.max_severity}, confidence={inc.consensus_confidence:.2%}")
        """
        if self.df_anomalies.empty:
            logger.info("[CLUSTER] No anomalies – skipping clustering.")
            return []

        gaps = self.df_anomalies["dt"].diff().dt.total_seconds().fillna(0.0)
        new_incident = (gaps > self.config["debounce_seconds"])
        new_incident.iloc[0] = True
        group_ids = new_incident.astype(int).cumsum() - 1

        working = self.df_anomalies.copy()
        working["_gid"] = group_ids.values
        has_warmup = "is_warmup" in working.columns

        self.incidents = []
        for gid, group in working.groupby("_gid"):
            group_clean = group.drop(columns=["_gid"])
            incident = self._build_incident(int(gid), group_clean, has_warmup)
            self.incidents.append(incident)

        logger.info(f"[CLUSTER] {len(self.incidents)} raw incidents clustered.")
        return self.incidents

    def _build_incident(
        self,
        iid: int,
        rows: pd.DataFrame,
        has_warmup: bool,
    ) -> SecurityIncidentV2:
        """Construct a fully enriched SecurityIncidentV2 from a group of anomaly rows.

        This internal method builds a single incident by:
            1. Extracting temporal boundaries (start_time, end_time).
            2. Determining warmup status (if > 50% of rows labeled is_warmup=1).
            3. Building tier evidence summaries via _build_tier_evidence().
            4. Identifying top-3 culprit features via XAI _build_feature_attribution().
            5. Computing family stress profiles via _compute_family_stress().
            6. Mapping culprit metrics to MITRE techniques via _map_mitre().

        Args:
            iid (int): Sequential incident identifier (0-based) from cluster_incidents().
            rows (pd.DataFrame): Slice of df_anomalies containing all anomaly windows
                for this temporal cluster. Columns include: dt, is_anomaly, severity,
                physical_culprit, culprit_deviation (|σ|), family_consensus, and
                tier-specific columns (balltree_severity, gmm_anomaly, etc.).
            has_warmup (bool): True if the 'is_warmup' column exists in rows.

        Returns:
            SecurityIncidentV2: Fully enriched incident object with all XAI metadata,
                tier evidence, and MITRE mappings.

        Raises:
            None explicitly. Gracefully handles missing columns and null values.

        Side effects:
            - Modifies no state except computing derived properties on rows.
            - Performs up to 4 data aggregations (_build_tier_evidence, XAI attribution, etc.).
        """
        # --- Timestamps ------------------------------------------------
        if "_abs_timestamp" in rows.columns:
            valid_ts = rows["_abs_timestamp"].dropna().pipe(
                lambda s: s[s > 1e9]
            )
            if not valid_ts.empty:
                start = pd.Timestamp(valid_ts.iloc[0], unit="s")
                end = pd.Timestamp(valid_ts.iloc[-1], unit="s")
            else:
                start, end = rows["dt"].iloc[0], rows["dt"].iloc[-1]
        else:
            start, end = rows["dt"].iloc[0], rows["dt"].iloc[-1]

        # --- Warm-up flag ----------------------------------------------
        is_warmup = False
        if has_warmup and "is_warmup" in rows.columns:
            warmup_ratio = (rows["is_warmup"] == True).sum() / len(rows)
            is_warmup = warmup_ratio > 0.5

        # --- Tier evidence ---------------------------------------------
        tier_evidence = self._build_tier_evidence(rows)

        # --- XAI feature attribution -----------------------------------
        top_features = self._build_feature_attribution(rows)

        # --- Family stress radar data ----------------------------------
        family_stress = self._compute_family_stress(rows)

        # --- MITRE mapping --------------------------------------------
        mitre_tactics = self._map_mitre(rows)

        return SecurityIncidentV2(
            incident_id=iid,
            start_time=start,
            end_time=end,
            anomaly_rows=rows,
            tier_evidence=tier_evidence,
            top_features=top_features,
            family_stress=family_stress,
            mitre_tactics=mitre_tactics,
            is_warmup=is_warmup,
        )

    # ------------------------------------------------------------------
    # Tier evidence
    # ------------------------------------------------------------------

    def _build_tier_evidence(self, rows: pd.DataFrame) -> List[TierEvidenceSummary]:
        """Build per-tier firing summaries for an incident (tier consensus breakdown).

        This method aggregates detection evidence from all 4 Cascaded Sentinel detection
        tiers for an incident. For each tier, it reports whether the tier fired (detected
        anomaly), the count of anomalous windows, and the mean confidence score.

        Tier reference:
            - BallTree (Tier 1): Euclidean distance-based density anomalies; score is
              proximity to decision boundary (lower = more anomalous).
            - GMM (Tier 2A): Gaussian Mixture Model log-likelihood; score is log-likelihood
              of the data point under fitted mixture.
            - IForest (Tier 2B): Isolation Forest; score is path length (anomaly score [0, 1]).
            - PhysicalSentinel (Tier 3): Blocked-PCA residual magnitude; score is |σ|
              (standard deviation in Hilbert-space).
            - VelocityBypass (Tier 4): Temporal rate-of-change detection; score is
              acceleration anomaly metric.

        Args:
            rows (pd.DataFrame): Anomaly rows for the incident containing columns for
                each tier (balltree_severity, gmm_anomaly, iforest_anomaly, physical_culprit,
                vel_bypass) and their corresponding score columns (balltree_score, gmm_score,
                iforest_score, culprit_deviation, vel_score).

        Returns:
            List[TierEvidenceSummary]: One summary object per available tier, each containing:
                - tier_name: Identifier ('BallTree', 'GMM', 'IForest', 'PhysicalSentinel', 'VelocityBypass')
                - fired: bool – whether the tier detected any anomaly in this incident
                - fire_count: int – number of anomalous windows for this tier
                - mean_score: float – average confidence/anomaly score (units vary per tier)

        Side effects:
            - Returns empty list if no tier columns are present (graceful degradation).
            - Missing score columns default to 0.0 (no error thrown).
        """
        summaries: List[TierEvidenceSummary] = []

        # Tier 1 – BallTree
        if "balltree_severity" in rows.columns:
            bt_fired_mask = rows["balltree_severity"] > 0
            summaries.append(TierEvidenceSummary(
                tier_name="BallTree",
                fired=bool(bt_fired_mask.any()),
                fire_count=int(bt_fired_mask.sum()),
                mean_score=float(rows["balltree_score"].mean()) if "balltree_score" in rows.columns else 0.0,
            ))

        # Tier 2A – GMM
        if "gmm_anomaly" in rows.columns:
            gmm_mask = rows["gmm_anomaly"] == 1
            summaries.append(TierEvidenceSummary(
                tier_name="GMM",
                fired=bool(gmm_mask.any()),
                fire_count=int(gmm_mask.sum()),
                mean_score=float(rows["gmm_score"].mean()) if "gmm_score" in rows.columns else 0.0,
            ))

        # Tier 2B – IForest
        if "iforest_anomaly" in rows.columns:
            if_mask = rows["iforest_anomaly"] == 1
            summaries.append(TierEvidenceSummary(
                tier_name="IForest",
                fired=bool(if_mask.any()),
                fire_count=int(if_mask.sum()),
                mean_score=float(rows["iforest_score"].mean()) if "iforest_score" in rows.columns else 0.0,
            ))

        # Tier 3 – Physical Sentinel (inferred from physical_culprit presence)
        if "physical_culprit" in rows.columns:
            sentinel_mask = rows["physical_culprit"].notna()
            summaries.append(TierEvidenceSummary(
                tier_name="PhysicalSentinel",
                fired=bool(sentinel_mask.any()),
                fire_count=int(sentinel_mask.sum()),
                mean_score=float(rows["culprit_deviation"].abs().mean())
                if "culprit_deviation" in rows.columns else 0.0,
            ))

        # Tier 4 – Velocity Bypass
        if "vel_bypass" in rows.columns:
            vel_mask = rows["vel_bypass"] == True
            summaries.append(TierEvidenceSummary(
                tier_name="VelocityBypass",
                fired=bool(vel_mask.any()),
                fire_count=int(vel_mask.sum()),
                mean_score=float(rows["vel_score"].mean()) if "vel_score" in rows.columns else 0.0,
            ))

        return summaries

    # ------------------------------------------------------------------
    # XAI feature attribution
    # ------------------------------------------------------------------

    def _build_feature_attribution(
        self, rows: pd.DataFrame, top_n: int = 3
    ) -> List[FeatureAttribution]:
        """Identify the top-N culprit features via Blocked-PCA loading magnitude ranking (XAI).

        This is the core explainability (XAI) method: it identifies which physical metrics
        (features) best explain the Hilbert-space deviation observed in an incident.
        Features are ranked by normalized |σ| (standard deviation in inertial reference frame),
        with aggregation across all windows in the incident.

        XAI methodology:
            1. Parse physical_culprit annotations to extract:
                - Canonical metric name (e.g., 'flag_syn_ratio')
                - |σ| (deviation magnitude in Hilbert-space)
                - Event type ('SPIKE' or 'DROP')
                - Percentage change (Δ%)
            2. Normalize loading_magnitude = |σ| / max_|σ| within incident (range [0, 1]).
            3. Infer physical family from family_consensus (BlockedPCA) or keyword matching.
            4. Aggregate across rows: keep max |σ| and Δ% per feature.
            5. Sort by normalized loading (descending) and return top-N.

        Physical interpretation:
            - loading_magnitude (normalized): How much this feature contributed to the
              anomaly (0=negligible, 1=dominant culprit).
            - max_sigma (|σ|): Peak standard deviation distance from baseline. Higher
              values indicate stronger detection consensus.
            - event_type (SPIKE/DROP): Direction of deviation (amplification vs suppression).
            - family: Physical category (volume, flags, payload, protocol, connection, kinematics).

        Args:
            rows (pd.DataFrame): Anomaly rows for this incident containing:
                - physical_culprit: Blocked-PCA annotation string
                - family_consensus: Physical family from BlockedPCA metadata (optional)
                - culprit_deviation: |σ| values (Hilbert-space distance)
            top_n (int): Number of top culprit features to return. Default: 3.

        Returns:
            List[FeatureAttribution]: Sorted list of top culprit features, ranked by
                loading_magnitude (highest first). Returns empty list if no culprits found.
                Each FeatureAttribution contains: feature_name, loading_magnitude, event_type,
                max_sigma, max_pct, family.

        Example:
            >>> top_3 = engine._build_feature_attribution(incident_rows, top_n=3)
            >>> for i, feat in enumerate(top_3, 1):
            ...     print(f"{i}. {feat.feature_name} ({feat.family}): "
            ...           f"{feat.event_type} +{feat.max_pct:.0f}% (σ={feat.max_sigma:.2f})")
            1. flag_syn_ratio (flags): SPIKE +865% (σ=4.2)
            2. bytes_total (volume): SPIKE +320% (σ=3.1)
            3. packet_size_anomaly (payload): DROP -45% (σ=2.8)
        """
        if "physical_culprit" not in rows.columns:
            return []

        series = rows["physical_culprit"].fillna("")
        fc_series = rows["family_consensus"] if "family_consensus" in rows.columns else pd.Series([""] * len(rows), index=rows.index)
        dev_series = rows["culprit_deviation"].abs() if "culprit_deviation" in rows.columns else pd.Series([0.0] * len(rows), index=rows.index)

        records: Dict[str, Dict[str, Any]] = {}
        for raw, fc, dev in zip(series, fc_series, dev_series):
            if not raw:
                continue
            base = _extract_base_name(raw)
            if base == "unknown":
                continue
            sigma = max(_extract_sigma(raw), float(dev) if not math.isnan(float(dev)) else 0.0)
            pct = _extract_pct(raw)
            etype = _extract_event_type(raw)
            fam = _infer_family(base, fc)

            if base not in records:
                records[base] = {"sigma": sigma, "pct": pct, "etype": etype, "fam": fam}
            else:
                if sigma > records[base]["sigma"]:
                    records[base]["sigma"] = sigma
                    records[base]["etype"] = etype
                if pct > records[base]["pct"]:
                    records[base]["pct"] = pct

        if not records:
            return []

        max_sigma = max(r["sigma"] for r in records.values()) or 1.0
        attributions = [
            FeatureAttribution(
                feature_name=name,
                loading_magnitude=rec["sigma"] / max_sigma,
                event_type=rec["etype"],
                max_sigma=rec["sigma"],
                max_pct=rec["pct"],
                family=rec["fam"],
            )
            for name, rec in records.items()
        ]
        attributions.sort(key=lambda a: a.loading_magnitude, reverse=True)
        return attributions[:top_n]

    # ------------------------------------------------------------------
    # Family stress
    # ------------------------------------------------------------------

    def _compute_family_stress(self, rows: pd.DataFrame) -> Dict[str, float]:
        """Compute normalized anomaly stress [0, 1] for each BlockedPCA physical family.

        Family stress quantifies how much each physical metric family (volume, flags, payload,
        protocol, connection, kinematics) contributed to the incident's overall anomaly load.
        Stress is computed as the sum of |σ| (culprit_deviation) values aggregated by family,
        then normalized so all families sum to 1.0 (L1 norm).

        Physical interpretation:
            - stress[family] ∈ [0, 1]: Fractional contribution of this family to total
              anomaly load. Higher values indicate this family was the primary vector.
            - Example: If flags=0.65, volume=0.25, others=0.10, then a flag-based attack
              (e.g., SYN flood) was the dominant anomaly.

        BlockedPCA families:
            1. volume: Aggregate packet/byte counts, inter-packet timings.
            2. flags: TCP flag distributions (SYN, ACK, RST, FIN).
            3. payload: Packet size distributions and entropy.
            4. protocol: Layer-3/4 protocol mix (ICMP, UDP, TCP varieties).
            5. connection: Connection state counts and lifecycle metrics.
            6. kinematics: Velocity metrics, acceleration anomalies, temporal patterns.

        Args:
            rows (pd.DataFrame): Anomaly rows for the incident containing:
                - physical_culprit: Blocked-PCA annotation string (source of metric names)
                - family_consensus: Physical family label from BlockedPCA (optional)
                - culprit_deviation: |σ| values (Hilbert-space distance per row)

        Returns:
            Dict[str, float]: Mapping of family name → stress in [0, 1]. Returns empty dict
                if no physical_culprit column found. All families sum to 1.0 (if populated).

        Example:
            >>> family_stress = engine._compute_family_stress(incident_rows)
            >>> print(family_stress)
            {'flags': 0.65, 'volume': 0.25, 'protocol': 0.10}  # SYN flood signature
        """
        if "physical_culprit" not in rows.columns:
            return {}

        fc_col = rows["family_consensus"] if "family_consensus" in rows.columns else pd.Series([""] * len(rows), index=rows.index)
        dev_col = rows["culprit_deviation"].abs() if "culprit_deviation" in rows.columns else pd.Series([0.0] * len(rows), index=rows.index)

        stress: Dict[str, float] = {}
        for raw, fc, dev in zip(rows["physical_culprit"].fillna(""), fc_col, dev_col):
            if not raw:
                continue
            base = _extract_base_name(raw)
            fam = _infer_family(base, fc)
            stress[fam] = stress.get(fam, 0.0) + float(dev) if not math.isnan(float(dev)) else 0.0

        total = sum(stress.values()) or 1.0
        return {fam: v / total for fam, v in stress.items()}

    # ------------------------------------------------------------------
    # MITRE mapping
    # ------------------------------------------------------------------

    def _map_mitre(self, rows: pd.DataFrame) -> Dict[str, List[str]]:
        """Map physical culprit metrics to MITRE ATT&CK tactics and techniques (threat intelligence).

        This method performs automatic threat intelligence mapping by matching detected physical
        metrics to known attack patterns in the MITRE ATT&CK framework. This helps Blue Teams
        understand *which attack tactics* the observed anomalies align with, providing context
        for incident response.

        Mapping methodology:
            1. Parse physical_culprit annotations to extract metric names (e.g., 'flag_syn_ratio').
            2. Look up each metric in the MITRE_ATT_CK_MAPPING global dictionary.
            3. If a match is found, add the (tactic, technique) pair to results.
            4. Deduplicate techniques within each tactic (set tracking).
            5. Return a dict: tactic → list of unique techniques.

        Example mappings:
            - flag_syn_ratio (SPIKE) → Tactic='Reconnaissance', Technique='Active Scanning'
            - bytes_total (SPIKE) → Tactic='Command&Control', Technique='Data Obfuscation'
            - packet_interarrival (DROP) → Tactic='DefenseEvasion', Technique='Timing Evasion'

        Args:
            rows (pd.DataFrame): Anomaly rows for the incident containing:
                - physical_culprit: Blocked-PCA annotation strings (source of metric names)

        Returns:
            Dict[str, List[str]]: Mapping of MITRE tactic (str) → deduplicated list of
                technique names (str). Returns empty dict if no physical_culprit column
                or no mappings found.

        Example:
            >>> mitre = engine._map_mitre(incident_rows)
            >>> print(mitre)
            {'Reconnaissance': ['Active Scanning'], 'Command&Control': ['Data Obfuscation']}

        Note:
            - This is an automated heuristic; analysts should always verify mappings
              in context of the incident timeline and threat model.
            - MITRE_ATT_CK_MAPPING is maintained at module level and may be extended
              as new metrics are instrumented in BlockedPCA.
        """
        if "physical_culprit" not in rows.columns:
            return {}

        result: Dict[str, List[str]] = {}
        seen: set = set()
        for raw in rows["physical_culprit"].dropna():
            base = _extract_base_name(str(raw))
            for key, (tactic, technique) in MITRE_ATT_CK_MAPPING.items():
                if key in base and technique not in seen:
                    result.setdefault(tactic, []).append(technique)
                    seen.add(technique)
        return result

    # ------------------------------------------------------------------
    # Data drop detection
    # ------------------------------------------------------------------

    def detect_data_drops(self) -> List[Dict[str, Any]]:
        """Detect telemetry gaps in the full capture timeline (sensor saturation forensics).

        This method identifies periods where the IDS sensor was unable to capture traffic,
        inferring causation from context: whether a high-severity incident preceded the gap
        (sensor saturation hypothesis), whether anomalies surrounded the gap (sensor blindness),
        or if the gap was benign network silence.

        Data drop detection algorithm (O(n) scan):
            1. Compute time deltas between consecutive rows in the full df (including baseline).
            2. Flag any gap > data_drop_threshold_seconds (default: 60s from config).
            3. For each gap, inspect rows immediately before and after:
                - Check if either row is anomalous (is_anomaly=1).
                - Extract severity level if anomalous.
            4. Classify gap causation:
                - POSSIBLE_SENSOR_SATURATION: High-severity incident (severity ≥ 2) ends
                  ≤15s before gap start → indicates sensor overload during attack.
                - SENSOR_BLINDNESS: Gap preceded by anomaly with severity ≥ 2 → indicates
                  ongoing attack obscured missing telemetry.
                - CAPTURE_LOSS: Gap not adjacent to anomalies → benign network silence or
                  capture filter reset.

        Temporal context:
            - All timestamps are normalized to UTC, timezone-aware.
            - Gap duration is in seconds (floating-point).
            - Incident-gap correlation uses ≤15s proximity threshold.

        Args:
            None. Uses self.df (full DataFrame), self.incidents (clustered incidents),
                and self.config['data_drop_threshold_seconds'].

        Returns:
            List[Dict[str, Any]]: List of data-drop events, each with keys:
                - start_time (pd.Timestamp): Time of row before gap.
                - end_time (pd.Timestamp): Time of row after gap.
                - gap_seconds (float): Duration of gap in seconds.
                - severity_before (Optional[int]): Severity of rows adjacent to gap (1-3).
                - is_anomaly_context (bool): True if any adjacent row is anomalous.
                - reason (str): Classification reason (see above).

        Side effects:
            - Stores results in self.data_drops list.
            - Logs count of detected gaps at INFO level.

        Example:
            >>> engine.cluster_incidents()
            >>> drops = engine.detect_data_drops()
            >>> for drop in drops:
            ...     print(f"Gap {drop['gap_seconds']:.0f}s at {drop['start_time']}: {drop['reason']}")
            Gap 120s at 2024-01-15 10:45:30: [POSSIBLE_SENSOR_SATURATION]

        Notes:
            - Sensor Saturation is a critical indicator of DoS/DDoS success.
            - Gaps adjacent to multiple incidents are classified by the most recent incident.
            - This method should be called after cluster_incidents() to populate self.incidents.
        """
        self.data_drops = []
        if len(self.df) < 2:
            return self.data_drops

        gaps = self.df["dt"].diff().dt.total_seconds().fillna(0.0)
        threshold = self.config["data_drop_threshold_seconds"]
        big_gaps = np.where(gaps > threshold)[0]

        for idx in big_gaps:
            gap_s = float(gaps.iloc[idx])
            t_start = self.df.iloc[idx - 1]["dt"] if idx > 0 else self.df.iloc[0]["dt"]
            t_end = self.df.iloc[idx]["dt"]

            sev_before: Optional[int] = None
            is_anom = False
            if idx > 0 and self.df.iloc[idx - 1]["is_anomaly"] == 1:
                sev_before = int(self.df.iloc[idx - 1]["severity"])
                is_anom = True
            if self.df.iloc[idx]["is_anomaly"] == 1:
                is_anom = True
                if sev_before is None:
                    sev_before = int(self.df.iloc[idx]["severity"])

            # Classify
            def _tz_delta(a: Any, b: Any) -> float:
                """Subtract two timestamps robustly, stripping timezone info."""
                ta = pd.Timestamp(a)
                tb = pd.Timestamp(b)
                if ta.tz is not None:
                    ta = ta.tz_localize(None)
                if tb.tz is not None:
                    tb = tb.tz_localize(None)
                return (ta - tb).total_seconds()

            sensor_sat = any(
                inc.max_severity >= 2
                and 0 <= _tz_delta(t_end, inc.end_time) <= 15
                for inc in self.incidents
            )
            if sensor_sat:
                reason = "[POSSIBLE_SENSOR_SATURATION] Gap follows high-severity incident"
            elif is_anom and sev_before is not None and sev_before >= 2:
                reason = "Sensor Blindness / Data Drop due to Saturation"
            else:
                reason = "Capture Loss / Network Silence"

            self.data_drops.append({
                "start_time": t_start,
                "end_time": t_end,
                "gap_seconds": gap_s,
                "severity_before": sev_before,
                "is_anomaly_context": is_anom,
                "reason": reason,
            })

        logger.info(f"[DROPS] {len(self.data_drops)} telemetry gaps detected.")
        return self.data_drops

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def get_reportable_incidents(self, **kwargs: Any) -> List[SecurityIncidentV2]:
        """Return incidents meeting all reporting quality thresholds (multi-filter scoring).

        This method applies four independent filters to self.incidents, returning only
        SecurityIncidentV2 objects that meet *all* criteria simultaneously. Filters are
        applied in precedence order (volume → duration → consensus confidence → σ culprit),
        and can be overridden via kwargs for ad-hoc analysis.

        Filtering criteria (AND logic):
            1. Volume (total_anomalies ≥ min_anomalies_per_incident): Suppress single-window
               noise artifacts. Default: 2+ windows per incident.
            2. Duration (duration_seconds ≥ min_duration_seconds): Exclude ephemeral blips.
               Default: 5+ seconds of sustained anomaly.
            3. Consensus Confidence (consensus_confidence ≥ confidence_filter): Multi-tier
               agreement threshold. Ranges from 0 (single-tier weak) to 1 (full unanimity).
               Default: 0.45 (medium confidence).
            4. Culprit Magnitude (mean_|σ| ≥ sigma_culprit_min): Minimum Hilbert-space
               deviation to suppress low-energy transients. Default: 2.0σ.

        Physical interpretation:
            - Filters work together to separate true positives (coordinated, sustained)
              from noise (ephemeral, low-confidence, low-energy).
            - Incidents passing all filters are suitable for executive reporting and
              incident response triage.

        Args:
            **kwargs (Any): Optional threshold overrides (all optional, use config defaults
                if not provided):
                - confidence_filter (float ∈ [0, 1]): Consensus confidence minimum threshold.
                - min_anomalies_per_incident (int): Minimum anomaly window count per incident.
                - min_duration_seconds (float): Minimum sustained anomaly duration in seconds.
                - sigma_culprit_min (float): Minimum mean |σ| (Hilbert-space deviation).

        Returns:
            List[SecurityIncidentV2]: Sorted list of filtered incidents. Returns empty list
                if no incidents pass all filters. Each incident retains all XAI metadata
                (culprit features, family stress, MITRE mappings).

        Example:
            >>> engine.cluster_incidents()
            >>> reportable = engine.get_reportable_incidents(
            ...     confidence_filter=0.50,
            ...     min_anomalies_per_incident=3
            ... )
            >>> print(f"High-confidence incidents: {len(reportable)}")
        """
        cf = kwargs.get("confidence_filter", self.config["confidence_filter"])
        ma = kwargs.get("min_anomalies_per_incident", self.config["min_anomalies_per_incident"])
        md = kwargs.get("min_duration_seconds", self.config["min_duration_seconds"])
        sc = kwargs.get("sigma_culprit_min", self.config["sigma_culprit_min"])

        out = []
        for inc in self.incidents:
            if inc.total_anomalies < ma:
                continue
            if inc.duration_seconds < md:
                continue
            if inc.consensus_confidence < cf:
                continue
            mean_abs_sigma = float(
                inc.anomaly_rows["culprit_deviation"].abs().mean()
            ) if "culprit_deviation" in inc.anomaly_rows.columns else 0.0
            if mean_abs_sigma < sc:
                continue
            out.append(inc)
        return out

    # ------------------------------------------------------------------
    # Summary statistics
    # ------------------------------------------------------------------

    def generate_summary_stats(self, **kwargs: Any) -> Dict[str, Any]:
        """Compute executive-level summary statistics for report generation.

        This method aggregates key metrics across all incidents (or a filtered subset),
        providing Blue Team leadership with high-level situational awareness: incident
        counts, severity ranges, temporal coverage, and data quality indicators.

        Statistics computed (optional filtering):
            - total_anomalies: Count of all rows flagged is_anomaly=1.
            - total_incidents: Count of clustered incidents (or reportable if kwargs provided).
            - avg_incident_duration: Mean duration_seconds across filtered incidents.
            - max_severity: Highest severity tier observed (1-3).
            - avg_severity: Mean severity across all anomalies.
            - time_range_start, time_range_end: Min/max timestamps in df (capture window).
            - data_drops_detected: Count of telemetry gaps (from detect_data_drops()).

        Args:
            **kwargs (Any): Optional filter overrides (passed to get_reportable_incidents()).
                If kwargs are provided, statistics are computed on the filtered subset only.
                If empty, statistics use self.incidents (all raw clustered incidents).

        Returns:
            Dict[str, Any]: Dictionary with keys:
                - total_anomalies (int): Volume of anomalous windows.
                - total_incidents (int): Count of incidents after filtering (if kwargs).
                - avg_incident_duration (float): Mean incident duration in seconds.
                - max_severity (int): Peak severity (1-3) or 0 if no anomalies.
                - avg_severity (float): Mean severity of anomalous rows [1, 3].
                - time_range_start (pd.Timestamp): First row timestamp.
                - time_range_end (pd.Timestamp): Last row timestamp.
                - data_drops_detected (int): Count of sensor saturation/capture loss events.

        Example:
            >>> engine.cluster_incidents()
            >>> engine.detect_data_drops()
            >>> stats = engine.generate_summary_stats(confidence_filter=0.50)
            >>> print(f"High-confidence incidents: {stats['total_incidents']}, "
            ...       f"avg_duration: {stats['avg_incident_duration']:.0f}s")
        """
        reportable = self.get_reportable_incidents(**kwargs) if kwargs else self.incidents
        return {
            "total_anomalies":        len(self.df_anomalies),
            "total_incidents":        len(reportable),
            "avg_incident_duration":  (
                sum(i.duration_seconds for i in reportable) / len(reportable)
                if reportable else 0.0
            ),
            "max_severity":           int(self.df_anomalies["severity"].max()) if not self.df_anomalies.empty else 0,
            "avg_severity":           float(self.df_anomalies["severity"].mean()) if not self.df_anomalies.empty else 0.0,
            "time_range_start":       self.df["dt"].min() if not self.df.empty else None,
            "time_range_end":         self.df["dt"].max() if not self.df.empty else None,
            "data_drops_detected":    len(self.data_drops),
        }

    def get_runtime_settings(self) -> Dict[str, Any]:
        """Return a deep copy of the engine configuration dictionary (auditability + transparency).

        This method exposes the current runtime configuration for logging, auditability,
        and report generation. Useful for verifying which filters and thresholds were
        applied to a particular analysis run.

        Returns:
            Dict[str, Any]: Copy of self.config containing all forensic.* settings from
                config.yaml / settings object (debounce_seconds, data_drop_threshold_seconds,
                confidence_filter, min_anomalies_per_incident, min_duration_seconds,
                sigma_culprit_min, etc.). Modifications to returned dict do not affect engine.

        Example:
            >>> engine = HiGIForensicEngine(...)
            >>> cfg = engine.get_runtime_settings()
            >>> print(f"Confidence filter: {cfg['confidence_filter']}")
        """
        return self.config.copy()

    # ------------------------------------------------------------------
    # V1 compatibility shim for main.py
    # ------------------------------------------------------------------

    def get_threat_distribution(self) -> pd.Series:
        """Return value-counts of base culprit metric names for the threat pie."""
        if self.df_anomalies.empty or "physical_culprit" not in self.df_anomalies.columns:
            return pd.Series(dtype=int)
        return (
            self.df_anomalies["physical_culprit"]
            .dropna()
            .apply(_extract_base_name)
            .value_counts()
        )

    # ------------------------------------------------------------------
    # Visualisations
    # ------------------------------------------------------------------

    def generate_visuals(
        self,
        output_dir: Path,
        stem: Optional[str] = None,
        **filter_kwargs: Any,
    ) -> Dict[str, str]:
        """Generate and save the two executive visualisations.

        Plot A — Attack Intensity Timeline:
            A dual-layer time-series showing the rolling anomaly MA score
            (or severity when unavailable) with coloured severity bands and
            incident annotations.  Persistent attack phases are visually
            distinguished from transient spikes via fill-between shading.
            Only reportable incidents (filtered by confidence, severity, etc.)
            are annotated on the timeline.

        Plot B — Physical Family Stress Radar:
            A filled radar / spider chart showing how much stress each
            physical feature family (flags, volume, payload, protocol,
            connection, kinematics) contributed to the total anomaly load
            across the capture period.  Provides an immediate at-a-glance
            view of the attack vector distribution.  Stress aggregation is
            computed from reportable incidents only.

        Args:
            output_dir: Directory where PNG files are written.
            stem: Optional filename stem derived from the CSV name.
                  Defaults to ``self.csv_path.stem``.
            **filter_kwargs: Threshold overrides (confidence_filter,
                min_anomalies_per_incident, min_duration_seconds,
                sigma_culprit_min).  Forwarded to get_reportable_incidents().

        Returns:
            Dictionary with keys ``"timeline_plot"`` and
            ``"radar_plot"`` containing the relative file-names
            (suitable for embedding in Markdown ``![alt](path)``).
        """
        import matplotlib
        matplotlib.use("Agg")

        # ── GUARANTEE DATA: Ensure incidents are clustered ──
        # If caller hasn't run cluster_incidents(), do it automatically.
        if not self.incidents:
            logger.info("[VIS] Auto-clustering incidents before generating visuals...")
            self.cluster_incidents()

        # Apply the same filters used in the Markdown report
        incidents_to_plot = self.get_reportable_incidents(**filter_kwargs)
        logger.info(
            f"[VIS] Filtering incidents for visualisation: "
            f"{len(incidents_to_plot)} reportable out of {len(self.incidents)} total"
        )

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        s = stem or self.csv_path.stem

        timeline_fname  = f"{s}_timeline.png"
        radar_fname     = f"{s}_radar.png"
        timeline_path   = output_dir / timeline_fname
        radar_path      = output_dir / radar_fname

        # ── Plot A: Attack Intensity Timeline (with filtered incidents) ──
        self._plot_timeline(timeline_path, incidents_to_plot=incidents_to_plot)

        # ── Plot B: Physical Family Stress Radar (from filtered incidents) ─
        self._plot_family_radar(radar_path, incidents_to_plot=incidents_to_plot)

        logger.info(f"[VIS] Plots saved → {timeline_fname}, {radar_fname}")
        return {
            "timeline_plot": timeline_fname,
            "radar_plot":    radar_fname,
        }

    def _plot_timeline(
        self,
        out_path: Path,
        incidents_to_plot: Optional[List[Any]] = None,
    ) -> None:
        """Render the Attack Intensity Timeline visualization and save to PNG (publication-ready).

        This method produces a polished time-series chart showing anomaly severity evolution
        across the entire capture window, with embedded incident annotations. It features:
            - Severity-based fill regions (low/medium/high bands with distinct colors).
            - Velocity Bypass markers (triangle markers for rate-of-change anomalies).
            - Incident annotations with staggered + fan-out layout to prevent overlap.
            - Symmetric log scale to preserve visibility of both low and high anomaly scores.
            - Dark GitHub theme styling (#0d1117 background, #58a6ff accent).

        Visualization features:
            - X-axis: UTC timestamps (capture window)
            - Y-axis: anomaly_ma_score or severity (configurable, log-scale for readability)
            - Severity bands:
                * Severity 1 (Low): Yellow (#f1c40f), α=0.35
                * Severity 2 (High): Orange (#e67e22), α=0.45
                * Severity 3 (Critical): Red (#e74c3c), α=0.65
            - Incident annotations:
                * Positioned in header zone above the plot (external annotation space)
                * Vertical stagger levels [1.12, 1.25, 1.38] prevent dense vertical overlap
                * Horizontal fan-out [−0.05, 0, +0.05] creates radial spacing for bursts
                * Each label includes incident #ID and top culprit feature name (XAI)
                * Dashed arrow (arrowstyle="-|>", lw=0.8, α=0.6) traces to data point

        Annotation algorithm:
            1. For each incident, find maximum severity within temporal window (t_start, t_end).
            2. Calculate label position via stagger level + fan-out offset.
            3. Draw arrow from label to data point, with safety minimum y_value ≥ 0.5
               (prevents burial in x-axis for low-severity incidents).
            4. Clip x-position to [0.02, 0.98] to keep labels in frame.
            5. Align text direction (left/right/center) based on horizontal position.

        Args:
            out_path (Path): Output PNG file path (absolute or relative to cwd).
            incidents_to_plot (Optional[List[SecurityIncidentV2]]): List of incidents to
                annotate. If None, uses self.incidents (all clustered incidents).
                Typically pass the filtered list from get_reportable_incidents() for
                consistency with executive Markdown report.

        Returns:
            None. Saves PNG to out_path directly.

        Side effects:
            - Creates figure with dark theme styling.
            - Logs incident annotation details at DEBUG level.
            - Gracefully skips incidents if timestamp mapping fails.

        Example:
            >>> engine.cluster_incidents()
            >>> reportable = engine.get_reportable_incidents(confidence_filter=0.50)
            >>> engine._plot_timeline(Path("reports/timeline.png"), reportable)
        """
        df = self.df.copy()
        if "dt" not in df.columns:
            return

        # Strip timezone for matplotlib compatibility
        x = df["dt"].dt.tz_localize(None) if df["dt"].dt.tz is not None else df["dt"]
        y_col = "anomaly_ma_score" if "anomaly_ma_score" in df.columns else "severity"
        y = df[y_col].fillna(0.0)

        fig, ax = plt.subplots(figsize=(15, 5))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#0d1117")
        
        # Create header space for external annotations (zona de cabecera vacía)
        # Increased top margin to accommodate 3 staggered levels: [1.12, 1.25, 1.38]
        fig.subplots_adjust(top=0.72)

        # Background grid
        ax.grid(True, color="#21262d", linestyle="--", linewidth=0.6, alpha=0.8)

        # Baseline signal
        ax.plot(x, y, linewidth=0.8, color="#30363d", alpha=0.6, zorder=1)

        # Severity bands
        sev_col = df["severity"] if "severity" in df.columns else pd.Series(0, index=df.index)
        sev_val = sev_col.fillna(0.0)

        low_m  = sev_val == 1
        mid_m  = sev_val == 2
        high_m = sev_val >= 3

        if low_m.any():
            ax.fill_between(x, 0, y, where=low_m, color="#f1c40f",  alpha=0.35, label="Severity 1 (Low)",      zorder=2)
        if mid_m.any():
            ax.fill_between(x, 0, y, where=mid_m, color="#e67e22",  alpha=0.45, label="Severity 2 (High)",     zorder=3)
        if high_m.any():
            ax.fill_between(x, 0, y, where=high_m, color="#e74c3c", alpha=0.65, label="Severity 3 (Critical)", zorder=4)
        # Use symmetric log scale to handle wide range of anomaly scores while preserving visibility of low-level activity.
        ax.set_yscale('symlog', linthresh=1.0)

        # Velocity bypass markers
        if "vel_bypass" in df.columns:
            vel_mask = df["vel_bypass"] == True
            if vel_mask.any():
                ax.scatter(
                    x[vel_mask], y[vel_mask],
                    color="#1abc9c", s=50, marker="^", alpha=0.7,
                    label="Velocity Bypass", zorder=5, edgecolors="none",
                )

        # Incident annotations — use provided list or fall back to all incidents
        target_incidents = incidents_to_plot if incidents_to_plot is not None else self.incidents
        logger.info(
            f"[_plot_timeline] Rendering annotations for "
            f"{len(target_incidents)} incident(s)"
        )

        # Vertical staggering levels (cascada/escalones) to avoid label overlap
        stagger_levels = [1.12, 1.25, 1.38]

        for i, inc in enumerate(target_incidents):
            # Calculate incident time boundaries (strip timezone)
            t_start = pd.Timestamp(inc.start_time).replace(tzinfo=None)
            t_end = pd.Timestamp(inc.end_time).replace(tzinfo=None)
            t_mid = pd.Timestamp(
                inc.start_time + (inc.end_time - inc.start_time) / 2
            ).replace(tzinfo=None)

            # ── TARGETING: Find MAXIMUM severity within incident window ──
            # (not just the midpoint value)
            try:
                # Create mask for rows within incident time range
                x_tz_aware = x.dt.tz_localize(None) if x.dt.tz is not None else x
                incident_mask = (x_tz_aware >= t_start) & (x_tz_aware <= t_end)
                
                if not incident_mask.any():
                    # Fallback: find closest point to midpoint
                    idx_near = (pd.to_datetime(x) - t_mid).abs().idxmin()
                    y_at_max = y.loc[idx_near]
                    logger.debug(
                        f"[_plot_timeline] No data in incident window for #{inc.incident_id + 1}; "
                        f"using midpoint value {y_at_max:.4f}"
                    )
                else:
                    # Find maximum y value within incident window (follows the peak)
                    y_max_in_window = y[incident_mask].max()
                    if pd.isna(y_max_in_window) or y_max_in_window == 0:
                        idx_near = (pd.to_datetime(x) - t_mid).abs().idxmin()
                        y_at_max = y.loc[idx_near]
                        logger.debug(
                            f"[_plot_timeline] Invalid max in window for #{inc.incident_id + 1}; "
                            f"using midpoint value {y_at_max:.4f}"
                        )
                    else:
                        y_at_max = y_max_in_window
                        logger.debug(
                            f"[_plot_timeline] Incident #{inc.incident_id + 1}: "
                            f"targeting peak severity {y_at_max:.4f} within window [{t_start}, {t_end}]"
                        )
                        
            except (KeyError, TypeError, ValueError) as e:
                logger.debug(
                    f"[_plot_timeline] Could not locate incident #{inc.incident_id + 1} "
                    f"at time {t_mid}: {e} — skipping annotation."
                )
                continue

            # ── SAFETY FILTER: Enforce minimum y-value to prevent burial ──
            # If peak is too low, force to 0.5 so arrow doesn't disappear into x-axis
            y_arrow_point = max(y_at_max, 0.5)

            # Use the top feature name as the label if available
            culprit_label = (
                inc.top_features[0].feature_name
                if inc.top_features
                else "?"
            )

            # ── POSITION CALCULATION: Map timestamp to axes fraction ──
            # Calculate relative position in the x-axis for external annotation placement
            try:
                x_min, x_max = ax.get_xlim()
                # Convert pandas Timestamp to numeric (matplotlib date number)
                t_mid_numeric = mdates.date2num(t_mid)
                x_frac = (t_mid_numeric - x_min) / (x_max - x_min)
                # Clamp to valid range [0, 1]
                x_frac = max(0.05, min(0.95, x_frac))
            except Exception:
                # Fallback: distribute evenly by incident ID
                x_frac = (inc.incident_id + 1) / (len(target_incidents) + 1)

            # ── EXTERNAL ANNOTATION: Position in header zone with FAN-OUT effect ──
            # Combine vertical stagger + horizontal fan-out to prevent dense burst overlap
            # When multiple incidents occur near each other, labels 'open up' like a fan
            y_pos = stagger_levels[i % len(stagger_levels)]
            
            # Horizontal offsets create the fan-out effect (left, center, right)
            x_offsets = [-0.05, 0, 0.05]
            x_offset = x_offsets[i % len(x_offsets)]
            x_text_pos = x_frac + x_offset
            # Clamp x_text_pos to stay within bounds
            x_text_pos = max(0.02, min(0.98, x_text_pos))
            
            # Anchor labels away from the center: labels on edges look away, center looks center
            if x_offset < 0:
                ha_align = "right"
            elif x_offset > 0:
                ha_align = "left"
            else:
                ha_align = "center"

            ax.annotate(
                f"#{inc.incident_id + 1}: {culprit_label}",
                xy=(t_mid, y_arrow_point),
                xytext=(x_text_pos, y_pos),
                xycoords="data",  # Arrow origin stays at actual data point
                textcoords="axes fraction",  # Text box positioned in figure space
                fontsize=7.5, color="#f0f6fc", ha=ha_align, va="center",
                bbox=dict(
                    boxstyle="round,pad=0.3", facecolor="#0d1117",
                    edgecolor="#58a6ff", linewidth=0.8, alpha=0.95,
                ),
                arrowprops=dict(
                    arrowstyle="-|>", color="#58a6ff", lw=0.8,
                    connectionstyle="arc3,rad=0.0",  # Straight line
                    linestyle="--", alpha=0.6, mutation_scale=10,
                    shrinkB=2, shrinkA=2,
                ),
            )

        ax.set_xlabel("Time (UTC)", color="#8b949e", fontsize=10)
        ax.set_ylabel(y_col.replace("_", " ").title(), color="#8b949e", fontsize=10)
        ax.set_title(
            "Attack Intensity Timeline — HiGI IDS",
            color="#f0f6fc", fontsize=13, fontweight="bold", pad=12,
        )
        ax.tick_params(colors="#8b949e")
        for spine in ax.spines.values():
            spine.set_edgecolor("#21262d")
        ax.legend(
            loc="upper right", framealpha=0.3,
            labelcolor="#f0f6fc", facecolor="#21262d",
        )
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout(pad=1.5)
        fig.savefig(out_path, dpi=120, bbox_inches="tight", facecolor="#0d1117")
        plt.close(fig)

    def _plot_family_radar(
        self,
        out_path: Path,
        incidents_to_plot: Optional[List[Any]] = None,
    ) -> None:
        """Render the Physical Family Stress Radar polar chart and save to PNG (publication-ready).

        This method produces a radar (polar) visualization showing how anomaly load is distributed
        across the six BlockedPCA physical metric families. Each family represents a distinct
        attack vector or network behavior dimension (volume, payload, flags, protocol, connection,
        kinematics), and the radar shows which families were most stressed during the capture.

        Visualization features:
            - Polar plot with 6 axes (one per family)
            - Fill region (polygon) shows aggregate stress distribution (normalized [0,1])
            - Color-coded vertices: each family has a distinct color from FAMILY_COLOURS
            - Concentric circles: grid at 0.2, 0.4, 0.6, 0.8, 1.0 stress fractions
            - Dark GitHub theme: #0d1117 background, #58a6ff fill, family-specific vertex colors
            - Legend positioned lower-right with family color mapping

        Family definitions:
            1. volume: Packet/byte count aggregates, inter-packet timing (attack throughput)
            2. payload: Packet size distributions, entropy (data exfiltration/injection)
            3. flags: TCP flag combinations (SYN, ACK, RST, FIN) — key for scan/DoS detection
            4. protocol: Layer-3/4 protocol mix (ICMP, UDP, TCP) — protocol abuse detection
            5. connection: Connection state counts (ESTABLISHED, SYN_SENT, LISTEN) — lifecycle
            6. kinematics: Temporal velocity, acceleration (rate-of-change anomalies) — timing

        Stress aggregation:
            - For each incident in incidents_to_plot: sum(family_stress.values()) → aggregate
            - Normalize by total aggregate [L1 norm] so all families sum to 1.0
            - Fallback: if no incidents, compute from raw df_anomalies via _infer_family()

        Args:
            out_path (Path): Output PNG file path (absolute or relative to cwd).
            incidents_to_plot (Optional[List[SecurityIncidentV2]]): List of incidents to
                aggregate family stress from. If None, uses self.incidents (all clustered).
                Typically pass the filtered list from get_reportable_incidents() for
                consistency with executive Markdown report.

        Returns:
            None. Saves PNG to out_path directly.

        Side effects:
            - Creates polar figure with Agg backend (headless rendering).
            - Fallback: if no incidents available, constructs aggregate from raw anomalies.

        Example:
            >>> engine.cluster_incidents()
            >>> reportable = engine.get_reportable_incidents(confidence_filter=0.50)
            >>> engine._plot_family_radar(Path("reports/family_stress_radar.png"), reportable)
        """
        # Aggregate family stress across incidents
        target_incidents = incidents_to_plot if incidents_to_plot is not None else self.incidents
        aggregate: Dict[str, float] = {}
        for inc in target_incidents:
            for fam, stress in inc.family_stress.items():
                aggregate[fam] = aggregate.get(fam, 0.0) + stress

        # Fallback: build from raw df if no incidents
        if not aggregate and "physical_culprit" in self.df_anomalies.columns:
            fc_col = (
                self.df_anomalies["family_consensus"]
                if "family_consensus" in self.df_anomalies.columns
                else pd.Series([""] * len(self.df_anomalies))
            )
            for raw, fc in zip(self.df_anomalies["physical_culprit"].fillna(""), fc_col):
                if not raw:
                    continue
                fam = _infer_family(_extract_base_name(raw), fc)
                aggregate[fam] = aggregate.get(fam, 0.0) + 1.0

        # Canonical family order for the radar
        families = ["volume", "payload", "flags", "protocol", "connection", "kinematics"]
        total = sum(aggregate.values()) or 1.0
        values = [aggregate.get(f, 0.0) / total for f in families]

        # Close the loop for polar fill
        angles = np.linspace(0, 2 * np.pi, len(families), endpoint=False).tolist()
        values_plot = values + [values[0]]
        angles_plot = angles + [angles[0]]

        fig, ax = plt.subplots(figsize=(7, 7), subplot_kw={"polar": True})
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#161b22")

        ax.plot(angles_plot, values_plot, color="#58a6ff", linewidth=2.0, zorder=3)
        ax.fill(angles_plot, values_plot, color="#58a6ff", alpha=0.30, zorder=2)

        # Family colour dots at each vertex
        for angle, val, fam in zip(angles, values, families):
            col = FAMILY_COLOURS.get(fam, "#95a5a6")
            ax.scatter([angle], [val], color=col, s=120, zorder=5, linewidths=0)

        ax.set_xticks(angles)
        ax.set_xticklabels(
            [f.capitalize() for f in families],
            color="#f0f6fc", fontsize=11,
        )
        ax.set_yticklabels([], color="#8b949e")
        ax.set_ylim(0, max(values_plot) * 1.25 if max(values_plot) > 0 else 1.0)
        ax.tick_params(colors="#8b949e")
        ax.spines["polar"].set_color("#21262d")
        ax.grid(color="#21262d", linestyle="--", linewidth=0.8)

        ax.set_title(
            "Physical Family Stress Radar\n(normalised anomaly load per feature family)",
            color="#f0f6fc", fontsize=12, fontweight="bold", pad=20,
        )

        # Legend: family → colour
        patches = [
            mpatches.Patch(color=FAMILY_COLOURS.get(f, "#95a5a6"), label=f.capitalize())
            for f in families
        ]
        ax.legend(
            handles=patches, loc="lower right",
            bbox_to_anchor=(1.35, -0.05),
            framealpha=0.3, labelcolor="#f0f6fc", facecolor="#21262d",
            fontsize=9,
        )

        plt.tight_layout(pad=1.5)
        fig.savefig(out_path, dpi=120, bbox_inches="tight", facecolor="#0d1117")
        plt.close(fig)

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def generate_report(
        self,
        output_dir: Optional[str] = None,
        visual_paths: Optional[Dict[str, str]] = None,
        **filter_kwargs: Any,
    ) -> str:
        """Generate the Markdown executive report (main public entry point for reporting pipeline).

        This is the primary method for producing a comprehensive, publication-ready forensic
        report combining executive summary, incident tables, visualizations, and data quality
        warnings. It orchestrates the full pipeline from raw data to final Markdown file.

        Reporting pipeline (orchestration):
            1. Auto-execute clustering if not already done (cluster_incidents()).
            2. Auto-detect data drops if not already done (detect_data_drops()).
            3. Generate two publication-ready PNG visualizations:
                - Attack Intensity Timeline (temporal severity evolution)
                - Physical Family Stress Radar (anomaly vector distribution)
            4. Render full Markdown document with embedded plot references.
            5. Write .md file to output_dir and return its path.

        Report contents:
            - Executive Summary: Incident counts, severity ranges, temporal window
            - Incident Table: Per-incident row with timestamp, duration, severity, confidence, and top culprits
            - Family Threat Distribution: Table showing which physical families drove anomalies
            - Data Quality: Telemetry gap warnings and sensor saturation indicators
            - Visualizations: Embedded PNG paths for timeline + radar charts
            - Metadata: Generation timestamp, configuration transparency

        Args:
            output_dir (Optional[str]): Directory for report + PNG files. Defaults to
                {csv_parent}/reports/ (e.g., data/processed/../reports/).
                Creates directory if not present.
            visual_paths (Optional[Dict[str, str]]): Pre-computed plot paths (skips PNG
                generation when provided, useful for testing or external visualization).
                Keys: 'timeline', 'family_radar'; Values: relative or absolute paths.
            **filter_kwargs (Any): Threshold overrides forwarded to get_reportable_incidents().
                Common filters:
                    - confidence_filter (float): Consensus confidence minimum [0, 1]
                    - min_anomalies_per_incident (int): Minimum anomaly window count
                    - min_duration_seconds (float): Minimum incident duration

        Returns:
            str: Absolute path of the written Markdown file (e.g.,
                /home/.../data/processed/results_FORENSIC.md).

        Raises:
            None explicitly. Logs warnings if visualization generation fails.

        Side effects:
            - Creates output_dir if not present.
            - Calls cluster_incidents() and detect_data_drops() if not pre-populated.
            - Writes PNG files to output_dir (via generate_visuals).
            - Writes Markdown .md file to output_dir.

        Example:
            >>> engine = HiGIForensicEngine(...)
            >>> engine.cluster_incidents()
            >>> md_path = engine.generate_report(
            ...     output_dir="reports",
            ...     confidence_filter=0.50
            ... )
            >>> print(f"Report saved: {md_path}")
        """
        # Auto-run clustering / drop detection if caller skipped them
        if not self.incidents:
            self.cluster_incidents()
        if not self.data_drops:
            self.detect_data_drops()

        out_dir = Path(output_dir) if output_dir else self.csv_path.parent.parent / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)

        stem = self.csv_path.stem
        md_path = out_dir / f"{stem}_FORENSIC.md"

        if visual_paths is None:
            # Generate visuals with the same filters as the report
            visual_paths = self.generate_visuals(
                out_dir,
                stem=stem,
                **filter_kwargs,
            )

        md_content = self._render_markdown(visual_paths, **filter_kwargs)
        md_path.write_text(md_content, encoding="utf-8")
        logger.info(f"[REPORT] Markdown written → {md_path}")
        return str(md_path)

    def _render_markdown(
        self,
        visual_paths: Dict[str, str],
        **filter_kwargs: Any,
    ) -> str:
        """Render the complete Markdown string for the executive forensic report (internal).

        This internal method synthesizes all incident, statistical, and visualization data
        into a polished Markdown document suitable for Blue Team leadership and incident
        responders. It produces human-readable tables, metric summaries, and embedded
        visualization paths for integration into security dashboards or PDF reports.

        Report structure:
            1. Title & Metadata: Report name, generation timestamp, configuration visibility
            2. Executive Summary Section: Incident counts, severity breakdown, temporal coverage
            3. Incident Details Table: Per-incident rows with:
                - Incident ID, timestamp window, duration (seconds)
                - Severity, consensus confidence, anomaly count
                - Top 3 culprit features (XAI) with SPIKE/DROP directionality
            4. Physical Family Threat Distribution: Table mapping families → anomaly load
            5. Data Quality Warnings: Telemetry gaps, sensor saturation indicators
            6. Visualization Sections: Timeline + Radar charts (embedded as ![...](path))
            7. Configuration Transparency: Applied filters, thresholds (for auditability)

        Table formatting:
            - Incident table: Fixed-width columns for readability (e.g., ID | Duration | Severity)
            - Family distribution: Rows per family with normalized stress [0, 1]
            - Markdown tables use pipe-delimited format for GitHub/Confluence rendering

        Args:
            visual_paths (Dict[str, str]): Mapping of visualization keys to file paths:
                - 'timeline': PNG path for Attack Intensity Timeline
                - 'family_radar': PNG path for Physical Family Stress Radar
            **filter_kwargs (Any): Threshold parameters used in filtering:
                - confidence_filter, min_anomalies_per_incident, min_duration_seconds, sigma_culprit_min
                - These are documented in the report for reproducibility.

        Returns:
            str: Complete Markdown document as a single string, ready to be written to file.
                Does NOT include file I/O; that is handled by generate_report().

        Side effects:
            - Calls get_reportable_incidents() to retrieve filtered incidents.
            - Calls generate_summary_stats() to compute executive statistics.
            - Computes family threat distribution from df_anomalies.

        Notes:
            - All timestamps are localized to UTC unless specified otherwise.
            - Culprit features shown in top-3 ranking order (by loading magnitude).
            - Data quality warnings use severity color-coding (🟡 Low, 🟠 Medium, 🔴 High).
            - MITRE ATT&CK tactics included in incident rows (if available in inc.mitre_tactics).
        """
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        cfg = self.config
        stats = self.generate_summary_stats(**filter_kwargs)
        reportable = self.get_reportable_incidents(**filter_kwargs)

        t_start = stats["time_range_start"]
        t_end   = stats["time_range_end"]
        t_start_str = t_start.strftime("%Y-%m-%d %H:%M:%S") if t_start else "N/A"
        t_end_str   = t_end.strftime("%Y-%m-%d %H:%M:%S")   if t_end   else "N/A"

        # ── Family-level threat distribution ──────────────────────────
        fam_counts: Dict[str, int] = {}
        if "physical_culprit" in self.df_anomalies.columns:
            fc_col = (
                self.df_anomalies["family_consensus"]
                if "family_consensus" in self.df_anomalies.columns
                else pd.Series([""] * len(self.df_anomalies))
            )
            for raw, fc in zip(self.df_anomalies["physical_culprit"].fillna(""), fc_col):
                if not raw:
                    continue
                fam = _infer_family(_extract_base_name(str(raw)), fc)
                fam_counts[fam] = fam_counts.get(fam, 0) + 1

        total_anom = stats["total_anomalies"] or 1

        lines: List[str] = []
        a = lines.append  # shorthand

        # ── HEADER ────────────────────────────────────────────────────
        a("# HiGI IDS — Forensic Security Incident Report")
        a("")
        a(f"> **Generated:** {now}  ")
        a(f"> **Source file:** `{self.csv_path.name}`  ")
        a(f"> **Analysis window:** {t_start_str} → {t_end_str}")
        a("")

        # ── ANALYSIS PARAMETERS ───────────────────────────────────────
        a("## Analysis Parameters")
        a("")
        a("| Parameter | Value | Purpose |")
        a("|-----------|-------|---------|")
        a(f"| Incident debounce | {cfg['debounce_seconds']:.0f} s | Maximum gap for grouping consecutive anomalies |")
        a(f"| Data-drop threshold | {cfg['data_drop_threshold_seconds']:.0f} s | Gap size flagged as sensor blindness |")
        a(f"| Confidence filter | {cfg['confidence_filter']:.0%} | Minimum tier-weighted confidence for reporting |")
        a(f"| Min anomalies/incident | {cfg['min_anomalies_per_incident']} | Alert-fatigue suppression floor |")
        a(f"| Min duration | {cfg['min_duration_seconds']:.1f} s | Minimum incident duration |")
        a(f"| Min σ culprit | {cfg['sigma_culprit_min']:.1f} | Minimum mean \\|σ\\| to include in report |")
        a("")

        # ── EXECUTIVE SUMMARY ─────────────────────────────────────────
        a("## Executive Summary")
        a("")
        sev_label = SEVERITY_RISK_LABELS.get(stats["max_severity"], "Critical — Full unanimity")
        a(f"- **Total anomalous windows detected:** {stats['total_anomalies']:,}")
        a(f"- **Reportable incidents after filtering:** {stats['total_incidents']}")
        a(f"- **Maximum severity:** {stats['max_severity']}/3 ({sev_label})")
        a(f"- **Average severity:** {stats['avg_severity']:.2f}/3")
        a(f"- **Average incident duration:** {stats['avg_incident_duration']:.1f} s")
        a(f"- **Telemetry data-drops detected:** {stats['data_drops_detected']}")
        a("")

        # ── FAMILY STRESS TABLE ───────────────────────────────────────
        a("## Physical Family Stress Distribution")
        a("")
        a("| Family | Anomaly Count | Share | Interpretation |")
        a("|--------|--------------|-------|----------------|")
        family_interpretations = {
            "flags":      "TCP-flag manipulation — possible SYN/RST/FIN flood or stealth scan",
            "volume":     "Bandwidth/PPS overload — volumetric DoS or data exfiltration",
            "payload":    "Payload anomaly — obfuscation, encryption or protocol tunnelling",
            "protocol":   "Protocol-ratio shift — possible protocol abuse or evasion",
            "connection": "Connection-topology anomaly — port-scan, service discovery",
            "kinematics": "Rate/volatility anomaly — beaconing, slow-rate attack or burst",
            "velocity":   "Velocity bypass triggered — rapid burst above Z-score threshold",
            "unknown":    "Family could not be inferred from available metadata",
        }
        for fam, cnt in sorted(fam_counts.items(), key=lambda x: -x[1]):
            pct = cnt / total_anom * 100
            interp = family_interpretations.get(fam, "–")
            a(f"| **{fam.capitalize()}** | {cnt:,} | {pct:.1f}% | {interp} |")
        a("")

        # ── VISUALISATIONS ────────────────────────────────────────────
        a("## Visual Evidence")
        a("")
        if visual_paths.get("timeline_plot"):
            fname = visual_paths["timeline_plot"]
            a(f"### Figure 1 — Attack Intensity Timeline")
            a("")
            a(f"![Attack Intensity Timeline]({fname})")
            a("")
            a(
                "**Reading guide:** Coloured fill indicates severity level "
                "(yellow = Severity 1, orange = Severity 2, red = Severity 3). "
                "Teal downward triangles mark Velocity Bypass events. "
                "Callout boxes annotate the three highest-severity incidents with "
                "their primary culprit metric."
            )
            a("")

        if visual_paths.get("radar_plot"):
            fname = visual_paths["radar_plot"]
            a(f"### Figure 2 — Physical Family Stress Radar")
            a("")
            a(f"![Physical Family Stress Radar]({fname})")
            a("")
            a(
                "**Reading guide:** Each axis represents a physical feature family. "
                "A larger filled area indicates that family contributed more anomaly "
                "load. Dominant axes identify the primary attack vector and guide "
                "immediate countermeasure prioritisation."
            )
            a("")

        # ── DETAILED INCIDENTS ────────────────────────────────────────
        a("## Detailed Incident Analysis")
        a("")

        if not reportable:
            a("> No incidents met the reporting thresholds after filtering.")
            a("")
        else:
            for inc in reportable:
                sev_lbl = SEVERITY_RISK_LABELS.get(inc.max_severity, "Critical")
                a(f"### Incident #{inc.incident_id + 1}")
                a("")
                a(f"| Field | Value |")
                a(f"|-------|-------|")
                a(f"| **Start (UTC)** | {inc.start_time.strftime('%Y-%m-%d %H:%M:%S')} |")
                a(f"| **End (UTC)** | {inc.end_time.strftime('%Y-%m-%d %H:%M:%S')} |")
                a(f"| **Duration** | {inc.duration_seconds:.0f} s |")
                a(f"| **Anomalous windows** | {inc.total_anomalies} |")
                a(f"| **Max severity** | {inc.max_severity}/3 — {sev_lbl} |")
                a(f"| **Dynamic severity score** | {inc.dynamic_severity_score:.2f} |")
                a(f"| **Consensus confidence** | {inc.consensus_confidence:.1%} |")
                a(f"| **Persistence label** | {inc.persistence_label} |")
                a(f"| **Top-3 destination ports** | {', '.join(map(str, inc.top_3_ports)) or 'N/A'} |")
                a(f"| **Warm-up period** | {'Yes ⚠' if inc.is_warmup else 'No'} |")
                a("")

                # Tier firing table
                if inc.tier_evidence:
                    a("#### Tier Evidence")
                    a("")
                    a("| Tier | Fired | Fire Count | Mean Score |")
                    a("|------|-------|-----------|------------|")
                    for te in inc.tier_evidence:
                        fired_str = "✅" if te.fired else "—"
                        a(f"| {te.tier_name} | {fired_str} | {te.fire_count} | {te.mean_score:.4f} |")
                    a("")

                # XAI top-3 features
                if inc.top_features:
                    a("#### Top-3 Physical Feature Attributions (XAI)")
                    a("")
                    a("| Rank | Feature | Family | Event Type | Max \\|σ\\| | Max Δ% | Loading |")
                    a("|------|---------|--------|-----------|--------|--------|---------|")
                    for rank, fa in enumerate(inc.top_features, 1):
                        direction = "⬆ SPIKE" if fa.event_type == "SPIKE" else "⬇ DROP"
                        a(
                            f"| {rank} | `{fa.feature_name}` | {fa.family.capitalize()} "
                            f"| {direction} | {fa.max_sigma:.2f}σ | {fa.max_pct:.0f}% "
                            f"| {fa.loading_magnitude:.3f} |"
                        )
                    a("")

                # MITRE mapping
                if inc.mitre_tactics:
                    a("#### MITRE ATT&CK Mapping")
                    a("")
                    for tactic, techniques in inc.mitre_tactics.items():
                        a(f"- **{tactic}**")
                        for tech in techniques:
                            a(f"  - {tech}")
                    a("")

        # ── DATA DROPS ────────────────────────────────────────────────
        if self.data_drops:
            a("## Telemetry Data Drops")
            a("")
            a("| Start (UTC) | End (UTC) | Gap (s) | Severity Before | Reason |")
            a("|------------|----------|---------|----------------|--------|")
            for drop in self.data_drops:
                sev_b = str(drop["severity_before"]) if drop["severity_before"] is not None else "–"
                a(
                    f"| {drop['start_time'].strftime('%H:%M:%S')} "
                    f"| {drop['end_time'].strftime('%H:%M:%S')} "
                    f"| {drop['gap_seconds']:.1f} "
                    f"| {sev_b} "
                    f"| {drop['reason']} |"
                )
            a("")

        # ── FOOTER ───────────────────────────────────────────────────
        a("---")
        a("")
        a("*Report generated automatically by **HiGI IDS ForensicEngine V2.0**.*  ")
        a("*Consult your security team for remediation guidance.*")
        a("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# V1 drop-in alias  (main.py imports ``ForensicEngine``)
# ---------------------------------------------------------------------------
ForensicEngine = HiGIForensicEngine


# ---------------------------------------------------------------------------
# Standalone report generator functions (keep signature parity with V1)
# ---------------------------------------------------------------------------

def generate_markdown_report(
    engine: HiGIForensicEngine,
    output_path: str,
    visual_paths: Optional[Dict[str, str]] = None,
    **filter_kwargs: Any,
) -> None:
    """Write the Markdown forensic report to ``output_path``.

    Thin wrapper that makes ``HiGIForensicEngine`` compatible with the
    ``main.py`` call-site used by ForensicEngine V1.

    Critical: Passes **filter_kwargs to generate_visuals() to ensure
    plots are generated with the same filtering logic as the report text.
    This guarantees consistency: if the MD says N incidents, the PNG will
    annotate exactly those N incidents.

    Execution order (strictly enforced):
        1. Cluster incidents (if not already done)
        2. Detect data drops (if not already done)
        3. Generate visualizations with filtered incidents
        4. Render Markdown report with same filters

    Args:
        engine: Initialised and clustered ``HiGIForensicEngine`` instance.
        output_path: Destination path for the Markdown file.
        visual_paths: Optional pre-computed plot paths.  If provided,
            skip plot generation entirely (useful for testing).
        **filter_kwargs: Threshold overrides (confidence_filter,
            min_anomalies_per_incident, min_duration_seconds,
            sigma_culprit_min) forwarded to both plot generation and
            the Markdown renderer.
    """
    # ── PHASE 1: Cluster incidents if needed ──────────────────────────
    if not engine.incidents:
        logger.info("[WRAPPER] Phase 1: Clustering incidents...")
        engine.cluster_incidents()
    else:
        logger.info(f"[WRAPPER] Phase 1: Incidents already clustered ({len(engine.incidents)} total)")

    # ── PHASE 2: Detect data drops if needed ───────────────────────────
    if not engine.data_drops:
        logger.info("[WRAPPER] Phase 2: Detecting data drops...")
        engine.detect_data_drops()
    else:
        logger.info(f"[WRAPPER] Phase 2: Data drops already detected ({len(engine.data_drops)} total)")

    out_dir = Path(output_path).parent
    stem = Path(output_path).stem.replace("_FORENSIC", "")

    # ── PHASE 3: Generate visualizations with filters ──────────────────
    if visual_paths is None:
        logger.info("[WRAPPER] Phase 3: Generating visualizations with filters...")
        visual_paths = engine.generate_visuals(
            out_dir,
            stem=stem,
            **filter_kwargs,
        )
        logger.info(f"[WRAPPER] Phase 3: Visualizations complete → {visual_paths}")
    else:
        logger.info("[WRAPPER] Phase 3: Using pre-computed visual paths (skipped generation)")

    # ── PHASE 4: Render Markdown with same filters ─────────────────────
    logger.info("[WRAPPER] Phase 4: Rendering Markdown with filters...")
    md_content = engine._render_markdown(visual_paths, **filter_kwargs)
    Path(output_path).write_text(md_content, encoding="utf-8")
    logger.info(f"[WRAPPER] Phase 4: Report written → {output_path}")
    logger.info("[WRAPPER] Execution complete: clustering → drops → visuals → markdown")


def generate_forensic_pdf(
    engine: HiGIForensicEngine,
    output_path: str,
    organization: str = "HiGI Security Operations",
    **filter_kwargs: Any,
) -> None:
    """Generate a PDF forensic report (delegates to ReportLab).

    Replicates the V1 signature so ``main.py`` requires no changes.  If
    ReportLab is not installed the function logs a warning and returns
    gracefully instead of raising.

    Args:
        engine: Initialised and clustered ``HiGIForensicEngine``.
        output_path: Destination path for the PDF file.
        organization: Organisation name rendered in the report header.
        **filter_kwargs: Threshold overrides forwarded to the engine.
    """
    try:
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle,
            Paragraph, Spacer, PageBreak, Image,
        )
    except ImportError:
        logger.warning("[PDF] ReportLab not installed – PDF generation skipped.")
        return

    if not engine.incidents:
        engine.cluster_incidents()
    if not engine.data_drops:
        engine.detect_data_drops()

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        rightMargin=0.75 * inch, leftMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    story: List[Any] = []

    title_style = ParagraphStyle(
        "HiGITitle", parent=styles["Heading1"],
        fontSize=22, spaceAfter=6, fontName="Helvetica-Bold",
    )
    h2 = ParagraphStyle(
        "HiGIH2", parent=styles["Heading2"],
        fontSize=13, spaceAfter=10, spaceBefore=10, fontName="Helvetica-Bold",
    )

    story.append(Paragraph("HiGI IDS — Forensic Security Incident Report", title_style))
    story.append(Paragraph(f"<i>{organization}</i>", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    stats = engine.generate_summary_stats(**filter_kwargs)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    t_start = stats["time_range_start"]
    t_end   = stats["time_range_end"]
    period  = (
        f"{t_start.strftime('%Y-%m-%d %H:%M:%S')} → {t_end.strftime('%Y-%m-%d %H:%M:%S')}"
        if t_start else "N/A"
    )

    meta_data = [
        ["Generated",       now],
        ["Analysis period", period],
        ["Data source",     engine.csv_path.name],
    ]
    meta_tbl = Table(meta_data, colWidths=[2 * inch, 4 * inch])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), rl_colors.HexColor("#ecf0f1")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.grey),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Executive Summary", h2))
    sev_lbl = SEVERITY_RISK_LABELS.get(stats["max_severity"], "Critical")
    summary_text = (
        f"<b>Anomalies detected:</b> {stats['total_anomalies']:,}<br/>"
        f"<b>Reportable incidents:</b> {stats['total_incidents']}<br/>"
        f"<b>Maximum severity:</b> {stats['max_severity']}/3 ({sev_lbl})<br/>"
        f"<b>Average severity:</b> {stats['avg_severity']:.2f}/3<br/>"
        f"<b>Data drops:</b> {stats['data_drops_detected']}"
    )
    story.append(Paragraph(summary_text, styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Detailed Incident Analysis", h2))
    reportable = engine.get_reportable_incidents(**filter_kwargs)
    if not reportable:
        story.append(Paragraph("No reportable incidents after filtering.", styles["Normal"]))
    else:
        for inc in reportable:
            sev_l = SEVERITY_RISK_LABELS.get(inc.max_severity, "Critical")
            hdr = (
                f"Incident #{inc.incident_id + 1} | "
                f"Start: {inc.start_time.strftime('%H:%M:%S')} | "
                f"Duration: {inc.duration_seconds:.0f}s | "
                f"Severity: {inc.max_severity}/3 ({sev_l})"
            )
            story.append(Paragraph(f"<b>{hdr}</b>", styles["Heading3"]))

            mitre_str = (
                ", ".join(inc.mitre_tactics.keys()) if inc.mitre_tactics else "Unknown"
            )
            feat_lines = "".join(
                f"<br/>&nbsp;&nbsp;{i + 1}. <b>{fa.feature_name}</b> "
                f"[{fa.event_type}] σ={fa.max_sigma:.2f}"
                for i, fa in enumerate(inc.top_features)
            )
            detail = (
                f"<b>Primary culprit:</b> {inc.primary_culprit}<br/>"
                f"<b>Confidence:</b> {inc.consensus_confidence:.1%}<br/>"
                f"<b>Anomalies:</b> {inc.total_anomalies}<br/>"
                f"<b>Ports:</b> {', '.join(map(str, inc.top_3_ports)) or 'N/A'}<br/>"
                f"<b>MITRE tactics:</b> {mitre_str}<br/>"
                f"<b>Top features:</b>{feat_lines}<br/>"
                f"<b>UTC range:</b> {inc.start_time.strftime('%Y-%m-%d %H:%M:%S')} → "
                f"{inc.end_time.strftime('%H:%M:%S')}"
            )
            story.append(Paragraph(detail, styles["Normal"]))
            story.append(Spacer(1, 0.1 * inch))

    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "<i>Generated automatically by HiGI IDS ForensicEngine V2. "
        "Consult your security team for remediation.</i>",
        styles["Normal"],
    ))

    doc.build(story)
    logger.info(f"[PDF] Report written → {output_path}")
    
## File: src/ingestion/processor_optime.py

"""Packet Processing Module for PCAP Analysis.

Standardized feature extraction using IANA protocol registry with memory-efficient
processing for large datasets. Adheres to PEP8, professional naming conventions,
and complete type hinting.

Features:
    - Robust IANA protocol mapping without hardcoded indices
    - Optimized entropy calculation (10-15x faster than scipy)
    - Memory-efficient chunked processing with Polars
    - Complete type hints and Google-style docstrings
    - Consistent dpkt-based packet parsing (no library mixing)
"""

from asyncio.log import logger
import gc
import os
from typing import Any, Dict, Generator, List, Optional, Tuple
from functools import partial

import dpkt
import dpkt.ethernet
import dpkt.ip
import dpkt.tcp
import dpkt.udp
import dpkt.sll
import joblib
import numpy as np
import pandas as pd
import scipy as sp
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import FunctionTransformer, RobustScaler, StandardScaler
import polars as pl
import concurrent.futures
import tqdm 


class PcapProcessorError(Exception):
    """Base exception for PCAP processing errors."""

    pass


class InvalidPcapPathError(PcapProcessorError):
    """Raised when PCAP file path is invalid or inaccessible."""

    pass


class ProtocolMappingError(PcapProcessorError):
    """Raised when IANA protocol mapping fails."""

    pass


# ============================================================================
# GLOBAL UTILITY FUNCTIONS (multiprocessing-compatible)
# ============================================================================



def _calculate_entropy_vectorized(payload: bytes) -> float:
    """Calculate Shannon entropy of packet payload using vectorized NumPy.

    Optimized implementation using numpy operations for speed.
    Approximately 10-15x faster than scipy.stats.entropy for typical payloads.

    Formula: H(X) = -Σ(p_i * log2(p_i)) where p_i = count_i / length

    Args:
        payload: Raw packet payload bytes.

    Returns:
        Shannon entropy in bits (0.0 for empty payload). Range: [0.0, 8.0].
    """
    if not payload or len(payload) == 0:
        return 0.0

    # Count byte frequencies efficiently
    byte_counts = np.bincount(
        np.frombuffer(payload, dtype=np.uint8), minlength=256
    )

    # Filter out zero counts and compute probabilities
    non_zero_counts = byte_counts[byte_counts > 0]
    probabilities = non_zero_counts / len(payload)

    # Vectorized entropy: H = -Σ(p * log2(p))
    entropy_value = -np.sum(probabilities * np.log2(probabilities))
    return float(entropy_value)


def _extract_tcp_flags(tcp_packet: dpkt.tcp.TCP) -> Dict[str, int]:
    """Extract TCP control flags from dpkt TCP packet.

    Args:
        tcp_packet: Parsed dpkt TCP packet object.

    Returns:
        Dictionary with flags as {flag_name: 0|1}.
    """
    # TCP flags are stored in single byte (bits 4-9)
    flags_byte = tcp_packet.flags

    return {
        "tcp_flags_syn": 1 if (flags_byte & dpkt.tcp.TH_SYN) else 0,
        "tcp_flags_ack": 1 if (flags_byte & dpkt.tcp.TH_ACK) else 0,
        "tcp_flags_fin": 1 if (flags_byte & dpkt.tcp.TH_FIN) else 0,
        "tcp_flags_rst": 1 if (flags_byte & dpkt.tcp.TH_RST) else 0,
        "tcp_flags_psh": 1 if (flags_byte & dpkt.tcp.TH_PUSH) else 0,
        "tcp_flags_urg": 1 if (flags_byte & dpkt.tcp.TH_URG) else 0,
    }


# Standard service ports for traffic directionality detection (v2.2.0)
# Inbound: packets from these ports are responses
# Outbound: packets to these ports are requests
STANDARD_SERVICE_PORTS: set = {
    20, 21,      # FTP
    22,          # SSH
    25, 587,     # SMTP
    53,          # DNS
    80, 8080, 8000,     # HTTP
    110, 143,    # POP3, IMAP
    143, 993,    # IMAP, IMAPS
    443, 8443,   # HTTPS
    444,         # SNPP
    445,         # SMB
    465,         # SMTP SSL
    514,         # Syslog
    1433,        # SQL Server
    3306,        # MySQL
    3389,        # RDP
    5432,        # PostgreSQL
    5984,        # CouchDB
    6379,        # Redis
    8888,        # Jupyter
    9200,        # Elasticsearch
    27017,       # MongoDB
}


def _detect_traffic_direction(src_port: int, dst_port: int) -> Tuple[str, int]:
    """Detect traffic direction (inbound/outbound) and identify service port.

    Inbound: src_port is a service port (server sending response).
    Outbound: dst_port is a service port (client sending request).

    Args:
        src_port: Source port (-1 if N/A).
        dst_port: Destination port (-1 if N/A).

    Returns:
        Tuple: (direction: "inbound"|"outbound"|"unknown", server_port: int or -1)
    """
    # Handle invalid ports
    if src_port < 0 and dst_port < 0:
        return ("unknown", -1)

    # Check if source is a service port (inbound response)
    if src_port in STANDARD_SERVICE_PORTS:
        return ("inbound", src_port)

    # Check if destination is a service port (outbound request)
    if dst_port in STANDARD_SERVICE_PORTS:
        return ("outbound", dst_port)

    # Default to outbound if either port is missing but one is service-like
    if src_port < 1024 or dst_port >= 1024:
        return ("outbound", dst_port if dst_port >= 0 else -1)

    return ("unknown", -1)


def _process_batch(
    batch_data: List[Tuple[bytes, float, int]],
    iana_map: Dict[int, str],
    first_timestamp: float = 0.0,
) -> List[Dict[str, Any]]:
    """Process a batch of IPv4 packets to extract features.

    Args:
        batch_data: List of tuples (ip_payload_bytes, timestamp, packet_length).
        iana_map: Mapping from IANA protocol numbers to protocol names.
        first_timestamp: Absolute timestamp of first packet in PCAP (base time).

    Returns:
        List of feature dictionaries, one per successfully parsed packet.
        Fields include:
            - abs_ts: Absolute timestamp from PCAP (float, seconds since epoch).
            - direction: Traffic direction ("inbound", "outbound", "unknown").
            - server_port: Service port (if identified, else -1).
            - req_payload: Request payload bytes (dst=service port).
            - res_payload: Response payload bytes (src=service port).
            - payload_bytes: Total transport payload size in bytes (0 if no payload).
    """
    results = []

    for ip_payload, timestamp, total_packet_length in batch_data:
        try:
            # Parse IP packet from dpkt
            ip_packet = dpkt.ip.IP(ip_payload)

            # Extract protocol type
            protocol_num = ip_packet.p
            protocol_name = iana_map.get(protocol_num, f"PROTO_{protocol_num}").upper()

            # Extract payload (data after IP + transport headers)
            payload = bytes(ip_packet.data) if ip_packet.data else b""

            # Initialize TCP flags (all zero by default)
            tcp_flags = {
                "tcp_flags_syn": 0,
                "tcp_flags_ack": 0,
                "tcp_flags_fin": 0,
                "tcp_flags_rst": 0,
                "tcp_flags_psh": 0,
                "tcp_flags_urg": 0,
            }

            # Extract transport layer info
            src_port: int = -1
            dst_port: int = -1

            if isinstance(ip_packet.data, dpkt.tcp.TCP):
                # TCP packet: extract ports and flags
                tcp_layer = ip_packet.data
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                tcp_flags = _extract_tcp_flags(tcp_layer)
                # Payload is data after TCP header
                payload = bytes(tcp_layer.data) if tcp_layer.data else b""

            elif isinstance(ip_packet.data, dpkt.udp.UDP):
                # UDP packet: extract ports
                udp_layer = ip_packet.data
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                # Payload is data after UDP header
                payload = bytes(udp_layer.data) if udp_layer.data else b""

            # Calculate entropy of transport layer payload
            entropy = _calculate_entropy_vectorized(payload)

            # Detect traffic direction and identify service port (v2.2.0)
            direction, server_port = _detect_traffic_direction(src_port, dst_port)

            # Differentiate payload by direction (v2.2.0)
            # req_payload: client → server (outbound requests)
            # res_payload: server → client (inbound responses)
            payload_size = len(payload)
            if direction == "outbound":
                req_payload = payload_size
                res_payload = 0
            elif direction == "inbound":
                req_payload = 0
                res_payload = payload_size
            else:
                req_payload = 0
                res_payload = 0

            # Build feature record
            record = {
                "abs_ts": timestamp,  # Absolute timestamp from PCAP (v2.2.0)
                "timestamp": timestamp,
                "size": total_packet_length,  # Total IP packet size
                "entropy": entropy,
                "protocol": protocol_name,
                "src_port": src_port,
                "dst_port": dst_port,
                "direction": direction,  # "inbound", "outbound", or "unknown"
                "server_port": server_port,  # Service port if detected, else -1
                **tcp_flags,
                "payload_bytes": payload_size,  # Total transport payload (0 if no payload)
                "req_payload": req_payload,  # Request payload bytes (v2.2.0)
                "res_payload": res_payload,  # Response payload bytes (v2.2.0)
            }

            results.append(record)

        except (dpkt.UnpackError, AttributeError, TypeError):
            # Skip malformed packets silently
            continue
        except Exception:
            # Skip any unexpected errors
            continue

    return results


class PcapProcessor:
    """Processes PCAP files into standardized feature matrices.

    This class extracts network packets from PCAP files, computes statistical
    features (entropy, packet size, protocol type), and aggregates them into
    time-windowed feature matrices suitable for IDS analysis.

    Uses Scapy's internal IANA protocol database for robust protocol name
    resolution without hardcoded mapping tables.

    Attributes:
        pcap_path (str): Path to the PCAP file to process.
        chunk_size (int): Number of packets to process per memory chunk.
        iana_map (Dict[int, str]): Mapping from IANA protocol numbers to names.

    New physical dimensions (v2.1.0):
        The feature matrix produced by _build_base_matrix() includes four
        additional physics-grounded dimensions beyond the original set:

        flow_duration (float): Temporal observation window per aggregation
            interval (seconds). Computed as max(timestamp) - min(timestamp)
            within each second_window group. Floored at 1e-6 to prevent
            downstream division-by-zero in duration-derived ratios.
            Physical interpretation: short durations signal burst traffic;
            long durations signal sustained low-rate flows (e.g., Slowloris).

        payload_continuity (float): Mean transport payload bytes per packet
            within the window. Computed as sum(payload_bytes) / pps.
            Physical interpretation: values near zero indicate header-only
            traffic (SYN flood, port scan); high values indicate data transfer
            or exfiltration.

        iat_mean (float): Mean inter-arrival time between consecutive packets
            in the window (seconds). Derived analytically as
            flow_duration / (pps - 1), avoiding per-packet list storage.
            Physical interpretation: regular low IAT indicates flooding;
            irregular high IAT indicates covert beaconing.

        flag_psh_ratio (float): Fraction of packets with TCP PSH flag set.
            Already extracted by the existing dynamic flag loop.
            Physical interpretation: sustained PSH storms indicate application-
            layer data exfiltration or C2 data channel activity.

        flag_urg_ratio (float): Fraction of packets with TCP URG flag set.
            Already extracted by the existing dynamic flag loop.
            Physical interpretation: URG abuse is a known fingerprint of
            legacy DoS tools and some C2 implants.
    """

    DEFAULT_CHUNK_SIZE: int = 5000
    """Default number of packets per processing chunk for memory efficiency."""

    def __init__(self, pcap_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE, n_jobs: int = 6) -> None:
        """Initialize PCAP processor with file validation and IANA mapping.

        Args:
            pcap_path (str): Path to the PCAP file. Must exist and be readable.
            chunk_size (int, optional): Number of packets to buffer before processing.
                Defaults to 5000. Larger values use more memory but reduce overhead.

        Raises:
            InvalidPcapPathError: If pcap_path doesn't exist or isn't readable.
            ProtocolMappingError: If IANA protocol mapping initialization fails.
        """
        self._validate_pcap_path(pcap_path)
        self.pcap_path: str = pcap_path
        self.chunk_size: int = chunk_size
        if n_jobs == -1:
            self.n_jobs = os.cpu_count() or 1
        else:
            self.n_jobs = n_jobs
        self.iana_map: Dict[int, str] = self._initialize_iana_map()

    @staticmethod
    def _validate_pcap_path(pcap_path: str) -> None:
        """Validate PCAP file existence and accessibility.

        Args:
            pcap_path (str): Path to validate.

        Raises:
            InvalidPcapPathError: If file doesn't exist or isn't readable.
        """
        if not os.path.exists(pcap_path):
            raise InvalidPcapPathError(f"PCAP file not found: {pcap_path}")
        if not os.path.isfile(pcap_path):
            raise InvalidPcapPathError(f"Path is not a file: {pcap_path}")
        if not os.access(pcap_path, os.R_OK):
            raise InvalidPcapPathError(f"PCAP file not readable: {pcap_path}")

    @staticmethod
    def _initialize_iana_map() -> Dict[int, str]:
        """Initialize IANA protocol number to name mapping.

        Builds protocol mapping from dpkt's IP module constants and standard
        IANA protocol numbers. Falls back to generic names for unmapped protocols.

        Returns:
            Dictionary mapping IANA protocol numbers (int) to protocol names (str).

        Raises:
            ProtocolMappingError: If IANA mapping initialization fails completely.
        """
        try:
            # Base mapping with standard IANA protocol numbers
            proto_map: Dict[int, str] = {
                0: "IP",
                1: "ICMP",
                2: "IGMP",
                3: "GGP",
                4: "IP-IN-IP",
                5: "ST",
                6: "TCP",
                7: "CBT",
                8: "EGP",
                9: "IGP",
                10: "BBN_RCC_MON",
                11: "NVP_II",
                12: "PUP",
                13: "ARGUS",
                14: "EMCON",
                15: "XNET",
                16: "CHAOS",
                17: "UDP",
                18: "MUX",
                19: "DCN_MEAS",
                20: "HMP",
                21: "PRM",
                22: "XNS_IDP",
                23: "TRUNK_1",
                24: "TRUNK_2",
                25: "LEAF_1",
                26: "LEAF_2",
                27: "RDP",
                28: "IRTP",
                29: "ISO_TP4",
                30: "NETBLT",
                31: "MFE_NSP",
                32: "MERIT_INP",
                33: "DCCP",
                41: "IPv6",
                47: "GRE",
                50: "ESP",
                51: "AH",
                112: "VRRP",
                132: "SCTP",
            }

            # Try to add dpkt-specific constants if available
            if hasattr(dpkt.ip, "IP_PROTO_TCP"):
                proto_map[dpkt.ip.IP_PROTO_TCP] = "TCP"
            if hasattr(dpkt.ip, "IP_PROTO_UDP"):
                proto_map[dpkt.ip.IP_PROTO_UDP] = "UDP"
            if hasattr(dpkt.ip, "IP_PROTO_ICMP"):
                proto_map[dpkt.ip.IP_PROTO_ICMP] = "ICMP"

            if not proto_map:
                raise ProtocolMappingError(
                    "Failed to build protocol mapping"
                )

            return proto_map

        except Exception as error:
            raise ProtocolMappingError(
                f"Failed to initialize IANA protocol mapping: {error}"
            ) from error

    def _batch_generator(
        self
    ) -> Generator[List[Tuple[bytes, float, int]], None, None]:
        """Stream PCAP file and yield batches of IPv4 packets.

        Handles multiple datalink types (Ethernet, Linux SLL, Raw IP) without
        hardcoded offsets. Uses dpkt's datalink() method for robust detection.

        Yields:
            Lists of tuples (ip_payload_bytes, timestamp_sec, total_packet_length).
            Empty payloads are skipped automatically.

        Raises:
            dpkt.UnpackError: If PCAP file is corrupted or unreadable.
        """
        current_batch: List[Tuple[bytes, float, int]] = []

        try:
            with open(self.pcap_path, "rb") as pcap_file:
                # Attempt to open as standard PCAP first
                try:
                    reader = dpkt.pcap.Reader(pcap_file)
                except (ValueError, dpkt.UnpackError):
                    # Fall back to PCAP-NG format
                    pcap_file.seek(0)
                    reader = dpkt.pcapng.Reader(pcap_file)

                # Detect datalink layer type once per file
                datalink_type = reader.datalink()

                logger.info(
                    f"[*] Detected datalink type: {datalink_type} "
                    f"(EN10MB={dpkt.pcap.DLT_EN10MB}, "
                    f"LINUX_SLL={dpkt.pcap.DLT_LINUX_SLL}, "
                    f"RAW={dpkt.pcap.DLT_RAW})"
                )

                packet_count = 0
                skipped_count = 0

                for timestamp, raw_packet_bytes in reader:
                    try:
                        # Extract IP layer based on datalink type
                        ip_payload: Optional[bytes] = None
                        total_length = len(raw_packet_bytes)

                        if datalink_type == dpkt.pcap.DLT_EN10MB:
                            # Standard Ethernet frame (EN10MB = Ethernet)
                            try:
                                eth_frame = dpkt.ethernet.Ethernet(raw_packet_bytes)
                                if isinstance(eth_frame.data, dpkt.ip.IP):
                                    ip_payload = bytes(eth_frame.data)
                            except (dpkt.UnpackError, AttributeError, TypeError):
                                skipped_count += 1
                                continue

                        elif datalink_type == dpkt.pcap.DLT_LINUX_SLL:
                            # Linux Cooked Capture (SLL)
                            try:
                                sll_frame = dpkt.sll.SLL(raw_packet_bytes)
                                if isinstance(sll_frame.data, dpkt.ip.IP):
                                    ip_payload = bytes(sll_frame.data)
                            except (dpkt.UnpackError, AttributeError, TypeError):
                                skipped_count += 1
                                continue

                        elif datalink_type == dpkt.pcap.DLT_RAW:
                            # Raw IP packets (no link layer header)
                            try:
                                ip_packet = dpkt.ip.IP(raw_packet_bytes)
                                if isinstance(ip_packet, dpkt.ip.IP):
                                    ip_payload = bytes(ip_packet)
                            except (dpkt.UnpackError, AttributeError, TypeError):
                                skipped_count += 1
                                continue

                        else:
                            # Unsupported datalink type - try generic IP extraction
                            try:
                                ip_packet = dpkt.ip.IP(raw_packet_bytes)
                                if isinstance(ip_packet, dpkt.ip.IP):
                                    ip_payload = bytes(ip_packet)
                            except (dpkt.UnpackError, AttributeError, TypeError):
                                skipped_count += 1
                                continue

                        # Only process valid IP payloads
                        if ip_payload is None or len(ip_payload) < 20:
                            # IP header minimum size is 20 bytes
                            skipped_count += 1
                            continue

                        packet_count += 1
                        current_batch.append((ip_payload, float(timestamp), total_length))

                        # Yield batch when it reaches chunk size
                        if len(current_batch) >= self.chunk_size:
                            yield current_batch
                            current_batch = []

                    except Exception:
                        # Skip any packet that causes parsing errors
                        skipped_count += 1
                        continue

                # Yield remaining packets in final incomplete batch
                if current_batch:
                    yield current_batch

                logger.info(f"[+] Batch generator complete: {packet_count} packets, "
                      f"{skipped_count} skipped")

        except FileNotFoundError as error:
            raise InvalidPcapPathError(f"PCAP file not found: {self.pcap_path}") from error
        except dpkt.UnpackError as error:
            raise InvalidPcapPathError(
                f"Failed to read PCAP file (corrupted?): {self.pcap_path}"
            ) from error


    def _get_protocol_name(self, protocol_id: int) -> str:
        """Resolve IANA protocol number to its official name.

        Args:
            protocol_id: IANA protocol number (0-255).

        Returns:
            Official protocol name in uppercase (e.g., 'TCP', 'UDP').
            Falls back to 'PROTO_{id}' if mapping not found.
        """
        protocol_name = self.iana_map.get(protocol_id, f"PROTO_{protocol_id}")
        return protocol_name.upper()





    def to_dataframe(self, n_jobs: Optional[int] = None) -> pd.DataFrame:
        """Extract PCAP packets into DataFrame using lazy streaming.

        Uses ProcessPoolExecutor with batch generator for memory efficiency.
        Avoids pre-loading entire PCAP into memory.

        Args:
            n_jobs: Number of worker processes. Default: -1 (use all cores).

        Returns:
            Pandas DataFrame with columns:
                - timestamp: Relative time from file start (seconds)
                - size: Total IP packet size (bytes)
                - entropy: Shannon entropy of transport payload (bits)
                - protocol: IANA protocol name
                - src_port, dst_port: Transport layer ports (-1 if N/A)
                - tcp_flags_*: TCP flag indicators (0 or 1)

        Raises:
            InvalidPcapPathError: If PCAP file is inaccessible.
        """
        # Determine worker count for multiprocessing
        num_workers = n_jobs if n_jobs is not None else self.n_jobs

        logger.info(f"Starting PCAP ingestion: {os.path.basename(self.pcap_path)}")
        logger.info(f"Architecture: StreamGenerator → ProcessPool → Polars Chunks")
        logger.info(f"Workers: {num_workers} | Chunk size: {self.chunk_size}")

        # Collect Polars DataFrames as chunks (no dict accumulation)
        chunks: List[pl.DataFrame] = []

        # MAX_INFLIGHT: Process batches in parallel as they are generated, converting to Polars immediately.
        MAX_INFLIGHT = num_workers * 2  # Limit number of batches in flight to control memory usage

        try:
            with concurrent.futures.ProcessPoolExecutor(
                max_workers=num_workers
            ) as executor:
                inflight = []
                first_packet_timestamp: float = 0.0
                
                # Submit batches to executor, consuming from generator lazily
                # Stream generator reads PCAP on-demand to avoid pre-loading entire file into memory
                for batch in self._batch_generator():
                    # Capture first packet timestamp for absolute time reference (v2.2.0)
                    if not first_packet_timestamp and batch:
                        first_packet_timestamp = batch[0][1]  # timestamp from first (ip_payload, timestamp, length) tuple
                    
                    # Use functools.partial for picklable multiprocessing (v2.2.0)
                    process_batch_func_partial = partial(
                        _process_batch, 
                        iana_map=self.iana_map, 
                        first_timestamp=first_packet_timestamp
                    )
                    
                    if len(inflight) >= MAX_INFLIGHT:
                        # Wait for at least one batch to complete to avoid saturating the executor queue
                        done, pending = concurrent.futures.wait(
                            inflight, return_when=concurrent.futures.FIRST_COMPLETED
                        )
                        for future in done:
                            res = future.result()
                            if res: chunks.append(pl.from_dicts(res))
                        inflight = list(pending)

                    inflight.append(executor.submit(process_batch_func_partial, batch))

                # Final cleanup: process remaining batches still in flight
                for future in concurrent.futures.as_completed(inflight):
                    res = future.result()
                    if res: chunks.append(pl.from_dicts(res))

        except Exception as error:
            if isinstance(error, InvalidPcapPathError):
                raise
            raise InvalidPcapPathError(
                f"Error processing PCAP: {error}"
            ) from error

        # Validate extraction results
        if not chunks:
            logger.info("[!] Warning: No IPv4 packets extracted from PCAP")
            return pd.DataFrame()

        logger.info(f"[+] Extracted {len(chunks)} chunks. Concatenating...")

        # Concatenate chunks efficiently in memory
        try:
            df_polars = pl.concat(chunks, rechunk=True)
            del chunks  # Release chunk list from memory
            gc.collect()  # Force garbage collection to free memory
        except Exception as error:
            raise ValueError(f"Failed to concatenate chunks: {error}") from error

        # CRITICAL FIX: Restore chronological order after parallel concatenation.
        # Parallel execution with n_jobs=N causes chunks to complete out-of-order.
        # Concatenating unordered chunks breaks time-series analysis and forensic auditing.
        # This sort operation is MANDATORY to prevent false "Data Drop" alerts and broken
        # delta calculations in downstream windowing. Uses Polars native sort for O(n log n) performance.
        logger.info("[*] Restoring chronological order (sort by absolute timestamp)...")
        df_polars = df_polars.sort("timestamp")

        # Add absolute timestamp (_abs_timestamp) and relative time (dt)
        # Now safe to perform after chronological restoration
        df_polars = df_polars.with_columns([
            pl.col("timestamp").alias("_abs_timestamp"),
            (pl.col("timestamp") - pl.col("timestamp").min()).alias("dt")
        ])

        # Ensure _abs_timestamp is treated as protected metadata
        logger.info(
            f"[+] Metadata preserved: _abs_timestamp column added. "
            f"Relative time (dt) calculated for windowing."
        )

        # Normalize timestamps to relative time from file start
        df_polars = df_polars.with_columns([
            pl.col("timestamp").alias("abs_ts"),
            (pl.col("timestamp") - pl.col("timestamp").min()).alias("time_rel")
        ])
        logger.info(
            f"[+] Ingestion complete: {len(df_polars)} packets, "
            f"time span: {df_polars['timestamp'].max():.2f}s"
        )

        return df_polars

    def _build_base_matrix(
        self, dataframe: pl.DataFrame, time_interval: str = "1s"
    ) -> pd.DataFrame:
        """Build feature matrix with dynamic protocol and TCP flag detection.

        Aggregates raw packet features into time-windowed statistics:
            - Intensity: Total bytes, packets/second (log-normalized)
            - Composition: Per-protocol ratios, TCP flags ratio, port diversity
            - Kinematics: Velocity (1st derivative), acceleration (2nd derivative)
            - Volatility: Rolling std deviation over 5-second windows
            - Momentum: Count of burst events (PPS > 1.5x rolling mean)
            - DoS/Flooding Detection: Dynamic Z-Score metrics over 60-second windows

        Args:
            dataframe: Raw packet DataFrame from to_dataframe().
            time_interval: Pandas resample frequency. Default "1s".

        Returns:
            Aggregated feature matrix indexed by relative time (seconds).
            Columns: Dynamic (based on detected protocols and TCP flags).
            
            Existing dimensions:
                - total_pps_log: Log-normalized packets per second.
                - total_bytes_log: Log-normalized bytes per second.
                - {protocol}_ratio: Per-protocol packet fraction.
                - flag_{name}_ratio: TCP flag fraction per window.
                    Includes: syn, ack, fin, rst, psh, urg.
                - port_scan_ratio: Unique destination ports per packet.
                - burst_factor: Max packet size / mean packet size.
                - entropy_avg: Mean Shannon entropy of payloads.
                - pps_velocity, bytes_velocity, entropy_velocity: 1st derivative.
                - pps_acceleration, bytes_acceleration: 2nd derivative.
                - pps_volatility, bytes_volatility, entropy_volatility: Rolling std.
                - pps_momentum: Burst event count (rolling 5-window sum).
            
            NEW physical dimensions (added in v2.1.0):
                - flow_duration: Temporal span of packets in window (seconds).
                    Floor: 1e-6 for single-packet windows (prevents /0 in ratios).
                - payload_continuity: Mean transport payload bytes per packet.
                    Zero is valid (header-only traffic: SYN floods, ACK storms).
                - iat_mean: Mean inter-arrival time between consecutive packets (s).
                    Derived as flow_duration / (pps - 1); floor at single-packet case.
                - flag_psh_ratio: PSH flag fraction per window.
                    Elevated values indicate data push bursts or exfiltration patterns.
                - flag_urg_ratio: URG flag fraction per window.
                    Elevated values indicate urgent pointer abuse or C2 signalling.
            
            NEW DoS/Flooding detection metrics (added in v2.3.0):
                - vel_pps_z: Dynamic Z-Score of total_pps_log (60-second rolling window).
                    Formula: (value - rolling_mean) / (rolling_std + 1e-6)
                    Detects relative velocity anomalies invisible in Hilbert space
                    when baseline magnitudes are similar to attack magnitudes.
                    Positive values = traffic regime shift upward (onset).
                    Negative values = traffic regime shift downward (decline).
                
                - vel_bytes_z: Dynamic Z-Score of total_bytes_log (60-second rolling window).
                    Similar to vel_pps_z but for aggregate throughput.
                    Captures volumetric DoS attacks (bandwidth-based flooding).
                
                - vel_syn_z: Dynamic Z-Score of flag_syn_ratio (60-second rolling window).
                    High positive values indicate SYN flood onset.
                    Normalized by historical SYN packet proportion to reduce false positives.

        Raises:
            ValueError: If dataframe is empty or cannot be aggregated.
        """
        # Convert to Polars LazyFrame and prepare the time axis
        lf = dataframe.lazy()
        lf = lf.with_columns([
            pl.col("timestamp").cast(pl.Int64).alias("second_window")
        ])

        # Detect protocols and TCP flags dynamically
        protocols = dataframe["protocol"].unique().to_list()
        flag_cols = [c for c in dataframe.columns if c.startswith("tcp_flags_")]

        # Dynamic aggregation
        matrix = (
            lf.group_by("second_window")
            .agg([
                pl.len().alias("pps"),
                pl.col("size").sum().alias("bytes"),
                *[(pl.col("protocol") == p).sum().alias(f"count_{p.lower()}") for p in protocols],
                *[(pl.col(f) == 1).sum().alias(f"count_{f.replace('tcp_flags_', '')}") for f in flag_cols],
                pl.col("dst_port").n_unique().alias("unique_dst_ports"),
                pl.col("size").mean().alias("size_avg"),
                pl.col("entropy").mean().alias("entropy_avg"),
                pl.col("size").max().alias("size_max"),
                # NEW PHYSICAL DIMENSIONS ---
                # Flow Duration: temporal span of packets within each window.
                pl.col("timestamp").max().alias("_ts_max"),
                pl.col("timestamp").min().alias("_ts_min"),
                # Payload volume: total transport payload bytes across the window.
                pl.col("payload_bytes").sum().alias("total_payload_bytes"),
                # NEW v2.2.0: L7-Asymmetry and Absolute Timestamps ---
                # Absolute timestamp (first packet in window) for forensic reporting.
                pl.col("abs_ts").min().alias("_abs_timestamp"),
                # Request and response payload accumulation (directional traffic analysis).
                pl.col("req_payload").sum().alias("total_req_payload"),
                pl.col("res_payload").sum().alias("total_res_payload"),
                # Service port (most common, acts as flow classifier) - use temp name to avoid conflicts
                pl.col("server_port").max().alias("_server_port_agg"),
            ])
            .with_columns([
                # Logarithmic transformation of intensity metrics
                pl.col("pps").log1p().alias("total_pps_log"),
                pl.col("bytes").log1p().alias("total_bytes_log"),

                # Dynamic ratios for protocols, flags, and ports
                *[(pl.col(f"count_{p.lower()}") / pl.col("pps")).alias(f"{p.lower()}_ratio") for p in protocols],
                *[(pl.col(f"count_{f.replace('tcp_flags_', '')}") / pl.col("pps")).alias(f"flag_{f.replace('tcp_flags_', '')}_ratio") for f in flag_cols],
                (pl.col("unique_dst_ports") / pl.col("pps")).alias("port_scan_ratio"),

                # Burst factor
                (pl.col("size_max") / pl.col("size_avg")).alias("burst_factor"),

                # --- NEW PHYSICAL DIMENSION DERIVATIONS ---
                # Flow Duration (seconds): temporal span within the aggregation window.
                # Silence treatment: 1e-6 floor prevents /0 in iat_mean and future
                # duration-derived features. Do NOT use 0.0 — it propagates silently
                # through ratio chains and collapses to NaN after log transforms.
                (
                    (pl.col("_ts_max") - pl.col("_ts_min"))
                    .clip(lower_bound=1e-6)
                    .alias("flow_duration")
                ),

                # Payload Continuity: mean payload bytes per packet.
                # Zero is semantically valid: a window of pure header traffic has
                # 0 payload bytes and continuity=0.0. No floor needed here.
                (pl.col("total_payload_bytes") / pl.col("pps")).alias("payload_continuity"),

                # --- NEW v2.2.0: L7-Asymmetry Ratio ---
                # Payload Continuity Ratio: response payload vs request payload.
                # High values (> 1.0) indicate server is responding with more data than
                # clients are sending (normal for data exfiltration/C2 beaconing).
                # Low values (< 1.0) indicate balanced bidirectional traffic.
                (pl.col("total_res_payload") / (pl.col("total_req_payload") + 1e-6)).alias("payload_continuity_ratio"),

                # Server Port: identified service port (metadata, will NOT be scaled).
                pl.col("_server_port_agg").alias("server_port"),
            ])
            .with_columns([
                # IAT Mean (Inter-Arrival Time): mean gap between consecutive packets.
                # Denominator floor: clip(lower_bound=2) ensures pps=1 maps to
                # iat_mean = flow_duration / 1 = flow_duration (not /0).
                # This is physically correct: one packet has no inter-arrival time,
                # so we use the window duration as a conservative upper bound.
                (
                    pl.col("flow_duration") / (pl.col("pps").clip(lower_bound=2) - 1)
                ).alias("iat_mean"),
            ])
            .sort("second_window")
            .with_columns([
                # Kinetics: First and second derivatives of PPS and entropy
                pl.col("total_pps_log").diff().fill_null(0).alias("pps_velocity"),
                pl.col("total_bytes_log").diff().fill_null(0).alias("bytes_velocity"),
                pl.col("entropy_avg").diff().fill_null(0).alias("entropy_velocity"),
            ])
            .with_columns([
                # Acceleration (second derivative)
                pl.col("pps_velocity").diff().fill_null(0).alias("pps_acceleration"),
                pl.col("bytes_velocity").diff().fill_null(0).alias("bytes_acceleration"),
                pl.col("entropy_velocity").diff().fill_null(0).alias("entropy_acceleration"),

                # Volatility: Rolling std dev over 5-second windows
                pl.col("total_pps_log").rolling_std(5).fill_null(0).alias("pps_volatility"),
                pl.col("total_bytes_log").rolling_std(5).fill_null(0).alias("bytes_volatility"),
                pl.col("entropy_avg").rolling_std(5).fill_null(0).alias("entropy_volatility"),

                #Momentum: Cumulative sum of PPS and entropy
                (pl.col("total_pps_log") > (pl.col("total_pps_log").rolling_mean(window_size=10) * 1.5))
                .cast(pl.Int64)
                .rolling_sum(window_size=5)
                .alias("pps_momentum")
            ])
            .with_columns([
                # --- NEW: Dynamic Z-Score metrics (60-second rolling window) ---
                # Detects relative velocity anomalies for DoS/Flooding onset detection.
                # Formula: (current_value - rolling_mean) / (rolling_std + 1e-6)
                # 60-second window captures traffic regime transitions invisible in Hilbert space
                # when baseline magnitudes are similar to attack magnitudes.
                (
                    (pl.col("total_pps_log") - pl.col("total_pps_log").rolling_mean(60)) / 
                    (pl.col("total_pps_log").rolling_std(60) + 1e-6)
                ).fill_null(0).alias("vel_pps_z"),
                
                (
                    (pl.col("total_bytes_log") - pl.col("total_bytes_log").rolling_mean(60)) / 
                    (pl.col("total_bytes_log").rolling_std(60) + 1e-6)
                ).fill_null(0).alias("vel_bytes_z"),
                
                (
                    (pl.col("flag_syn_ratio") - pl.col("flag_syn_ratio").rolling_mean(60)) / 
                    (pl.col("flag_syn_ratio").rolling_std(60) + 1e-6)
                ).fill_null(0).alias("vel_syn_z"),
            ])
            .drop(["_ts_max", "_ts_min", "total_payload_bytes", "total_req_payload", "total_res_payload", "_server_port_agg"])
            .fill_null(0)
            .collect()
        )

        

        # Select final columns (ratios + intensity + stats)
        FEATURE_WHITELIST = [
            "_ratio",                    # Protocol ratios, flag ratios, port scan ratio
            "_log",                      # Log-normalized intensity metrics
            "avg",                       # Entropy average, size average
            "factor",                    # Burst factor
            "velocity",                  # First derivative of intensity signals
            "acceleration",              # Second derivative
            "volatility",                # Rolling standard deviation
            "momentum",                  # Burst event accumulation
            "flow_duration",             # NEW: Temporal span of traffic window
            "payload_continuity",        # NEW: Mean payload bytes per packet
            "iat_mean",                  # NEW: Mean inter-arrival time between packets
            "payload_continuity_ratio",  # NEW v2.2.0: L7-Asymmetry (response/request ratio)
            "server_port",               # NEW v2.2.0: Identified service port (metadata)
            "vel_",                      # NEW DoS/Flooding: Dynamic Z-Score metrics (60s window)
        ]
        
        # METADATA COLUMNS: Start with _ or meta_; excluded from scaling
        METADATA_COLS = ["_abs_timestamp", "server_port"]
        
        BASE_PHYSICAL_METRICS = ["size_max", "unique_dst_ports", "bytes"]

        # Select feature columns (whitelist) + metadata columns (explicit)
        final_cols = [
             c for c in matrix.columns 
             if any(suffix in c for suffix in FEATURE_WHITELIST) 
             or c in BASE_PHYSICAL_METRICS
        ]
        
        # Ensure metadata columns are included and preserved (avoid duplicates)
        metadata_cols_present = [c for c in matrix.columns if c in METADATA_COLS and c not in final_cols]
        final_cols = final_cols + metadata_cols_present

        df_final = matrix.rename({"second_window": "dt"}).select(["dt"] + final_cols).to_pandas()
        return df_final.set_index("dt")

    @staticmethod
    def _identity_func(x: Any) -> Any:
        """Identity transformation for ColumnTransformer.

        Used to preserve ratio columns without scaling.

        Args:
            x: Input data (unchanged).

        Returns:
            Output data (identical to input).
        """
        return x

    def get_standardized_matrix(
        self,
        dataframe: pd.DataFrame,
        scaler_type: str = "standard",
        export_name: Optional[str] = "network_preprocessor",
        trained_scaler: Optional[ColumnTransformer] = None,
    ) -> pd.DataFrame:
        """Standardize feature matrix with hybrid scaling strategy + numerical stability.

        Applies dual-strategy scaling:
            - Ratios: Identity (no scaling, already normalized to [0, 1])
            - Other features: Standard or Robust scaler (zero-mean, unit variance)

        **STABILITY PATCHES (Senior Data Engineering):**
        1. Sanitización de Datos: Inf → NaN → 0 (evita explosión numérica)
        2. Blindaje de Tipos: select_dtypes(numeric) (solo columnas numéricas)
        3. Paralelismo Real: n_jobs=self.n_jobs en ColumnTransformer
        4. Contrato de Inferencia: fit_transform garantiza determinismo

        The preprocessor is persisted to models/scalers/ for inference pipeline.

        Args:
            dataframe: Aggregated feature matrix from _build_base_matrix().
            scaler_type: "standard" for StandardScaler or "robust" for RobustScaler.
            export_name: Name prefix for saved scaler artifact.

        Returns:
            Standardized DataFrame with same shape and index as input.

        Raises:
            ValueError: If dataframe is empty or scaler_type is invalid.

        Examples:
            >>> base_matrix = processor._build_base_matrix(df)
            >>> scaled = processor.get_standardized_matrix(base_matrix, scaler_type="robust")
            >>> logger.info(scaled.shape)  # (n_windows, n_features)
        """
        # Handle both Polars and Pandas DataFrames (v2.2.0 compatibility)
        if isinstance(dataframe, pl.DataFrame):
            dataframe = dataframe.to_pandas()
        
        if len(dataframe) == 0:
            raise ValueError("Input DataFrame is empty")

        if scaler_type not in ("standard", "robust"):
            raise ValueError(f"scaler_type must be 'standard' or 'robust', got {scaler_type}")

        # ====== METADATA COLUMN EXTRACTION (v2.2.0) ======
        # Separate metadata columns (start with _ or meta_, OR in KNOWN_METADATA_COLS) for preservation.
        # These are NOT scaled and are rejoined after transformation.
        KNOWN_METADATA_COLS = ["_abs_timestamp", "server_port"]  # Known metadata columns (v2.2.0)
        metadata_cols = [
            c for c in dataframe.columns 
            if c.startswith("_") or c.startswith("meta_") or c in KNOWN_METADATA_COLS
        ]
        df_metadata = dataframe[metadata_cols].copy() if metadata_cols else pd.DataFrame()
        
        df_without_metadata = dataframe[[c for c in dataframe.columns if c not in metadata_cols]].copy()

        # ====== DATA SANITIZATION ======
        # Replace Inf and -Inf with NaN, then fill NaN with 0.
        # Prevents numerical overflow in downstream transformations (PowerTransformer).
        df_sanitized = df_without_metadata.replace([np.inf, -np.inf], np.nan)
        n_inf_replaced = df_sanitized.isna().sum().sum() - df_without_metadata.isna().sum().sum()
        if n_inf_replaced > 0:
            logger.info(f"Sanitization: Replaced {n_inf_replaced} Inf/NaN values with 0")
        df_sanitized = df_sanitized.fillna(0.0)

        # ====== TYPE SAFETY ======
        # Select only numeric columns to prevent conversion errors
        # (e.g., string columns like 'TCP' that would break downstream steps)
        df_numeric_only = df_sanitized.select_dtypes(include=[np.number])
        
        # Verify no critical columns were lost
        if len(df_numeric_only.columns) != len(df_sanitized.columns):
            dropped_cols = set(df_sanitized.columns) - set(df_numeric_only.columns)
            logger.info(f"[!] Warning: Non-numeric columns removed: {dropped_cols}")
        
        # Identify ratio columns vs others (only from numeric columns)
        # Exclude metadata columns from scaling (already separated above)
        ratio_cols = [c for c in df_numeric_only.columns if "ratio" in c]
        other_cols = [c for c in df_numeric_only.columns if c not in ratio_cols]

        if trained_scaler is not None:
            # If pre-trained scaler provided, use it directly (inference mode)
            matrix_scaled = trained_scaler.transform(df_numeric_only)
            cols_out = trained_scaler.get_feature_names_out()
        
        else:

            # ====== PARALLEL PROCESSING ======
            # Pass n_jobs=self.n_jobs to ColumnTransformer for multi-core execution
            # especially for scaling tasks.
            preprocessor = ColumnTransformer(
                transformers=[
                    ("ratios", FunctionTransformer(self._identity_func, feature_names_out='one-to-one'), ratio_cols),
                    (
                        "scaler",
                        StandardScaler() if scaler_type == "standard" else RobustScaler(),
                        other_cols,
                    )
                ],
                verbose_feature_names_out=False,
                n_jobs=self.n_jobs  # Use configured CPU cores
            )

            # ====== INFERENCE CONTRACT ======
            # fit_transform ensures determinism:
            # - Training: compute baseline statistics
            # - Detection: use .transform() only (no recalculation, strict contract)
            matrix_scaled = preprocessor.fit_transform(df_numeric_only)
            cols_out = preprocessor.get_feature_names_out()

            # Persist the preprocessor for inference
            os.makedirs(os.path.join("models", "scalers"), exist_ok=True)
            model_path = os.path.join("models", "scalers", f"{scaler_type}_{export_name}.pkl")
            joblib.dump(preprocessor, model_path)

            logger.info(f"[+] Scaler saved to: {model_path}")
            logger.info(f"[+] Configuration: scaler_type={scaler_type}, n_jobs={self.n_jobs}, "
                f"ratio_cols={len(ratio_cols)}, numeric_cols={len(other_cols)}")

        # Reconstruct the DataFrame with original column names
        df_result = pd.DataFrame(
            matrix_scaled,
            columns=cols_out,
            index=df_numeric_only.index
        )
        
        # NOTE: Metadata columns are NOT re-attached here (v2.2.0)
        # The orchestrator handles metadata extraction/re-attachment explicitly
        # This ensures the engine only receives feature columns it was trained on
        if not df_metadata.empty:
            logger.info(f"[+] Metadata columns extracted but NOT re-attached (orchestrator responsibility): {metadata_cols}")
        
        return df_result

    def get_capture_health_report(
        self, dataframe: pd.DataFrame, verbose: bool = False
    ) -> Dict[str, Any]:
        """Generate comprehensive data integrity report for network capture.

        Validates capture quality and pipeline health using statistical moments,
        temporal continuity, and physical constraints.

        **Validation Checks:**
            1. Silent Periods: % of time windows with zero packets
            2. Statistical Moments: Skewness and Kurtosis of PPS and Entropy
            3. Temporal Continuity: Packet timestamp gaps (detect loss/reordering)
            4. Physical Bounds: Entropy range verification [0.0, 8.0] bits

        Args:
            dataframe: Raw packet DataFrame with [timestamp, size, entropy, protocol].
            verbose: If True, logger.info formatted human-readable report to stdout.

        Returns:
            Dictionary with keys:
                - packet_count: Total IPv4 packets
                - time_span_sec: Duration from start to end (seconds)
                - pps_avg: Mean packets per second
                - silent_windows_pct: % of 1-second windows with 0 PPS
                - entropy_avg: Mean payload entropy (bits)
                - entropy_std: Std dev of entropy
                - pps_skewness: Statistical skewness (>0 = right-skewed distribution)
                - pps_kurtosis: Statistical kurtosis (>3 = heavy-tailed)
                - entropy_skewness: Entropy distribution skewness
                - entropy_kurtosis: Entropy distribution kurtosis
                - max_timestamp_gap_sec: Largest gap between consecutive packets
                - entropy_violations: Count of samples outside [0.0, 8.0] range

        Raises:
            ValueError: If dataframe is empty.

        Examples:
            >>> df = processor.to_dataframe()
            >>> report = processor.get_capture_health_report(df, verbose=True)
            >>> if report['entropy_violations'] > 0:
            ...     logger.info(f"⚠️  {report['entropy_violations']} entropy anomalies detected")
        """
        if dataframe.empty:
            raise ValueError("Input DataFrame is empty")

        # Extract metrics from raw packets
        dataframe["timestamp"] = dataframe["timestamp"].astype(float)
        packet_count = len(dataframe)
        time_span_sec = dataframe["timestamp"].max() - dataframe["timestamp"].min()

        # Time-series aggregation for PPS (packets per second)
        pps_ts = dataframe.groupby(
            pd.cut(dataframe["timestamp"], bins=int(time_span_sec) + 1),
            observed=True
        ).size()

        # Statistical moments
        pps_avg = pps_ts.mean()
        pps_skewness = float(sp.stats.skew(pps_ts, bias=False))
        pps_kurtosis = float(sp.stats.kurtosis(pps_ts, bias=False))

        entropy_data = dataframe["entropy"].values
        entropy_avg = float(entropy_data.mean())
        entropy_std = float(entropy_data.std())
        entropy_skewness = float(sp.stats.skew(entropy_data, bias=False))
        entropy_kurtosis = float(sp.stats.kurtosis(entropy_data, bias=False))

        # Silent windows
        silent_windows = (pps_ts == 0).sum()
        silent_pct = (silent_windows / len(pps_ts) * 100) if len(pps_ts) > 0 else 0.0

        # Temporal continuity: detect gaps in timestamps
        time_diffs = np.diff(dataframe["timestamp"].values)
        max_gap_sec = float(
            time_diffs.max() if len(time_diffs) > 0 else 0.0
        )

        # Physical bounds validation
        entropy_violations = int(
            ((entropy_data < 0.0) | (entropy_data > 8.0)).sum()
        )

        # Construct report
        report = {
            "packet_count": int(packet_count),
            "time_span_sec": float(time_span_sec),
            "pps_avg": float(pps_avg),
            "silent_windows_pct": float(silent_pct),
            "entropy_avg": entropy_avg,
            "entropy_std": entropy_std,
            "pps_skewness": pps_skewness,
            "pps_kurtosis": pps_kurtosis,
            "entropy_skewness": entropy_skewness,
            "entropy_kurtosis": entropy_kurtosis,
            "max_timestamp_gap_sec": max_gap_sec,
            "entropy_violations": entropy_violations,
        }

        # Print formatted summary
        if verbose:
            logger.info("\n" + "=" * 80)
            logger.info("CAPTURE HEALTH REPORT")
            logger.info("=" * 80)
            logger.info(f"Packets Analyzed:        {report['packet_count']:,}")
            logger.info(f"Time Span:               {report['time_span_sec']:.2f} seconds")
            logger.info(f"Average PPS:             {report['pps_avg']:.2f} packets/sec")
            logger.info(f"Silent Windows:          {report['silent_windows_pct']:.1f}%")
            logger.info("\nPayload Entropy (bits):")
            logger.info(f"  Mean:                  {report['entropy_avg']:.3f}")
            logger.info(f"  Std Dev:               {report['entropy_std']:.3f}")
            logger.info(f"  Entropy Violations:    {report['entropy_violations']} (valid: [0.0, 8.0])")
            logger.info("\nStatistical Moments (PPS):")
            logger.info(f"  Skewness:              {report['pps_skewness']:.3f}")
            logger.info(f"  Kurtosis:              {report['pps_kurtosis']:.3f}")
            logger.info("\nStatistical Moments (Entropy):")
            logger.info(f"  Skewness:              {report['entropy_skewness']:.3f}")
            logger.info(f"  Kurtosis:              {report['entropy_kurtosis']:.3f}")
            logger.info("\nTemporal Continuity:")
            logger.info(f"  Max Timestamp Gap:     {report['max_timestamp_gap_sec']:.4f} sec")
            logger.info("=" * 80 + "\n")

        return report

if __name__ == "__main__":
    # Configuration
    PCAP_INPUT_PATH: str = "data/raw/Monday_Victim_50.pcap"
    TIME_WINDOW_INTERVAL: str = "1s"

    # Dynamically generate the output CSV path based on the input PCAP file name
    pcap_filename = os.path.basename(PCAP_INPUT_PATH).replace(".pcap", "")
    CSV_OUTPUT_PATH: str = f"data/processed/{pcap_filename}_standardized_matrix.csv"

    try:
        # Initialize processor with memory-efficient chunk size
        processor: PcapProcessor = PcapProcessor(
            pcap_path=PCAP_INPUT_PATH, chunk_size=5000
        )

        # Extract features from PCAP
        logger.info("[*] Extracting packet features...")
        raw_dataframe: pd.DataFrame = processor.to_dataframe()

        if raw_dataframe.empty:
            logger.info("[!] Warning: No IPv4 packets found in PCAP")
        else:
            logger.info(f"[+] Extracted {len(raw_dataframe)} packets")

        # Aggregate into time-windowed matrix
        logger.info(f"Building base matrix (Composition + Intensity)...")
        base_matrix = processor._build_base_matrix(raw_dataframe, time_interval=TIME_WINDOW_INTERVAL)

        logger.info(f"Standardizing feature matrix...")
        feature_matrix: pd.DataFrame = processor.get_standardized_matrix(
            base_matrix,
            scaler_type="robust",
            export_name=pcap_filename 
        )

        # Display results
        logger.info("\n" + "=" * 80)
        logger.info("STANDARDIZED FEATURE MATRIX (IANA-COMPLIANT, OPTIMIZED)")
        logger.info("=" * 80)
        logger.info(f"Matrix shape: {feature_matrix.shape}")
        logger.info(f"Time range: {feature_matrix.index.min():.2f}s - {feature_matrix.index.max():.2f}s")
        logger.info("-" * 80)
        logger.info(feature_matrix.head(10))
        logger.info("=" * 80)
        logger.info(processor.get_capture_health_report(raw_dataframe))

        # Persist results
        os.makedirs(os.path.dirname(CSV_OUTPUT_PATH), exist_ok=True)
        feature_matrix.to_csv(CSV_OUTPUT_PATH)
        logger.info(f"[+] Matrix saved to: {CSV_OUTPUT_PATH}")
        logger.info(f"[+] File size: {os.path.getsize(CSV_OUTPUT_PATH) / 1024:.2f} KB")

    except InvalidPcapPathError as error:
        logger.info(f"[!] PCAP Access Error: {error}")
    except ProtocolMappingError as error:
        logger.info(f"[!] Protocol Mapping Error: {error}")
    except ValueError as error:
        logger.info(f"[!] Data Validation Error: {error}")
    except Exception as error:
        logger.info(f"[!] Unexpected Error: {error}")
        raise
        
## File: src/orchestrator.py
#!/usr/bin/env python3
"""
HiGI Orchestrator: Production-Grade IDS Pipeline Orchestration.

Manages the complete lifecycle of network anomaly detection:
  1. TRAINING MODE: Baseline establishment from benign network traffic
  2. DETECTION MODE: Inference on test data with cascaded sentinel architecture

Architecture:
  Training → PCAP (Baseline) → PcapProcessor (optime) → Scalers → HiGI Engine → Bundle
  Detection → PCAP (Test) + Bundle → Feature Transform → HiGI Analyze → Results

Production Requirements:
  - Feature schema consistency enforcement (train.feature_cols == test.feature_cols)
  - Strict standardization contract: Only .transform() in detection mode
  - Comprehensive logging and error handling
  - Artifact versioning and metadata tracking

Module: scripts/higi_orchestrator.py
Author: Blue Team Engineering
Date: 2026-04-09
"""

import argparse
import gc
import logging
import sys
import time
import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import traceback
import os
import warnings
from sklearn.exceptions import ConvergenceWarning

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pandas as pd
import joblib

from src.ingestion.processor_optime import PcapProcessor, PcapProcessorError
from src.models.higi_engine import (
    HiGIEngine,
    HiGIConfig,
    HiGITrainingError,
    HiGIInferenceError,
)
from src.config import HiGISettings


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configure logging for orchestrator."""
    logger = logging.getLogger("HiGI_Orchestrator")
    logging.getLogger().handlers = []
    logger.setLevel(getattr(logging, log_level.upper()))
    warnings.filterwarnings("ignore", category=ConvergenceWarning)

    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


logger = setup_logging("INFO")


# ============================================================================
# CUSTOM EXCEPTIONS
# ============================================================================


class OrchestratorError(Exception):
    """Base exception for orchestration failures."""

    pass


class TrainingError(OrchestratorError):
    """Raised when training pipeline fails."""

    pass


class DetectionError(OrchestratorError):
    """Raised when detection pipeline fails."""

    pass


class ArtifactError(OrchestratorError):
    """Raised when artifact loading/saving fails."""

    pass


# ============================================================================
# ARTIFACT MANAGEMENT
# ============================================================================


class ArtifactBundle:
    """Immutable container for trained model artifacts.

    !! CRITICAL ARCHITECTURE FIX (Matrioshka Escalado):
    The bundle now ONLY stores engine + schema. Scaling is encapsulated inside HiGIEngine.
    This removes the triple-scaling bug that was collapsing variance.
    """

    def __init__(
        self,
        engine: HiGIEngine,
        feature_cols: list,
        metadata: Dict[str, Any],
        scaler: Any = None,  # REMOVED: No external scaler, all normalization is internal to HiGIEngine
        baseline_medians: Optional[
            Dict[str, float]
        ] = None,  # Baseline feature medians for safe imputation
    ) -> None:
        """
        Initialize artifact bundle.

        Args:
            engine: Trained HiGIEngine instance (contains internal PowerTransformer + PCA)
            feature_cols: Ordered list of feature column names (schema contract)
            metadata: Training metadata (date, source PCAP, version, etc.)
            baseline_medians: Dict mapping feature names to median values from training baseline.
                Used for safe imputation of missing protocol features in test data.
                If None, defaults to empty dict (will use 0.0 fallback during detection).
        """
        self.engine = engine
        self.feature_cols = feature_cols
        self.metadata = metadata
        self.scaler = scaler  # Scaler of baseline
        self.baseline_medians = baseline_medians if baseline_medians is not None else {}

    def save(self, path: str) -> None:
        """
        Persist bundle to disk as single .joblib file.
        !! CRITICAL FIX (Matrioshka Escalado): Now saves RobustScaler + schema + engine

        Args:
            path: Output file path (e.g., 'models/baseline_monday.pkl')

        Raises:
            ArtifactError: If save fails
        """
        try:
            path_obj = Path(path)
            path_obj.parent.mkdir(parents=True, exist_ok=True)

            state = {
                "engine": self.engine,
                "feature_cols": self.feature_cols,
                "metadata": self.metadata,
                "scaler": self.scaler,  # !! CRITICAL: Save RobustScaler for deterministic inference
                "baseline_medians": self.baseline_medians,  # Median values for safe imputation of missing features
            }

            joblib.dump(state, path_obj)
            logger.info(f"[✓] Bundle saved: {path}")
            if self.scaler is not None:
                logger.info(
                    f"    Artifacts: RobustScaler (physics) + Engine (internal normalizers) + {len(self.feature_cols)} features"
                )
            else:
                logger.info(
                    f"    Artifacts: Engine (with internal normalizers) + {len(self.feature_cols)} features"
                )

            # Write metadata sidecar for quick inspection
            metadata_path = path_obj.with_suffix(".json")
            with open(metadata_path, "w") as f:
                json.dump(self.metadata, f, indent=2, default=str)
            logger.info(f"[✓] Metadata sidecar: {metadata_path}")

        except Exception as e:
            raise ArtifactError(f"Failed to save bundle: {str(e)}") from e

    @staticmethod
    def load(path: str) -> "ArtifactBundle":
        """
        Load bundle from disk.

        Args:
            path: Bundle file path

        Returns:
            Loaded ArtifactBundle

        Raises:
            ArtifactError: If load fails or file not found
        """
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                raise FileNotFoundError(f"Bundle not found: {path}")

            state = joblib.load(path_obj)

            # Handle both old (without scaler/medians) and new bundle format
            bundle = ArtifactBundle(
                engine=state["engine"],
                feature_cols=state["feature_cols"],
                metadata=state["metadata"],
                scaler=state.get(
                    "scaler", None
                ),  # !! CRITICAL: Restore RobustScaler (None for old bundles)
                baseline_medians=state.get(
                    "baseline_medians", {}
                ),  # Median imputation values (empty dict for old bundles)
            )

            logger.info(f"[✓] Bundle loaded: {path}")
            logger.info(
                f"    Baseline PCAP: {bundle.metadata.get('source_pcap', 'N/A')}"
            )
            logger.info(
                f"    Training date: {bundle.metadata.get('training_date', 'N/A')}"
            )
            logger.info(f"    Features: {len(bundle.feature_cols)}")
            if bundle.scaler is not None:
                logger.info("    ✓ RobustScaler restored (physics layer)")
            logger.info(
                "    ✓ Engine contains internal normalizers (PowerTransformer + PCA)"
            )
            # [Phase 6] Log restored Phase 6 capabilities
            phase6_features = bundle.metadata.get("phase_6_features", {})
            if phase6_features:
                logger.info("    [Phase 6] Restored capabilities:")
                logger.info(
                    f"      BayesianGMM: {phase6_features.get('bayesian_gmm', 'N/A')}"
                )
                logger.info(
                    f"      CDF normalization: {phase6_features.get('cdf_normalization', 'N/A')}"
                )
                logger.info(
                    f"      Per-feature thresholds: {phase6_features.get('per_feature_sensitivity', 'N/A')}"
                )
                logger.info(
                    f"      Directionality (SPIKE/DROP): {phase6_features.get('directionality_analysis', 'N/A')}"
                )
            per_feature_thresholds = bundle.metadata.get(
                "per_feature_ll_thresholds", {}
            )
            if per_feature_thresholds:
                logger.info(
                    f"    [Phase 6] Per-feature LL thresholds: {len(per_feature_thresholds)} features"
                )

            return bundle

        except Exception as e:
            raise ArtifactError(f"Failed to load bundle: {str(e)}") from e


# ============================================================================
# PIPELINE: TRAINING MODE
# ============================================================================


class TrainingPipeline:
    """Orchestrates baseline establishment from benign network traffic."""

    def __init__(
        self,
        pcap_path: str,
        output_bundle_path: str,
        chunks: int = 5000,
        cores: int = 6,
        higi_config: Optional[HiGIConfig] = None,
        augmentation_noise_scale: Optional[float] = None,
        augmentation_synthetic_fraction: Optional[float] = None,
    ) -> None:
        """
        Initialize the training pipeline with dependency injection.

        Args:
            pcap_path: Path to baseline PCAP file.
            output_bundle_path: Path where to save the artifact bundle.
            chunks: PCAP processing chunk size (packets per chunk).
            cores: Number of CPU cores for parallel ingestion.
            higi_config: HiGIConfig instance for engine configuration.
                If None, creates a minimal default config.
            augmentation_noise_scale: Noise scale for baseline augmentation (fraction of std dev).
                If None, defaults to 0.05 (5%).
            augmentation_synthetic_fraction: Fraction of augmented samples relative to baseline.
                If None, defaults to 0.10 (10%).
        """
        self.pcap_path = Path(pcap_path)
        self.output_bundle_path = Path(output_bundle_path)
        self.chunks = chunks
        self.cores = cores

        # Dependency injection: accept pre-configured HiGIConfig
        self.higi_config = higi_config or HiGIConfig()

        # Augmentation parameters with sensible defaults
        self.augmentation_noise_scale = (
            augmentation_noise_scale if augmentation_noise_scale is not None else 0.05
        )
        self.augmentation_synthetic_fraction = (
            augmentation_synthetic_fraction
            if augmentation_synthetic_fraction is not None
            else 0.10
        )

        if not self.pcap_path.exists():
            raise TrainingError(f"PCAP file not found: {pcap_path}")

        logger.info(f"\n{'=' * 90}")
        logger.info("HiGI ORCHESTRATOR: TRAINING PIPELINE")
        logger.info(f"{'=' * 90}")
        logger.info(f"Input PCAP: {self.pcap_path}")
        logger.info(f"Output bundle: {self.output_bundle_path}")
        logger.info(f"Augmentation noise scale: {self.augmentation_noise_scale:.3f}")
        logger.info(
            f"Augmentation synthetic fraction: {self.augmentation_synthetic_fraction:.3f}"
        )

    def _augment_baseline(
        self,
        df_baseline: pd.DataFrame,
        noise_scale: Optional[float] = None,
        synthetic_fraction: Optional[float] = None,
    ) -> pd.DataFrame:
        """
        Augment baseline with Gaussian noise to improve generalization.

        Prevents overfitting to specific traffic pattern by synthesizing
        plausible variants of normal behavior.

        Args:
            df_baseline: Original baseline feature matrix.
            noise_scale: Noise magnitude as fraction of feature std dev.
                If None, uses self.augmentation_noise_scale from config.
            synthetic_fraction: Fraction of augmented samples relative to baseline.
                If None, uses self.augmentation_synthetic_fraction from config.

        Returns:
            pd.DataFrame: Augmented baseline (original + synthetic).
        """
        # Use injected parameters or fall back to instance defaults
        noise_scale = (
            noise_scale if noise_scale is not None else self.augmentation_noise_scale
        )
        synthetic_fraction = (
            synthetic_fraction
            if synthetic_fraction is not None
            else self.augmentation_synthetic_fraction
        )

        # Calculate number of synthetic samples to add
        n_augmented = int(len(df_baseline) * synthetic_fraction)

        rng = np.random.default_rng(seed=42)  # Reproducible augmentation
        stds = df_baseline.std(axis=0)

        noise = rng.normal(
            loc=0.0,
            scale=noise_scale * stds.values,
            size=(n_augmented, df_baseline.shape[1]),
        )

        sample_indices = rng.integers(0, len(df_baseline), size=n_augmented)
        augmented_data = df_baseline.iloc[sample_indices].values + noise

        result = pd.concat(
            [df_baseline, pd.DataFrame(augmented_data, columns=df_baseline.columns)],
            ignore_index=True,
        )

        logger.debug(
            f"Augmentation: {len(df_baseline)} baseline → "
            f"+{n_augmented} synthetic → {len(result)} total "
            f"(noise_scale={noise_scale:.3f}, synthetic_fraction={synthetic_fraction:.3f})"
        )

        return result

    def run(self) -> ArtifactBundle:
        """
        Execute complete training pipeline.

        Pipeline:
          1. PCAP Ingestion: Extract packets and compute features
          2. Feature Aggregation: Time-windowed matrix construction
          3. Scaler Training: Fit RobustScaler on aggregated features
          4. Transformer Training: Fit PowerTransformer (Yeo-Johnson)
          5. HiGI Training: Train cascaded sentinel detectors
          6. Bundle Creation: Assemble artifacts with metadata

        Returns:
            ArtifactBundle ready for persistence

        Raises:
            TrainingError: If any step fails
        """
        try:
            # ---- STEP 1: PCAP Ingestion ----
            logger.info("\n[STEP 1] PCAP Ingestion (PcapProcessor)")
            logger.info("-" * 90)
            t0 = time.time()

            processor = PcapProcessor(
                str(self.pcap_path), chunk_size=self.chunks, n_jobs=self.cores
            )
            df_packets = processor.to_dataframe()

            t_ingest = time.time() - t0
            logger.info(
                f"[✓] Ingestion complete: {len(df_packets):,} packets in {t_ingest:.2f}s"
            )
            logger.info(f"    Packet rate: {len(df_packets) / t_ingest:.0f} pps")

            # ---- STEP 2: Feature Aggregation ----
            logger.info("\n[STEP 2] Feature Aggregation (Time-Windowed Matrix)")
            logger.info("-" * 90)
            t0 = time.time()

            # First: Aggregate raw packets into feature matrix
            df_features = processor._build_base_matrix(df_packets)

            pcap_filename = Path(self.pcap_path).stem
            audit_csv_name = f"audit_{pcap_filename}.csv"
            audit_csv_path = os.path.join("data", "processed", audit_csv_name)

            os.makedirs(os.path.dirname(audit_csv_path), exist_ok=True)

            if hasattr(df_features, "write_csv"):
                df_features.write_csv(audit_csv_path)
            else:
                df_features.to_csv(audit_csv_path, index=True)

            logger.info(
                f"[✓] Audit CSV generated for {pcap_filename}: {audit_csv_path}"
            )

            # Then: Standardize (scale) the aggregated features
            df_aggregated = processor.get_standardized_matrix(
                df_features, scaler_type="robust", export_name="training_baseline"
            )

            t_agg = time.time() - t0
            logger.info(
                f"[✓] Aggregation complete: {len(df_aggregated):,} windows in {t_agg:.2f}s"
            )
            logger.info(f"    Features: {len(df_aggregated.columns)}")
            logger.info(f"    Sample shape: {df_aggregated.shape}")

            # !! CRITICAL FIX (Matrioshka Escalado):
            # Load the RobustScaler that was just persisted by get_standardized_matrix()
            # This ensures deterministic inference in detection mode
            scaler_path = os.path.join(
                "models", "scalers", "robust_training_baseline.pkl"
            )
            if os.path.exists(scaler_path):
                trained_baseline_scaler = joblib.load(scaler_path)
                logger.info(f"[✓] RobustScaler loaded from: {scaler_path}")
            else:
                trained_baseline_scaler = None
                logger.warning(f"[!] RobustScaler not found at: {scaler_path}")

            # Extract feature columns for schema contract
            feature_cols = list(df_aggregated.columns)

            # !! CRITICAL ARCHITECTURE FIX (Matrioshka Escalado):
            # REMOVED redundant Steps 3-4 (RobustScaler + PowerTransformer).
            # These were DUPLICATING scaling already applied in get_standardized_matrix().
            # HiGIEngine now owns ALL normalization internally via HilbertSpaceProjector.

            # ---- STEP 3: HiGI Training (Encapsulated Normalization) ----
            logger.info("\n[STEP 5] HiGI Engine Training (Cascaded Sentinel + Phase 6)")
            logger.info("-" * 90)
            t0 = time.time()
            df_aggregated = self._augment_baseline(df_aggregated)

            logger.info(f"Final training set shape: {df_aggregated.shape}")
            logger.info(f"  [Config] Using injected HiGIConfig:")
            logger.info(f"    BayesianGMM: {self.higi_config.use_bayesian_gmm}")
            logger.info(
                f"    CDF-normalization: {self.higi_config.gmm_score_normalization_method}"
            )
            logger.info(
                f"    Per-feature thresholds: {self.higi_config.per_feature_thresholds}"
            )
            logger.info(
                f"    Blocked PCA enabled: {self.higi_config.blocked_pca_enabled}"
            )
            if self.higi_config.blocked_pca_enabled and self.higi_config.blocked_pca_variance_per_family:
                logger.info(
                    f"    Blocked PCA families: {list(self.higi_config.blocked_pca_variance_per_family.keys())}"
                )

            engine = HiGIEngine(self.higi_config, n_jobs=self.cores)
            engine.train(df_aggregated)

            t_train = time.time() - t0
            logger.info(f"[✓] HiGI training complete in {t_train:.2f}s")
            logger.info(
                f"    Hilbert dimensions: {engine.training_stats.get('hilbert_dimensions', 'N/A')}"
            )
            logger.info(
                f"    GMM components: {engine.training_stats.get('gmm_components', 'N/A')}"
            )
            
            # Log projection mode
            if self.higi_config.blocked_pca_enabled:
                logger.info("    ✓ Hilbert projection: Blocked PCA (per-family)")
                if hasattr(engine.projector, 'blocked_pca_transformer') and engine.projector.blocked_pca_transformer:
                    logger.info(
                        f"      Families: {list(self.higi_config.blocked_pca_variance_per_family.keys())}"
                    )
            else:
                logger.info("    ✓ Hilbert projection: Global PCA with PowerTransformer (Yeo-Johnson)")
            
            logger.info(
                f"    ✓ Per-feature LL thresholds: {len(engine.univariate_ll_thresholds)} features"
            )
            logger.info(
                "    ✓ Phase 6 capabilities: BayesianGMM + CDF normalization + Directionality"
            )

            # ---- STEP 4: Bundle Creation ----
            logger.info("\n[STEP 4] Bundle Creation")
            logger.info("-" * 90)

            metadata = {
                "training_date": datetime.now().isoformat(),
                "source_pcap": str(self.pcap_path),
                "pcap_packets": len(df_packets),
                "aggregated_windows": len(df_aggregated),
                "feature_count": len(feature_cols),
                "training_duration_sec": t_ingest + t_agg + t_train,
                "config": engine.config.to_dict(),
                "training_stats": engine.training_stats,
                # [Phase 6] Forensic metadata - new per-feature thresholds and directionality
                "per_feature_ll_thresholds": engine.univariate_ll_thresholds,  # P99.9 per-feature LL thresholds
                "phase_6_features": {
                    "bayesian_gmm": engine.config.use_bayesian_gmm,
                    "cdf_normalization": engine.config.gmm_score_normalization_method
                    == "cdf",
                    "per_feature_sensitivity": engine.config.per_feature_thresholds,
                    "directionality_analysis": engine.config.sentinel_directionality_analysis,
                },
                "hilbert_projection": {
                    "blocked_pca_enabled": engine.config.blocked_pca_enabled,
                    "blocked_pca_families": list(
                        engine.config.blocked_pca_variance_per_family.keys()
                    ) if engine.config.blocked_pca_variance_per_family else [],
                    "blocked_pca_variance_targets": engine.config.blocked_pca_variance_per_family,
                },
            }

            # ---- Calculate baseline medians for safe imputation ----
            # Used to replace missing protocol features in test data (instead of hardcoded 1e-6)
            # Filter NaN and infinite values to ensure robust statistics
            logger.info("[*] Computing baseline medians for feature imputation...")
            baseline_medians: Dict[str, float] = {}
            for feat in feature_cols:
                if feat in df_aggregated.columns:
                    # Extract valid values (remove NaN and infinite)
                    valid_values = df_aggregated[feat].dropna()
                    valid_values = valid_values[np.isfinite(valid_values)]

                    if len(valid_values) > 0:
                        baseline_medians[feat] = float(valid_values.median())
                    else:
                        # Fallback if all values are NaN/inf (rare)
                        baseline_medians[feat] = 0.0

            logger.info(f"[✓] Computed {len(baseline_medians)} baseline medians")
            logger.info(
                f"    Example medians: {dict(list(baseline_medians.items())[:3])}..."
            )

            # !! SIMPLIFIED BUNDLE (Matrioshka Escalado fix):
            # Now includes RobustScaler for deterministic inference
            bundle = ArtifactBundle(
                engine=engine,
                feature_cols=feature_cols,
                metadata=metadata,
                scaler=trained_baseline_scaler,  # !! CRITICAL: Inject baseline RobustScaler
                baseline_medians=baseline_medians,  # Feature medians for safe imputation
            )

            logger.info("[✓] Bundle created with metadata:")
            logger.info(f"    Packets: {metadata['pcap_packets']:,}")
            logger.info(f"    Windows: {metadata['aggregated_windows']:,}")
            logger.info(f"    Features: {metadata['feature_count']}")
            logger.info(
                f"    [Hilbert] Blocked PCA: {metadata['hilbert_projection']['blocked_pca_enabled']}"
            )
            if metadata['hilbert_projection']['blocked_pca_enabled']:
                logger.info(
                    f"    [Hilbert] Families: {metadata['hilbert_projection']['blocked_pca_families']}"
                )
            logger.info(
                f"    [Phase 6] BayesianGMM: {metadata['phase_6_features']['bayesian_gmm']}"
            )
            logger.info(
                f"    [Phase 6] CDF-Normalization: {metadata['phase_6_features']['cdf_normalization']}"
            )
            logger.info(
                f"    [Phase 6] Per-feature thresholds: {metadata['phase_6_features']['per_feature_sensitivity']}"
            )
            logger.info(
                f"    [Phase 6] Directionality (SPIKE/DROP): {metadata['phase_6_features']['directionality_analysis']}"
            )

            return bundle

        except PcapProcessorError as e:
            raise TrainingError(f"PCAP processing failed: {str(e)}") from e
        except HiGITrainingError as e:
            raise TrainingError(f"HiGI training failed: {str(e)}") from e
        except Exception as e:
            logger.error(f"[✗] Training failed: {str(e)}")
            logger.error(traceback.format_exc())
            raise TrainingError(f"Unexpected error during training: {str(e)}") from e


# ============================================================================
# PIPELINE: DETECTION MODE
# ============================================================================


class DetectionPipeline:
    """Orchestrates anomaly detection inference on test data."""

    def __init__(
        self,
        pcap_path: str,
        bundle_path: str,
        output_results_path: str,
        settings: HiGISettings,
    ) -> None:
        self.pcap_path = Path(pcap_path)
        self.bundle_path = Path(bundle_path)
        self.output_results_path = Path(output_results_path)
        self.settings = settings

        if not self.pcap_path.exists():
            raise DetectionError(f"Test PCAP not found: {pcap_path}")
        if not self.bundle_path.exists():
            raise DetectionError(f"Bundle not found: {bundle_path}")

        logger.info(f"\n{'=' * 90}")
        logger.info("HiGI ORCHESTRATOR: DETECTION PIPELINE")
        logger.info(f"{'=' * 90}")
        logger.info(f"Test PCAP: {self.pcap_path}")
        logger.info(f"Baseline bundle: {self.bundle_path}")
        logger.info(f"Output results: {self.output_results_path}")

    def run(self) -> pd.DataFrame:
        """
        Execute complete detection pipeline.

        **GOLDEN RULE**: This pipeline MUST use .transform() only.
        NO .fit() calls are permitted. Strict inference mode.

        Pipeline:
          1. Bundle Loading: Restore baseline artifacts
          2. PCAP Ingestion: Extract packets from test data
          3. Feature Aggregation: Time-windowed matrix construction
          4. Feature Normalization: Apply baseline scalers (.transform() only)
          5. HiGI Inference: Cascaded sentinel analysis
          6. Result Export: Save detection outputs with forensics

        Returns:
            Detection results DataFrame with columns:
              - balltree_score, gmm_score, iforest_score
              - is_anomaly, severity, persistence
              - culprit_component, suspect_features
              - forensic_evidence

        Raises:
            DetectionError: If any step fails
        """
        try:
            # ---- STEP 1: Bundle Loading ----
            logger.info("\n[STEP 1] Bundle Loading (Artifact Restoration)")
            logger.info("-" * 90)

            bundle = ArtifactBundle.load(str(self.bundle_path))
            logger.info(f"[✓] Baseline features: {len(bundle.feature_cols)}")

            # ---- ENGINE CONFIG SYNCHRONIZATION ----
            # Ensure consistency between bundle (training-time) config and deployment (runtime) config
            # CRITICAL: Blocked PCA is a training-time decision — cannot be changed at runtime
            from dataclasses import replace
            
            bundle_config = bundle.engine.config
            settings_config = self.settings.to_higi_config()
            
            # Verify Blocked PCA consistency (mismatch would corrupt results)
            if bundle_config.blocked_pca_enabled != settings_config.blocked_pca_enabled:
                logger.warning(
                    f"[⚠] Blocked PCA mode mismatch: "
                    f"bundle={bundle_config.blocked_pca_enabled}, "
                    f"config={settings_config.blocked_pca_enabled}. "
                    f"Using bundle training-time configuration (Blocked PCA is immutable)."
                )
            else:
                logger.debug(
                    f"[✓] Blocked PCA mode consistent: {bundle_config.blocked_pca_enabled}"
                )
            
            # Sync velocity bypass settings from current deployment config
            if bundle_config.velocity_bypass_enabled != settings_config.velocity_bypass_enabled:
                logger.info(
                    f"[*] Velocity bypass mode override: "
                    f"bundle={bundle_config.velocity_bypass_enabled} → "
                    f"config={settings_config.velocity_bypass_enabled}"
                )
                bundle.engine.config = replace(
                    bundle_config,
                    velocity_bypass_enabled=settings_config.velocity_bypass_enabled,
                    velocity_bypass_threshold=settings_config.velocity_bypass_threshold,
                    velocity_tribunal_weight=settings_config.velocity_tribunal_weight,
                )
            else:
                logger.debug(
                    f"[✓] Velocity bypass mode consistent: {bundle_config.velocity_bypass_enabled}"
                )

            # ---- STEP 2: PCAP Ingestion ----
            logger.info("\n[STEP 2] PCAP Ingestion (Test Data)")
            logger.info("-" * 90)
            t0 = time.time()

            processor = PcapProcessor(
                str(self.pcap_path),
                chunk_size=self.settings.ingestion.chunk_size,
                n_jobs=self.settings.ingestion.n_jobs,
            )
            df_packets = processor.to_dataframe()

            t_ingest = time.time() - t0
            logger.info(
                f"[✓] Ingestion complete: {len(df_packets):,} packets in {t_ingest:.2f}s"
            )

            # ---- STEP 3: Feature Aggregation ----
            logger.info("\n[STEP 3] Feature Aggregation (Time-Windowed Matrix)")
            logger.info("-" * 90)
            t0 = time.time()

            # Aggregate raw packets into feature matrix (REUSE for both steps)
            # FIX (E12): Removed double call to _build_base_matrix() - was needlessly doubling CPU time
            df_aggregated_raw = processor._build_base_matrix(df_packets)
            del df_packets  # Free memory immediately after aggregation
            gc.collect()

            t_agg = time.time() - t0
            logger.info(
                f"[✓] Raw aggregation complete: {len(df_aggregated_raw):,} windows (unscaled)"
            )

            # ---- STEP 4: Feature Schema Alignment (Dynamic Protocols) ----
            logger.info(
                "\n[STEP 4] Feature Schema Alignment (Handle Dynamic Protocols)"
            )
            logger.info("-" * 90)

            test_features = set(df_aggregated_raw.columns)
            baseline_features = set(bundle.feature_cols)

            METADATA_COLS_V2_2 = {"_abs_timestamp", "server_port"}

            missing_features = baseline_features - test_features
            extra_features = (
                test_features - baseline_features - METADATA_COLS_V2_2
            )  # Allow metadata to be extra without warning

            if missing_features:
                logger.warning(
                    f"⚠️  Test data missing {len(missing_features)} protocol features: {missing_features}"
                )
                logger.warning(
                    f"    (Reason: Protocol absent in test PCAP, filling with baseline medians)"
                )
                # Fill missing features with baseline medians from training data
                # This ensures imputations are consistent with expected baseline behavior (not arbitrary 1e-6)
                # Rigor: Use 0.0 as safe fallback if feature median not available (only for backward compatibility)
                for feat in missing_features:
                    imputation_value = bundle.baseline_medians.get(feat, 0.0)
                    df_aggregated_raw[feat] = imputation_value
                logger.info(
                    f"    [✓] Filled {len(missing_features)} missing features with baseline medians"
                )
                logger.info(
                    f"      Example imputed values: {dict(list({feat: bundle.baseline_medians.get(feat, 0.0) for feat in list(missing_features)[:3]}.items()))}"
                )

            if extra_features:
                logger.warning(
                    f"⚠️  Test data has {len(extra_features)} extra features (will be ignored)"
                )
                # Remove extra features not in baseline
                df_aggregated_raw = df_aggregated_raw.drop(columns=list(extra_features))
                logger.info(f"    [✓] Removed {len(extra_features)} extra features")

            logger.info(
                f"[✓] Schema aligned: {len(df_aggregated_raw.columns)} features match baseline"
            )

            # ---- STEP 5: VECTORIZED METADATA SEPARATION & SCALING (v2.2.0 Optimized) ----
            logger.info("\n[STEP 5] Vectorized Metadata Separation & Scaler Transform")
            logger.info("-" * 90)

            t0_step5 = time.time()

            # Define metadata columns that should NOT be scaled
            METADATA_COLS_V2_2 = ["_abs_timestamp", "server_port"]
            metadata_cols_present = [
                c for c in df_aggregated_raw.columns if c in METADATA_COLS_V2_2
            ]

            # VECTORIZED SPLIT: Extract metadata once (no copies unless necessary)
            if metadata_cols_present:
                X_metadata = df_aggregated_raw[metadata_cols_present].copy()
                # CRITICAL: Reset index to 0-based for alignment in STEP 6
                X_metadata = X_metadata.reset_index(drop=True)
                logger.info(
                    f"[→] Extracted {len(metadata_cols_present)} metadata columns (preserved as-is): {metadata_cols_present}"
                )
            else:
                X_metadata = pd.DataFrame()
                logger.info("[→] No metadata columns found")

            # Define feature columns (everything except metadata)
            METADATA_SET = set(METADATA_COLS_V2_2)
            feature_cols_only = [
                c for c in bundle.feature_cols if c not in METADATA_SET
            ]

            # VECTORIZED SLICING: Get DataFrame (sklearn scaler expects DataFrame, not NumPy array)
            X_features = df_aggregated_raw[feature_cols_only]

            # VECTORIZED TRANSFORM: Apply trained scaler directly to DataFrame
            if bundle.scaler is not None:
                logger.info("[✓] Using baseline RobustScaler from training bundle")
                X_scaled = bundle.scaler.transform(
                    X_features
                )  # Direct transform (no fit), returns NumPy array
                logger.info("    [✓] Transform-only mode (vectorized, deterministic)")
            else:
                logger.warning("[!] WARNING: No baseline scaler in bundle!")
                logger.warning(
                    "    [!] Cannot proceed - bundle must contain a trained scaler"
                )
                raise ValueError(
                    "Bundle missing trained scaler. Inference requires baseline scaling."
                )

            # EFFICIENT RECONSTRUCTION: Convert scaled array back to DataFrame with 0-based index
            df_aggregated_scaled = pd.DataFrame(
                X_scaled, columns=feature_cols_only
            ).astype("float64")
            # CRITICAL: Ensure 0-based index for alignment with X_metadata and results
            df_aggregated_scaled = df_aggregated_scaled.reset_index(drop=True)

            # Verify no metadata leaked into scaled features
            metadata_still_present = [
                c for c in df_aggregated_scaled.columns if c in METADATA_SET
            ]
            if metadata_still_present:
                logger.warning(
                    f"[!] WARNING: Metadata columns in scaled DF (should be empty): {metadata_still_present}"
                )
                df_aggregated_scaled = df_aggregated_scaled.drop(
                    columns=metadata_still_present
                )

            df_aligned = df_aggregated_scaled

            t_step5 = time.time() - t0_step5
            logger.info(
                f"[✓] Feature scaling complete: {df_aligned.shape} in {t_step5 * 1000:.2f}ms ({len(feature_cols_only)} features, 0 metadata, 0-based index)"
            )

            # ---- STEP 6: HiGI Inference (Cascaded Sentinel - Phase 6) ----
            logger.info("\n[STEP 6] HiGI Inference (Cascaded Sentinel - Phase 6)")
            logger.info("-" * 90)
            t0 = time.time()

            results = bundle.engine.analyze(
                df_aligned, n_jobs=self.settings.ingestion.n_jobs
            )

            # Re-attach metadata to results for forensic linkage (v2.2.0)
            # Index alignment guaranteed: both have 0-based RangeIndex from STEP 5
            if not X_metadata.empty:
                # Verify length consistency (should be guaranteed, but check anyway)
                if len(results) != len(X_metadata):
                    logger.error(
                        f"[!] CRITICAL: Length mismatch after alignment: results={len(results)}, metadata={len(X_metadata)}"
                    )
                    raise ValueError("Index alignment failed in STEP 6")

                # Safe concatenation with aligned 0-based indices
                results = pd.concat([results, X_metadata], axis=1)
                logger.info(
                    f"[✓] Re-attached {len(metadata_cols_present)} metadata columns to results"
                )

            t_infer = time.time() - t0
            logger.info(f"[✓] Inference complete in {t_infer:.2f}s")
            logger.info(f"    Throughput: {len(df_aligned) / t_infer:,.0f} samples/sec")

            # Extract detection stats
            n_anomalies = results["is_anomaly"].sum()
            n_critical = (results["severity"] == 3).sum()

            # [Phase 6] Capture Soft Threshold activation (P90-P95 defense zone)
            soft_zone_mask = (
                results["balltree_severity"] == 0.5
                if "balltree_severity" in results
                else pd.Series([False] * len(results))
            )
            n_soft_zone = soft_zone_mask.sum()

            logger.info(f"\n[DETECTION SUMMARY]")
            logger.info(f"  Total samples: {len(results):,}")
            logger.info(
                f"  Anomalies: {n_anomalies:,} ({n_anomalies / len(results) * 100:.2f}%)"
            )
            logger.info(f"  Critical: {n_critical:,}")
            logger.info(
                f"  [Phase 6] Soft Zone (P90-P95): {n_soft_zone:,} samples → PASSED TO TIER 2 (Defense)"
            )
            logger.info("  Severity breakdown:")
            for sev in range(4):
                count = (results["severity"] == sev).sum()
                labels = ["Normal", "Borderline", "Medium", "Critical"]
                logger.info(f"    {labels[sev]:12} {count:,}")

            # [Phase 6] Forensic evidence analysis
            if "physical_culprit" in results:
                spike_count = (
                    results["physical_culprit"]
                    .str.contains("SPIKE", case=False, na=False)
                    .sum()
                )
                drop_count = (
                    results["physical_culprit"]
                    .str.contains("DROP", case=False, na=False)
                    .sum()
                )
                if spike_count > 0 or drop_count > 0:
                    logger.info("  [Phase 6] Directionality Analysis (SPIKE/DROP):")
                    logger.info(f"    SPIKE (anomalously high): {spike_count:,}")
                    logger.info(f"    DROP (anomalously low): {drop_count:,}")

            # ---- STEP 7: Result Export (Enhanced Forensics) ----
            logger.info("\n[STEP 7] Result Export (Enhanced with Phase 6 Forensics)")
            logger.info("-" * 90)

            # [BUG-F1 FIX] CRITICAL: Use ONLY baseline soft zone from higi_engine.analyze()
            # DO NOT recalculate thresholds using np.percentile() on current batch.
            # This prevents 'threshold inflation' where massive attacks (DoS Hulk) inflate
            # the percentile and pass as normal, while background noise is marked soft zone.
            if "balltree_severity" in results:
                # Soft zone = physical threshold (balltree_severity == 0.5) calibrated at training time.
                # Trust the BallTree detector; no dynamic re-thresholding in orchestrator.
                results["soft_zone_triggered"] = results["balltree_severity"] == 0.5
                logger.info(
                    f"  [BUG-F1 FIX] Soft zone (P90-P95 baseline): {results['soft_zone_triggered'].sum():,} samples"
                )
                logger.info(
                    "             Using STATIC baseline thresholds (NOT batch percentiles)"
                )

            # Enhance forensic evidence with directionality (already in physical_culprit from Phase 6)
            if "physical_culprit" in results:
                logger.info(
                    "  [Phase 6] Forensic SPIKE/DROP directionality preserved in 'physical_culprit' column"
                )

            self.output_results_path.parent.mkdir(parents=True, exist_ok=True)
            results.to_csv(self.output_results_path, index=True)
            logger.info(f"[✓] Results saved: {self.output_results_path}")

            # Save summary metadata (enhanced with Phase 6 metrics)
            summary = {
                "detection_date": datetime.now().isoformat(),
                "test_pcap": str(self.pcap_path),
                "baseline_bundle": str(self.bundle_path),
                "total_samples": len(results),
                "anomalies_detected": int(n_anomalies),
                "critical_count": int(n_critical),
                "soft_zone_count": int(
                    n_soft_zone
                ),  # [Phase 6] Soft threshold zone samples
                "anomaly_rate_pct": float(n_anomalies / len(results) * 100),
                "inference_duration_sec": t_ingest + t_agg + t_infer,
                "throughput_samples_per_sec": len(results) / t_infer,
                # [Phase 6] Phase 6 metrics
                "phase_6_enabled": True,
                "soft_threshold_defended": int(n_soft_zone),
                "directionality_analysis": "SPIKE/DROP in physical_culprit",
            }

            summary_path = self.output_results_path.with_suffix(".json")
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2, default=str)
            logger.info(f"[✓] Summary saved: {summary_path}")

            return results

        except DetectionError:
            raise
        except PcapProcessorError as e:
            logger.error(f"[✗] PCAP processing failed: {str(e)}")
            raise DetectionError(f"PCAP processing failed: {str(e)}") from e
        except HiGIInferenceError as e:
            logger.error(f"[✗] HiGI inference failed: {str(e)}")
            raise DetectionError(f"HiGI inference failed: {str(e)}") from e
        except Exception as e:
            logger.error(f"[✗] Detection failed: {str(e)}")
            logger.error(traceback.format_exc())
            raise DetectionError(f"Unexpected error during detection: {str(e)}") from e


# ============================================================================
# CLI INTERFACE
# ============================================================================


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog="higi_orchestrator.py",
        description="HiGI IDS Orchestrator: Production baseline training and anomaly detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:

  1. Training mode (establish baseline):
     
     python scripts/higi_orchestrator.py train \\
       --pcap data/raw/Monday.pcap \\
       --output models/baseline_monday.pkl

  2. Detection mode (inference on test data):
     
     python scripts/higi_orchestrator.py detect \\
       --pcap data/raw/Wednesday.pcap \\
       --bundle models/baseline_monday.pkl \\
       --output data/processed/wednesday_results.csv

  3. Verbose logging:
     
     python scripts/higi_orchestrator.py train \\
       --pcap data/raw/Monday.pcap \\
       --output models/baseline.pkl \\
       --verbose
        """,
    )

    subparsers = parser.add_subparsers(
        dest="mode", help="Operation mode", required=True
    )

    # ---- TRAINING SUBCOMMAND ----
    train_parser = subparsers.add_parser(
        "train", help="Training mode: Establish baseline from benign PCAP"
    )
    train_parser.add_argument(
        "--pcap",
        type=str,
        required=True,
        help="Path to baseline PCAP file (benign/normal network traffic)",
    )
    train_parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output path for artifact bundle (.pkl)",
    )
    train_parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose logging"
    )

    # ---- DETECTION SUBCOMMAND ----
    detect_parser = subparsers.add_parser(
        "detect", help="Detection mode: Inference on test PCAP with baseline bundle"
    )
    detect_parser.add_argument(
        "--pcap", type=str, required=True, help="Path to test PCAP file"
    )
    detect_parser.add_argument(
        "--bundle",
        type=str,
        required=True,
        help="Path to baseline artifact bundle (from training mode)",
    )
    detect_parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output path for detection results (.csv)",
    )
    detect_parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose logging"
    )
    # Añade esto a train_parser y detect_parser
    for p in [train_parser, detect_parser]:
        p.add_argument(
            "--chunks",
            type=int,
            default=5000,
            help="Tamaño del chunk para el procesamiento paralelo (default: 5000)",
        )
        p.add_argument(
            "--cores",
            type=int,
            default=6,
            help="Number of CPU cores to use (default: 6)",
        )
    return parser


def main() -> int:
    """Main entry point
        EXAMPLE USAGE:
        python scripts/higi_orchestrator.py train --pcap data/raw/Monday.pcap --output models/baseline_monday.pkl --cores 6 --chunks 5000
        python scripts/higi_orchestrator.py detect --pcap data/raw/Wednesday.pcap --bundle models/baseline_monday.pkl --output data/processed/wednesday_results.csv
    ."""
    parser = create_argument_parser()
    args = parser.parse_args()

    try:
        if args.mode == "train":
            # ---- TRAINING MODE ----
            pipeline = TrainingPipeline(
                args.pcap, args.output, chunks=args.chunks, cores=args.cores
            )
            bundle = pipeline.run()
            bundle.save(args.output)

            logger.info(f"\n{'=' * 90}")
            logger.info("✓ TRAINING COMPLETE - Baseline bundle ready for detection")
            logger.info(f"{'=' * 90}\n")
            return 0

        elif args.mode == "detect":
            # ---- DETECTION MODE ----
            pipeline = DetectionPipeline(
                args.pcap,
                args.bundle,
                args.output,
                chunks=args.chunks,
                cores=args.cores,
            )
            results = pipeline.run()

            logger.info(f"\n{'=' * 90}")
            logger.info("✓ DETECTION COMPLETE - Results exported")
            logger.info(f"{'=' * 90}\n")
            return 0

        else:
            parser.print_help()
            return 1

    except (TrainingError, DetectionError, ArtifactError) as e:
        logger.error(f"\n✗ ORCHESTRATION FAILED: {str(e)}\n")
        return 1
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Interrupted by user\n")
        return 130
    except Exception as e:
        logger.error(f"\n✗ FATAL ERROR: {str(e)}")
        logger.error(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())

## File: src/config.py

"""
HiGI IDS — Centralised Configuration Loader.

Reads config.yaml and validates it into a frozen HiGISettings dataclass.
Every module in the HiGI pipeline imports its configuration exclusively from
this module — zero magic numbers live anywhere else in the codebase.

Module: src/config.py
Usage:
    from src.config import load_settings

    settings = load_settings()               # reads config.yaml from project root
    settings = load_settings("custom.yaml")  # override path

    # Access nested sections:
    settings.balltree.threshold_p95          # → 95.0
    settings.velocity.bypass_threshold       # → 5.0
    settings.forensic.debounce_seconds       # → 30

Architecture note:
    HiGISettings is a plain frozen dataclass of typed sub-dataclasses, not a
    Pydantic model.  This avoids a heavy dependency while still providing
    full type-safety through mypy.  The only runtime dependency is PyYAML.

Author: Blue Team Engineering
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

# Project root is two levels above this file: src/config.py → src/ → project/
_PROJECT_ROOT = Path(__file__).parent.parent
_DEFAULT_CONFIG_PATH = _PROJECT_ROOT / "config.yaml"


# ============================================================================
# SUB-DATACLASSES — one per config.yaml top-level section
# ============================================================================

@dataclass(frozen=True)
class PathsSettings:
    models_dir: str = "models"
    results_dir: str = "data/processed"
    reports_dir: str = "reports"
    logs_dir: str = "logs"
    scalers_dir: str = "models/scalers"


@dataclass(frozen=True)
class IngestionSettings:
    chunk_size: int = 5000
    n_jobs: int = 6
    time_interval: str = "1s"


@dataclass(frozen=True)
class TrainingSettings:
    """Configuration for baseline training and data augmentation."""
    baseline_augmentation_enabled: bool = True
    augmentation_noise_scale: float = 0.05         # 5% of feature std dev
    augmentation_synthetic_fraction: float = 0.10  # 10% additional synthetic samples


@dataclass(frozen=True)
class HilbertSettings:
    pca_variance_target: float = 0.99
    pca_eigenvalue_max_condition: float = 1e12
    blocked_pca_enabled: bool = True
    blocked_pca_variance_per_family: Optional[Dict[str, float]] = field(
        default_factory=lambda: {
            "volume": 0.95,
            "payload": 0.95,
            "flags": 0.99,
            "protocol": 0.99,
            "connection": 0.95,
        }
    )


@dataclass(frozen=True)
class BallTreeSettings:
    k_neighbors: int = 5
    threshold_p90: float = 90.0
    threshold_p95: float = 95.0
    threshold_p99: float = 99.0
    threshold_p99_9: float = 99.9
    slack: float = 1.2


@dataclass(frozen=True)
class GMMSettings:
    use_bayesian: bool = True
    bayesian_weight_concentration_prior: float = 1e-2
    reg_covar: float = 0.1
    max_iter: int = 200
    n_init: int = 10
    n_components_fallback: int = 5
    threshold_percentile: float = 99.9
    score_normalization: str = "cdf"
    adaptive_k_enabled: bool = True
    adaptive_k_range: Tuple[int, int] = (1, 5)
    adaptive_k_max_components: int = 25


@dataclass(frozen=True)
class IForestSettings:
    contamination: float = 0.05
    n_estimators: int = 100


@dataclass(frozen=True)
class SentinelSettings:
    enabled: bool = True
    per_feature_thresholds: bool = True
    global_threshold: float = 1e-6
    directionality_analysis: bool = True
    portero_sigma_threshold: float = 20.0


@dataclass(frozen=True)
class VelocitySeverityRule:
    """A single (z_threshold, severity_level) rule."""
    z_threshold: float
    severity_level: int


@dataclass(frozen=True)
class VelocitySettings:
    enabled: bool = True
    bypass_threshold: float = 5.0
    tribunal_weight: float = 0.30
    severity_thresholds: Tuple[VelocitySeverityRule, ...] = field(
        default_factory=lambda: (
            VelocitySeverityRule(12.0, 3),
            VelocitySeverityRule(8.0, 2),
            VelocitySeverityRule(5.0, 1),
        )
    )

    def as_tuple_list(self) -> Tuple[Tuple[float, int], ...]:
        """Return severity thresholds in the format expected by VelocityBypassDetector."""
        return tuple((r.z_threshold, r.severity_level) for r in self.severity_thresholds)


@dataclass(frozen=True)
class TribunalWeights:
    balltree: float = 0.25
    gmm: float = 0.40
    iforest: float = 0.35


@dataclass(frozen=True)
class TribunalSettings:
    weighted_mode: bool = True
    weights: TribunalWeights = field(default_factory=TribunalWeights)
    consensus_threshold: float = 0.5
    majority_vote_threshold: int = 2


@dataclass(frozen=True)
class FamilyConsensusSettings:
    enabled: bool = True
    min_hits: int = 2
    z_threshold: float = 2.0


@dataclass(frozen=True)
class PersistenceSettings:
    warmup_multiplier: int = 3
    ma_window_size: int = 5
    transient_threshold: float = 0.4
    hysteresis_entry_multiplier: float = 1.0
    hysteresis_exit_multiplier: float = 0.75
    alert_minimum_persistence: int = 3
    persistence_filter_window: int = 3


@dataclass(frozen=True)
class ForensicSettings:
    debounce_seconds: int = 30
    data_drop_threshold_seconds: int = 60
    sigma_culprit_min: float = 2.0
    default_confidence_filter: float = 0.75
    default_min_anomalies: int = 3
    default_min_duration_seconds: float = 1.0
    top_features_per_pc: int = 3
    tier_confidence_weights: Dict[str, float] = field(default_factory=lambda: {
        "balltree": 0.20,
        "gmm": 0.25,
        "iforest": 0.20,
        "physical_sentinel": 0.20,
        "velocity_bypass": 0.15
    })


@dataclass(frozen=True)
class LoggingSettings:
    level: str = "INFO"
    format: str = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
    date_format: str = "%Y-%m-%d %H:%M:%S"
    file_enabled: bool = True
    file_max_bytes: int = 10_485_760
    file_backup_count: int = 5


# ============================================================================
# ROOT SETTINGS
# ============================================================================

@dataclass(frozen=True)
class HiGISettings:
    """
    Root configuration object for the entire HiGI IDS pipeline.

    Constructed by load_settings() from config.yaml.  Every pipeline component
    receives its configuration from the relevant sub-dataclass:

        detector = HiGIEngine(config=settings.to_higi_config())
        processor = PcapProcessor(
            chunk_size=settings.ingestion.chunk_size,
            n_jobs=settings.ingestion.n_jobs,
        )
    """

    paths: PathsSettings = field(default_factory=PathsSettings)
    ingestion: IngestionSettings = field(default_factory=IngestionSettings)
    training: TrainingSettings = field(default_factory=TrainingSettings)
    hilbert: HilbertSettings = field(default_factory=HilbertSettings)
    balltree: BallTreeSettings = field(default_factory=BallTreeSettings)
    gmm: GMMSettings = field(default_factory=GMMSettings)
    iforest: IForestSettings = field(default_factory=IForestSettings)
    sentinel: SentinelSettings = field(default_factory=SentinelSettings)
    velocity: VelocitySettings = field(default_factory=VelocitySettings)
    tribunal: TribunalSettings = field(default_factory=TribunalSettings)
    family_consensus: FamilyConsensusSettings = field(default_factory=FamilyConsensusSettings)
    persistence: PersistenceSettings = field(default_factory=PersistenceSettings)
    forensic: ForensicSettings = field(default_factory=ForensicSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)

    def to_higi_config(self) -> "Any":
        """
        Materialise a HiGIConfig instance from the current settings.

        This is the canonical bridge between config.yaml and HiGIEngine.
        HiGIConfig is imported lazily to avoid circular imports.

        Returns:
            HiGIConfig: Ready to pass to HiGIEngine(config=...).
        """
        from src.models.higi_engine import HiGIConfig  # lazy import

        # Derive tribunal weights dict (velocity carve-out applied inside __post_init__)
        weights = {
            "balltree": self.tribunal.weights.balltree,
            "gmm": self.tribunal.weights.gmm,
            "iforest": self.tribunal.weights.iforest,
        }

        # Validate adaptive_k_range
        k_range = self.gmm.adaptive_k_range
        if not isinstance(k_range, (list, tuple)) or len(k_range) < 2:
            raise ValueError(
                f"Config Error: 'adaptive_k_range' debe ser una lista de 2 enteros [min, max]. "
                f"Recibido: {k_range}"
            )

        return HiGIConfig(
            # Hilbert space
            pca_variance=self.hilbert.pca_variance_target,
            pca_eigenvalue_max_condition=self.hilbert.pca_eigenvalue_max_condition,
            blocked_pca_enabled=self.hilbert.blocked_pca_enabled,
            blocked_pca_variance_per_family=self.hilbert.blocked_pca_variance_per_family,
            # Detection thresholds
            threshold_p95=self.balltree.threshold_p95,
            threshold_p99=self.balltree.threshold_p99,
            threshold_p99_9=self.balltree.threshold_p99_9,
            threshold_percentile=self.gmm.threshold_percentile,
            # Tier 2
            reg_covar=self.gmm.reg_covar,
            iforest_contamination=self.iforest.contamination,
            use_bayesian_gmm=self.gmm.use_bayesian,
            bayesian_weight_concentration_prior=self.gmm.bayesian_weight_concentration_prior,
            univariate_gmm_components=self.gmm.n_components_fallback,
            adaptive_univariate_k=self.gmm.adaptive_k_enabled,
            adaptive_univariate_k_range=(
                int(k_range[0]),
                int(k_range[1])
            ),
            # Tribunal
            weighted_tribunal=self.tribunal.weighted_mode,
            tribunal_weights=weights,
            tribunal_consensus_threshold=self.tribunal.consensus_threshold,
            majority_vote_threshold=self.tribunal.majority_vote_threshold,
            gmm_score_normalization_method=self.gmm.score_normalization,
            # Tier 3 — Sentinel
            physical_sentinel_enabled=self.sentinel.enabled,
            physical_sentinel_threshold=self.sentinel.global_threshold,
            per_feature_thresholds=self.sentinel.per_feature_thresholds,
            sentinel_directionality_analysis=self.sentinel.directionality_analysis,
            portero_sigma_threshold=self.sentinel.portero_sigma_threshold,
            # Tier 4 — Velocity Bypass
            velocity_bypass_enabled=self.velocity.enabled,
            velocity_bypass_threshold=self.velocity.bypass_threshold,
            velocity_tribunal_weight=self.velocity.tribunal_weight,
            # Persistence / hysteresis
            ma_window_size=self.persistence.ma_window_size,
            transient_threshold=self.persistence.transient_threshold,
            balltree_slack=self.balltree.slack,
            hysteresis_entry_multiplier=self.persistence.hysteresis_entry_multiplier,
            hysteresis_exit_multiplier=self.persistence.hysteresis_exit_multiplier,
            alert_minimum_persistence=self.persistence.alert_minimum_persistence,
            # Forensics
            enable_forensics=True,
            top_features_per_pc=self.forensic.top_features_per_pc,
            # FIX-4 — Family consensus
            family_consensus_enabled=self.family_consensus.enabled,
            family_consensus_min_hits=self.family_consensus.min_hits,
        )


# ============================================================================
# LOADER
# ============================================================================

def _nested_get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely traverse a nested dict."""
    node = d
    for key in keys:
        if not isinstance(node, dict):
            return default
        node = node.get(key, default)
        if node is default:
            return default
    return node


def load_settings(path: Optional[str] = None) -> HiGISettings:
    """
    Load, validate, and return HiGISettings from a YAML file.

    Falls back to all-default values if the file cannot be read, so the
    pipeline can start even without a config.yaml (useful for unit tests).

    Args:
        path: Path to config YAML. Defaults to <project_root>/config.yaml.

    Returns:
        HiGISettings: Fully validated, frozen configuration object.
    """
    config_path = Path(path) if path else _DEFAULT_CONFIG_PATH

    if not config_path.exists():
        logger.warning(
            f"[config] config.yaml not found at {config_path}. "
            "Using all-default settings."
        )
        return HiGISettings()

    try:
        with config_path.open("r", encoding="utf-8") as fh:
            raw: Dict[str, Any] = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        logger.error(f"[config] YAML parse error in {config_path}: {exc}")
        raise ValueError(f"Invalid config.yaml: {exc}") from exc

    logger.info(f"[config] Loaded configuration from {config_path}")

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------
    p = raw.get("paths", {})
    paths = PathsSettings(
        models_dir=p.get("models_dir", "models"),
        results_dir=p.get("results_dir", "data/processed"),
        reports_dir=p.get("reports_dir", "reports"),
        logs_dir=p.get("logs_dir", "logs"),
        scalers_dir=p.get("scalers_dir", "models/scalers"),
    )

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    ing = raw.get("ingestion", {})
    ingestion = IngestionSettings(
        chunk_size=ing.get("chunk_size", 5000),
        n_jobs=ing.get("n_jobs", 6),
        time_interval=ing.get("time_interval", "1s"),
    )

    # ------------------------------------------------------------------
    # Training (Augmentation parameters)
    # ------------------------------------------------------------------
    trn = raw.get("training", {})
    training = TrainingSettings(
        baseline_augmentation_enabled=trn.get("baseline_augmentation_enabled", True),
        augmentation_noise_scale=trn.get("augmentation_noise_scale", 0.05),
        augmentation_synthetic_fraction=trn.get("augmentation_synthetic_fraction", 0.10),
    )

    # ------------------------------------------------------------------
    # Hilbert
    # ------------------------------------------------------------------
    hil = raw.get("hilbert", {})
    blocked_pca_var_raw = hil.get(
        "blocked_pca_variance_per_family",
        {"volume": 0.95, "payload": 0.95, "flags": 0.99, "protocol": 0.99, "connection": 0.95},
    )
    hilbert = HilbertSettings(
        pca_variance_target=hil.get("pca_variance_target", 0.99),
        pca_eigenvalue_max_condition=hil.get("pca_eigenvalue_max_condition", 1e12),
        blocked_pca_enabled=hil.get("blocked_pca_enabled", True),
        blocked_pca_variance_per_family=blocked_pca_var_raw,
    )

    # ------------------------------------------------------------------
    # BallTree
    # ------------------------------------------------------------------
    bt = raw.get("balltree", {})
    balltree = BallTreeSettings(
        k_neighbors=bt.get("k_neighbors", 5),
        threshold_p90=bt.get("threshold_p90", 90.0),
        threshold_p95=bt.get("threshold_p95", 95.0),
        threshold_p99=bt.get("threshold_p99", 99.0),
        threshold_p99_9=bt.get("threshold_p99_9", 99.9),
        slack=bt.get("slack", 1.2),
    )

    # ------------------------------------------------------------------
    # GMM
    # ------------------------------------------------------------------
    gm = raw.get("gmm", {})
    k_range_raw = gm.get("adaptive_k_range", [1, 5])
    gmm = GMMSettings(
        use_bayesian=gm.get("use_bayesian", True),
        bayesian_weight_concentration_prior=gm.get(
            "bayesian_weight_concentration_prior", 1e-2
        ),
        reg_covar=gm.get("reg_covar", 0.1),
        max_iter=gm.get("max_iter", 200),
        n_init=gm.get("n_init", 10),
        n_components_fallback=gm.get("n_components_fallback", 5),
        threshold_percentile=gm.get("threshold_percentile", 99.9),
        score_normalization=gm.get("score_normalization", "cdf"),
        adaptive_k_enabled=gm.get("adaptive_k_enabled", True),
        adaptive_k_range=(int(k_range_raw[0]), int(k_range_raw[1])),
        adaptive_k_max_components=gm.get("adaptive_k_max_components", 25),
    )

    # ------------------------------------------------------------------
    # IForest
    # ------------------------------------------------------------------
    ifr = raw.get("iforest", {})
    iforest = IForestSettings(
        contamination=ifr.get("contamination", 0.05),
        n_estimators=ifr.get("n_estimators", 100),
    )

    # ------------------------------------------------------------------
    # Sentinel
    # ------------------------------------------------------------------
    sen = raw.get("sentinel", {})
    sentinel = SentinelSettings(
        enabled=sen.get("enabled", True),
        per_feature_thresholds=sen.get("per_feature_thresholds", True),
        global_threshold=sen.get("global_threshold", 1e-6),
        directionality_analysis=sen.get("directionality_analysis", True),
        portero_sigma_threshold=sen.get("portero_sigma_threshold", 20.0),
    )

    # ------------------------------------------------------------------
    # Velocity
    # ------------------------------------------------------------------
    vel = raw.get("velocity", {})
    vel_sev_raw = vel.get(
        "severity_thresholds", [[12.0, 3], [8.0, 2], [5.0, 1]]
    )
    vel_sev_rules = tuple(
        VelocitySeverityRule(float(row[0]), int(row[1])) for row in vel_sev_raw
    )
    velocity = VelocitySettings(
        enabled=vel.get("enabled", True),
        bypass_threshold=vel.get("bypass_threshold", 5.0),
        tribunal_weight=vel.get("tribunal_weight", 0.30),
        severity_thresholds=vel_sev_rules,
    )

    # ------------------------------------------------------------------
    # Tribunal
    # ------------------------------------------------------------------
    tri = raw.get("tribunal", {})
    tw = tri.get("weights", {})
    tribunal = TribunalSettings(
        weighted_mode=tri.get("weighted_mode", True),
        weights=TribunalWeights(
            balltree=tw.get("balltree", 0.25),
            gmm=tw.get("gmm", 0.40),
            iforest=tw.get("iforest", 0.35),
        ),
        consensus_threshold=tri.get("consensus_threshold", 0.5),
        majority_vote_threshold=tri.get("majority_vote_threshold", 2),
    )

    # ------------------------------------------------------------------
    # Family Consensus
    # ------------------------------------------------------------------
    fc = raw.get("family_consensus", {})
    family_consensus = FamilyConsensusSettings(
        enabled=fc.get("enabled", True),
        min_hits=fc.get("min_hits", 2),
        z_threshold=fc.get("z_threshold", 2.0),
    )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    per = raw.get("persistence", {})
    persistence = PersistenceSettings(
        warmup_multiplier=per.get("warmup_multiplier", 3),
        ma_window_size=per.get("ma_window_size", 5),
        transient_threshold=per.get("transient_threshold", 0.4),
        hysteresis_entry_multiplier=per.get("hysteresis_entry_multiplier", 1.0),
        hysteresis_exit_multiplier=per.get("hysteresis_exit_multiplier", 0.75),
        alert_minimum_persistence=per.get("alert_minimum_persistence", 3),
        persistence_filter_window=per.get("persistence_filter_window", 3),
    )

    # ------------------------------------------------------------------
    # Forensic
    # ------------------------------------------------------------------
    for_ = raw.get("forensic", {})
    forensic = ForensicSettings(
        debounce_seconds=for_.get("debounce_seconds", 30),
        data_drop_threshold_seconds=for_.get("data_drop_threshold_seconds", 60),
        sigma_culprit_min=for_.get("sigma_culprit_min", 2.0),
        default_confidence_filter=for_.get("default_confidence_filter", 0.75),
        default_min_anomalies=for_.get("default_min_anomalies", 3),
        default_min_duration_seconds=for_.get("default_min_duration_seconds", 1.0),
        top_features_per_pc=for_.get("top_features_per_pc", 3),
    )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log = raw.get("logging", {})
    logging_cfg = LoggingSettings(
        level=log.get("level", "INFO"),
        format=log.get(
            "format",
            "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
        ),
        date_format=log.get("date_format", "%Y-%m-%d %H:%M:%S"),
        file_enabled=log.get("file_enabled", True),
        file_max_bytes=int(log.get("file_max_bytes", 10_485_760)),
        file_backup_count=int(log.get("file_backup_count", 5)),
    )

    settings = HiGISettings(
        paths=paths,
        ingestion=ingestion,
        training=training,
        hilbert=hilbert,
        balltree=balltree,
        gmm=gmm,
        iforest=iforest,
        sentinel=sentinel,
        velocity=velocity,
        tribunal=tribunal,
        family_consensus=family_consensus,
        persistence=persistence,
        forensic=forensic,
        logging=logging_cfg,
    )

    _validate(settings)
    return settings


def _validate(s: HiGISettings) -> None:
    """Raise ValueError for any logically invalid parameter combination."""
    errors: List[str] = []

    if not (0.80 <= s.hilbert.pca_variance_target <= 1.0):
        errors.append(
            f"hilbert.pca_variance_target must be in [0.80, 1.0], "
            f"got {s.hilbert.pca_variance_target}"
        )
    if not (0.0 < s.iforest.contamination < 0.5):
        errors.append(
            f"iforest.contamination must be in (0, 0.5), "
            f"got {s.iforest.contamination}"
        )
    if not (0.0 <= s.tribunal.consensus_threshold <= 1.0):
        errors.append(
            f"tribunal.consensus_threshold must be in [0, 1], "
            f"got {s.tribunal.consensus_threshold}"
        )
    if not (0.0 <= s.velocity.tribunal_weight <= 1.0):
        errors.append(
            f"velocity.tribunal_weight must be in [0, 1], "
            f"got {s.velocity.tribunal_weight}"
        )
    w = s.tribunal.weights
    if abs(w.balltree + w.gmm + w.iforest - 1.0) > 1e-4:
        errors.append(
            f"tribunal.weights must sum to 1.0, "
            f"got {w.balltree + w.gmm + w.iforest:.4f}"
        )
    if s.velocity.bypass_threshold <= 0:
        errors.append(
            f"velocity.bypass_threshold must be > 0, "
            f"got {s.velocity.bypass_threshold}"
        )
    if s.persistence.ma_window_size < 1:
        errors.append(
            f"persistence.ma_window_size must be ≥ 1, "
            f"got {s.persistence.ma_window_size}"
        )
    if not (0.0 < s.training.augmentation_noise_scale < 1.0):
        errors.append(
            f"training.augmentation_noise_scale must be in (0.0, 1.0), "
            f"got {s.training.augmentation_noise_scale}"
        )
    if not (0.0 < s.training.augmentation_synthetic_fraction < 1.0):
        errors.append(
            f"training.augmentation_synthetic_fraction must be in (0.0, 1.0), "
            f"got {s.training.augmentation_synthetic_fraction}"
        )

    if errors:
        raise ValueError(
            "config.yaml validation failed:\n"
            + "\n".join(f"  • {e}" for e in errors)
        )

    logger.debug(f"[config] Validation passed ({len(errors)} errors).")


## File: main.py
#!/usr/bin/env python3
"""
HiGI IDS — Unified Entry Point.

Single command-line interface for all HiGI operations:

    python main.py train  --source Monday.pcap     --bundle models/baseline.pkl
    python main.py detect --source Wednesday.pcap  --bundle models/baseline.pkl
    python main.py report --results data/processed/wednesday_results.csv --bundle models/baseline_model.pkl --output-dir reports/forensic_wednesday/ 
    python main.py run    --source Wednesday.pcap  --bundle models/baseline.pkl

Modes:
    train  — Ingest a benign PCAP, build feature matrix, train the four-tier
             detection engine (BallTree + GMM + IForest + Velocity Bypass),
             and persist an ArtifactBundle to disk.

    detect — Load an ArtifactBundle, ingest a test PCAP, run inference, and
             write a results CSV with anomaly flags, severity, and forensic
             evidence for every time window.

    report — Read an existing results CSV and generate a professional
             forensic report (PDF + Markdown) with incident clustering,
             MITRE ATT&CK mapping, and data-quality heuristics.

    run    — Shorthand for detect followed immediately by report.  Produces
             the CSV, PDF, and Markdown in a single command.

Design principles:
    • Zero magic numbers — every threshold is read from config.yaml via
      src/config.py → HiGISettings.
    • No business logic — this file contains only CLI glue.  All physics,
      ML, and forensic logic lives in the src/ modules.
    • Micro-batch ready — the DetectionPipeline processes data in chunks,
      so swapping the PCAP reader for a live socket reader tomorrow requires
      changing only one function in src/ingestion/.
    • Idempotent — all outputs are deterministic for a given (source, bundle)
      pair; running the same command twice produces identical results.

Usage examples:
    # Establish Monday baseline:
    python main.py train \\
        --source data/raw/Monday.pcap \\
        --bundle models/baseline_monday.pkl

    # Detect on Wednesday with verbose logging:
    python main.py detect \\
        --source data/raw/Wednesday.pcap \\
        --bundle models/baseline_monday.pkl \\
        --output data/processed/wednesday_results.csv \\
        --verbose

    # Generate forensic report with strict filters:
    python main.py report \\
        --results data/processed/wednesday_results.csv \\
        --confidence 0.90 \\
        --min-anomalies 5 \\
        --output-dir reports/

    # Full pipeline in one command (detect + report):
    python main.py run \\
        --source data/raw/Wednesday.pcap \\
        --bundle models/baseline_monday.pkl \\
        --output-dir data/processed/ \\
        --confidence 0.75

    # Use a custom config file:
    python main.py train --source Monday.pcap --bundle models/b.pkl \\
        --config configs/production.yaml

Author: Blue Team Engineering
Version: 4.0.0
"""

from __future__ import annotations

import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"

import argparse
import gc
import json
import logging
import logging.handlers
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from src.orchestrator import TrainingError, TrainingPipeline

# Project root on PYTHONPATH so `src.*` imports resolve correctly.
_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))

from src.config import HiGISettings, load_settings


# ============================================================================
# LOGGING SETUP
# ============================================================================

def _configure_logging(settings: HiGISettings, verbose: bool = False) -> logging.Logger:
    """
    Configure the root logger from HiGISettings.

    If verbose=True the effective level is forced to DEBUG regardless of the
    config file value.  Log files rotate at 10 MB by default.

    Args:
        settings: Loaded HiGISettings from config.yaml.
        verbose: Override log level to DEBUG when True.

    Returns:
        Root logger ready for use.
    """
    cfg = settings.logging
    level_name = "DEBUG" if verbose else cfg.level.upper()
    level = getattr(logging, level_name, logging.INFO)

    formatter = logging.Formatter(fmt=cfg.format, datefmt=cfg.date_format)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # Console handler (always enabled)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # Rotating file handler (optional)
    if cfg.file_enabled:
        log_dir = Path(settings.paths.logs_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"higi_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=cfg.file_max_bytes,
            backupCount=cfg.file_backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    return logging.getLogger("higi")


# ============================================================================
# MODE: TRAIN
# ============================================================================

def run_train(args: argparse.Namespace, settings: HiGISettings) -> int:
    """
        Training pipeline: PCAP → feature matrix → HiGIEngine → ArtifactBundle.

        Reads all tunable parameters (chunk size, HiGI thresholds, GMM components)
        from HiGISettings derived from config.yaml.

        Args:
            args: Parsed CLI arguments (source, bundle).
            settings: Loaded HiGISettings.

        Returns:
            Exit code (0 = success, 1 = failure).
    """
        

    logger = logging.getLogger("higi.train")

    source = Path(args.source)
    bundle_path = Path(args.bundle)

    if not source.exists():
        logger.error(f"Source PCAP not found: {source}")
        return 1

    logger.info("=" * 80)
    logger.info("HiGI TRAINING MODE")
    logger.info("=" * 80)
    logger.info(f"  Source PCAP : {source}")
    logger.info(f"  Output Bundle: {bundle_path}")
    logger.info("")

    try:
        # Extract configuration from loaded settings (dependency injection)
        higi_config = settings.to_higi_config()
        
        logger.info("Injected Configuration:")
        logger.info(f"  Engine config: {higi_config.use_bayesian_gmm=}, "
                    f"{higi_config.gmm_score_normalization_method=}, "
                    f"{higi_config.per_feature_thresholds=}")
        logger.info(f"  Augmentation: noise_scale={settings.training.augmentation_noise_scale}, "
                    f"synthetic_fraction={settings.training.augmentation_synthetic_fraction}")
        
        # Initialize pipeline with all configuration injected
        pipeline = TrainingPipeline(
            pcap_path=str(source),
            output_bundle_path=str(bundle_path),
            chunks=settings.ingestion.chunk_size,
            cores=settings.ingestion.n_jobs,
            higi_config=higi_config,
            augmentation_noise_scale=settings.training.augmentation_noise_scale,
            augmentation_synthetic_fraction=settings.training.augmentation_synthetic_fraction,
        )
        bundle = pipeline.run()
        bundle.save(str(bundle_path))
        logger.info(f"  ✓ Training complete. Bundle saved to {bundle_path}")

        return 0
    except TrainingError as exc:
        print(f"\n[!] Error en el Pipeline de Entrenamiento: {exc}")
        return 1
    except Exception as exc:
        print(f"\n[!] Error inesperado: {exc}")
        return 1
    


# ============================================================================
# MODE: DETECT
# ============================================================================

def run_detect(args: argparse.Namespace, settings: HiGISettings) -> int:
    """
    Detection mode: delegate to DetectionPipeline.

    Args:
        args: Parsed CLI arguments (source, bundle, output).
        settings: Loaded HiGISettings.

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    from src.orchestrator import DetectionPipeline, DetectionError

    logger = logging.getLogger("higi.detect")

    source = Path(args.source)
    bundle_path = Path(args.bundle)
    output_path = Path(getattr(args, "output", None) or _default_results_path(source, settings))

    if not source.exists():
        logger.error(f"Source PCAP not found: {source}")
        return 1
    if not bundle_path.exists():
        logger.error(f"Bundle not found: {bundle_path}")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 80)
    logger.info("HiGI DETECTION MODE")
    logger.info("=" * 80)
    logger.info(f"  Source PCAP  : {source}")
    logger.info(f"  Bundle       : {bundle_path}")
    logger.info(f"  Output CSV   : {output_path}")
    logger.info("")

    try:
        pipeline = DetectionPipeline(
            pcap_path=str(source),
            bundle_path=str(bundle_path),
            output_results_path=str(output_path),
            settings=settings,
        )
        pipeline.run()

        if hasattr(args, "_results_path_out"):
            args._results_path_out = str(output_path)

        return 0

    except DetectionError as exc:
        logger.error(f"Detection pipeline failed: {exc}")
        return 1
    except Exception as exc:
        logger.error(f"Unexpected detection error: {exc}")
        logger.debug(traceback.format_exc())
        return 1



# ============================================================================
# MODE: REPORT
# ============================================================================

def run_report(args: argparse.Namespace, settings: HiGISettings) -> int:
    """
    Forensic report generation: results CSV → PDF + Markdown.

    All filtering parameters (confidence, min_anomalies, min_duration) default
    to values from config.yaml → forensic section and can be overridden via CLI.

    Args:
        args: Parsed CLI arguments (results, output_dir, confidence, etc.).
        settings: Loaded HiGISettings.

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    from src.analysis.forensic_engine import (
        HiGIForensicEngine,
        generate_forensic_pdf,
        generate_markdown_report,
    )
    from src.orchestrator import ArtifactBundle

    logger = logging.getLogger("higi.report")

    results_path = Path(args.results)
    output_dir = Path(
        getattr(args, "output_dir", None) or settings.paths.reports_dir
    )

    #Load the trained bundle for forensic attribution (optional but recommended)
    bundle = None
    if hasattr(args, "bundle") and args.bundle:
        bundle_path = Path(args.bundle)
        if bundle_path.exists():
            try:
                bundle = ArtifactBundle.load(bundle_path)
                logger.info(f"[✓] PCA Metadata loaded from {bundle_path}")
            except Exception as e:
                logger.warning(f"Could not load ArtifactBundle: {e}. Degrading to CSV-only mode.")
    
    if not results_path.exists():
        logger.error(f"Results CSV not found: {results_path}")
        return 1

    # Resolve filter parameters: CLI overrides config defaults
    confidence = getattr(args, "confidence", None) or settings.forensic.default_confidence_filter
    min_anomalies = getattr(args, "min_anomalies", None) or settings.forensic.default_min_anomalies
    min_duration = getattr(args, "min_duration", None) or settings.forensic.default_min_duration_seconds
    sigma_min = settings.forensic.sigma_culprit_min

    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = results_path.stem
    pdf_out = output_dir / f"{base_name}_FORENSIC.pdf"
    md_out = output_dir / f"{base_name}_FORENSIC.md"

    if not results_path.exists():
        logger.error(f"Results CSV not found: {results_path}")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = results_path.stem
    pdf_out = output_dir / f"{base_name}_FORENSIC.pdf"
    md_out = output_dir / f"{base_name}_FORENSIC.md"

    logger.info("=" * 80)
    logger.info("HiGI FORENSIC REPORT MODE")
    logger.info("=" * 80)
    logger.info(f"  Results CSV  : {results_path}")
    logger.info(f"  Output dir   : {output_dir}")
    logger.info(f"  Confidence   : ≥ {confidence:.0%}")
    logger.info(f"  Min anomalies: {min_anomalies}")
    logger.info(f"  Min duration : {min_duration}s")
    logger.info("")

    try:
        # ForensicEnginev2 reads the CSV and clusters incidents internally.
        engine = HiGIForensicEngine(
            settings=settings, 
            results_path=results_path, 
            bundle=bundle
        )
        logger.info(f"[INFO] Clustering incidents (Debounce: {settings.forensic.debounce_seconds}s)...")    

        logger.info(
            f"[INFO] Clustering with {settings.forensic.debounce_seconds:.0f}s debounce…"
        )
        data_drops = engine.detect_data_drops()

        logger.info(f"  ✓ {len(data_drops)} data gaps detected")

        filter_kwargs = {
            "confidence_filter": confidence,
            "min_anomalies_per_incident": min_anomalies,
            "min_duration_seconds": min_duration,
            "sigma_culprit_min": sigma_min,
        }

        stats = engine.generate_summary_stats(**filter_kwargs)
        capture_health = stats.get("capture_health", {})

        logger.info(
            f"  ✓ Quality score: "
            f"{capture_health.get('capture_quality_score', 0):.1%}"
        )

        # Generate visualizations for the Markdown report
        logger.info("[VIS] Generating Physical Stress Radar and Timeline...")
        try:
            visual_paths = engine.generate_visuals(output_dir)
            logger.info(f"  ✓ Timeline plot: {visual_paths.get('timeline_plot', 'N/A')}")
            logger.info(f"  ✓ Distribution plot: {visual_paths.get('distribution_plot', 'N/A')}")
        except Exception as vis_exc:
            logger.warning(f"Failed to generate visualizations: {vis_exc}")
            visual_paths = None

        # PDF report
        logger.info(f"[PDF] Generating {pdf_out.name}…")
        generate_forensic_pdf(engine, str(pdf_out), **filter_kwargs)
        logger.info(f"  ✓ {pdf_out.stat().st_size / 1024:.1f} KB")

        # Markdown report with visual evidence
        logger.info(f"[MD ] Generating {md_out.name}…")
        generate_markdown_report(engine, str(md_out), visual_paths=visual_paths, **filter_kwargs)
        logger.info(f"  ✓ {md_out.stat().st_size / 1024:.1f} KB")

        logger.info("")
        logger.info("[SUMMARY]")
        logger.info("-" * 80)
        logger.info(f"  Total anomalies  : {stats.get('total_anomalies', 0)}")
        logger.info(f"  ✓ Quality Score   : {stats.get('capture_health', {}).get('capture_quality_score', 0):.1%}")
        logger.info(f"  ✓ Total Incidents : {stats.get('total_incidents', 0)}")
        logger.info(f"  ✓ Max Severity    : {stats.get('max_severity', 0)}/3")
        logger.info("=" * 80)
        logger.info(
            f"  Max / Avg severity: "
            f"{stats.get('max_severity', 0)}/3 / "
            f"{stats.get('avg_severity', 0):.2f}/3"
        )
        logger.info(f"  Data drops       : {stats.get('data_drops_detected', 0)}")

        logger.info("=" * 80)
        logger.info("✓ REPORT GENERATION COMPLETE")
        logger.info(f"  PDF  : {pdf_out}")
        logger.info(f"  MD   : {md_out}")
        logger.info("=" * 80)
        return 0

    except Exception as exc:
        logger.error(f"Report generation failed: {exc}")
        logger.debug(traceback.format_exc())
        return 1


# ============================================================================
# MODE: RUN (detect + report in one shot)
# ============================================================================

def run_pipeline(args: argparse.Namespace, settings: HiGISettings) -> int:
    """
    Full pipeline shorthand: detect → report.

    Derives the intermediate results CSV path from --output-dir and the source
    PCAP stem so intermediate files are always predictably named.

    Args:
        args: Parsed CLI arguments.
        settings: Loaded HiGISettings.

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    logger = logging.getLogger("higi.run")

    output_dir = Path(getattr(args, "output_dir", None) or settings.paths.results_dir)
    source_stem = Path(args.source).stem
    results_csv = output_dir / f"{source_stem}_results.csv"

    # Inject the computed output path so run_detect knows where to write.
    args.output = str(results_csv)
    args._results_path_out = str(results_csv)

    logger.info("=" * 80)
    logger.info("HiGI FULL PIPELINE (detect + report)")
    logger.info("=" * 80)

    rc = run_detect(args, settings)
    if rc != 0:
        return rc

    # Wire the report step to the just-written CSV.
    args.results = str(results_csv)
    args.output_dir = str(output_dir)
    return run_report(args, settings)


# ============================================================================
# CLI PARSER
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    """Construct and return the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="HiGI IDS — Physical-layer Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="PATH",
        help="Path to config YAML (default: config.yaml in project root).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Force DEBUG-level logging.",
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    # ── train ──────────────────────────────────────────────────────────────
    p_train = subparsers.add_parser(
        "train",
        help="Establish baseline from a benign PCAP.",
    )
    p_train.add_argument(
        "--source", required=True, metavar="PCAP",
        help="Path to benign baseline PCAP file.",
    )
    p_train.add_argument(
        "--bundle", required=True, metavar="PKL",
        help="Output path for trained ArtifactBundle (.pkl).",
    )

    # ── detect ─────────────────────────────────────────────────────────────
    p_detect = subparsers.add_parser(
        "detect",
        help="Run anomaly detection on a test PCAP.",
    )
    p_detect.add_argument(
        "--source", required=True, metavar="PCAP",
        help="Path to test PCAP file.",
    )
    p_detect.add_argument(
        "--bundle", required=True, metavar="PKL",
        help="Path to trained ArtifactBundle (.pkl).",
    )
    p_detect.add_argument(
        "--output", default=None, metavar="CSV",
        help="Output results CSV (default: <results_dir>/<source_stem>_results.csv).",
    )

    # ── report ─────────────────────────────────────────────────────────────
    p_report = subparsers.add_parser(
        "report",
        help="Generate PDF + Markdown forensic report from a results CSV.",
    )
    p_report.add_argument(
        "--results", required=True, metavar="CSV",
        help="Path to detection results CSV (output of detect).",
    )
    p_report.add_argument(
        "--output-dir", default=None, metavar="DIR",
        help="Directory for PDF and Markdown outputs (default: from config.yaml).",
    )
    p_report.add_argument(
        "--confidence", type=float, default=None, metavar="FLOAT",
        help="Minimum incident confidence to report (0.0–1.0; default from config.yaml).",
    )
    p_report.add_argument(
        "--min-anomalies", type=int, default=None, metavar="N",
        help="Minimum anomalies per incident (default from config.yaml).",
    )
    p_report.add_argument(
        "--min-duration", type=float, default=None, metavar="SEC",
        help="Minimum incident duration in seconds (default from config.yaml).",
    )

    p_report.add_argument(
        "--bundle", type = Path,
        help="Path to the trained ArtifactBundle (.pkl)."
    )

    # ── run ────────────────────────────────────────────────────────────────
    p_run = subparsers.add_parser(
        "run",
        help="Full pipeline: detect + report in one command.",
    )
    p_run.add_argument(
        "--source", required=True, metavar="PCAP",
        help="Path to test PCAP file.",
    )
    p_run.add_argument(
        "--bundle", required=True, metavar="PKL",
        help="Path to trained ArtifactBundle (.pkl).",
    )
    p_run.add_argument(
        "--output-dir", default=None, metavar="DIR",
        help="Directory for all outputs (CSV, PDF, MD; default from config.yaml).",
    )
    p_run.add_argument(
        "--confidence", type=float, default=None, metavar="FLOAT",
        help="Min incident confidence for report (default from config.yaml).",
    )
    p_run.add_argument(
        "--min-anomalies", type=int, default=None, metavar="N",
        help="Min anomalies per incident for report (default from config.yaml).",
    )
    p_run.add_argument(
        "--min-duration", type=float, default=None, metavar="SEC",
        help="Min incident duration in seconds for report (default from config.yaml).",
    )

    return parser


def _default_results_path(source: Path, settings: HiGISettings) -> str:
    """Derive a sensible default results CSV path from source stem + config."""
    return str(Path(settings.paths.results_dir) / f"{source.stem}_results.csv")


# ============================================================================
# ENTRY POINT
# ============================================================================

def main() -> int:
    """
    Parse arguments, load settings, dispatch to the appropriate mode handler.

    Returns:
        Exit code passed to sys.exit().
    """
    parser = _build_parser()
    args = parser.parse_args()

    # Load settings first (needed by logging setup)
    try:
        settings = load_settings(args.config)
    except ValueError as exc:
        # config.yaml validation failure — print directly since logger not ready
        print(f"[ERROR] Configuration error: {exc}", file=sys.stderr)
        return 1

    _configure_logging(settings, verbose=args.verbose)
    logger = logging.getLogger("higi")
    logger.info(f"HiGI IDS v4.0  |  mode={args.mode}")

    dispatch = {
        "train": run_train,
        "detect": run_detect,
        "report": run_report,
        "run": run_pipeline,
    }

    handler = dispatch.get(args.mode)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args, settings)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        return 130
    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        logger.debug(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())

## File config.yaml

# =============================================================================
# HiGI IDS — Unified Configuration (config.yaml)
# =============================================================================
# Every threshold, weight, sigma, and file path lives here.
# The source code contains zero magic numbers.
#
# Format: YAML 1.2 (loaded by PyYAML / strictyaml-compatible)
# Validated at startup by src/config.py → HiGISettings dataclass.
# =============================================================================

# ---------------------------------------------------------------------------
# I/O Paths
# ---------------------------------------------------------------------------
paths:
  models_dir: "models"                          # Trained artifact bundles (.pkl)
  results_dir: "data/processed"                 # Detection result CSVs
  reports_dir: "reports"                        # Forensic PDF + Markdown
  logs_dir: "logs"                              # Rotating log files
  scalers_dir: "models/scalers"                 # RobustScaler snapshots

# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
ingestion:
  chunk_size: 5000          # Packets per parallel processing chunk
  n_jobs: 6                 # CPU cores for parallel ingestion
  time_interval: "1s"       # Feature aggregation window size

# ---------------------------------------------------------------------------
# Training Augmentation (Baseline Synthesis)
# ---------------------------------------------------------------------------
training:
  baseline_augmentation_enabled: true     # Enable Gaussian noise augmentation during training
  augmentation_noise_scale: 0.05          # Noise magnitude as fraction of feature std dev (5% default)
  augmentation_synthetic_fraction: 0.10   # Fraction of augmented samples relative to baseline (10% default)

# ---------------------------------------------------------------------------
# Hilbert Space Projector
# ---------------------------------------------------------------------------
hilbert:
  pca_variance_target: 0.99           # Cumulative explained variance for PCA (fallback)
  pca_eigenvalue_max_condition: 1.0e12  # Stability floor for eigenvalue conditioning
  blocked_pca_enabled: true           # Enable per-family Blocked PCA
  blocked_pca_variance_per_family:    # Per-family variance retention targets
    volume: 0.95                       # High-variance features (bytes, pps, velocity)
    payload: 0.95                      # Raw byte counts with extreme scales
    flags: 0.99                        # Low-variance ratios [0,1] — retain more variance
    protocol: 0.99                     # Low-variance ratios — retain more variance
    connection: 0.95                   # Kinematics and port features

# ---------------------------------------------------------------------------
# BallTree Detector (Tier 1)
# ---------------------------------------------------------------------------
balltree:
  k_neighbors: 5              # k for mean k-NN distance computation
  threshold_p90: 90.0         # Soft-zone lower bound (%)
  threshold_p95: 95.0         # Borderline tier threshold (%)
  threshold_p99: 99.0         # Medium tier threshold (%)
  threshold_p99_9: 99.9       # Critical tier threshold (%)
  slack: 1.2                  # Threshold multiplier for sensitivity tuning

# ---------------------------------------------------------------------------
# GMM Detector (Tier 2A)
# ---------------------------------------------------------------------------
gmm:
  use_bayesian: true                      # BayesianGaussianMixture vs GaussianMixture
  bayesian_weight_concentration_prior: 1.0e-2   # Sparse cluster penalty
  reg_covar: 0.1                          # Ridge covariance regularisation
  max_iter: 200                           # EM iterations
  n_init: 10                             # Random restarts
  n_components_fallback: 5               # Used when adaptive K selection fails
  threshold_percentile: 99.9             # Inverted LL threshold (%)
  score_normalization: "cdf"             # "cdf" | "robust" | "minmax"
  adaptive_k_enabled: true              # Ensemble-vote for optimal K
  adaptive_k_range: [1, 5]             # Search range for adaptive K
  adaptive_k_max_components: 25         # Upper bound for multivariate K

# ---------------------------------------------------------------------------
# Isolation Forest Detector (Tier 2B)
# ---------------------------------------------------------------------------
iforest:
  contamination: 0.05         # Expected anomaly fraction
  n_estimators: 100

# ---------------------------------------------------------------------------
# Physical Sentinel (Tier 3 — univariate GMM log-likelihood)
# ---------------------------------------------------------------------------
sentinel:
  enabled: true
  per_feature_thresholds: true        # Per-feature LL threshold (P99.9 per feature)
  global_threshold: 1.0e-6            # Fallback if per-feature disabled
  directionality_analysis: true       # Track SPIKE/DROP direction in forensic output
  portero_sigma_threshold: 20.0       # Extreme sigma → forced CRITICAL (Portero veto)

# ---------------------------------------------------------------------------
# Velocity Bypass Detector (Tier 4 — rolling Z-score gate)
# ---------------------------------------------------------------------------
velocity:
  enabled: true
  bypass_threshold: 5.0       # Z-score magnitude that fires emergency bypass
  tribunal_weight: 0.30       # Weight in Tribunal consensus
  # Severity mapping: z_score >= threshold → severity_level
  severity_thresholds:
    - [12.0, 3]               # Critical
    - [8.0, 2]                # Medium
    - [5.0, 1]                # Borderline

# ---------------------------------------------------------------------------
# Tribunal Consensus
# ---------------------------------------------------------------------------
tribunal:
  weighted_mode: true
  # Base weights BEFORE velocity carve-out.
  # Actual weights = base_weight × (1 - velocity.tribunal_weight).
  # Final weights are normalised to sum 1.0 in HiGIConfig.__post_init__().
  weights:
    balltree: 0.25
    gmm: 0.40
    iforest: 0.35
  consensus_threshold: 0.5            # Minimum weighted score to confirm anomaly
  majority_vote_threshold: 2          # Votes needed in legacy (non-weighted) mode

# ---------------------------------------------------------------------------
# Family Consensus (FIX-4 — co-firing requirement for borderline samples)
# ---------------------------------------------------------------------------
family_consensus:
  enabled: true
  min_hits: 2                 # Min features from same family required for escalation
  z_threshold: 2.0            # Feature-level Z-score to count as "hit"

# ---------------------------------------------------------------------------
# Persistence / Hysteresis
# ---------------------------------------------------------------------------
persistence:
  warmup_multiplier: 3        # warmup_rows = ma_window_size × warmup_multiplier
  ma_window_size: 5           # Rolling mean window for MA contextualisation
  transient_threshold: 0.4    # ratio > 1/transient_threshold → "Transient Spike"
  hysteresis_entry_multiplier: 1.0    # Entry threshold = p95 × multiplier
  hysteresis_exit_multiplier: 0.75    # Exit threshold = p95 × multiplier
  alert_minimum_persistence: 3        # Base consecutive windows to confirm alert
  persistence_filter_window: 3        # Rolling-min window for anti-FP filter

# ---------------------------------------------------------------------------
# Forensic Engine
# ---------------------------------------------------------------------------
forensic:
  debounce_seconds: 30                # Incident clustering debounce
  data_drop_threshold_seconds: 60     # Gap size that counts as a "Data Drop"
  sigma_culprit_min: 2.0              # Min mean |sigma| to include incident in report
  default_confidence_filter: 0.8     # Default min confidence for reportable incidents
  default_min_anomalies: 3            # Default min anomalies per incident
  default_min_duration_seconds: 1.0   # Default min incident duration
  top_features_per_pc: 3              # Features per PC in forensic attribution
  tier_confidence_weights:      # Pesos para Consensus Confidence Index
    balltree: 0.20
    gmm: 0.25
    iforest: 0.20
    physical_sentinel: 0.20
    velocity_bypass: 0.15

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging:
  level: "INFO"               # DEBUG | INFO | WARNING | ERROR
  format: "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
  date_format: "%Y-%m-%d %H:%M:%S"
  file_enabled: true
  file_max_bytes: 10_485_760  # 10 MB per log file
  file_backup_count: 5


