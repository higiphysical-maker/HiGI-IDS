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

from dataclasses import dataclass, replace as dataclass_replace
from pathlib import Path
from typing import Any, Dict, Final, List, Optional, Tuple, TYPE_CHECKING

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

if TYPE_CHECKING:
    from src.config import RuntimeConfig

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

    def apply_runtime_config(self, runtime_config: "RuntimeConfig") -> "HiGIConfig":
        """
        Create a new HiGIConfig with updated runtime parameters.
        
        This method respects frozen=True by using dataclasses.replace(),
        which creates a new immutable instance. All runtime parameters
        (persistence, tribunal weights, velocity thresholds, forensic settings)
        are updated while mathematical parameters remain fixed.
        
        Args:
            runtime_config: RuntimeConfig from config.yaml (hot-swappable).
        
        Returns:
            New HiGIConfig with updated runtime parameters, ready for inference.
        
        Example:
            >>> engine = HiGIEngine.load('model.pkl')
            >>> settings = load_settings('config.yaml')
            >>> engine.update_runtime_config(settings.to_runtime_config())
        """
        return dataclass_replace(
            self,
            # Persistence / hysteresis
            ma_window_size=runtime_config.ma_window_size,
            transient_threshold=runtime_config.transient_threshold,
            hysteresis_entry_multiplier=runtime_config.hysteresis_entry_multiplier,
            hysteresis_exit_multiplier=runtime_config.hysteresis_exit_multiplier,
            alert_minimum_persistence=runtime_config.alert_minimum_persistence,
            # Tribunal
            weighted_tribunal=runtime_config.weighted_tribunal,
            tribunal_weights=runtime_config.tribunal_weights,
            tribunal_consensus_threshold=runtime_config.consensus_threshold,
            majority_vote_threshold=runtime_config.majority_vote_threshold,
            # Tier 4 — Velocity Bypass
            velocity_bypass_enabled=runtime_config.velocity_enabled,
            velocity_bypass_threshold=runtime_config.velocity_bypass_threshold,
            velocity_tribunal_weight=runtime_config.velocity_tribunal_weight,
            # Family Consensus
            family_consensus_enabled=runtime_config.family_consensus_enabled,
            family_consensus_min_hits=runtime_config.family_consensus_min_hits,
        )


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
    # RUNTIME CONFIGURATION UPDATE (v4.0 — Persistence Conflict Fix)
    # ------------------------------------------------------------------

    def update_runtime_config(self, runtime_config: "RuntimeConfig") -> None:
        """
        Hot-swap operational parameters without retraining.
        
        This method updates the engine's configuration with new runtime
        parameters (persistence filters, tribunal weights, velocity thresholds,
        forensic settings) from config.yaml.  The mathematical foundation
        (Hilbert space, tier-1/2/3 trained models) remains unchanged.
        
        Respects frozen=True by creating a new HiGIConfig via dataclass_replace()
        and assigning it to self.config.  All subsequent analyze() calls use
        the new parameters immediately.
        
        Primary use case: After loading a model with HiGIEngine.load(), call
        this method to apply current config.yaml settings before inference.
        
        Args:
            runtime_config: RuntimeConfig from load_settings(config.yaml).
                           Contains persistence, tribunal, velocity, forensic params.
        
        Returns:
            None — modifies self.config in-place.
        
        Example:
            >>> engine = HiGIEngine.load('models/higi_v4.pkl')
            >>> settings = load_settings('config.yaml')
            >>> engine.update_runtime_config(settings.to_runtime_config())
            >>> # Now analyze() uses the current YAML settings for persistence, etc.
            >>> results = engine.analyze(df_test)
        """
        if not isinstance(runtime_config, dict) and not hasattr(runtime_config, "ma_window_size"):
            raise TypeError(f"Expected RuntimeConfig, got {type(runtime_config)}")
        
        # Apply runtime config to create a new frozen HiGIConfig instance.
        self.config = self.config.apply_runtime_config(runtime_config)
        logger.info(
            f"[✓] Engine runtime config updated: "
            f"alert_min_persistence={self.config.alert_minimum_persistence}, "
            f"velocity_bypass_threshold={self.config.velocity_bypass_threshold}, "
            f"consensus_threshold={self.config.tribunal_consensus_threshold}"
        )

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

        v4.0 change (Persistence Conflict Fix):
        Only the mathematical config (ModelConfig) is persisted. Runtime
        parameters (persistence, tribunal weights, etc.) are loaded from
        config.yaml at inference time via update_runtime_config().

        VelocityBypassDetector has no learned state and is not persisted;
        it is reconstructed from HiGIConfig on the next load.

        Args:
            path: Output file path (e.g. 'models/higi_v4.pkl').
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if not self.is_fitted:
            logger.warning("Engine not fitted — saving anyway.")
        
        # Ensure config has been properly initialized
        if self.config is None:
            raise ValueError("Engine config is not initialized")
        
        joblib.dump(
            {
                "config": self.config,  # Full config saved (backward compatibility)
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
        logger.info("    Note: Runtime config will be loaded from config.yaml at inference time")

    @staticmethod
    def load(path: str, runtime_config: Optional["RuntimeConfig"] = None) -> "HiGIEngine":
        """
        Load engine from disk with optional runtime configuration injection.

        v4.0 change (Persistence Conflict Fix):
        After loading the trained model, optionally inject a RuntimeConfig
        to ensure hot-swappable parameters (persistence, tribunal weights, etc.)
        match the current config.yaml.

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
            5. Injects runtime_config if provided.
            6. Logs detailed diagnostics for debugging deserialization issues.

        Backward compatibility:
            v3.0 bundles lack velocity config fields — HiGIConfig defaults apply.
            v2.x bundles lack training_p99_distance — _patch_v3_balltree() derives it.
            Missing vel_* features at inference time degrade gracefully to zeros.

        Args:
            path: File path (.pkl or .joblib).
            runtime_config: Optional RuntimeConfig to inject after loading.
                          Typically obtained via load_settings().to_runtime_config().

        Returns:
            HiGIEngine ready for inference (all components validated, runtime
            parameters injected if provided).

        Raises:
            FileNotFoundError: Path does not exist.
            ValueError: Cannot extract valid engine from file.
            HiGIInferenceError: Engine components corrupted or not fitted.

        Examples:
            >>> # Basic load
            >>> engine = HiGIEngine.load('models/higi_v4.pkl')
            >>> results = engine.analyze(df_test)
            
            >>> # Load with runtime config from YAML
            >>> settings = load_settings('config.yaml')
            >>> engine = HiGIEngine.load(
            ...     'models/higi_v4.pkl',
            ...     runtime_config=settings.to_runtime_config()
            ... )
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
            if runtime_config:
                loaded.update_runtime_config(runtime_config)
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
            if runtime_config:
                e.update_runtime_config(runtime_config)
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
        
        # Inject runtime config if provided (v4.0 — Persistence Conflict Fix)
        if runtime_config:
            e.update_runtime_config(runtime_config)

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
