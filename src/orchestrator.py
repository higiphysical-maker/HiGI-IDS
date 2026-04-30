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

            # ---- STEP 1.5: RUNTIME CONFIG INJECTION (v4.0 — Persistence Conflict Fix) ----
            # Hot-swap operational parameters from config.yaml without retraining.
            # CRITICAL: Blocked PCA is a training-time decision — immutable.
            logger.info("\n[STEP 1.5] Runtime Config Injection (Persistence Conflict Fix)")
            logger.info("-" * 90)
            
            bundle_config = bundle.engine.config
            runtime_config = self.settings.to_runtime_config()
            
            # Verify Blocked PCA consistency (training-time immutable parameter)
            if bundle_config.blocked_pca_enabled:
                logger.debug(
                    f"[✓] Blocked PCA enabled (training-time immutable): "
                    f"{bundle_config.blocked_pca_variance_per_family}"
                )
            
            # Inject hot-swappable runtime parameters
            # This updates persistence, tribunal weights, velocity bypass thresholds,
            # forensic settings, and family consensus parameters from config.yaml
            bundle.engine.update_runtime_config(runtime_config)
            
            logger.info(
                f"[✓] Runtime config injected:"
                f"\n    alert_minimum_persistence: {bundle.engine.config.alert_minimum_persistence}"
                f"\n    velocity_bypass_threshold: {bundle.engine.config.velocity_bypass_threshold:.1f}σ"
                f"\n    tribunal_consensus_threshold: {bundle.engine.config.tribunal_consensus_threshold}"
                f"\n    family_consensus_enabled: {bundle.engine.config.family_consensus_enabled}"
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
