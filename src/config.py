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
