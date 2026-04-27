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