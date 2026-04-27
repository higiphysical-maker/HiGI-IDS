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
    """Extract the canonical metric name from a raw ``physical_culprit`` string.

    Args:
        raw: Raw culprit annotation, e.g.
             ``"flag_syn_ratio (SPIKE (+865%), σ=4.2) | GMM: pps_acc (LL=-3.2)"``.

    Returns:
        Lowercase metric identifier, e.g. ``"flag_syn_ratio"``.
        Falls back to ``"unknown"`` on parse failure or null input.
    """
    if raw is None or (isinstance(raw, float) and math.isnan(raw)):
        return "unknown"
    match = re.match(r"^([a-z_][a-z0-9_]*)", str(raw).strip(), re.IGNORECASE)
    return match.group(1).lower() if match else "unknown"


def _extract_event_type(raw: str) -> str:
    """Return ``"SPIKE"`` or ``"DROP"`` from a culprit annotation string."""
    m = re.search(r"\b(SPIKE|DROP)\b", str(raw), re.IGNORECASE)
    return m.group(1).upper() if m else "UNKNOWN"


def _extract_sigma(raw: str) -> float:
    """Return the |σ| value embedded in a culprit annotation, or 0.0."""
    m = re.search(r"σ\s*=\s*([\d.]+)", str(raw))
    return float(m.group(1)) if m else 0.0


def _extract_pct(raw: str) -> float:
    """Return the absolute percentage deviation from a culprit annotation."""
    m = re.search(r"(?:SPIKE|DROP)\s*\(([+-]?[\d.]+)%\)", str(raw), re.IGNORECASE)
    return abs(float(m.group(1))) if m else 0.0


def _infer_family(culprit_base: str, family_consensus: Any) -> str:
    """Resolve the physical family for a given anomaly row.

    Precedence:
    1. ``family_consensus`` column value (set by orchestrator from BlockedPCA metadata).
    2. Keyword-match against the culprit metric name.
    3. Fallback → ``"unknown"``.

    Args:
        culprit_base: Canonical metric name, e.g. ``"flag_syn_ratio"``.
        family_consensus: Value from the ``family_consensus`` CSV column (may be NaN).

    Returns:
        Physical family name string.
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
    """Map |σ| → confidence probability via Gaussian CDF.

    Physical interpretation: the probability that a deviation of ``sigma``
    standard deviations is *not* due to chance under a Normal baseline.

    Args:
        sigma: Absolute deviation in standard deviations (≥ 0).

    Returns:
        Confidence in [0.5, 1.0].
    """
    return float(norm.cdf(max(0.0, sigma)))


# ===========================================================================
# DATA STRUCTURES
# ===========================================================================


@dataclass
class TierEvidenceSummary:
    """Compressed evidence record for a single detection tier within an incident.

    Attributes:
        tier_name: Human-readable tier label.
        fired: True if this tier triggered at least once during the incident.
        fire_count: Number of windows where this tier fired.
        mean_score: Mean tier score across all windows (0.0 if not applicable).
    """

    tier_name: str
    fired: bool
    fire_count: int
    mean_score: float


@dataclass
class FeatureAttribution:
    """Top contributing physical feature derived from PCA loadings or column evidence.

    Attributes:
        feature_name: Canonical metric name (e.g. ``"flag_syn_ratio"``).
        loading_magnitude: Absolute PCA loading coefficient (0–1). Set to the
            normalised |σ| if loadings are unavailable.
        event_type: ``"SPIKE"`` or ``"DROP"``.
        max_sigma: Maximum observed |σ| across all windows in the incident.
        max_pct: Maximum observed percentage deviation.
        family: Physical family this feature belongs to.
    """

    feature_name: str
    loading_magnitude: float
    event_type: str
    max_sigma: float
    max_pct: float
    family: str


@dataclass
class SecurityIncidentV2:
    """A clustered security incident with V2 enriched metadata.

    Attributes:
        incident_id: Sequential identifier (0-based).
        start_time: Timezone-aware or naive ``datetime`` of first anomaly.
        end_time: ``datetime`` of last anomaly.
        anomaly_rows: Slice of the results DataFrame belonging to this incident.
        tier_evidence: Summary of which detection tiers fired.
        top_features: Top-3 physical feature attributions, ranked by loading magnitude.
        family_stress: Mapping of family → normalised stress score in [0, 1].
        mitre_tactics: Mapping of MITRE tactic → list of technique strings.
        is_warmup: True if > 50 % of rows are labelled ``is_warmup``.
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
        """Wall-clock duration of the incident in seconds."""
        return (self.end_time - self.start_time).total_seconds()

    @property
    def total_anomalies(self) -> int:
        """Number of anomalous windows in the incident."""
        return len(self.anomaly_rows)

    @property
    def max_severity(self) -> int:
        """Maximum discrete severity label (1–3) within the incident."""
        if self.anomaly_rows.empty:
            return 0
        return int(self.anomaly_rows["severity"].max())

    @property
    def primary_culprit(self) -> str:
        """Most frequently reported physical metric across the incident."""
        if "physical_culprit" not in self.anomaly_rows.columns:
            return "Unknown"
        bases = self.anomaly_rows["physical_culprit"].dropna().apply(_extract_base_name)
        vc = bases.value_counts()
        return str(vc.index[0]) if len(vc) > 0 else "Unknown"

    @property
    def top_3_ports(self) -> List[int]:
        """Top-3 destination ports by detection frequency."""
        if "server_port" not in self.anomaly_rows.columns:
            return []
        return [int(p) for p in self.anomaly_rows["server_port"].value_counts().head(3).index]

    @property
    def persistence_label(self) -> str:
        """Most common persistence classification within the incident."""
        if "persistence" not in self.anomaly_rows.columns:
            return "Unknown"
        vc = self.anomaly_rows["persistence"].dropna().value_counts()
        return str(vc.index[0]) if len(vc) > 0 else "Unknown"

    # ------------------------------------------------------------------
    # Composite scoring
    # ------------------------------------------------------------------

    @property
    def consensus_confidence(self) -> float:
        """Tier-weighted confidence index.

        Formula:
            base   = Gaussian-CDF( mean_|σ| )
            volume = log2(1 + n_anomalies) / log2(513)   [saturates at 512]
            tier_w = Σ(tier_weight_i × fired_i) / Σ(tier_weight_i)
            conf   = 0.45×base + 0.35×volume + 0.20×tier_w

        Warm-up incidents receive a 50 % confidence penalty to reduce
        false-positive pressure during the detector stabilisation phase.

        Returns:
            Confidence score in [0.0, 1.0].
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
        """Euclidean-distance-inspired severity on a continuous [0, ∞) scale.

        Uses the maximum |σ| observed in the incident as a proxy for the
        Euclidean distance to the P99 decision boundary, then amplifies
        non-linearly for extreme deviations (σ > 5) to avoid attenuation
        of high-impact DoS bursts.

        Returns:
            Continuous severity. Typical range [0.0, ~12.0].
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
    """Forensic analysis engine for HiGI IDS V4.0 Blocked-PCA telemetry.

    Converts a raw results CSV (or DataFrame) into a structured incident
    report including:
      * Blocked-PCA family attribution for every anomaly window.
      * Tier-weighted Consensus Confidence Index.
      * XAI top-3 feature attributions per incident (SPIKE / DROP).
      * MITRE ATT&CK mapping per culprit metric.
      * Two executive-grade visualisations (attack intensity timeline and
        physical family stress radar).
      * Markdown executive report with embedded plot references.

    The engine is designed to be a drop-in replacement for ``ForensicEngine``
    V1: ``main.py`` can import it under the same alias.

    Example usage::

        from src.analysis.forensic_engine import HiGIForensicEngine as ForensicEngine

        engine = HiGIForensicEngine("data/processed/Wednesday_Victim_50_results.csv")
        engine.cluster_incidents()
        engine.detect_data_drops()
        engine.generate_report()

    Attributes:
        csv_path: Path to the results CSV file.
        config: Runtime configuration dictionary (mirrors config.yaml forensic section).
        df: Full results DataFrame.
        df_anomalies: Filtered DataFrame containing only anomalous / soft-zone rows.
        incidents: Clustered ``SecurityIncidentV2`` objects.
        data_drops: Detected telemetry gaps.
    """

    def __init__(
        self,
        settings : Any,
        results_path: str,
        bundle: Optional[Any] = None,
    ) -> None:
        """Initialise the ForensicEngine and load the results CSV.

        Args:
            csv_path: Path to the HiGI results CSV.
            debounce_seconds: Maximum gap (s) between consecutive anomalies
                before starting a new incident cluster.
            data_drop_threshold_seconds: Minimum gap (s) to flag as a
                telemetry data-drop event.
            confidence_filter: Minimum ``consensus_confidence`` for an
                incident to appear in the report.
            min_anomalies_per_incident: Minimum anomaly count per incident.
            min_duration_seconds: Minimum duration (s) per incident.
            sigma_culprit_min: Incidents whose mean |σ| falls below this
                value are suppressed from the executive report.

        Raises:
            FileNotFoundError: If ``csv_path`` does not exist.
            ValueError: If essential DataFrame columns are missing.
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
        """Validate required columns and build the ``dt`` timeline column.

        Raises:
            ValueError: If the DataFrame is empty or missing critical columns.
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
        """Cluster anomaly windows into ``SecurityIncidentV2`` objects.

        Algorithm:
            1. Compute time gaps between consecutive anomalous windows (O(n)).
            2. Mark a new incident whenever the gap exceeds ``debounce_seconds``.
            3. Assign cumulative incident IDs and group the DataFrame.
            4. Enrich each incident with tier evidence, feature attribution,
               family stress, and MITRE mappings.

        Returns:
            Ordered list of ``SecurityIncidentV2`` instances.
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
        """Construct a ``SecurityIncidentV2`` from a group of anomaly rows.

        Args:
            iid: Incident index (0-based).
            rows: DataFrame slice for this incident's anomaly windows.
            has_warmup: True if the ``is_warmup`` column is present.

        Returns:
            Fully enriched ``SecurityIncidentV2``.
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
        """Build per-tier firing summaries for an incident.

        Args:
            rows: Anomaly rows for the incident.

        Returns:
            List of ``TierEvidenceSummary`` objects (one per detection tier).
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
        """Identify the top-``top_n`` physical features by deviation magnitude.

        Methodology:
          * Extract base metric name, |σ|, event type, and deviation % from
            the ``physical_culprit`` annotations in each row.
          * Normalise loading magnitude as |σ| / max_|σ| within the incident
            so values are comparable across incidents.
          * Infer physical family from the ``family_consensus`` column when
            available, otherwise via keyword matching.

        Args:
            rows: Anomaly rows for the incident.
            top_n: Number of top features to return.

        Returns:
            Sorted list of ``FeatureAttribution`` objects (highest loading first).
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
        """Compute a normalised stress score [0, 1] for each physical family.

        Stress is the sum of |culprit_deviation| values attributed to that
        family, normalised by the total deviation across all families.

        Args:
            rows: Anomaly rows for the incident.

        Returns:
            Dictionary mapping family name → stress in [0, 1].
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
        """Map physical culprit metrics in ``rows`` to MITRE ATT&CK techniques.

        Args:
            rows: Anomaly rows for the incident.

        Returns:
            Mapping of tactic name → deduplicated list of technique strings.
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
        """Detect telemetry gaps in the full capture timeline.

        A gap is flagged when consecutive ``dt`` values differ by more than
        ``data_drop_threshold_seconds``.  Gaps that follow a high-severity
        incident cluster are classified as possible Sensor Saturation.

        Returns:
            List of gap dictionaries with keys
            ``start_time``, ``end_time``, ``gap_seconds``,
            ``severity_before``, ``is_anomaly_context``, and ``reason``.
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
        """Return incidents that satisfy all reporting quality thresholds.

        Applies three physical filters (confidence, volume, duration) and an
        optional σ-culprit filter to suppress noise bursts.

        Args:
            **kwargs: Optional threshold overrides:
                ``confidence_filter``, ``min_anomalies_per_incident``,
                ``min_duration_seconds``, ``sigma_culprit_min``.

        Returns:
            Filtered and sorted list of ``SecurityIncidentV2``.
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
        """Compute executive-level summary statistics.

        Args:
            **kwargs: Optional filter overrides (passed to
                ``get_reportable_incidents``).

        Returns:
            Dictionary of aggregate metrics used by report generators.
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
        """Return a copy of the engine configuration for transparency / logging."""
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
        """Render the Attack Intensity Timeline and save to ``out_path``.

        Args:
            out_path: Output PNG file path.
            incidents_to_plot: Optional list of SecurityIncidentV2 objects to
                annotate.  If None, uses self.incidents.  Typically this is the
                filtered list from get_reportable_incidents() to ensure
                consistency with the Markdown report.
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
        fig.subplots_adjust(top=0.82)

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

        for inc in target_incidents:
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

            # ── EXTERNAL ANNOTATION: Position in header zone (y > 1.0) ──
            # y=1.12 places the text box above the plot area in axes fraction coordinates
            ax.annotate(
                f"#{inc.incident_id + 1}: {culprit_label}",
                xy=(t_mid, y_arrow_point),
                xytext=(x_frac, 1.12),
                xycoords="data",  # Arrow origin stays at actual data point
                textcoords="axes fraction",  # Text box positioned in figure space
                fontsize=8, color="#f0f6fc", ha="center", va="bottom",
                bbox=dict(
                    boxstyle="round,pad=0.4", facecolor="#0d1117",
                    edgecolor="#58a6ff", linewidth=0.8, alpha=0.95,
                ),
                arrowprops=dict(
                    arrowstyle="-", color="#58a6ff", lw=0.5,
                    connectionstyle="arc3,rad=0.0",  # Straight line
                    linestyle="--", alpha=0.4,
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
        """Render the Physical Family Stress Radar chart and save to ``out_path``.

        Args:
            out_path: Output PNG file path.
            incidents_to_plot: Optional list of SecurityIncidentV2 objects to
                aggregate family stress from.  If None, uses self.incidents.
                Typically this is the filtered list from get_reportable_incidents()
                to ensure consistency with the Markdown report.
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
        """Generate the Markdown executive report (main public entry point).

        Orchestrates the full pipeline:
          1. Cluster incidents (if not already done).
          2. Detect data drops (if not already done).
          3. Generate visualisations and save PNGs adjacent to the report.
          4. Write the Markdown file and return its path as a string.

        Args:
            output_dir: Directory for report + PNG files. Defaults to
                ``reports/`` relative to the CSV's parent directory.
            visual_paths: Pre-computed plot paths (skips plot generation
                when provided, useful for testing).
            **filter_kwargs: Threshold overrides forwarded to
                ``get_reportable_incidents``.

        Returns:
            Absolute path of the written Markdown file.
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
        """Render the full Markdown string for the executive report.

        Args:
            visual_paths: Mapping from plot key to relative filename.
            **filter_kwargs: Passed to ``get_reportable_incidents``.

        Returns:
            Complete Markdown document as a string.
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