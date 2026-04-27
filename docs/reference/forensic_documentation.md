# Table of Contents

* [src.analysis.forensic\_engine](#src.analysis.forensic_engine)
  * [TierEvidenceSummary](#src.analysis.forensic_engine.TierEvidenceSummary)
  * [FeatureAttribution](#src.analysis.forensic_engine.FeatureAttribution)
  * [SecurityIncidentV2](#src.analysis.forensic_engine.SecurityIncidentV2)
    * [duration\_seconds](#src.analysis.forensic_engine.SecurityIncidentV2.duration_seconds)
    * [total\_anomalies](#src.analysis.forensic_engine.SecurityIncidentV2.total_anomalies)
    * [max\_severity](#src.analysis.forensic_engine.SecurityIncidentV2.max_severity)
    * [primary\_culprit](#src.analysis.forensic_engine.SecurityIncidentV2.primary_culprit)
    * [top\_3\_ports](#src.analysis.forensic_engine.SecurityIncidentV2.top_3_ports)
    * [persistence\_label](#src.analysis.forensic_engine.SecurityIncidentV2.persistence_label)
    * [consensus\_confidence](#src.analysis.forensic_engine.SecurityIncidentV2.consensus_confidence)
    * [dynamic\_severity\_score](#src.analysis.forensic_engine.SecurityIncidentV2.dynamic_severity_score)
  * [HiGIForensicEngine](#src.analysis.forensic_engine.HiGIForensicEngine)
    * [\_\_init\_\_](#src.analysis.forensic_engine.HiGIForensicEngine.__init__)
    * [cluster\_incidents](#src.analysis.forensic_engine.HiGIForensicEngine.cluster_incidents)
    * [detect\_data\_drops](#src.analysis.forensic_engine.HiGIForensicEngine.detect_data_drops)
    * [get\_reportable\_incidents](#src.analysis.forensic_engine.HiGIForensicEngine.get_reportable_incidents)
    * [generate\_summary\_stats](#src.analysis.forensic_engine.HiGIForensicEngine.generate_summary_stats)
    * [get\_runtime\_settings](#src.analysis.forensic_engine.HiGIForensicEngine.get_runtime_settings)
    * [get\_threat\_distribution](#src.analysis.forensic_engine.HiGIForensicEngine.get_threat_distribution)
    * [generate\_visuals](#src.analysis.forensic_engine.HiGIForensicEngine.generate_visuals)
    * [generate\_report](#src.analysis.forensic_engine.HiGIForensicEngine.generate_report)
  * [generate\_markdown\_report](#src.analysis.forensic_engine.generate_markdown_report)
  * [generate\_forensic\_pdf](#src.analysis.forensic_engine.generate_forensic_pdf)

<a id="src.analysis.forensic_engine"></a>

# src.analysis.forensic\_engine

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

<a id="src.analysis.forensic_engine.TierEvidenceSummary"></a>

## TierEvidenceSummary Objects

```python
@dataclass
class TierEvidenceSummary()
```

Compressed evidence record summarizing a single detection tier's behavior within an incident.

Each of the four detection tiers (BallTree, GMM/IForest, Physical Sentinel, Velocity Bypass)
operates independently on the telemetry stream. This dataclass summarizes the aggregate
firing pattern for one tier across all windows in an incident, used to compute the
Consensus Confidence Index.

**Attributes**:

- `tier_name` _str_ - Human-readable detection tier identifier.
  One of: 'BallTree', 'GMM', 'IForest', 'PhysicalSentinel', 'VelocityBypass'.
- `fired` _bool_ - True if this tier triggered (fired) at least once during the incident.
- `fire_count` _int_ - Total number of windows (temporal bins) in which this tier
  raised an anomaly alert during the incident window.
- `mean_score` _float_ - Mean detection score across all windows in the incident.
  Score units are tier-specific (e.g., Euclidean distance for BallTree,
  log-likelihood for GMM, anomaly score [0-1] for IForest).

<a id="src.analysis.forensic_engine.FeatureAttribution"></a>

## FeatureAttribution Objects

```python
@dataclass
class FeatureAttribution()
```

Top contributing physical feature identified via Blocked-PCA analysis (XAI module).

The HiGI explainability system identifies the culprit feature (the physical metric
whose anomalous behavior best explains the Hilbert-space deviation) for each incident.
FeatureAttribution records the top-3 culprit features, ranked by their loading magnitude
in the principal component space.

**Attributes**:

- `feature_name` _str_ - Canonical metric identifier (e.g., 'flag_syn_ratio', 'bytes_total').
- `loading_magnitude` _float_ - Normalized contribution coefficient in [0, 1].
  Derived from Blocked-PCA loadings, or from normalized |σ| if loadings unavailable.
  Higher values indicate stronger alignment with anomalous principal components.
- `event_type` _str_ - Directionality of anomaly: 'SPIKE' (positive) or 'DROP' (negative).
- `max_sigma` _float_ - Maximum standard deviation distance (σ) in the Hilbert-space
  inertial reference frame observed for this feature within the incident.
- `max_pct` _float_ - Dimensionless maximum percentage deviation (e.g., 865.0 for +865%).
  Used for analyst-friendly severity interpretation.
- `family` _str_ - Physical feature family category:
  'volume', 'payload', 'flags', 'protocol', 'connection', 'kinematics', or 'unknown'.

<a id="src.analysis.forensic_engine.SecurityIncidentV2"></a>

## SecurityIncidentV2 Objects

```python
@dataclass
class SecurityIncidentV2()
```

A clustered security incident with V2 enriched metadata and XAI attribution.

SecurityIncidentV2 represents a contiguous temporal cluster of anomalies detected
by the HiGI IDS. The incident is enriched with Blocked-PCA family attribution,
consensus-weighted confidence scoring, and MITRE ATT&CK technique mapping.

An incident spans from the first anomalous window to the last window before
exceeding the debounce threshold, and contains at least one detection from the
Multi-tier Tribunal (BallTree, GMM/IForest, Physical Sentinel, or Velocity Bypass).

**Attributes**:

- `incident_id` _int_ - Sequential identifier (0-based) within the forensic engine session.
- `start_time` _datetime_ - Timezone-aware or naive datetime of the first anomalous window.
- `end_time` _datetime_ - Datetime of the last anomalous window in the incident cluster.
- `anomaly_rows` _pd.DataFrame_ - Slice of the results DataFrame containing all rows
  (with is_anomaly=1 or soft_zone=True) belonging to this incident.
- `tier_evidence` _List[TierEvidenceSummary]_ - Summary of which detection tiers fired.
  Used to compute the Consensus Confidence Index.
- `top_features` _List[FeatureAttribution]_ - Top-3 culprit features (XAI module),
  ranked by Blocked-PCA loading magnitude. Identifies which physical metrics
  best explain the Hilbert-space deviation.
- `family_stress` _Dict[str, float]_ - Mapping of physical family → normalized stress
  score in [0, 1]. Stress represents each family's contribution to total anomaly load.
- `mitre_tactics` _Dict[str, List[str]]_ - MITRE ATT&CK mapping: tactic → list of
  technique identifiers relevant to the incident's culprit metrics.
- `is_warmup` _bool_ - True if > 50% of anomaly_rows are labeled is_warmup=1.
  Warmup incidents receive 50% confidence penalty to reduce false positives.

<a id="src.analysis.forensic_engine.SecurityIncidentV2.duration_seconds"></a>

#### duration\_seconds

```python
@property
def duration_seconds() -> float
```

Wall-clock duration of the incident in seconds (temporal magnitude).

**Returns**:

- `float` - Elapsed time between first and last anomalous window, in seconds.

<a id="src.analysis.forensic_engine.SecurityIncidentV2.total_anomalies"></a>

#### total\_anomalies

```python
@property
def total_anomalies() -> int
```

Total count of anomalous windows (temporal bins) in the incident.

**Returns**:

- `int` - Number of rows in anomaly_rows (volume metric).

<a id="src.analysis.forensic_engine.SecurityIncidentV2.max_severity"></a>

#### max\_severity

```python
@property
def max_severity() -> int
```

Maximum discrete severity label observed within the incident (1–3).

Severity tiers:
1: Low — single-tier detection.
2: High — majority consensus (≥2 tiers agreed).
3: Critical — full unanimity (all tiers fired).

**Returns**:

- `int` - Maximum severity in [1, 3], or 0 if anomaly_rows is empty.

<a id="src.analysis.forensic_engine.SecurityIncidentV2.primary_culprit"></a>

#### primary\_culprit

```python
@property
def primary_culprit() -> str
```

Most frequently reported physical culprit metric (feature family attribute).

Identifies the single most common anomalous physical metric across all windows
in the incident, providing a quick summary of the dominant attack vector.

**Returns**:

- `str` - Canonical metric name (e.g., 'flag_syn_ratio'), or 'Unknown'.

<a id="src.analysis.forensic_engine.SecurityIncidentV2.top_3_ports"></a>

#### top\_3\_ports

```python
@property
def top_3_ports() -> List[int]
```

Top-3 destination ports by detection frequency (network topology).

**Returns**:

- `List[int]` - Up to 3 port numbers ranked by occurrence count. Empty if
  server_port column unavailable.

<a id="src.analysis.forensic_engine.SecurityIncidentV2.persistence_label"></a>

#### persistence\_label

```python
@property
def persistence_label() -> str
```

Most common persistence classification within the incident.

Persistence label categorizes the temporal pattern of anomalies (e.g., transient,
recurring, sustained) based on the anomaly_rows temporal structure.

**Returns**:

- `str` - Persistence category identifier, or 'Unknown' if unavailable.

<a id="src.analysis.forensic_engine.SecurityIncidentV2.consensus_confidence"></a>

#### consensus\_confidence

```python
@property
def consensus_confidence() -> float
```

Tier-weighted consensus confidence index for the incident (XAI metric).

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

**Returns**:

- `float` - Confidence probability in [0.0, 1.0]. Ranges:
  < 0.40: Low confidence (likely noise or detector miscalibration).
- `0.40–0.70` - Medium confidence (recommend manual review).
  > 0.70: High confidence (strong multi-tier agreement).

<a id="src.analysis.forensic_engine.SecurityIncidentV2.dynamic_severity_score"></a>

#### dynamic\_severity\_score

```python
@property
def dynamic_severity_score() -> float
```

Euclidean-distance-inspired severity index on continuous [0, ∞) scale.

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

**Returns**:

- `float` - Continuous severity score. Typical range [0.0, ~12.0].

<a id="src.analysis.forensic_engine.HiGIForensicEngine"></a>

## HiGIForensicEngine Objects

```python
class HiGIForensicEngine()
```

Forensic analysis engine for HiGI IDS V4.0 Blocked-PCA telemetry (XAI module).

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

**Attributes**:

- `csv_path` _Path_ - Absolute path to the HiGI results CSV file.
- `config` _Dict[str, Any]_ - Runtime configuration mapping thresholds and parameters.
- `df` _pd.DataFrame_ - Full results DataFrame (all rows, both anomalies and baseline).
- `df_anomalies` _pd.DataFrame_ - Filtered subset containing anomalous or soft-zone rows.
- `incidents` _List[SecurityIncidentV2]_ - Clustered incident objects after clustering.
- `data_drops` _List[Dict[str, Any]]_ - Detected telemetry gaps / data-drop events.

<a id="src.analysis.forensic_engine.HiGIForensicEngine.__init__"></a>

#### \_\_init\_\_

```python
def __init__(settings: Any,
             results_path: str,
             bundle: Optional[Any] = None) -> None
```

Initialize the HiGI Forensic Engine and load telemetry results.

Constructs the engine instance, loads the results CSV, validates required
columns, builds the timeline (dt), and prepares the anomaly subset. All
thresholds and parameters are read from the settings object (mirrors config.yaml).

**Arguments**:

- `settings` _Any_ - Configuration object with nested structure:
- `settings.forensic.debounce_seconds` _float_ - Maximum temporal gap
  (in seconds) between consecutive anomalies before starting a new
  incident cluster. Typical range: 30–120 seconds.
- `settings.forensic.data_drop_threshold_seconds` _float_ - Minimum gap
  (in seconds) to flag as a telemetry data-drop event. Typical: 300–600 s.
- `settings.forensic.default_confidence_filter` _float_ - Minimum
  consensus_confidence [0, 1] for an incident to appear in the report.
- `settings.forensic.default_min_anomalies` _int_ - Minimum anomaly count
  per incident (volume filter). Typical: 2–5.
- `settings.forensic.default_min_duration_seconds` _float_ - Minimum incident
  duration in seconds (temporal filter).
- `settings.forensic.sigma_culprit_min` _float_ - Incidents whose mean |σ|
  (Hilbert-space deviation) falls below this value are suppressed
  from the report (statistical quality filter).
- `results_path` _str_ - Absolute path to the HiGI results CSV file, typically
  produced by src/orchestrator.py. Expected columns:
  - dt or _abs_timestamp: Temporal index (datetime or Epoch seconds).
  - is_anomaly: Binary flag (0/1) for anomaly windows.
  - severity: Discrete severity (1=Low, 2=High, 3=Critical).
  - consensus_votes: Number of tiers that fired.
  - physical_culprit: Blocked-PCA culprit metric annotation.
  - family_consensus: Physical family from BlockedPCA (optional).
  - culprit_deviation: |σ| value (Hilbert-space deviation).
  - Other tier-specific columns (balltree_severity, gmm_anomaly, etc.).
- `bundle` _Optional[Any]_ - Optional BlockedPCA metadata bundle (pickle object)
  containing _blocked_pca_family_mapping and _blocked_pca_loadings_by_family.
  If provided, enables full PCA-aware feature attribution. Falls back to
  CSV column parsing if None.
  

**Raises**:

- `FileNotFoundError` - If results_path does not exist.
- `ValueError` - If DataFrame is empty or missing critical columns
  (_abs_timestamp or dt, is_anomaly, severity, consensus_votes).
  
  Side effects:
  - Loads and sorts DataFrame by timestamp.
  - Forward-fills isolated NaT entries to preserve burst continuity.
  - Filters anomaly subset (df_anomalies) for subsequent clustering.

<a id="src.analysis.forensic_engine.HiGIForensicEngine.cluster_incidents"></a>

#### cluster\_incidents

```python
def cluster_incidents() -> List[SecurityIncidentV2]
```

Cluster consecutive anomaly windows into SecurityIncidentV2 incidents (temporal grouping).

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

**Returns**:

- `List[SecurityIncidentV2]` - Ordered list of clustered incidents, sorted by start_time.
  Returns empty list if df_anomalies has no rows. Each SecurityIncidentV2 is
  fully enriched with XAI and metadata.
  

**Raises**:

  None explicitly, but logs warnings for edge cases.
  

**Example**:

  >>> engine = HiGIForensicEngine(...)
  >>> engine.cluster_incidents()  # Returns ~10-50 incidents
  >>> incidents = engine.incidents
  >>> for inc in incidents:
  ...     print(f"Incident {inc.incident_id}: {inc.duration_seconds:.0f}s, "
  ...           f"severity={inc.max_severity}, confidence={inc.consensus_confidence:.2%}")

<a id="src.analysis.forensic_engine.HiGIForensicEngine.detect_data_drops"></a>

#### detect\_data\_drops

```python
def detect_data_drops() -> List[Dict[str, Any]]
```

Detect telemetry gaps in the full capture timeline (sensor saturation forensics).

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

**Arguments**:

  None. Uses self.df (full DataFrame), self.incidents (clustered incidents),
  and self.config['data_drop_threshold_seconds'].
  

**Returns**:

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
  

**Example**:

  >>> engine.cluster_incidents()
  >>> drops = engine.detect_data_drops()
  >>> for drop in drops:
  ...     print(f"Gap {drop['gap_seconds']:.0f}s at {drop['start_time']}: {drop['reason']}")
  Gap 120s at 2024-01-15 10:45:30: [POSSIBLE_SENSOR_SATURATION]
  

**Notes**:

  - Sensor Saturation is a critical indicator of DoS/DDoS success.
  - Gaps adjacent to multiple incidents are classified by the most recent incident.
  - This method should be called after cluster_incidents() to populate self.incidents.

<a id="src.analysis.forensic_engine.HiGIForensicEngine.get_reportable_incidents"></a>

#### get\_reportable\_incidents

```python
def get_reportable_incidents(**kwargs: Any) -> List[SecurityIncidentV2]
```

Return incidents meeting all reporting quality thresholds (multi-filter scoring).

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

**Arguments**:

- `**kwargs` _Any_ - Optional threshold overrides (all optional, use config defaults
  if not provided):
  - confidence_filter (float ∈ [0, 1]): Consensus confidence minimum threshold.
  - min_anomalies_per_incident (int): Minimum anomaly window count per incident.
  - min_duration_seconds (float): Minimum sustained anomaly duration in seconds.
  - sigma_culprit_min (float): Minimum mean |σ| (Hilbert-space deviation).
  

**Returns**:

- `List[SecurityIncidentV2]` - Sorted list of filtered incidents. Returns empty list
  if no incidents pass all filters. Each incident retains all XAI metadata
  (culprit features, family stress, MITRE mappings).
  

**Example**:

  >>> engine.cluster_incidents()
  >>> reportable = engine.get_reportable_incidents(
  ...     confidence_filter=0.50,
  ...     min_anomalies_per_incident=3
  ... )
  >>> print(f"High-confidence incidents: {len(reportable)}")

<a id="src.analysis.forensic_engine.HiGIForensicEngine.generate_summary_stats"></a>

#### generate\_summary\_stats

```python
def generate_summary_stats(**kwargs: Any) -> Dict[str, Any]
```

Compute executive-level summary statistics for report generation.

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

**Arguments**:

- `**kwargs` _Any_ - Optional filter overrides (passed to get_reportable_incidents()).
  If kwargs are provided, statistics are computed on the filtered subset only.
  If empty, statistics use self.incidents (all raw clustered incidents).
  

**Returns**:

  Dict[str, Any]: Dictionary with keys:
  - total_anomalies (int): Volume of anomalous windows.
  - total_incidents (int): Count of incidents after filtering (if kwargs).
  - avg_incident_duration (float): Mean incident duration in seconds.
  - max_severity (int): Peak severity (1-3) or 0 if no anomalies.
  - avg_severity (float): Mean severity of anomalous rows [1, 3].
  - time_range_start (pd.Timestamp): First row timestamp.
  - time_range_end (pd.Timestamp): Last row timestamp.
  - data_drops_detected (int): Count of sensor saturation/capture loss events.
  

**Example**:

  >>> engine.cluster_incidents()
  >>> engine.detect_data_drops()
  >>> stats = engine.generate_summary_stats(confidence_filter=0.50)
  >>> print(f"High-confidence incidents: {stats['total_incidents']}, "
  ...       f"avg_duration: {stats['avg_incident_duration']:.0f}s")

<a id="src.analysis.forensic_engine.HiGIForensicEngine.get_runtime_settings"></a>

#### get\_runtime\_settings

```python
def get_runtime_settings() -> Dict[str, Any]
```

Return a deep copy of the engine configuration dictionary (auditability + transparency).

This method exposes the current runtime configuration for logging, auditability,
and report generation. Useful for verifying which filters and thresholds were
applied to a particular analysis run.

**Returns**:

  Dict[str, Any]: Copy of self.config containing all forensic.* settings from
  config.yaml / settings object (debounce_seconds, data_drop_threshold_seconds,
  confidence_filter, min_anomalies_per_incident, min_duration_seconds,
  sigma_culprit_min, etc.). Modifications to returned dict do not affect engine.
  

**Example**:

  >>> engine = HiGIForensicEngine(...)
  >>> cfg = engine.get_runtime_settings()
  >>> print(f"Confidence filter: {cfg['confidence_filter']}")

<a id="src.analysis.forensic_engine.HiGIForensicEngine.get_threat_distribution"></a>

#### get\_threat\_distribution

```python
def get_threat_distribution() -> pd.Series
```

Return value-counts of base culprit metric names for the threat pie.

<a id="src.analysis.forensic_engine.HiGIForensicEngine.generate_visuals"></a>

#### generate\_visuals

```python
def generate_visuals(output_dir: Path,
                     stem: Optional[str] = None,
                     **filter_kwargs: Any) -> Dict[str, str]
```

Generate and save the two executive visualisations.

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

**Arguments**:

- `output_dir` - Directory where PNG files are written.
- `stem` - Optional filename stem derived from the CSV name.
  Defaults to ``self.csv_path.stem``.
- `**filter_kwargs` - Threshold overrides (confidence_filter,
  min_anomalies_per_incident, min_duration_seconds,
  sigma_culprit_min).  Forwarded to get_reportable_incidents().
  

**Returns**:

  Dictionary with keys ``"timeline_plot"`` and
  ``"radar_plot"`` containing the relative file-names
  (suitable for embedding in Markdown ``![alt](path)``).

<a id="src.analysis.forensic_engine.HiGIForensicEngine.generate_report"></a>

#### generate\_report

```python
def generate_report(output_dir: Optional[str] = None,
                    visual_paths: Optional[Dict[str, str]] = None,
                    **filter_kwargs: Any) -> str
```

Generate the Markdown executive report (main public entry point for reporting pipeline).

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

**Arguments**:

- `output_dir` _Optional[str]_ - Directory for report + PNG files. Defaults to
  {csv_parent}/reports/ (e.g., data/processed/../reports/).
  Creates directory if not present.
- `visual_paths` _Optional[Dict[str, str]]_ - Pre-computed plot paths (skips PNG
  generation when provided, useful for testing or external visualization).
- `Keys` - 'timeline', 'family_radar'; Values: relative or absolute paths.
- `**filter_kwargs` _Any_ - Threshold overrides forwarded to get_reportable_incidents().
  Common filters:
  - confidence_filter (float): Consensus confidence minimum [0, 1]
  - min_anomalies_per_incident (int): Minimum anomaly window count
  - min_duration_seconds (float): Minimum incident duration
  

**Returns**:

- `str` - Absolute path of the written Markdown file (e.g.,
  /home/.../data/processed/results_FORENSIC.md).
  

**Raises**:

  None explicitly. Logs warnings if visualization generation fails.
  
  Side effects:
  - Creates output_dir if not present.
  - Calls cluster_incidents() and detect_data_drops() if not pre-populated.
  - Writes PNG files to output_dir (via generate_visuals).
  - Writes Markdown .md file to output_dir.
  

**Example**:

  >>> engine = HiGIForensicEngine(...)
  >>> engine.cluster_incidents()
  >>> md_path = engine.generate_report(
  ...     output_dir="reports",
  ...     confidence_filter=0.50
  ... )
  >>> print(f"Report saved: {md_path}")

<a id="src.analysis.forensic_engine.generate_markdown_report"></a>

#### generate\_markdown\_report

```python
def generate_markdown_report(engine: HiGIForensicEngine,
                             output_path: str,
                             visual_paths: Optional[Dict[str, str]] = None,
                             **filter_kwargs: Any) -> None
```

Write the Markdown forensic report to ``output_path``.

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

**Arguments**:

- `engine` - Initialised and clustered ``HiGIForensicEngine`` instance.
- `output_path` - Destination path for the Markdown file.
- `visual_paths` - Optional pre-computed plot paths.  If provided,
  skip plot generation entirely (useful for testing).
- `**filter_kwargs` - Threshold overrides (confidence_filter,
  min_anomalies_per_incident, min_duration_seconds,
  sigma_culprit_min) forwarded to both plot generation and
  the Markdown renderer.

<a id="src.analysis.forensic_engine.generate_forensic_pdf"></a>

#### generate\_forensic\_pdf

```python
def generate_forensic_pdf(engine: HiGIForensicEngine,
                          output_path: str,
                          organization: str = "HiGI Security Operations",
                          **filter_kwargs: Any) -> None
```

Generate a PDF forensic report (delegates to ReportLab).

Replicates the V1 signature so ``main.py`` requires no changes.  If
ReportLab is not installed the function logs a warning and returns
gracefully instead of raising.

**Arguments**:

- `engine` - Initialised and clustered ``HiGIForensicEngine``.
- `output_path` - Destination path for the PDF file.
- `organization` - Organisation name rendered in the report header.
- `**filter_kwargs` - Threshold overrides forwarded to the engine.

