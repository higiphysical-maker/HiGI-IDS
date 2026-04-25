<a id="src.models.higi_engine"></a>

# src.models.higi\_engine

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

<a id="src.models.higi_engine.HiGIError"></a>

## HiGIError Objects

```python
class HiGIError(Exception)
```

Base exception for HiGI engine errors.

<a id="src.models.higi_engine.HiGITrainingError"></a>

## HiGITrainingError Objects

```python
class HiGITrainingError(HiGIError)
```

Raised when training fails.

<a id="src.models.higi_engine.HiGIInferenceError"></a>

## HiGIInferenceError Objects

```python
class HiGIInferenceError(HiGIError)
```

Raised when inference fails.

<a id="src.models.higi_engine.InsufficientDataError"></a>

## InsufficientDataError Objects

```python
class InsufficientDataError(HiGIError)
```

Raised when training data is insufficient.

<a id="src.models.higi_engine.HiGIConfig"></a>

## HiGIConfig Objects

```python
@dataclass(frozen=True)
class HiGIConfig()
```

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

<a id="src.models.higi_engine.HiGIConfig.__post_init__"></a>

#### \_\_post\_init\_\_

```python
def __post_init__() -> None
```

Derive default tribunal weights when not explicitly supplied.

<a id="src.models.higi_engine.HiGIConfig.to_dict"></a>

#### to\_dict

```python
def to_dict() -> Dict[str, Any]
```

Serialise to plain dict for logging / persistence.

<a id="src.models.higi_engine.HilbertSpaceProjector"></a>

## HilbertSpaceProjector Objects

```python
class HilbertSpaceProjector()
```

Project raw feature matrix into Hilbert space via Yeo-Johnson + PCA.

Velocity features (vel_pps_z, vel_bytes_z, vel_syn_z) are treated as
first-class dimensions.  Because they are already Z-scores their
distribution is near-normal during baseline, so they enrich the Hilbert
space without distorting PCA variance ratios significantly.  The
VelocityBypassDetector operates on raw Z-score values BEFORE projection,
making the two mechanisms complementary.

<a id="src.models.higi_engine.HilbertSpaceProjector.fit"></a>

#### fit

```python
def fit(df: pd.DataFrame,
        variance_target: float = PCA_VARIANCE_TARGET,
        exclude_cols: Optional[set] = None) -> "HilbertSpaceProjector"
```

Fit Yeo-Johnson + PCA on the baseline feature matrix.

**Arguments**:

- `df` - Baseline feature matrix (n_samples × n_features).
- `variance_target` - PCA cumulative variance to retain [0.85, 0.99].
- `exclude_cols` - Metadata column names to exclude.
  

**Returns**:

  self — for method chaining.
  

**Raises**:

- `ValueError` - Fewer than 100 samples or no numeric features.

<a id="src.models.higi_engine.HilbertSpaceProjector.transform"></a>

#### transform

```python
def transform(df: pd.DataFrame) -> np.ndarray
```

Project a test DataFrame into the fitted Hilbert space.

**Arguments**:

- `df` - Test feature matrix.
  

**Returns**:

- `np.ndarray` - Hilbert coordinates, shape (n_samples, n_components).
  

**Raises**:

- `ValueError` - Projector not fitted.

<a id="src.models.higi_engine.HilbertSpaceProjector.fit_transform"></a>

#### fit\_transform

```python
def fit_transform(df: pd.DataFrame,
                  variance_target: float = PCA_VARIANCE_TARGET) -> np.ndarray
```

Fit and transform in a single call.

<a id="src.models.higi_engine.HilbertSpaceProjector.get_pc_loadings"></a>

#### get\_pc\_loadings

```python
def get_pc_loadings() -> pd.DataFrame
```

Return PCA loadings as (n_features × n_components) DataFrame.

<a id="src.models.higi_engine.HilbertSpaceProjector.get_culprit_component"></a>

#### get\_culprit\_component

```python
def get_culprit_component(X_hilbert: np.ndarray,
                          sample_idx: int) -> Dict[str, Any]
```

Identify the PC with maximum absolute coordinate for one sample.

<a id="src.models.higi_engine.HilbertSpaceProjector.get_suspect_features"></a>

#### get\_suspect\_features

```python
def get_suspect_features(culprit_pc_idx: int, top_n: int = 3) -> List[str]
```

Return top-N features contributing to a Principal Component.

<a id="src.models.higi_engine.BallTreeDetector"></a>

## BallTreeDetector Objects

```python
class BallTreeDetector()
```

k-NN Euclidean distance detector (k=5 mean) in Hilbert space.

FIX-1 (v3.0): score() returns raw_distance / training_p99_distance,
making scores batch-independent.  A score of 1.0 equals the training P99
boundary; scores above 1.0 indicate increasing isolation from the baseline.

<a id="src.models.higi_engine.BallTreeDetector.fit"></a>

#### fit

```python
def fit(X_hilbert: np.ndarray,
        percentiles: Optional[Dict[str, float]] = None) -> "BallTreeDetector"
```

Fit BallTree on baseline Hilbert coordinates.

**Arguments**:

- `X_hilbert` - Baseline data, shape (n_samples, n_components).
- `percentiles` - Threshold percentile dict {p95, p99, p99_9}.
  

**Returns**:

  self

<a id="src.models.higi_engine.BallTreeDetector.score"></a>

#### score

```python
def score(X_hilbert: np.ndarray) -> np.ndarray
```

Absolute anomaly score = mean_k5_distance / training_p99_distance.

**Returns**:

- `np.ndarray` - Shape (n_samples,). Values > 1.0 exceed training P99.

<a id="src.models.higi_engine.BallTreeDetector.predict"></a>

#### predict

```python
def predict(X_hilbert: np.ndarray, severity: str = "p95") -> np.ndarray
```

Binary prediction at the specified threshold tier.

<a id="src.models.higi_engine.BallTreeDetector.get_severity"></a>

#### get\_severity

```python
def get_severity(X_hilbert: np.ndarray, slack: float = 1.0) -> np.ndarray
```

Map absolute scores to tiered severity (float32 preserves 0.5 soft-zone).

**Returns**:

- `np.ndarray` - Values in {0, 0.5, 1, 2, 3}, dtype float32.

<a id="src.models.higi_engine.GMMDetector"></a>

## GMMDetector Objects

```python
class GMMDetector()
```

Log-Likelihood anomaly detection via Gaussian Mixture Model.

<a id="src.models.higi_engine.GMMDetector.fit"></a>

#### fit

```python
def fit(X_hilbert: np.ndarray,
        n_components: int = 5,
        percentile: float = PERCENTILE_THRESHOLD,
        reg_covar: float = 1e-3) -> "GMMDetector"
```

Fit GMM on Hilbert space baseline.

<a id="src.models.higi_engine.GMMDetector.score"></a>

#### score

```python
def score(X_hilbert: np.ndarray) -> np.ndarray
```

Inverted log-likelihood (higher = more anomalous).

<a id="src.models.higi_engine.GMMDetector.predict"></a>

#### predict

```python
def predict(X_hilbert: np.ndarray) -> np.ndarray
```

Binary anomaly flag.

<a id="src.models.higi_engine.IForestDetector"></a>

## IForestDetector Objects

```python
class IForestDetector()
```

Structural anomaly detection via Isolation Forest.

<a id="src.models.higi_engine.IForestDetector.fit"></a>

#### fit

```python
def fit(X_hilbert: np.ndarray,
        contamination: float = 0.01) -> "IForestDetector"
```

Fit Isolation Forest on Hilbert space baseline.

<a id="src.models.higi_engine.IForestDetector.score"></a>

#### score

```python
def score(X_hilbert: np.ndarray) -> np.ndarray
```

Inverted isolation score (higher = more anomalous).

<a id="src.models.higi_engine.IForestDetector.predict"></a>

#### predict

```python
def predict(X_hilbert: np.ndarray) -> np.ndarray
```

Binary anomaly flag.

<a id="src.models.higi_engine.VelocityBypassDetector"></a>

## VelocityBypassDetector Objects

```python
class VelocityBypassDetector()
```

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

<a id="src.models.higi_engine.VelocityBypassDetector.compute"></a>

#### compute

```python
@staticmethod
def compute(
    df_test: pd.DataFrame,
    bypass_threshold: float = 5.0
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]
```

Compute velocity bypass signals for all samples in one vectorised pass.

**Arguments**:

- `df_test` - Test DataFrame containing vel_pps_z, vel_bytes_z, vel_syn_z.
- `bypass_threshold` - Z-score magnitude that triggers the bypass gate.
  

**Returns**:

  Tuple of four np.ndarrays, all shape (n_samples,):
  vel_scores      — continuous score in [0, 3.0] for Tribunal.
  bypass_mask     — bool, True where emergency bypass fires.
  bypass_severity — int, HiGI severity level (0 if no bypass).
  vel_culprit     — object array of strings, e.g.
  "vel_pps_z(z=+9.43)" or "" for non-bypass.

<a id="src.models.higi_engine.HiGIEngine"></a>

## HiGIEngine Objects

```python
class HiGIEngine()
```

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

<a id="src.models.higi_engine.HiGIEngine.train"></a>

#### train

```python
def train(df_baseline: pd.DataFrame,
          n_jobs: Optional[int] = None) -> "HiGIEngine"
```

Train HiGI on baseline (normal) traffic data.

Velocity features are included in the Hilbert space PCA and in the
univariate GMMs when present.  During normal Monday traffic their
values cluster near 0 (stable regime), so the BallTree's training P99
in the velocity dimensions is small — making DoS-onset vel_pps_z > 8
correctly anomalous even in Hilbert space.

VelocityBypassDetector requires no training.

**Arguments**:

- `df_baseline` - Normal traffic feature matrix (n_samples ≥ 100).
- `n_jobs` - CPU cores; overrides self.n_jobs when provided.
  

**Returns**:

  self — for method chaining.
  

**Raises**:

- `InsufficientDataError` - Fewer than 100 baseline samples.
- `HiGITrainingError` - Any detector fails to fit.

<a id="src.models.higi_engine.HiGIEngine.analyze"></a>

#### analyze

```python
def analyze(df_test: pd.DataFrame,
            n_jobs: Optional[int] = None) -> pd.DataFrame
```

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

**Arguments**:

- `df_test` - Test feature matrix. vel_* features are optional but
  required for Tier 4 to be active.
- `n_jobs` - CPU cores override.
  

**Returns**:

  pd.DataFrame with all v3.0 columns plus vel_score, vel_bypass,
  vel_culprit.

<a id="src.models.higi_engine.HiGIEngine.save"></a>

#### save

```python
def save(path: str) -> None
```

Persist engine state to disk as a joblib file.

VelocityBypassDetector has no learned state and is not persisted;
it is reconstructed from HiGIConfig on the next load.

**Arguments**:

- `path` - Output file path (e.g. 'models/higi_v4.pkl').

<a id="src.models.higi_engine.HiGIEngine.load"></a>

#### load

```python
@staticmethod
def load(path: str) -> "HiGIEngine"
```

Load engine from disk with full backward compatibility.

Supported bundle formats:
1. Direct HiGIEngine instance (orchestrator ArtifactBundle).
2. State dict from save().
3. HiGIEngine inside a dict wrapper.
4. State dict inside a dict wrapper (legacy).

Backward compatibility:
v3.0 bundles lack velocity config fields — HiGIConfig defaults apply.
v2.x bundles lack training_p99_distance — _patch_v3_balltree() derives it.
Missing vel_* features at inference time degrade gracefully to zeros.

**Arguments**:

- `path` - File path (.pkl or .joblib).
  

**Returns**:

  HiGIEngine ready for inference.
  

**Raises**:

- `FileNotFoundError` - Path does not exist.
- `ValueError` - Cannot extract valid engine from file.

