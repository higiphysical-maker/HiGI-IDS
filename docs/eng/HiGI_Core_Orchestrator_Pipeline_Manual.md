# HiGI IDS — Core: Orchestrator & Execution Pipeline Manual

**Version:** 4.0.0 · **Modules:** [`src/orchestrator.py`](/src/orchestrator.py) · [`main.py`](/main.py)  
**Classification:** Internal Technical Documentation — Blue Team Engineering  
**Ecosystem:** HiGI IDS v4.0 · **Reference Format:** IEEE / Clean Code / PEP 8

---

## Table of Contents

1. [Architectural Overview](#1-architectural-overview)
2. [The ArtifactBundle: Immutable Ground Truth](#2-the-artifactbundle-immutable-ground-truth)
3. [The Execution Lifecycle](#3-the-execution-lifecycle)
4. [CLI Reference — `main.py`](#4-cli-reference--mainpy)
5. [Error Handling and Resilience](#5-error-handling-and-resilience)
6. [Configuration Contract: ModelConfig vs. RuntimeConfig](#6-configuration-contract-modelconfig-vs-runtimeconfig)
7. [Technical Disclaimer: The Hilbert Space](#7-technical-disclaimer-the-hilbert-space)
8. [Glossary](#8-glossary)

---

## 1. Architectural Overview

### 1.1 The Orchestrator as the Loom of Forensic Evidence

The term *orchestrator* is deliberately evocative. A standard pipeline runner executes steps sequentially and discards intermediate state. The HiGI Orchestrator does something fundamentally different: it **preserves and propagates epistemic context** across every phase of the detection lifecycle. The `TrainingPipeline` does not merely fit a model — it constructs a geometrically coherent inertial reference frame and encapsulates it in an `ArtifactBundle`. The `DetectionPipeline` does not merely score samples — it enforces a strict mathematical contract that the test data be evaluated against exactly the same geometric space in which the baseline was defined.

This distinction is not stylistic. It is the architectural guarantee that makes HiGI's detections physically interpretable rather than statistically opaque.

### 1.2 The Three-Engine Architecture

`src/orchestrator.py` is the integration layer that coordinates three independent engines, each with a well-defined and non-overlapping responsibility:

```
                          ┌─────────────────────────────────┐
                          │         HiGISettings            │
                          │    (config.yaml → dataclass)    │
                          └────────────┬────────────────────┘
                                       │  injects into
              ┌────────────────────────┼────────────────────────┐
              │                        │                         │
              ▼                        ▼                         ▼
   ┌──────────────────┐   ┌────────────────────┐   ┌────────────────────────┐
   │  PcapProcessor   │   │    HiGIEngine       │   │  HiGIForensicEngine    │
   │  (Ingestion)     │   │  (Detection)        │   │  (Reporting)           │
   │                  │   │                     │   │                        │
   │ · tshark/scapy   │   │ · Tier 1: BallTree  │   │ · Incident clustering  │
   │ · parallel chunks│   │ · Tier 2A: GMM      │   │ · σ attribution        │
   │ · feature matrix │   │ · Tier 2B: IForest  │   │ · MITRE mapping        │
   │ · RobustScaler   │   │ · Tier 3: Sentinel  │   │ · PDF + Markdown       │
   │ · 1-second window│   │ · Tier 4: Velocity  │   │ · CCI computation      │
   └──────────────────┘   └────────────────────┘   └────────────────────────┘
              │                        │                         │
              └────────────────────────┼─────────────────────────┘
                                       │
                              ┌────────▼────────┐
                              │  ArtifactBundle  │
                              │  (.pkl + .json)  │
                              │                  │
                              │ engine           │
                              │ feature_cols     │
                              │ scaler           │
                              │ baseline_medians │
                              │ metadata         │
                              └─────────────────┘
```

**Critical design principle:** `HiGISettings` is the single source of truth (SSoT) for all configuration. No engine receives hardcoded parameters. Every threshold, weight, and window size is injected from the frozen dataclass hierarchy constructed by `load_settings()` from `config.yaml`. This is what the codebase means by *zero magic numbers*.

### 1.3 The Golden Rule of Inference

The entire detection contract is condensed in one invariant, documented explicitly in `DetectionPipeline.run()`:

> **GOLDEN RULE: This pipeline MUST use `.transform()` only. NO `.fit()` calls are permitted in detection mode.**

The geometric meaning is precise: during training, `RobustScaler` learns the median and interquartile range of the baseline traffic distribution. During detection, the same scaler is restored from the `ArtifactBundle` and applied to the test data with `.transform()` only — mapping test windows into the *same coordinate system* as the training baseline. Any call to `.fit()` in detection mode would redefine the coordinate origin using the test data itself, making anomaly detection mathematically self-referential and operationally meaningless.

This constraint is verified at every detection step. If the `ArtifactBundle` does not contain a trained `scaler`, the pipeline raises a `ValueError` and aborts rather than proceeding with an inconsistent scaling.

---

## 2. The ArtifactBundle: Immutable Ground Truth

### 2.1 Composition and Architecture

The `ArtifactBundle` is the physical artefact of a completed training session. It is an immutable container — once saved, it must not be modified. Any change to a structural parameter (e.g., feature schema, PCA variance target, number of GMM components) requires creating a new bundle from scratch.

| Field | Type | Content | Mutable? |
|-------|------|---------|----------|
| `engine` | `HiGIEngine` | Trained four-tier detection engine including internal `PowerTransformer`, `Blocked PCA`, `BallTree`, `BayesianGMM`, `IsolationForest`, and per-feature LL thresholds | ❌ Never |
| `feature_cols` | `list[str]` | Ordered list of feature column names — the schema contract between training and detection | ❌ Never |
| `scaler` | `RobustScaler` | Fitted baseline scaler for deterministic normalization during inference | ❌ Never |
| `baseline_medians` | `dict[str, float]` | Per-feature median values from training, used for safe imputation of missing protocol features in test PCAPs | ❌ Never |
| `metadata` | `dict` | Training provenance: date, source PCAP, window count, Phase 6 capabilities, Hilbert projection settings | ❌ Never |

### 2.2 The Matrioshka Escalado Fix (v4.0)

Earlier versions of the pipeline contained a critical architectural defect known internally as *Matrioshka Escalado* (nested scaling): the `RobustScaler` was applied twice — once by `PcapProcessor.get_standardized_matrix()` and once redundantly by the engine during feature projection. This double-scaling collapsed variance in the Hilbert space, producing systematically underestimated σ scores and missed detections.

v4.0 resolves this definitively:

1. `PcapProcessor.get_standardized_matrix()` applies `RobustScaler` and persists it to `models/scalers/robust_training_baseline.pkl`.
2. The orchestrator loads this exact scaler and injects it into the `ArtifactBundle`.
3. `HiGIEngine` owns all subsequent normalization internally (Yeo-Johnson `PowerTransformer` → Blocked PCA → whitening). It receives pre-scaled data and does not re-scale.
4. In detection, only `.transform()` is called on the restored scaler. No re-fitting at any stage.

The result is a clean, single-pass normalization chain: `RobustScaler` (orchestrator layer) → `PowerTransformer` (engine layer) → `Blocked PCA` (Hilbert projection layer).

### 2.3 Backward Compatibility

`ArtifactBundle.load()` handles bundles created before v4.0 gracefully:

```python
scaler=state.get("scaler", None)          # None for pre-v4 bundles
baseline_medians=state.get("baseline_medians", {})  # {} for pre-v4 bundles
```

If `scaler` is `None`, the detection pipeline raises a `ValueError` and refuses to proceed, requiring the user to retrain with the current codebase. This is the correct behavior: a bundle without a scaler cannot guarantee inference correctness.

### 2.4 The Metadata Sidecar

Every `.pkl` bundle is accompanied by a human-readable `.json` sidecar written by `bundle.save()`. This file contains the complete training provenance in plain text and is useful for quick inspection without loading the full binary:

```json
{
  "training_date": "2026-04-27T14:32:11.847221",
  "source_pcap": "data/raw/Monday.pcap",
  "pcap_packets": 2847293,
  "aggregated_windows": 29174,
  "feature_count": 42,
  "hilbert_projection": {
    "blocked_pca_enabled": true,
    "blocked_pca_families": ["volume", "payload", "flags", "protocol", "connection"]
  },
  "phase_6_features": {
    "bayesian_gmm": true,
    "cdf_normalization": true,
    "per_feature_sensitivity": true,
    "directionality_analysis": true
  }
}
```

---

## 3. The Execution Lifecycle

### 3.1 Phase Overview

The complete HiGI lifecycle comprises three sequential phases, each exposed as a separate CLI mode. Phases 1 and 2 are executed once per baseline; Phase 3 can be re-executed independently with varying filter parameters without rerunning inference.

```
PHASE 1: TRAINING          PHASE 2: DETECTION         PHASE 3: REPORTING
─────────────────────      ─────────────────────      ─────────────────────
 Benign PCAP               Test PCAP                  results CSV
     │                         │                           │
     ▼                         ▼                           ▼
 Ingestion               Bundle Loading             Incident Clustering
 (PcapProcessor)         (ArtifactBundle)           (debounce 30s)
     │                         │                           │
     ▼                         ▼                           ▼
 Feature Matrix          Runtime Config             Confidence Filter
 (1s windows, 42 feat.)  Injection (v4.0)           (CCI ≥ 0.80)
     │                         │                           │
     ▼                         ▼                           ▼
 Baseline Augmentation   Schema Alignment           σ Attribution
 (Gaussian, 10%, σ=5%)   (median imputation)        (culprit + family)
     │                         │                           │
     ▼                         ▼                           ▼
 RobustScaler fit        RobustScaler transform     MITRE Mapping
     │                   (GOLDEN RULE: no fit)           │
     ▼                         │                           ▼
 HiGIEngine.train()            ▼                    Visual Evidence
 (4 tiers, Phase 6)      HiGIEngine.analyze()       (timeline + radar)
     │                   (per-window scoring)            │
     ▼                         │                           ▼
 ArtifactBundle.save()         ▼                    PDF + Markdown
 (.pkl + .json)          results.csv + .json        Forensic Report
```

### 3.2 Phase 1 — Training: Establishing the Inertial Frame

**Entry point:** `TrainingPipeline.run()` → `main.py train`

The training phase constructs the geometric reference frame against which all future traffic will be evaluated. Its steps are strictly ordered:

**Step 1 — PCAP Ingestion.** `PcapProcessor` reads the baseline PCAP in parallel chunks of `ingestion.chunk_size` packets using `n_jobs` cores. Each chunk is processed with `tshark`/`scapy` to extract raw packet-level features (timestamps, IP headers, TCP flags, payload bytes). This step is I/O-bound and benefits linearly from additional cores up to the disk read bandwidth.

**Step 2 — Feature Aggregation.** `_build_base_matrix()` aggregates raw packets into 1-second time windows. Each window produces a 42-dimensional feature vector spanning the five physical families: Volume (PPS, bytes), Payload (continuity ratio, payload size), Flags (SYN/RST/FIN/URG/ACK ratios), Protocol (ICMP/TCP/UDP ratios), and Connection (unique destination IPs/ports, IAT statistics). The `time_interval: "1s"` in `config.yaml` is an **immutable structural parameter** — changing it invalidates the bundle.

**Step 3 — Baseline Augmentation.** To prevent the statistical model from overfitting to the specific traffic patterns of the training day (time-of-day periodicity, specific browsing sessions), the orchestrator applies controlled Gaussian noise to the feature matrix:

```
n_augmented = ⌊N_baseline × augmentation_synthetic_fraction⌋
noise ~ N(0, augmentation_noise_scale × σ_feature)
X_augmented[i] = X_baseline[random_i] + noise[i]
```

With the default settings (`noise_scale=0.05`, `synthetic_fraction=0.10`), 10% additional synthetic windows are generated with 5% feature-level noise. The RNG is seeded at 42 for reproducibility. This augmentation enlarges the effective support of the normal distribution, reducing the false positive rate when minor protocol variations occur in test traffic.

**Step 4 — HiGI Engine Training.** `HiGIEngine.train()` executes the complete four-tier training sequence:

| Tier | Component | Training Action |
|------|-----------|----------------|
| Tier 1 | BallTree | Builds k-d tree in Hilbert-projected space; computes P90/P95/P99/P99.9 distance percentiles on baseline |
| Tier 2A | BayesianGMM | Fits multivariate Bayesian GMM with adaptive K selection (ensemble vote over K ∈ [1, 5]); P99.9 log-likelihood threshold computed |
| Tier 2B | IForest | Trains Isolation Forest with `contamination=0.05`; isolation score threshold calibrated |
| Tier 3 | Physical Sentinel | Fits one univariate GMM per feature; per-feature P99.9 log-likelihood thresholds computed (42 independent thresholds) |
| Tier 4 | Velocity Bypass | Stateless (no training required); rolling Z-score statistics computed on baseline velocity features |

**Step 5 — Bundle Assembly.** All trained artifacts are packaged into an `ArtifactBundle` with complete provenance metadata. Baseline medians are computed per-feature (filtering NaN and infinite values) for use as safe imputation values in detection.

### 3.3 Phase 2 — Detection: Inference Under Strict Contract

**Entry point:** `DetectionPipeline.run()` → `main.py detect`

The detection phase is the operationally critical path. Every design decision is oriented toward a single objective: produce per-window anomaly scores that are mathematically comparable to the training baseline, with zero information leakage from the test distribution.

**Step 1.5 — Runtime Config Injection (v4.0).** Before processing any test data, the orchestrator hot-swaps the operational parameters from the current `config.yaml` into the loaded engine, without invalidating the trained mathematical model:

```python
runtime_config = self.settings.to_runtime_config()
bundle.engine.update_runtime_config(runtime_config)
```

This mechanism (introduced in v4.0 to resolve the *Persistence Conflict*) allows the operator to adjust `alert_minimum_persistence`, `velocity_bypass_threshold`, `tribunal_consensus_threshold`, `family_consensus_min_hits`, and all forensic reporting thresholds between detection runs without retraining. The Blocked PCA geometry, BallTree distances, GMM components, and per-feature LL thresholds remain frozen in the bundle. See [Section 6](#6-configuration-contract-modelconfig-vs-runtimeconfig) for the complete taxonomy.

**Step 4 — Schema Alignment.** Test PCAPs may not contain all protocols present in the training baseline (e.g., a test day with no ICMP traffic will produce zero `icmp_ratio` windows). The orchestrator resolves this with deterministic imputation:

```python
for feat in missing_features:
    imputation_value = bundle.baseline_medians.get(feat, 0.0)
    df_aggregated_raw[feat] = imputation_value
```

Imputation uses the baseline median (not zero, not mean) because the median is robust to outliers and represents the most probable value under the baseline distribution. Using `0.0` as a fallback (for protocols absent even in baseline) is physically correct: a feature that never fired in baseline has a baseline distribution centered at zero.

**Step 5 — Scaler Transform.** The restored `RobustScaler` is applied via `.transform()` to the feature matrix. This maps each test window into the coordinate system where the baseline occupies the region near the origin. After this step, Euclidean distances in feature space are approximately comparable to Mahalanobis distances under the baseline covariance — the geometric precondition for meaningful anomaly scoring.

**Step 6 — HiGI Inference.** `engine.analyze()` runs the complete Tribunal consensus for each time window:

```
For each window t:
  1. Project x_t to Hilbert space via Blocked PCA
  2. Tier 1: k-NN distance → BallTree severity (0/0.5/1/2/3)
  3. Tier 2A: Inverted GMM log-likelihood → CDF score
  4. Tier 2B: IForest isolation score
  5. Tier 3: Per-feature LL → physical_culprit + SPIKE/DROP + |σ|
  6. Tier 4: Velocity Z-score → emergency bypass if Z > 5.0σ
  7. Tribunal: weighted_score = Σ(tier_weight × tier_score)
  8. is_anomaly = (weighted_score > consensus_threshold) AND (persistence ≥ alert_minimum_persistence)
```

The Soft Zone (P90–P95) is a diagnostic zone — windows in this range activate Tier 2 analysis but are not escalated to alerts unless multiple tiers co-fire. The static baseline thresholds are used exclusively; no dynamic re-thresholding from the test batch is permitted (Bug-F1 fix).

**Step 7 — Result Export.** The results DataFrame is written to CSV with all forensic columns preserved: `is_anomaly`, `severity`, `balltree_score`, `gmm_score`, `iforest_score`, `physical_culprit`, `suspect_features`, `soft_zone_triggered`, `_abs_timestamp`, `server_port`. A companion `.json` file records detection session metadata and Phase 6 metrics.

### 3.4 Phase 3 — Reporting: Weaving Forensic Intelligence

**Entry point:** `run_report()` → `main.py report`

The reporting phase is the only phase that can be re-executed with different filter parameters without touching the detection artifacts. Its input is the CSV produced in Phase 2; its output is a dual-format report (PDF + Markdown).

The `HiGIForensicEngine` reads the results CSV and executes:

1. **Data Drop Detection.** Gaps exceeding `forensic.data_drop_threshold_seconds` (default: 60s) between consecutive windows are flagged as sensor blindness events, not anomalies. Each gap is classified as "Capture Loss / Network Silence" or "Sensor Blindness / Data Drop due to Saturation" based on the severity of the preceding window.

2. **Incident Clustering.** Consecutive anomalous windows separated by less than `forensic.debounce_seconds` (default: 30s) are merged into a single incident. This debounce mechanism prevents alert storms from multi-window attacks (e.g., a 20-minute DoS flood) from generating thousands of individual alerts.

3. **Confidence Filtering.** Each incident's Consensus Confidence Index (CCI) is computed as a weighted sum of tier activations:

   ```
   CCI = 0.20 × balltree + 0.25 × gmm + 0.20 × iforest
       + 0.20 × physical_sentinel + 0.15 × velocity_bypass
   ```

   Only incidents with `CCI ≥ forensic.default_confidence_filter` (default: 0.80) and `mean|σ| ≥ forensic.sigma_culprit_min` (default: 2.0) are included in the report. These thresholds are **mutable** and can be overridden at the CLI level.

4. **σ Attribution and MITRE Mapping.** The top-3 culprit features by loading magnitude are extracted per incident, classified into physical families (Flags, Volume, Payload, Protocol, Connection), and mapped to MITRE ATT&CK tactics and techniques.

5. **Visual Evidence Generation.** Two figures are produced per session: (a) the Attack Intensity Timeline (severity × time, with Velocity Bypass markers and top-incident callouts) and (b) the Physical Family Stress Radar (per-family anomaly share, guiding immediate countermeasure prioritisation).

---

## 4. CLI Reference — `main.py`

### 4.1 Design Principles

`main.py` is pure CLI glue. It contains no business logic, no ML code, and no physics. Its sole responsibilities are: (1) parse arguments, (2) load `HiGISettings` from `config.yaml`, (3) configure the logging subsystem, and (4) dispatch to the appropriate pipeline handler. This separation guarantees that the entire pipeline logic is unit-testable without invoking the CLI.

**Key properties:**
- **Idempotent:** Running the same command twice with the same inputs produces identical outputs. All randomness is seeded (augmentation: `seed=42`).
- **Config-first:** CLI flags override `config.yaml` defaults where applicable; they never introduce values not covered by `HiGISettings`.
- **Micro-batch ready:** The `PcapProcessor` processes data in configurable chunks. Replacing the PCAP reader with a live socket reader requires changing a single function in `src/ingestion/`.

### 4.2 Global Flags

These flags are valid for all subcommands:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config PATH` | `str` | `config.yaml` | Path to configuration YAML. Allows maintaining multiple environment-specific configs (e.g., `configs/production.yaml`, `configs/debug.yaml`). |
| `--verbose` | `flag` | `False` | Forces the logging level to `DEBUG`, overriding `logging.level` in `config.yaml`. Produces per-tier scoring details, scaler statistics, and schema alignment diagnostics. |

### 4.3 `train` — Establish Baseline

```bash
python main.py train --source <PCAP> --bundle <PKL> [--config <YAML>] [--verbose]
```

**Purpose:** Ingest a benign PCAP, construct the feature matrix, train the four-tier detection engine, and persist the `ArtifactBundle` to disk.

| Argument | Required | Description |
|----------|----------|-------------|
| `--source PCAP` | ✅ | Path to the benign baseline PCAP file. Typically a Monday or known-clean capture. |
| `--bundle PKL` | ✅ | Output path for the trained `ArtifactBundle`. Extension `.pkl` is conventional but not enforced. |

**What it reads from `config.yaml`:**
- `ingestion.chunk_size`, `ingestion.n_jobs`, `ingestion.time_interval` — ingestion parallelism and window resolution.
- `training.baseline_augmentation_enabled`, `.augmentation_noise_scale`, `.augmentation_synthetic_fraction` — baseline augmentation parameters.
- `hilbert.*` — Blocked PCA geometry (immutable at training time).
- `gmm.*`, `balltree.*`, `iforest.*`, `sentinel.*` — tier configuration.

**Example:**
```bash
python main.py train \
    --source data/raw/Monday.pcap \
    --bundle models/baseline_monday.pkl \
    --verbose
```

**Expected output:**
```
[2026-04-27 14:32:11] [INFO    ] [higi.train] ================================================================================
[2026-04-27 14:32:11] [INFO    ] [higi.train] HiGI TRAINING MODE
[2026-04-27 14:32:11] [INFO    ] [higi.train] ================================================================================
[2026-04-27 14:32:11] [INFO    ] [higi.train]   Source PCAP : data/raw/Monday.pcap
[2026-04-27 14:32:11] [INFO    ] [higi.train]   Output Bundle: models/baseline_monday.pkl
...
[2026-04-27 14:48:03] [INFO    ] [higi.train]   ✓ Training complete. Bundle saved to models/baseline_monday.pkl
```

### 4.4 `detect` — Run Inference

```bash
python main.py detect \
    --source <PCAP> --bundle <PKL> \
    [--output <CSV>] [--config <YAML>] [--verbose]
```

**Purpose:** Load an `ArtifactBundle`, ingest a test PCAP, apply the runtime config, run four-tier inference, and write the results CSV.

| Argument | Required | Description |
|----------|----------|-------------|
| `--source PCAP` | ✅ | Path to the test PCAP to evaluate. |
| `--bundle PKL` | ✅ | Path to the trained `ArtifactBundle` produced by `train`. |
| `--output CSV` | ❌ | Output results CSV path. Defaults to `<results_dir>/<source_stem>_results.csv` as defined in `config.yaml`. |

**Example:**
```bash
python main.py detect \
    --source data/raw/Wednesday.pcap \
    --bundle models/baseline_monday.pkl \
    --output data/processed/wednesday_results.csv \
    --verbose
```

### 4.5 `report` — Generate Forensic Report

```bash
python main.py report \
    --results <CSV> --bundle <PKL> \
    [--output-dir <DIR>] [--confidence <FLOAT>] \
    [--min-anomalies <N>] [--min-duration <SEC>] \
    [--config <YAML>] [--verbose]
```

**Purpose:** Cluster incidents from an existing results CSV and generate the PDF + Markdown forensic report. The `--bundle` argument is optional but strongly recommended: it provides the Blocked PCA family mapping metadata needed for accurate culprit attribution.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--results CSV` | ✅ | — | Detection results CSV produced by `detect`. |
| `--bundle PKL` | ❌ | None | ArtifactBundle for PCA metadata-enhanced attribution. Without it, the engine degrades to keyword-based family inference. |
| `--output-dir DIR` | ❌ | `config.yaml:paths.reports_dir` | Directory for PDF and Markdown outputs. Created if absent. |
| `--confidence FLOAT` | ❌ | `config.yaml:forensic.default_confidence_filter` | Minimum CCI (0.0–1.0) for an incident to appear in the report. CLI value takes precedence. |
| `--min-anomalies N` | ❌ | `config.yaml:forensic.default_min_anomalies` | Minimum number of anomalous windows per incident. Filters out transient spikes. |
| `--min-duration SEC` | ❌ | `config.yaml:forensic.default_min_duration_seconds` | Minimum incident duration in seconds. |

**Override priority:** CLI > `config.yaml` > dataclass default. The report command is designed to be re-run iteratively with different filter parameters to explore the incident space without repeating the computationally expensive inference phase.

**Example — strict filter for high-confidence reporting:**
```bash
python main.py report \
    --results data/processed/wednesday_results.csv \
    --bundle models/baseline_monday.pkl \
    --confidence 0.90 \
    --min-anomalies 5 \
    --output-dir reports/wednesday_strict/
```

**Example — permissive filter for reconnaissance during triage:**
```bash
python main.py report \
    --results data/processed/wednesday_results.csv \
    --bundle models/baseline_monday.pkl \
    --confidence 0.60 \
    --min-anomalies 1 \
    --min-duration 0.0 \
    --output-dir reports/wednesday_triage/
```

**Output files:**
```
reports/wednesday_strict/
├── wednesday_results_FORENSIC.pdf     # Professional PDF with charts
└── wednesday_results_FORENSIC.md      # GitHub-renderable Markdown with embedded figure paths
```

### 4.6 `run` — Full Pipeline in One Command

```bash
python main.py run \
    --source <PCAP> --bundle <PKL> \
    [--output-dir <DIR>] [--confidence <FLOAT>] \
    [--min-anomalies <N>] [--min-duration <SEC>] \
    [--config <YAML>] [--verbose]
```

**Purpose:** `detect` followed immediately by `report` in a single invocation. The intermediate CSV is written to `<output-dir>/<source_stem>_results.csv` and then consumed by the report generator. All report flags are available.

```bash
python main.py run \
    --source data/raw/Wednesday.pcap \
    --bundle models/baseline_monday.pkl \
    --output-dir data/processed/ \
    --confidence 0.75
```

### 4.7 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — all outputs written. |
| `1` | Failure — pipeline error (PCAP not found, bundle corrupt, config invalid, etc.). Specific error logged. |
| `130` | Interrupted — user sent `KeyboardInterrupt` (Ctrl+C). Partial outputs may exist. |

---

## 5. Error Handling and Resilience

### 5.1 Exception Hierarchy

The orchestrator defines a typed exception hierarchy that prevents generic `Exception` catches from silently swallowing diagnostic information:

```
OrchestratorError          (base — never raised directly)
├── TrainingError          (Step 1–5 of TrainingPipeline)
├── DetectionError         (Step 1–7 of DetectionPipeline)
└── ArtifactError          (bundle save/load operations)
```

Each exception wraps its cause with `raise ... from e`, preserving the full exception chain in the traceback. `--verbose` mode activates `logger.debug(traceback.format_exc())` for complete stack traces in the log file.

### 5.2 PCAP Corruption and Partial Captures

`PcapProcessorError` is raised by the ingestion layer when a PCAP is unreadable, truncated, or structurally invalid. The orchestrator catches this exception specifically and re-raises it as a `TrainingError` or `DetectionError` with an explanatory message:

```python
except PcapProcessorError as e:
    raise TrainingError(f"PCAP processing failed: {str(e)}") from e
```

Partial PCAPs (captures terminated mid-session by a system crash) are handled gracefully: `PcapProcessor` reads as many valid packets as available and constructs the feature matrix from the valid portion. The metadata sidecar will reflect the actual packet count.

### 5.3 Feature Schema Inconsistencies

The most common operational failure mode is a mismatch between the feature schema of the training baseline and the test PCAP. This arises when the test traffic does not use all protocols present in baseline (e.g., no ICMP in Wednesday's DoS captures, or no multicast traffic in a single-server test).

The orchestrator handles this in two directions:

**Missing features (in test but not in baseline):** Filled with baseline medians from `bundle.baseline_medians`. A `WARNING` is logged identifying each missing feature and its imputed value. This is the safe path: the missing feature was statistically zero or near-zero in baseline, and the median imputation preserves that expectation.

**Extra features (in test but not in baseline):** Dropped with `df.drop(columns=...)`. These are typically new protocol sub-variants (e.g., a new IPv6 extension header type) not present in the training data. They cannot be evaluated against the baseline model and are silently excluded. A `WARNING` is logged.

**Schema verification before inference:**
```python
if len(results) != len(X_metadata):
    raise ValueError("Index alignment failed in STEP 6")
```

This post-inference check guarantees that the timestamp and server port metadata are correctly aligned with the inference results before the CSV is written. If alignment fails (which should be architecturally impossible), the pipeline aborts rather than writing a misaligned output.

### 5.4 Configuration Validation Failures

`config.yaml` is validated by `_validate()` in `src/config.py` before any pipeline code runs. Validation failures produce a structured error listing all constraint violations:

```
[ERROR] Configuration error: config.yaml validation failed:
  • tribunal.weights must sum to 1.0, got 0.9500
  • hilbert.pca_variance_target must be in [0.80, 1.0], got 1.05
```

The pipeline does not start if any validation error is present. This design prevents partially misconfigured runs that produce subtly incorrect results.

### 5.5 Visualization Failures

Report visualization (timeline plot, radar chart) is wrapped in an isolated `try/except`:

```python
try:
    visual_paths = engine.generate_visuals(output_dir)
except Exception as vis_exc:
    logger.warning(f"Failed to generate visualizations: {vis_exc}")
    visual_paths = None
```

A visualization failure (e.g., matplotlib backend unavailable in a headless environment) does not abort the report. The PDF and Markdown are still generated, with figure placeholders instead of embedded charts. This ensures that the forensic intelligence is always delivered even in degraded rendering environments.

---

## 6. Configuration Contract: ModelConfig vs. RuntimeConfig

### 6.1 The Persistence Conflict (v4.0 Solution)

Prior to v4.0, a critical design defect caused detection sensitivity to be frozen at training time: parameters such as `alert_minimum_persistence` and `tribunal_consensus_threshold` were baked into the `ArtifactBundle` during training and could not be changed without retraining. This made rapid operational tuning (e.g., lowering persistence to catch a 2-minute SQL Injection) impossible without a full retraining cycle.

v4.0 resolves this through a clean architectural split: `ModelConfig` vs. `RuntimeConfig`.

### 6.2 ModelConfig — Frozen at Training Time

`ModelConfig` contains all parameters that define the geometry of the Hilbert space and the mathematical calibration of the four-tier detectors. These parameters are serialized into the `ArtifactBundle.engine` and must not change between training and detection.

| Section | Parameter | Why Immutable |
|---------|-----------|---------------|
| `hilbert` | `pca_variance_target`, `blocked_pca_variance_per_family`, `blocked_pca_enabled` | Defines the dimensionality and axis orientation of the Hilbert projection space. Changing it makes BallTree distances physically meaningless. |
| `ingestion` | `time_interval` | Defines the temporal resolution of each feature window. A 1-second window produces different feature statistics than a 5-second window. |
| `balltree` | `k_neighbors` | Determines the neighborhood radius in the geometric space. |
| `gmm` | `reg_covar`, `use_bayesian`, `adaptive_k_range`, `n_components_fallback`, `score_normalization` | Defines the density model fitted to the baseline. Different settings produce different log-likelihood thresholds. |
| `iforest` | `contamination`, `n_estimators` | Determines the isolation score calibration. |
| `sentinel` | `per_feature_thresholds`, `global_threshold` | Per-feature P99.9 thresholds are computed at training time over the baseline distribution. |
| `training` | `augmentation_noise_scale`, `augmentation_synthetic_fraction` | Affects the effective support of the baseline model. |

### 6.3 RuntimeConfig — Hot-Swappable via `config.yaml`

`RuntimeConfig` contains all operational parameters that can be changed between detection sessions without invalidating the trained model. These are loaded from `config.yaml` at the start of every `detect` run via `settings.to_runtime_config()` and injected into the engine via `bundle.engine.update_runtime_config(runtime_config)`.

| Section | Parameter | Operational Effect |
|---------|-----------|-------------------|
| `persistence` | `alert_minimum_persistence` | ↓ to detect short attacks (SQLi, 2-min windows); ↑ to suppress transients. |
| `persistence` | `hysteresis_entry_multiplier`, `hysteresis_exit_multiplier` | Controls alert sustain/decay relative to the P95 threshold. |
| `persistence` | `ma_window_size` | Smoothing window for moving-average contextualisation. |
| `tribunal` | `consensus_threshold` | ↓ for higher recall (more alerts); ↑ for higher precision (fewer FP). |
| `tribunal` | `weights.{balltree,gmm,iforest}` | Rebalance Tribunal vote without retraining. Weights must sum to 1.0. |
| `velocity` | `bypass_threshold` | Z-score at which Tier 4 fires unconditionally. ↓ detects moderate spikes; ↑ reserves Tier 4 for extreme floods. |
| `family_consensus` | `min_hits`, `z_threshold` | Anti-FP gate: requires N features from same family above z_threshold to escalate borderline detections. |
| `forensic` | `debounce_seconds` | Incident clustering window. ↑ merges adjacent alerts into longer incidents; ↓ produces finer granularity. |
| `forensic` | `default_confidence_filter` | CCI cutoff for reportable incidents. |
| `forensic` | `sigma_culprit_min` | Minimum mean |σ| for culprit features in reportable incidents. |

---

## 7. Technical Disclaimer: The Hilbert Space

### 7.1 Conceptual Grounding

The nomenclature *Hilbert space* in HiGI is a deliberate conceptual reference to the mathematical framework of quantum mechanics, where the state of a system is represented as a vector in an infinite-dimensional inner product space. In quantum mechanics, measurement collapses the state vector onto an eigenstate; in HiGI, the Tribunal consensus collapses the multi-dimensional anomaly score onto a discrete severity level.

The analogy is not merely rhetorical. In both cases, the fundamental operation is the computation of a **distance from a reference state** (the baseline) using a metric that accounts for the natural variance of the system (the covariance structure). The Mahalanobis distance used by the BallTree detector is the classical mechanics analogue of the expectation value of the deviation operator in quantum theory.

### 7.2 Implementation Reality

In concrete engineering terms, HiGI's "Hilbert space" is a finite-dimensional Euclidean space produced by the following sequence of transformations:

```
x_t ∈ ℝ^42  (raw features, RobustScaler-normalised)
      │
      │ Yeo-Johnson PowerTransformer (per-feature Gaussianisation)
      ▼
x̃_t ∈ ℝ^42  (approximately Gaussian marginals)
      │
      │ Blocked PCA per physical family (decorrelation + whitening)
      │ Family f: z_t^(f) = W^(f)ᵀ (x̃_t^(f) − μ_0^(f))
      ▼
z_t ∈ ℝ^k   (k ≤ 42, whitened principal components)
```

The resulting space `ℝ^k` has the property that:

1. **Euclidean distances approximate Mahalanobis distances** in the original feature space, because the Blocked PCA whitening effectively applies the inverse square root of the per-family covariance matrix.
2. **Each principal component maps to exactly one physical family**, because Blocked PCA operates independently per family. This is the property that makes forensic attribution possible: the PCA component that deviates most from the baseline can be directly traced back to its feature family.
3. **The space is maximally compact** for the given variance retention targets (`blocked_pca_variance_per_family`). Features with low discriminative power are collapsed into fewer components, reducing BallTree computation and improving statistical power.

The term "Hilbert space" in the codebase and documentation should therefore be understood as a conceptually motivated shorthand for: *a whitened, family-structured metric space in which the baseline distribution occupies a compact high-density region and anomalies are points geometrically distant from that region*.

### 7.3 Why This Matters for Operational Trust

The physical grounding of the Hilbert projection is not an academic exercise. It is the engineering guarantee that a detection at 4,120σ (`payload_continuity_ratio`, DoS GoldenEye) is not a numerical artifact or a model pathology — it is the geometrically correct statement that the observed traffic window lies 4,120 baseline standard deviations away from the center of the normal traffic manifold, in the direction of maximum payload structure disruption. That statement is independently verifiable, dimensionally consistent, and operationally actionable.

Supervised models produce probabilities or class labels. HiGI produces **physical displacements from an inertial reference frame**. The difference is not cosmetic.

---

## 8. Glossary

| Term | Definition |
|------|------------|
| **ArtifactBundle** | Immutable `.pkl` file containing the trained `HiGIEngine`, feature schema, `RobustScaler`, baseline medians, and training provenance metadata. |
| **Blocked PCA** | Principal Component Analysis performed independently per physical feature family. Preserves semantic interpretability of components and enables accurate family-level forensic attribution. |
| **CCI (Consensus Confidence Index)** | Weighted sum of tier activation scores for an incident, computed by the ForensicEngine. Range [0, 1]. |
| **DSS (Dynamic Severity Score)** | Per-window severity level assigned by the Tribunal: 0 = Normal, 1 = Borderline, 2 = Medium, 3 = Critical. |
| **Golden Rule** | The inference invariant: `.transform()` only in detection mode. Never `.fit()`. |
| **Hilbert Space** | HiGI's internal metric space — a whitened, family-structured Euclidean projection of the raw feature space in which Euclidean distances approximate Mahalanobis distances under the baseline covariance. See [Section 7](#7-technical-disclaimer-the-hilbert-space). |
| **Inertial Reference Frame** | The baseline traffic distribution `N(μ₀, Σ₀)` learned from benign training data. All anomaly scores are relative displacements from this frame. |
| **Matrioshka Escalado** | v4.0 bug fix codename. Refers to the nested (double) scaling defect where `RobustScaler` was applied twice, collapsing variance. |
| **ModelConfig** | Parameters frozen at training time that define the geometry of the Hilbert space and the calibration of the four-tier detectors. Immutable in the bundle. |
| **Persistence Conflict** | v4.0 architectural issue where operational runtime parameters were erroneously frozen in the `ArtifactBundle`, preventing hot-swap tuning. |
| **Portero Veto** | Tier 3 override: if any feature exceeds `sentinel.portero_sigma_threshold` (default: 12.0σ in `config.yaml`, 20.0σ in `config.py` dataclass default), the window is unconditionally escalated to CRITICAL regardless of Tribunal vote. Last-resort defense against catastrophic deviations. |
| **RuntimeConfig** | Parameters loaded from `config.yaml` at every detection session and hot-swapped into the engine without retraining. Controls operational sensitivity. |
| **Soft Zone (P90–P95)** | BallTree distance percentile range that activates Tier 2 analysis without direct escalation. A defense-in-depth zone for borderline windows. |
| **Tribunal** | The weighted voting mechanism that aggregates scores from Tiers 1–4 into a single `is_anomaly` decision and DSS level. |
| **Velocity Bypass (Tier 4)** | Stateless emergency detector based on rolling Z-score of traffic velocity (PPS, bytes/s). Fires unconditionally when Z exceeds `velocity.bypass_threshold`, bypassing the Tribunal vote. |

---

*HiGI IDS Core Manual v4.0.0 · Blue Team Engineering · 2026*  
*This document is part of the HiGI IDS technical documentation suite. Cross-reference with:*  
*[Forensic Intelligence & Attribution Manual (XAI)](docs/) ·*  
*[Configuration & Tuning Reference](docs/) ·*  
*[Ingestion Pipeline Manual](docs/)*
