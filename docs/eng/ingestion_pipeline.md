# HiGI IDS — Data Engineering and Ingestion Manual
## Data Pipeline: From Raw PCAP to High-Fidelity Feature Matrix

**Module:** `src/ingestion/processor_optime.py`  
**Documented Version:** v2.3.0  
**Classification:** Internal Technical Reference — Engineering Level  

---

## Table of Contents

1. [Architectural Overview](#1-architectural-overview)
2. [Technical Pipeline Specifications](#2-technical-pipeline-specifications)
3. [Phase 1 — Ingestion: From PCAP to Raw DataFrame](#3-phase-1--ingestion-from-pcap-to-raw-dataframe)
4. [Phase 2 — Time Windowing and Aggregation](#4-phase-2--time-windowing-and-aggregation)
5. [Phase 3 — Feature Engineering: Physical Dimensions](#5-phase-3--feature-engineering-physical-dimensions)
6. [Phase 4 — Standardization and Inference Contract](#6-phase-4--standardization-and-inference-contract)
7. [Resource Optimization and Parallelism](#7-resource-optimization-and-parallelism)
8. [Robustness and Error Handling](#8-robustness-and-error-handling)
9. [Integrity Validation: Capture Health Report](#9-integrity-validation-capture-health-report)
10. [Complete Feature Inventory](#10-complete-feature-inventory)

---

## 1. Architectural Overview

The `processor_optime.py` module constitutes the **ingestion and transformation layer** of HiGI IDS. Its responsibility is to take a network capture PCAP file — potentially several gigabytes in size — and produce a standardized **Feature Matrix**, indexed by time window, ready to be consumed by the detection engine (`higi_engine.py`).

The pipeline design is governed by three engineering principles:

**1. Physics before statistics.** Each feature is not an arbitrary transformation, but the projection of a real physical magnitude of network traffic: flow velocity, payload continuity, packet kinematics. This ensures that detected anomalies have a direct operational interpretation.

**2. Memory efficiency over simplicity.** The pipeline never loads the complete PCAP into memory. Processing is performed in batches of configurable size (default: 5,000 packets) using a Python generator, and the final concatenation is performed on Polars chunks — not on lists of dictionaries.

**3. Contractual determinism.** The `RobustScaler` trained during the baseline phase is serialized as an artifact (`.pkl`) and is the same object applied during inference. No parameter recalibration exists during detection time.

### Pipeline Flow Diagram

```
PCAP File
    │
    ▼
┌─────────────────────────────────────────────┐
│  _batch_generator()                          │
│  StreamGenerator → chunks of 5,000 packets  │
│  Support: Ethernet, Linux SLL, Raw IP        │
└───────────────┬─────────────────────────────┘
                │  batches (ip_payload, timestamp, length)
                ▼
┌─────────────────────────────────────────────┐
│  ProcessPoolExecutor (n_jobs=6)             │
│  _process_batch() — parallel by batch       │
│  ├── Parse IP/TCP/UDP (dpkt)                │
│  ├── Extraction of ports and TCP flags      │
│  ├── Shannon Entropy (NumPy vectorized)     │
│  └── Direction detection (in/outbound)      │
└───────────────┬─────────────────────────────┘
                │  List[Dict] → pl.DataFrame chunks
                ▼
┌─────────────────────────────────────────────┐
│  pl.concat() + sort("timestamp")            │
│  Restoration of chronological order         │
│  Calculation of relative timestamps (dt)     │
└───────────────┬─────────────────────────────┘
                │  pl.DataFrame (packets)
                ▼
┌─────────────────────────────────────────────┐
│  _build_base_matrix()                       │
│  LazyFrame group_by("second_window")        │
│  ├── Intensity aggregation (PPS, bytes)     │
│  ├── Ratios by protocol and TCP flags       │
│  ├── Physical dimensions (flow, IAT, PCR)   │
│  └── Dynamic Z-scores (60s window)          │
└───────────────┬─────────────────────────────┘
                │  pd.DataFrame (feature matrix)
                ▼
┌─────────────────────────────────────────────┐
│  get_standardized_matrix()                  │
│  ColumnTransformer (parallel, n_jobs)       │
│  ├── Ratios → Identity (no scaling)         │
│  └── Rest → RobustScaler                    │
└───────────────┬─────────────────────────────┘
                │
                ▼
      Standardized Feature Matrix
      → higi_engine.py (Consensus Tribunal)
```

---

## 2. Technical Pipeline Specifications

| Parameter | Value / Configuration | Description |
|---|---|---|
| **Parsing library** | `dpkt` (unique) | No library mixing; homogeneous API |
| **Aggregation engine** | `polars.LazyFrame` | Lazy evaluation; no materialization until `.collect()` |
| **Chunk size (default)** | 5,000 packets | Controlled by `PcapProcessor.DEFAULT_CHUNK_SIZE` |
| **Parallelism** | `ProcessPoolExecutor` (n_jobs=6) | Independent processes; avoids GIL |
| **MAX_INFLIGHT** | `n_jobs × 2` | Maximum simultaneous batches in worker queue |
| **Baseline scaler** | `RobustScaler` | Resistant to extreme outliers (DoS attacks) |
| **Inference scaler** | Pre-trained (`.pkl`) | Deterministic contract; no recalibration in detection |
| **Internal types** | `Float64` (Polars) / `np.float32` where applicable | Computing efficiency in dense matrices |
| **Time window** | `1s` (configurable) | `time_interval` in `config.yaml` |
| **Dynamic Z-score window** | 60 seconds | Traffic regime detection (v2.3.0) |
| **Volatility window** | 5 seconds | `rolling_std(5)` over PPS, bytes, entropy |
| **Shannon Entropy** | Range `[0.0, 8.0]` bits | NumPy vectorized; 10-15× faster than scipy |
| **Supported datalinks** | Ethernet, Linux SLL, Raw IP | Generic fallback for unknown types |
| **Malformed handling** | `dpkt.UnpackError` → silent skip | No pipeline interruption |
| **Metadata columns** | `_abs_timestamp`, `server_port` | Excluded from scaling; orchestrator responsibility |

---

## 3. Phase 1 — Ingestion: From PCAP to Raw DataFrame

### 3.1 Stream Generator: Reading without Pre-loading in Memory

Ingestion begins in `_batch_generator()`, a Python generator that reads the PCAP incrementally. The file is never fully loaded into RAM; instead, it is iterated packet by packet, accumulating batches of `chunk_size` packets before yielding them to the process pool.

```python
# Backpressure control pattern (MAX_INFLIGHT)
if len(inflight) >= MAX_INFLIGHT:
    done, pending = concurrent.futures.wait(
        inflight, return_when=concurrent.futures.FIRST_COMPLETED
    )
```

The `MAX_INFLIGHT = n_jobs × 2` parameter acts as a backpressure mechanism: if workers cannot consume batches with sufficient speed, the generator waits before enqueuing more work, preventing the accumulation of unprocessed batches in memory.

### 3.2 IANA Protocol Resolution

The module initializes in `__init__` a `Dict[int, str]` map that translates IP protocol numbers to their official IANA names. This is performed by extracting constants from the `dpkt.ip` module — there is no hardcoded table. Unrecognized protocols are represented as `PROTO_{number}`, ensuring forensic traceability even for experimental or proprietary protocols.

### 3.3 Batch Processing: `_process_batch()`

Each batch is processed in an independent worker. For each IPv4 packet, the worker performs the following operations in sequence:

**a) Transport Layer Parsing**

```
IP header → (TCP | UDP | others)
             ├── Extraction of src_port, dst_port
             ├── TCP Flags (SYN, ACK, FIN, RST, PSH, URG) — bitmask
             └── Payload: bytes after transport header
```

TCP flags are extracted via bitmask operations on the `flags` field of the `dpkt.tcp.TCP` packet:

```python
"tcp_flags_syn": 1 if (flags_byte & dpkt.tcp.TH_SYN) else 0
```

**b) Payload Shannon Entropy**

For each packet, the transport payload entropy is calculated using a NumPy vectorized implementation:

$$H(X) = -\sum_{i=0}^{255} p_i \cdot \log_2(p_i)$$

where $p_i = \frac{n_i}{L}$, with $n_i$ being the number of occurrences of byte $i$ and $L$ the total payload length. The valid range is $H \in [0.0, 8.0]$ bits. Empty payloads return $H = 0.0$.

The implementation uses `np.bincount()` on a `uint8` buffer, avoiding histogram creation via loops and achieving a speed 10-15 times higher than `scipy.stats.entropy` for typical network traffic payload sizes.

**c) Traffic Direction Detection**

Each packet is semantically classified based on whether the source or destination port belongs to the `STANDARD_SERVICE_PORTS` set (22 defined ports, including HTTP, HTTPS, SSH, DNS, common databases):

- **`outbound`**: `dst_port` ∈ SERVICE_PORTS → client sends a request to the server
- **`inbound`**: `src_port` ∈ SERVICE_PORTS → server sends a response to the client
- **`unknown`**: no recognized port

This classification allows for the calculation of L7 payload asymmetry in the aggregation phase (see §5.3).

### 3.4 Post-Parallel Chronological Reordering

The parallel execution of batches introduces non-determinism in completion order: a later batch may finish before an earlier one if the computational load is uneven. Directly concatenating unordered chunks breaks the temporal continuity of the series, producing false "Data Drop" alerts and incorrect derivatives in velocity calculations.

```python
# MANDATORY OPERATION — do not omit in any future refactor
df_polars = df_polars.sort("timestamp")
```

This `sort` in Polars operates in $O(n \log n)$ on the timestamp column and is the last operation on the raw DataFrame before windowing.

---

## 4. Phase 2 — Time Windowing and Aggregation

### 4.1 LazyFrame: Deferred Evaluation with Polars

The transition from individual packets to the Feature Matrix occurs in `_build_base_matrix()`. The raw DataFrame is converted into a Polars **LazyFrame**:

```python
lf = dataframe.lazy()
lf = lf.with_columns([
    pl.col("timestamp").cast(pl.Int64).alias("second_window")
])
```

The cast to `Int64` truncates each packet's timestamp to its integer second, creating the time window index. Polars does not execute any operation until `.collect()` is called at the end of the transformation chain, allowing the Polars query optimizer to reorder, fuse, and parallelize operations internally.

**Advantage over Pandas:** In Pandas, each `.groupby().agg()` materializes a complete intermediate DataFrame. Polars builds a single execution plan and executes it in a single pass over the data, reducing memory copies and leveraging processor SIMD instructions.

### 4.2 Dynamic Window Aggregation

The `group_by("second_window")` is **dynamic**: protocols and TCP flags are detected in the raw DataFrame before aggregation, and the list of columns to aggregate is built programmatically. This eliminates the need to update the pipeline when unforeseen protocols appear in the traffic.

```python
protocols = dataframe["protocol"].unique().to_list()
flag_cols = [c for c in dataframe.columns if c.startswith("tcp_flags_")]
```

For each 1-second window, the following raw magnitudes are calculated:

| Raw Aggregate | Polars Operation | Physical Meaning |
|---|---|---|
| `pps` | `pl.len()` | Packets per second |
| `bytes` | `pl.col("size").sum()` | Raw throughput in bytes |
| `count_{protocol}` | `(pl.col("protocol") == p).sum()` | Count per protocol |
| `count_{flag}` | `(pl.col(flag) == 1).sum()` | Count per TCP flag |
| `unique_dst_ports` | `pl.col("dst_port").n_unique()` | Destination port diversity |
| `entropy_avg` | `pl.col("entropy").mean()` | Average payload entropy |
| `size_max`, `size_avg` | `.max()`, `.mean()` | Packet size statistics |
| `total_payload_bytes` | `pl.col("payload_bytes").sum()` | Transport payload bytes |
| `total_req_payload` | `pl.col("req_payload").sum()` | Outbound bytes (client→server) |
| `total_res_payload` | `pl.col("res_payload").sum()` | Inbound bytes (server→client) |
| `_ts_max`, `_ts_min` | `.max()`, `.min()` of timestamp | Temporal span within the window |
| `_abs_timestamp` | `pl.col("abs_ts").min()` | Absolute timestamp of the first packet |

---

## 5. Phase 3 — Feature Engineering: Physical Dimensions

### 5.1 Intensity Transformations (Log-Normalization)

Raw intensity metrics (`pps`, `bytes`) exhibit heavily right-skewed distributions, characteristic of bursty network traffic. Logarithmic transformation projects them to a manageable scale:

$$\text{total\_pps\_log} = \log(1 + \text{pps})$$

$$\text{total\_bytes\_log} = \log(1 + \text{bytes})$$

Using $\log(1 + x)$ instead of $\log(x)$ ensures that windows with zero packets (silent periods) produce 0.0 instead of $-\infty$.

### 5.2 Composition Ratios

Protocol and TCP flag ratios normalize raw counts by the number of packets in the window, producing values in $[0.0, 1.0]$ that represent **traffic composition** regardless of volume:

$$r_{\text{protocol}} = \frac{\text{count\_protocol}}{\text{pps}}$$

$$r_{\text{flag}} = \frac{\text{count\_flag}}{\text{pps}}$$

$$r_{\text{port\_scan}} = \frac{\text{unique\_dst\_ports}}{\text{pps}}$$

These ratios are treated as **scale invariants** in the standardization phase: an identity transformation is applied instead of RobustScaler, preserving their direct probabilistic interpretation. A `flag_syn_ratio = 0.95` means 95% of packets in that window have the SYN flag active — an unequivocal SYN flood signature.

### 5.3 Advanced Physical Dimensions (v2.1.0 — v2.2.0)

#### 5.3.1 Flow Duration

Real temporal duration of observed traffic within the aggregation window:

$$\text{flow\_duration} = \max(\text{timestamp}) - \min(\text{timestamp})$$

with a floor of $10^{-6}$ seconds for single-packet windows (avoids division by zero in subsequent calculations without introducing a zero that propagates `NaN` after log transformations).

**Physical interpretation:** Short durations with high PPS indicate bursts; long durations with low PPS are the kinematic signature of slow attacks like Slowloris.

#### 5.3.2 Payload Continuity

Average transport payload bytes per packet within the window:

$$\text{payload\_continuity} = \frac{\sum \text{payload\_bytes}}{\text{pps}}$$

**Physical interpretation:** Values near zero indicate pure header traffic — SYN floods, ACK storms, port scans. High values signal data transfer or exfiltration.

#### 5.3.3 IAT Mean (Inter-Arrival Time)

Average time between the arrival of consecutive packets within the window, analytically derived without storing timestamp lists per packet:

$$\text{iat\_mean} = \frac{\text{flow\_duration}}{\max(\text{pps}, 2) - 1}$$

The denominator is clipped at 2 (not 1) so that single-packet windows produce `iat_mean = flow_duration` — the physically correct conservative upper limit, as a single packet has no inter-arrival time.

**Physical interpretation:** Low and regular IAT → systematic flooding. High and irregular IAT → covert beaconing or reconnaissance traffic.

#### 5.3.4 Payload Continuity Ratio (PCR) — L7 Asymmetry

Ratio between response and request payload, quantifying the bidirectional asymmetry of traffic at the application layer:

$$\text{PCR} = \frac{\sum \text{res\_payload}}{\sum \text{req\_payload} + 10^{-6}}$$

The $10^{-6}$ term in the denominator avoids division by zero in windows where no outbound traffic was detected. A value $\text{PCR} \gg 1$ indicates the server is responding with significantly more data than the client requests — characteristic of traffic amplification or data exfiltration patterns. A value $\text{PCR} \approx 1$ indicates balanced bidirectional communication. This feature reached **4120σ** Sigma deviations during the GoldenEye DoS attack in the CIC-IDS2017 validation.

### 5.4 Traffic Kinematics: Velocity, Acceleration, and Volatility

Once windows are chronologically ordered, the pipeline calculates the **time derivatives** of intensity metrics, treating the window time series as a physical signal:

**First derivative (Velocity):** Instant-to-instant rate of change.

$$v_{\text{pps}}[t] = \text{total\_pps\_log}[t] - \text{total\_pps\_log}[t-1]$$

**Second derivative (Acceleration):** Rate of change of velocity — detects the onset phase of a volumetric attack before absolute volume exceeds thresholds.

$$a_{\text{pps}}[t] = v_{\text{pps}}[t] - v_{\text{pps}}[t-1]$$

**Volatility (Rolling standard deviation):** Measure of signal irregularity in a 5-second window.

$$\sigma_{\text{pps}}[t] = \text{std}\left(\text{total\_pps\_log}[t-4..t]\right)$$

**Momentum (Burst counter):** Rolling sum of burst events — windows where PPS exceeds 1.5 times the 10-window rolling mean:

$$\text{pps\_momentum}[t] = \sum_{i=t-4}^{t} \mathbf{1}\left[\text{pps\_log}[i] > 1.5 \cdot \overline{\text{pps\_log}}_{10}[i]\right]$$

### 5.5 Dynamic Z-Score: Traffic Regime Detection (v2.3.0)

Hilbert-Space features are effective for detecting absolute anomalies relative to the stationary baseline. However, in scenarios where an attack's magnitude is similar to normal traffic (sustained low-volume attacks), geometric separation may be insufficient. Dynamic Z-scores over a 60-second rolling window resolve this limitation by detecting **relative regime changes**:

$$Z_{\text{pps}}[t] = \frac{\text{total\_pps\_log}[t] - \mu_{60}[t]}{\sigma_{60}[t] + 10^{-6}}$$

$$Z_{\text{bytes}}[t] = \frac{\text{total\_bytes\_log}[t] - \mu_{60}[t]}{\sigma_{60}[t] + 10^{-6}}$$

$$Z_{\text{syn}}[t] = \frac{\text{flag\_syn\_ratio}[t] - \mu_{60}[t]}{\sigma_{60}[t] + 10^{-6}}$$

where $\mu_{60}$ and $\sigma_{60}$ are the rolling mean and standard deviation over the last 60 1-second windows. The $10^{-6}$ term in the denominator prevents numerical instability during periods of constant signal.

Positive values indicate a sudden increase relative to the recent regime (attack onset); negative values indicate a decrease (decline or post-attack recovery). These features directly feed the **Velocity Bypass Detector (Tier 4)** of the HiGI engine.

---

## 6. Phase 4 — Standardization and Inference Contract

### 6.1 Hybrid Scaling Strategy

The `get_standardized_matrix()` method applies a differentiated scaling strategy via a scikit-learn `ColumnTransformer` executed in parallel (`n_jobs=self.n_jobs`):

| Feature Category | Applied Scaling | Justification |
|---|---|---|
| `*_ratio` columns | `FunctionTransformer` (identity) | Already normalized in $[0.0, 1.0]$ by construction |
| Other numerical columns | `RobustScaler` | Resistant to extreme outliers from DoS attacks |

`RobustScaler` centers by median and scales by Interquartile Range (IQR), rather than mean and standard deviation. This is critical in the IDS context: an 857σ attack burst in `bytes` must not shift the scaler's center during baseline training.

### 6.2 Pre-Scaling Data Sanitization

Before scaling, the pipeline applies a numerical sanitization cycle:

```
1. Substitution of Inf and -Inf → NaN
2. Substitution of NaN → 0.0
3. Filtering of non-numerical columns (select_dtypes)
```

The count of replaced Inf values is recorded in the operations log for auditing. This sanitization prevents numerical explosions in the Yeo-Johnson `PowerTransformer` applied by `higi_engine.py` in the next layer.

### 6.3 Metadata Column Separation

The `_abs_timestamp` and `server_port` columns are extracted before scaling and **are not reincorporated** into the output DataFrame. This is an explicit architectural contract (v2.2.0): the `higi_engine.py` engine was trained on features without metadata, and reintroducing these fields would break the expected dimensionality of the model. Reincorporation is the exclusive responsibility of the orchestrator (`orchestrator.py`), which maintains metadata separately for subsequent forensic mapping.

### 6.4 Scaling Artifact Persistence

In training mode (baseline), the trained `ColumnTransformer` is serialized with `joblib`:

```
models/scalers/{scaler_type}_{export_name}.pkl
```

In inference mode (detection), the serialized artifact is loaded and only `.transform()` is invoked — never `.fit_transform()`. This contract guarantees that the scaler parameters (median, IQR) are those of the reference traffic and are not contaminated by the traffic under analysis.

---

## 7. Resource Optimization and Parallelism

### 7.1 Concurrency Architecture

The pipeline uses `ProcessPoolExecutor` (not `ThreadPoolExecutor`) for the packet parsing phase. The reason is the CPython **GIL** (Global Interpreter Lock): parsing operations with `dpkt` and NumPy entropy calculations release the GIL occasionally, but not enough to obtain real parallelism with threads. Independent processes have separate memory spaces and execute with true parallelism on multi-core CPUs.

The `_process_batch()` function is passed to workers via `functools.partial` — the only way to serialize (pickle) a function with additional arguments (`iana_map`, `first_timestamp`) for `ProcessPoolExecutor`.

### 7.2 Active Memory Management

```python
del chunks      # Frees chunks list after concatenation
gc.collect()    # Forces garbage collection immediately
```

After concatenating chunks into a single Polars DataFrame, the chunks list is explicitly deleted and the garbage collector is manually invoked. In multi-hour captures with millions of packets, this operation can reclaim hundreds of megabytes of RAM before the aggregation phase.

### 7.3 Lazy Evaluation in Polars

The entire `_build_base_matrix()` chain — from `group_by` to dynamic Z-scores — is a single `LazyFrame` expression that executes no operations until the final `.collect()`. The Polars optimizer:

- **Fuses** consecutive operations that can be combined into a single pass over the data
- **Eliminates** intermediate columns not used in subsequent steps
- **Parallelizes** independent subtrees of the execution plan across available cores

The result is memory consumption significantly lower than the Pandas equivalent, where each `.assign()` or `.transform()` materializes a copy of the DataFrame.

---

## 8. Robustness and Error Handling

### 8.1 Exception Hierarchy

The module defines a domain-specific exception hierarchy:

```
PcapProcessorError (base)
├── InvalidPcapPathError    — file not found, not accessible, corrupt
└── ProtocolMappingError    — failure in IANA map initialization
```

These exceptions are caught and re-thrown in the orchestrator with additional context, providing traceable error messages to the specific failed operation.

### 8.2 Multi-Datalink Support

The `_batch_generator()` detector identifies the PCAP link layer type before starting iteration:

| Datalink Type | dpkt Constant | Treatment |
|---|---|---|
| Ethernet (IEEE 802.3) | `DLT_EN10MB` | Ethernet frame parse → IP extraction |
| Linux SLL (cooked capture) | `DLT_LINUX_SLL` | SLL header parse → IP extraction |
| Raw IP | `DLT_RAW` | Direct parse as `dpkt.ip.IP` |
| Unknown | — | Generic IP parse attempt; skip if failed |

This detection ensures that captures generated with `tcpdump` on Linux (`-i any`, which produces Linux SLL) are processed correctly without analyst intervention.

### 8.3 Invalid Packet Filtering

Packets are silently discarded (incrementing `skipped_count`) in the following cases:

- IP payload length less than 20 bytes (minimum IP header)
- `dpkt.UnpackError` during parse — malformed or truncated packet
- `AttributeError` / `TypeError` — unexpected layer structure (e.g., tunnels, fragmentation)
- Any uncaught exception during individual packet processing

The final count of processed vs. discarded packets is recorded at the generator's end. A discard rate higher than 5% should alert the analyst to possible PCAP corruption or incomplete captures.

### 8.4 Out-of-Sequence Packets

Packets processed in parallel may arrive at the final DataFrame out of chronological capture order. The post-concatenation `sort("timestamp")` (§3.4) restores the correct order with stability guarantees for equal timestamps (Polars guarantees stability in `sort` by default). Derivative (`diff()`) and rolling window operations (`rolling_std`, `rolling_mean`) are only correct on temporally ordered series — hence why the sort is declared a mandatory operation in code comments.

---

## 9. Integrity Validation: Capture Health Report

The `get_capture_health_report()` method generates a diagnostic report on capture quality before feeding the Feature Matrix to the detection engine. It validates four integrity dimensions:

### 9.1 Statistical Moments

Skewness (*skewness*) and kurtosis (*kurtosis*) of the PPS and entropy distributions are calculated:

$$\text{skewness} = \frac{E\left[(X-\mu)^3\right]}{\sigma^3}, \quad \text{kurtosis} = \frac{E\left[(X-\mu)^4\right]}{\sigma^4} - 3$$

High PPS kurtosis ($\kappa \gg 3$, leptokurtic distribution) indicates the presence of extreme events — traffic bursts or volumetric attacks. Positive skewness in entropy suggests most traffic has low entropy with occasional high-entropy events (e.g., encrypted or compressed traffic).

### 9.2 Temporal Continuity

```python
time_diffs = np.diff(dataframe["timestamp"].values)
max_gap_sec = float(time_diffs.max())
```

The maximum gap between consecutive timestamps detects **Data Drops** — packet losses in the capture, typically caused by network adapter buffer saturation during high-intensity attacks. A gap exceeding the `forensic.data_drop_threshold_seconds` threshold (60s in standard config) is labeled as a Data Drop in the forensic report.

### 9.3 Entropy Physical Limit Validation

The Shannon entropy of a byte payload has a physically bounded range:

$$H \in [0.0, 8.0] \text{ bits}$$

Any value outside this range is a violation of the model's physical limits — a symptom of payload parsing errors or corrupt data. The report counts these violations (`entropy_violations`) as a pipeline health indicator.

### 9.4 Silent Windows

Percentage of 1-second windows with PPS = 0:

$$\text{silent\_pct} = \frac{\#\{w : \text{pps}[w] = 0\}}{N_{\text{windows}}} \times 100$$

A high percentage of silent windows indicates a sporadic capture or a sensor with a low effective sampling rate. Values above 30% should be considered when interpreting velocity and momentum-based anomalies.

---

## 10. Complete Feature Inventory

The following table documents all features produced by `_build_base_matrix()` and their classification within the HiGI pipeline.

### 10.1 Intensity Features

| Feature | Formula | HiGI Family | Scaling |
|---|---|---|---|
| `total_pps_log` | $\log(1 + \text{pps})$ | Volume | RobustScaler |
| `total_bytes_log` | $\log(1 + \text{bytes})$ | Volume | RobustScaler |
| `bytes` | $\sum \text{size}$ | Volume | RobustScaler |
| `size_max` | $\max(\text{size})$ | Volume | RobustScaler |

### 10.2 Composition Features (Ratios)

| Feature | Formula | HiGI Family | Scaling |
|---|---|---|---|
| `{protocol}_ratio` | $\text{count\_proto} / \text{pps}$ | Protocol | Identity |
| `flag_syn_ratio` | $\text{count\_syn} / \text{pps}$ | Flags | Identity |
| `flag_ack_ratio` | $\text{count\_ack} / \text{pps}$ | Flags | Identity |
| `flag_fin_ratio` | $\text{count\_fin} / \text{pps}$ | Flags | Identity |
| `flag_rst_ratio` | $\text{count\_rst} / \text{pps}$ | Flags | Identity |
| `flag_psh_ratio` | $\text{count\_psh} / \text{pps}$ | Flags | Identity |
| `flag_urg_ratio` | $\text{count\_urg} / \text{pps}$ | Flags | Identity |
| `port_scan_ratio` | $\text{unique\_dst\_ports} / \text{pps}$ | Connection | Identity |
| `burst_factor` | $\text{size\_max} / \text{size\_avg}$ | Volume | RobustScaler |

### 10.3 Advanced Physical Dimensions

| Feature | Formula | HiGI Family | Scaling |
|---|---|---|---|
| `flow_duration` | $\max(ts) - \min(ts)$, floor $10^{-6}$ | Connection | RobustScaler |
| `payload_continuity` | $\sum \text{payload\_bytes} / \text{pps}$ | Payload | RobustScaler |
| `iat_mean` | $\text{flow\_duration} / (\max(\text{pps},2) - 1)$ | Connection | RobustScaler |
| `payload_continuity_ratio` | $\sum \text{res\_payload} / (\sum \text{req\_payload} + 10^{-6})$ | Payload | RobustScaler |
| `entropy_avg` | $\overline{H(\text{payload})}$ | Payload | RobustScaler |
| `unique_dst_ports` | $\|\text{dst\_port}\|_{\text{distinct}}$ | Connection | RobustScaler |

### 10.4 Kinematic Features

| Feature | Formula | HiGI Family | Scaling |
|---|---|---|---|
| `pps_velocity` | $\Delta \text{total\_pps\_log}$ | Volume | RobustScaler |
| `bytes_velocity` | $\Delta \text{total\_bytes\_log}$ | Volume | RobustScaler |
| `entropy_velocity` | $\Delta \text{entropy\_avg}$ | Payload | RobustScaler |
| `pps_acceleration` | $\Delta^2 \text{total\_pps\_log}$ | Volume | RobustScaler |
| `bytes_acceleration` | $\Delta^2 \text{total\_bytes\_log}$ | Volume | RobustScaler |
| `entropy_acceleration` | $\Delta^2 \text{entropy\_avg}$ | Payload | RobustScaler |
| `pps_volatility` | $\sigma_5(\text{total\_pps\_log})$ | Volume | RobustScaler |
| `bytes_volatility` | $\sigma_5(\text{total\_bytes\_log})$ | Volume | RobustScaler |
| `entropy_volatility` | $\sigma_5(\text{entropy\_avg})$ | Payload | RobustScaler |
| `pps_momentum` | $\sum_5 \mathbf{1}[\text{pps\_log} > 1.5\mu_{10}]$ | Volume | RobustScaler |

### 10.5 Regime Detection Features (v2.3.0)

| Feature | Formula | HiGI Tier | Scaling |
|---|---|---|---|
| `vel_pps_z` | $(\text{pps\_log} - \mu_{60}) / (\sigma_{60} + 10^{-6})$ | Tier 4 (Velocity Bypass) | RobustScaler |
| `vel_bytes_z` | $(\text{bytes\_log} - \mu_{60}) / (\sigma_{60} + 10^{-6})$ | Tier 4 (Velocity Bypass) | RobustScaler |
| `vel_syn_z` | $(\text{syn\_ratio} - \mu_{60}) / (\sigma_{60} + 10^{-6})$ | Tier 4 (Velocity Bypass) | RobustScaler |

### 10.6 Metadata Columns (Unscaled)

| Column | Description | Responsible |
|---|---|---|
| `_abs_timestamp` | Absolute UNIX timestamp of the first packet in the window | `orchestrator.py` |
| `server_port` | Identified service port in the window | `orchestrator.py` |

---

*HiGI IDS — Network Intelligence Unit. 2026.* *Document generated from static analysis of [`src/ingestion/processor_optime.py`](/src/ingestion/processor_optime.py) v2.3.0.* *For description of downstream detection engine, see [`docs/reference/eng/engine_documentation.md`](/docs/eng/Higi_manual.md).*