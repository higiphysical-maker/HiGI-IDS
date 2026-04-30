# HiGI IDS — Forensic Intelligence and Attribution Manual (XAI)

**Version:** 2.0.0 · **Engine:** [`forensic_engine.py`](/src/analysis/forensic_engine.py) · **Ecosystem:** HiGI IDS v4.0  
**Classification:** Internal Technical Documentation — SOC / Blue Team  
**Reference Format:** IEEE / MITRE ATT&CK v14

---

## Table of Contents

1. [Foundables of Forensic Attribution](#1-foundations-of-forensic-attribution)
2. [Culprit Feature Logic](#2-culprit-feature-logic)
3. [Polarity and Event Analysis: SPIKE vs. DROP](#3-analysis-of-polarity-and-events-spike-vs-drop)
4. [Physical Family Taxonomy](#4-taxonomy-of-physical-families)
5. [MITRE ATT&CK Tactical Mapping](#5-mitre-attck-tactical-mapping)
6. [Grouping and Persistence — Debounce Logic](#6-grouping-and-persistence--debounce-logic)
7. [Dynamic Severity Metrics (DSS)](#7-dynamic-severity-metrics-dss)
8. [Interpretation of Visual Evidence](#8-interpretation-of-visual-evidence)
9. [Glossary of Technical Terms](#9-glossary-of-technical-terms)

---

## 1. Foundations of Forensic Attribution

### 1.1 The Core Problem: From Mathematics to Intelligence

An anomaly detector produces, in its most elementary form, a binary response: _normal_ or _anomalous_. This output is mathematically correct but operationally useless for a SOC analyst. The critical question is not _"is there an anomaly?"_ but _"which physical characteristic of the traffic has changed, in what direction, with what magnitude, and to which adversary tactic does it correspond?"_

The HiGI `ForensicEngine V2` solves this problem through a four-stage causal attribution pipeline:

```
Mathematical anomaly (σ > threshold)
        ↓
Identification of the culprit feature (weighted max |σ|)
        ↓
Classification by physical family (Flags / Volume / Payload / ...)
        ↓
MITRE ATT&CK tactical mapping (tactic + technique)
```

### 1.2 The Traffic Inertial Reference Frame

In classical mechanics, an *inertial reference frame* is one in which Newton's laws are valid: an object at rest remains at rest unless acted upon by an external force. In HiGI's forensic analysis, the **Monday baseline** (office traffic without attacks) constitutes the exact equivalent of that inertial frame.

Formally, let $\mathbf{x}_t \in \mathbb{R}^d$ be the vector of physical traffic features in time window $t$, and let $\mathcal{N}(\boldsymbol{\mu}_0, \boldsymbol{\Sigma}_0)$ be the baseline distribution, where $\boldsymbol{\mu}_0$ and $\boldsymbol{\Sigma}_0$ are the mean and covariance estimated during training on Monday.

**Definition — Traffic Inertial Reference Frame:**

> The inertial reference system is the distribution $\mathcal{N}(\boldsymbol{\mu}_0, \boldsymbol{\Sigma}_0)$ of the baseline traffic. In the absence of adversarial perturbations, the observed traffic $\mathbf{x}_t$ is a sample point from this distribution. An attack acts as an **external force** that displaces $\mathbf{x}_t$ outside the high-density region of the reference distribution.

The magnitude of the displacement is measured using the **Mahalanobis distance** between $\mathbf{x}_t$ and the center of the inertial frame:

$$D_M(\mathbf{x}_t) = \sqrt{(\mathbf{x}_t - \boldsymbol{\mu}_0)^\top \boldsymbol{\Sigma}_0^{-1} (\mathbf{x}_t - \boldsymbol{\mu}_0)}$$

This metric is superior to Euclidean distance because it is normalized by the baseline covariance: a deviation of 100 bytes/s might be insignificant in a datacenter network but catastrophic in a home network. Mahalanobis distance is invariant to the scale of each feature.

### 1.3 Projection to Hilbert Space via Blocked PCA

Before reaching the forensic engine, `higi_engine.py` projects the vector $\mathbf{x}_t$ to the **Hilbert space** using a Blocked PCA by physical families. This projection has two effects that are fundamental for forensic attribution:

**Effect 1 — Decorrelation within each family.** Features within the same family (e.g., `bytes_in`, `bytes_out`, `pps`) are highly correlated with each other. PCA per family extracts the directions of maximum variance (principal components $\mathbf{v}_k^{(f)}$), eliminating redundancy.

**Effect 2 — Preservation of physical semantics.** Unlike a global PCA, Blocked PCA guarantees that each principal component $\text{PC}_k^{(f)}$ belongs exclusively to family $f$. The forensic engine can thus track which component triggered the anomaly and map it directly to the corresponding physical family using the `_blocked_pca_family_mapping` metadata.

Formally, let $\mathbf{W}^{(f)} \in \mathbb{R}^{d_f \times k_f}$ be the loading matrix for family $f$. The projection is:

$$\mathbf{z}_t^{(f)} = {\mathbf{W}^{(f)}}^\top (\mathbf{x}_t^{(f)} - \boldsymbol{\mu}_0^{(f)})$$

where $\mathbf{x}_t^{(f)}$ is the sub-vector of features belonging to family $f$. The projected Hilbert space has the property that the Euclidean distance within it approximates the Mahalanobis distance in the original space.

### 1.4 The Digital Chain of Custody

The legal concept of *chain of custody* requires that all evidence be traceable from its origin to its conclusion. `ForensicEngine V2` implements this principle computationally: each reported incident includes the identifier of the tier that triggered the alert, the specific feature, the magnitude in $|\sigma|$, the percentage change, the direction (SPIKE/DROP), the physical family, and the MITRE technique. No inference step exists that is not completely auditable.

---

## 2. Culprit Feature Logic

### 2.1 Mathematical Definition of the Culprit Feature

For each time window $t$ classified as anomalous, `higi_engine.py` computes the **deviation score** of each feature $f_j$ of the observed vector relative to the baseline:

$$\sigma_j(t) = \frac{x_j(t) - \mu_{0,j}}{s_{0,j}}$$

where $\mu_{0,j}$ and $s_{0,j}$ are the estimated baseline mean and standard deviation for the $j$-th feature. This is the standard Z-score of a normal random variable.

The **primary culprit feature** of window $t$ is defined as:

$$j^*(t) = \arg\max_{j \in \{1,\ldots,d\}} \left| \sigma_j(t) \right|$$

This choice has a precise statistical justification: under the hypothesis that an attack acts predominantly on a small subset of features (adversarial sparsity hypothesis), the feature with the largest absolute deviation has the highest discriminative power, analogous to the Portmanteau statistic in time series.

The resulting annotation consumed by the forensic engine follows the format:

```
flag_syn_ratio (SPIKE (+865%), σ=4.2) | GMM: pps_acc (LL=-3.2)
```

The `_extract_sigma()` method extracts $|\sigma_j|$ using the regular expression `σ\s*=\s*([\d.]+)`, and `_extract_pct()` extracts the relative percentage change:

$$\Delta\%(t) = \frac{x_j(t) - \mu_{0,j}}{\mu_{0,j}} \times 100$$

### 2.2 Loading Normalization for Comparability between Incidents

Within an incident of duration $T$ windows, the same feature may trigger with different magnitudes in each window. To produce a stable ranking, the engine aggregates using the **maximum** (not the mean) and then normalizes:

$$\ell_j = \frac{\max_{t \in T} |\sigma_j(t)|}{\max_{j'} \max_{t \in T} |\sigma_{j'}(t)|}$$

This $\ell_j \in [0, 1]$ is the **Loading Magnitude** of feature $j$ in the incident, corresponding to the `loading_magnitude` field of `FeatureAttribution`. Ranking by decreasing $\ell_j$ produces the Top-3 features of the XAI.

Normalization by the incident's maximum (and not by a global constant) has an important consequence: the loading is **relative to the incident**, not absolute. A loading of 1.0 means that feature had the highest deviation of all in that incident, regardless of whether $|\sigma| = 5$ or $|\sigma| = 216,000$.

### 2.3 Extraction of the Feature Base Name

Culprit annotations may contain additional text (event type, sigma, GMM probability). The `_extract_base_name()` method implements a regular expression parser:

```python
match = re.match(r"^([a-z_][a-z0-9_]*)", str(raw).strip(), re.IGNORECASE)
```

The expression `[a-z_][a-z0-9_]*` captures the canonical Python identifier of the feature (the column name) and discards the rest of the annotation. This guarantees that `flag_syn_ratio (SPIKE (+865%), σ=4.2)` is reduced to `flag_syn_ratio`, which is the lookup key in the MITRE dictionary.

### 2.4 Resolution of Conflicts between Tiers

When multiple tiers report different culprits (BallTree points to `bytes` while GMM points to `iat_mean`), the forensic engine does not vote: it uses the `physical_culprit` column embedded in the CSV by the orchestrator, which is determined by the Physical Sentinel (Tier 3) when available, as it operates on individual features and has the highest spatial resolution.

---

## 3. Analysis of Polarity and Events: SPIKE vs. DROP

### 3.1 Formal Definition of Polarity

The polarity of an event is determined by the sign of the Z-score of the culprit feature in the anomalous window:

$$\text{Polaridad}(t) = \text{sgn}\left(\sigma_{j^*}(t)\right) = \text{sgn}\left(x_{j^*}(t) - \mu_{0,j^*}\right)$$

- **SPIKE** ($\text{sgn} = +1$, $\Delta\% \gg 0$): The observed value significantly exceeds the baseline mean. Traffic in that dimension is more intense than expected.
- **DROP** ($\text{sgn} = -1$, $\Delta\% < 0$): The observed value falls significantly below the baseline mean. Traffic in that dimension is less intense than expected.

### 3.2 Physical Semantics of Polarity by Feature

Polarity is not symmetric in terms of threat. The following table shows the correct forensic interpretation based on the feature and polarity:

| Feature | SPIKE (value > baseline) | DROP (value < baseline) | Predominant Threat |
|---|---|---|---|
| `iat_mean` | Irregularly slow connections / regular C2 cadence | High-frequency flood / saturation | Slowloris (SPIKE), DoS (DROP) |
| `payload_continuity_ratio` | Completely different payloads between packets (Brute Force, fuzzing) | Identical repeated payloads (deterministic attack loop) | BF/XSS (SPIKE), replay (DROP) |
| `flag_syn_ratio` | SYN flood / open port scanning | Handshake drop (massive RST blocking) | SYN Flood (SPIKE) |
| `flag_urg_ratio` | Nmap with special flags / TCP Xmas scan | — (URG should never drop in baseline) | Active Reconnaissance (SPIKE) |
| `bytes` | Volumetric attack / massive exfiltration | Low bandwidth covert channel | DoS Hulk (SPIKE), Beaconing (DROP) |
| `unique_dst_ports` | Port scan / socket exhaustion | Concentrated access on a single service | Reconnaissance (SPIKE) |
| `icmp_ratio` | ICMP flood / ping sweep / server error responses | ICMP blocking by firewall after attack | ICMP DoS (SPIKE), side effect (SPIKE) |

### 3.3 The Asymmetric Case: `iat_mean` as a Bidirectional Detector

The `iat_mean` feature (mean inter-arrival time between packets) is the most instructive example of semantic polarity asymmetry:

**SPIKE in `iat_mean`:** The average time between successive packets is greater than normal. Physically, this means packets are arriving slower. An attacker executing Slowloris or Slowhttptest keeps HTTP connections open by sending one header at a time, with deliberate pauses of several seconds between them. From the victim server's perspective, `iat_mean` increases dramatically compared to office traffic (where users browse continuously). In incident #12 of [Thursday](../reports/forensic_thursday/Thursday_Victim_50_results_FORENSIC.md) (Brute Force), `iat_mean` = +18,315% with +52.43σ — the regular cadence of the Burp Suite scanner produces a more uniform and slightly longer IAT than irregular human traffic.

**DROP in `iat_mean`:** The time between packets is less than normal. This indicates a higher-than-expected transmission rate. A volumetric DoS flood (Hulk) sends packets at the attacker's maximum possible speed, reducing the IAT to its minimum. On [Wednesday](../reports/forensic_wednesday/Wednesday_Victim_50_results_FORENSIC.md), the DoS Hulk incident shows a SPIKE in `bytes` (volume), but IAT drops are absorbed by Tier 4 (Velocity Bypass).

Formally, the correct interpretation of a SPIKE in `iat_mean` is:

$$\Delta\text{IAT} = \bar{t}_{\text{observed}} - \bar{t}_{\text{baseline}} \gg 0 \implies \text{deliberate slow connections} \lor \text{regular C2 cadence}$$

### 3.4 `payload_continuity_ratio`: The Application Randomness Detector

This feature deserves a detailed explanation because it produces the most extreme $|\sigma|$ values in the dataset (up to 38,836σ for the Brute Force on [Thursday](../reports/forensic_thursday/Thursday_Victim_50_results_FORENSIC.md)).

Let $P_t$ be the set of payload bytes observed in window $t$, and let $P_{t-1}$ be that of the previous window. The continuity ratio measures what fraction of the current payload is "new" relative to recent history:

$$\rho_t = 1 - \frac{|P_t \cap P_{t-1}|}{|P_t \cup P_{t-1}|}$$

Normal office traffic (loading cached web pages, compressed video streams) has a moderately stable $\rho_t$: there is some variation but within the HTTP/HTTPS compression space.

An HTTP POST Brute Force has $\rho_t \approx 1$ in each window because each request contains a unique combination of credentials. The Monday baseline has $\bar{\rho}_0$ with low variance. The distance in sigmas is therefore:

$$\sigma_{\rho}(t) = \frac{\rho_t - \bar{\rho}_0}{s_{\rho_0}} \approx \frac{1 - \bar{\rho}_0}{s_{\rho_0}}$$

If $s_{\rho_0}$ is small (baseline is stable), the fixed numerator produces a denominator that amplifies the deviation to values of tens of thousands of sigmas. This is not a numerical artifact: it is the correct mathematical consequence of the fact that Brute Force generates a payload novelty that is **statistically impossible** under the baseline model.

---

## 4. Taxonomy of Physical Families

### 4.1 Taxonomy Design Principle

HiGI's physical families are not arbitrary feature categories: they are **subspaces of the network state space** that capture independent modes of behavior. Network traffic can be abnormal in its *volume* without being so in its *flag composition*, and vice-versa. Separation by families allows the analyst to identify precisely which of the five network operation modes has been disturbed.

Classification is implemented in `_infer_family()` through a two-level precedence system:

1. **Primary level:** `family_consensus` column of the CSV, populated by the orchestrator from the `_blocked_pca_family_mapping` metadata of the ArtifactBundle. This is the source of truth when the Blocked-PCA engine is available.

2. **Secondary level (fallback):** Keyword matching in the culprit feature name. The keyword dictionary defines the semantic space for each family.

### 4.2 `flags` Family — TCP Control Manipulation

**Physical definition:** TCP flags (SYN, RST, FIN, ACK, URG, PSH) are control bits of the TCP protocol that govern the lifecycle of connections. In normal traffic, their distribution reflects the proportion of new connections (SYN), established transfers (ACK), and closures (FIN/RST).

**Included features:** `flag_syn_ratio`, `flag_rst_ratio`, `flag_fin_ratio`, `flag_ack_ratio`, `flag_urg_ratio`, `flag_psh_ratio`.

**Adversarial reasoning:** An attacker manipulating TCP flags is acting directly on the transport protocol, not the application content. This makes it:

- **Difficult to encrypt:** TCP headers are not encrypted in TLS. An IDS analyzing flags is effective even over HTTPS traffic.
- **Difficult to mask:** The flag distribution in normal traffic is very stable (≈ 60% ACK, 20% SYN, 15% FIN, 5% RST in typical office traffic). Any deviation is statistically significant.

**Typical signatures by technique:**

| Feature | Anomalous Value | Adversarial Technique |
|---|---|---|
| `flag_syn_ratio` ↑ | > 3σ | SYN Flood (T1498.001) |
| `flag_rst_ratio` ↑ | > 2σ | RST Flood, massive connection rejection (T1499.002) |
| `flag_fin_ratio` ↑ | > 2σ | Stealth FIN Scan (T1595) |
| `flag_urg_ratio` ↑ | > 5σ | Nmap Xmas/URG scan, OS fingerprinting (T1046) |
| `flag_syn_ratio` ↓ | < −2σ | Firewall blocking SYN after previous flood |

### 4.3 `volume` Family — Communication Channel Overuse

**Physical definition:** Measures the amount of data transferred per unit of time. It is the equivalent of *intensity* in wave physics: I = P/A (power per unit area). A volumetric attack is, literally, a perturbation of the communication channel's intensity.

**Included features:** `bytes`, `pps` (packets per second), `traffic_volume`, `bandwidth`.

**Adversarial reasoning:** Volumetric attacks do not require technical sophistication — only bandwidth. However, they are devastating because they saturate the communication channel, preventing legitimate traffic. Blocked PCA on the `volume` family is especially effective because the covariance between `bytes` and `pps` in the baseline is very stable (correlation coefficient ~0.85 in typical office traffic). A volumetric DoS breaks this covariance: it can increase `pps` without proportionally increasing `bytes` if using small packets (ICMP flood), or increase `bytes` without increasing `pps` if using large packets.

**Covariance invariance as a volumetric attack detector:**

In the reduced space of the `volume` family PCA, the baseline distribution forms an ellipse whose principal axis follows the bytes-pps correlation. A DoS displaces the observed point outside this ellipse. The Physical Sentinel (Tier 3) detects this displacement with higher precision than a simple volume threshold.

### 4.4 `payload` Family — Application Layer Content

**Physical definition:** Analyzes the statistical properties of packet content: its entropy, size, variability, and temporal continuity.

**Included features:** `payload_continuity_ratio`, `payload_continuity`, `entropy_anomaly`, `size_max`, `size_min`.

**Why the `payload` family reveals application attacks:**

Layer 7 (application) attacks — Brute Force, XSS, SQL Injection — operate on the content of HTTP/HTTPS requests, not on packet structure. They do not dramatically modify TCP flags or volume. However, they inevitably modify the **statistical properties of the payload**:

1. **Brute Force:** Each POST request contains different credentials → high entropy, maximum `payload_continuity_ratio`, stable `size_max`.
2. **XSS fuzzing:** Each request contains different JavaScript injection vectors → high entropy (special characters `<script>`, `onerror=`), elevated `payload_continuity_ratio`.
3. **SQL Injection:** SQL queries have specific syntactic structures that raise entropy relative to normal HTML traffic.

**The critical argument for TLS environments:** Even with encrypted traffic (HTTPS), the `payload` family is partially observable. Packet sizes (`size_max` field) and the number of packets per connection are visible in plain text in TCP/IP headers. An HTTPS Brute Force generates a different distribution of packet sizes compared to normal browsing traffic (credential POST forms have a characteristic size). Encrypted payload entropy tends toward ~8 bits/byte (maximum entropy), which in itself is a signature: office traffic has compressed text with variable entropy and a mean of ~6.5 bits/byte.

### 4.5 `connection` Family — Connection Topology

**Physical definition:** Describes how the victim host is being contacted: from how many different ports, with what new connection rate, with what flow duration.

**Included features:** `unique_dst_ports`, `connection_rate`, `port_scan_ratio`, `flow_duration`, `iat_mean`.

**Adversarial reasoning:** Connection topology is the signature of the *who* and *how* of an attack, not the *what*:

- A socket-exhaustion (Slowloris) opens hundreds of simultaneous connections to port 80 from multiple source ports → `unique_dst_ports` ↑, `connection_rate` ↑, `flow_duration` ↑.
- A port scan opens a brief connection to each destination port → `unique_dst_ports` ↑↑, `flow_duration` ↓ (very brief connections).
- A C2 beaconing opens a periodic connection to the C2 server with very regular IAT → abnormally stable `iat_mean` (low variance in IAT).

### 4.6 `protocol` Family — Traffic Composition by Protocol

**Physical definition:** Measures the fraction of traffic for each network protocol (UDP, TCP, ICMP, DNS, TTL).

**Included features:** `udp_ratio`, `icmp_ratio`, `ttl_anomaly`, `dns_spike`, `protocol_anomaly`.

**Adversarial reasoning:** Protocol distribution in a network is very stable during office hours. An attacker using an unusual protocol (ICMP for exfiltration, DNS for C2, UDP for amplification) breaks this distribution in a measurable way. Anomalous TTL can indicate source IP spoofing (the TTL does not match the expected distance from the origin).

### 4.7 `kinematics` Family — Temporal Traffic Dynamics

**Physical definition:** Measures not the state of traffic but its *time derivative*: the rate of volume change, connection acceleration, payload volatility.

**Included features:** `bytes_volatility`, `pps_volatility`, `entropy_volatility`.

**Adversarial reasoning:** Some attacks are not distinguishable from normal traffic looking at instantaneous values, but are if looking at their temporal dynamics. A GoldenEye flood keeps byte volume relatively constant, but does so with a payload volatility (continuous keepalives with modified content) that does not exist in normal traffic. The `kinematics` family captures these second-order perturbations.

---

## 5. MITRE ATT&CK Tactical Mapping

### 5.1 Mapper Architecture

The HiGI MITRE mapper implements an inference function $\mathcal{M}: \text{feature\_base} \to (\text{tactic}, \text{technique})$ defined by the `MITRE_ATT_CK_MAPPING` dictionary. This function operates on the primary culprit feature name (not on the attack type, which the system does not know a priori).

```python
MITRE_ATT_CK_MAPPING: Dict[str, Tuple[str, str]] = {
    "flag_syn_ratio":   ("Impact",          "T1498.001 – SYN Flood"),
    "flag_urg_ratio":   ("Reconnaissance",  "T1046 – Network Service Discovery"),
    "unique_dst_ports": ("Reconnaissance",  "T1046 – Network Service Discovery"),
    "iat_mean":         ("Command & Control", "T1071 – Beaconing / Irregular IAT"),
    ...
}
```

The `_map_mitre()` method iterates over the incident's culprit annotations, extracts the base name, looks it up in the dictionary, and groups results by tactic:

```
{
    "Reconnaissance":    ["T1046 – Network Service Discovery", "T1595.001 – ..."],
    "Command & Control": ["T1071 – Beaconing / Irregular IAT"],
    "Impact":            ["T1498.001 – SYN Flood"]
}
```

### 5.2 Why Mapping from Physical Features is Robust Against Encryption

The standard MITRE mapping approach (based on content signatures or payload patterns) fails completely against TLS 1.3, which encrypts even application layer headers. HiGI avoids this problem because its features belong to layers observable even in encrypted traffic:

| Observable Layer (Always) | HiGI Features | Detectable MITRE Techniques |
|---|---|---|
| TCP flags (L4) | `flag_*_ratio` | T1498.001, T1499.002, T1595, T1046 |
| Packet Size (L3/L4) | `size_max`, `bytes` | T1048, T1001.003 |
| Timing (L3/L4) | `iat_mean`, `flow_duration` | T1071, T1573 |
| Port Distribution (L4) | `unique_dst_ports`, `port_scan_ratio` | T1046, T1595.001 |
| Protocol Ratio (L3/L4) | `udp_ratio`, `icmp_ratio` | T1498.001, T1071.004 |

The consequence is that HiGI can infer the MITRE tactic of an encrypted HTTPS/TLS attack without decrypting a single byte of payload. The attacker can encrypt their content, but they cannot hide the *rhythm*, *volume*, *flag structure*, and *port distribution* of their traffic.

### 5.3 Limitations of the Current Mapper and Proposed Improvements

**Limitation 1 — Single-level granularity.** The current mapper assigns one technique per feature without considering incident context. For example, `flag_syn_ratio` always maps to T1498.001 (SYN Flood) even if the SYN increase is a consequence of a Brute Force (many new HTTP connections). An improvement would be to implement a second-level mapper that simultaneously queries destination port, dominant family, and duration:

$$\mathcal{M}_2(\text{feature}, \text{port}, \text{family}, \text{duration}) \to (\text{tactic}, \text{technique})$$

**Limitation 2 — Absence of historical context.** The current mapper does not query previous incidents from the same session. A Reconnaissance incident (T1046) followed 20 minutes later by Impact (T1498) is evidence of an orchestrated attack chain (MITRE Pattern: Recon → Resource Development → Impact). This temporal correlation between incidents is currently outside the forensic engine's scope.

**Limitation 3 — False tactical precision for ambiguous features.** The `iat_mean` feature is always mapped to T1071 (Beaconing), but an IAT increase can be due to either C2 or Slowloris (T1190). Disambiguation requires combining IAT polarity with destination port context and incident duration.

---

## 6. Grouping and Persistence — Debounce Logic

### 6.1 The Problem of Temporal Fragmentation

A sustained 30-minute attack produces ~1,800 windows of 1 second, each potentially classified as anomalous independently. Without a grouping mechanism, the SOC analyst would receive 1,800 alerts for a single event. **Debounce Logic** solves this by grouping temporally contiguous windows into a single `SecurityIncidentV2` object.

### 6.2 Temporal Clustering Algorithm

The algorithm implemented in `cluster_incidents()` operates in $O(n)$ time on the vector of anomalous window timestamps:

**Step 1 — Computation of temporal gaps:**

$$\Delta t_i = t_i - t_{i-1}, \quad i = 1, \ldots, n$$

where $t_i$ is the timestamp of the $i$-th anomalous window.

**Step 2 — Marking incident boundaries:**

$$b_i = \mathbb{1}\left[\Delta t_i > \tau_{\text{debounce}}\right]$$

where $\tau_{\text{debounce}} = 30$ seconds (configurable in `config.yaml`). The first window always marks a boundary ($b_1 = 1$).

**Step 3 — Assignment of group IDs:**

$$g_i = \sum_{k=1}^{i} b_k - 1$$

This monotonic ID assigns the same integer to all windows within the same cluster.

**Step 4 — Construction of `SecurityIncidentV2`:** For each group $g$, an object is created with aggregated windows, and enrichment methods are executed (tier evidence, XAI attribution, family stress, MITRE mapping).

### 6.3 Choice of the $\tau_{\text{debounce}}$ Parameter

The choice of 30 seconds is not arbitrary. it responds to a logic of compromise between two types of error:

- **Debounce too short** ($\tau < 10$ s): An attack with micro-pauses (e.g., a scanner that pauses for 5 seconds between probes) fragments into multiple incidents, generating a false sense of multiple attackers.
- **Debounce too long** ($\tau > 120$ s): A short attack (2-minute SQLi) followed by a pause and a 2-minute XSS merges into a single incident, losing tactical granularity.

 The 30-second value is consistent with TCP retransmission times (maximum 30 s per RFC 6298) — if a gap is larger than a retransmission timeout, it is almost certainly a new network event, not a pause within the same attack.

### 6.4 Persistence and Incident Classification

Within the HiGI ecosystem, incidents are classified by their temporal pattern using the `persistence` column:

| Label | Criterion | Forensic Implication |
|---|---|---|
| `Sustained Attack` | Continuous anomalies for > configurable threshold | Active attack, immediate action required |
| `Transient Spike` | Isolated spike without persistence | Possible false positive or exploratory probe |
| `Data Drop` | Detected telemetry gap | Possible sensor saturation, investigate |

The forensic engine groups by the most frequent `persistence` value within the cluster, reporting it as the incident's `persistence_label`.

### 6.5 Detection of Data Drops (Degraded Telemetry)

The `detect_data_drops()` method operates on the full DataFrame (not just anomalous ones) to detect telemetry gaps. The logic is analogous to debounce but with a separate threshold ($\tau_{\text{drop}} = 60$ s):

$$\text{DataDrop}_i = \mathbb{1}\left[\Delta t_i^{\text{full}} > \tau_{\text{drop}}\right]$$

where $\Delta t_i^{\text{full}}$ is the gap between consecutive observations in the full DataFrame, including normal windows.

Gaps are classified into:

- **Capture Loss / Network Silence:** Gap without previous attack context. Likely legitimate network silence or capture issue.
- **Sensor Blindness / Data Drop due to Saturation:** Gap preceded by an alert of severity ≥ 2. The capture sensor may have saturated during the attack, creating a period of blindness.
- **POSSIBLE_SENSOR_SATURATION:** Gap occurring within 15 seconds of the end of an incident with severity ≥ 2.

---

## 7. Dynamic Severity Metrics (DSS)

### 7.1 Limitations of Discrete Severity

The `severity` field in the CSV takes values in $\{0, 1, 2, 3\}$ where 3 = Critical. This scale is binary in practice: an incident with `severity = 3` could have lasted 30 seconds or 30 minutes, with $|\sigma| = 4$ or $|\sigma| = 216,000$. Discrete severity does not capture the *physical magnitude* of the event.

The **Dynamic Severity Score (DSS)** introduces a continuous metric $\mathbb{R}_{\geq 0}$ that combines baseline distance with attack persistence.

### 7.2 Dynamic Severity Score Formula

$$\text{DSS}(I) = \sigma_{\text{score}}(I) \cdot \left(1 + P(I)\right)$$

where the components are:

**Component $\sigma_{\text{score}}$** — Distance to the P99 boundary:

$$\sigma_{\text{score}}(I) = \begin{cases} \dfrac{\sigma_{\max}(I)}{5.0} & \text{if } \sigma_{\max}(I) \leq 5 \\[6pt] 1.0 + \dfrac{(\sigma_{\max}(I) - 5.0)^{1.8}}{10.0} & \text{if } \sigma_{\max}(I) > 5 \end{cases}$$

with $\sigma_{\max}(I) = \max_{t \in I} |\sigma_{j^*}(t)|$.

The transition at $\sigma = 5$ has a direct statistical justification: under a normal distribution, $P(|Z| > 5) \approx 5.7 \times 10^{-7}$, meaning a 5σ deviation occurs less than once per million windows under the baseline. Below 5σ, the scale is linear (proportional to distance). Above, the 1.8 exponent introduces a non-linear amplification that prevents extreme attacks (like Hulk with 857σ) from being attenuated to the same scale as moderate attacks.

**Component $P(I)$** — Persistence Boost (logarithmic scale):

$$P(I) = \frac{\ln(1 + n_I)}{\ln(1 + 100)}$$

where $n_I$ is the number of anomalous windows in the incident. This function is logarithmic for two reasons:

1. The first 10 minutes of an attack are much more informative than the next 10 minutes (law of diminishing returns for persistence).
2. It prevents very long incidents (>100 windows) from dominating the ranking simply due to their duration.

### 7.3 Consensus Confidence Index (CCI)

The **Consensus Confidence Index** measures how much of the detection "tribunal" agrees on reporting the incident. The formula implemented in the `consensus_confidence` property combines three independent signals:

$$\text{CCI}(I) = 0.45 \cdot C_{\text{base}} + 0.35 \cdot C_{\text{volume}} + 0.20 \cdot C_{\text{tier}}$$

**Base component** $C_{\text{base}}$ — Statistical rarity of the deviation:

$$C_{\text{base}} = \Phi\left(\bar{\sigma}(I)\right)$$

where $\Phi(\cdot)$ is the CDF of the standard normal distribution and $\bar{\sigma}(I)$ is the mean of $|\sigma_{j^*}(t)|$ in the incident. This function maps any mean deviation $\bar{\sigma}$ to the probability that the event is NOT noise under the baseline:

- $\bar{\sigma} = 1$: $\Phi(1) = 0.841$ → 84.1% confidence
- $\bar{\sigma} = 2$: $\Phi(2) = 0.977$ → 97.7% confidence
- $\bar{\sigma} = 3$: $\Phi(3) = 0.9987$ → 99.87% confidence

**Volume component** $C_{\text{volume}}$ — Logarithmic saturation of persistence:

$$C_{\text{volume}} = \min\left(1.0, \frac{\log_2(1 + n_I)}{\log_2(513)}\right)$$

The function saturates at $n_I = 512$: an incident with 512 or more windows receives the maximum for this component. The value 513 = $2^9 + 1$ guarantees that $\log_2(512) / \log_2(513) \approx 1$.

**Tier component** $C_{\text{tier}}$ — Weighted fraction of the triggered tribunal:

$$C_{\text{tier}} = \frac{\sum_{k} w_k \cdot \mathbb{1}[\text{Tier}_k \text{ fired}]}{\sum_{k} w_k}$$

where the weights are:

| Tier | $w_k$ | Weight Justification |
|---|---|---|
| BallTree | 0.20 | Geometric detector, good in high-dimensional space |
| GMM | 0.25 | Probabilistic model with higher discriminative power |
| IForest | 0.20 | Robust to outliers, good for low-density anomalies |
| Physical Sentinel | 0.20 | Operates on individual features, high spatial resolution |
| Velocity Bypass | 0.15 | Complementary, triggered only in high-speed events |

Physical Sentinel and GMM receive the highest weights because they are the hardest to fool: GMM requires the point to leave the high-density region in the complete multivariate space, and Physical Sentinel confirms at least one individual feature is in an impossible regime.

**Warm-up Penalty:**

$$\text{CCI}_{\text{final}} = \begin{cases} 0.5 \cdot \text{CCI}(I) & \text{if } I.\text{is\_warmup} \\ \text{CCI}(I) & \text{otherwise} \end{cases}$$

Incidents during the detector's warm-up period (first windows after startup) receive a 50% confidence penalty to reduce false positive pressure during model stabilization.

---

## 8. Interpretation of Visual Evidence

### 8.1 Attack Intensity Timeline (Figure 1)
![Timeline](../reports/forensic_wednesday/Wednesday_Victim_50_results_timeline.png)*Figure 1: Attack timeline for Wednesday from the CIC IDS 2017 dataset*

#### Chart Structure

The Intensity Timeline is a temporal area chart with four layers of overlapping information:

**Layer 1 — Background signal (dark grey):** The baseline of the `anomaly_ma_score` or the `severity` field over the entire capture period, including normal windows. This layer provides the "background noise" context and allows visual identification of what fraction of time anomalous activity occurs.

**Layer 2 — Colored severity fills:**

```
Yellow (#f1c40f) → Severity 1 (Low)  — Single tier detection
Orange (#e67e22) → Severity 2 (High) — Majority tier consensus
Red    (#e74c3c) → Severity 3 (Critical) — Tribunal unanimity
```

The `fill_between()` fill colors the area under the curve only in windows where severity reaches the corresponding threshold. The overlapping colors (stacked fills) make maximum severity peaks appear visually as "red peaks emerging from an orange and yellow base," faithfully reflecting the cascading nature of detection.

**Layer 3 — Velocity Bypass markers (teal triangles):** Triangles pointing downwards (`marker="v"`) indicate windows where Tier 4 (Velocity Bypass) triggered independently, without needing tribunal consensus. These markers are diagnostically important: they signal moments of extreme arrival rate that the velocity Z-score directly classified as critical.

**Layer 4 — Incident annotations (blue callouts):** Blue text boxes with arrows identify incidents with the highest `dynamic_severity_score`. The box text includes the incident ID and the primary culprit feature, allowing the analyst to correlate the visual peak with the physical cause without consulting the detailed table.

#### What to Look for in the Timeline

**Sustained attack pattern:** A continuous orange/red fill region lasting minutes. Indicates a persistent attack (sustained DoS, Brute Force). The horizontal width on the time axis corresponds directly to attack duration.

**Repetitive pulse pattern:** Multiple discrete peaks separated by periods of normality. Indicates an attack in waves (port scan with multiple passes) or a C2 with periodic beaconing. The separation between peaks is the beaconing period or re-scanning interval.

**Single high-intensity peak pattern:** A single peak of very short duration but with `severity = 3`. May indicate a single-packet exploit (buffer overflow), a surgical SQL injection, or the explosive start of a flood before sensor saturation.

**Increasing intensity transition:** The Y-axis (logarithmic when `anomaly_ma_score` varies across several orders of magnitude) shows if the attack scales in intensity. A positive slope on the temporal axis indicates an accelerating attack.

### 8.2 Physical Family Stress Radar (Figure 2)
![Radar Stress](../reports/forensic_wednesday/Wednesday_Victim_50_results_radar.png)
*Figure 2: Physical Family Stress Radar - Attack vector analysis for Wednesday's dataset.*

#### Chart Structure

The Stress Radar is a polar chart with six axes, one per physical family:

```
Top axis:         Payload
Top-left axis:    Flags
Left axis:        Protocol
Bottom axis:      Connection
Bottom-right axis: Kinematics
Right axis:       Volume
```

Each axis has a [0, 1] scale where 1 represents that family contributing 100% of the incident's anomaly load. The filled surface (semi-transparent blue fill) represents the normalized stress distribution:

$$s_f = \frac{\text{estrés}_f}{\sum_{f'} \text{estrés}_{f'}}$$

where family stress is the sum of $|\sigma|$ for all culprit features belonging to that family throughout the incident.

#### What to Look for in the Radar

**Unbalanced radar — specific vector attack:** If a single family dominates the radar (e.g., `Flags` occupies 70% of the area), the attack is using a very specific vector. An Nmap scan produces absolute dominance of `Flags` (URG) and `Connection` (unique_dst_ports). An HTTP Brute Force produces dominance of `Payload` (payload_continuity_ratio) and `Connection` (iat_mean).

**Balanced radar — multi-vector attack:** If all families have similar stress, it may indicate a sophisticated attack deliberately distributing its effects to evade family-based threshold detection. It can also indicate multiple attackers or techniques active simultaneously.

**Thursday interpretation (real example):** The Thursday radar shows clear dominance of `Payload` (≈35%), `Flags` (≈30%), and `Connection` (≈20%), with moderate `Volume` (≈10%) and residual `Protocol` and `Kinematics`. This distribution is consistent with Thursday's attack mix: Layer 7 Web Attacks (dominating Payload and Connection) + Nmap scan (dominating Flags: URG ratio).

#### Correlation between Timeline and Radar

The most powerful analysis is obtained by correlating both figures:

1. Identify maximum intensity periods (red peaks) in the **Timeline**.
2. Verify which family dominates stress in the **Radar**.
3. Consult the incident's **XAI Attribution Table** for the specific feature.
4. Verify the corresponding **MITRE tactic**.

This four-step analysis flow allows a SOC analyst to go from "there is an alert" to "it is an Nmap Xmas scan attacking the web server" in less than 2 minutes, without needing to review PCAP captures or manually correlate logs.

---

## 9. Glossary of Technical Terms

| Term | Definition |
|---|---|
| **Anomaly MA Score** | Moving Average of the multi-tier anomaly score. Smooths transient spikes to distinguish persistent attacks from noise. |
| **ArtifactBundle** | `.pkl` file encapsulating the complete trained model: BallTree, GMM, IForest, Blocked PCA loadings, and family metadata. |
| **Baseline** | Statistical distribution of network traffic during a normal activity period (Monday without attacks). The system's inertial reference frame. |
| **Blocked PCA** | PCA applied by blocks (feature families) rather than globally. Preserves the physical semantics of each family. |
| **BallTree** | Data structure for efficient k-nearest neighbors search in the projected Hilbert space (Tier 1). |
| **CCI** | Consensus Confidence Index. Composite metric [0,1] weighting statistical rarity, persistence, and tribunal consensus. |
| **Culprit Feature** | Physical feature with the highest absolute deviation $|\sigma_{j^*}|$ in an anomalous window. The alert's "primary responsible." |
| **Debounce** | Temporal clustering mechanism grouping anomalous windows separated by less than $\tau_{\text{debounce}}$ seconds into a single incident. |
| **DSS** | Dynamic Severity Score. Continuous metric $[0, \infty)$ combining baseline distance with attack persistence. |
| **DROP** | Event where the observed value falls significantly below the baseline mean ($\sigma_{j^*} < 0$). |
| **Family Stress** | Normalized fraction of anomaly load (in $|\sigma|$) attributed to each physical family. Represented in the Radar. |
| **GMM** | Gaussian Mixture Model. Tier 2A probabilistic model estimating each window's log-likelihood under the baseline distribution. |
| **IForest** | Isolation Forest. Tier 2B detector isolating anomalies via random partitioning of the feature space. |
| **IAT** | Inter-Arrival Time. Time between consecutive packets. Critical feature for detecting beaconing and regular cadence attacks. |
| **Loading Magnitude** | Normalized coefficient [0,1] quantifying a feature's relative contribution to an incident's anomaly. |
| **MITRE ATT&CK** | Adversarial knowledge framework classifying attack tactics and techniques. Version v14 used. |
| **Physical Sentinel** | Tier 3 of the detection engine. Analyzes individual features via per-feature statistical thresholds, with higher spatial resolution than global tiers. |
| **SPIKE** | Event where the observed value significantly exceeds the baseline mean ($\sigma_{j^*} > 0$). |
| **Velocity Bypass** | Tier 4 of the detection engine. Emergency alert based on packet arrival rate Z-score, independent of the main tribunal. |
| **Warm-up** | Initial period after detector startup where the statistical model hasn't fully converged. Incidents during this period receive a 50% confidence penalty. |
| **Z-score** | $\sigma_j = (x_j - \mu_{0,j}) / s_{0,j}$. Measure of how many standard deviations from the baseline an observed value lies. |

---

*This manual describes the attribution architecture of [forensic_engine.py](/src/analysis/forensic_engine.py) (HiGI IDS v4.0, ForensicEngine V2.0). For documentation on detection tiers (BallTree, GMM, IForest, Physical Sentinel, Velocity Bypass), consult [Higi_manual.md](/docs/eng/Higi_manual.md). For threshold configuration, consult [config.yaml](/config.yaml).*

*— HiGI Security Data Engineering Team*