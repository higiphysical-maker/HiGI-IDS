# HiGI IDS — Logical-Mathematical Manual

**Hilbert-space Gaussian Intelligence** *Fourth Generation Intrusion Detection System*

**Version:** 4.0.0 · **Status:** Production · **Authorship:** Blue Team Engineering  
**Reference Module:** [`src/models/higi_engine.py`](/src/models/higi_engine.py)

---

## Table of Contents

1. [Conceptual Fundamentals](#1-conceptual-fundamentals)
2. [Pipeline Architecture](#2-pipeline-architecture)
3. [Phase I — Construction of the Inertial Reference Frame (Training)](#3-phase-i--construction-of-the-inertial-reference-frame-training)
4. [Projection to Hilbert Space](#4-projection-to-hilbert-space)
5. [Tier 1 — The Geometric Gatekeeper (BallTree)](#5-tier-1--the-geometric-gatekeeper-balltree)
6. [Tier 2 — The Probabilistic Tribunal (GMM + IForest)](#6-tier-2--the-probabilistic-tribunal-gmm--iforest)
7. [Tier 3 — The Physical Sentinel (Univariate GMM)](#7-tier-3--the-physical-sentinel-univariate-gmm)
8. [Tier 4 — The Emergency Valve (Velocity Bypass)](#8-tier-4--the-emergency-valve-velocity-bypass)
9. [The Tribunal Consensus](#9-the-tribunal-consensus)
10. [Temporal Stabilization Mechanisms](#10-temporal-stabilization-mechanisms)
11. [Forensic Attribution](#11-forensic-attribution)
12. [Detection Phase — The Inference Projection](#12-detection-phase--the-inference-projection)
13. [Centralized Configuration and Runtime Hot-Swap](#13-centralized-configuration-and-runtime-hot-swap)
14. [Architectural Recommendations](#14-architectural-recommendations)
15. [Parameter Reference](#15-parameter-reference)

---

## 1. Conceptual Fundamentals

### 1.1 The Physical Perspective of Network Traffic

HiGI does not treat network traffic as a sequence of discrete events to be compared against a signature list. It treats it as a **physical field**: a continuous flow of energy, pressure, and composition that obeys stable statistical rules under normal conditions. When the field is altered, HiGI detects it as a seismograph would detect an anomalous vibration: by deviation from the calibrated state of rest.

This perspective has three direct architectural consequences:

1. **The state of rest must be established empirically** on known benign traffic. There is no absolute value for "normal PPS"; there is only the observed PPS in this environment, on this network, at this time.

2. **Detection is always relative to the state of rest.** A new traffic sample is evaluated by how much it deviates from the calibrated field, not by whether it contains attack keywords.

3. **Geometry matters more than absolute value.** A SYN packet with a ratio of 0.9 in a datacenter network might be completely normal; the same ratio in an office network is a severe anomaly. The position in the representation space encodes the context of the environment.

### 1.2 Hilbert Space as a Data Manifold

The feature space of network traffic is high-dimensional (typically 40–60 features in v4.0, including relative velocity features) and highly non-linear. Projection to Hilbert Space $\mathcal{H}$ — via Blocked PCA by physical family or via Yeo-Johnson + global PCA — reduces that manifold to a compact representation (typically 17–25 dimensions) where:

- Euclidean distance is a good estimator of semantic dissimilarity.
- Multivariate Gaussian probability density can be stably estimated.
- The directions of greatest variance correspond to the most informative "physical axes" of the traffic.

In a strict sense, it is not a Hilbert space in the pure mathematical definition (which requires an inner product and completeness), but the naming captures the essence: a metric space where geometry has physical meaning.

### 1.3 The Architectural Novelty of v4.0: Geometric Blindness Resolved

The root-cause audit of April 2026 identified that Hulk and GoldenEye DoS attacks were **geometrically invisible** in Hilbert Space. The reason is physical: a high-rate HTTP flood produces low intra-window variance traffic, statistically identical to normal heavy Monday HTTP traffic. The BallTree assigned scores of only $0.26 \times P99$ to these attacks, while Slowloris — genuinely different from the baseline — reached $1.56 \times P99$.

The solution introduces **Tier 4 (VelocityBypassDetector)**: a detector that operates completely *outside* the Hilbert Space, using three dynamic 60-second Z-score features produced by `processor_optime.py` v2.3.0. This detector is **self-normalizing**: it requires no training and captures regime transitions that are invisible to any detector based on absolute magnitudes.

---

## 2. Pipeline Architecture

The HiGI v4.0 inference pipeline is a cascade of four detection levels operating in a coordinated manner. Tier 4 runs on **all samples in parallel** with Tier 1. Tiers 2 and 3 operate only on suspicious samples (including those marked by Tier 4), ensuring computational efficiency. The exact sequence of steps in `HiGIEngine.analyze()` is:

```
┌─────────────────────────────────────────────────────────────────────┐
│                  PCAP / Live Socket                                  │
└────────────────────────────────┬───────────────────────────────────-┘
                                 │
                    ┌────────────▼────────────┐
                    │   processor_optime.py    │
                    │  Ingestion · 1s Windows  │
                    │  Physical features +     │
                    │  vel_pps_z · vel_bytes_z │
                    │  · vel_syn_z  (v2.3.0)   │
                    └────────────┬────────────┘
                                 │  X ∈ ℝⁿˣᵈ  (d ≈ 40–60 features)
                    ┌────────────▼────────────┐
                    │   Hilbert Projector      │
                    │   Blocked PCA (default)  │  ← FROZEN weights
                    │   or Global PCA (fallback)│    from training
                    └────────────┬────────────┘
                                 │  Xₕ ∈ ℋ  (h ≈ 17–25 dims)
          ┌──────────────────────┼──────────────────────┐
          │    (STEP 1)          │                      │  (STEP 1)
┌─────────▼──────────┐           │            ┌─────────▼──────────┐
│    TIER 1           │           │            │    TIER 4           │
│    Geometric        │           │            │    Velocity Bypass  │
│    Gatekeeper       │           │            │    ALL              │
│                     │           │            │    samples          │
└─────────┬──────────┘           │            └─────────┬──────────┘
          │ Normal → short-circuit│                      │ bypass_mask
          │ Suspicious → Tier 2   │                      │ vel_score
          └──────────────────────┼──────────────────────┘
                                 │ Suspicious ∪ Bypass  (STEP 2)
                    ┌────────────▼────────────┐
                    │   TIER 2A: GMM           │
                    │   Log-Likelihood         │
                    │   (local density)        │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   TIER 2B: IForest       │
                    │   Isolation Score        │
                    │   (global structure)     │
                    └────────────┬────────────┘
                                 │  STEP 3A: Weighted consensus
                    ┌────────────▼────────────┐
                    │   TIER 3: Physical       │
                    │   Sentinel               │   STEP 3B
                    │   Univariate GMM         │
                    │   per feature            │
                    └────────────┬────────────┘
                                 │  STEP 3C: Final decision + FIX-4
                    ┌────────────▼────────────┐
                    │   Bypass Override        │
                    │   is_anomaly[bypass]=1   │
                    │   severity=max(bt,vel)   │
                    └────────────┬────────────┘
                                 │  STEP 3D+3E: Persistence + Hysteresis
                    ┌────────────▼────────────┐
                    │   HYSTERESIS · PERSIST   │
                    │   Adaptive Schmitt       │
                    │   Trigger (FIX-3)        │
                    │   [bypass protected]     │
                    └────────────┬────────────┘
                                 │  STEP 5: Forensic attribution
                    ┌────────────▼────────────┐
                    │   FORENSIC ATTRIBUTION   │
                    │   PC culprit · SPIKE/    │
                    │   DROP · MITRE ATT&CK    │
                    │   ⚡VELOCITY BYPASS ann. │
                    └─────────────────────────┘
```

**Note on short-circuiting and Tier 4:** Samples marked by the Velocity Bypass (`bypass_mask = True`) are incorporated into the suspicious mask and receive full Tier 2 evaluation. This ensures that the Tribunal evidence is always complete, even for samples whose anomaly was primarily detected by Tier 4.

---

## 3. Phase I — Construction of the Inertial Reference Frame (Training)

### 3.1 The Inertial Frame Analogy

In classical physics, an inertial reference frame is one in which the laws of motion are met without fictitious corrections: an observer at rest can measure the deviations of any moving object relative to that state of rest.

HiGI training constructs exactly that frame: from known benign traffic (e.g., the Monday of the CIC-IDS-2017 dataset), it calculates all statistical parameters that define the "rest" of this network. Once the frame is established, it is **frozen**. No future traffic samples can alter it. This is architecturally enforced via the `HiGIConfig(frozen=True)` dataclass: any parameter modification creates a new instance via `dataclasses.replace()`, preserving the immutability of the original contract.

### 3.2 Training Steps (`HiGIEngine.train()`)

**Step 0 — Feature Schema Extraction**

The engine extracts the set of numerical columns $\mathcal{F} = \{f_1, f_2, \ldots, f_d\}$ from the baseline matrix, excluding metadata (`dt`, `timestamp`, `second_window`, `label`, `frame_number`). In v4.0, relative velocity features $\{v_\text{pps}, v_\text{bytes}, v_\text{syn}\}$ are included in the schema when present.

Univariate reference statistics are calculated and frozen:

$$\mu_j = \frac{1}{N}\sum_{i=1}^N x_{ij}, \qquad \sigma_j = \sqrt{\frac{1}{N-1}\sum_{i=1}^N (x_{ij} - \mu_j)^2}, \qquad j \in \{1, \ldots, d\}$$

With graceful degradation if velocity features are absent:
```
⚠ Velocity features ABSENT from baseline. VelocityBypass will degrade
gracefully during inference. Re-process PCAP with processor_optime v2.3.0+
to enable Tier 4.
```

**Step 0.5 — Univariate GMMs (one per feature)**

For each feature $f_j$, an optimal Gaussian Mixture Model of $K_j$ components is fitted (selected by the `_find_optimal_k_for_feature()` function via BIC/AIC/Silhouette/Davies-Bouldin) and the log-likelihood threshold at the training P99.9 is computed:

$$\tau_j = \mathrm{P}_{99.9}\bigl[\ell_j(x_{ij})\bigr]_{\,x_{ij} \sim \mathcal{D}_\text{train}}$$

where $\ell_j(x) = \log p_j(x)$ is the univariate GMM log-likelihood for feature $j$. This threshold is **feature-specific**: the sensitivity for `flag_syn_ratio` and `flow_duration` are intrinsically different. A global threshold would introduce systematic biases between features with very different natural variances.

**Step 0.6 — Tribunal Weight Normalization**

The Tribunal weights are normalized so that their sum is exactly 1.0. With `velocity_tribunal_weight = 0.15` (default in `HiGIConfig`) and `velocity_bypass_enabled = True`:

$$w_\text{vel} = 0.15, \quad w_\text{rem} = 1.0 - 0.15 = 0.85$$

$$w_\text{bt} = 0.25 \cdot w_\text{rem} = 0.2125, \quad w_\text{gmm} = 0.40 \cdot w_\text{rem} = 0.34, \quad w_\text{if} = 0.35 \cdot w_\text{rem} = 0.2975$$

This distribution is computed in `HiGIConfig.__post_init__()` and re-normalized in `train()` to ensure $\sum_i w_i = 1.0$.

**Step 1 — Projection to Hilbert Space**

Detailed in Section 4.

**Step 2 — Training of Tribunal Detectors**

Using the projected baseline matrix $X_\mathcal{H} \in \mathbb{R}^{N \times h}$, three detectors are fitted:

| Detector | Frozen Parameters | Physical Function |
|---|---|---|
| BallTree (Tier 1) | $k$-NN Tree · $\delta_{P99}$ · severity percentiles | Geometry: is it in a known zone? |
| GMM (Tier 2A) | $\{\pi_k, \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k\}$ · $\tau_\text{gmm}$ | Density: how probable is it? |
| IForest (Tier 2B) | Isolation tree ensemble | Structure: is it easy to isolate? |

**Tier 4 (Velocity Bypass) has no trainable parameters**: its Z-scores are self-normalizing by construction.

### 3.3 Why Weights are Frozen

If the normalizer were re-trained with test data during the detection phase, what we call **reference poisoning** would occur: a flood of very homogeneous DoS traffic would occupy most of the batch distribution and become the new "state of rest." The system would then detect the residual benign traffic as anomalous.

Mathematically: let $\hat{\mu}_\text{batch}$ and $\hat{\sigma}_\text{batch}$ be the moments of the inference batch. If the batch contains massive DoS traffic:

$$\hat{\mu}_\text{batch}^\text{pps} \gg \mu_\text{train}^\text{pps}$$

and the DoS is projected to the center of the normalized distribution, obtaining a score of zero. By using frozen training parameters:

$$z_i = \frac{x_i - \mu_\text{train}}{\sigma_\text{train}}$$

the DoS produces values $z_i \gg 1$ and is correctly detected by the Physical Sentinel.

---

## 4. Projection to Hilbert Space

The `HilbertSpaceProjector` supports two projection modes selectable in `HiGIConfig`:

### 4.1 Primary Mode: Blocked PCA by Physical Family (`blocked_pca_enabled=True`)

This is the default mode in v4.0. Instead of applying a global PCA across all features, Blocked PCA applies an independent `(StandardScaler → PCA)` pipeline for each physical family, then concatenates the resulting representations:

| Family | Representative Features | Target Variance |
|---|---|---|
| `volume` | `total_pps_log`, `total_bytes_log`, `bytes`, `vel_pps_z`, `vel_bytes_z` | 95% |
| `payload` | `entropy_avg`, `payload_continuity`, `payload_continuity_ratio` | 95% |
| `flags` | `flag_syn_ratio`, `flag_rst_ratio`, `flag_psh_ratio`, `vel_syn_z` | 99% |
| `protocol` | `tcp_ratio`, `udp_ratio`, `icmp_ratio` | 99% |
| `connection` | `unique_dst_ports`, `port_scan_ratio`, `flow_duration`, `iat_mean` | 95% |

The motivation for this design is **Component Collapse**: in global PCA, high-variance families (`payload`) monopolize the first principal components at the expense of low-variance families (`flags`). A `flag_syn_ratio = 0.99` — an unmistakable SYN flood signature — has a small absolute variance (its natural range is $[0,1]$) and would be buried in later components. Blocked PCA ensures that each family has proportional representation in the joint space $\mathcal{H}$.

The transformation of a sample in Blocked PCA mode is:

$$\mathbf{x}_\mathcal{H} = \bigl[\mathbf{V}_\text{vol}^\top \tilde{\mathbf{x}}_\text{vol} \;\|\; \mathbf{V}_\text{pay}^\top \tilde{\mathbf{x}}_\text{pay} \;\|\; \mathbf{V}_\text{flags}^\top \tilde{\mathbf{x}}_\text{flags} \;\|\; \mathbf{V}_\text{prot}^\top \tilde{\mathbf{x}}_\text{prot} \;\|\; \mathbf{V}_\text{conn}^\top \tilde{\mathbf{x}}_\text{conn} \bigr]$$

where $\tilde{\mathbf{x}}_f = \text{StandardScaler}_f(\mathbf{x}_f)$ is the per-family normalization and $\mathbf{V}_f$ are the PCA loading matrices per family, with dimensions adjusted to the target variance of each.

The underlying `ColumnTransformer` uses `remainder="drop"` (features not assigned to any family are discarded) and `n_jobs=1` for `joblib` serialization compatibility.

### 4.2 Alternative Mode: Global PCA with Yeo-Johnson (`blocked_pca_enabled=False`)

In this fallback mode, the projection follows the classic three-step pipeline:

**Step 1 — Clipping at P99:** P99 percentile limits are calculated per feature and extreme values are clipped, preventing baseline outliers from distorting the $\boldsymbol{\lambda}$ estimation.

**Step 2 — Yeo-Johnson Transformation:** Network feature space is highly non-Gaussian. PPS and bytes follow heavy-tailed log-normal distributions; flag ratios are bimodal. The Yeo-Johnson transformation Gaussianizes each feature:

$$\psi_\lambda(x) = \begin{cases}
\dfrac{(x+1)^\lambda - 1}{\lambda} & \text{if } \lambda \neq 0, \; x \geq 0 \\[6pt]
\ln(x+1) & \text{if } \lambda = 0, \; x \geq 0 \\[6pt]
\dfrac{1 - (1-x)^{2-\lambda}}{2-\lambda} & \text{if } \lambda \neq 2, \; x < 0 \\[6pt]
-\ln(1-x) & \text{if } \lambda = 2, \; x < 0
\end{cases}$$

The exponent $\lambda_j$ is estimated by maximum likelihood for each feature during training (`sklearn.preprocessing.PowerTransformer(method="yeo-johnson", standardize=True)`) and is **frozen**. Unlike the natural logarithm, Yeo-Johnson accepts negative values, which is essential for relative velocity features $v_j \in \mathbb{R}$.

If Yeo-Johnson produces non-finite values, a fallback `QuantileTransformer` trained on the baseline is applied.

**Step 3 — PCA with Whitening:** On the transformed matrix $\tilde{X}$, PCA with `whiten=True` is applied. Whitening scales the principal components by the inverse of their standard deviation, so that all have unit variance in $\mathcal{H}$. This makes Euclidean distance in $\mathcal{H}$ equivalent to **Mahalanobis distance** in the original space:

$$d_\mathcal{H}(\mathbf{a}, \mathbf{b}) = \|\mathbf{a}_\mathcal{H} - \mathbf{b}_\mathcal{H}\|_2 \approx \sqrt{(\mathbf{a} - \mathbf{b})^\top \boldsymbol{\Sigma}^{-1} (\mathbf{a} - \mathbf{b})}$$

The number of components $h$ is automatically selected to retain 99% of the variance:

$$h = \min\left\{k : \sum_{i=1}^k \lambda_i \Big/ \sum_{i=1}^d \lambda_i \geq 0.99\right\}$$

In practice, $h \approx 17$–$20$ components from the original 40–60 features.

### 4.3 Forensic Attribution Metadata

In Blocked PCA mode, the `_build_blocked_pca_metadata()` method constructs two structures for forensic attribution:

- `_blocked_pca_family_mapping`: map of global component index → `(family, local_index_in_family)`
- `_blocked_pca_loadings_by_family`: for each family, the transposed loading matrix `(n_features_family, n_components_family)` and the list of features

These structures allow the `ForensicEngine` to trace any anomaly in $\mathcal{H}$ back to the original features of the responsible family, without ambiguity about which family contributed to each component.

---

## 5. Tier 1 — The Geometric Gatekeeper (BallTree)

### 5.1 Physical Intuition

The Gatekeeper answers the most direct question: **is this sample in a region of space that benign traffic visited during training?**

A BallTree on the baseline samples in $\mathcal{H}$ constitutes a geometric density map. If the mean distance to the $k=5$ nearest neighbors is small, the sample is in a populated zone. If it is large, it is in a desert zone: an outlier.

### 5.2 Absolute Scoring (FIX-1)

The BallTree score is the mean Euclidean distance to the $k$ nearest neighbors in $\mathcal{H}$, normalized against the training P99 percentile:

$$s_\text{bt}(\mathbf{x}) = \frac{1}{\delta_{P99}} \cdot \frac{1}{k} \sum_{i=1}^{k} \|\mathbf{x}_\mathcal{H} - \mathbf{nn}_i\|_2$$

where $\delta_{P99} = \mathrm{P}_{99}\bigl[\bar{d}_{kNN}(\mathbf{x}_\text{train})\bigr]$ is the P99 percentile of the $kNN$ mean distances calculated on the training set itself and stored in `BallTreeDetector.training_p99_distance`.

This normalization has a fundamental physical consequence: the score is **batch-independent**. A DoS attack that produces distances 10 times greater than $\delta_{P99}$ will obtain $s_\text{bt} \approx 10.0$ regardless of what other samples are in the batch. Without this normalization (using min-max per batch), a homogeneous flood that dominates the batch compresses all scores and becomes invisible.

The interpretation of the resulting scale is direct:

| $s_\text{bt}$ | Interpretation | Real Example (CIC-IDS2017) |
|---|---|---|
| $< 0.9$ | Clearly within baseline | Benign Monday traffic |
| $\approx 1.0$ | Exactly at the P99 limit | High-load HTTP traffic |
| $1.0$–$2.0$ | Borderline zone | Slowloris: $s \approx 1.56$ |
| $> 5.0$ | Strongly anomalous | DoS GoldenEye: $s \gg 5$ |
| DoS Hulk (high-rate flood) | $\approx 0.26$ (invisible!) | → resolved by Tier 4 |

### 5.3 Severity Stratification

The score is mapped to five severity levels with a `balltree_slack = 1.2` multiplier applied to the percentile thresholds:

| Zone | Condition | Action |
|---|---|---|
| Normal | $s_\text{bt} < s_{P90}$ | Short-circuit: skip Tiers 2 and 3 |
| Soft Zone | $s_{P90} \leq s_\text{bt} < s_{P95}$ | Passes to Tier 2 as a slight suspicious |
| Borderline | $s_{P95} \leq s_\text{bt} < s_{P99}$ | Tier 2 + requires family consensus (FIX-4) |
| Medium | $s_{P99} \leq s_\text{bt} < s_{P99.9}$ | Tier 2, confirmation by weighted consensus |
| Critical | $s_\text{bt} \geq s_{P99.9}$ | **Unconditional** anomaly |

---

## 6. Tier 2 — The Probabilistic Tribunal (GMM + IForest)

### 6.1 The Geometric-Probabilistic Complement

The BallTree operates with geometry: it measures distances. But in regions of high-dimensional space with Gaussian density, the distance between any pair of points tends to concentrate (*measure concentration* phenomenon). Two samples of totally different nature can be geometrically close.

The GMM corrects this problem: instead of measuring distances, it measures **local probability density**. The relationship between the two can be expressed as:

> **Gatekeeper**: *Have you been here before?* (distance)  
> **Tribunal**: *How likely is it that someone like you is here?* (density)

### 6.2 Gaussian Mixture Model — Formulation

Given the projected Hilbert space $\mathbf{x} \in \mathbb{R}^h$, the GMM estimates the distribution of benign traffic as a mixture of $K$ full Gaussians:

$$p_\text{GMM}(\mathbf{x}) = \sum_{k=1}^{K} \pi_k \; \mathcal{N}(\mathbf{x} \mid \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k)$$

with $\sum_k \pi_k = 1$, $\pi_k \geq 0$. The **log-likelihood** of a sample under the model is:

$$\ell(\mathbf{x}) = \log p_\text{GMM}(\mathbf{x}) = \log \sum_{k=1}^{K} \pi_k \; \mathcal{N}(\mathbf{x} \mid \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k)$$

The GMM anomaly score is the **inverted** log-likelihood (higher score = more anomalous):

$$s_\text{gmm}(\mathbf{x}) = -\ell(\mathbf{x})$$

The binary decision threshold is the P99.9 percentile of $s_\text{gmm}$ on the training set:

$$\tau_\text{gmm} = \mathrm{P}_{99.9}\bigl[s_\text{gmm}(\mathbf{x}_\text{train})\bigr]$$

A sample is marked as anomalous by the GMM if $s_\text{gmm}(\mathbf{x}) > \tau_\text{gmm}$.

### 6.3 Why BayesianGaussianMixture

HiGI uses `BayesianGaussianMixture` with a weight concentration prior $\alpha_0 = 10^{-5}$ (value in `HiGIConfig.bayesian_weight_concentration_prior`). A small prior penalizes clusters with very few members, forcing the model to concentrate on the dense clusters of the baseline. This avoids overfitting spurious clusters to sampling artifacts in long-duration captures. Covariance is regularized with a ridge term $\delta = 0.1$ (`reg_covar`) for numerical stability in the high-dimensional Hilbert space.

### 6.4 Adaptive K Selection

The optimal number of components $K^*$ is selected by weighted voting of four criteria in `_select_optimal_components()`:

$$K^* = \arg\max_K \bigl[0.40 \cdot \text{BIC}^*(K) + 0.10 \cdot \text{AIC}^*(K) + 0.25 \cdot \text{Sil}^*(K) + 0.25 \cdot \text{DB}^*(K)\bigr]$$

where asterisks indicate min-max normalization of individual scores (with inversion for BIC and AIC, where smaller values are better). BIC dominates with a weight of 0.40 because it penalizes model complexity consistently with sample size.

### 6.5 Isolation Forest — Structural Detection

IForest complements GMM: a point is anomalous if it can be **isolated with few partitions** in a random decision tree. While GMM measures density (how likely is it?), IForest measures structural isolability (how easy is it to separate from the rest?).

A data exfiltration attack might be difficult to detect by density (if the space region has few training points but the multivariate profile exists) but easy to detect by structure (the feature combination is unique). The expected contamination is `iforest_contamination = 0.005` (0.5%), configured for networks with relatively stable traffic.

---

## 7. Tier 3 — The Physical Sentinel (Univariate GMM)

### 7.1 The Marginal Invariance Hypothesis

An anomaly manifesting in multivariate space (Tiers 1 and 2) must manifest in at least one of the marginal distributions of its component features. The Sentinel exploits this hypothesis by verifying, feature by feature, if the sample is physically plausible in each dimension separately.

For each feature $f_j$, there is a univariate GMM with log-likelihood $\ell_j(x)$ and threshold $\tau_j$ (P99.9 of $\ell_j$ in training). The Sentinel votes in favor of an anomaly if:

$$\exists\, j : \ell_j(x_j) < \tau_j$$

The condition requires that **at least one** feature produces a log-likelihood below the training threshold (the observed value is more improbable than what 99.9% of benign traffic ever produced for that feature).

### 7.2 Directionality Analysis

When `sentinel_directionality_analysis = True`, the Sentinel identifies not only the culprit feature but also records the **anomaly direction**:

$$\text{direction}(x_j) = \begin{cases}
\text{SPIKE} & \text{if } x_j > \mu_j \\
\text{DROP} & \text{if } x_j < \mu_j
\end{cases}$$

and the relative percentage deviation:

$$\Delta_j = \frac{|x_j - \mu_j|}{|\mu_j| + \varepsilon} \times 100\%$$

This information is the primary input for the `ForensicEngine` to build the attack narrative. An `icmp_ratio` with a SPIKE of +612.5% is a signature directly interpretable as protocol collapse (saturated server response), requiring no prior knowledge of the attack type.

### 7.3 The Gatekeeper Veto (Portero Veto)

If a sample produces $|\sigma_j| \geq \theta_\text{gatekeeper} = 20.0\sigma$ in any individual feature, the system forces `severity = 3` regardless of consensus (`portero_sigma_threshold` in `HiGIConfig`). This is the exception to the consensus rule: a 20-sigma deviation in any physical feature has a probability of order $10^{-88}$ under the Gaussian null hypothesis. No additional consensus is necessary.

**Real Example:** During the GoldenEye DoS attack in CIC-IDS2017 Wednesday, `payload_continuity_ratio` reached **4120σ**. This value activates the Gatekeeper Veto unconditionally.

---

## 8. Tier 4 — The Emergency Valve (Velocity Bypass)

### 8.1 The Problem of Geometric Blindness

Massive flood attacks (Hulk DoS, GoldenEye) generate traffic that is statistically **indistinguishable from normal heavy HTTP traffic** in Hilbert Space. The reason is physical:

During an HTTP GET flood at 10,000 packets/second, all packets are identical (same size, same TTL, same destination port). **Intra-window variance** collapses to near zero. The feature vector of a 1-second window is perfectly regular: small $k$-NN distance, high GMM log-likelihood. The BallTree assigns $s_\text{bt} \approx 0.26 \times P99$ — classified as low-priority benign traffic.

The problem is not system calibration; it is that the attack produces a type of traffic that *exists in the benign baseline* (massive HTTP is normal in high-traffic networks). Geometry and density are not enough to discriminate it.

### 8.2 The Dynamic Regime Signal

What *does not* exist in the benign baseline is an **abrupt regime transition**. A healthy HTTP server receiving many requests receives them from many simultaneous clients, with natural temporal variance. A Hulk DoS appears in 1–3 seconds as a brutal multiplication of PPS without precedent in recent history.

The solution: calculate the Z-score for each velocity feature **relative to its own 60-second moving average** (calculated by `processor_optime.py` v2.3.0 before ingestion into the engine):

$$z_\text{pps}(t) = \frac{x_\text{pps\_log}(t) - \bar{x}_\text{pps\_log}^{(60)}(t)}{\hat{\sigma}_\text{pps\_log}^{(60)}(t) + \varepsilon}$$

$$z_\text{bytes}(t) = \frac{x_\text{bytes\_log}(t) - \bar{x}_\text{bytes\_log}^{(60)}(t)}{\hat{\sigma}_\text{bytes\_log}^{(60)}(t) + \varepsilon}$$

$$z_\text{syn}(t) = \frac{x_\text{syn\_ratio}(t) - \bar{x}_\text{syn\_ratio}^{(60)}(t)}{\hat{\sigma}_\text{syn\_ratio}^{(60)}(t) + \varepsilon}$$

where $\varepsilon = 10^{-6}$ prevents division by zero during periods of perfectly stationary traffic. These three features (`vel_pps_z`, `vel_bytes_z`, `vel_syn_z`) are collectively called **relative velocity features**.

The dynamic Z-score measures the **pressure** that traffic exerts on its own recent history. It does not measure if PPS is high in absolute terms, but whether it is *abnormally high for this specific moment of the day*.

### 8.3 The Emergency Bypass Gate (`VelocityBypassDetector.compute()`)

Let $Z_{\max}(t) = \max\bigl(|z_\text{pps}(t)|, |z_\text{bytes}(t)|, |z_\text{syn}(t)|\bigr)$ be the maximum velocity Z-score at time $t$. Tier 4 defines:

$$\text{bypass}(t) = \mathbf{1}\bigl[Z_{\max}(t) \geq \theta_\text{bypass}\bigr]$$

with $\theta_\text{bypass} = 10.0\sigma$ by default in `HiGIConfig.velocity_bypass_threshold` (configurable via `config.yaml → velocity.bypass_threshold`). If `bypass(t) = 1`, the sample is marked `is_anomaly = 1` **unconditionally**. Severity is assigned according to `VELOCITY_SEVERITY_THRESHOLDS`:

$$\text{severity}(t) = \begin{cases}
3 & \text{if } Z_{\max} \geq 12.0\sigma \quad \text{(Critical)} \\
2 & \text{if } 8.0\sigma \leq Z_{\max} < 12.0\sigma \quad \text{(Medium)} \\
1 & \text{if } 5.0\sigma \leq Z_{\max} < 8.0\sigma \quad \text{(Borderline)}
\end{cases}$$

The continuous score for the Tribunal is:

$$s_\text{vel}(t) = \min\left(\frac{Z_{\max}(t)}{\theta_\text{bypass}},\; 3.0\right) \in [0, 3.0]$$

normalized to $[0,1]$ by dividing it by 3.0 before entering the weighted consensus sum. The `vel_culprit` is recorded as `"feature_name(z=±X.XX)"` for forensic evidence.

### 8.4 Why the Threshold is 10.0σ (and not 5.0σ)

`HiGIConfig` defines `velocity_bypass_threshold = 10.0σ` as the default. This is a more conservative threshold than discussed in previous analyses, chosen to minimize false positives in production environments with moderate traffic variability. For environments with very stable traffic (forensic laboratory, segmented network), the parameter can be reduced to 5.0σ.

Under a Gaussian hypothesis, $P(|Z| \geq 5) \approx 5.7 \times 10^{-7}$ and $P(|Z| \geq 10) \approx 1.5 \times 10^{-23}$. A Hulk DoS that doubles the PPS in 3 seconds on a network with $\hat{\sigma}_\text{pps}^{(60)} \approx 0.15$ (log-scale) produces:

$$z_\text{pps} = \frac{\log(2 \cdot \text{PPS}_\text{baseline}) - \log(\text{PPS}_\text{baseline})}{\hat{\sigma}_\text{pps}^{(60)}} = \frac{\ln 2}{0.15} \approx 4.6\sigma$$

and in a few additional seconds, when the flood stabilizes at 5× the baseline, $z_\text{pps} \approx 10.7\sigma$: activating the bypass even with the conservative 10.0σ threshold.

### 8.5 Integration of Velocity Features into Hilbert Space

Relative velocity features ($v_\text{pps}$, $v_\text{bytes}$, $v_\text{syn}$) are included in the Hilbert Space projection when present in the baseline. In stationary benign traffic, their values cluster near 0 (stable regime). The baseline BallTree learns that $|v_j| \approx 0$ is normal: when $|v_\text{pps}| \gg 1$ appears during inference, the BallTree also detects it as far from the baseline in $\mathcal{H}$, complementing the direct Tier 4 signal. In Blocked PCA mode, `vel_pps_z` and `vel_bytes_z` belong to the `volume` family, and `vel_syn_z` to the `flags` family, so each contributes within its family block.

### 8.6 Protection of Bypass Against Persistence Filters

In steps 3D and 3E of the pipeline, the persistence filter (`rolling_min`) and hysteresis could suppress an isolated 1-second bypass. To prevent the attack onset from being silenced, samples marked as bypass are **explicitly protected**: after each filter, `is_anomaly[vel_bypass] = 1` is re-applied. The bypass overrides all filters by design.

---

## 9. The Consensus Tribunal

### 9.1 Weighted Voting

The final decision integrates four signals via a weighted sum. GMM and IForest scores are min-max normalized per batch (acceptable as they are used as relative tie-breakers):

$$C(\mathbf{x}) = w_\text{bt} \cdot \hat{s}_\text{bt} + w_\text{gmm} \cdot \hat{s}_\text{gmm} + w_\text{if} \cdot \hat{s}_\text{if} + w_\text{vel} \cdot \hat{s}_\text{vel}$$

where $\hat{s}_\text{vel} = s_\text{vel} / 3.0$ (already has a defined physical scale, no batch normalization required).

Default weights, computed in `HiGIConfig.__post_init__()` with `velocity_tribunal_weight = 0.15`, are:

$$w_\text{bt} = 0.2125, \quad w_\text{gmm} = 0.3400, \quad w_\text{if} = 0.2975, \quad w_\text{vel} = 0.1500$$

GMM has the highest weight of the Hilbert-space detectors because it is the most direct density estimator for the probabilistic structure of benign traffic. The BallTree score uses absolute normalization (FIX-1), so it is not min-max normalized in the Tribunal: $\hat{s}_\text{bt} = s_\text{bt}$ directly.

### 9.2 Escalation by Severity Level

The decision process in step 3C differs according to the BallTree severity level and the presence of Velocity Bypass:

```
is_anomaly = 0  (initial state for all samples)

If severity == 3 (Critical):      → is_anomaly = 1  (unconditional)
If severity == 2 (Medium):        → is_anomaly = 1  if C(x) ≥ τ_consensus
If severity == 1 (Borderline):    → is_anomaly = 1  if C(x) ≥ τ_consensus
                                                 AND family_consensus (FIX-4)
If severity == 0 and vel_bypass:    → is_anomaly = 1  (Tier 4 override)
                                    severity = max(bt_severity, vel_bypass_sev)
If severity == 0 and Sentinel:     → is_anomaly = 1  if C(x) ≥ max(0.7, τ_consensus)
```

The default consensus threshold is $\tau_\text{consensus} = 0.5$.

### 9.3 Family Consensus (FIX-4)

A borderline sample ($s_\text{bt} \in [s_{P95}, s_{P99})$) is only confirmed as an anomaly if at least $N_\text{hits} = 2$ features from the same `METRIC_FAMILIES` family are simultaneously elevated ($|Z_j| \geq 2.0\sigma$ relative to the baseline):

| Family (`METRIC_FAMILIES`) | Member Features in v4.0 |
|---|---|
| `volume_flood` | `total_pps_log`, `total_bytes_log`, `flag_syn_ratio`, `flag_rst_ratio`, `pps_momentum`, **`vel_pps_z`**, **`vel_bytes_z`**, **`vel_syn_z`** |
| `slow_attack` | `flow_duration`, `iat_mean`, `payload_continuity`, `flag_fin_ratio` |
| `exfiltration` | `payload_continuity_ratio`, `entropy_avg`, `bytes_velocity`, `flag_psh_ratio` |
| `kinematics` | `pps_velocity`, `bytes_velocity`, `pps_acceleration`, `bytes_acceleration`, `pps_volatility`, `bytes_volatility` |
| `recon` | `port_scan_ratio`, `unique_dst_ports`, `flag_fin_ratio`, `flag_urg_ratio` |

**Change in v4.0:** The three relative velocity features were added to the `volume_flood` family. This ensures that a Velocity Bypass event automatically triggers family consensus for that family, since `vel_pps_z >= 10.0σ >> 2.0σ` satisfies `N_hits >= 2` by itself when combined with any other feature in the family.

The requirement for co-triggering prevents a single transient spike (e.g., elevated `flag_rst_ratio` during a legitimate TCP disconnect) from generating an alert. A coordinated attack simultaneously affects multiple metrics within the same family.

---

## 10. Temporal Stabilization Mechanisms

### 10.1 Persistence Filter (Anti-FP Shield) — Step 3D

The binary anomaly signal is filtered with a 3-position sliding window:

```
confirmed = rolling_min(is_anomaly, window=3)  # requires 3 consecutive windows
propagated = rolling_max(confirmed, window=3)  # propagates state for 3 windows
```

This filter eliminates transient spikes of 1–2 windows that do not correspond to sustained attacks. The disadvantage — suppressing an attack onset — is mitigated by Velocity Bypass, whose samples are re-protected after the filter: `is_anomaly[vel_bypass] = 1` is unconditionally re-applied.

### 10.2 Adaptive Schmitt-Trigger Hysteresis (FIX-3) — Step 3E

The alert state is controlled via a dual-threshold Schmitt trigger:

$$\theta_\text{entry} = \theta_{P95} \cdot m_\text{entry}, \qquad \theta_\text{exit} = \theta_{P95} \cdot m_\text{exit}$$

with $m_\text{entry} = 1.0$ (`hysteresis_entry_multiplier`) and $m_\text{exit} = 0.75$ (`hysteresis_exit_multiplier`). Once in an alert state, the system remains there as long as $s_\text{bt}(t) > \theta_\text{exit}$, even if $s_\text{bt}(t)$ briefly falls below $\theta_\text{entry}$. This prevents an attack with natural variability from generating multiple fragmented incidents.

The novelty of FIX-3 is **adaptive exit persistence**: the number of consecutive windows below $\theta_\text{exit}$ required to deactivate the alert is not fixed, but a function of the current score:

$$N_\text{exit}(t) = \max\left(1,\; \min\left(N_\text{base},\; \left\lfloor\frac{3}{r(t) + 0.1}\right\rfloor\right)\right)$$

where $r(t) = s_\text{bt}(t) / \theta_\text{entry}$ is the score/threshold ratio and $N_\text{base} = 3$ (`alert_minimum_persistence`).

The physical behavior of this function is notable:

| Scenario | $r(t)$ | $N_\text{exit}$ | Interpretation |
|---|---|---|---|
| Very low score (safe): $s = 0.1\theta$ | $r = 0.1$ | $N = 3$ | Clearly normal traffic; slow de-escalation |
| Moderate score: $s = 0.5\theta$ | $r = 0.5$ | $N = 3$ | Borderline zone; sustained caution |
| High score (surgical attack): $s = 2\theta$ | $r = 2.0$ | $N = 1$ | Score drops fast; agile de-escalation |
| Extreme score: $s = 10\theta$ | $r = 10.0$ | $N = 1$ | Extreme event; immediate de-escalation |

A high-sigma attack that produces a single large-magnitude spike exits the alert state in 1 window. Low-magnitude noise requires 3 consecutive windows in a clean zone to deactivate.

Velocity Bypass samples are also re-protected after the hysteresis filter.

### 10.3 Warmup Period (FIX-2)

The first $N_\text{warmup} = \text{ma\_window\_size} \times 3 = 5 \times 3 = 15$ rows of the batch are marked `is_warmup = True`. During this period, the moving average does not have enough history to distinguish sustained trends from transient variations. The `ForensicEngine` applies a 0.5 confidence discount factor to incidents that fall entirely within the warmup period, preventing initialization noise from generating high-priority incidents.

---

## 11. Forensic Attribution

### 11.1 Physical Culprit Identification

For each anomalous sample, the following are identified:

**Univariate culprit feature**: the feature $f_{j^*}$ with the greatest Z-deviation from the baseline:

$$j^* = \arg\max_j \left|\frac{x_j - \mu_j}{\sigma_j}\right|$$

The direction (SPIKE if $x_{j^*} > \mu_{j^*}$, DROP if $x_{j^*} < \mu_{j^*}$) and percentage deviation are reported:

$$\Delta_{j^*} = \frac{|x_{j^*} - \mu_{j^*}|}{|\mu_{j^*}| + \varepsilon} \times 100\%$$

**Hilbert-space culprit component**: the principal component with the largest absolute coordinate deviation:

$$c^* = \arg\max_c |x_{\mathcal{H},c}|$$

In Blocked PCA mode, `_blocked_pca_family_mapping[c*]` returns `(family, local_index)`, allowing identification of which family the culprit component corresponds to. The $N_\text{top} = 3$ features with the highest loading on that component are reported as "suspicious features" (`top_features_per_pc = 3`).

### 11.2 Velocity Bypass Annotation

When Tier 4 triggers, forensic evidence includes an explicit annotation in the `forensic_evidence` field:

```
⚡VELOCITY BYPASS: vel_pps_z(z=+9.43) (≥10.0σ — emergency gate fired).
```

This annotation allows the `ForensicEngine` to automatically distinguish between incidents detected by geometric anomaly (Tiers 1–3) and incidents detected by regime transition (Tier 4), generating reports with etiological precision.

### 11.3 Gatekeeper Veto

As described in §7.3, if a sample produces $|\sigma_j| \geq 20.0\sigma$ in feature space (Pipeline Step 5B), the system forces `severity = 3` regardless of consensus. Emblematic example: `payload_continuity_ratio` at **4120σ** during GoldenEye DoS in CIC-IDS2017.

---

## 12. Detection Phase — The Inference Projection

### 12.1 The Golden Rule: Only `.transform()`

In the detection phase, no fitting function (`.fit()`, `.fit_transform()`) may be called on the test data. Only transformations whose parameters were calculated during training are applied. `HilbertSpaceProjector` explicitly validates its state with `validate_fitted()` before each `.transform()`:

```
Training:       BlockedPCA.fit_transform(X_train) → ColumnTransformer [FROZEN]
                    └─ StandardScaler_f.fit()     → μ_f, σ_f           [FROZEN]
                    └─ PCA_f.fit()                → V_f, Λ_f            [FROZEN]
                BallTree.fit(Xh_train)            → tree                [FROZEN]
                GMM.fit(Xh_train)                 → π_k, μ_k, Σ_k      [FROZEN]
                GMM_j.fit(Xf_train)               → θ_j (P99.9)         [FROZEN]
                                                     (per each feature j)

Detection:      BlockedPCA.transform(X_test)      ← uses μ_f, σ_f, V_f from train
                BallTree.query(Xh_test)            ← distances in train tree
                GMM.score_samples(Xh_test)         ← density under π_k, μ_k, Σ_k from train
                GMM_j.score_samples(Xf_test)       ← LL under GMM_j from train
                VelocityBypass.compute(vel_test)   ← self-normalizing (no train)
```

### 12.2 Configuration Runtime Hot-Swap

An innovation in v4.0 is the ability to update operational parameters without re-training the model. `HiGIEngine.update_runtime_config()` allows applying current `config.yaml` settings to an already loaded model:

```python
engine = HiGIEngine.load('models/baseline_monday.pkl')
settings = load_settings('config.yaml')
engine.update_runtime_config(settings.to_runtime_config())
results = engine.analyze(df_test)
```

Parameters updatable without re-training include: `alert_minimum_persistence`, `hysteresis_entry_multiplier`, `hysteresis_exit_multiplier`, `tribunal_consensus_threshold`, `velocity_bypass_threshold`, `velocity_tribunal_weight`, `sigma_culprit_min`, and all `persistence` parameters. Mathematical parameters (Hilbert space, detectors, percentile thresholds) remain invariant.

This is possible because `HiGIConfig` is a `frozen=True` dataclass: `apply_runtime_config()` creates a new immutable instance via `dataclasses.replace()`, respecting the principle of inertial frame immutability.

### 12.3 Schema Alignment

If the test dataset was captured under different network conditions than the baseline (e.g., additional protocols active):

- **Missing features (non-velocity)**: imputed with the corresponding baseline median (stored in the `ArtifactBundle`). The median is physically more informative than zero: a protocol active in the baseline but absent in test likely has activity near its median, not null.
- **Missing velocity features**: return zeros with a warning log — graceful degradation without inference error.
- **Extra features**: silently removed before projection.

---

## 13. Centralized Configuration and Runtime Hot-Swap

HiGI follows the **Single Source of Truth (SSoT)** principle for configuration: all thresholds, weights, and file paths reside exclusively in `config.yaml`. The source code contains no literal numbers with semantic meaning. The configuration flow chain is:

```
config.yaml
    └─→ src/config.py::load_settings()         [typed validation]
             └─→ HiGISettings                  [frozen dataclass]
                      └─→ .to_higi_config()    [bridge to HiGIConfig]
                               └─→ HiGIEngine(config=...)
                                        └─→ .update_runtime_config()
                                            (post-load hot-swap)
```

The `forensic` section of `config.yaml` includes the `sigma_culprit_min: 2.0` parameter, which filters incidents with a mean Z-score deviation below $2\sigma$ from the report. This eliminates pre-attack reconnaissance noise (UNB lab setup scans in CIC-IDS-2017) that generates incidents with $\bar{\sigma} \approx 0.5$–$1.2$ but no real operational impact.

---

## 14. Architectural Recommendations

### 14.1 Projection Mode Selection

Use **Blocked PCA** (default) when:
- The dataset has features from multiple physical families with very different variances.
- Precise forensic attribution by family is required.
- Network traffic includes low-variance TCP flag features alongside high-variance volumetric features.

Use **Global PCA** (fallback) when:
- The dataset is small (< 500 baseline samples) and Blocked PCA convergence is unstable.
- Compatibility with models serialized in previous HiGI versions is required.

### 14.2 Velocity Bypass Calibration

The `velocity_bypass_threshold` parameter should be calibrated according to the variability profile of the target network:

| Network Type | Recommended Threshold | Justification |
|---|---|---|
| Lab / Segmented network | 5.0–7.0σ | Low natural variability |
| Standard corporate network | 10.0σ (default) | Moderate variability |
| Datacenter / CDN network | 12.0–15.0σ | High natural traffic variability |

### 14.3 Baseline Capture

The baseline must capture the **full range of normal conditions** for the network. A single business day baseline may not represent weekend patterns, night hours, or backup periods. It is recommended to:

- Minimum 3 days of representative benign traffic.
- Include low and high activity periods.
- Exclude any period with maintenance activity or known unusual traffic.
- Verify quality with `get_capture_health_report()` before training.

---

## 15. Parameter Reference

### 15.1 Critical Parameters (High Detection Impact)

| Parameter | `HiGIConfig` Field | Default | Effect |
|---|---|---|---|
| `velocity.bypass_threshold` | `velocity_bypass_threshold` | 10.0 | $\theta_\text{bypass}$ threshold; lower → more sensitive to floods |
| `velocity.tribunal_weight` | `velocity_tribunal_weight` | 0.15 | Tier 4 weight in the Tribunal |
| `balltree.threshold_p95` | `threshold_p95` | 95.0 | Gatekeeper borderline threshold |
| `tribunal.consensus_threshold` | `tribunal_consensus_threshold` | 0.5 | $\tau_\text{consensus}$; lower → more alerts |
| `forensic.sigma_culprit_min` | — (ForensicEngine) | 2.0 | Noise filter in the report |
| `hilbert.blocked_pca_enabled` | `blocked_pca_enabled` | `true` | Blocked PCA vs global PCA |

### 15.2 Stabilization Parameters

| Parameter | `HiGIConfig` Field | Default | Effect |
|---|---|---|---|
| `persistence.alert_minimum_persistence` | `alert_minimum_persistence` | 3 | Minimum sustained alert windows |
| `persistence.hysteresis_exit_multiplier` | `hysteresis_exit_multiplier` | 0.75 | Exit hysteresis factor |
| `persistence.ma_window_size` | `ma_window_size` | 5 | Moving average window (warmup: ×3) |
| `sentinel.portero_sigma_threshold` | `portero_sigma_threshold` | 20.0 | $\sigma$ for unconditional veto |

### 15.3 Tribunal Parameters

| Parameter | `HiGIConfig` Field | Default | Effect |
|---|---|---|---|
| `gmm.use_bayesian` | `use_bayesian_gmm` | `true` | Bayesian GMM vs classic |
| `gmm.reg_covar` | `reg_covar` | 0.1 | Covariance regularization |
| `gmm.score_normalization` | `gmm_score_normalization_method` | `"cdf"` | GMM score normalization |
| `family_consensus.min_hits` | `family_consensus_min_hits` | 2 | Minimum co-trigger for borderline |

### 15.4 Blocked PCA Parameters

| Parameter | YAML Location | Default | Effect |
|---|---|---|---|
| `hilbert.blocked_pca_variance_per_family.volume` | `blocked_pca_variance_per_family` | 0.95 | Retained variance in Volume family |
| `hilbert.blocked_pca_variance_per_family.payload` | `blocked_pca_variance_per_family` | 0.95 | Retained variance in Payload family |
| `hilbert.blocked_pca_variance_per_family.flags` | `blocked_pca_variance_per_family` | 0.99 | Retained variance in Flags family |
| `hilbert.blocked_pca_variance_per_family.protocol` | `blocked_pca_variance_per_family` | 0.99 | Retained variance in Protocol family |
| `hilbert.blocked_pca_variance_per_family.connection` | `blocked_pca_variance_per_family` | 0.95 | Retained variance in Connection family |

---

*Document generated for HiGI IDS v4.0.0 — Velocity Bypass Architecture.* *All equations refer directly to the source code in [`src/models/higi_engine.py`](/src/models/higi_engine.py).* *Validated against CIC-IDS2017 (Wednesday + Thursday). DoS/DDoS Recall: 100%. Latency: ≤ 1 min.*