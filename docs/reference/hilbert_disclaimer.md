> [!IMPORTANT]
> **Technical Disclaimer:** The use of "Hilbert Space" in HiGI is a conceptual bridge between quantum state representation and high-dimensional network forensics.

### Conceptual Grounding

The nomenclature *Hilbert space* in HiGI is a deliberate conceptual reference to the mathematical framework of quantum mechanics, where the state of a system is represented as a vector in an infinite-dimensional inner product space. In quantum mechanics, measurement collapses the state vector onto an eigenstate; in HiGI, the Tribunal consensus collapses the multi-dimensional anomaly score onto a discrete severity level.

The analogy is not merely rhetorical. In both cases, the fundamental operation is the computation of a **distance from a reference state** (the baseline) using a metric that accounts for the natural variance of the system (the covariance structure). The Mahalanobis distance used by the BallTree detector is the classical mechanics analogue of the expectation value of the deviation operator in quantum theory.

### Implementation Reality

In concrete engineering terms, HiGI's "Hilbert space" is a finite-dimensional Euclidean space produced by the following sequence of transformations:

```mermaid
graph TD
    A["<b>Raw Features</b><br>xₜ ∈ ℝ⁴²<br><i>(RobustScaler-normalised)</i>"]
    
    A -->|"Yeo-Johnson PowerTransformer<br>(per-feature Gaussianisation)"| B
    
    B["<b>Gaussian Marginals</b><br>x̃ₜ ∈ ℝ⁴²<br><i>(Approximately Gaussian)</i>"]
    
    B -->|"Blocked PCA per physical family<br>(decorrelation + whitening)<br>Family f: zₜ⁽ᶠ⁾ = W⁽ᶠ⁾ᵀ(x̃ₜ⁽ᶠ⁾ − μ₀⁽ᶠ⁾)"| C
    
    C["<b>Whitened Hilbert Space</b><br>zₜ ∈ ℝᵏ<br><i>(k ≤ 42, whitened principal components)</i>"]
    
    C -->|"Tribunal Consensus<br>(Baseline displacement)"| D["<b>Physical Displacement Analysis</b>"]
```

The resulting space `ℝᵏ` has the property that:

1. **Euclidean distances approximate Mahalanobis distances** in the original feature space, because the Blocked PCA whitening effectively applies the inverse square root of the per-family covariance matrix.
    <details>
    <summary><b>Click to expand the full derivation</b></summary>

    Let $\mathbf{x} \in \mathbb{R}^n$ be a feature vector with mean $\boldsymbol{\mu}$ and
    covariance matrix $\boldsymbol{\Sigma}$.  The Mahalanobis distance of a point
    $\mathbf{x}$ to the centre of the distribution is

    $$D_M(\mathbf{x}) = \sqrt{(\mathbf{x} - \boldsymbol{\mu})^\top \boldsymbol{\Sigma}^{-1} (\mathbf{x} - \boldsymbol{\mu})}\, .$$

    Because $\boldsymbol{\Sigma}$ is symmetric and positive definite, it can be
    diagonalised:

    $$\boldsymbol{\Sigma} = \mathbf{U} \boldsymbol{\Lambda} \mathbf{U}^\top,$$

    where $\mathbf{U}$ is the orthogonal matrix of eigenvectors
    ($\mathbf{U}^\top \mathbf{U} = \mathbf{I}$) and $\boldsymbol{\Lambda}$ is the
    diagonal matrix of eigenvalues.  The *whitening* transformation is defined as

    $$\mathbf{z} = \boldsymbol{\Lambda}^{-1/2} \mathbf{U}^\top (\mathbf{x} - \boldsymbol{\mu}).$$

    Now compute the squared Euclidean norm of $\mathbf{z}$:

    $$\begin{aligned} \|\mathbf{z}\|_2^2 &= \mathbf{z}^\top \mathbf{z} \\ &= \bigl( \boldsymbol{\Lambda}^{-1/2} \mathbf{U}^\top (\mathbf{x} - \boldsymbol{\mu}) \bigr)^\top \bigl( \boldsymbol{\Lambda}^{-1/2} \mathbf{U}^\top (\mathbf{x} - \boldsymbol{\mu}) \bigr) \\ &= (\mathbf{x} - \boldsymbol{\mu})^\top \mathbf{U} (\boldsymbol{\Lambda}^{-1/2})^\top \boldsymbol{\Lambda}^{-1/2} \mathbf{U}^\top (\mathbf{x} - \boldsymbol{\mu}) . \end{aligned}$$

    Since $\boldsymbol{\Lambda}$ is diagonal,
    $(\boldsymbol{\Lambda}^{-1/2})^\top = \boldsymbol{\Lambda}^{-1/2}$ and
    $\boldsymbol{\Lambda}^{-1/2}\boldsymbol{\Lambda}^{-1/2} = \boldsymbol{\Lambda}^{-1}$,
    so

    $$\|\mathbf{z}\|_2^2 = (\mathbf{x} - \boldsymbol{\mu})^\top \mathbf{U} \boldsymbol{\Lambda}^{-1} \mathbf{U}^\top (\mathbf{x} - \boldsymbol{\mu}) .$$

    Using the matrix inverse identity
    $\boldsymbol{\Sigma}^{-1} = (\mathbf{U} \boldsymbol{\Lambda} \mathbf{U}^\top)^{-1} = \mathbf{U} \boldsymbol{\Lambda}^{-1} \mathbf{U}^\top$, we obtain

    $$\|\mathbf{z}\|_2^2 = (\mathbf{x} - \boldsymbol{\mu})^\top \boldsymbol{\Sigma}^{-1} (\mathbf{x} - \boldsymbol{\mu}) ,$$

    hence

    $$\boxed{\|\mathbf{z}\|_2 = \sqrt{(\mathbf{x} - \boldsymbol{\mu})^\top \boldsymbol{\Sigma}^{-1} (\mathbf{x} - \boldsymbol{\mu})} = D_M(\mathbf{x}) } .$$

    In words: **after whitening the feature space, Euclidean distance is identical to the Mahalanobis distance in the original space.**  This is why HiGI's BallTree detector, which uses plain Euclidean distance, is actually measuring statistically meaningful deviations from the baseline.

    </details>

2. **Each principal component maps to exactly one physical family**, because Blocked PCA operates independently per family. This is the property that makes forensic attribution possible: the PCA component that deviates most from the baseline can be directly traced back to its feature family.
3. **The space is maximally compact** for the given variance retention targets (`blocked_pca_variance_per_family`). Features with low discriminative power are collapsed into fewer components, reducing BallTree computation and improving statistical power.

The term "Hilbert space" in the codebase and documentation should therefore be understood as a conceptually motivated shorthand for: *a whitened, family-structured metric space in which the baseline distribution occupies a compact high-density region and anomalies are points geometrically distant from that region*.

### Why This Matters for Operational Trust

The physical grounding of the Hilbert projection is not an academic exercise. It is the engineering guarantee that a detection at 4,120σ (`payload_continuity_ratio`, DoS GoldenEye) is not a numerical artifact or a model pathology — it is the geometrically correct statement that the observed traffic window lies 4,120 baseline standard deviations away from the center of the normal traffic manifold, in the direction of maximum payload structure disruption. That statement is independently verifiable, dimensionally consistent, and operationally actionable.

Supervised models produce probabilities or class labels. HiGI produces **physical displacements from an inertial reference frame**. The difference is not cosmetic.