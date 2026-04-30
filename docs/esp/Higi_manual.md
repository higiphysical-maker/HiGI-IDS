# HiGI IDS — Manual Lógico-Matemático

**Hilbert-space Gaussian Intelligence**  
*Sistema de Detección de Intrusiones de Cuarta Generación*

**Versión:** 4.0.0 · **Estado:** Producción · **Autoría:** Blue Team Engineering  
**Módulo de referencia:** [`src/models/higi_engine.py`](/src/models/higi_engine.py)

---

## Tabla de Contenidos

1. [Fundamentos Conceptuales](#1-fundamentos-conceptuales)
2. [Arquitectura del Pipeline](#2-arquitectura-del-pipeline)
3. [Fase I — Construcción del Marco de Referencia Inercial (Entrenamiento)](#3-fase-i--construcción-del-marco-de-referencia-inercial-entrenamiento)
4. [Proyección al Espacio de Hilbert](#4-proyección-al-espacio-de-hilbert)
5. [Tier 1 — El Portero Geométrico (BallTree)](#5-tier-1--el-portero-geométrico-balltree)
6. [Tier 2 — El Tribunal Probabilístico (GMM + IForest)](#6-tier-2--el-tribunal-probabilístico-gmm--iforest)
7. [Tier 3 — El Centinela Físico (GMM Univariante)](#7-tier-3--el-centinela-físico-gmm-univariante)
8. [Tier 4 — La Válvula de Emergencia (Velocity Bypass)](#8-tier-4--la-válvula-de-emergencia-velocity-bypass)
9. [El Consenso del Tribunal](#9-el-consenso-del-tribunal)
10. [Mecanismos de Estabilización Temporal](#10-mecanismos-de-estabilización-temporal)
11. [Atribución Forense](#11-atribución-forense)
12. [Fase de Detección — La Proyección de Inferencia](#12-fase-de-detección--la-proyección-de-inferencia)
13. [Configuración Centralizada y Runtime Hot-Swap](#13-configuración-centralizada-y-runtime-hot-swap)
14. [Recomendaciones de Arquitectura](#14-recomendaciones-de-arquitectura)
15. [Referencia de Parámetros](#15-referencia-de-parámetros)

---

## 1. Fundamentos Conceptuales

### 1.1 La Perspectiva Física del Tráfico de Red

HiGI no trata el tráfico de red como una secuencia de eventos discretos que comparar contra una lista de firmas. Lo trata como un **campo físico**: un flujo continuo de energía, presión y composición que obedece reglas estadísticas estables en condiciones normales. Cuando el campo se altera, HiGI lo detecta como detectaría un sismógrafo una vibración anómala: por desviación respecto al estado de reposo calibrado.

Esta perspectiva tiene tres consecuencias arquitectónicas directas:

1. **El estado de reposo debe establecerse empíricamente** sobre tráfico benigno conocido. No existe ningún valor absoluto de "PPS normal"; sólo existe el PPS observado en este entorno, en esta red, en este horario.

2. **La detección es siempre relativa al estado de reposo.** Una muestra de tráfico nueva se evalúa por cuánto se aleja del campo calibrado, no por si contiene palabras clave de ataque.

3. **La geometría importa más que el valor absoluto.** Un paquete SYN con ratio 0.9 en una red de datacenter puede ser completamente normal; el mismo ratio en una red de oficina es una anomalía severa. La posición en el espacio de representación codifica el contexto del entorno.

### 1.2 El Espacio de Hilbert como Variedad de Datos

El espacio de features de tráfico de red es de alta dimensión (típicamente 40–60 features en v4.0, incluyendo las features de velocidad relativa) y altamente no lineal. La proyección al Espacio de Hilbert $\mathcal{H}$ — mediante Blocked PCA por familia física o mediante Yeo-Johnson + PCA global — reduce esa variedad a una representación compacta (típicamente 17–25 dimensiones) donde:

- La distancia euclidiana es un buen estimador de disimilitud semántica.
- La densidad de probabilidad gaussiana multivariante puede estimarse de forma estable.
- Las direcciones de mayor varianza corresponden a los "ejes físicos" más informativos del tráfico.

En sentido estricto, no es un espacio de Hilbert en la definición matemática pura (que requiere producto interno y completitud), pero la denominación captura la esencia: un espacio métrico donde la geometría tiene significado físico.

### 1.3 La Novedad Arquitectónica de v4.0: Ceguera Geométrica Resuelta

La auditoría de root-cause de abril de 2026 identificó que los ataques DoS Hulk y GoldenEye eran **geométricamente invisibles** en el Espacio de Hilbert. La razón es física: una inundación HTTP de alta tasa produce tráfico de baja varianza intra-ventana, estadísticamente idéntico al tráfico HTTP pesado normal del lunes. El BallTree asignaba scores de sólo $0.26 \times P99$ a estos ataques, mientras que Slowloris — genuinamente diferente del baseline — alcanzaba $1.56 \times P99$.

La solución introduce el **Tier 4 (VelocityBypassDetector)**: un detector que opera completamente *fuera* del Espacio de Hilbert, sobre tres features de Z-score dinámico de 60 segundos producidas por `processor_optime.py` v2.3.0. Este detector es **auto-normalizante**: no requiere entrenamiento y captura transiciones de régimen que son invisibles para cualquier detector basado en magnitudes absolutas.

---

## 2. Arquitectura del Pipeline

El pipeline de inferencia de HiGI v4.0 es una cascada de cuatro niveles de detección que operan de forma coordinada. El Tier 4 se ejecuta sobre **todas las muestras en paralelo** con el Tier 1. Los Tiers 2 y 3 operan sólo sobre muestras sospechosas (incluyendo las marcadas por el Tier 4), garantizando eficiencia computacional. El orden exacto de pasos en `HiGIEngine.analyze()` es:

```
┌─────────────────────────────────────────────────────────────────────┐
│                  PCAP / Socket en Vivo                               │
└────────────────────────────────┬───────────────────────────────────-┘
                                 │
                    ┌────────────▼────────────┐
                    │   processor_optime.py    │
                    │  Ingestión · Ventanas 1s │
                    │  Features físicas +      │
                    │  vel_pps_z · vel_bytes_z │
                    │  · vel_syn_z  (v2.3.0)   │
                    └────────────┬────────────┘
                                 │  X ∈ ℝⁿˣᵈ  (d ≈ 40–60 features)
                    ┌────────────▼────────────┐
                    │   Hilbert Projector      │
                    │   Blocked PCA (default)  │  ← pesos CONGELADOS
                    │   o Global PCA (fallback)│    del entrenamiento
                    └────────────┬────────────┘
                                 │  Xₕ ∈ ℋ  (h ≈ 17–25 dims)
          ┌──────────────────────┼──────────────────────┐
          │    (STEP 1)          │                      │  (STEP 1)
┌─────────▼──────────┐           │            ┌─────────▼──────────┐
│    TIER 1           │           │            │    TIER 4           │
│    BallTree         │           │            │    Velocity Bypass  │
│    Portero          │           │            │    TODAS las        │
│    Geométrico       │           │            │    muestras         │
└─────────┬──────────┘           │            └─────────┬──────────┘
          │ Normal → short-circuit│                      │ bypass_mask
          │ Sospechoso → Tier 2   │                      │ vel_score
          └──────────────────────┼──────────────────────┘
                                 │ Sospechosos ∪ Bypass  (STEP 2)
                    ┌────────────▼────────────┐
                    │   TIER 2A: GMM           │
                    │   Log-Likelihood         │
                    │   (densidad local)       │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   TIER 2B: IForest       │
                    │   Isolation Score        │
                    │   (estructura global)    │
                    └────────────┬────────────┘
                                 │  STEP 3A: Consenso ponderado
                    ┌────────────▼────────────┐
                    │   TIER 3: Centinela      │
                    │   GMM Univariante        │   STEP 3B
                    │   por feature            │
                    └────────────┬────────────┘
                                 │  STEP 3C: Decisión final + FIX-4
                    ┌────────────▼────────────┐
                    │   Bypass Override        │
                    │   is_anomaly[bypass]=1   │
                    │   severity=max(bt,vel)   │
                    └────────────┬────────────┘
                                 │  STEP 3D+3E: Persistencia + Histéresis
                    ┌────────────▼────────────┐
                    │   HYSTERESIS · PERSIST   │
                    │   Schmitt Trigger        │
                    │   Adaptativo (FIX-3)     │
                    │   [bypass protegido]     │
                    └────────────┬────────────┘
                                 │  STEP 5: Atribución forense
                    ┌────────────▼────────────┐
                    │   ATRIBUCIÓN FORENSE     │
                    │   PC culprit · SPIKE/    │
                    │   DROP · MITRE ATT&CK    │
                    │   ⚡VELOCITY BYPASS ann. │
                    └─────────────────────────┘
```

**Nota sobre el cortocircuito y el Tier 4:** Las muestras marcadas por el Velocity Bypass (`bypass_mask = True`) se incorporan a la máscara de sospechosos y reciben evaluación completa de Tier 2. Esto garantiza que la evidencia del Tribunal sea siempre completa, incluso para muestras cuya anomalía fue detectada primariamente por el Tier 4.

---

## 3. Fase I — Construcción del Marco de Referencia Inercial (Entrenamiento)

### 3.1 La Analogía del Marco Inercial

En física clásica, un marco de referencia inercial es aquel en el que las leyes del movimiento se cumplen sin correcciones ficticias: un observador en reposo puede medir las desviaciones de cualquier objeto móvil respecto a ese estado de reposo.

El entrenamiento de HiGI construye exactamente ese marco: a partir de tráfico benigno conocido (e.g., el lunes del dataset CIC-IDS-2017), calcula todos los parámetros estadísticos que definen "el reposo" de esta red. Una vez establecido el marco, se **congela**. Ninguna muestra de tráfico futuro puede alterarlo. Esto se impone arquitectónicamente mediante el dataclass `HiGIConfig(frozen=True)`: cualquier modificación de parámetros crea una nueva instancia mediante `dataclasses.replace()`, preservando la inmutabilidad del contrato original.

### 3.2 Pasos del Entrenamiento (`HiGIEngine.train()`)

**Paso 0 — Extracción del esquema de features**

El engine extrae el conjunto de columnas numéricas $\mathcal{F} = \{f_1, f_2, \ldots, f_d\}$ de la matriz baseline, excluyendo metadatos (`dt`, `timestamp`, `second_window`, `label`, `frame_number`). En v4.0, las features de velocidad relativa $\{v_\text{pps}, v_\text{bytes}, v_\text{syn}\}$ se incluyen en el esquema cuando están presentes.

Se calculan y congelan los estadísticos de referencia univariante:

$$\mu_j = \frac{1}{N}\sum_{i=1}^N x_{ij}, \qquad \sigma_j = \sqrt{\frac{1}{N-1}\sum_{i=1}^N (x_{ij} - \mu_j)^2}, \qquad j \in \{1, \ldots, d\}$$

Con degradación graceful si las features de velocidad están ausentes:
```
⚠ Velocity features ABSENT from baseline. VelocityBypass will degrade
gracefully during inference. Re-process PCAP with processor_optime v2.3.0+
to enable Tier 4.
```

**Paso 0.5 — GMMs Univariantes (una por feature)**

Para cada feature $f_j$, se ajusta un modelo de mezcla gaussiana de $K_j$ componentes óptimo (seleccionado por la función `_find_optimal_k_for_feature()` mediante BIC/AIC/Silhouette/Davies-Bouldin) y se computa el umbral de log-likelihood al P99.9 del entrenamiento:

$$\tau_j = \mathrm{P}_{99.9}\bigl[\ell_j(x_{ij})\bigr]_{\,x_{ij} \sim \mathcal{D}_\text{train}}$$

donde $\ell_j(x) = \log p_j(x)$ es la log-likelihood del GMM univariante para la feature $j$. Este umbral es **específico por feature**: la sensibilidad del `flag_syn_ratio` y la del `flow_duration` son intrínsecamente diferentes. Un umbral global introduciría sesgos sistemáticos entre features con varianza natural muy diferente.

**Paso 0.6 — Normalización de los pesos del Tribunal**

Los pesos del Tribunal se normalizan para que su suma sea exactamente 1.0. Con `velocity_tribunal_weight = 0.15` (default en `HiGIConfig`) y `velocity_bypass_enabled = True`:

$$w_\text{vel} = 0.15, \quad w_\text{rem} = 1.0 - 0.15 = 0.85$$

$$w_\text{bt} = 0.25 \cdot w_\text{rem} = 0.2125, \quad w_\text{gmm} = 0.40 \cdot w_\text{rem} = 0.34, \quad w_\text{if} = 0.35 \cdot w_\text{rem} = 0.2975$$

Este reparto se computa en `HiGIConfig.__post_init__()` y se re-normaliza en `train()` para garantizar $\sum_i w_i = 1.0$.

**Paso 1 — Proyección al Espacio de Hilbert**

Detallado en la Sección 4.

**Paso 2 — Entrenamiento de los detectores del Tribunal**

Con la matriz baseline proyectada $X_\mathcal{H} \in \mathbb{R}^{N \times h}$ se ajustan tres detectores:

| Detector | Parámetros congelados | Función física |
|---|---|---|
| BallTree (Tier 1) | Árbol $k$-NN · $\delta_{P99}$ · percentiles por severidad | Geometría: ¿está en zona conocida? |
| GMM (Tier 2A) | $\{\pi_k, \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k\}$ · $\tau_\text{gmm}$ | Densidad: ¿qué tan probable es? |
| IForest (Tier 2B) | Ensamble de árboles de aislamiento | Estructura: ¿es fácil de aislar? |

El **Tier 4 (Velocity Bypass) no tiene parámetros entrenables**: sus Z-scores son auto-normalizantes por construcción.

### 3.3 Por Qué Se Congelan los Pesos

Si en la fase de detección se re-entrenara el normalizador con los datos de test, ocurriría lo que llamamos **envenenamiento de la referencia**: una inundación de tráfico DoS muy homogéneo ocuparía la mayor parte de la distribución del batch y se convertiría en el nuevo "estado de reposo". El sistema detectaría como anómalo el tráfico benigno residual.

Matemáticamente: sea $\hat{\mu}_\text{batch}$ y $\hat{\sigma}_\text{batch}$ los momentos del batch de inferencia. Si el batch contiene tráfico DoS masivo:

$$\hat{\mu}_\text{batch}^\text{pps} \gg \mu_\text{train}^\text{pps}$$

y el DoS se proyecta al centro de la distribución normalizada, obteniendo score cero. Al usar los parámetros del entrenamiento congelados:

$$z_i = \frac{x_i - \mu_\text{train}}{\sigma_\text{train}}$$

el DoS produce valores $z_i \gg 1$ y es detectado correctamente por el Centinela Físico.

---

## 4. Proyección al Espacio de Hilbert

El `HilbertSpaceProjector` soporta dos modos de proyección seleccionables en `HiGIConfig`:

### 4.1 Modo Primario: Blocked PCA por Familia Física (`blocked_pca_enabled=True`)

Este es el modo por defecto en v4.0. En lugar de aplicar un PCA global sobre todas las features, el Blocked PCA aplica un pipeline independiente `(StandardScaler → PCA)` por cada familia física, luego concatena las representaciones resultantes:

| Familia | Features representativas | Varianza objetivo |
|---|---|---|
| `volume` | `total_pps_log`, `total_bytes_log`, `bytes`, `vel_pps_z`, `vel_bytes_z` | 95% |
| `payload` | `entropy_avg`, `payload_continuity`, `payload_continuity_ratio` | 95% |
| `flags` | `flag_syn_ratio`, `flag_rst_ratio`, `flag_psh_ratio`, `vel_syn_z` | 99% |
| `protocol` | `tcp_ratio`, `udp_ratio`, `icmp_ratio` | 99% |
| `connection` | `unique_dst_ports`, `port_scan_ratio`, `flow_duration`, `iat_mean` | 95% |

La motivación de este diseño es el **Colapso de Componentes**: en el PCA global, las familias de alta varianza (`payload`) monopolizan los primeros componentes principales a expensas de familias de baja varianza (`flags`). Un `flag_syn_ratio = 0.99` — firma inequívoca de SYN flood — tiene varianza absoluta pequeña (su rango natural es $[0,1]$) y quedaría enterrado en componentes tardíos. El Blocked PCA garantiza que cada familia tenga representación proporcional en el espacio conjunto $\mathcal{H}$.

La transformación de una muestra en modo Blocked PCA es:

$$\mathbf{x}_\mathcal{H} = \bigl[\mathbf{V}_\text{vol}^\top \tilde{\mathbf{x}}_\text{vol} \;\|\; \mathbf{V}_\text{pay}^\top \tilde{\mathbf{x}}_\text{pay} \;\|\; \mathbf{V}_\text{flags}^\top \tilde{\mathbf{x}}_\text{flags} \;\|\; \mathbf{V}_\text{prot}^\top \tilde{\mathbf{x}}_\text{prot} \;\|\; \mathbf{V}_\text{conn}^\top \tilde{\mathbf{x}}_\text{conn} \bigr]$$

donde $\tilde{\mathbf{x}}_f = \text{StandardScaler}_f(\mathbf{x}_f)$ es la normalización por familia y $\mathbf{V}_f$ son las matrices de loadings del PCA por familia, de dimensiones ajustadas a la varianza objetivo de cada una.

El `ColumnTransformer` subyacente usa `remainder="drop"` (features no asignadas a ninguna familia se descartan) y `n_jobs=1` para compatibilidad con la serialización `joblib`.

### 4.2 Modo Alternativo: PCA Global con Yeo-Johnson (`blocked_pca_enabled=False`)

En este modo de fallback, la proyección sigue el pipeline clásico de tres pasos:

**Paso 1 — Clipping al P99:** Se calculan los límites del percentil P99 por feature y se recortan los valores extremos, previniendo que outliers del baseline distorsionen la estimación de $\boldsymbol{\lambda}$.

**Paso 2 — Transformación de Yeo-Johnson:** El espacio de features de red es altamente no gaussiano. PPS y bytes siguen distribuciones log-normal con cola pesada; los ratios de flags son bimodales. La transformación de Yeo-Johnson gaussianiza cada feature:

$$\psi_\lambda(x) = \begin{cases}
\dfrac{(x+1)^\lambda - 1}{\lambda} & \text{si } \lambda \neq 0, \; x \geq 0 \\[6pt]
\ln(x+1) & \text{si } \lambda = 0, \; x \geq 0 \\[6pt]
\dfrac{1 - (1-x)^{2-\lambda}}{2-\lambda} & \text{si } \lambda \neq 2, \; x < 0 \\[6pt]
-\ln(1-x) & \text{si } \lambda = 2, \; x < 0
\end{cases}$$

El exponente $\lambda_j$ se estima por máxima verosimilitud para cada feature durante el entrenamiento (`sklearn.preprocessing.PowerTransformer(method="yeo-johnson", standardize=True)`) y se **congela**. A diferencia del logaritmo natural, Yeo-Johnson acepta valores negativos, lo que es esencial para las features de velocidad relativa $v_j \in \mathbb{R}$.

Si la Yeo-Johnson produce valores no finitos, se aplica un `QuantileTransformer` de fallback entrenado sobre el baseline.

**Paso 3 — PCA con Blanqueamiento:** Sobre la matriz transformada $\tilde{X}$, se aplica PCA con `whiten=True`. El blanqueamiento escala los componentes principales por el inverso de su desviación estándar, de modo que todos tienen varianza unitaria en $\mathcal{H}$. Esto hace que la distancia euclidiana en $\mathcal{H}$ sea equivalente a la **distancia de Mahalanobis** en el espacio original:

$$d_\mathcal{H}(\mathbf{a}, \mathbf{b}) = \|\mathbf{a}_\mathcal{H} - \mathbf{b}_\mathcal{H}\|_2 \approx \sqrt{(\mathbf{a} - \mathbf{b})^\top \boldsymbol{\Sigma}^{-1} (\mathbf{a} - \mathbf{b})}$$

El número de componentes $h$ se selecciona automáticamente para retener el 99% de la varianza:

$$h = \min\left\{k : \sum_{i=1}^k \lambda_i \Big/ \sum_{i=1}^d \lambda_i \geq 0.99\right\}$$

en la práctica $h \approx 17$–$20$ componentes de los 40–60 features originales.

### 4.3 Metadatos de Atribución Forense

En modo Blocked PCA, el método `_build_blocked_pca_metadata()` construye dos estructuras para la atribución forense:

- `_blocked_pca_family_mapping`: mapa de índice global de componente → `(familia, índice_local_en_familia)`
- `_blocked_pca_loadings_by_family`: para cada familia, la matriz de loadings transpuesta `(n_features_familia, n_componentes_familia)` y la lista de features

Estas estructuras permiten al `ForensicEngine` trazar cualquier anomalía en $\mathcal{H}$ de vuelta a las features originales de la familia responsable, sin ambigüedad sobre qué familia contribuyó a cada componente.

---

## 5. Tier 1 — El Portero Geométrico (BallTree)

### 5.1 Intuición Física

El Portero responde a la pregunta más directa: **¿esta muestra está en una región del espacio que el tráfico benigno visitó durante el entrenamiento?**

Un BallTree sobre las muestras del baseline en $\mathcal{H}$ constituye un mapa de densidad geométrica. Si la distancia media a los $k=5$ vecinos más próximos es pequeña, la muestra está en una zona poblada. Si es grande, está en una zona desértica: un outlier.

### 5.2 Puntuación Absoluta (FIX-1)

La puntuación del BallTree es la distancia euclidiana media a los $k$ vecinos más próximos en $\mathcal{H}$, normalizada contra el percentil P99 del entrenamiento:

$$s_\text{bt}(\mathbf{x}) = \frac{1}{\delta_{P99}} \cdot \frac{1}{k} \sum_{i=1}^{k} \|\mathbf{x}_\mathcal{H} - \mathbf{nn}_i\|_2$$

donde $\delta_{P99} = \mathrm{P}_{99}\bigl[\bar{d}_{kNN}(\mathbf{x}_\text{train})\bigr]$ es el percentil P99 de las distancias medias $k$-NN calculadas sobre el propio conjunto de entrenamiento y guardado en `BallTreeDetector.training_p99_distance`.

Esta normalización tiene una consecuencia física fundamental: el score es **batch-independent**. Un ataque DoS que produce distancias 10 veces mayores que $\delta_{P99}$ obtendrá $s_\text{bt} \approx 10.0$ independientemente de qué otras muestras estén en el batch. Sin esta normalización (con min-max por batch), un flood homogéneo que domina el batch comprime todos los scores y se vuelve invisible.

La interpretación de la escala resultante es directa:

| $s_\text{bt}$ | Interpretación | Ejemplo real (CIC-IDS2017) |
|---|---|---|
| $< 0.9$ | Claramente dentro del baseline | Tráfico Monday benigno |
| $\approx 1.0$ | Exactamente en el límite P99 | Tráfico HTTP de alta carga |
| $1.0$–$2.0$ | Zona borderline | Slowloris: $s \approx 1.56$ |
| $> 5.0$ | Fuertemente anómalo | DoS GoldenEye: $s \gg 5$ |
| DoS Hulk (high-rate flood) | $\approx 0.26$ (¡invisible!) | → resuelto por Tier 4 |

### 5.3 Estratificación de Severidad

El score se mapea a cinco niveles de severidad con un multiplicador `balltree_slack = 1.2` aplicado a los umbrales de percentil:

| Zona | Condición | Acción |
|---|---|---|
| Normal | $s_\text{bt} < s_{P90}$ | Short-circuit: skip Tiers 2 y 3 |
| Soft Zone | $s_{P90} \leq s_\text{bt} < s_{P95}$ | Pasa a Tier 2 como sospechoso leve |
| Borderline | $s_{P95} \leq s_\text{bt} < s_{P99}$ | Tier 2 + requiere consenso familiar (FIX-4) |
| Medium | $s_{P99} \leq s_\text{bt} < s_{P99.9}$ | Tier 2, confirmación por consenso ponderado |
| Critical | $s_\text{bt} \geq s_{P99.9}$ | Anomalía **incondicional** |

---

## 6. Tier 2 — El Tribunal Probabilístico (GMM + IForest)

### 6.1 El Complemento Geométrico-Probabilístico

El BallTree opera con geometría: mide distancias. Pero en regiones del espacio de alta dimensión con densidad gaussiana, la distancia entre cualquier par de puntos tiende a concentrarse (fenómeno de *concentración de la medida*). Dos muestras de naturaleza totalmente diferente pueden estar geométricamente cercanas.

El GMM corrige este problema: en lugar de medir distancias, mide **densidad de probabilidad local**. La relación entre ambos puede expresarse así:

> **Portero**: *¿Has estado aquí antes?* (distancia)  
> **Tribunal**: *¿Qué tan probable es que alguien como tú esté aquí?* (densidad)

### 6.2 Gaussian Mixture Model — Formulación

Dado el espacio de Hilbert proyectado $\mathbf{x} \in \mathbb{R}^h$, el GMM estima la distribución del tráfico benigno como mezcla de $K$ gaussianas completas:

$$p_\text{GMM}(\mathbf{x}) = \sum_{k=1}^{K} \pi_k \; \mathcal{N}(\mathbf{x} \mid \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k)$$

con $\sum_k \pi_k = 1$, $\pi_k \geq 0$. La **log-verosimilitud** de una muestra bajo el modelo es:

$$\ell(\mathbf{x}) = \log p_\text{GMM}(\mathbf{x}) = \log \sum_{k=1}^{K} \pi_k \; \mathcal{N}(\mathbf{x} \mid \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k)$$

El score de anomalía del GMM es la log-likelihood **invertida** (mayor score = más anómalo):

$$s_\text{gmm}(\mathbf{x}) = -\ell(\mathbf{x})$$

El umbral de decisión binaria es el percentil P99.9 de $s_\text{gmm}$ sobre el conjunto de entrenamiento:

$$\tau_\text{gmm} = \mathrm{P}_{99.9}\bigl[s_\text{gmm}(\mathbf{x}_\text{train})\bigr]$$

Una muestra se marca como anómala por el GMM si $s_\text{gmm}(\mathbf{x}) > \tau_\text{gmm}$.

### 6.3 Por Qué BayesianGaussianMixture

HiGI usa `BayesianGaussianMixture` con prior de concentración de pesos $\alpha_0 = 10^{-5}$ (valor en `HiGIConfig.bayesian_weight_concentration_prior`). Un prior pequeño penaliza clusters con muy pocos miembros, forzando al modelo a concentrarse en los clusters densos del baseline. Esto evita el sobreajuste de clusters espurios a artefactos de muestreo en capturas de larga duración. La covarianza se regulariza con un término de ridge $\delta = 0.1$ (`reg_covar`) para estabilidad numérica en el espacio de Hilbert de alta dimensión.

### 6.4 Selección Adaptativa de K

El número óptimo de componentes $K^*$ se selecciona mediante voto ponderado de cuatro criterios en `_select_optimal_components()`:

$$K^* = \arg\max_K \bigl[0.40 \cdot \text{BIC}^*(K) + 0.10 \cdot \text{AIC}^*(K) + 0.25 \cdot \text{Sil}^*(K) + 0.25 \cdot \text{DB}^*(K)\bigr]$$

donde los asteriscos indican normalización min-max de los scores individuales (con inversión para BIC y AIC, donde valores menores son mejores). El BIC domina con peso 0.40 porque penaliza la complejidad del modelo de forma consistente con el tamaño muestral.

### 6.5 Isolation Forest — Detección Estructural

El IForest complementa al GMM: un punto es anómalo si puede **aislarse con pocas particiones** en un árbol de decisión aleatorio. Mientras el GMM mide densidad (¿qué tan probable es?), el IForest mide aislabilidad estructural (¿qué tan fácil es separarlo del resto?).

Un ataque de exfiltración de datos puede ser difícil de detectar por densidad (si la región del espacio tiene pocos puntos del training pero el perfil multivariante existe) pero fácil de detectar por estructura (la combinación de features es única). La contaminación esperada es `iforest_contamination = 0.005` (0.5%), configurada para redes con tráfico relativamente estable.

---

## 7. Tier 3 — El Centinela Físico (GMM Univariante)

### 7.1 La Hipótesis de Invarianza Marginal

Una anomalía que se manifiesta en el espacio multivariante (Tiers 1 y 2) debe manifestarse al menos en una de las distribuciones marginales de sus features componentes. El Centinela explota esta hipótesis verificando, feature por feature, si la muestra es físicamente plausible en cada dimensión por separado.

Para cada feature $f_j$, se tiene un GMM univariante con log-likelihood $\ell_j(x)$ y umbral $\tau_j$ (P99.9 de $\ell_j$ en el training). El Centinela vota a favor de anomalía si:

$$\exists\, j : \ell_j(x_j) < \tau_j$$

La condición requiere que **al menos una** feature produzca una log-likelihood por debajo del umbral de entrenamiento (el valor observado es más improbable de lo que el 99.9% del tráfico benigno jamás produjo en esa feature).

### 7.2 Análisis de Direccionalidad

Cuando `sentinel_directionality_analysis = True`, el Centinela no sólo identifica la feature culpable sino que registra la **dirección de la anomalía**:

$$\text{dirección}(x_j) = \begin{cases}
\text{SPIKE} & \text{si } x_j > \mu_j \\
\text{DROP} & \text{si } x_j < \mu_j
\end{cases}$$

y la desviación relativa porcentual:

$$\Delta_j = \frac{|x_j - \mu_j|}{|\mu_j| + \varepsilon} \times 100\%$$

Esta información es el insumo principal del `ForensicEngine` para construir la narrativa de ataque. Un `icmp_ratio` con SPIKE del +612.5% es una firma directamente interpretable como colapso de protocolo (respuesta del servidor saturado), no requiere conocimiento previo del tipo de ataque.

### 7.3 El Veto del Portero (Portero Veto)

Si una muestra produce $|\sigma_j| \geq \theta_\text{portero} = 20.0\sigma$ en cualquier feature individual, el sistema la fuerza a `severity = 3` independientemente del consenso (`portero_sigma_threshold` en `HiGIConfig`). Esta es la excepción a la regla de consenso: una desviación de 20 sigmas en cualquier feature física tiene probabilidad de orden $10^{-88}$ bajo la hipótesis nula gaussiana. Ningún consenso adicional es necesario.

**Ejemplo real:** Durante el ataque DoS GoldenEye en CIC-IDS2017 Wednesday, `payload_continuity_ratio` alcanzó **4120σ**. Este valor activa el Portero Veto de forma incondicional.

---

## 8. Tier 4 — La Válvula de Emergencia (Velocity Bypass)

### 8.1 El Problema de la Ceguera Geométrica

Los ataques de inundación masiva (DoS Hulk, GoldenEye) generan tráfico estadísticamente **indistinguible del tráfico HTTP pesado normal** en el Espacio de Hilbert. La razón es física:

Durante un flood de HTTP GET a 10.000 paquetes/segundo, todos los paquetes son idénticos (mismo tamaño, mismo TTL, mismo puerto destino). La **varianza intra-ventana** se colapsa a casi cero. El vector de features de una ventana de 1 segundo es perfectamente regular: distancia $k$-NN pequeña, log-likelihood del GMM alta. El BallTree asigna $s_\text{bt} \approx 0.26 \times P99$ — clasificado como tráfico benigno de baja prioridad.

El problema no es la calibración del sistema; es que el ataque produce un tipo de tráfico que *existe en el baseline* (HTTP masivo es normal en redes de alto tráfico). La geometría y la densidad no bastan para discriminarlo.

### 8.2 La Señal de Régimen Dinámico

Lo que *no* existe en el baseline benigno es una **transición abrupta de régimen**. Un servidor HTTP sano que recibe muchas peticiones las recibe de muchos clientes simultáneos, con varianza temporal natural. Un DoS Hulk aparece en 1–3 segundos como una multiplicación brutal del PPS sin precedente en la historia reciente.

La solución: calcular el Z-score de cada feature de velocidad **respecto a su propia media móvil de 60 segundos** (calculado por `processor_optime.py` v2.3.0 antes de la ingestión al engine):

$$z_\text{pps}(t) = \frac{x_\text{pps\_log}(t) - \bar{x}_\text{pps\_log}^{(60)}(t)}{\hat{\sigma}_\text{pps\_log}^{(60)}(t) + \varepsilon}$$

$$z_\text{bytes}(t) = \frac{x_\text{bytes\_log}(t) - \bar{x}_\text{bytes\_log}^{(60)}(t)}{\hat{\sigma}_\text{bytes\_log}^{(60)}(t) + \varepsilon}$$

$$z_\text{syn}(t) = \frac{x_\text{syn\_ratio}(t) - \bar{x}_\text{syn\_ratio}^{(60)}(t)}{\hat{\sigma}_\text{syn\_ratio}^{(60)}(t) + \varepsilon}$$

donde $\varepsilon = 10^{-6}$ previene divisiones por cero durante períodos de tráfico perfectamente estacionario. Estas tres features (`vel_pps_z`, `vel_bytes_z`, `vel_syn_z`) se denominan colectivamente **features de velocidad relativa**.

El Z-score dinámico mide la **presión** que el tráfico ejerce sobre su propia historia reciente. No mide si el PPS es alto en términos absolutos, sino si es *anormalmente alto para este momento específico de la jornada*.

### 8.3 La Puerta de Bypass de Emergencia (`VelocityBypassDetector.compute()`)

Sea $Z_{\max}(t) = \max\bigl(|z_\text{pps}(t)|, |z_\text{bytes}(t)|, |z_\text{syn}(t)|\bigr)$ el Z-score de velocidad máximo en el instante $t$. El Tier 4 define:

$$\text{bypass}(t) = \mathbf{1}\bigl[Z_{\max}(t) \geq \theta_\text{bypass}\bigr]$$

con $\theta_\text{bypass} = 10.0\sigma$ por defecto en `HiGIConfig.velocity_bypass_threshold` (configurable vía `config.yaml → velocity.bypass_threshold`). Si `bypass(t) = 1`, la muestra es marcada `is_anomaly = 1` **incondicionalmente**. La severidad se asigna según `VELOCITY_SEVERITY_THRESHOLDS`:

$$\text{severity}(t) = \begin{cases}
3 & \text{si } Z_{\max} \geq 12.0\sigma \quad \text{(Critical)} \\
2 & \text{si } 8.0\sigma \leq Z_{\max} < 12.0\sigma \quad \text{(Medium)} \\
1 & \text{si } 5.0\sigma \leq Z_{\max} < 8.0\sigma \quad \text{(Borderline)}
\end{cases}$$

El score continuo para el Tribunal es:

$$s_\text{vel}(t) = \min\left(\frac{Z_{\max}(t)}{\theta_\text{bypass}},\; 3.0\right) \in [0, 3.0]$$

normalizado a $[0,1]$ dividiéndolo por 3.0 antes de entrar en la suma ponderada del consenso. El `vel_culprit` se registra como `"feature_name(z=±X.XX)"` para la evidencia forense.

### 8.4 Por Qué el Umbral es 10.0σ (y no 5.0σ)

El `HiGIConfig` define `velocity_bypass_threshold = 10.0σ` como default. Este es un umbral más conservador que el discutido en análisis previos, elegido para minimizar falsos positivos en entornos productivos con variabilidad de tráfico moderada. Para entornos con tráfico muy estable (laboratorio forense, red segmentada), el parámetro puede reducirse a 5.0σ.

Bajo hipótesis gaussiana, $P(|Z| \geq 5) \approx 5.7 \times 10^{-7}$ y $P(|Z| \geq 10) \approx 1.5 \times 10^{-23}$. Un DoS Hulk que duplica el PPS en 3 segundos sobre una red con $\hat{\sigma}_\text{pps}^{(60)} \approx 0.15$ (log-scale) produce:

$$z_\text{pps} = \frac{\log(2 \cdot \text{PPS}_\text{baseline}) - \log(\text{PPS}_\text{baseline})}{\hat{\sigma}_\text{pps}^{(60)}} = \frac{\ln 2}{0.15} \approx 4.6\sigma$$

y en pocos segundos adicionales, cuando el flood se estabiliza a 5× el baseline, $z_\text{pps} \approx 10.7\sigma$: activando el bypass incluso con el umbral conservador de 10.0σ.

### 8.5 Integración de las Features de Velocidad en el Espacio de Hilbert

Las features de velocidad relativa ($v_\text{pps}$, $v_\text{bytes}$, $v_\text{syn}$) se incluyen en la proyección al Espacio de Hilbert cuando están presentes en el baseline. En tráfico benigno estacionario, sus valores se agrupan cerca de 0 (régimen estable). El BallTree del baseline aprende que $|v_j| \approx 0$ es normal: cuando en inferencia aparece $|v_\text{pps}| \gg 1$, el BallTree también lo detecta como alejado del baseline en $\mathcal{H}$, complementando la señal directa del Tier 4. En modo Blocked PCA, `vel_pps_z` y `vel_bytes_z` pertenecen a la familia `volume`, y `vel_syn_z` a la familia `flags`, por lo que cada una contribuye en el bloque de su familia.

### 8.6 Protección del Bypass Ante Filtros de Persistencia

En los pasos 3D y 3E del pipeline, el filtro de persistencia (`rolling_min`) y la histéresis podrían suprimir un bypass aislado de 1 segundo. Para evitar que el onset del ataque sea silenciado, las muestras marcadas como bypass se **protegen explícitamente**: tras cada filtro, se re-aplica `is_anomaly[vel_bypass] = 1`. El bypass supera todos los filtros por diseño.

---

## 9. El Consenso del Tribunal

### 9.1 Votación Ponderada

La decisión final integra cuatro señales mediante una suma ponderada. Los scores de GMM e IForest se normalizan min-max por batch (aceptable porque se usan como tie-breakers relativos):

$$C(\mathbf{x}) = w_\text{bt} \cdot \hat{s}_\text{bt} + w_\text{gmm} \cdot \hat{s}_\text{gmm} + w_\text{if} \cdot \hat{s}_\text{if} + w_\text{vel} \cdot \hat{s}_\text{vel}$$

donde $\hat{s}_\text{vel} = s_\text{vel} / 3.0$ (ya tiene escala física definida, no requiere normalización por batch).

Los pesos por defecto, computados en `HiGIConfig.__post_init__()` con `velocity_tribunal_weight = 0.15`, son:

$$w_\text{bt} = 0.2125, \quad w_\text{gmm} = 0.3400, \quad w_\text{if} = 0.2975, \quad w_\text{vel} = 0.1500$$

El GMM tiene el peso más alto de los detectores Hilbert-space porque es el estimador de densidad más directo para la estructura probabilística del tráfico benigno. El score del BallTree utiliza normalización absoluta (FIX-1), por lo que no se normaliza min-max en el Tribunal: $\hat{s}_\text{bt} = s_\text{bt}$ directamente.

### 9.2 Escalada por Nivel de Severidad

El proceso de decisión en el paso 3C difiere según el nivel de severidad del BallTree y la presencia del Velocity Bypass:

```
is_anomaly = 0  (estado inicial para todos los samples)

Si severity == 3 (Critical):      → is_anomaly = 1  (incondicional)
Si severity == 2 (Medium):        → is_anomaly = 1  si C(x) ≥ τ_consenso
Si severity == 1 (Borderline):    → is_anomaly = 1  si C(x) ≥ τ_consenso
                                                 Y  consenso_familiar (FIX-4)
Si severity == 0 y vel_bypass:    → is_anomaly = 1  (Tier 4 override)
                                    severity = max(bt_severity, vel_bypass_sev)
Si severity == 0 y Sentinela:     → is_anomaly = 1  si C(x) ≥ max(0.7, τ_consenso)
```

El umbral de consenso por defecto es $\tau_\text{consenso} = 0.5$.

### 9.3 Consenso Familiar (FIX-4)

Una muestra borderline ($s_\text{bt} \in [s_{P95}, s_{P99})$) sólo se confirma como anomalía si al menos $N_\text{hits} = 2$ features de una misma familia de `METRIC_FAMILIES` están simultáneamente elevadas ($|Z_j| \geq 2.0\sigma$ respecto al baseline):

| Familia (`METRIC_FAMILIES`) | Features miembro en v4.0 |
|---|---|
| `volume_flood` | `total_pps_log`, `total_bytes_log`, `flag_syn_ratio`, `flag_rst_ratio`, `pps_momentum`, **`vel_pps_z`**, **`vel_bytes_z`**, **`vel_syn_z`** |
| `slow_attack` | `flow_duration`, `iat_mean`, `payload_continuity`, `flag_fin_ratio` |
| `exfiltration` | `payload_continuity_ratio`, `entropy_avg`, `bytes_velocity`, `flag_psh_ratio` |
| `kinematics` | `pps_velocity`, `bytes_velocity`, `pps_acceleration`, `bytes_acceleration`, `pps_volatility`, `bytes_volatility` |
| `recon` | `port_scan_ratio`, `unique_dst_ports`, `flag_fin_ratio`, `flag_urg_ratio` |

**Cambio en v4.0:** Las tres features de velocidad relativa se añadieron a la familia `volume_flood`. Esto garantiza que un evento de Velocity Bypass activa automáticamente el consenso familiar para esa familia, ya que `vel_pps_z >= 10.0σ >> 2.0σ` satisface `N_hits >= 2` por sí solo combinado con cualquier otra feature de la familia.

El requerimiento de co-disparo previene que un único spike transitorio (e.g., `flag_rst_ratio` elevado durante una desconexión TCP legítima) genere una alerta. Un ataque coordinado afecta simultáneamente múltiples métricas de la misma familia.

---

## 10. Mecanismos de Estabilización Temporal

### 10.1 Filtro de Persistencia (Anti-FP Shield) — Paso 3D

La señal binaria de anomalía se filtra con una ventana deslizante de 3 posiciones:

```
confirmed = rolling_min(is_anomaly, window=3)  # requiere 3 ventanas consecutivas
propagated = rolling_max(confirmed, window=3)  # propaga el estado durante 3 ventanas
```

Este filtro elimina spikes transitorios de 1–2 ventanas que no corresponden a ataques sostenidos. La desventaja — suprimir el onset de un ataque — se mitiga con el Velocity Bypass, cuyas muestras se re-protegen después del filtro: `is_anomaly[vel_bypass] = 1` se re-aplica incondicionalmente.

### 10.2 Histéresis Schmitt-Trigger Adaptativa (FIX-3) — Paso 3E

El estado de alerta se controla mediante un trigger de Schmitt de doble umbral:

$$\theta_\text{entry} = \theta_{P95} \cdot m_\text{entry}, \qquad \theta_\text{exit} = \theta_{P95} \cdot m_\text{exit}$$

con $m_\text{entry} = 1.0$ (`hysteresis_entry_multiplier`) y $m_\text{exit} = 0.75$ (`hysteresis_exit_multiplier`). Una vez en estado de alerta, el sistema permanece en él mientras $s_\text{bt}(t) > \theta_\text{exit}$, incluso si $s_\text{bt}(t)$ cae brevemente por debajo de $\theta_\text{entry}$. Esto evita que un ataque con variabilidad natural genere múltiples incidentes fragmentados.

La novedad de FIX-3 es la **persistencia de salida adaptativa**: el número de ventanas consecutivas por debajo de $\theta_\text{exit}$ necesario para desactivar la alerta no es fijo, sino función del score actual:

$$N_\text{exit}(t) = \max\left(1,\; \min\left(N_\text{base},\; \left\lfloor\frac{3}{r(t) + 0.1}\right\rfloor\right)\right)$$

donde $r(t) = s_\text{bt}(t) / \theta_\text{entry}$ es el ratio score/threshold y $N_\text{base} = 3$ (`alert_minimum_persistence`).

El comportamiento físico de esta función es notable:

| Escenario | $r(t)$ | $N_\text{exit}$ | Interpretación |
|---|---|---|---|
| Score muy bajo (seguro): $s = 0.1\theta$ | $r = 0.1$ | $N = 3$ | Tráfico claramente normal; desescalada lenta |
| Score moderado: $s = 0.5\theta$ | $r = 0.5$ | $N = 3$ | Zona borderline; cautela sostenida |
| Score alto (ataque quirúrgico): $s = 2\theta$ | $r = 2.0$ | $N = 1$ | Score cae rápido; desescalada ágil |
| Score extremo: $s = 10\theta$ | $r = 10.0$ | $N = 1$ | Evento extremo; desescalada inmediata |

Un ataque de alta sigma que produce un único spike de gran magnitud abandona el estado de alerta en 1 ventana. Ruido de baja magnitud requiere 3 ventanas consecutivas en zona limpia para desactivarse.

Las muestras de Velocity Bypass se re-protegen también tras el filtro de histéresis.

### 10.3 Período de Calentamiento (FIX-2)

Las primeras $N_\text{warmup} = \text{ma\_window\_size} \times 3 = 5 \times 3 = 15$ filas del batch se marcan `is_warmup = True`. Durante este período, la media móvil no tiene suficiente historia para distinguir tendencias sostenidas de variaciones transitorias. El `ForensicEngine` aplica un factor de descuento de confianza de 0.5 a los incidentes que caen íntegramente dentro del período de calentamiento, evitando que el ruido de inicialización genere incidentes de alta prioridad.

---

## 11. Atribución Forense

### 11.1 Identificación del Culprit Físico

Para cada muestra anómala, se identifican:

**Feature culprit univariante**: la feature $f_{j^*}$ con mayor desviación Z respecto al baseline:

$$j^* = \arg\max_j \left|\frac{x_j - \mu_j}{\sigma_j}\right|$$

Se reporta la dirección (SPIKE si $x_{j^*} > \mu_{j^*}$, DROP si $x_{j^*} < \mu_{j^*}$) y el porcentaje de desviación:

$$\Delta_{j^*} = \frac{|x_{j^*} - \mu_{j^*}|}{|\mu_{j^*}| + \varepsilon} \times 100\%$$

**Componente culprit en $\mathcal{H}$**: el componente principal con mayor desviación absoluta de coordenada:

$$c^* = \arg\max_c |x_{\mathcal{H},c}|$$

En modo Blocked PCA, `_blocked_pca_family_mapping[c*]` devuelve `(familia, índice_local)`, permitiendo identificar a qué familia corresponde el componente culpable. Las $N_\text{top} = 3$ features con mayor loading en ese componente se reportan como "features sospechosas" (`top_features_per_pc = 3`).

### 11.2 Anotación del Velocity Bypass

Cuando el Tier 4 dispara, la evidencia forense incluye la anotación explícita en el campo `forensic_evidence`:

```
⚡VELOCITY BYPASS: vel_pps_z(z=+9.43) (≥10.0σ — emergency gate fired).
```

Esta anotación permite al `ForensicEngine` distinguir automáticamente entre incidentes detectados por anomalía geométrica (Tiers 1–3) e incidentes detectados por transición de régimen (Tier 4), generando reportes con precisión etiológica.

### 11.3 El Veto del Portero

Como se describió en §7.3, si una muestra produce $|\sigma_j| \geq 20.0\sigma$ en el espacio de features (Paso 5B del pipeline), el sistema la fuerza a `severity = 3` independientemente del consenso. Ejemplo emblemático: `payload_continuity_ratio` a **4120σ** durante DoS GoldenEye en CIC-IDS2017.

---

## 12. Fase de Detección — La Proyección de Inferencia

### 12.1 La Regla de Oro: Solo `.transform()`

En la fase de detección, ninguna función de ajuste (`.fit()`, `.fit_transform()`) puede ser invocada sobre los datos de test. Sólo se aplican transformaciones cuyos parámetros fueron calculados en el entrenamiento. El `HilbertSpaceProjector` valida explícitamente su estado con `validate_fitted()` antes de cada `.transform()`:

```
Entrenamiento:  BlockedPCA.fit_transform(X_train) → ColumnTransformer [CONGELADO]
                    └─ StandardScaler_f.fit()     → μ_f, σ_f           [CONGELADO]
                    └─ PCA_f.fit()                → V_f, Λ_f            [CONGELADO]
                BallTree.fit(Xh_train)            → árbol               [CONGELADO]
                GMM.fit(Xh_train)                 → π_k, μ_k, Σ_k      [CONGELADOS]
                GMM_j.fit(Xf_train)               → θ_j (P99.9)         [CONGELADOS]
                                                     (por cada feature j)

Detección:      BlockedPCA.transform(X_test)      ← usa μ_f, σ_f, V_f del train
                BallTree.query(Xh_test)            ← distancias en árbol del train
                GMM.score_samples(Xh_test)         ← densidad bajo π_k, μ_k, Σ_k del train
                GMM_j.score_samples(Xf_test)       ← LL bajo GMM_j del train
                VelocityBypass.compute(vel_test)   ← auto-normalizante (sin train)
```

### 12.2 Runtime Hot-Swap de Configuración

Una innovación de v4.0 es la posibilidad de actualizar parámetros operacionales sin re-entrenar el modelo. `HiGIEngine.update_runtime_config()` permite aplicar la configuración actual de `config.yaml` sobre un modelo ya cargado:

```python
engine = HiGIEngine.load('models/baseline_monday.pkl')
settings = load_settings('config.yaml')
engine.update_runtime_config(settings.to_runtime_config())
results = engine.analyze(df_test)
```

Los parámetros actualizables sin re-entrenamiento incluyen: `alert_minimum_persistence`, `hysteresis_entry_multiplier`, `hysteresis_exit_multiplier`, `tribunal_consensus_threshold`, `velocity_bypass_threshold`, `velocity_tribunal_weight`, `sigma_culprit_min`, y todos los parámetros de `persistence`. Los parámetros matemáticos (Hilbert space, detectores, thresholds de percentil) permanecen invariantes.

Esto es posible porque `HiGIConfig` es un `frozen=True` dataclass: `apply_runtime_config()` crea una nueva instancia inmutable mediante `dataclasses.replace()`, respetando el principio de inmutabilidad del marco inercial.

### 12.3 Alineación de Schema

Si el dataset de test fue capturado en condiciones de red diferentes al baseline (e.g., protocolos adicionales activos):

- **Features faltantes (no-velocity)**: se imputan con la mediana del baseline correspondiente (guardada en el `ArtifactBundle`). La mediana es físicamente más informativa que cero: un protocolo activo en el baseline pero ausente en el test probablemente tiene actividad cercana a su mediana, no nula.
- **Features de velocity faltantes**: devuelven ceros con log de advertencia — degradación graceful sin error de inferencia.
- **Features extra**: se eliminan silenciosamente antes de la proyección.

---

## 13. Configuración Centralizada y Runtime Hot-Swap

HiGI sigue el principio de **Fuente Única de Verdad (SSoT)** para la configuración: todos los umbrales, pesos y rutas de fichero residen exclusivamente en `config.yaml`. El código fuente no contiene ningún número literal con significado semántico. La cadena de flujo de configuración es:

```
config.yaml
    └─→ src/config.py::load_settings()         [validación tipada]
             └─→ HiGISettings                  [frozen dataclass]
                      └─→ .to_higi_config()    [bridge a HiGIConfig]
                               └─→ HiGIEngine(config=...)
                                        └─→ .update_runtime_config()
                                            (hot-swap post-load)
```

La sección `forensic` de `config.yaml` incluye el parámetro `sigma_culprit_min: 2.0`, que filtra del reporte los incidentes cuya desviación media en Z-score sea inferior a $2\sigma$. Esto elimina el ruido de reconocimiento pre-ataque (escaneos de setup del laboratorio UNB en el CIC-IDS-2017) que genera incidentes con $\bar{\sigma} \approx 0.5$–$1.2$ pero sin impacto operacional real.

---

## 14. Recomendaciones de Arquitectura

### 14.1 Selección del Modo de Proyección

Usar **Blocked PCA** (default) cuando:
- El dataset tiene features de múltiples familias físicas con varianzas muy distintas.
- Se requiere atribución forense precisa por familia.
- El tráfico de red incluye features de flags TCP de baja varianza junto con features volumétricas de alta varianza.

Usar **Global PCA** (fallback) cuando:
- El dataset es pequeño (< 500 muestras de baseline) y la convergencia del Blocked PCA es inestable.
- Se requiere compatibilidad con modelos serializados en versiones anteriores de HiGI.

### 14.2 Calibración del Velocity Bypass

El parámetro `velocity_bypass_threshold` debe calibrarse según el perfil de variabilidad de la red objetivo:

| Tipo de red | Threshold recomendado | Justificación |
|---|---|---|
| Red de laboratorio / segmentada | 5.0–7.0σ | Baja variabilidad natural |
| Red corporativa estándar | 10.0σ (default) | Variabilidad moderada |
| Red de datacenter / CDN | 12.0–15.0σ | Alta variabilidad natural de tráfico |

### 14.3 Captura del Baseline

El baseline debe capturar el **rango completo de condiciones normales** de la red. Un baseline de un único día laborable puede no representar los patrones de fin de semana, horarios nocturnos, o periodos de backup. Se recomienda:

- Mínimo 3 días de tráfico benigno representativo.
- Incluir periodos de baja y alta actividad.
- Excluir cualquier periodo con actividad de mantenimiento o tráfico inusual conocido.
- Verificar la calidad con `get_capture_health_report()` antes de entrenar.

---

## 15. Referencia de Parámetros

### 15.1 Parámetros Críticos (Alto Impacto en Detección)

| Parámetro | Campo `HiGIConfig` | Default | Efecto |
|---|---|---|---|
| `velocity.bypass_threshold` | `velocity_bypass_threshold` | 10.0 | Umbral $\theta_\text{bypass}$; bajar → más sensible a floods |
| `velocity.tribunal_weight` | `velocity_tribunal_weight` | 0.15 | Peso del Tier 4 en el Tribunal |
| `balltree.threshold_p95` | `threshold_p95` | 95.0 | Umbral borderline del Portero |
| `tribunal.consensus_threshold` | `tribunal_consensus_threshold` | 0.5 | $\tau_\text{consenso}$; bajar → más alertas |
| `forensic.sigma_culprit_min` | — (ForensicEngine) | 2.0 | Filtro de ruido en el reporte |
| `hilbert.blocked_pca_enabled` | `blocked_pca_enabled` | `true` | Blocked PCA vs PCA global |

### 15.2 Parámetros de Estabilización

| Parámetro | Campo `HiGIConfig` | Default | Efecto |
|---|---|---|---|
| `persistence.alert_minimum_persistence` | `alert_minimum_persistence` | 3 | Ventanas mínimas de alerta sostenida |
| `persistence.hysteresis_exit_multiplier` | `hysteresis_exit_multiplier` | 0.75 | Factor de histéresis de salida |
| `persistence.ma_window_size` | `ma_window_size` | 5 | Ventana de la media móvil (warmup: ×3) |
| `sentinel.portero_sigma_threshold` | `portero_sigma_threshold` | 20.0 | $\sigma$ para veto incondicional |

### 15.3 Parámetros del Tribunal

| Parámetro | Campo `HiGIConfig` | Default | Efecto |
|---|---|---|---|
| `gmm.use_bayesian` | `use_bayesian_gmm` | `true` | Bayesian GMM vs clásico |
| `gmm.reg_covar` | `reg_covar` | 0.1 | Regularización de covarianza |
| `gmm.score_normalization` | `gmm_score_normalization_method` | `"cdf"` | Normalización del score GMM |
| `family_consensus.min_hits` | `family_consensus_min_hits` | 2 | Co-disparo mínimo para borderline |

### 15.4 Parámetros del Blocked PCA

| Parámetro | Ubicación YAML | Default | Efecto |
|---|---|---|---|
| `hilbert.blocked_pca_variance_per_family.volume` | `blocked_pca_variance_per_family` | 0.95 | Varianza retenida en familia Volume |
| `hilbert.blocked_pca_variance_per_family.payload` | `blocked_pca_variance_per_family` | 0.95 | Varianza retenida en familia Payload |
| `hilbert.blocked_pca_variance_per_family.flags` | `blocked_pca_variance_per_family` | 0.99 | Varianza retenida en familia Flags |
| `hilbert.blocked_pca_variance_per_family.protocol` | `blocked_pca_variance_per_family` | 0.99 | Varianza retenida en familia Protocol |
| `hilbert.blocked_pca_variance_per_family.connection` | `blocked_pca_variance_per_family` | 0.95 | Varianza retenida en familia Connection |

---

*Documento generado para HiGI IDS v4.0.0 — Velocity Bypass Architecture.*  
*Todas las ecuaciones hacen referencia directa al código fuente en [`src/models/higi_engine.py`](/src/models/higi_engine.py).*  
*Validado contra CIC-IDS2017 (Wednesday + Thursday). Recall DoS/DDoS: 100%. Latencia: ≤ 1 min.*