# HiGI IDS — Manual Lógico-Matemático

**Hilbert-space Gaussian Intelligence**  
*Sistema de Detección de Intrusiones de Cuarta Generación*

**Versión:** 4.0.0 · **Estado:** Producción · **Autoría:** Blue Team Engineering

---

## Tabla de Contenidos

1. [Fundamentos Conceptuales](#1-fundamentos-conceptuales)
2. [Arquitectura del Pipeline](#2-arquitectura-del-pipeline)
3. [Fase I — Construcción del Marco de Referencia Inercial](#3-fase-i--construccion-del-marco-de-referencia-inercial-entrenamiento)
4. [Proyección al Espacio de Hilbert](#4-proyeccion-al-espacio-de-hilbert)
5. [Tier 1 — El Portero Geométrico (BallTree)](#5-tier-1--el-portero-geometrico-balltree)
6. [Tier 2 — El Tribunal Probabilístico (GMM + IForest)](#6-tier-2--el-tribunal-probabilistico-gmm--iforest)
7. [Tier 3 — El Centinela Físico (GMM Univariante)](#7-tier-3--el-centinela-fisico-gmm-univariante)
8. [Tier 4 — La Válvula de Emergencia (Velocity Bypass)](#8-tier-4--la-valvula-de-emergencia-velocity-bypass)
9. [El Consenso del Tribunal](#9-el-consenso-del-tribunal)
10. [Mecanismos de Estabilización Temporal](#10-mecanismos-de-estabilizacion-temporal)
11. [Atribución Forense](#11-atribucion-forense)
12. [Fase de Detección — La Proyección de Inferencia](#12-fase-de-deteccion--la-proyeccion-de-inferencia)
13. [Configuración Centralizada](#13-configuracion-centralizada)
14. [Recomendaciones de Arquitectura](#14-recomendaciones-de-arquitectura)
15. [Referencia de Parámetros](#15-referencia-de-parametros)

---

## 1. Fundamentos Conceptuales

### 1.1 La Perspectiva Física del Tráfico de Red

HiGI no trata el tráfico de red como una secuencia de eventos discretos que comparar contra una lista de firmas. Lo trata como un **campo físico**: un flujo continuo de energía, presión y composición que obedece reglas estadísticas estables en condiciones normales. Cuando el campo se altera, HiGI lo detecta como detectaría un sismógrafo una vibración anómala: por desviación respecto al estado de reposo calibrado.

Esta perspectiva tiene tres consecuencias arquitectónicas directas:

1. **El estado de reposo debe establecerse empíricamente** sobre tráfico benigno conocido. No existe ningún valor absoluto de "PPS normal"; sólo existe el PPS observado en este entorno, en esta red, en este horario.

2. **La detección es siempre relativa al estado de reposo.** Una muestra de tráfico nueva se evalúa por cuánto se aleja del campo calibrado, no por si contiene palabras clave de ataque.

3. **La geometría importa más que el valor absoluto.** Un paquete SYN con ratio 0.9 en una red de datacenter puede ser completamente normal; el mismo ratio en una red de oficina es una anomalía severa. La posición en el espacio de representación codifica el contexto del entorno.

### 1.2 El Espacio de Hilbert como Variedad de Datos

El espacio de características de tráfico de red es de alta dimensión (típicamente 30–60 features) y altamente no lineal. La transformación de Yeo-Johnson + PCA proyecta ese espacio en una **variedad de dimensión reducida** (17–20 dimensiones) donde:

- La distancia euclidiana es un buen estimador de disimilitud semántica.
- La densidad de probabilidad gaussiana multivariate puede estimarse de forma estable.
- Las direcciones de mayor varianza corresponden a los "ejes físicos" más informativos del tráfico.

En sentido estricto, no es un espacio de Hilbert en la definición matemática pura (que requiere producto interno y completitud), pero la denominación captura la esencia: un espacio métrico donde la geometría tiene significado físico. Usaremos la notación $\mathcal{H}$ para referirnos a él.

---

## 2. Arquitectura del Pipeline

El pipeline de inferencia de HiGI es una cascada de cuatro niveles de detección independientes que operan de forma coordinada. La eficiencia computacional se garantiza mediante un mecanismo de *cortocircuito*: sólo las muestras que superan el umbral del Tier 1 son enviadas al Tier 2. El Tier 4, por el contrario, opera sobre **todas las muestras** en paralelo.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PCAP / Socket en Vivo                        │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   processor_optime.py    │
                    │  Ingesta · Ventanas 1s  │
                    │  Features físicas +     │
                    │  vel_pps_z · vel_bytes_z│
                    │  · vel_syn_z            │
                    └────────────┬────────────┘
                                 │  Matriz de features X ∈ ℝⁿˣᵈ
                    ┌────────────▼────────────┐
                    │   RobustScaler          │  ← pesos CONGELADOS
                    │   Yeo-Johnson + PCA     │    del entrenamiento
                    └────────────┬────────────┘
                                 │  X_hilbert ∈ ℋ (17–20 dims)
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
┌─────────▼──────────┐           │            ┌─────────▼──────────┐
│    TIER 1          │           │            │    TIER 4          │
│    BallTree        │           │            │    Velocity        │
│    Portero         │           │            │    Bypass          │
│    Geométrico      │           │            │    (todas muestras)│
└─────────┬──────────┘           │            └─────────┬──────────┘
          │ Normal → skip        │                      │ bypass_mask
          │ Sospechoso → Tier 2  │                      │ vel_score
          └──────────────────────┼──────────────────────┘
                                 │ Sospechosos ∪ Bypass
                    ┌────────────▼────────────┐
                    │   TIER 2A: GMM          │
                    │   Log-Likelihood        │
                    │   (densidad local)      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   TIER 2B: IForest      │
                    │   Isolation Score       │
                    │   (estructura global)   │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   TIER 3: Centinela     │
                    │   GMM Univariante       │
                    │   por feature           │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   CONSENSO PONDERADO    │
                    │   w_bt + w_gmm + w_if   │
                    │   + w_vel               │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   HYSTERESIS · PERSIST  │
                    │   Schmitt Trigger       │
                    │   Adaptativo (FIX-3)   │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   ATRIBUCIÓN FORENSE    │
                    │   PC culprit · SPIKE/   │
                    │   DROP · MITRE ATT&CK  │
                    └─────────────────────────┘
```

---

## 3. Fase I — Construcción del Marco de Referencia Inercial (Entrenamiento)

### 3.1 La Analogía del Marco Inercial

En física clásica, un marco de referencia inercial es aquel en el que las leyes del movimiento se cumplen sin correcciones ficticias: un observador en reposo puede medir las desviaciones de cualquier objeto móvil respecto a ese estado de reposo.

El entrenamiento de HiGI construye exactamente ese marco: a partir de tráfico benigno conocido (e.g., el lunes del dataset CIC-IDS-2017), calcula todos los parámetros estadísticos que definen "el reposo" de esta red. Una vez establecido el marco, se **congela**. Ninguna muestra de tráfico futuro puede alterarlo.

Esta decisión es físicamente análoga a calibrar un gravímetro en condiciones de referencia: los datos de calibración definen el cero del instrumento y no se actualizan durante la medición.

### 3.2 Pasos del Entrenamiento

**Paso 0 — Extracción del esquema de features**

El procesador extrae el conjunto de columnas numéricas $\mathcal{F} = \{f_1, f_2, \ldots, f_d\}$ de la matriz baseline, incluyendo las nuevas features de velocidad relativa $\{v_\text{pps}, v_\text{bytes}, v_\text{syn}\}$. Este esquema es el **contrato de la interfaz**: cualquier muestra de inferencia que no contenga todas las columnas de $\mathcal{F}$ provoca un error controlado.

También se calculan y congelan:

$$\mu_j = \frac{1}{N}\sum_{i=1}^N x_{ij}, \quad \sigma_j = \sqrt{\frac{1}{N-1}\sum_{i=1}^N (x_{ij} - \mu_j)^2}, \quad j \in \{1, \ldots, d\}$$

Estos estadísticos se usan en la atribución forense (cálculo de Z-scores por feature) y en el Centinela Físico.

**Paso 0.5 — GMMs univariantes (una por feature)**

Para cada feature $f_j$, se ajusta un modelo de mezcla gaussiana de $K_j$ componentes óptimo (seleccionado por voto entre BIC, AIC, Silhouette y Davies-Bouldin) y se computa el umbral de log-likelihood al P99.9 del entrenamiento:

$$\tau_j = \mathrm{P}_{99.9}\bigl[-\log p_j(x_{ij})\bigr]_{\,x_{ij} \sim \mathcal{D}_\text{train}}$$

Este umbral es **específico por feature**: la sensibilidad del ratio SYN y la del PPS son intrínsecamente diferentes; un umbral global introduciría sesgos sistemáticos.

**Paso 1 — Proyección al Espacio de Hilbert**

Detallado en la Sección 4.

**Paso 2 — Entrenamiento de los detectores del Tribunal**

Con la matriz baseline proyectada $X_\mathcal{H} \in \mathbb{R}^{N \times h}$ (donde $h \ll d$), se ajustan los tres detectores:

| Detector | Parámetros congelados | Función física |
|---|---|---|
| BallTree (Tier 1) | $k$-NN distances · $\delta_{P99}$ | Geometría: ¿está en zona conocida? |
| GMM (Tier 2A) | $\{\pi_k, \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k\}$ | Densidad: ¿qué tan probable es? |
| IForest (Tier 2B) | Árboles de aislamiento | Estructura: ¿es fácil de aislar? |

El Tier 4 (Velocity Bypass) **no tiene parámetros entrenables**: sus Z-scores son auto-normalizantes por construcción.

### 3.3 Por Qué Se Congelan los Pesos

Si en la fase de detección se re-entrenara el normalizador con los datos de test, ocurriría lo que llamamos **envenenamiento de la referencia**: una inundación de tráfico DoS muy homogéneo ocuparía la mayor parte de la distribución del batch y se convertiría en el nuevo "estado de reposo". El sistema detectaría como anómalo el tráfico benigno residual en lugar del ataque.

Matemáticamente: sea $\hat{\mu}_\text{batch}$ y $\hat{\sigma}_\text{batch}$ los momentos del batch de inferencia. Si el batch contiene tráfico DoS masivo, entonces:

$$\hat{\mu}_\text{batch}^\text{pps} \gg \mu_\text{train}^\text{pps}$$

y el DoS se proyecta al centro de la distribución normalizada, obteniendo score cero. Al usar los parámetros del entrenamiento congelados:

$$z_i = \frac{x_i - \mu_\text{train}}{\sigma_\text{train}}$$

el DoS produce valores $z_i \gg 1$ y es detectado correctamente por el Centinela Físico.

---

## 4. Proyección al Espacio de Hilbert

### 4.1 Transformación de Yeo-Johnson

El espacio de features de red es altamente no gaussiano: PPS y bytes siguen distribuciones log-normal con cola pesada; los ratios de flags son bimodales. El PCA clásico asume gaussianidad implícitamente (la ortogonalización diagonaliza la covarianza, no la información mutua). Para garantizar que las distancias en el espacio proyectado sean estadísticamente significativas, HiGI aplica primero la transformación de **Yeo-Johnson**:

$$\psi_\lambda(x) = \begin{cases}
\dfrac{(x+1)^\lambda - 1}{\lambda} & \text{si } \lambda \neq 0, \; x \geq 0 \\[6pt]
\ln(x+1) & \text{si } \lambda = 0, \; x \geq 0 \\[6pt]
\dfrac{1 - (1-x)^{2-\lambda}}{2-\lambda} & \text{si } \lambda \neq 2, \; x < 0 \\[6pt]
-\ln(1-x) & \text{si } \lambda = 2, \; x < 0
\end{cases}$$

El exponente $\lambda_j$ se estima por máxima verosimilitud para cada feature durante el entrenamiento y se congela. A diferencia del logaritmo natural, Yeo-Johnson acepta valores negativos, lo que es esencial para las features de velocidad relativa $v_j \in \mathbb{R}$.

Tras la transformación, `standardize=True` normaliza cada feature a media cero y desviación estándar unidad.

### 4.2 Análisis de Componentes Principales con Blanqueamiento

Sobre la matriz transformada $\tilde{X} \in \mathbb{R}^{N \times d}$, se aplica PCA con blanqueamiento (`whiten=True`). El blanqueamiento es crucial: escala los componentes principales por el inverso de su desviación estándar, de modo que todos tienen varianza unitaria en el espacio de Hilbert. Esto hace que la distancia euclidiana en $\mathcal{H}$ sea equivalente a la **distancia de Mahalanobis** en el espacio original:

$$d_\mathcal{H}(\mathbf{a}, \mathbf{b}) = \|\mathbf{a}_\mathcal{H} - \mathbf{b}_\mathcal{H}\|_2 \approx \sqrt{(\mathbf{a} - \mathbf{b})^\top \boldsymbol{\Sigma}^{-1} (\mathbf{a} - \mathbf{b})}$$

El número de componentes $h$ se selecciona automáticamente para retener el 99% de la varianza explicada:

$$h = \min\left\{k : \sum_{i=1}^k \lambda_i \Big/ \sum_{i=1}^d \lambda_i \geq 0.99\right\}$$

donde $\lambda_i$ son los valores propios de la matriz de covarianza muestral. En la práctica se obtienen $h \approx 17$–$20$ componentes de los 40–60 features originales.

Las features de velocidad relativa ($v_\text{pps}$, $v_\text{bytes}$, $v_\text{syn}$) son ya $Z$-scores con distribución cercana a $\mathcal{N}(0,1)$ en condiciones de baseline estable. Su contribución a las primeras componentes principales es modesta en entrenamiento (tráfico benigno estacionario), pero se vuelve dominante durante ataques de flood que producen $|v_j| \gg 1$. Esto añade una dimensión de separabilidad en $\mathcal{H}$ que el BallTree también puede explotar, complementando el Tier 4.

---

## 5. Tier 1 — El Portero Geométrico (BallTree)

### 5.1 Intuición Física

El Portero responde a la pregunta más directa: **¿esta muestra está en una región del espacio que el tráfico benigno visitó durante el entrenamiento?**

Un árbol de vecinos más próximos (BallTree) sobre las muestras del baseline en $\mathcal{H}$ constituye un mapa de densidad geométrica. Si la distancia media a los $k=5$ vecinos más cercanos es pequeña, la muestra está en una zona poblada del espacio. Si es grande, está en una zona desértica: un outlier.

### 5.2 Puntuación Absoluta (FIX-1)

La puntuación del BallTree es la distancia euclidiana media a los $k$ vecinos más próximos en $\mathcal{H}$, normalizada contra el percentil P99 del entrenamiento:

$$s_\text{bt}(\mathbf{x}) = \frac{1}{\delta_{P99}} \cdot \frac{1}{k} \sum_{i=1}^{k} \|\mathbf{x}_\mathcal{H} - \mathbf{nn}_i\|_2$$

donde $\delta_{P99} = \mathrm{P}_{99}\bigl[\bar{d}_{kNN}(\mathbf{x}_\text{train})\bigr]$ es el percentil P99 de las distancias medias $k$-NN calculadas sobre el propio conjunto de entrenamiento.

Esta normalización tiene una consecuencia física fundamental: el score es **batch-independent**. Un ataque DoS que produce distancias 10 veces mayores que $\delta_{P99}$ obtendrá $s_\text{bt} \approx 10.0$ independientemente de qué otras muestras estén en el batch. Sin esta normalización (con min-max por batch), un flood homogéneo que domina el batch comprime todos los scores y se vuelve invisible.

La interpretación de la escala resultante es directa:

| $s_\text{bt}$ | Interpretación |
|---|---|
| $< 0.9$ | Claramente dentro del baseline |
| $\approx 1.0$ | Exactamente en el límite P99 del entrenamiento |
| $1.0$–$2.0$ | Zona borderline |
| $> 5.0$ | Fuertemente anómalo (e.g., Slowloris: $s \approx 1.56$) |

### 5.3 Estratificación de Severidad

El score se mapea a cinco niveles de severidad:

| Zona | Condición | Acción |
|---|---|---|
| Normal | $s_\text{bt} < s_{P90}$ | Short-circuit: skip Tier 2 |
| Soft Zone | $s_{P90} \leq s_\text{bt} < s_{P95}$ | Pasa a Tier 2 como sospechoso |
| Borderline | $s_{P95} \leq s_\text{bt} < s_{P99}$ | Tier 2 + requiere consenso familiar |
| Medium | $s_{P99} \leq s_\text{bt} < s_{P99.9}$ | Tier 2, confirmación por consenso |
| Critical | $s_\text{bt} \geq s_{P99.9}$ | Anomalía incondicional |

---

## 6. Tier 2 — El Tribunal Probabilístico (GMM + IForest)

### 6.1 El Complemento Geométrico-Probabilístico

El BallTree opera con geometría: mide distancias. Pero la distancia al vecino más próximo tiene un límite: en regiones del espacio de alta dimensión con densidad gaussiana, la distancia entre cualquier par de puntos tiende a concentrarse alrededor de un valor típico (fenómeno de *concentración de la medida*). Dos muestras de naturaleza totalmente diferente pueden estar geométricamente cercanas si el espacio es suficientemente grande.

El GMM corrige este problema: en lugar de medir distancias, mide **densidad de probabilidad local**. Una muestra en una región de alta densidad bajo la distribución del baseline obtendrá alta log-likelihood; una muestra en una región de baja densidad (aunque geométricamente cercana a algunos puntos del training) obtendrá baja log-likelihood.

La relación entre ambos puede expresarse así:

> **Portero**: *¿Has estado aquí antes?* (distancia)  
> **Tribunal**: *¿Qué tan probable es que alguien como tú esté aquí?* (densidad)

### 6.2 Gaussian Mixture Model — Formulación

Dado el espacio de Hilbert proyectado $\mathbf{x} \in \mathbb{R}^h$, el GMM estima la distribución del tráfico benigno como mezcla de $K$ gaussianas completas:

$$p_\text{GMM}(\mathbf{x}) = \sum_{k=1}^{K} \pi_k \; \mathcal{N}(\mathbf{x} \mid \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k)$$

con $\sum_k \pi_k = 1$, $\pi_k \geq 0$.

La **log-verosimilitud** de una muestra bajo el modelo es:

$$\ell(\mathbf{x}) = \log p_\text{GMM}(\mathbf{x}) = \log \sum_{k=1}^{K} \pi_k \; \mathcal{N}(\mathbf{x} \mid \boldsymbol{\mu}_k, \boldsymbol{\Sigma}_k)$$

El score de anomalía del GMM es la log-likelihood **invertida** (mayor score = más anómalo):

$$s_\text{gmm}(\mathbf{x}) = -\ell(\mathbf{x})$$

El umbral de decisión binaria es el percentil P99.9 de $s_\text{gmm}$ sobre el conjunto de entrenamiento:

$$\tau_\text{gmm} = \mathrm{P}_{99.9}\bigl[s_\text{gmm}(\mathbf{x}_\text{train})\bigr]$$

Una muestra se marca como anómala por el GMM si $s_\text{gmm}(\mathbf{x}) > \tau_\text{gmm}$.

### 6.3 Por Qué BayesianGaussianMixture

HiGI usa `BayesianGaussianMixture` con prior de concentración de pesos $\alpha_0 = 10^{-2}$ (valor configurado en `config.yaml → gmm.bayesian_weight_concentration_prior`). Un prior pequeño penaliza clusters con muy pocos miembros, forzando al modelo a concentrarse en los clusters densos del baseline. Esto evita el sobreajuste de clusters espurios a artefactos de muestreo, lo que es crítico cuando el baseline tiene días de duración y puede contener ráfagas de tráfico atípico benigno.

### 6.4 Selección Adaptativa de K

El número óptimo de componentes $K^*$ se selecciona mediante voto ponderado de cuatro criterios:

$$K^* = \arg\max_K \bigl[0.40 \cdot \text{BIC}^*(K) + 0.10 \cdot \text{AIC}^*(K) + 0.25 \cdot \text{Sil}^*(K) + 0.25 \cdot \text{DB}^*(K)\bigr]$$

donde los asteriscos indican normalización min-max de los scores individuales (con inversión para BIC y AIC, donde valores menores son mejores). El BIC domina con un peso de 0.40 porque penaliza la complejidad del modelo de forma consistente con el tamaño muestral, lo cual es más adecuado para un dataset de días de tráfico que el AIC puro.

### 6.5 Isolation Forest — Detección Estructural

El IForest complementa al GMM con una perspectiva diferente: un punto es anómalo si puede **aislarse con pocas particiones** en un árbol de decisión aleatorio. Mientras el GMM mide densidad (qué tan probable es), el IForest mide aislabilidad estructural (qué tan fácil es separarlo del resto). Un ataque de exfiltración de datos puede ser difícil de detectar por densidad (si hay pocos samples del training en esa región) pero fácil de detectar por estructura (la combinación de features es única en el espacio). Ambas perspectivas son necesarias.

---

## 7. Tier 3 — El Centinela Físico (GMM Univariante)

### 7.1 La Hipótesis de Invarianza Marginal

Una anomalía que se manifiesta en el espacio multivariante (Tier 1 y 2) debe manifestarse al menos en una de las distribuciones marginales de sus features componentes. El Centinela explota esta hipótesis verificando, feature por feature, si la muestra es físicamente plausible en cada dimensión por separado.

Para cada feature $f_j$, se tiene un GMM univariante con log-likelihood $\ell_j(x)$ y umbral $\tau_j$ (P99.9 de $-\ell_j$ en el training). El Centinela vota a favor de anomalía si:

$$\exists\, j : -\ell_j(x_j) < \tau_j$$

La condición es una desigualdad estricta: sólo hace falta una feature cuya log-likelihood caiga **por debajo** del umbral de entrenamiento (es decir, el valor observado es más improbable de lo que el 99.9% del tráfico benigno jamás produjo en esa feature).

### 7.2 Por Qué Umbrales por Feature y No Global

Un umbral global de log-likelihood trataría igual a un ratio SYN de 0.99 (clarísimamente sospechoso en cualquier red) que a un flow_duration de 300s (perfectamente normal en conexiones de larga duración). Los umbrales por feature capturan la sensibilidad específica de cada dimensión física. Un flag como `flag_syn_ratio` tendrá un umbral muy estricto porque su variabilidad natural es baja; `flow_duration` tendrá un umbral mucho más permisivo porque es naturalmente variable.

---

## 8. Tier 4 — La Válvula de Emergencia (Velocity Bypass)

### 8.1 El Problema de la Ceguera Geométrica

Los ataques de inundación masiva (DoS Hulk, GoldenEye) generan tráfico que es estadísticamente **indistinguible del tráfico HTTP pesado normal** en el Espacio de Hilbert. La razón es física:

Durante un flood de HTTP GET a 10.000 paquetes/segundo, todos los paquetes son idénticos (mismo tamaño, mismo TTL, mismo puerto destino). La **varianza intra-ventana** se colapsa a casi cero. El vector de features de una ventana de 1 segundo es perfectamente regular: $\bar{d}_{kNN}$ pequeño, $\ell_\text{GMM}$ alto. El BallTree lo ve como un vecino muy cercano a todos los puntos del baseline de HTTP normal. El GMM ve una densidad alta bajo su distribución.

El problema no es la calibración del sistema; es que el ataque produce un tipo de tráfico que **existe en el baseline** (HTTP masivo es normal en redes de alto tráfico). La geometría y la densidad no bastan para discriminarlo.

### 8.2 La Señal de Régimen Dinámico

Lo que *no* existe en el baseline benigno es una **transición abrupta de régimen**. Un servidor HTTP sano que recibe muchas peticiones las recibe de muchos clientes simultáneos, con varianza temporal natural. Un DoS Hulk aparece en 1–3 segundos como una multiplicación brutal del PPS sin precedente en la historia reciente de esa ventana horaria.

La solución: calcular el Z-score de cada feature **respecto a su propia media móvil de 60 segundos**:

$$z_\text{pps}(t) = \frac{x_\text{pps\_log}(t) - \bar{x}_\text{pps\_log}^{(60)}(t)}{\hat{\sigma}_\text{pps\_log}^{(60)}(t) + \varepsilon}$$

$$z_\text{bytes}(t) = \frac{x_\text{bytes\_log}(t) - \bar{x}_\text{bytes\_log}^{(60)}(t)}{\hat{\sigma}_\text{bytes\_log}^{(60)}(t) + \varepsilon}$$

$$z_\text{syn}(t) = \frac{x_\text{syn\_ratio}(t) - \bar{x}_\text{syn\_ratio}^{(60)}(t)}{\hat{\sigma}_\text{syn\_ratio}^{(60)}(t) + \varepsilon}$$

donde $\varepsilon = 10^{-6}$ previene divisiones por cero durante períodos de tráfico perfectamente estacionario. Estas tres features ($v_\text{pps}$, $v_\text{bytes}$, $v_\text{syn}$) se denominan colectivamente **features de velocidad relativa** y son computadas por `processor_optime.py` antes de la ingesta al engine.

El Z-score dinámico mide la **presión** que el tráfico ejerce sobre su propia historia reciente. No mide si el PPS es alto en términos absolutos, sino si es *anormalmente alto para este momento específico de la jornada*.

### 8.3 La Puerta de Bypass de Emergencia

Sea $Z_{\max(t)} = \max(|z_\text{pps}|, |z_\text{bytes}|, |z_\text{syn}|)$ el Z-score de velocidad máximo en el instante $t$. El Tier 4 define:

$$\text{bypass}(t) = \mathbf{1}\bigl[Z_{\max(t)} \geq \text{bypass}\bigr]$$

con $\theta_\text{bypass} = 5.0\sigma$ por defecto (configurable en `config.yaml → velocity.bypass_threshold`).

Si `bypass(t) = 1`, la muestra es marcada `is_anomaly = 1` **incondicionalmente**, independientemente de lo que digan el BallTree, el GMM, el IForest o el Centinela. La severidad se asigna según:

$$\text{severity}(t) = \begin{cases}
3 & \text{si } Z_{\max} \geq 12.0\sigma \quad \text{(Crítico)} \\
2 & \text{si } 8.0\sigma \leq Z_{\max} < 12.0\sigma \quad \text{(Medio)} \\
1 & \text{si } 5.0\sigma \leq Z_{\max} < 8.0\sigma \quad \text{(Borderline)}
\end{cases}$$

El score continuo para el Tribunal es:

$$s_\text{vel}(t) = \min\left(\frac{Z_{\max(t)}}{\theta_\text{bypass}},\; 3.0\right) \in [0, 3.0]$$

normalizado a $[0,1]$ dividiéndolo por 3.0 antes de entrar en la suma ponderada del consenso.

### 8.4 Por Qué 5.0σ Como Umbral

Bajo la hipótesis nula de que el tráfico sigue el mismo régimen que en la ventana de 60 segundos previa (hipótesis gaussiana), la probabilidad de observar $|Z| \geq 5.0$ es $P(|Z| \geq 5) \approx 5.7 \times 10^{-7}$. En una red con 3.600 ventanas de 1 segundo por hora, la tasa de falsos positivos esperada es de $5.7 \times 10^{-7} \times 3600 \approx 2 \times 10^{-3}$ FP por hora: inferior a un falso positivo por jornada.

Un DoS Hulk que duplica el PPS en 3 segundos sobre una red con $\hat{\sigma}_\text{pps}^{(60)} \approx 0.15$ (log-scale) produce:

$$z_\text{pps} = \frac{\log(2 \cdot \text{PPS}_\text{baseline}) - \log(\text{PPS}_\text{baseline})}{\hat{\sigma}_\text{pps}^{(60)}} = \frac{\ln 2}{0.15} \approx 4.6\sigma$$

y en pocos segundos adicionales, cuando el flood se estabiliza a 5x el baseline, $z_\text{pps} \approx 10.7\sigma$: muy por encima del umbral.

### 8.5 Protección del Bypass Ante Filtros de Persistencia

El filtro de persistencia (rolling-min de 3 ventanas, Sección 10.1) suprimiría un bypass aislado de 1 segundo si el tráfico vuelve brevemente a niveles normales. Para evitar que el onset del ataque sea silenciado, las muestras marcadas como bypass se **protegen explícitamente**: tras cada filtro de persistencia o histéresis, se re-aplica `is_anomaly[vel_bypass] = 1`. El bypass supera todos los filtros por diseño.

---

## 9. El Consenso del Tribunal

### 9.1 Votación Ponderada

La decisión final integra cuatro señales mediante una suma ponderada con pesos derivados de `config.yaml`:

$$C(\mathbf{x}) = w_\text{bt} \cdot \hat{s}_\text{bt} + w_\text{gmm} \cdot \hat{s}_\text{gmm} + w_\text{if} \cdot \hat{s}_\text{if} + w_\text{vel} \cdot \hat{s}_\text{vel}$$

donde el símbolo $\hat{\cdot}$ indica normalización min-max por batch al rango $[0,1]$ (aceptable para las señales del Tribunal porque se usan como tie-breakers relativos, no como scores absolutos). La excepción es $\hat{s}_\text{vel} = s_\text{vel} / 3.0$, que ya tiene una escala física definida.

Los pesos por defecto (configurables) son:

$$w_\text{bt} = 0.175, \quad w_\text{gmm} = 0.280, \quad w_\text{if} = 0.245, \quad w_\text{vel} = 0.300$$

El GMM tiene el peso más alto de los detectores Hilbert-space porque es el estimador de densidad más directo y es el que mejor captura la estructura probabilística del tráfico benigno. El Velocity Bypass tiene el mayor peso individual (0.30) porque cuando dispara, lo hace con señales de muy alta confianza física.

### 9.2 Escalada por Nivel de Severidad

El proceso de decisión difiere según el nivel de severidad del BallTree:

```
is_anomaly = 0  (estado inicial para todos los samples)

Si severity == 3 (Crítico):    → is_anomaly = 1  (incondicional)
Si severity == 2 (Medio):      → is_anomaly = 1  si C(x) ≥ τ_consenso
Si severity == 1 (Borderline): → is_anomaly = 1  si C(x) ≥ τ_consenso
                                              Y  consenso_familiar (FIX-4)
Si severity == 0 y vel_bypass: → is_anomaly = 1  (Tier 4 override)
Si severity == 0 y Sentinela:  → is_anomaly = 1  si C(x) ≥ max(0.7, τ_consenso)
```

### 9.3 Consenso Familiar (FIX-4)

Una muestra borderline ($s_\text{bt} \in [s_{P95}, s_{P99})$) sólo se confirma como anomalía si al menos $N_\text{hits} = 2$ features de una misma familia física están simultáneamente elevadas ($|Z_j| \geq 2.0\sigma$ respecto al baseline):

| Familia | Features miembro |
|---|---|
| `volume_flood` | pps\_log, bytes\_log, syn\_ratio, rst\_ratio, vel\_pps\_z, vel\_bytes\_z, vel\_syn\_z |
| `slow_attack` | flow\_duration, iat\_mean, payload\_continuity, fin\_ratio |
| `exfiltration` | payload\_continuity\_ratio, entropy\_avg, bytes\_velocity, psh\_ratio |
| `kinematics` | pps\_velocity, bytes\_velocity, pps\_acceleration, pps\_volatility |
| `recon` | port\_scan\_ratio, unique\_dst\_ports, fin\_ratio, urg\_ratio |

El requerimiento de co-disparo previene que un único spike transitorio de una sola métrica (e.g., `flag_rst_ratio` elevado brevemente durante una desconexión TCP legítima) genere una alerta. Un ataque coordinado afecta simultáneamente múltiples métricas de la misma familia.

---

## 10. Mecanismos de Estabilización Temporal

### 10.1 Filtro de Persistencia (Anti-FP Shield)

La señal binaria de anomalía se filtra con una ventana deslizante de 3 posiciones usando `rolling_min`, seguido de `rolling_max` para propagar el estado confirmado:

```
confirmed = rolling_min(is_anomaly, window=3)  # Requiere 3 ventanas consecutivas
propagated = rolling_max(confirmed, window=3)  # Propaga el estado durante 3 ventanas
```

Este filtro elimina spikes transitorios de 1–2 ventanas que no corresponden a ataques sostenidos. La desventaja — suprimir el onset de un ataque — se mitiga con el Velocity Bypass, que protege sus muestras de este filtro.

### 10.2 Histéresis Schmitt-Trigger Adaptativa (FIX-3)

El estado de alerta se controla mediante un trigger de Schmitt de doble umbral:

$$\theta_\text{entry} = \theta_{P95} \cdot m_\text{entry}, \qquad \theta_\text{exit} = \theta_{P95} \cdot m_\text{exit}$$

con $m_\text{entry} = 1.0$ y $m_\text{exit} = 0.75$. Una vez en estado de alerta, el sistema permanece en él mientras $s_\text{bt}(t) > \theta_\text{exit}$, incluso si $s_\text{bt}(t)$ cae brevemente por debajo de $\theta_\text{entry}$. Esto evita que un ataque con variabilidad natural genere múltiples incidentes fragmentados.

La novedad de FIX-3 es la **persistencia de salida adaptativa**. El número de ventanas consecutivas por debajo de $\theta_\text{exit}$ necesario para desactivar la alerta no es fijo, sino función del score actual:

$$N_\text{exit}(t) = \max\left(1,\; \min\left(N_\text{base},\; \left\lfloor\frac{3}{r(t) + 0.1}\right\rfloor\right)\right)$$

donde $r(t) = s_\text{bt}(t) / \theta_\text{entry}$ es el ratio score/threshold en el instante actual.

El comportamiento físico de esta función es notable:

| Escenario | $r(t)$ | $N_\text{exit}$ |
|---|---|---|
| Score muy bajo (seguro): $s = 0.1\theta$ | $r = 0.1$ | $N = \min(3, \lfloor 3/0.2 \rfloor) = 3$ |
| Score moderado: $s = 0.5\theta$ | $r = 0.5$ | $N = \min(3, \lfloor 3/0.6 \rfloor) = 3$ |
| Score alto (Heartbleed quirúrgico): $s = 2\theta$ | $r = 2.0$ | $N = \min(3, \lfloor 3/2.1 \rfloor) = 1$ |
| Score extremo: $s = 10\theta$ | $r = 10.0$ | $N = \max(1, \min(3,0)) = 1$ |

Un ataque quirúrgico de alta sigma que produce un único spike de gran magnitud abandona el estado de alerta en 1 ventana. Ruido de baja magnitud requiere 3 ventanas consecutivas en zona limpia para desactivarse.

### 10.3 Período de Calentamiento (FIX-2)

Las primeras $N_\text{warmup} = ma\_window\_size \times 3$ filas del batch se marcan `is_warmup = True`. Durante este período, la media móvil no tiene suficiente historia para distinguir tendencias sostenidas de variaciones transitorias. El `ForensicEngine` aplica un factor de descuento de confianza de 0.5 a los incidentes que caen íntegramente dentro del período de calentamiento, evitando que el ruido de inicialización genere incidentes de alta prioridad.

---

## 11. Atribución Forense

### 11.1 Identificación del Culprit Físico

Para cada muestra anómala, se identifican:

**Feature culprit univariante**: la feature $f_j^*$ con mayor desviación Z respecto al baseline:

$$j^* = \arg\max_j \left|\frac{x_j - \mu_j}{\sigma_j}\right|$$

Se reporta la dirección (SPIKE si $x_{j^*} > \mu_{j^*}$, DROP si $x_{j^*} < \mu_{j^*}$) y el porcentaje de desviación:

$$\Delta_{j^*} = \frac{|x_{j^*} - \mu_{j^*}|}{|\mu_{j^*}| + \varepsilon} \times 100\%$$

**Componente culprit en $\mathcal{H}$**: el componente principal con mayor desviación absoluta de coordenada:

$$c^* = \arg\max_c |x_{\mathcal{H},c}|$$

Las $N_\text{top} = 3$ features con mayor loading en $\text{PC}_{c^*}$ se reportan como "features sospechosas".

### 11.2 Anotación del Velocity Bypass

Cuando Tier 4 dispara, la evidencia forense incluye la anotación:

```
⚡VELOCITY BYPASS: vel_pps_z(z=+9.43) (≥5.0σ — emergency gate fired).
```

Esta anotación permite al `ForensicEngine` distinguir automáticamente entre incidentes detectados por ceguera geométrica (Tiers 1–3) e incidentes detectados por transición de régimen (Tier 4), generando reportes con precisión etiológica.

### 11.3 El Veto del Portero (Portero Veto)

Si una muestra produce $|\sigma_\text{PC}| \geq \theta_\text{portero} = 20.0\sigma$ en el espacio de Hilbert, el sistema la fuerza a `severity = 3` independientemente del consenso. Esta es la excepción a la regla de consenso: una desviación de 20 sigmas en un espacio gaussiano tiene probabilidad de orden $10^{-88}$ bajo la hipótesis nula. Ningún consenso adicional es necesario.

---

## 12. Fase de Detección — La Proyección de Inferencia

### 12.1 La Regla de Oro: Solo `.transform()`

En la fase de detección, ninguna función de ajuste (`.fit()`, `.fit_transform()`) puede ser invocada sobre los datos de test. Sólo se aplican transformaciones cuyos parámetros fueron calculados en el entrenamiento:

```
Entrenamiento:  RobustScaler.fit(X_train) → μ_IQR, σ_IQR  [CONGELADOS]
                PowerTransformer.fit(X_train) → λ_j         [CONGELADOS]
                PCA.fit(X_train) → V, Λ                     [CONGELADOS]
                BallTree.fit(X_train) → árbol               [CONGELADO]
                GMM.fit(X_train) → π_k, μ_k, Σ_k            [CONGELADOS]

Detección:      RobustScaler.transform(X_test)   ← usa μ_IQR, σ_IQR del train
                PowerTransformer.transform(X_test) ← usa λ_j del train
                PCA.transform(X_test)              ← usa V, Λ del train
                BallTree.query(X_test)             ← distancias en árbol del train
                GMM.score_samples(X_test)          ← densidad bajo π_k, μ_k, Σ_k del train
```

La proyección de una muestra nueva $\mathbf{x}_\text{test}$ al espacio de Hilbert es:

$$\mathbf{x}_\mathcal{H} = \boldsymbol{\Lambda}^{-1/2} \mathbf{V}^\top \psi_{\hat{\boldsymbol{\lambda}}}(\mathbf{x}_\text{test})$$

donde $\psi_{\hat{\boldsymbol{\lambda}}}$ es la transformación de Yeo-Johnson con exponentes $\hat{\boldsymbol{\lambda}}$ aprendidos en el training, $\mathbf{V}$ son los vectores propios (loadings del PCA) y $\boldsymbol{\Lambda}$ es la matriz diagonal de valores propios (blanqueamiento).

### 12.2 Alineación de Schema

Si el dataset de test fue capturado en condiciones de red diferentes al baseline (e.g., protocolos adicionales activos), puede tener features ausentes del schema de entrenamiento. En ese caso:

- **Features faltantes**: se imputan con la mediana del baseline correspondiente (conservada en el `ArtifactBundle`), no con ceros. La mediana es físicamente más informativa que cero: un protocolo que estaba activo en el baseline pero ausente en el test probablemente tiene un nivel de actividad cercano a su mediana, no nulo.
- **Features extra**: se eliminan silenciosamente antes de la proyección.

---

## 13. Configuración Centralizada

HiGI sigue el principio de **Fuente Única de Verdad (SSoT)** para la configuración: todos los umbrales, pesos y rutas de fichero residen exclusivamente en `config.yaml`. El código fuente no contiene ningún número literal con significado semántico.

La cadena de flujo de configuración es:

```
config.yaml
    └─→ src/config.py::load_settings()       [validación tipada]
             └─→ HiGISettings                [frozen dataclass]
                      └─→ .to_higi_config()  [bridge a HiGIConfig]
                               └─→ HiGIEngine(config=...)
```

La sección `forensic` de `config.yaml` introduce el parámetro `sigma_culprit_min: 2.0`, que filtra del reporte los incidentes cuya desviación media en Z-score sea inferior a $2\sigma$. Esto elimina el ruido de reconocimiento pre-ataque (escaneos de setup del laboratorio UNB en el CIC-IDS-2017) que genera incidentes con $\bar{\sigma} \approx 0.5$–$1.2$ pero sin impacto operacional real.

---

## 15. Referencia de Parámetros

### 15.1 Parámetros Críticos (Alto Impacto en Detección)

| Parámetro | Ubicación YAML | Default | Efecto |
|---|---|---|---|
| `velocity.bypass_threshold` | `velocity.bypass_threshold` | 5.0 | Umbral $\theta_\text{bypass}$; bajar → más sensible a floods |
| `velocity.tribunal_weight` | `velocity.tribunal_weight` | 0.30 | Peso del Tier 4 en consenso |
| `balltree.threshold_p95` | `balltree.threshold_p95` | 95.0 | Umbral borderline del Portero |
| `tribunal.consensus_threshold` | `tribunal.consensus_threshold` | 0.5 | $\tau_\text{consenso}$; bajar → más alertas |
| `forensic.sigma_culprit_min` | `forensic.sigma_culprit_min` | 2.0 | Filtro de ruido en el reporte |

### 15.2 Parámetros de Estabilización

| Parámetro | Ubicación YAML | Default | Efecto |
|---|---|---|---|
| `persistence.alert_minimum_persistence` | `persistence.alert_minimum_persistence` | 3 | Ventanas mínimas de alerta sostenida |
| `persistence.hysteresis_exit_multiplier` | `persistence.hysteresis_exit_multiplier` | 0.75 | Factor de histéresis de salida |
| `persistence.ma_window_size` | `persistence.ma_window_size` | 5 | Ventana de la media móvil |
| `sentinel.portero_sigma_threshold` | `sentinel.portero_sigma_threshold` | 20.0 | $\sigma$ para veto incondicional |

### 15.3 Parámetros del Tribunal

| Parámetro | Ubicación YAML | Default | Efecto |
|---|---|---|---|
| `gmm.use_bayesian` | `gmm.use_bayesian` | true | Bayesian GMM vs clásico |
| `gmm.reg_covar` | `gmm.reg_covar` | 0.1 | Regularización de covarianza |
| `gmm.score_normalization` | `gmm.score_normalization` | `"cdf"` | Normalización del score GMM |
| `family_consensus.min_hits` | `family_consensus.min_hits` | 2 | Co-disparo mínimo para borderline |

---

*Documento generado para HiGI IDS v4.0.0 — Velocity Bypass Architecture.*  
*Todas las ecuaciones hacen referencia directa al código fuente en `src/models/higi_engine.py`.*
