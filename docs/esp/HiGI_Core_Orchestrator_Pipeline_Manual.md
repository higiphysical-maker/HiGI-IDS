# Manual de HiGI IDS — Core: Orquestador y Pipeline de Ejecución

**Versión:** 4.0.0 · **Módulos:** [`src/orchestrator.py`](/src/orchestrator.py) · [`main.py`](/main.py)  
**Clasificación:** Documentación Técnica Interna — Ingeniería de Blue Team  
**Ecosistema:** HiGI IDS v4.0 · **Formato de Referencia:** IEEE / Clean Code / PEP 8

---

## Índice

1. [Visión General de la Arquitectura](#1-visión-general-de-la-arquitectura)
2. [El ArtifactBundle: La Verdad Inmutable](#2-el-artifactbundle-la-verdad-inmutable)
3. [El Ciclo de Vida de Ejecución](#3-el-ciclo-de-vida-de-ejecución)
4. [Referencia de CLI — `main.py`](#4-referencia-de-cli--mainpy)
5. [Manejo de Errores y Resiliencia](#5-manejo-de-errores-y-resiliencia)
6. [Contrato de Configuración: ModelConfig vs. RuntimeConfig](#6-contrato-de-configuración-modelconfig-vs-runtimeconfig)
7. [Aviso Técnico: El Espacio de Hilbert](#7-aviso-técnico-el-espacio-de-hilbert)
8. [Glosario](#8-glosario)

---

## 1. Visión General de la Arquitectura

### 1.1 El Orquestador como el Telar de Evidencia Forense

El término *orquestador* es deliberadamente evocador. Un ejecutor de pipeline estándar ejecuta pasos de manera secuencial y descarta el estado intermedio. El Orquestador de HiGI hace algo fundamentalmente diferente: **preserva y propaga el contexto epistémico** a través de cada fase del ciclo de vida de detección. El `TrainingPipeline` no se limita a ajustar un modelo; construye un sistema de referencia inercial geométricamente coherente y lo encapsula en un `ArtifactBundle`. El `DetectionPipeline` no se limita a puntuar muestras; impone un contrato matemático estricto para que los datos de prueba sean evaluados exactamente contra el mismo espacio geométrico en el que se definió el Baseline.

Esta distinción no es estilística. Es la garantía arquitectónica que hace que las detecciones de HiGI sean físicamente interpretables en lugar de estadísticamente opacas.

### 1.2 La Arquitectura de Tres Motores

`src/orchestrator.py` es la capa de integración que coordina tres motores independientes, cada uno con una responsabilidad bien definida y sin solapamientos:

```
                          ┌─────────────────────────────────┐
                          │         HiGISettings            │
                          │    (config.yaml → dataclass)    │
                          └────────────┬────────────────────┘
                                       │  inyecta en
              ┌────────────────────────┼────────────────────────┐
              │                        │                         │
              ▼                        ▼                         ▼
   ┌──────────────────┐   ┌────────────────────┐   ┌────────────────────────┐
   │  PcapProcessor   │   │    HiGIEngine       │   │  HiGIForensicEngine    │
   │  (Ingestión)     │   │  (Detección)        │   │  (Reportes)            │
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

**Principio de diseño crítico:** `HiGISettings` es la Fuente Única de Verdad (SSoT) para toda la configuración. Ningún motor recibe parámetros prefijados (hardcoded). Cada umbral, peso y tamaño de ventana se inyecta desde la jerarquía de dataclasses congeladas construida por `load_settings()` a partir de `config.yaml`. Esto es lo que el código denomina *zero magic numbers*.

### 1.3 La Regla de Oro de la Inferencia

El contrato de detección completo se condensa en un invariante, documentado explícitamente en `DetectionPipeline.run()`:

> **REGLA DE ORO: Este pipeline DEBE usar únicamente `.transform()`. NO se permiten llamadas a `.fit()` en modo detección.**

El significado geométrico es preciso: durante el entrenamiento, `RobustScaler` aprende la mediana y el rango intercuartílico de la distribución del tráfico del Baseline. Durante la detección, el mismo scaler se restaura desde el `ArtifactBundle` y se aplica a los datos de prueba solo con `.transform()`, mapeando las ventanas de prueba al *mismo sistema de coordenadas* que el Baseline de entrenamiento. Cualquier llamada a `.fit()` en modo detección redefiniría el origen de coordenadas utilizando los propios datos de prueba, haciendo que la detección de anomalías sea matemáticamente autorreferencial y operacionalmente sin sentido.

Esta restricción se verifica en cada paso de detección. Si el `ArtifactBundle` no contiene un `scaler` entrenado, el pipeline lanza un `ValueError` y aborta en lugar de proceder con un escalado inconsistente.

---

## 2. El ArtifactBundle: La Verdad Inmutable

### 2.1 Composición y Arquitectura

El `ArtifactBundle` es el artefacto físico de una sesión de entrenamiento completada. Es un contenedor inmutable; una vez guardado, no debe modificarse. Cualquier cambio en un parámetro estructural (ej. esquema de features, objetivo de varianza de PCA, número de componentes GMM) requiere crear un nuevo bundle desde cero.

| Campo | Tipo | Contenido | ¿Mutable? |
|-------|------|-----------|-----------|
| `engine` | `HiGIEngine` | Motor de detección de cuatro niveles entrenado, incluyendo `PowerTransformer` interno, `Blocked PCA`, `BallTree`, `BayesianGMM`, `IsolationForest`, y umbrales LL por característica | ❌ Nunca |
| `feature_cols` | `list[str]` | Lista ordenada de nombres de columnas de características: el contrato de esquema entre entrenamiento y detección | ❌ Nunca |
| `scaler` | `RobustScaler` | Scaler del Baseline ajustado para normalización determinista durante la inferencia | ❌ Nunca |
| `baseline_medians` | `dict[str, float]` | Valores de mediana por característica del entrenamiento, usados para imputación segura de protocolos ausentes en PCAPs de prueba | ❌ Nunca |
| `metadata` | `dict` | Procedencia del entrenamiento: fecha, PCAP de origen, recuento de ventanas, capacidades de Phase 6, ajustes de proyección de Hilbert | ❌ Nunca |

### 2.2 La Corrección de Matrioshka Escalado (v4.0)

Las versiones anteriores del pipeline contenían un defecto arquitectónico crítico conocido internamente como *Matrioshka Escalado* (escalado anidado): el `RobustScaler` se aplicaba dos veces; una por `PcapProcessor.get_standardized_matrix()` y otra redundante por el motor durante la proyección de características. Este doble escalado colapsaba la varianza en el espacio de Hilbert, produciendo puntuaciones σ sistemáticamente subestimadas y detecciones omitidas.

La v4.0 resuelve esto definitivamente:

1. `PcapProcessor.get_standardized_matrix()` aplica `RobustScaler` y lo persiste en `models/scalers/robust_training_baseline.pkl`.
2. El orquestador carga este scaler exacto y lo inyecta en el `ArtifactBundle`.
3. `HiGIEngine` posee toda la normalización subsiguiente internamente (Yeo-Johnson `PowerTransformer` → Blocked PCA → whitening). Recibe datos pre-escalados y no vuelve a escalar.
4. En detección, solo se llama a `.transform()` en el scaler restaurado. Sin re-ajustes en ninguna etapa.

El resultado es una cadena de normalización limpia de un solo paso: `RobustScaler` (capa del orquestador) → `PowerTransformer` (capa del motor) → `Blocked PCA` (capa de proyección de Hilbert).

### 2.3 Compatibilidad Hacia Atrás

`ArtifactBundle.load()` gestiona los bundles creados antes de la v4.0 de forma controlada:

```python
scaler=state.get("scaler", None)          # None para bundles pre-v4
baseline_medians=state.get("baseline_medians", {})  # {} para bundles pre-v4
```

Si el `scaler` es `None`, el pipeline de detección lanza un `ValueError` y se niega a proceder, requiriendo que el usuario vuelva a entrenar con el código actual. Este es el comportamiento correcto: un bundle sin un scaler no puede garantizar la corrección de la inferencia.

### 2.4 El Metadata Sidecar

Cada bundle `.pkl` va acompañado de un archivo sidecar `.json` legible por humanos escrito por `bundle.save()`. Este archivo contiene la procedencia completa del entrenamiento en texto plano y es útil para una inspección rápida sin cargar el binario completo:

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

## 3. El Ciclo de Vida de Ejecución

### 3.1 Resumen de Fases

El ciclo de vida completo de HiGI comprende tres fases secuenciales, cada una expuesta como un modo de CLI independiente. Las Fases 1 y 2 se ejecutan una vez por Baseline; la Fase 3 puede re-ejecutarse de forma independiente con diferentes parámetros de filtrado sin repetir la inferencia.

```
FASE 1: ENTRENAMIENTO      FASE 2: DETECCIÓN          FASE 3: REPORTES
─────────────────────      ─────────────────────      ─────────────────────
 PCAP Benigno              PCAP de Prueba             CSV de resultados
     │                         │                           │
     ▼                         ▼                           ▼
 Ingestión               Carga de Bundle            Clustering de Incidentes
 (PcapProcessor)         (ArtifactBundle)           (debounce 30s)
     │                         │                           │
     ▼                         ▼                           ▼
 Matriz de Features      Inyección de Config        Filtro de Confianza
 (ventanas 1s, 42 feat.) de Runtime (v4.0)          (CCI ≥ 0.80)
     │                         │                           │
     ▼                         ▼                           ▼
 Augmentation de Baseline Alineación de Esquema     Atribución σ
 (Gaussian, 10%, σ=5%)   (imputación de mediana)    (culpable + familia)
     │                         │                           │
     ▼                         ▼                           ▼
 RobustScaler fit        RobustScaler transform     Mapeo MITRE
     │                   (REGLA DE ORO: no fit)          │
     ▼                         │                           ▼
 HiGIEngine.train()            ▼                    Evidencia Visual
 (4 tiers, Fase 6)      HiGIEngine.analyze()       (timeline + radar)
     │                   (scoring por ventana)           │
     ▼                         │                           ▼
 ArtifactBundle.save()         ▼                    PDF + Markdown
 (.pkl + .json)          results.csv + .json        Reporte Forense
```

### 3.2 Fase 1 — Entrenamiento: Estableciendo el Sistema de Referencia Inercial

**Punto de entrada:** `TrainingPipeline.run()` → `main.py train`

La fase de entrenamiento construye el marco de referencia geométrico contra el cual se evaluará todo el tráfico futuro. Sus pasos están estrictamente ordenados:

**Paso 1 — Ingestión de PCAP.** `PcapProcessor` lee el PCAP del Baseline en fragmentos paralelos de `ingestion.chunk_size` paquetes usando `n_jobs` núcleos. Cada fragmento se procesa con `tshark`/`scapy` para extraer características brutas a nivel de paquete (timestamps, cabeceras IP, flags TCP, bytes de payload). Este paso está limitado por I/O y se beneficia linealmente de núcleos adicionales hasta alcanzar el ancho de banda de lectura de disco.

**Paso 2 — Agregación de Características.** `_build_base_matrix()` agrega los paquetes brutos en ventanas de tiempo de 1 segundo. Cada ventana produce un vector de características de 42 dimensiones que abarca las cinco familias físicas: Volume (PPS, bytes), Payload (continuity ratio, payload size), Flags (ratios SYN/RST/FIN/URG/ACK), Protocol (ratios ICMP/TCP/UDP), y Connection (IPs/puertos de destino únicos, estadísticas de IAT). El `time_interval: "1s"` en `config.yaml` es un **parámetro estructural inmutable**; cambiarlo invalida el bundle.

**Paso 3 — Augmentation del Baseline.** Para evitar que el modelo estadístico sufra Overfitting ante patrones de tráfico específicos del día de entrenamiento (periodicidad de la hora, sesiones de navegación específicas), el orquestador aplica ruido gaussiano controlado a la matriz de características:

```
n_augmented = ⌊N_baseline × augmentation_synthetic_fraction⌋
noise ~ N(0, augmentation_noise_scale × σ_feature)
X_augmented[i] = X_baseline[random_i] + noise[i]
```

Con los ajustes por defecto (`noise_scale=0.05`, `synthetic_fraction=0.10`), se genera un 10% adicional de ventanas sintéticas con un 5% de ruido a nivel de característica. La semilla de RNG se fija en 42 para reproducibilidad. Esta augmentation amplía el soporte efectivo de la distribución normal, reduciendo la tasa de falsos positivos ante variaciones menores de protocolo en el tráfico de prueba.

**Paso 4 — Entrenamiento del Motor HiGI.** `HiGIEngine.train()` ejecuta la secuencia completa de entrenamiento de cuatro niveles:

| Nivel | Componente | Acción de Entrenamiento |
|------|-----------|----------------|
| Tier 1 | BallTree | Construye el k-d tree en el espacio proyectado de Hilbert; calcula percentiles de distancia P90/P95/P99/P99.9 sobre el Baseline |
| Tier 2A | BayesianGMM | Ajusta un GMM Bayesiano multivariante con selección adaptativa de K (voto de ensamble sobre K ∈ [1, 5]); se calcula el umbral P99.9 de log-likelihood |
| Tier 2B | IForest | Entrena un Isolation Forest con `contamination=0.05`; se calibra el umbral de isolation score |
| Tier 3 | Physical Sentinel | Ajusta un GMM univariante por característica; se calculan umbrales P99.9 de log-likelihood por característica (42 umbrales independientes) |
| Tier 4 | Velocity Bypass | Sin estado (no requiere entrenamiento); se calculan estadísticas de Z-score sobre las características de velocidad del Baseline |

**Paso 5 — Ensamblaje del Bundle.** Todos los artefactos entrenados se empaquetan en un `ArtifactBundle` con metadatos completos de procedencia. Las medianas del Baseline se calculan por característica (filtrando valores NaN e infinitos) para su uso como valores de imputación segura en la detección.

### 3.3 Fase 2 — Detección: Inferencia Bajo Contrato Estricto

**Punto de entrada:** `DetectionPipeline.run()` → `main.py detect`

La fase de detección es la ruta críticamente operativa. Cada decisión de diseño se orienta a un único objetivo: producir puntuaciones de anomalía por ventana que sean matemáticamente comparables al Baseline de entrenamiento, con cero fuga de información (Leakage) de la distribución de prueba.

**Paso 1.5 — Inyección de Configuración de Runtime (v4.0).** Antes de procesar cualquier dato de prueba, el orquestador intercambia los parámetros operativos del `config.yaml` actual en el motor cargado, sin invalidar el modelo matemático entrenado:

```python
runtime_config = self.settings.to_runtime_config()
bundle.engine.update_runtime_config(runtime_config)
```

Este mecanismo (introducido en la v4.0 para resolver el *Conflicto de Persistencia*) permite al operador ajustar `alert_minimum_persistence`, `velocity_bypass_threshold`, `tribunal_consensus_threshold`, `family_consensus_min_hits`, y todos los umbrales de reportes forenses entre ejecuciones de detección sin re-entrenar. La geometría de Blocked PCA, las distancias BallTree, los componentes GMM y los umbrales LL por característica permanecen congelados en el bundle. Consulte la [Sección 6](#6-contrato-de-configuración-modelconfig-vs-runtimeconfig) para la taxonomía completa.

**Paso 4 — Alineación de Esquema.** Es posible que los PCAPs de prueba no contengan todos los protocolos presentes en el Baseline de entrenamiento (ej. un día de prueba sin tráfico ICMP producirá ventanas con `icmp_ratio` en cero). El orquestador resuelve esto mediante imputación determinista:

```python
for feat in missing_features:
    imputation_value = bundle.baseline_medians.get(feat, 0.0)
    df_aggregated_raw[feat] = imputation_value
```

La imputación utiliza la mediana del Baseline (no el cero, ni la media) porque la mediana es robusta ante Outliers y representa el valor más probable bajo la distribución del Baseline. Usar `0.0` como fallback (para protocolos ausentes incluso en el Baseline) es físicamente correcto: una característica que nunca se activó en el Baseline tiene una distribución centrada en cero.

**Paso 5 — Transformación del Scaler.** El `RobustScaler` restaurado se aplica mediante `.transform()` a la matriz de características. Esto mapea cada ventana de prueba al sistema de coordenadas donde el Baseline ocupa la región cercana al origen. Tras este paso, las distancias euclidianas en el espacio de características son aproximadamente comparables a las distancias de Mahalanobis bajo la covarianza del Baseline: la condición geométrica previa para un scoring de anomalías significativo.

**Paso 6 — Inferencia HiGI.** `engine.analyze()` ejecuta el consenso completo del Tribunal para cada ventana de tiempo:

```
Para cada ventana t:
  1. Proyectar x_t al espacio de Hilbert mediante Blocked PCA
  2. Tier 1: k-NN distance → severidad BallTree (0/0.5/1/2/3)
  3. Tier 2A: Inverted GMM log-likelihood → CDF score
  4. Tier 2B: IForest isolation score
  5. Tier 3: LL por característica → physical_culprit + SPIKE/DROP + |σ|
  6. Tier 4: Z-score de Velocidad → bypass de emergencia si Z > 5.0σ
  7. Tribunal: weighted_score = Σ(tier_weight × tier_score)
  8. is_anomaly = (weighted_score > consensus_threshold) AND (persistence ≥ alert_minimum_persistence)
```

La Soft Zone (P90–P95) es una zona de diagnóstico: las ventanas en este rango activan el análisis del Tier 2, pero no se escalan a alertas a menos que múltiples niveles co-activen. Se utilizan exclusivamente los umbrales estáticos del Baseline; no se permite ningún re-umbralizado dinámico a partir del lote de prueba (corrección Bug-F1).

**Paso 7 — Exportación de Resultados.** El DataFrame de resultados se escribe en un CSV conservando todas las columnas forenses: `is_anomaly`, `severity`, `balltree_score`, `gmm_score`, `iforest_score`, `physical_culprit`, `suspect_features`, `soft_zone_triggered`, `_abs_timestamp`, `server_port`. Un archivo `.json` complementario registra los metadatos de la sesión de detección y las métricas de la Fase 6.

### 3.4 Fase 3 — Reportes: Tejiendo Inteligencia Forense

**Punto de entrada:** `run_report()` → `main.py report`

La fase de reporte es la única que puede re-ejecutarse con diferentes parámetros de filtrado sin tocar los artefactos de detección. Su entrada es el CSV producido en la Fase 2; su salida es un reporte de formato dual (PDF + Markdown).

El `HiGIForensicEngine` lee el CSV de resultados y ejecuta:

1. **Detección de Caída de Datos.** Los intervalos que superen el `forensic.data_drop_threshold_seconds` (por defecto: 60s) entre ventanas consecutivas se marcan como eventos de ceguera del sensor, no como anomalías. Cada brecha se clasifica como "Pérdida de Captura / Silencio de Red" o "Ceguera del Sensor / Caída de Datos por Saturación" basándose en la severidad de la ventana precedente.

2. **Clustering de Incidentes.** Las ventanas anómalas consecutivas separadas por menos de `forensic.debounce_seconds` (por defecto: 30s) se fusionan en un único incidente. Este mecanismo de debounce evita tormentas de alertas ante ataques de múltiples ventanas (ej. una inundación DoS de 20 minutos) que generarían miles de alertas individuales.

3. **Filtrado de Confianza.** El Índice de Confianza de Consenso (CCI) de cada incidente se calcula como una suma ponderada de activaciones de niveles:

   ```
   CCI = 0.20 × balltree + 0.25 × gmm + 0.20 × iforest
       + 0.20 × physical_sentinel + 0.15 × velocity_bypass
   ```

   Solo los incidentes con `CCI ≥ forensic.default_confidence_filter` (por defecto: 0.80) y `mean|σ| ≥ forensic.sigma_culprit_min` (por defecto: 2.0) se incluyen en el reporte. Estos umbrales son **mutables** y pueden sobrescribirse a nivel de CLI.

4. **Atribución σ y Mapeo MITRE.** Se extraen las 3 características culpables principales por magnitud de carga por incidente, clasificándolas en familias físicas (Flags, Volume, Payload, Protocol, Connection) y mapeándolas a tácticas y técnicas de MITRE ATT&CK.

5. **Generación de Evidencia Visual.** Se producen dos figuras por sesión: (a) la línea de tiempo de intensidad del ataque (severidad × tiempo, con marcadores de Velocity Bypass y llamadas a los incidentes principales) y (b) el radar de estrés de familias físicas (cuota de anomalías por familia, guiando la priorización inmediata de contramedidas).

---

## 4. Referencia de CLI — `main.py`

### 4.1 Principios de Diseño

`main.py` es puramente el pegamento de la CLI. No contiene lógica de negocio, ni código de ML, ni física. Sus únicas responsabilidades son: (1) parsear argumentos, (2) cargar `HiGISettings` de `config.yaml`, (3) configurar el subsistema de logging, y (4) despachar al manejador de pipeline correspondiente. Esta separación garantiza que toda la lógica del pipeline sea testable unitariamente sin invocar la CLI.

**Propiedades clave:**
- **Idempotente:** Ejecutar el mismo comando dos veces con las mismas entradas produce salidas idénticas. Toda aleatoriedad tiene semilla (augmentation: `seed=42`).
- **Config-first:** Los flags de la CLI sobrescriben los valores por defecto de `config.yaml` donde sea aplicable; nunca introducen valores no cubiertos por `HiGISettings`.
- **Preparado para Micro-batch:** El `PcapProcessor` procesa datos en fragmentos configurables. Reemplazar el lector de PCAP con un lector de socket en vivo requiere cambiar una sola función en `src/ingestion/`.

### 4.2 Flags Globales

Estos flags son válidos para todos los subcomandos:

| Flag | Tipo | Defecto | Descripción |
|------|------|---------|-------------|
| `--config PATH` | `str` | `config.yaml` | Ruta al YAML de configuración. Permite mantener múltiples configuraciones según el entorno (ej. `configs/production.yaml`, `configs/debug.yaml`). |
| `--verbose` | `flag` | `False` | Fuerza el nivel de logging a `DEBUG`, sobrescribiendo `logging.level` en `config.yaml`. Produce detalles de scoring por nivel, estadísticas del scaler y diagnósticos de alineación de esquema. |

### 4.3 `train` — Establecer Baseline

```bash
python main.py train --source <PCAP> --bundle <PKL> [--config <YAML>] [--verbose]
```

**Propósito:** Ingerir un PCAP benigno, construir la matriz de características, entrenar el motor de detección de cuatro niveles y persistir el `ArtifactBundle` en disco.

| Argumento | Requerido | Descripción |
|----------|----------|-------------|
| `--source PCAP` | ✅ | Ruta al archivo PCAP del Baseline benigno. Típicamente una captura de un lunes o una conocida como limpia. |
| `--bundle PKL` | ✅ | Ruta de salida para el `ArtifactBundle` entrenado. La extensión `.pkl` es convencional pero no obligatoria. |

**Qué lee de `config.yaml`:**
- `ingestion.chunk_size`, `ingestion.n_jobs`, `ingestion.time_interval`: paralelismo de ingestión y resolución de ventana.
- `training.baseline_augmentation_enabled`, `.augmentation_noise_scale`, `.augmentation_synthetic_fraction`: parámetros de augmentation del Baseline.
- `hilbert.*`: geometría de Blocked PCA (inmutable en el momento del entrenamiento).
- `gmm.*`, `balltree.*`, `iforest.*`, `sentinel.*`: configuración de niveles.

**Ejemplo:**
```bash
python main.py train \
    --source data/raw/Monday.pcap \
    --bundle models/baseline_monday.pkl \
    --verbose
```

**Salida esperada:**
```
[2026-04-27 14:32:11] [INFO    ] [higi.train] ================================================================================
[2026-04-27 14:32:11] [INFO    ] [higi.train] HiGI TRAINING MODE
[2026-04-27 14:32:11] [INFO    ] [higi.train] ================================================================================
[2026-04-27 14:32:11] [INFO    ] [higi.train]   Source PCAP : data/raw/Monday.pcap
[2026-04-27 14:32:11] [INFO    ] [higi.train]   Output Bundle: models/baseline_monday.pkl
...
[2026-04-27 14:48:03] [INFO    ] [higi.train]   ✓ Training complete. Bundle saved to models/baseline_monday.pkl
```

### 4.4 `detect` — Ejecutar Inferencia

```bash
python main.py detect \
    --source <PCAP> --bundle <PKL> \
    [--output <CSV>] [--config <YAML>] [--verbose]
```

**Propósito:** Cargar un `ArtifactBundle`, ingerir un PCAP de prueba, aplicar la configuración de runtime, ejecutar la inferencia de cuatro niveles y escribir el CSV de resultados.

| Argumento | Requerido | Descripción |
|----------|----------|-------------|
| `--source PCAP` | ✅ | Ruta al PCAP de prueba a evaluar. |
| `--bundle PKL` | ✅ | Ruta al `ArtifactBundle` entrenado producido por `train`. |
| `--output CSV` | ❌ | Ruta del CSV de resultados de salida. Por defecto es `<results_dir>/<source_stem>_results.csv` como se define en `config.yaml`. |

**Ejemplo:**
```bash
python main.py detect \
    --source data/raw/Wednesday.pcap \
    --bundle models/baseline_monday.pkl \
    --output data/processed/wednesday_results.csv \
    --verbose
```

### 4.5 `report` — Generar Reporte Forense

```bash
python main.py report \
    --results <CSV> --bundle <PKL> \
    [--output-dir <DIR>] [--confidence <FLOAT>] \
    [--min-anomalies <N>] [--min-duration <SEC>] \
    [--config <YAML>] [--verbose]
```

**Propósito:** Agrupar incidentes a partir de un CSV de resultados existente y generar el reporte forense en PDF + Markdown. El argumento `--bundle` es opcional pero muy recomendado: proporciona los metadatos de mapeo de familias de Blocked PCA necesarios para una atribución precisa de culpables.

| Argumento | Requerido | Defecto | Descripción |
|----------|----------|---------|-------------|
| `--results CSV` | ✅ | — | CSV de resultados de detección producido por `detect`. |
| `--bundle PKL` | ❌ | None | ArtifactBundle para atribución mejorada con metadatos de PCA. Sin él, el motor degrada a inferencia de familia basada en palabras clave. |
| `--output-dir DIR` | ❌ | `config.yaml:paths.reports_dir` | Directorio para salidas PDF y Markdown. Se crea si no existe. |
| `--confidence FLOAT` | ❌ | `config.yaml:forensic.default_confidence_filter` | CCI mínimo (0.0–1.0) para que un incidente aparezca en el reporte. El valor de CLI tiene precedencia. |
| `--min-anomalies N` | ❌ | `config.yaml:forensic.default_min_anomalies` | Número mínimo de ventanas anómalas por incidente. Filtra picos transitorios. |
| `--min-duration SEC` | ❌ | `config.yaml:forensic.default_min_duration_seconds` | Duración mínima del incidente en segundos. |

**Prioridad de sobrescritura:** CLI > `config.yaml` > valor por defecto de dataclass. El comando report está diseñado para ser re-ejecutado iterativamente con diferentes parámetros de filtrado para explorar el espacio de incidentes sin repetir la fase de inferencia, que es computacionalmente costosa.

**Ejemplo: filtro estricto para reportes de alta confianza:**
```bash
python main.py report \
    --results data/processed/wednesday_results.csv \
    --bundle models/baseline_monday.pkl \
    --confidence 0.90 \
    --min-anomalies 5 \
    --output-dir reports/wednesday_strict/
```

**Ejemplo: filtro permisivo para reconocimiento durante el triaje:**
```bash
python main.py report \
    --results data/processed/wednesday_results.csv \
    --bundle models/baseline_monday.pkl \
    --confidence 0.60 \
    --min-anomalies 1 \
    --min-duration 0.0 \
    --output-dir reports/wednesday_triage/
```

**Archivos de salida:**
```
reports/wednesday_strict/
├── wednesday_results_FORENSIC.pdf     # PDF profesional con gráficos
└── wednesday_results_FORENSIC.md      # Markdown renderizable en GitHub con rutas de figuras integradas
```

### 4.6 `run` — Pipeline Completo en un Solo Comando

```bash
python main.py run \
    --source <PCAP> --bundle <PKL> \
    [--output-dir <DIR>] [--confidence <FLOAT>] \
    [--min-anomalies <N>] [--min-duration <SEC>] \
    [--config <YAML>] [--verbose]
```

**Propósito:** `detect` seguido inmediatamente por `report` en una sola invocación. El CSV intermedio se escribe en `<output-dir>/<source_stem>_results.csv` y luego es consumido por el generador de reportes. Todos los flags de reporte están disponibles.

```bash
python main.py run \
    --source data/raw/Wednesday.pcap \
    --bundle models/baseline_monday.pkl \
    --output-dir data/processed/ \
    --confidence 0.75
```

### 4.7 Códigos de Salida

| Código | Significado |
|------|---------|
| `0` | Éxito: todas las salidas se han escrito. |
| `1` | Fallo: error en el pipeline (PCAP no encontrado, bundle corrupto, config inválida, etc.). Error específico registrado. |
| `130` | Interrumpido: el usuario envió `KeyboardInterrupt` (Ctrl+C). Pueden existir salidas parciales. |

---

## 5. Manejo de Errores y Resiliencia

### 5.1 Jerarquía de Excepciones

El orquestador define una jerarquía de excepciones tipificadas que evita que las capturas genéricas de `Exception` silencien información diagnóstica:

```
OrchestratorError          (base — nunca se lanza directamente)
├── TrainingError          (Paso 1–5 de TrainingPipeline)
├── DetectionError         (Paso 1–7 de DetectionPipeline)
└── ArtifactError          (operaciones de carga/guardado de bundle)
```

Cada excepción envuelve su causa con `raise ... from e`, preservando la cadena completa de excepciones en el Traceback. El modo `--verbose` activa `logger.debug(traceback.format_exc())` para obtener trazas completas de la pila en el archivo de log.

### 5.2 Corrupción de PCAP y Capturas Parciales

`PcapProcessorError` es lanzada por la capa de ingestión cuando un PCAP es ilegible, está truncado o es estructuralmente inválido. El orquestador captura esta excepción específicamente y la vuelve a lanzar como `TrainingError` o `DetectionError` con un mensaje explicativo:

```python
except PcapProcessorError as e:
    raise TrainingError(f"PCAP processing failed: {str(e)}") from e
```

Los PCAPs parciales (capturas terminadas abruptamente por un fallo del sistema) se gestionan de forma controlada: `PcapProcessor` lee tantos paquetes válidos como estén disponibles y construye la matriz de características a partir de la porción válida. El sidecar de metadatos reflejará el recuento real de paquetes.

### 5.3 Inconsistencias en el Esquema de Características

El modo de fallo operativo más común es un desajuste entre el esquema de características del Baseline de entrenamiento y el PCAP de prueba. Esto surge cuando el tráfico de prueba no utiliza todos los protocolos presentes en el Baseline (ej. sin ICMP en las capturas DoS de un miércoles, o sin tráfico multicast en una prueba de un solo servidor).

El orquestador gestiona esto en dos direcciones:

**Características faltantes (en prueba pero no en Baseline):** Se rellenan con las medianas del Baseline de `bundle.baseline_medians`. Se registra un `WARNING` identificando cada característica faltante y su valor imputado. Este es el camino seguro: la característica faltante era estadísticamente cero o cercana a cero en el Baseline, y la imputación por mediana preserva esa expectativa.

**Características extra (en prueba pero no en Baseline):** Se descartan con `df.drop(columns=...)`. Suelen ser nuevas subvariantes de protocolo (ej. un nuevo tipo de cabecera de extensión IPv6) no presentes en los datos de entrenamiento. No pueden evaluarse contra el modelo de Baseline y se excluyen silenciosamente. Se registra un `WARNING`.

**Verificación de esquema antes de la inferencia:**
```python
if len(results) != len(X_metadata):
    raise ValueError("Index alignment failed in STEP 6")
```

Esta comprobación posterior a la inferencia garantiza que los metadatos de timestamp y puerto de servidor estén correctamente alineados con los resultados de la inferencia antes de escribir el CSV. Si la alineación falla (lo cual debería ser arquitectónicamente imposible), el pipeline aborta en lugar de escribir una salida desalineada.

### 5.4 Fallos de Validación de Configuración

`config.yaml` es validado por `_validate()` en `src/config.py` antes de que se ejecute cualquier código de pipeline. Los fallos de validación producen un error estructurado que enumera todas las violaciones de restricciones:

```
[ERROR] Configuration error: config.yaml validation failed:
  • tribunal.weights must sum to 1.0, got 0.9500
  • hilbert.pca_variance_target must be in [0.80, 1.0], got 1.05
```

El pipeline no se inicia si existe algún error de validación. Este diseño evita ejecuciones parcialmente mal configuradas que produzcan resultados sutilmente incorrectos.

### 5.5 Fallos de Visualización

La visualización de reportes (gráfico de línea de tiempo, gráfico de radar) está envuelta en un `try/except` aislado:

```python
try:
    visual_paths = engine.generate_visuals(output_dir)
except Exception as vis_exc:
    logger.warning(f"Failed to generate visualizations: {vis_exc}")
    visual_paths = None
```

Un fallo de visualización (ej. backend de matplotlib no disponible en un entorno sin entorno gráfico) no aborta el reporte. El PDF y el Markdown se siguen generando, con marcadores de posición (placeholders) en lugar de los gráficos integrados. Esto asegura que la inteligencia forense siempre se entregue incluso en entornos de renderizado degradados.

---

## 6. Contrato de Configuración: ModelConfig vs. RuntimeConfig

### 6.1 El Conflicto de Persistencia (Solución v4.0)

Antes de la v4.0, un defecto de diseño crítico causaba que la sensibilidad de detección quedara congelada en el momento del entrenamiento: parámetros como `alert_minimum_persistence` y `tribunal_consensus_threshold` se grababan en el `ArtifactBundle` durante el entrenamiento y no podían cambiarse sin volver a entrenar. Esto imposibilitaba el ajuste operativo rápido (ej. reducir la persistencia para detectar una Inyección SQL de 2 minutos) sin un ciclo completo de re-entrenamiento.

La v4.0 resuelve esto mediante una división arquitectónica limpia: `ModelConfig` vs. `RuntimeConfig`.

### 6.2 ModelConfig — Congelado en el Entrenamiento

`ModelConfig` contiene todos los parámetros que definen la geometría del espacio de Hilbert y la calibración matemática de los detectores de cuatro niveles. Estos parámetros se serializan en el `ArtifactBundle.engine` y no deben cambiar entre entrenamiento y detección.

| Sección | Parámetro | Por qué es Inmutable |
|---------|-----------|---------------|
| `hilbert` | `pca_variance_target`, `blocked_pca_variance_per_family`, `blocked_pca_enabled` | Define la dimensionalidad y la orientación de los ejes del espacio de proyección de Hilbert. Cambiarlo hace que las distancias BallTree carezcan de sentido físico. |
| `ingestion` | `time_interval` | Define la resolución temporal de cada ventana de características. Una ventana de 1 segundo produce estadísticas de características diferentes a una de 5 segundos. |
| `balltree` | `k_neighbors` | Determina el radio de vecindad en el espacio geométrico. |
| `gmm` | `reg_covar`, `use_bayesian`, `adaptive_k_range`, `n_components_fallback`, `score_normalization` | Define el modelo de densidad ajustado al Baseline. Diferentes ajustes producen diferentes umbrales de log-likelihood. |
| `iforest` | `contamination`, `n_estimators` | Determina la calibración del isolation score. |
| `sentinel` | `per_feature_thresholds`, `global_threshold` | Los umbrales P99.9 por característica se calculan en el entrenamiento sobre la distribución del Baseline. |
| `training` | `augmentation_noise_scale`, `augmentation_synthetic_fraction` | Afecta al soporte efectivo del modelo de Baseline. |

### 6.3 RuntimeConfig — Intercambiable vía `config.yaml`

`RuntimeConfig` contiene todos los parámetros operativos que pueden cambiarse entre sesiones de detección sin invalidar el modelo entrenado. Estos se cargan desde `config.yaml` al inicio de cada ejecución de `detect` a través de `settings.to_runtime_config()` y se inyectan en el motor mediante `bundle.engine.update_runtime_config(runtime_config)`.

| Sección | Parámetro | Efecto Operativo |
|---------|-----------|-------------------|
| `persistence` | `alert_minimum_persistence` | ↓ para detectar ataques cortos (SQLi, ventanas de 2 min); ↑ para suprimir transitorios. |
| `persistence` | `hysteresis_entry_multiplier`, `hysteresis_exit_multiplier` | Controla el sostenimiento/caída de la alerta respecto al umbral P95. |
| `persistence` | `ma_window_size` | Ventana de suavizado para la contextualización de media móvil. |
| `tribunal` | `consensus_threshold` | ↓ para mayor Recall (más alertas); ↑ para mayor Precisión (menos FP). |
| `tribunal` | `weights.{balltree,gmm,iforest}` | Reequilibrar el voto del Tribunal sin re-entrenar. Los pesos deben sumar 1.0. |
| `velocity` | `bypass_threshold` | Z-score al cual el Tier 4 se activa incondicionalmente. ↓ detecta picos moderados; ↑ reserva el Tier 4 para inundaciones extremas. |
| `family_consensus` | `min_hits`, `z_threshold` | Compuerta anti-FP: requiere N características de la misma familia por encima de z_threshold para escalar detecciones limítrofes. |
| `forensic` | `debounce_seconds` | Ventana de agrupación de incidentes. ↑ fusiona alertas adyacentes en incidentes más largos; ↓ produce una granularidad más fina. |
| `forensic` | `default_confidence_filter` | Corte de CCI para incidentes reportables. |
| `forensic` | `sigma_culprit_min` | Media mínima de |σ| para características culpables en incidentes reportables. |

---

## 7. Aviso Técnico: El Espacio de Hilbert

### 7.1 Fundamentación Conceptual

La nomenclatura *espacio de Hilbert* en HiGI es una referencia conceptual deliberada al marco matemático de la mecánica cuántica, donde el estado de un sistema se representa como un vector en un espacio de producto interno de dimensiones infinitas. En mecánica cuántica, la medición colapsa el vector de estado en un autoestado (eigenstate); en HiGI, el consenso del Tribunal colapsa la puntuación de anomalía multidimensional en un nivel de severidad discreto.

La analogía no es meramente retórica. En ambos casos, la operación fundamental es el cálculo de una **distancia respecto a un estado de referencia** (el Baseline) utilizando una métrica que tiene en cuenta la varianza natural del sistema (la estructura de covarianza). La distancia de Mahalanobis utilizada por el detector BallTree es el análogo en mecánica clásica del valor esperado del operador de desviación en la teoría cuántica.

### 7.2 Realidad de la Implementación

En términos concretos de ingeniería, el "espacio de Hilbert" de HiGI es un espacio euclidiano de dimensiones finitas producido por la siguiente secuencia de transformaciones:

```
x_t ∈ ℝ^42  (features brutas, normalizadas con RobustScaler)
      │
      │ Yeo-Johnson PowerTransformer (gaussianización por característica)
      ▼
x̃_t ∈ ℝ^42  (marginales aproximadamente gaussianas)
      │
      │ Blocked PCA por familia física (decorrelación + whitening)
      │ Familia f: z_t^(f) = W^(f)ᵀ (x̃_t^(f) − μ_0^(f))
      ▼
z_t ∈ ℝ^k   (k ≤ 42, componentes principales blanqueadas/whitened)
```

El espacio resultante `ℝ^k` tiene la propiedad de que:

1. **Las distancias euclidianas aproximan las distancias de Mahalanobis** en el espacio original de características, porque el blanqueo (whitening) de Blocked PCA aplica efectivamente la raíz cuadrada inversa de la matriz de covarianza por familia.
2. **Cada componente principal se mapea exactamente a una familia física**, porque Blocked PCA opera de forma independiente por familia. Esta es la propiedad que hace posible la atribución forense: el componente de PCA que más se desvía del Baseline puede rastrearse directamente hasta su familia de características.
3. **El espacio es máximamente compacto** para los objetivos de retención de varianza dados (`blocked_pca_variance_per_family`). Las características con bajo poder discriminatorio se colapsan en menos componentes, reduciendo la computación de BallTree y mejorando el poder estadístico.

El término "espacio de Hilbert" en el código y la documentación debe entenderse, por tanto, como una abreviatura conceptualmente motivada para: *un espacio métrico blanqueado y estructurado por familias en el cual la distribución del Baseline ocupa una región compacta de alta densidad y las anomalías son puntos geométricamente distantes de esa región*.

### 7.3 Por qué esto es importante para la Confianza Operativa

El fundamento físico de la proyección de Hilbert no es un ejercicio académico. Es la garantía de ingeniería de que una detección a 4,120σ (`payload_continuity_ratio`, DoS GoldenEye) no es un artefacto numérico o una patología del modelo; es la afirmación geométricamente correcta de que la ventana de tráfico observada se encuentra a 4,120 desviaciones estándar del Baseline respecto al centro de la variedad (manifold) de tráfico normal, en la dirección de la máxima disrupción de la estructura del payload. Esa afirmación es independientemente verificable, dimensionalmente consistente y operacionalmente accionable.

Los modelos supervisados producen probabilidades o etiquetas de clase. HiGI produce **desplazamientos físicos desde un sistema de referencia inercial**. La diferencia no es cosmética.

---

## 8. Glosario

| Término | Definición |
|------|------------|
| **ArtifactBundle** | Archivo `.pkl` inmutable que contiene el `HiGIEngine` entrenado, el esquema de características, el `RobustScaler`, las medianas del Baseline y los metadatos de procedencia del entrenamiento. |
| **Blocked PCA** | Análisis de Componentes Principales realizado de forma independiente por familia física de características. Preserva la interpretabilidad semántica de los componentes y permite una atribución forense precisa a nivel de familia. |
| **CCI (Consensus Confidence Index)** | Suma ponderada de las puntuaciones de activación de niveles para un incidente, calculada por el ForensicEngine. Rango [0, 1]. |
| **DSS (Dynamic Severity Score)** | Nivel de severidad por ventana asignado por el Tribunal: 0 = Normal, 1 = Limítrofe, 2 = Medio, 3 = Crítico. |
| **Regla de Oro** | El invariante de inferencia: solo `.transform()` en modo detección. Nunca `.fit()`. |
| **Espacio de Hilbert** | Espacio métrico interno de HiGI: una proyección euclidiana blanqueada y estructurada por familias del espacio original de características en la cual las distancias euclidianas aproximan las distancias de Mahalanobis bajo la covarianza del Baseline. Ver [Sección 7](#7-aviso-técnico-el-espacio-de-hilbert). |
| **Sistema de Referencia Inercial** | La distribución del tráfico Baseline `N(μ₀, Σ₀)` aprendida de los datos de entrenamiento benignos. Todas las puntuaciones de anomalía son desplazamientos relativos desde este marco. |
| **Matrioshka Escalado** | Nombre en código de la corrección del bug de la v4.0. Se refiere al defecto de escalado anidado (doble) donde el `RobustScaler` se aplicaba dos veces, colapsando la varianza. |
| **ModelConfig** | Parámetros congelados en el entrenamiento que definen la geometría del espacio de Hilbert y la calibración de los detectores de cuatro niveles. Inmutable en el bundle. |
| **Conflicto de Persistencia** | Problema arquitectónico de la v4.0 donde los parámetros operativos de runtime se congelaban erróneamente en el `ArtifactBundle`, impidiendo el ajuste en caliente. |
| **Portero Veto** | Sobrescritura del Tier 3: si alguna característica supera el `sentinel.portero_sigma_threshold` (defecto: 12.0σ en `config.yaml`, 20.0σ en el dataclass `config.py`), la ventana se escala incondicionalmente a CRITICAL independientemente del voto del Tribunal. Defensa de último recurso contra desviaciones catastróficas. |
| **RuntimeConfig** | Parámetros cargados desde `config.yaml` en cada sesión de detección e intercambiados en el motor sin re-entrenar. Controla la sensibilidad operativa. |
| **Soft Zone (P90–P95)** | Rango de percentiles de distancia BallTree que activa el análisis del Tier 2 sin escalado directo. Una zona de defensa en profundidad para ventanas limítrofes. |
| **Tribunal** | El mecanismo de votación ponderada que agrega las puntuaciones de los niveles 1–4 en una única decisión de `is_anomaly` y nivel DSS. |
| **Velocity Bypass (Tier 4)** | Detector de emergencia sin estado basado en el Z-score de la velocidad del tráfico (PPS, bytes/s). Se activa incondicionalmente cuando Z supera el `velocity.bypass_threshold`, saltándose el voto del Tribunal. |

---

*Manual de HiGI IDS Core v4.0.0 · Ingeniería de Blue Team · 2026*   
*Este documento es parte de la suite de documentación técnica de HiGI IDS. Referencia cruzada con:*  
*[Manual de Inteligencia Forense y Atribución (XAI)](docs/) ·*   
*[Referencia de Configuración y Ajuste](docs/) ·*   
*[Manual del Pipeline de Ingestión](docs/)*  