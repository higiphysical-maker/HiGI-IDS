# HiGI IDS — Manual de Ingeniería de Datos e Ingestión
## Data Pipeline: De PCAP Crudo a Feature Matrix de Alta Fidelidad

**Módulo:** `src/ingestion/processor_optime.py`  
**Versión Documentada:** v2.3.0  
**Clasificación:** Referencia Técnica Interna — Nivel Ingeniería  

---

## Índice

1. [Visión General de la Arquitectura](#1-visión-general-de-la-arquitectura)
2. [Especificaciones Técnicas del Pipeline](#2-especificaciones-técnicas-del-pipeline)
3. [Fase 1 — Ingestión: Del PCAP al DataFrame Bruto](#3-fase-1--ingestión-del-pcap-al-dataframe-bruto)
4. [Fase 2 — Ventanización Temporal y Agregación](#4-fase-2--ventanización-temporal-y-agregación)
5. [Fase 3 — Feature Engineering: Dimensiones Físicas](#5-fase-3--feature-engineering-dimensiones-físicas)
6. [Fase 4 — Estandarización y Contrato de Inferencia](#6-fase-4--estandarización-y-contrato-de-inferencia)
7. [Optimización de Recursos y Paralelismo](#7-optimización-de-recursos-y-paralelismo)
8. [Robustez y Manejo de Errores](#8-robustez-y-manejo-de-errores)
9. [Validación de Integridad: Capture Health Report](#9-validación-de-integridad-capture-health-report)
10. [Inventario Completo de Features](#10-inventario-completo-de-features)

---

## 1. Visión General de la Arquitectura

El módulo `processor_optime.py` constituye la **capa de ingestión y transformación** de HiGI IDS. Su responsabilidad es tomar un archivo PCAP de captura de red — potencialmente de varios gigabytes — y producir una **Feature Matrix** estandarizada, indexada por ventana temporal, lista para ser consumida por el motor de detección (`higi_engine.py`).

El diseño del pipeline se rige por tres principios de ingeniería:

**1. Física antes que estadística.** Cada feature no es una transformación arbitraria, sino la proyección de una magnitud física real del tráfico de red: velocidad de flujo, continuidad de payload, cinemática de paquetes. Esto garantiza que las anomalías detectadas tengan una interpretación operacional directa.

**2. Eficiencia de memoria por encima de simplicidad.** El pipeline nunca carga el PCAP completo en memoria. El procesamiento se realiza en batches de tamaño configurable (default: 5.000 paquetes) mediante un generador Python, y la concatenación final se realiza sobre chunks Polars — no sobre listas de diccionarios.

**3. Determinismo contractual.** El escalador `RobustScaler` entrenado durante la fase de baseline se serializa como artefacto (`.pkl`) y es el mismo objeto que se aplica en inferencia. No existe recalibración de parámetros en tiempo de detección.

### Diagrama de Flujo del Pipeline

```
PCAP File
    │
    ▼
┌─────────────────────────────────────────────┐
│  _batch_generator()                          │
│  StreamGenerator → chunks de 5.000 paquetes │
│  Soporte: Ethernet, Linux SLL, Raw IP        │
└───────────────┬─────────────────────────────┘
                │  batches (ip_payload, timestamp, length)
                ▼
┌─────────────────────────────────────────────┐
│  ProcessPoolExecutor (n_jobs=6)             │
│  _process_batch() — paralelo por batch      │
│  ├── Parse IP/TCP/UDP (dpkt)                │
│  ├── Extracción de puertos y flags TCP       │
│  ├── Entropía Shannon (vectorizada NumPy)   │
│  └── Detección de dirección (in/outbound)   │
└───────────────┬─────────────────────────────┘
                │  List[Dict] → pl.DataFrame chunks
                ▼
┌─────────────────────────────────────────────┐
│  pl.concat() + sort("timestamp")            │
│  Restauración del orden cronológico         │
│  Cálculo de timestamps relativos (dt)       │
└───────────────┬─────────────────────────────┘
                │  pl.DataFrame (packets)
                ▼
┌─────────────────────────────────────────────┐
│  _build_base_matrix()                       │
│  LazyFrame group_by("second_window")        │
│  ├── Agregación de intensidad (PPS, bytes)  │
│  ├── Ratios por protocolo y flags TCP        │
│  ├── Dimensiones físicas (flow, IAT, PCR)   │
│  └── Z-scores dinámicos (ventana 60s)       │
└───────────────┬─────────────────────────────┘
                │  pd.DataFrame (feature matrix)
                ▼
┌─────────────────────────────────────────────┐
│  get_standardized_matrix()                  │
│  ColumnTransformer (paralelo, n_jobs)        │
│  ├── Ratios → Identity (sin escalar)        │
│  └── Resto → RobustScaler                   │
└───────────────┬─────────────────────────────┘
                │
                ▼
      Feature Matrix Estandarizada
      → higi_engine.py (Tribunal de Consenso)
```

---

## 2. Especificaciones Técnicas del Pipeline

| Parámetro | Valor / Configuración | Descripción |
|---|---|---|
| **Librería de parsing** | `dpkt` (única) | Sin mezcla de librerías; API homogénea |
| **Motor de agregación** | `polars.LazyFrame` | Evaluación lazy; sin materialización hasta `.collect()` |
| **Chunk size (default)** | 5.000 paquetes | Controlado por `PcapProcessor.DEFAULT_CHUNK_SIZE` |
| **Paralelismo** | `ProcessPoolExecutor` (n_jobs=6) | Procesos independientes; evita GIL |
| **MAX_INFLIGHT** | `n_jobs × 2` | Batches simultáneos máximos en cola de workers |
| **Escalador baseline** | `RobustScaler` | Resistente a outliers extremos (ataques DoS) |
| **Escalador inference** | Pre-entrenado (`.pkl`) | Contrato determinista; no recalibra en detección |
| **Tipos internos** | `Float64` (Polars) / `np.float32` donde aplica | Eficiencia de cómputo en matrices densas |
| **Ventana temporal** | `1s` (configurable) | `time_interval` en `config.yaml` |
| **Ventana Z-score dinámico** | 60 segundos | Detección de régimen de tráfico (v2.3.0) |
| **Ventana de volatilidad** | 5 segundos | `rolling_std(5)` sobre PPS, bytes, entropía |
| **Entropía Shannon** | Rango `[0.0, 8.0]` bits | Vectorizada NumPy; 10-15× más rápida que scipy |
| **Datalinks soportados** | Ethernet, Linux SLL, Raw IP | Fallback genérico para tipos desconocidos |
| **Manejo de malformados** | `dpkt.UnpackError` → skip silencioso | Sin interrupción del pipeline |
| **Columnas de metadata** | `_abs_timestamp`, `server_port` | Excluidas del escalado; responsabilidad del orquestador |

---

## 3. Fase 1 — Ingestión: Del PCAP al DataFrame Bruto

### 3.1 Stream Generator: Lectura sin Pre-carga en Memoria

La ingestión comienza en `_batch_generator()`, un generador Python que lee el PCAP de forma incremental. El archivo nunca se carga completo en RAM; en su lugar, se itera paquete a paquete, acumulando batches de `chunk_size` paquetes antes de cederlos (`yield`) al pool de procesos.

```python
# Patrón de control de backpressure (MAX_INFLIGHT)
if len(inflight) >= MAX_INFLIGHT:
    done, pending = concurrent.futures.wait(
        inflight, return_when=concurrent.futures.FIRST_COMPLETED
    )
```

El parámetro `MAX_INFLIGHT = n_jobs × 2` actúa como mecanismo de backpressure: si los workers no pueden consumir batches con suficiente velocidad, el generador espera antes de encolar más trabajo, evitando la acumulación de batches no procesados en memoria.

### 3.2 Resolución de Protocolo IANA

El módulo inicializa en `__init__` un mapa `Dict[int, str]` que traduce números de protocolo IP a sus nombres oficiales IANA. Esto se realiza extrayendo las constantes del módulo `dpkt.ip` — no existe una tabla hardcodeada. Protocolos no reconocidos se representan como `PROTO_{número}`, garantizando trazabilidad forense incluso para protocolos experimentales o propietarios.

### 3.3 Procesamiento por Batch: `_process_batch()`

Cada batch se procesa en un worker independiente. Para cada paquete IPv4, el worker realiza las siguientes operaciones en secuencia:

**a) Parsing de capas de transporte**

```
IP header → (TCP | UDP | otros)
             ├── Extracción de src_port, dst_port
             ├── Flags TCP (SYN, ACK, FIN, RST, PSH, URG) — máscara de bits
             └── Payload: bytes después del header de transporte
```

Los flags TCP se extraen mediante operaciones de máscara de bits sobre el campo `flags` del paquete `dpkt.tcp.TCP`:

```python
"tcp_flags_syn": 1 if (flags_byte & dpkt.tcp.TH_SYN) else 0
```

**b) Entropía de Shannon del Payload**

Para cada paquete, se calcula la entropía del payload de transporte mediante una implementación vectorizada con NumPy:

$$H(X) = -\sum_{i=0}^{255} p_i \cdot \log_2(p_i)$$

donde $p_i = \frac{n_i}{L}$, siendo $n_i$ el número de ocurrencias del byte $i$ y $L$ la longitud total del payload. El rango válido es $H \in [0.0, 8.0]$ bits. Payloads vacíos devuelven $H = 0.0$.

La implementación utiliza `np.bincount()` sobre un buffer `uint8`, evitando la creación de histogramas por bucle y logrando una velocidad 10-15 veces superior a `scipy.stats.entropy` para los tamaños de payload típicos en tráfico de red.

**c) Detección de Dirección de Tráfico**

Cada paquete es clasificado semánticamente en función de si el puerto origen o destino pertenece al conjunto `STANDARD_SERVICE_PORTS` (22 puertos definidos, incluyendo HTTP, HTTPS, SSH, DNS, bases de datos comunes):

- **`outbound`**: `dst_port` ∈ SERVICE_PORTS → el cliente envía una solicitud al servidor
- **`inbound`**: `src_port` ∈ SERVICE_PORTS → el servidor envía una respuesta al cliente
- **`unknown`**: ningún puerto reconocido

Esta clasificación permite calcular la asimetría de payload L7 en la fase de agregación (ver §5.3).

### 3.4 Reordenamiento Cronológico Post-Paralelo

La ejecución paralela de batches introduce no-determinismo en el orden de completación: un batch posterior puede terminar antes que uno anterior si la carga de cómputo es desigual. Concatenar directamente chunks desordenados rompe la continuidad temporal de la serie, produciendo falsas alertas de "Data Drop" y derivadas incorrectas en los cálculos de velocidad.

```python
# OPERACIÓN OBLIGATORIA — no omitir en ninguna refactorización futura
df_polars = df_polars.sort("timestamp")
```

Este `sort` en Polars opera en $O(n \log n)$ sobre la columna de timestamps y es la última operación sobre el DataFrame bruto antes de la ventanización.

---

## 4. Fase 2 — Ventanización Temporal y Agregación

### 4.1 LazyFrame: Evaluación Diferida con Polars

La transición de paquetes individuales a la Feature Matrix ocurre en `_build_base_matrix()`. El DataFrame bruto se convierte en un **LazyFrame** de Polars:

```python
lf = dataframe.lazy()
lf = lf.with_columns([
    pl.col("timestamp").cast(pl.Int64).alias("second_window")
])
```

El cast a `Int64` trunca el timestamp de cada paquete a su segundo entero, creando el índice de la ventana temporal. Polars no ejecuta ninguna operación hasta que se llama a `.collect()` al final de la cadena de transformaciones, permitiendo que el optimizador de consultas de Polars reordene, funda y paralelice las operaciones internamente.

**Ventaja sobre Pandas:** En Pandas, cada `.groupby().agg()` materializa un DataFrame intermedio completo. Polars construye un plan de ejecución único y lo ejecuta en un único paso sobre los datos, reduciendo las copias en memoria y aprovechando las instrucciones SIMD del procesador.

### 4.2 Agregación Dinámica por Ventana

El `group_by("second_window")` es **dinámico**: los protocolos y flags TCP se detectan en el DataFrame bruto antes de la agregación, y la lista de columnas a agregar se construye programáticamente. Esto elimina la necesidad de actualizar el pipeline cuando aparecen protocolos no previstos en el tráfico.

```python
protocols = dataframe["protocol"].unique().to_list()
flag_cols = [c for c in dataframe.columns if c.startswith("tcp_flags_")]
```

Para cada ventana de 1 segundo, se calculan las siguientes magnitudes brutas:

| Agregado bruto | Operación Polars | Significado físico |
|---|---|---|
| `pps` | `pl.len()` | Packets per second |
| `bytes` | `pl.col("size").sum()` | Throughput bruto en bytes |
| `count_{protocol}` | `(pl.col("protocol") == p).sum()` | Conteo por protocolo |
| `count_{flag}` | `(pl.col(flag) == 1).sum()` | Conteo por flag TCP |
| `unique_dst_ports` | `pl.col("dst_port").n_unique()` | Diversidad de puertos destino |
| `entropy_avg` | `pl.col("entropy").mean()` | Entropía media del payload |
| `size_max`, `size_avg` | `.max()`, `.mean()` | Estadísticas de tamaño de paquete |
| `total_payload_bytes` | `pl.col("payload_bytes").sum()` | Bytes de payload de transporte |
| `total_req_payload` | `pl.col("req_payload").sum()` | Bytes outbound (cliente→servidor) |
| `total_res_payload` | `pl.col("res_payload").sum()` | Bytes inbound (servidor→cliente) |
| `_ts_max`, `_ts_min` | `.max()`, `.min()` de timestamp | Span temporal dentro de la ventana |
| `_abs_timestamp` | `pl.col("abs_ts").min()` | Timestamp absoluto del primer paquete |

---

## 5. Fase 3 — Feature Engineering: Dimensiones Físicas

### 5.1 Transformaciones de Intensidad (Log-Normalización)

Las métricas de intensidad bruta (`pps`, `bytes`) presentan distribuciones fuertemente sesgadas hacia la derecha, características de tráfico de red con ráfagas esporádicas. La transformación logarítmica las proyecta a una escala manejable:

$$\text{total\_pps\_log} = \log(1 + \text{pps})$$

$$\text{total\_bytes\_log} = \log(1 + \text{bytes})$$

El uso de $\log(1 + x)$ en lugar de $\log(x)$ garantiza que ventanas con cero paquetes (periodos de silencio) produzcan 0.0 en lugar de $-\infty$.

### 5.2 Ratios de Composición

Los ratios de protocolo y de flags TCP normalizan los conteos brutos por el número de paquetes de la ventana, produciendo valores en $[0.0, 1.0]$ que representan la **composición del tráfico** independientemente del volumen:

$$r_{\text{protocol}} = \frac{\text{count\_protocol}}{\text{pps}}$$

$$r_{\text{flag}} = \frac{\text{count\_flag}}{\text{pps}}$$

$$r_{\text{port\_scan}} = \frac{\text{unique\_dst\_ports}}{\text{pps}}$$

Estos ratios son tratados como **invariantes de escala** en la fase de estandarización: se aplica una transformación identidad en lugar de RobustScaler, preservando su interpretación probabilística directa. Un `flag_syn_ratio = 0.95` significa que el 95% de los paquetes de esa ventana llevan el flag SYN activo — una firma inequívoca de SYN flood.

### 5.3 Dimensiones Físicas Avanzadas (v2.1.0 — v2.2.0)

#### 5.3.1 Flow Duration

Duración temporal real del tráfico observado dentro de la ventana de agregación:

$$\text{flow\_duration} = \max(\text{timestamp}) - \min(\text{timestamp})$$

con un piso de $10^{-6}$ segundos para ventanas de paquete único (evita división por cero en cálculos posteriores sin introducir un cero que propague `NaN` tras transformaciones logarítmicas).

**Interpretación física:** Duraciones cortas con PPS alto indican ráfagas; duraciones largas con PPS bajo son la firma cinemática de ataques lentos como Slowloris.

#### 5.3.2 Payload Continuity

Media de bytes de payload de transporte por paquete dentro de la ventana:

$$\text{payload\_continuity} = \frac{\sum \text{payload\_bytes}}{\text{pps}}$$

**Interpretación física:** Valores cercanos a cero indican tráfico de cabeceras puras — SYN floods, ACK storms, port scans. Valores elevados señalan transferencia de datos o exfiltración.

#### 5.3.3 IAT Mean (Inter-Arrival Time)

Tiempo medio entre la llegada de paquetes consecutivos dentro de la ventana, derivado analíticamente sin almacenar listas de timestamps por paquete:

$$\text{iat\_mean} = \frac{\text{flow\_duration}}{\max(\text{pps}, 2) - 1}$$

El denominador se recorta en 2 (no en 1) para que ventanas de paquete único produzcan `iat_mean = flow_duration` — el límite superior conservador físicamente correcto, ya que un único paquete no tiene tiempo entre llegadas.

**Interpretación física:** IAT bajo y regular → flooding sistemático. IAT alto e irregular → beaconing encubierto o tráfico de reconocimiento.

#### 5.3.4 Payload Continuity Ratio (PCR) — Asimetría L7

Ratio entre el payload de respuesta y el de solicitud, cuantificando la asimetría bidireccional del tráfico a nivel de capa de aplicación:

$$\text{PCR} = \frac{\sum \text{res\_payload}}{\sum \text{req\_payload} + 10^{-6}}$$

El término $10^{-6}$ en el denominador evita la división por cero en ventanas donde no se detectó tráfico outbound. Un valor $\text{PCR} \gg 1$ indica que el servidor está respondiendo con significativamente más datos de los que el cliente solicita — patrón característico de amplificación de tráfico o exfiltración de datos. Un valor $\text{PCR} \approx 1$ indica comunicación bidireccional balanceada. Este feature alcanzó desviaciones de **4120σ** durante el ataque DoS GoldenEye en la validación CIC-IDS2017.

### 5.4 Cinemática de Tráfico: Velocidad, Aceleración y Volatilidad

Una vez las ventanas están ordenadas cronológicamente, el pipeline calcula las **derivadas temporales** de las métricas de intensidad, tratando la serie temporal de ventanas como una señal física:

**Primera derivada (Velocidad):** Tasa de cambio instante a instante.

$$v_{\text{pps}}[t] = \text{total\_pps\_log}[t] - \text{total\_pps\_log}[t-1]$$

**Segunda derivada (Aceleración):** Tasa de cambio de la velocidad — detecta la fase de onset de un ataque volumétrico antes de que el volumen absoluto supere umbrales.

$$a_{\text{pps}}[t] = v_{\text{pps}}[t] - v_{\text{pps}}[t-1]$$

**Volatilidad (Desviación estándar rodante):** Medida de irregularidad de la señal en una ventana de 5 segundos.

$$\sigma_{\text{pps}}[t] = \text{std}\left(\text{total\_pps\_log}[t-4..t]\right)$$

**Momentum (Contador de ráfagas):** Suma rodante de eventos de ráfaga — ventanas donde el PPS supera 1.5 veces la media rodante de 10 ventanas:

$$\text{pps\_momentum}[t] = \sum_{i=t-4}^{t} \mathbf{1}\left[\text{pps\_log}[i] > 1.5 \cdot \overline{\text{pps\_log}}_{10}[i]\right]$$

### 5.5 Z-Score Dinámico: Detección de Régimen de Tráfico (v2.3.0)

Los features de Hilbert-Space son efectivos para detectar anomalías absolutas respecto al baseline estacionario. Sin embargo, en escenarios donde la magnitud de un ataque es similar a la del tráfico normal (ataques de bajo volumen sostenido), la separación geométrica puede ser insuficiente. Los Z-scores dinámicos sobre ventana rodante de 60 segundos resuelven esta limitación detectando **cambios de régimen relativos**:

$$Z_{\text{pps}}[t] = \frac{\text{total\_pps\_log}[t] - \mu_{60}[t]}{\sigma_{60}[t] + 10^{-6}}$$

$$Z_{\text{bytes}}[t] = \frac{\text{total\_bytes\_log}[t] - \mu_{60}[t]}{\sigma_{60}[t] + 10^{-6}}$$

$$Z_{\text{syn}}[t] = \frac{\text{flag\_syn\_ratio}[t] - \mu_{60}[t]}{\sigma_{60}[t] + 10^{-6}}$$

donde $\mu_{60}$ y $\sigma_{60}$ son la media y desviación estándar rodantes sobre las últimas 60 ventanas de 1 segundo. El término $10^{-6}$ en el denominador previene la inestabilidad numérica en periodos de señal constante.

Valores positivos indican un incremento repentino respecto al régimen reciente (onset de ataque); valores negativos indican un decremento (declive o recuperación post-ataque). Estos features alimentan directamente el **Velocity Bypass Detector (Tier 4)** del motor de HiGI.

---

## 6. Fase 4 — Estandarización y Contrato de Inferencia

### 6.1 Estrategia de Escalado Híbrido

El método `get_standardized_matrix()` aplica una estrategia de escalado diferenciada a través de un `ColumnTransformer` de scikit-learn ejecutado en paralelo (`n_jobs=self.n_jobs`):

| Categoría de Feature | Escalado Aplicado | Justificación |
|---|---|---|
| Columnas `*_ratio` | `FunctionTransformer` (identidad) | Ya normalizadas en $[0.0, 1.0]$ por construcción |
| Resto de columnas numéricas | `RobustScaler` | Resistente a outliers extremos de ataques DoS |

El `RobustScaler` centra por mediana y escala por rango intercuartílico (IQR), en lugar de media y desviación estándar. Esto es crítico en el contexto de IDS: una ráfaga de ataque de 857σ en `bytes` no debe desplazar el centro del escalador durante el entrenamiento del baseline.

### 6.2 Saneamiento de Datos Pre-Escaldo

Antes del escalado, el pipeline aplica un ciclo de saneamiento numérico:

```
1. Sustitución de Inf y -Inf → NaN
2. Sustitución de NaN → 0.0
3. Filtrado de columnas no numéricas (select_dtypes)
```

El conteo de valores Inf reemplazados se registra en el log de operaciones para auditoría. Este saneamiento previene explosiones numéricas en el `PowerTransformer` de Yeo-Johnson que aplica `higi_engine.py` en la capa siguiente.

### 6.3 Separación de Columnas de Metadata

Las columnas `_abs_timestamp` y `server_port` son extraídas antes del escalado y **no son reincorporadas** al DataFrame de salida. Este es un contrato arquitectural explícito (v2.2.0): el motor `higi_engine.py` fue entrenado sobre features sin metadata, y la reintroducción de estos campos rompería la dimensionalidad esperada del modelo. La reincorporación es responsabilidad exclusiva del orquestador (`orchestrator.py`), que mantiene la metadata por separado para el mapeo forense posterior.

### 6.4 Persistencia del Artefacto de Escalado

En modo de entrenamiento (baseline), el `ColumnTransformer` entrenado se serializa con `joblib`:

```
models/scalers/{scaler_type}_{export_name}.pkl
```

En modo de inferencia (detección), se carga el artefacto serializado y se invoca únicamente `.transform()` — nunca `.fit_transform()`. Este contrato garantiza que los parámetros del escalador (mediana, IQR) sean los del tráfico de referencia y no se contaminen con el tráfico bajo análisis.

---

## 7. Optimización de Recursos y Paralelismo

### 7.1 Arquitectura de Concurrencia

El pipeline utiliza `ProcessPoolExecutor` (no `ThreadPoolExecutor`) para la fase de parsing de paquetes. La razón es el **GIL** (Global Interpreter Lock) de CPython: las operaciones de parsing con `dpkt` y los cálculos NumPy de entropía liberan el GIL ocasionalmente, pero no lo suficiente para obtener paralelismo real con threads. Los procesos independientes tienen espacios de memoria separados y ejecutan con paralelismo verdadero en CPUs multi-core.

La función `_process_batch()` se pasa a los workers mediante `functools.partial` — la única forma de serializar (pickle) una función con argumentos adicionales (`iana_map`, `first_timestamp`) para `ProcessPoolExecutor`.

### 7.2 Gestión Activa de Memoria

```python
del chunks      # Libera la lista de chunks tras la concatenación
gc.collect()    # Fuerza la recolección de basura inmediatamente
```

Tras concatenar los chunks en un único DataFrame Polars, la lista de chunks es eliminada explícitamente y el garbage collector se invoca de forma manual. En capturas de varias horas con millones de paquetes, esta operación puede recuperar cientos de megabytes de RAM antes de la fase de agregación.

### 7.3 Evaluación Lazy en Polars

La cadena completa de `_build_base_matrix()` — desde el `group_by` hasta los Z-scores dinámicos — es una única expresión `LazyFrame` que no ejecuta ninguna operación hasta el `.collect()` final. El optimizador de Polars:

- **Funde** operaciones consecutivas que podrían combinarse en un único pass sobre los datos
- **Elimina** columnas intermedias que no se utilizan en pasos posteriores
- **Paraleliza** subárboles independientes del plan de ejecución en los cores disponibles

El resultado es un consumo de memoria significativamente inferior al equivalente en Pandas, donde cada `.assign()` o `.transform()` materializa una copia del DataFrame.

---

## 8. Robustez y Manejo de Errores

### 8.1 Jerarquía de Excepciones

El módulo define una jerarquía de excepciones específica del dominio:

```
PcapProcessorError (base)
├── InvalidPcapPathError    — archivo no encontrado, no accesible, corrupto
└── ProtocolMappingError    — fallo en inicialización del mapa IANA
```

Estas excepciones son capturadas y re-lanzadas en el orquestador con contexto adicional, proporcionando mensajes de error trazables hasta la operación específica que falló.

### 8.2 Soporte Multi-Datalink

El generador `_batch_generator()` detecta el tipo de capa de enlace del PCAP antes de iniciar la iteración:

| Tipo Datalink | Constante dpkt | Tratamiento |
|---|---|---|
| Ethernet (IEEE 802.3) | `DLT_EN10MB` | Parse de trama Ethernet → extracción IP |
| Linux SLL (cooked capture) | `DLT_LINUX_SLL` | Parse de cabecera SLL → extracción IP |
| Raw IP | `DLT_RAW` | Parse directo como `dpkt.ip.IP` |
| Desconocido | — | Intento genérico de parse IP; skip si falla |

Esta detección garantiza que capturas generadas con `tcpdump` en Linux (`-i any`, que produce Linux SLL) sean procesadas correctamente sin intervención del analista.

### 8.3 Filtrado de Paquetes Inválidos

Los paquetes se descartan silenciosamente (incrementando `skipped_count`) en los siguientes casos:

- Longitud de payload IP inferior a 20 bytes (mínimo del header IP)
- `dpkt.UnpackError` durante el parse — paquete malformado o truncado
- `AttributeError` / `TypeError` — estructura de capas inesperada (e.g., túneles, fragmentación)
- Cualquier excepción no capturada en el procesamiento individual del paquete

El conteo final de paquetes procesados vs. descartados se registra al término del generador. Una tasa de descarte superior al 5% debe alertar al analista sobre posible corrupción del PCAP o capturas incompletas.

### 8.4 Paquetes Fuera de Secuencia

Los paquetes procesados en paralelo pueden llegar al DataFrame final fuera del orden cronológico de captura. El `sort("timestamp")` post-concatenación (§3.4) restaura el orden correcto con garantías de estabilidad para timestamps iguales (Polars garantiza estabilidad en `sort` por defecto). Las operaciones de derivada (`diff()`) y ventana rodante (`rolling_std`, `rolling_mean`) son correctas únicamente sobre series temporalmente ordenadas — por eso el sort es declarado como operación obligatoria en los comentarios del código.

---

## 9. Validación de Integridad: Capture Health Report

El método `get_capture_health_report()` genera un informe de diagnóstico sobre la calidad de la captura antes de alimentar la Feature Matrix al motor de detección. Valida cuatro dimensiones de integridad:

### 9.1 Momentos Estadísticos

Se calculan la asimetría (*skewness*) y curtosis (*kurtosis*) de la distribución de PPS y entropía:

$$\text{skewness} = \frac{E\left[(X-\mu)^3\right]}{\sigma^3}, \quad \text{kurtosis} = \frac{E\left[(X-\mu)^4\right]}{\sigma^4} - 3$$

Una curtosis alta en PPS ($\kappa \gg 3$, distribución leptocúrtica) indica presencia de eventos extremos — ráfagas de tráfico o ataques volumétricos. Una asimetría positiva en entropía sugiere que la mayoría del tráfico tiene baja entropía con eventos ocasionales de alta entropía (e.g., tráfico cifrado o comprimido).

### 9.2 Continuidad Temporal

```python
time_diffs = np.diff(dataframe["timestamp"].values)
max_gap_sec = float(time_diffs.max())
```

El gap máximo entre timestamps consecutivos detecta **Data Drops** — pérdidas de paquetes en la captura, típicamente causadas por saturación del buffer del adaptador de red durante ataques de alta intensidad. Un gap superior al umbral `forensic.data_drop_threshold_seconds` (60s en la configuración estándar) se etiqueta como Data Drop en el informe forense.

### 9.3 Validación de Límites Físicos de Entropía

La entropía de Shannon de un payload de bytes tiene rango físicamente acotado:

$$H \in [0.0, 8.0] \text{ bits}$$

Cualquier valor fuera de este rango es una violación de los límites físicos del modelo — síntoma de un error en el parsing del payload o de datos corruptos. El informe cuenta estas violaciones (`entropy_violations`) como indicador de salud del pipeline.

### 9.4 Ventanas Silenciosas

Porcentaje de ventanas de 1 segundo con PPS = 0:

$$\text{silent\_pct} = \frac{\#\{w : \text{pps}[w] = 0\}}{N_{\text{ventanas}}} \times 100$$

Un porcentaje elevado de ventanas silenciosas indica una captura esporádica o un sensor con baja tasa de muestreo efectivo. Valores superiores al 30% deben ser considerados al interpretar anomalías basadas en velocidad y momentum.

---

## 10. Inventario Completo de Features

La siguiente tabla documenta todas las features producidas por `_build_base_matrix()` y su clasificación dentro del pipeline HiGI.

### 10.1 Features de Intensidad

| Feature | Fórmula | Familia HiGI | Escalado |
|---|---|---|---|
| `total_pps_log` | $\log(1 + \text{pps})$ | Volume | RobustScaler |
| `total_bytes_log` | $\log(1 + \text{bytes})$ | Volume | RobustScaler |
| `bytes` | $\sum \text{size}$ | Volume | RobustScaler |
| `size_max` | $\max(\text{size})$ | Volume | RobustScaler |

### 10.2 Features de Composición (Ratios)

| Feature | Fórmula | Familia HiGI | Escalado |
|---|---|---|---|
| `{protocol}_ratio` | $\text{count\_proto} / \text{pps}$ | Protocol | Identidad |
| `flag_syn_ratio` | $\text{count\_syn} / \text{pps}$ | Flags | Identidad |
| `flag_ack_ratio` | $\text{count\_ack} / \text{pps}$ | Flags | Identidad |
| `flag_fin_ratio` | $\text{count\_fin} / \text{pps}$ | Flags | Identidad |
| `flag_rst_ratio` | $\text{count\_rst} / \text{pps}$ | Flags | Identidad |
| `flag_psh_ratio` | $\text{count\_psh} / \text{pps}$ | Flags | Identidad |
| `flag_urg_ratio` | $\text{count\_urg} / \text{pps}$ | Flags | Identidad |
| `port_scan_ratio` | $\text{unique\_dst\_ports} / \text{pps}$ | Connection | Identidad |
| `burst_factor` | $\text{size\_max} / \text{size\_avg}$ | Volume | RobustScaler |

### 10.3 Dimensiones Físicas Avanzadas

| Feature | Fórmula | Familia HiGI | Escalado |
|---|---|---|---|
| `flow_duration` | $\max(ts) - \min(ts)$, floor $10^{-6}$ | Connection | RobustScaler |
| `payload_continuity` | $\sum \text{payload\_bytes} / \text{pps}$ | Payload | RobustScaler |
| `iat_mean` | $\text{flow\_duration} / (\max(\text{pps},2) - 1)$ | Connection | RobustScaler |
| `payload_continuity_ratio` | $\sum \text{res\_payload} / (\sum \text{req\_payload} + 10^{-6})$ | Payload | RobustScaler |
| `entropy_avg` | $\overline{H(\text{payload})}$ | Payload | RobustScaler |
| `unique_dst_ports` | $\|\text{dst\_port}\|_{\text{distinct}}$ | Connection | RobustScaler |

### 10.4 Features Cinemáticos

| Feature | Fórmula | Familia HiGI | Escalado |
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

### 10.5 Features de Detección de Régimen (v2.3.0)

| Feature | Fórmula | Tier HiGI | Escalado |
|---|---|---|---|
| `vel_pps_z` | $(\text{pps\_log} - \mu_{60}) / (\sigma_{60} + 10^{-6})$ | Tier 4 (Velocity Bypass) | RobustScaler |
| `vel_bytes_z` | $(\text{bytes\_log} - \mu_{60}) / (\sigma_{60} + 10^{-6})$ | Tier 4 (Velocity Bypass) | RobustScaler |
| `vel_syn_z` | $(\text{syn\_ratio} - \mu_{60}) / (\sigma_{60} + 10^{-6})$ | Tier 4 (Velocity Bypass) | RobustScaler |

### 10.6 Columnas de Metadata (No Escaladas)

| Columna | Descripción | Responsable |
|---|---|---|
| `_abs_timestamp` | Timestamp UNIX absoluto del primer paquete de la ventana | `orchestrator.py` |
| `server_port` | Puerto de servicio identificado en la ventana | `orchestrator.py` |

---

*HiGI IDS — Unidad de Inteligencia de Red. 2026.*  
*Documento generado a partir del análisis estático de [`src/ingestion/processor_optime.py`](/src/ingestion/processor_optime.py) v2.3.0.*  
*Para la descripción del motor de detección downstream, consultar [`docs/reference/esp/engine_documentation.md`](/docs/esp/Higi_manual.md).*
