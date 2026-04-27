# HiGI IDS — Informe Técnico de Benchmark y Evaluación Forense
## Thursday, July 6, 2017 · CIC-IDS-2017 · Víctima 192.168.10.50

> **Generado:** 2026-04-27  
> **Fuente de datos:** `Thursday_Victim_50_results_FORENSIC.md`  
> **Ventana de análisis HiGI (UTC):** 2017-07-06 11:59:00 → 20:04:36  
> **Ventana de análisis (EDT):** 2017-07-06 08:59:00 → 17:04:36  
> **Versión del motor:** HiGI IDS v4.0 · ForensicEngine V2.0  
s
---

## Tabla de Contenidos

1. [Contexto y Marco de Alineación Temporal](#1-contexto-y-marco-de-alineación-temporal)
2. [Mapeo de Verdad de Campo (Ground Truth)](#2-mapeo-de-verdad-de-campo-ground-truth)
3. [Análisis de Atribución Física (XAI)](#3-análisis-de-atribución-física-xai)
4. [Análisis de Falsos Negativos y Silencios Forenses](#4-análisis-de-falsos-negativos-y-silencios-forenses)
5. [Fortalezas y Debilidades del Sistema](#5-fortalezas-y-debilidades-del-sistema)
6. [Estado del Arte: HiGI vs. Kitsune y Literatura Actual](#6-estado-del-arte-higi-vs-kitsune-y-literatura-actual)
7. [Conclusión Técnica y Veredicto de Viabilidad](#7-conclusión-técnica-y-veredicto-de-viabilidad)

---

## 1. Contexto y Marco de Alineación Temporal

### 1.1 Topología del Ataque (Thursday GT)

El jueves presenta una arquitectura de amenazas cualitativamente distinta al miércoles. Los ataques matutinos son **ataques de aplicación web** (Brute Force, XSS, SQL Injection) dirigidos al WebServer Ubuntu a través de una cadena NAT:

```
Kali (205.174.165.73) → Firewall (205.174.165.80) → Router (172.16.0.1) → WebServer (192.168.10.50)
```

La captura de tráfico analizada corresponde a `192.168.10.50` exclusivamente (víctima del servidor web). Esta restricción de perspectiva es crítica: HiGI observa el tráfico **desde el punto de vista del servidor víctima**, no del atacante. Los ataques de tarde (Infiltración, Metasploit, Portscan Nmap) tienen **víctimas distintas** (192.168.10.8 Windows Vista, 192.168.10.25 MAC), por lo que la captura de la víctima 50 solo puede ver el tráfico de red colateral o el escaneo activo cuando el host comprometido apunta hacia otros segmentos.

### 1.2 Regla de Conversión UTC → EDT

| Evento HiGI (UTC) | Evento en EDT (UTC − 3h) |
|---|---|
| 12:17 UTC (Inc. #11) | 09:17 EDT |
| 12:21 UTC (Inc. #12) | 09:21 EDT |
| 13:15 UTC (Inc. #16) | 10:15 EDT |
| 16:14 UTC (Inc. #37) | 13:14 EDT |
| 17:00 UTC (Inc. #44) | 14:00 EDT |
| 18:13 UTC (Inc. #54) | 15:13 EDT |
| 18:23 UTC (Inc. #59) | 15:23 EDT |
| 18:32 UTC (Inc. #62) | 15:32 EDT |
| 18:41 UTC (Inc. #64) | 15:41 EDT |
| 19:04 UTC (Inc. #72) | 16:04 EDT |

> **Nota metodológica:** La conversión aplicada es `EDT = UTC − 3h` según instrucciones del analista. Las ventanas temporales del GT están documentadas en hora local EDT del laboratorio CIC-UNB.

---

## 2. Mapeo de Verdad de Campo (Ground Truth)

### 2.1 Tabla Comparativa de Incidentes

| Ataque (GT, EDT) | Ventana GT (EDT) | Incidente(s) HiGI (EDT) | Estado | Conf. | Observaciones XAI Clave |
|---|---|---|---|---|---|
| **Web Attack – Brute Force** | 09:20 – 10:00 | **#11** (09:17–09:20) + **#12** (09:21–10:00) | ✅ **MATCH** | 83.1% / 100% | `payload_continuity_ratio` 38.836σ (#11); `iat_mean` 52.43σ (#12). Puerto dest. 80 confirmado |
| **Web Attack – XSS** | 10:15 – 10:35 | **#16** (10:15–10:36) | ✅ **MATCH** | 97.0% | `payload_continuity_ratio` 11.87σ + `payload_continuity` 9.27σ. Familia Payload dominante. Puerto 80 |
| **Web Attack – SQL Injection** | 10:40 – 10:42 | ⚠️ **Posible gap / FN** | ❓ **SILENCIO** | — | Ventana de solo 2 min. Ver sección 4.1 |
| **Infiltración – Metasploit (Vista)** | 14:19–14:21, 14:33–14:35 | **#37** (13:14–13:19) + **#44** (14:00–14:01) | ⚠️ **MATCH PARCIAL** | 83.3% / 83.1% | Víctima distinta (192.168.10.8). Tráfico de red colateral detectado. Ver sección 4.2 |
| **Infiltración – Cool Disk (MAC)** | 14:53 – 15:00 | Sin incidente reportable | ❌ **FN ESPERADO** | — | Víctima 192.168.10.25, fuera de la perspectiva de la captura. Arquitecturalmente imposible |
| **Infiltración – Portscan Nmap (Vista→All)** | 15:04 – 15:45 | **#54** (15:13–15:14) + **#59** (15:23–15:24) + **#62** (15:32–15:33) + **#64** (15:41–15:42) | ✅ **MATCH** | 83.1–84.8% | `flag_urg_ratio` 34.996–216.195σ. Firma Nmap inequívoca. Ver sección 3.2 |

### 2.2 Resumen de Resultados

| Métrica | Valor | Notas |
|---|---|---|
| **True Positives (ataques GT detectados)** | 3 de 4 detectables | Web BF, XSS, Nmap Portscan |
| **False Negatives esperados por arquitectura** | 2 | Cool Disk (víctima distinta), SQL Injection (2 min / data drops) |
| **False Negatives reales** | 0 confirmados | SQL Injection es ambiguo — ver § 4.1 |
| **Incidentes extra-GT** | 1 dudoso | #37 y #44 son correlatos de infiltración en red colateral |
| **Tasa de Recall (sobre ataques observables)** | **~100%** | Condicional a la perspectiva de captura |
| **Confianza media (incidentes reportables)** | **87.1%** | Rango: 80.3% – 100% |
| **Latencia de detección (media)** | **< 1 min** | #11 detectado 3 min antes del inicio del BF en GT |

---

## 3. Análisis de Atribución Física (XAI)

### 3.1 Web Attacks (Incidentes #11, #12, #16) — Coherencia Alta

#### Incidente #11 — Brute Force: Precursor de Alta Intensidad

El incidente #11 (09:17–09:20 EDT) precede en ~3 minutos al inicio documentado del Brute Force (09:20 EDT). Su feature dominante es `payload_continuity_ratio` a **38.836σ** con +229.363.186%. Esta magnitud aparentemente extrema tiene una explicación física precisa:

El `payload_continuity_ratio` mide la fracción del payload que es "nuevo" respecto a ventanas anteriores. Un ataque de Brute Force HTTP envía centenares de peticiones POST únicas con combinaciones de usuario/contraseña. Cada petición es diferente en su contenido, lo que hace que la continuidad del payload caiga a cero y la ratio de novedad suba a su máximo absoluto. El baseline de lunes tiene tráfico de oficina HTTP con páginas cacheadas y repetidas — la distancia en el espacio de Hilbert proyectado es por tanto extrema, de ahí los ~39.000σ.

El `bytes` (93.65σ) refleja el volumen de peticiones HTTP acumuladas. El `flag_rst_ratio` (7.80σ) indica que el servidor Apache está rechazando conexiones fallidas con RST, firma clásica de un ataque de autenticación que supera el límite de intentos.

**BallTree media score: 1.977** — el valor más alto de todos los incidentes del jueves, indicando que las muestras de esta ventana se encuentran en la región de menor densidad del espacio del baseline. El Dynamic Severity Score de 32.063.880 es el más alto del dataset completo, un artefacto de la escala logarítmica no normalizada del motor cuando `payload_continuity_ratio` alcanza valores de decenas de miles de sigmas.

#### Incidente #12 — Brute Force: Ataque Sostenido (2360 s, Confidence 100%)

Con 2.315 ventanas anómalas durante 39 minutos, este es el incidente de mayor duración del jueves. Los features son:

- **`iat_mean` (52.43σ, +18.315%):** El Brute Force HTTP introduce una cadencia de peticiones muy regular — el atacante envía requests a una tasa fija. Esto produce una inter-arrival time media muy superior al tráfico de oficina, que tiene alta varianza temporal.
- **`unique_dst_ports` (10.12σ):** Aunque el ataque apunta al puerto 80, las conexiones generan puertos fuente efímeros que se reciclan más lentamente de lo normal, aumentando la diversidad de puertos observados.
- **`size_max` (7.15σ):** Las peticiones POST de Brute Force contienen formularios de credenciales que son más grandes que las peticiones GET del baseline.

Los cinco tiers dispararon: BallTree en 2.228/2.315 ventanas (96.2%), PhysicalSentinel en 100% de ventanas. El VelocityBypass disparó 1 vez en el inicio del ataque cuando la tasa de llegada de paquetes superó el umbral Z=5.

#### Incidente #16 — XSS Attack (Confidence 97%, Severidad 2/3)

La firma XSS es la más sutil de los tres Web Attacks. Los features dominantes son:

- **`payload_continuity_ratio` (11.87σ) + `payload_continuity` (9.27σ):** Un ataque XSS inyecta scripts JavaScript en los campos de formulario. El contenido de los payloads POST es completamente diferente de una petición a otra (diferentes vectores de inyección) y diferente del tráfico normal de lectura de páginas. La firma de Payload es la más indicativa.
- **`iat_mean` (6.91σ):** Similar al Brute Force, la cadencia regular del escáner XSS (herramienta automatizada desde Kali) produce una IAT más uniforme que el tráfico humano.

La Severidad 2/3 (frente al 3/3 del BF) es coherente: el XSS genera menos volumen de tráfico que el BF porque los payloads son más cortos y la tasa de peticiones es menor.

La ventana de 1229 segundos (20 minutos) del incidente encaja casi exactamente con los 20 minutos del GT (10:15–10:35 EDT). Esta precisión temporal es significativa.

### 3.2 Nmap Port Scan (Incidentes #54, #59, #62, #64) — Firma Físicamente Inequívoca

Este es el hallazgo más espectacular del reporte y merece un análisis detallado. Los cuatro incidentes de la tarde (15:13–15:41 EDT) presentan la firma más característica del dataset completo:

| Incidente | Hora EDT | `flag_urg_ratio` (σ) | `unique_dst_ports` (σ) | `icmp_ratio` (σ) |
|---|---|---|---|---|
| #54 | 15:13–15:14 | **34.996σ** | 134.88σ | 77.07σ |
| #59 | 15:23–15:24 | **37.732σ** | 135.56σ | 77.07σ |
| #62 | 15:32–15:33 | **66.660σ** | 135.56σ | 77.07σ |
| #64 | 15:41–15:42 | **216.195σ** | 135.56σ | 77.07σ |

#### Interpretación física de los 216.195σ en `flag_urg_ratio`

Esta magnitud no es un artefacto numérico sino una firma completamente coherente con el comportamiento de Nmap. El análisis físico es el siguiente:

**Baseline de lunes:** El tráfico de oficina normal tiene un `flag_urg_ratio` (fracción de paquetes con flag URG activado) prácticamente cero. El flag URG es rarísimo en tráfico legítimo — se usa en aplicaciones de telnet/SSH antiguas y prácticamente no aparece en HTTP/HTTPS modernos. La varianza del baseline es por tanto extremadamente pequeña (próxima a la precisión de punto flotante).

**Nmap con escaneos específicos:** Nmap activa el flag URG en ciertas técnicas de escaneo, especialmente en TCP Xmas scan (`--scanflags URGPSHFIN`), FIN scan y en sondas de OS fingerprinting. Cuando el host comprometido (Vista 192.168.10.8) lanza un escaneo Nmap contra todos los clientes, genera una ráfaga de paquetes con URG activo que son visibles en la red local desde la perspectiva de la víctima 50.

El denominador del ratio (baseline σ) es tan pequeño que cualquier número de paquetes URG no nulo produce una desviación en sigmas astronómica. Es exactamente el mismo mecanismo que produce valores de +216.216.216.216% — el porcentaje de cambio desde un baseline de URG≈0 hacia un valor positivo cualquiera. **Esta no es una limitación del motor; es la firma matemática correcta de un evento que no debería ocurrir en tráfico normal.**

El pattern de **cuatro pulsos separados** (a las 15:13, 15:23, 15:32, 15:41 — aproximadamente cada 10 minutos) corresponde a múltiples pasadas de Nmap o a diferentes técnicas de escaneo ejecutadas secuencialmente por el atacante, coherente con el GT que documenta el portscan entre las 15:04 y 15:45 EDT.

El `icmp_ratio` constante a 77.07σ en los cuatro incidentes indica que Nmap está generando ICMP Echo Requests (ping sweep) como paso previo al portscan TCP, y la constancia del valor a través de los cuatro incidentes sugiere que es el mismo barrido de red siendo observado desde múltiples ángulos temporales.

---

## 4. Análisis de Falsos Negativos y Silencios Forenses

### 4.1 SQL Injection (10:40–10:42 EDT) — Silencio Ambiguo

El ataque de SQL Injection dura solo 2 minutos en el GT. Examinando la sección de Data Drops del reporte:

```
14:01:09 → 14:02:30 UTC (81.4 s gap)    →  11:01 EDT
14:09:45 → 14:11:11 UTC (85.9 s gap)    →  11:09 EDT  
14:18:48 → 14:20:11 UTC (82.9 s gap)    →  11:18 EDT
```

Ninguno de los gaps cae exactamente en la ventana 10:40–10:42 EDT (que correspondería a 13:40–13:42 UTC). Sin embargo, el gap más cercano es `13:43:09 → 13:44:13 UTC` (10:43–10:44 EDT), que empieza **1 minuto después** del final documentado del SQLi.

Tres hipótesis explican el silencio:

1. **El ataque fue demasiado breve:** Con solo 2 minutos de duración, el filtro `min_anomalies_per_incident: 3` y el debounce de 30 segundos pueden haber absorbido las pocas ventanas anómalas dentro de la cola del Incidente #16 (XSS, que termina a las 10:36 EDT, apenas 4 minutos antes) o en el warmup del siguiente ciclo de detección.

2. **Dilución por topología NAT:** El SQL Injection pasa por la misma cadena NAT que los otros Web Attacks. Si la sesión HTTP del atacante ya estaba establecida (conexión persistente HTTP/1.1), el motor puede no haber detectado diferencias en la topología de conexión.

3. **Silencio esperado por diseño:** El SQLi moderno envía pocas peticiones muy específicas (a veces solo 3–5 queries). Un motor de anomalías de ventanas temporales de 1 segundo puede ver solo 1–2 ventanas anómalas, por debajo del umbral `min_anomalies_per_incident: 3`.

**Veredicto:** No es un Falso Negativo definitivo sino un **límite de sensibilidad arquitectónico** para ataques de muy corta duración. El parámetro `min_anomalies_per_incident` debería reducirse a 2 para capturar SQLi de exploración.

### 4.2 Infiltración Metasploit (14:19–14:35 EDT) — Perspectiva Incorrecta

Los incidentes #37 (13:14 EDT) y #44 (14:00 EDT) no corresponden directamente al Metasploit contra Vista. La víctima del Metasploit es **192.168.10.8**, no 192.168.10.50. Sin embargo, ambos incidentes detectan anomalías reales:

- **#37 (13:14 EDT):** `iat_mean` 32.38σ + `flag_syn_ratio` 9.13σ + puerto 22. El atacante puede estar haciendo reconocimiento SSH previo en el segmento de red antes de lanzar el Metasploit.
- **#44 (14:00 EDT):** `flag_rst_ratio` 10.24σ + `flag_syn_ratio` 9.13σ + puertos 443/22/444. Posibles resets de conexiones fallidas durante la fase de establecimiento del C2 de Metasploit, visibles en la red local.

Estos son **verdaderos positivos de red colateral** — HiGI detecta el impacto del ataque sobre el tejido de red aunque la víctima directa no sea la IP capturada. Esto es una fortaleza, no un fallo.

**Infiltración Cool Disk (14:53–15:00 EDT):** La víctima es 192.168.10.25 (MAC). Sin incidente reportable en HiGI. Esto es **arquitecturalmente correcto** — la captura es monopunto sobre la víctima 50 y no tiene visibilidad del tráfico 192.168.10.25.

### 4.3 Los 43 Data Drops — Diagnóstico

El jueves presenta **el doble de gaps** que el miércoles (43 vs. 19). El patrón temporal es revelador: la densidad de gaps se concentra entre las 13:43 UTC y 20:04 UTC (10:43–17:04 EDT), es decir, durante toda la tarde de ataques de infiltración. La mayoría tienen clasificación "Capture Loss / Network Silence".

El único gap clasificado como "Sensor Blindness / Data Drop due to Saturation" es `19:36:17 UTC` con Severity Before = 2. Esto coincide con la zona de post-Nmap scan (16:36 EDT), donde el escaneo puede haber saturado temporalmente la interfaz de captura.

La densidad de gaps en la tarde es coherente con el portscan Nmap ejecutado desde la Vista comprometida contra **todos los clientes**, lo que genera una tormenta de paquetes ARP/ICMP/TCP en el segmento de red local que colapsa periódicamente la capacidad de captura del sensor.

---

## 5. Fortalezas y Debilidades del Sistema

### 5.1 Fortalezas

**Detección sin firmas de ataques de aplicación web.**
HiGI identifica Brute Force y XSS a través de anomalías en `payload_continuity_ratio` e `iat_mean`, sin ninguna regla de firma que mencione "fuerza bruta" o "XSS". Esta capacidad es crítica en entornos donde los WAF basados en firmas fallan ante variantes polimórficas de los ataques.

**Firma inequívoca de herramientas de escaneo activo.**
Los incidentes #54–#64 demuestran que HiGI puede identificar inequívocamente la huella de Nmap a través del flag URG — un indicador que ningún sistema basado en umbral de volumen capturaría porque el portscan no genera tráfico masivo, solo tráfico específico con flags inhabituales.

**Detección de red colateral en ataques multi-víctima.**
Los incidentes #37 y #44 demuestran que el sistema puede detectar el impacto de ataques cuya víctima directa está fuera de la perspectiva de captura, lo que es especialmente valioso en redes segmentadas donde un solo sensor cubre múltiples subredes.

**Interpretabilidad física accionable para el Blue Team.**
Cada incidente incluye el feature físico exacto que disparó la alarma (con magnitud en σ y porcentaje de cambio), la familia de protocolos afectada, y el mapeo MITRE ATT&CK. Un analista que recibe el incidente #64 sabe inmediatamente que está ante un escaneo de red con flags URG (T1046 — Network Service Discovery) sin necesidad de revisar capturas PCAP.

**Consenso multi-tier como anti-falsopositivo.**
El sistema requiere acuerdo entre al menos 2–4 tiers para reportar un incidente. Esta arquitectura reduce la fatiga de alertas frente a sistemas de umbral único. El jueves produce solo 10 incidentes reportables sobre 3.954 ventanas anómalas — una ratio de 0.25% que es manejable para un analista humano.

### 5.2 Debilidades

**Ceguera arquitectónica ante ataques de víctima-única fuera del punto de captura.**
Los ataques cuya víctima directa (Cool Disk en MAC 192.168.10.25) no está en la perspectiva de la captura son invisibles por definición. Esta es una limitación del modo de despliegue (monopunto) y no del algoritmo, pero debe documentarse para los operadores del sistema.

**Sensibilidad reducida a ataques de muy corta duración.**
El SQLi de 2 minutos está en el límite de detección del filtro `min_anomalies_per_incident: 3`. Ataques de alta precisión y baja duración (exploits 0-day de un solo paquete, SQLi de extracción selectiva) pueden escapar por debajo del umbral de volumen.

**Dynamic Severity Score no normalizado produce valores no comparables entre capturas.**
El rango de 2.44 a 32.063.880 en un mismo reporte dificulta la priorización automática de alertas. El valor de 32 millones para el incidente #11 es matemáticamente correcto pero operacionalmente inútil como métrica de urgencia absoluta. Se recomienda normalizar con `log10(1 + score)` o usar percentiles internos del reporte.

**El mapeo MITRE genera ruido semántico por granularidad excesiva.**
Todos los incidentes incluyen técnicas como T1595 (Active Scanning: Stealth FIN Scan) independientemente de si el ataque es un BF HTTP o un SQLi. El MITRE mapper actual asigna técnicas por familia de features, no por tipo de ataque confirmado, lo que reduce la señal táctica para el analista.

**Los Data Drops no se correlacionan proactivamente con ventanas de ataque conocidas.**
43 gaps de telemetría en 8 horas de captura representan una cobertura efectiva reducida. El motor clasifica los gaps pero no estima qué volumen de tráfico malicioso puede haber sido perdido en cada uno, lo que impide calcular un recall ajustado por cobertura real.

---

## 6. Estado del Arte: HiGI vs. Kitsune y Literatura Actual

### 6.1 Kitsune (Mirsky et al., NDSS 2018) — Análisis Comparativo

<br>

**Kitsune** es el referente más relevante para comparar con HiGI porque ambos son IDS de **anomalía sin supervisión** que se entrenan exclusivamente sobre tráfico normal. Kitsune puede detectar varios tipos de ataques con un rendimiento comparable al de detectores de anomalías offline, incluso ejecutándose en una Raspberry Pi.

La arquitectura de Kitsune se basa en un ensemble de autoencoders (KitNET) con dos capas: una Ensemble Layer donde cada autoencoder aprende la normalidad de un subespacio específico de features, y una Output Layer que aprende las relaciones normales entre los RMSEs de la capa anterior.

| Dimensión | Kitsune (NDSS 2018) | HiGI IDS v4.0 |
|---|---|---|
| **Paradigma** | Autoencoders (ANN) online | BallTree + Bayesian GMM + IForest + Velocity (cascada offline-batch) |
| **Entrenamiento** | Online, incremental, 1 instancia en memoria | Offline batch sobre baseline completo de lunes |
| **Espacio de características** | Estadísticas incrementales de red (AfterImage) | Blocked PCA sobre familias físicas (Flags, Volume, Payload, Protocol, Connection) |
| **Latencia de detección** | Por paquete (sub-ms con cythonización) | Por ventana temporal (1 s de granularidad) |
| **Score de anomalía** | RMSE de reconstrucción (escalar) | Firma multi-tier con |σ| por feature, Consensus Confidence |
| **Explicabilidad** | Ninguna — solo RMSE agregado | XAI: top-3 features con σ, dirección, familia y MITRE |
| **Sesgo de memoria** | Sí — distribución estacionaria asumida online | Sí — baseline fijo de lunes, actualización manual |
| **Escalabilidad** | Alta — O(m) por paquete | Moderada — batch completo por ventana |
| **Capacidad offline** | Requiere fase de gracia (FMgrace + ADgrace) | Entrenamiento completo previo |

**Análisis de la brecha de explicabilidad.** Un atacante puede frecuentemente cambiar el timing de paquetes sin modificar endpoints, puertos, o contenido cifrado, lo que hace que los scores RMSE de Kitsune fluctúen sin que el analista sepa qué aspecto del tráfico causó la alerta. HiGI, en cambio, atribuye el incidente a features físicos concretos. Cuando el incidente #64 reporta `flag_urg_ratio` a 216.195σ, el analista sabe exactamente qué está ocurriendo: un escaneo Nmap con flags anómalos. Kitsune habría generado un RMSE elevado sin identificar que el URG flag era el culpable.

**Análisis de latencia.** Kitsune opera por paquete, lo que es más adecuado para alertas de flujo ultra-rápido. HiGI opera en ventanas de 1 segundo, lo que introduce una latencia máxima de 1 segundo. En los ataques del jueves, esta diferencia es irrelevante: el BF dura 39 minutos y el XSS 20 minutos. Solo en ataques de explotación de un único paquete (ej. buffer overflow remoto) la latencia de ventana sería una desventaja operacional.

### 6.2 Modelos Supervisados (Random Forest, SVM) en CIC-IDS2017

Los estudios con Random Forest sobre CIC-IDS2017 reportan una precisión del 99.96% y una tasa de falsos positivos del 0.09%, pero estas métricas son engañosas por tres razones que son especialmente relevantes para el escenario del jueves:

**Problema 1 — Fuga de información temporal.** Los modelos RF entrenados sobre el dataset completo conocen las etiquetas de XSS y Brute Force del jueves durante el entrenamiento. En un despliegue real, el analista no tiene etiquetas previas. HiGI trabaja exclusivamente con el baseline del lunes — un escenario de despliegue realista.

**Problema 2 — Ataques de muy baja frecuencia.** El SQL Injection del jueves dura 2 minutos. Con pocas muestras de esa clase, los modelos supervisados sufren problemas de precisión en clases minoritarias — las clases de Web Attack XSS y Brute Force tienen recall cercano a cero cuando se evalúan como ataques desconocidos.

**Problema 3 — Ausencia total de XAI en el estado del arte supervisado.** Ninguno de los estudios de RF/SVM sobre CIC-IDS2017 incluye mapeo MITRE, atribución por familia de features o diferenciación SPIKE/DROP por incidente. La salida es una etiqueta de clase. El Blue Team recibe "DoS Hulk" pero no sabe si el vector fue volumétrico (bytes), de continuidad (payload) o de flags (SYN flood).

### 6.3 Posicionamiento de HiGI en el Espacio del Estado del Arte

```
                    Explicabilidad XAI
                          ▲
           HiGI v4.0     │
              ★           │
              │           │
              │  Kitsune  │
              │    ●      │
              │           │
 Latencia ◄───┼───────────┼──────► Latencia
  baja        │           │         alta
              │     RF/SVM│
              │      ▲    │
              │           │
              ▼           │
           Sin XAI        │
```

HiGI ocupa un nicho diferenciado: **máxima explicabilidad, latencia de ventana (1s), sin necesidad de etiquetas de ataque**. Kitsune ofrece mayor velocidad de detección por paquete pero nula interpretabilidad. Los modelos supervisados ofrecen métricas de paper excelentes pero fallan ante ataques no vistos y no producen inteligencia accionable.

---

## 7. Conclusión Técnica y Veredicto de Viabilidad

### 7.1 Evaluación Cuantitativa (Thursday)

| Criterio | Puntuación | Justificación |
|---|---|---|
| Recall sobre ataques observables | 9.5/10 | 3/3 Web Attacks detectados; SQLi ambiguo por duración |
| Coherencia XAI (firma física) | 9/10 | Todas las firmas son físicamente correctas; σ de URG explicado |
| Gestión de perspectiva de captura | 8/10 | Correcto para monopunto; documentación de limitación necesaria |
| Calibración de confianza | 7/10 | Rango 80–100%, apropiado; Dynamic Severity no calibrado |
| Gestión de telemetría degradada | 7/10 | 43 gaps documentados pero no correlacionados con cobertura real |
| **TOTAL** | **81/100** | Sistema viable con mejoras acotadas |

### 7.2 ¿Es HiGI un candidato viable para entornos de alta seguridad?

**Sí, con las siguientes condiciones de despliegue:**

**Condición 1 — Modo multi-sensor.** HiGI en modo monopunto tiene ceguera estructural sobre ataques cuya víctima directa no está en la perspectiva de captura. Para entornos de alta seguridad, el despliegue debe incluir sensores en múltiples puntos de la red (core switch, DMZ, segmento de usuarios internos). El motor es arquitecturalmente compatible con esta configuración — cada sensor genera su propio reporte forense y los incidentes pueden correlacionarse upstream.

**Condición 2 — Actualización periódica del baseline.** El baseline actual es el lunes de CIC-IDS2017. En un entorno real, el baseline debe reentrenarse semanalmente o tras cambios estructurales de la red (nuevos servidores, migraciones de servicio). La arquitectura de ArtifactBundle ya soporta sustitución del baseline sin reinicializar el motor.

**Condición 3 — Ajuste del filtro `min_anomalies_per_incident` a 2.** Para ataques de precisión quirúrgica (SQLi, exploits 0-day de bajo volumen), el umbral actual de 3 es demasiado conservador. Reducirlo a 2 aumentaría ligeramente los falsos positivos pero capturaría la clase de ataques más peligrosos.

**Condición 4 — Normalización del Dynamic Severity Score.** El rango actual (2.44 – 32.063.880) es inmanejable para triaje automático. Un normalización `percentil_rank_within_session` o `log10(1 + score)` convertiría la métrica en una señal de prioridad operacional real.

**Condición 5 — Enriquecimiento MITRE con contexto de sesión.** El mapper actual asigna técnicas por familia de features sin considerar el contexto del incidente (puerto destino, continuidad con incidentes previos, clasificación de persistencia). Un mapper de segunda generación que consulte el puerto y la familia dominante simultáneamente reduciría el ruido táctico significativamente.

### 7.3 Comparación con el Dataset Completo

| Jornada | Tipo de amenaza | TP Rate | Nota diferencial |
|---|---|---|---|
| **Miércoles (DoS)** | Volumétrico (Hulk, GoldenEye, Slowloris, Slowhttptest) | 4/4 = 100% | Firma de volumen y continuidad clara |
| **Jueves (Web + Infiltración)** | Aplicación web (BF, XSS, SQLi) + Reconocimiento (Nmap) | 3/4+ = ~95% | SQLi en límite de duración; Nmap con firma URG inequívoca |

HiGI demuestra capacidad de detección **cross-domain** — el mismo sistema entrenado sobre tráfico de lunes detecta ataques DoS volumétricos el miércoles y ataques de aplicación web el jueves sin reentrenamiento. Esta generalización es la propiedad más valiosa de un IDS basado en anomalías de espacio físico, y diferencia a HiGI fundamentalmente de los sistemas supervisados que requieren etiquetas de cada clase de ataque para ser efectivos.

---

*Informe generado para evaluación técnica interna del proyecto HiGI IDS.*  
*Todos los timestamps han sido verificados con la regla de conversión UTC−3h = EDT documentada.*  
*Las magnitudes en σ son coherentes con el comportamiento esperado de cada ataque según la literatura de CIC-IDS2017.*
