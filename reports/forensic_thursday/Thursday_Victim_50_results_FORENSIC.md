# HiGI IDS — Forensic Security Incident Report

> **Generated:** 2026-04-28 08:15:36 UTC  
> **Source file:** `Thursday_Victim_50_results.csv`  
> **Analysis window:** 2017-07-06 11:59:00 → 2017-07-06 20:04:36

## Analysis Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Incident debounce | 30 s | Maximum gap for grouping consecutive anomalies |
| Data-drop threshold | 60 s | Gap size flagged as sensor blindness |
| Confidence filter | 80% | Minimum tier-weighted confidence for reporting |
| Min anomalies/incident | 1 | Alert-fatigue suppression floor |
| Min duration | 1.0 s | Minimum incident duration |
| Min σ culprit | 2.0 | Minimum mean \|σ\| to include in report |

## Executive Summary

- **Total anomalous windows detected:** 3,700
- **Reportable incidents after filtering:** 6
- **Maximum severity:** 3/3 (Critical — Full unanimity)
- **Average severity:** 1.23/3
- **Average incident duration:** 634.5 s
- **Telemetry data-drops detected:** 43

## Physical Family Stress Distribution

| Family | Anomaly Count | Share | Interpretation |
|--------|--------------|-------|----------------|
| **Volume** | 1,122 | 30.3% | Bandwidth/PPS overload — volumetric DoS or data exfiltration |
| **Payload** | 1,085 | 29.3% | Payload anomaly — obfuscation, encryption or protocol tunnelling |
| **Connection** | 522 | 14.1% | Connection-topology anomaly — port-scan, service discovery |
| **Kinematics** | 391 | 10.6% | Rate/volatility anomaly — beaconing, slow-rate attack or burst |
| **Flags** | 249 | 6.7% | TCP-flag manipulation — possible SYN/RST/FIN flood or stealth scan |
| **Slow_attack** | 184 | 5.0% | – |
| **Volume_flood** | 126 | 3.4% | – |
| **Protocol** | 16 | 0.4% | Protocol-ratio shift — possible protocol abuse or evasion |
| **Recon** | 5 | 0.1% | – |

## Visual Evidence

### Figure 1 — Attack Intensity Timeline

![Attack Intensity Timeline](Thursday_Victim_50_results_timeline.png)

**Reading guide:** Coloured fill indicates severity level (yellow = Severity 1, orange = Severity 2, red = Severity 3). Teal downward triangles mark Velocity Bypass events. Callout boxes annotate the three highest-severity incidents with their primary culprit metric.

### Figure 2 — Physical Family Stress Radar

![Physical Family Stress Radar](Thursday_Victim_50_results_radar.png)

**Reading guide:** Each axis represents a physical feature family. A larger filled area indicates that family contributed more anomaly load. Dominant axes identify the primary attack vector and guide immediate countermeasure prioritisation.

## Detailed Incident Analysis

### Incident #12

| Field | Value |
|-------|-------|
| **Start (UTC)** | 2017-07-06 12:21:15 |
| **End (UTC)** | 2017-07-06 13:00:35 |
| **Duration** | 2360 s |
| **Anomalous windows** | 2253 |
| **Max severity** | 3/3 — Critical — Full unanimity |
| **Dynamic severity score** | 215.52 |
| **Consensus confidence** | 100.0% |
| **Persistence label** | Sustained Attack |
| **Top-3 destination ports** | 80, 123, 40048 |
| **Warm-up period** | No |

#### Tier Evidence

| Tier | Fired | Fire Count | Mean Score |
|------|-------|-----------|------------|
| BallTree | ✅ | 2208 | 0.9740 |
| GMM | ✅ | 139 | 0.9800 |
| IForest | ✅ | 328 | 0.2808 |
| PhysicalSentinel | ✅ | 2253 | 3.3553 |
| VelocityBypass | ✅ | 1 | 0.2178 |

#### Top-3 Physical Feature Attributions (XAI)

| Rank | Feature | Family | Event Type | Max \|σ\| | Max Δ% | Loading |
|------|---------|--------|-----------|--------|--------|---------|
| 1 | `iat_mean` | Connection | ⬆ SPIKE | 52.43σ | 18315% | 1.000 |
| 2 | `unique_dst_ports` | Volume_flood | ⬆ SPIKE | 10.12σ | 6108% | 0.193 |
| 3 | `size_max` | Payload | ⬆ SPIKE | 7.15σ | 1856% | 0.136 |

#### MITRE ATT&CK Mapping

- **Command & Control**
  - T1573 – Encrypted / Obfuscated Traffic
  - T1071 – Beaconing / Irregular IAT
- **Exfiltration**
  - T1048 – Oversized Packet Exfiltration
- **Impact**
  - T1498 – Resource Exhaustion: Bandwidth Volatility
  - T1498 – Volumetric PPS Volatility
  - T1190 – Exploit Public-Facing Application (Slow DoS)
  - T1498.001 – DoS: Direct Network Flood (SYN Flood)
  - T1499.002 – DoS: Endpoint Service (RST Flood)
  - T1498.001 – UDP Flood / Amplification
- **Reconnaissance**
  - T1046 – Network Service Discovery

### Incident #16

| Field | Value |
|-------|-------|
| **Start (UTC)** | 2017-07-06 13:15:36 |
| **End (UTC)** | 2017-07-06 13:35:52 |
| **Duration** | 1216 s |
| **Anomalous windows** | 1131 |
| **Max severity** | 2/3 — High — Majority consensus |
| **Dynamic severity score** | 9.12 |
| **Consensus confidence** | 97.0% |
| **Persistence label** | Sustained Attack |
| **Top-3 destination ports** | 80, 123, 137 |
| **Warm-up period** | No |

#### Tier Evidence

| Tier | Fired | Fire Count | Mean Score |
|------|-------|-----------|------------|
| BallTree | ✅ | 1122 | 1.4117 |
| GMM | ✅ | 419 | 0.9920 |
| IForest | ✅ | 850 | 0.4110 |
| PhysicalSentinel | ✅ | 1131 | 4.7845 |
| VelocityBypass | — | 0 | 0.2142 |

#### Top-3 Physical Feature Attributions (XAI)

| Rank | Feature | Family | Event Type | Max \|σ\| | Max Δ% | Loading |
|------|---------|--------|-----------|--------|--------|---------|
| 1 | `payload_continuity_ratio` | Payload | ⬆ SPIKE | 11.87σ | 70100% | 1.000 |
| 2 | `payload_continuity` | Payload | ⬆ SPIKE | 9.02σ | 12620% | 0.760 |
| 3 | `iat_mean` | Connection | ⬆ SPIKE | 6.91σ | 2342% | 0.582 |

#### MITRE ATT&CK Mapping

- **Reconnaissance**
  - T1595.001 – Active Scanning: IP Addresses
  - T1595 – Active Scanning (Stealth FIN Scan)
- **Command & Control**
  - T1573 – Encrypted / Obfuscated Traffic
  - T1071 – Beaconing / Irregular IAT
- **Impact**
  - T1498 – Resource Exhaustion: Bandwidth Volatility
  - T1498.001 – DoS: Direct Network Flood (SYN Flood)
  - T1190 – Exploit Public-Facing Application (Slow DoS)

### Incident #43

| Field | Value |
|-------|-------|
| **Start (UTC)** | 2017-07-06 17:00:31 |
| **End (UTC)** | 2017-07-06 17:01:12 |
| **Duration** | 40 s |
| **Anomalous windows** | 15 |
| **Max severity** | 2/3 — High — Majority consensus |
| **Dynamic severity score** | 6.86 |
| **Consensus confidence** | 80.6% |
| **Persistence label** | Sustained Attack |
| **Top-3 destination ports** | 443, 22, 444 |
| **Warm-up period** | No |

#### Tier Evidence

| Tier | Fired | Fire Count | Mean Score |
|------|-------|-----------|------------|
| BallTree | ✅ | 15 | 2.3109 |
| GMM | ✅ | 13 | 1.0000 |
| IForest | ✅ | 13 | 0.6485 |
| PhysicalSentinel | ✅ | 15 | 9.2086 |
| VelocityBypass | ✅ | 2 | 0.6057 |

#### Top-3 Physical Feature Attributions (XAI)

| Rank | Feature | Family | Event Type | Max \|σ\| | Max Δ% | Loading |
|------|---------|--------|-----------|--------|--------|---------|
| 1 | `iat_mean` | Connection | ⬆ SPIKE | 12.29σ | 4292% | 1.000 |
| 2 | `flag_rst_ratio` | Flags | ⬆ SPIKE | 10.24σ | 9081% | 0.833 |
| 3 | `flag_syn_ratio` | Flags | ⬆ SPIKE | 9.13σ | 1745% | 0.743 |

#### MITRE ATT&CK Mapping

- **Impact**
  - T1498.001 – DoS: Direct Network Flood (SYN Flood)
  - T1499.002 – DoS: Endpoint Service (RST Flood)
- **Command & Control**
  - T1071 – Beaconing / Irregular IAT
- **Exfiltration**
  - T1048 – Oversized Packet Exfiltration

### Incident #55

| Field | Value |
|-------|-------|
| **Start (UTC)** | 2017-07-06 18:13:41 |
| **End (UTC)** | 2017-07-06 18:14:55 |
| **Duration** | 74 s |
| **Anomalous windows** | 20 |
| **Max severity** | 3/3 — Critical — Full unanimity |
| **Dynamic severity score** | 759.99 |
| **Consensus confidence** | 82.1% |
| **Persistence label** | Sustained Attack |
| **Top-3 destination ports** | 45585, 445, 65389 |
| **Warm-up period** | No |

#### Tier Evidence

| Tier | Fired | Fire Count | Mean Score |
|------|-------|-----------|------------|
| BallTree | ✅ | 18 | 4.1958 |
| GMM | ✅ | 11 | 0.9000 |
| IForest | ✅ | 13 | 0.4860 |
| PhysicalSentinel | ✅ | 20 | 16.0034 |
| VelocityBypass | ✅ | 4 | 0.4507 |

#### Top-3 Physical Feature Attributions (XAI)

| Rank | Feature | Family | Event Type | Max \|σ\| | Max Δ% | Loading |
|------|---------|--------|-----------|--------|--------|---------|
| 1 | `flag_urg_ratio` | Flags | ⬆ SPIKE | 34996.50σ | 35000000000% | 1.000 |
| 2 | `unique_dst_ports` | Connection | ⬆ SPIKE | 134.88σ | 81418% | 0.004 |
| 3 | `icmp_ratio` | Protocol | ⬆ SPIKE | 77.09σ | 458585% | 0.002 |

#### MITRE ATT&CK Mapping

- **Reconnaissance**
  - T1046 – Network Service Discovery
- **Impact**
  - T1498.001 – DoS: Direct Network Flood (SYN Flood)
  - T1190 – Exploit Public-Facing Application (Slow DoS)
  - T1499.002 – DoS: Endpoint Service (RST Flood)
- **Command & Control**
  - T1573 – Encrypted / Obfuscated Traffic
- **Exfiltration**
  - T1048 – Oversized Packet Exfiltration

### Incident #60

| Field | Value |
|-------|-------|
| **Start (UTC)** | 2017-07-06 18:23:01 |
| **End (UTC)** | 2017-07-06 18:24:09 |
| **Duration** | 69 s |
| **Anomalous windows** | 25 |
| **Max severity** | 3/3 — Critical — Full unanimity |
| **Dynamic severity score** | 787.60 |
| **Consensus confidence** | 83.3% |
| **Persistence label** | Sustained Attack |
| **Top-3 destination ports** | 51700, 445, 22 |
| **Warm-up period** | No |

#### Tier Evidence

| Tier | Fired | Fire Count | Mean Score |
|------|-------|-----------|------------|
| BallTree | ✅ | 23 | 3.7391 |
| GMM | ✅ | 13 | 0.9200 |
| IForest | ✅ | 17 | 0.4453 |
| PhysicalSentinel | ✅ | 25 | 14.3471 |
| VelocityBypass | ✅ | 2 | 0.3832 |

#### Top-3 Physical Feature Attributions (XAI)

| Rank | Feature | Family | Event Type | Max \|σ\| | Max Δ% | Loading |
|------|---------|--------|-----------|--------|--------|---------|
| 1 | `flag_urg_ratio` | Flags | ⬆ SPIKE | 37732.08σ | 37735849057% | 1.000 |
| 2 | `unique_dst_ports` | Connection | ⬆ SPIKE | 135.56σ | 81826% | 0.004 |
| 3 | `icmp_ratio` | Protocol | ⬆ SPIKE | 77.09σ | 458585% | 0.002 |

#### MITRE ATT&CK Mapping

- **Reconnaissance**
  - T1046 – Network Service Discovery
  - T1595 – Active Scanning (Stealth FIN Scan)
- **Impact**
  - T1498.001 – DoS: Direct Network Flood (SYN Flood)
  - T1498 – Volumetric PPS Volatility
  - T1190 – Exploit Public-Facing Application (Slow DoS)
  - T1499.002 – DoS: Endpoint Service (RST Flood)
- **Command & Control**
  - T1573 – Encrypted / Obfuscated Traffic
  - T1071 – Beaconing / Irregular IAT

### Incident #63

| Field | Value |
|-------|-------|
| **Start (UTC)** | 2017-07-06 18:32:27 |
| **End (UTC)** | 2017-07-06 18:33:15 |
| **Duration** | 48 s |
| **Anomalous windows** | 22 |
| **Max severity** | 3/3 — Critical — Full unanimity |
| **Dynamic severity score** | 775.44 |
| **Consensus confidence** | 82.6% |
| **Persistence label** | Sustained Attack |
| **Top-3 destination ports** | 445, 53719, 65389 |
| **Warm-up period** | No |

#### Tier Evidence

| Tier | Fired | Fire Count | Mean Score |
|------|-------|-----------|------------|
| BallTree | ✅ | 22 | 4.0008 |
| GMM | ✅ | 11 | 1.0000 |
| IForest | ✅ | 13 | 0.4540 |
| PhysicalSentinel | ✅ | 22 | 14.7841 |
| VelocityBypass | ✅ | 3 | 0.4024 |

#### Top-3 Physical Feature Attributions (XAI)

| Rank | Feature | Family | Event Type | Max \|σ\| | Max Δ% | Loading |
|------|---------|--------|-----------|--------|--------|---------|
| 1 | `flag_urg_ratio` | Flags | ⬆ SPIKE | 66660.00σ | 66666666667% | 1.000 |
| 2 | `unique_dst_ports` | Connection | ⬆ SPIKE | 135.56σ | 81826% | 0.002 |
| 3 | `icmp_ratio` | Protocol | ⬆ SPIKE | 77.09σ | 458585% | 0.001 |

#### MITRE ATT&CK Mapping

- **Reconnaissance**
  - T1046 – Network Service Discovery
- **Impact**
  - T1498.001 – DoS: Direct Network Flood (SYN Flood)
  - T1499.002 – DoS: Endpoint Service (RST Flood)
  - T1190 – Exploit Public-Facing Application (Slow DoS)
  - T1498 – Resource Exhaustion: Bandwidth Volatility
- **Command & Control**
  - T1573 – Encrypted / Obfuscated Traffic
- **Exfiltration**
  - T1048 – Oversized Packet Exfiltration

## Telemetry Data Drops

| Start (UTC) | End (UTC) | Gap (s) | Severity Before | Reason |
|------------|----------|---------|----------------|--------|
| 13:43:09 | 13:44:13 | 63.7 | – | Capture Loss / Network Silence |
| 13:47:26 | 13:48:27 | 61.4 | – | Capture Loss / Network Silence |
| 14:01:09 | 14:02:30 | 81.4 | – | Capture Loss / Network Silence |
| 14:09:45 | 14:11:11 | 85.9 | – | Capture Loss / Network Silence |
| 14:18:48 | 14:20:11 | 82.9 | – | Capture Loss / Network Silence |
| 14:22:41 | 14:24:31 | 109.7 | – | Capture Loss / Network Silence |
| 14:30:05 | 14:31:15 | 70.3 | – | Capture Loss / Network Silence |
| 15:07:10 | 15:08:21 | 71.4 | – | Capture Loss / Network Silence |
| 15:11:26 | 15:12:58 | 92.2 | – | Capture Loss / Network Silence |
| 15:19:12 | 15:20:18 | 65.5 | – | Capture Loss / Network Silence |
| 15:22:04 | 15:23:08 | 63.5 | – | Capture Loss / Network Silence |
| 15:44:43 | 15:45:50 | 67.2 | – | Capture Loss / Network Silence |
| 16:04:38 | 16:06:40 | 122.1 | – | Capture Loss / Network Silence |
| 16:12:21 | 16:13:32 | 71.4 | – | Capture Loss / Network Silence |
| 16:24:53 | 16:26:45 | 112.0 | – | Capture Loss / Network Silence |
| 16:39:26 | 16:40:37 | 70.5 | – | Capture Loss / Network Silence |
| 16:45:49 | 16:46:50 | 61.2 | – | Capture Loss / Network Silence |
| 16:49:56 | 16:50:58 | 62.4 | – | Capture Loss / Network Silence |
| 17:03:46 | 17:05:20 | 94.5 | – | Capture Loss / Network Silence |
| 17:13:18 | 17:14:47 | 89.1 | – | Capture Loss / Network Silence |
| 17:39:51 | 17:40:52 | 60.8 | – | Capture Loss / Network Silence |
| 17:42:03 | 17:43:29 | 86.2 | – | Capture Loss / Network Silence |
| 17:53:03 | 17:54:19 | 76.9 | – | Capture Loss / Network Silence |
| 17:59:59 | 18:01:25 | 85.6 | – | Capture Loss / Network Silence |
| 18:15:53 | 18:16:58 | 65.6 | – | Capture Loss / Network Silence |
| 18:18:50 | 18:19:52 | 61.5 | – | Capture Loss / Network Silence |
| 18:19:52 | 18:21:07 | 75.2 | – | Capture Loss / Network Silence |
| 18:25:26 | 18:27:14 | 108.9 | – | Capture Loss / Network Silence |
| 18:33:28 | 18:35:03 | 94.5 | – | Capture Loss / Network Silence |
| 18:35:57 | 18:37:17 | 79.8 | – | Capture Loss / Network Silence |
| 18:42:45 | 18:44:10 | 85.4 | – | Capture Loss / Network Silence |
| 18:53:11 | 18:54:19 | 68.7 | – | Capture Loss / Network Silence |
| 19:00:11 | 19:01:59 | 107.8 | – | Capture Loss / Network Silence |
| 19:17:27 | 19:18:43 | 75.9 | – | Capture Loss / Network Silence |
| 19:18:46 | 19:20:01 | 75.0 | – | Capture Loss / Network Silence |
| 19:36:17 | 19:37:29 | 71.9 | 2 | Sensor Blindness / Data Drop due to Saturation |
| 19:40:42 | 19:42:29 | 107.7 | – | Capture Loss / Network Silence |
| 19:44:36 | 19:45:51 | 75.7 | – | Capture Loss / Network Silence |
| 19:50:03 | 19:51:35 | 92.3 | – | Capture Loss / Network Silence |
| 19:54:20 | 19:55:27 | 67.1 | – | Capture Loss / Network Silence |
| 19:56:00 | 19:57:27 | 87.7 | – | Capture Loss / Network Silence |
| 19:58:09 | 19:59:24 | 75.7 | – | Capture Loss / Network Silence |
| 20:02:38 | 20:04:36 | 118.5 | – | Capture Loss / Network Silence |

---

*Report generated automatically by **HiGI IDS ForensicEngine V2.0**.*  
*Consult your security team for remediation guidance.*
