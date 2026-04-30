"""
Figure 2: Physics-Based Attack Fingerprint Atlas (Powered by HiGI Forensic Engine)
Protocolo: Sincronización Temporal Forense (EDT to UTC +3h) y Mapeo Completo.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import LogNorm, LinearSegmentedColormap

# Configuración de Path para encontrar 'src'
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, "../../../"))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.analysis.forensic_engine import HiGIForensicEngine as ForensicEngine

# =============================================================================
# DICCIONARIO DE ATAQUES (Horas EDT convertidas a UTC +3h)
# =============================================================================
def to_utc_custom(date_str, time_str):
    """Convierte la hora del reporte (EDT) al UTC del motor (Offset +3h)."""
    dt_edt = pd.to_datetime(f"{date_str} {time_str}")
    # Ajuste solicitado: 3 horas de desfase
    dt_utc = dt_edt + pd.Timedelta(hours=3)
    return dt_utc.tz_localize('UTC')

ATTACK_WINDOWS = {
    'MON: Control':     {'file': 'Monday_Victim_50_results.csv',    'start': to_utc_custom('2017-07-03', '09:00'), 'end': to_utc_custom('2017-07-03', '17:00')},
    'WED: Recon':       {'file': 'Wednesday_Victim_50_results.csv', 'start': to_utc_custom('2017-07-05', '09:20'), 'end': to_utc_custom('2017-07-05', '09:40')},
    'WED: Slowloris':   {'file': 'Wednesday_Victim_50_results.csv', 'start': to_utc_custom('2017-07-05', '09:47'), 'end': to_utc_custom('2017-07-05', '10:11')},
    'WED: Slowhttp':    {'file': 'Wednesday_Victim_50_results.csv', 'start': to_utc_custom('2017-07-05', '10:14'), 'end': to_utc_custom('2017-07-05', '10:35')},
    'WED: Hulk':        {'file': 'Wednesday_Victim_50_results.csv', 'start': to_utc_custom('2017-07-05', '10:43'), 'end': to_utc_custom('2017-07-05', '11:00')},
    'WED: GoldenEye':   {'file': 'Wednesday_Victim_50_results.csv', 'start': to_utc_custom('2017-07-05', '11:10'), 'end': to_utc_custom('2017-07-05', '11:23')},
    'THU: BruteForce':  {'file': 'Thursday_Victim_50_results.csv',  'start': to_utc_custom('2017-07-06', '09:17'), 'end': to_utc_custom('2017-07-06', '10:00')},
    'THU: XSS':         {'file': 'Thursday_Victim_50_results.csv',  'start': to_utc_custom('2017-07-06', '10:15'), 'end': to_utc_custom('2017-07-06', '10:36')},
    'THU: Nmap':        {'file': 'Thursday_Victim_50_results.csv',  'start': to_utc_custom('2017-07-06', '15:04'), 'end': to_utc_custom('2017-07-06', '15:45')}
}

def get_higi_atlas_data(settings):
    data_dir = os.path.join(project_root, "data/processed")
    families = ['connection', 'flags', 'payload', 'protocol', 'kinematics', 'volume']
    matrix = np.full((len(families), len(ATTACK_WINDOWS)), 0.1)

    for col_idx, (label, win) in enumerate(ATTACK_WINDOWS.items()):
        file_path = os.path.join(data_dir, win['file'])
        if not os.path.exists(file_path):
            continue

        engine = ForensicEngine(settings=settings, results_path=file_path)
        engine.cluster_incidents()
        incidents = engine.get_reportable_incidents()
        
        for inc in incidents:
            # Forzamos localización UTC para evitar el TypeError de comparación
            t_start = inc.start_time.tz_localize('UTC') if inc.start_time.tzinfo is None else inc.start_time
            t_end = inc.end_time.tz_localize('UTC') if inc.end_time.tzinfo is None else inc.end_time

            # Filtro de ventana temporal (Strict UTC)
            if not (t_end < win['start'] or t_start > win['end']):
                for feat in inc.top_features:
                    fam = feat.family.lower()
                    if fam in families:
                        row_idx = families.index(fam)
                        matrix[row_idx, col_idx] = max(matrix[row_idx, col_idx], feat.max_sigma)

    return matrix, list(ATTACK_WINDOWS.keys()), families

def plot_physics_atlas(matrix, attacks, families):
    """Renderizado con estética de publicación científica."""
    colors = ["#0d1117", "#30363d", "#f1c40f", "#e67e22", "#e74c3c"]
    higi_cmap = LinearSegmentedColormap.from_list("higi_fire", colors, N=256)

    fig, ax = plt.subplots(figsize=(14, 8), dpi=300)

    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")
    
    yticklabels = [f.capitalize() for f in families]
    xticklabels = [a.replace(': ', ':\n') for a in attacks]

    sns.heatmap(
        matrix,
        xticklabels=xticklabels,
        yticklabels=yticklabels,
        annot=True,
        fmt=".1f",
        norm=LogNorm(vmin=0.1, vmax=max(matrix.max(), 100.0)),
        cmap=higi_cmap,
        linewidths=0.8,
        linecolor="#21262d",
        cbar_kws={'label': 'Peak Physical Deviation |σ|'},
        annot_kws={"size": 9, "weight": "bold", "color": "#f0f6fc"},
        ax=ax
    )

    ax.set_title('Figure 1: Physics-Based Attack Fingerprint Atlas\n(HiGI Forensic Engine - +3h UTC Sync)', 
                 fontsize=15, fontweight='bold', color="#f0f6fc", pad=20)
    
    ax.set_xlabel('Ground Truth Attack Scenario', fontweight='bold', color="#8b949e")
    ax.set_ylabel('Physical Feature Family', fontweight='bold', color="#8b949e")
    
    ax.tick_params(colors="#8b949e", which='both')

    cbar = ax.collections[0].colorbar
    cbar.ax.yaxis.set_tick_params(color='#8b949e', labelcolor='#8b949e')
    cbar.set_label('Peak Physical Deviation |σ|', color='#8b949e', fontweight='bold')
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    output_path = os.path.join(project_root, "reports/benchmarks/figures/higi_atlas_engine_validated.png")
    plt.savefig(output_path)
    print(f"✅ Heatmap generado con desfase +3h en: {output_path}")

if __name__ == "__main__":
    class Settings:
        class forensic:
            debounce_seconds = 30
            data_drop_threshold_seconds = 60
            default_confidence_filter = 0.8 
            default_min_anomalies = 3
            default_min_duration_seconds = 2.0
            sigma_culprit_min = 2.0

    sigma_matrix, attack_labels, family_labels = get_higi_atlas_data(Settings)
    plot_physics_atlas(sigma_matrix, attack_labels, family_labels)