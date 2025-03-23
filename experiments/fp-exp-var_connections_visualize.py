import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import sys
import os

import numpy as np

#   {
#     "timestamp": "2025-03-23 16:30:01",
#     "available_memory_bit": 100000,
#     "n_benign_connections": 4000,
#     "n_hostile_test_packets": 10000,
#     "bloom_part_2": {
#       "size_bits": 50000,
#       "fp_hits": 0,
#       "fp_rate": 0
#     },
#     "bloom_part_3": {
#       "size_bits": 33333,
#       "fp_hits": 0,
#       "fp_rate": 0
#     },
#     "bloom_std": {
#       "size_bits": 100000,
#       "fp_hits": 0,
#       "fp_rate": 0
#     },
#     "varbloom": {
#       "size_bits": 100000,
#       "fp_hits": 0,
#       "fp_rate": 0
#     },
#     "varbloom_time_decay": {
#       "size_bits": 50000,
#       "fp_hits": 9,
#       "fp_rate": 0.0009
#     },
#     "cuckoo": {
#       "fingerprint_size": 23,
#       "n_buckets": 1086,
#       "n_fingerprints": 4344,
#       "fp_hits": 0,
#       "fp_rate": 0,
#       "fp_rate_ss": 0
#     }
#   },

def main(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    results = {}

    for entry in data:
        n_connections = entry['n_benign_connections']  # Extract number of connections
        n_hostile = entry['n_hostile_test_packets']

        for key, value in entry.items():
            if isinstance(value, dict) and 'fp_hits' in value:
                fp_hits = value['fp_hits']
                fp_rate = fp_hits / n_hostile * 100 # in percent

                if key not in results:
                    results[key] = {'connections': [], 'fp_rate': []}

                results[key]['connections'].append(n_connections)  # Use connections instead of memory
                results[key]['fp_rate'].append(fp_rate)

    # === IEEE-style Plot Configuration ===
    mpl.rcParams.update({
        "figure.figsize": (6, 3.2),            # Inches: typical for IEEE 1-col or 2-col layout
        "font.size": 9,                        # Slightly smaller than default
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans"],
        "axes.grid": True,
        "axes.edgecolor": "#444444",
        "axes.linewidth": 0.8,
        "lines.linewidth": 1.2,
        "lines.markersize": 4,
        "legend.frameon": False,
        "legend.fontsize": 8,
        "xtick.direction": "in",
        "ytick.direction": "in",
        "pdf.fonttype": 42,                    # Editable fonts in PDF
        "svg.fonttype": "none"                 # Editable fonts in SVG
    })

    fig, ax = plt.subplots()

    for filter_type, values in results.items():
        if filter_type in ['bloom_part_2', 'bloom_std', 'bloom_part_3', 'varbloom_time_decay']:
            continue
        connections = values['connections']
        fpr = values['fp_rate']
        if len(connections) != len(fpr):
            print(f"⚠️ Skipping '{filter_type}' due to mismatched data lengths ({len(connections)} vs {len(fpr)})")
            continue
        ax.plot(connections, fpr, marker='o', label=filter_type)

    ax.set_yscale("log")  # Set y-axis to logarithmic scale
    ax.yaxis.set_major_formatter(mpl.ticker.PercentFormatter())
    ax.yaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda y, _: f"{y:.5f}%"))
    ax.tick_params(axis='y', which='both', labelsize=8)
    ax.set_xlabel("Number of Connections")  # Update x-axis label
    ax.set_ylabel("False Positive Rate")
    ax.legend(loc="upper right", ncol=1)
    ax.set_ylim(bottom=0.0001)  # Adjust bottom limit for log scale
    ax.set_title("")  # Keep minimal for paper inclusion

    fig.tight_layout()
    output_file = "false_positive_rates.svg"
    plt.savefig(output_file, format="svg")
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python plot_fp_rates.py path/to/results.json")
        sys.exit(1)

    json_path = sys.argv[1]
    if not os.path.exists(json_path):
        print(f"Error: File '{json_path}' not found.")
        sys.exit(1)

    main(json_path)
