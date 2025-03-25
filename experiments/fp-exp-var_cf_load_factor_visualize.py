import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import sys
import os

import numpy as np

# {
#     "timestamp": "2025-03-24 10:43:30",
#     "available_memory_bit": 84227,
#     "n_benign_connections": 5000,
#     "n_test_packets": 100000,
#     "bloom_part_2": {
#       "size_bits": 42113,
#       "fp_hits": 1253,
#       "fp_rate": 0.012533
#     },
#     "bloom_part_3": {
#       "size_bits": 28075,
#       "fp_hits": 434,
#       "fp_rate": 0.00434157
#     },
#     "bloom_std": {
#       "size_bits": 84227,
#       "fp_hits": 5763,
#       "fp_rate": 0.0576361
#     },
#     "varbloom": {
#       "size_bits": 84227,
#       "fp_hits": 30,
#       "fp_rate": 0.00030613
#     },
#     "varbloom_time_decay": {
#       "size_bits": 42113,
#       "fp_hits": 1749,
#       "fp_rate": 0.0174978
#     },
#     "cuckoo": {
#       "fingerprint_size": 16,
#       "n_buckets": 1316,
#       "n_fingerprints": 5264,
#       "fp_hits": 12,
#       "fp_rate": 0.000122022,
#       "fp_rate_ss": 6.10111e-05
#     },
#     "cuckoo_var_load": {
#       "fingerprint_size": 5,
#       "n_buckets": 4211,
#       "n_fingerprints": 16844,
#       "fp_hits": 24992,
#       "fp_rate": 0.249927,
#       "load_factor": 0.3
#     }
#   }

def main(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    results = {}

    for entry in data:
        load_factor = entry.get('cuckoo_var_load', {}).get('load_factor', 0)  # Extract load factor from cuckoo_var_load
        n_test = entry['n_test_packets']

        for key, value in entry.items():
            if isinstance(value, dict) and 'fp_hits' in value:
                fp_hits = value['fp_hits']
                fp_rate = fp_hits / n_test * 100  # Convert to percentage

                if key not in results:
                    results[key] = {'load_factor': [], 'fp_rate': []}

                results[key]['load_factor'].append(load_factor)
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
        if filter_type in ["bloom_part_2", "bloom_std"]:
            continue
        load_factors = values['load_factor']
        fpr = values['fp_rate']
        if len(load_factors) != len(fpr):
            print(f"⚠️ Skipping '{filter_type}' due to mismatched data lengths ({len(load_factors)} vs {len(fpr)})")
            continue
        ax.plot(load_factors, fpr, marker='o', label=filter_type)

    ax.set_yscale("log")  # Set y-axis to logarithmic scale
    ax.yaxis.set_major_formatter(mpl.ticker.PercentFormatter())
    ax.yaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda y, _: f"{y:.2f}%"))
    ax.tick_params(axis='y', which='both', labelsize=8)
    ax.set_xlabel("Load Factor of cuckoo_var_load")  # Update x-axis label
    ax.set_ylabel("False Positive Rate")
    ax.legend(loc="upper right", ncol=1)
    ax.set_ylim(bottom=0.01)  # Adjust bottom limit for log scale
    ax.set_title("")  # Keep minimal for paper inclusion

    fig.tight_layout()
    output_file = "figures/fp-var_cf_load_factor.svg"
    plt.savefig(output_file, format="svg")
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    
    json_file_name = "results/fp-var_cf_load_factor.json"  # Hardcoded relative path to the JSON file
    json_path = os.path.abspath(json_file_name)

    main(json_path)
