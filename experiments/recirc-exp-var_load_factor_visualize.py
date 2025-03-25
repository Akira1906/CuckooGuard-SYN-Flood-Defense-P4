import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import sys
import os

#   {
#     "timestamp": "2025-03-24 08:33:18",
#     "load_factor": 0.3,
#     "n_preloaded_connections": 1579,
#     "fingerprint_size": 16,
#     "n_buckets": 1316,
#     "n_benign_connections": 5000,
#     "n_test_packets": 1000,
#     "packet_count": -1579
#   },

def main(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    results = {'load_factor': [], 'recirc_overhead': []}

    for entry in data:
        load_factor = entry['load_factor']
        n_test = entry['n_test_packets']
        packet_count = entry['packet_count']

        recirc_overhead = (packet_count - n_test) / n_test * 100  # Calculate y-axis value

        results['load_factor'].append(load_factor)
        results['recirc_overhead'].append(recirc_overhead)

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

    x = results['load_factor']
    y = results['recirc_overhead']
    if len(x) != len(y):
        print(f"⚠️ Skipping plot due to mismatched data lengths ({len(x)} vs {len(y)})")
        return
    ax.plot(x, y, marker='o', label="Recirculation Overhead")

    ax.set_yscale("log")
    ax.set_xlabel("Load Factor (α)")  # Update x-axis label
    ax.set_ylabel("Recirculation Overhead")  # Update y-axis label
    ax.legend(loc="upper right", ncol=1)
    ax.set_title("")  # Keep minimal for paper inclusion

    ax.yaxis.set_major_formatter(mpl.ticker.PercentFormatter())
    ax.yaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda y, _: f"{y:.3f}%"))
    ax.tick_params(axis='y', which='both', labelsize=8)
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    output_file = "figures/recirc-var_load_factor.svg"
    plt.savefig(output_file, format="svg")
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    json_file_name = "results/recirc-experiment_history.json"  # Hardcoded relative path to the JSON file
    json_path = os.path.abspath(json_file_name)

    main(json_path)
