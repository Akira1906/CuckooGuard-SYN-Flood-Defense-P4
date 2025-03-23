import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import sys
import os

def main(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    results = {}

    for entry in data:
        memory_bits = entry['available_memory_bit']
        n_hostile = entry['n_hostile_test_packets']

        for key, value in entry.items():
            if isinstance(value, dict) and 'fp_hits' in value:
                fp_hits = value['fp_hits']
                fp_rate = fp_hits / n_hostile

                if key not in results:
                    results[key] = {'memory': [], 'fp_rate': []}

                results[key]['memory'].append(memory_bits)
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
        mem = values['memory']
        fpr = values['fp_rate']
        if len(mem) != len(fpr):
            print(f"⚠️ Skipping '{filter_type}' due to mismatched data lengths ({len(mem)} vs {len(fpr)})")
            continue
        ax.plot(mem, fpr, marker='o', label=filter_type)

    ax.set_yscale("log")  # Set y-axis to logarithmic scale
    ax.set_xlabel("Available Memory (bits)")
    ax.set_ylabel("False Positive Rate")
    ax.legend(loc="upper right", ncol=1)
    ax.set_ylim(bottom=0.001)  # Adjust bottom limit for log scale
    ax.set_title("")  # Keep minimal for paper inclusion

    fig.tight_layout()
    output_file = "figures/fp-var_memory.svg"
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
