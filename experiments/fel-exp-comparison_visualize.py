import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import os

def main():
    json_file = os.path.join(os.path.dirname(__file__), "results/fel-varbloom_results.json")  # Construct absolute path
    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found.")
        return

    with open(json_file, 'r') as f:
        data = json.load(f)

    # Parse Bloom Filter data
    results = {'time_seconds': [], 'total_elements': []}
    for entry in data:
        time_seconds = entry['timestamp_ns'] / 1e9  # Convert nanoseconds to seconds
        total_elements = entry['reg_bloom_0_size'] + entry['reg_bloom_1_size']  # Sum of Bloom filter sizes
        results['time_seconds'].append(time_seconds)
        results['total_elements'].append(total_elements)

    # Parse Cuckoo Filter data
    cuckoo_file = os.path.join(os.path.dirname(__file__), "results/fel-cuckoo_results.json")  # New JSON file
    if not os.path.exists(cuckoo_file):
        print(f"Error: File '{cuckoo_file}' not found.")
        return

    with open(cuckoo_file, 'r') as f:
        cuckoo_data = json.load(f)

    cuckoo_results = {'time_seconds': [], 'n_elements': []}
    for entry in cuckoo_data:
        time_seconds = entry['timestamp_ns'] / 1e9  # Convert nanoseconds to seconds
        n_elements = entry['n_elements']
        cuckoo_results['time_seconds'].append(time_seconds)
        cuckoo_results['n_elements'].append(n_elements)

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

    # Plot Bloom Filter data
    x = results['time_seconds']
    y = results['total_elements']
    if len(x) != len(y):
        print(f"⚠️ Skipping Bloom Filter plot due to mismatched data lengths ({len(x)} vs {len(y)})")
        return
    ax.plot(x, y, label="Total Elements in Bloom Filter")  # Removed marker='o'

    # Plot Cuckoo Filter data
    x_cuckoo = cuckoo_results['time_seconds']
    y_cuckoo = cuckoo_results['n_elements']
    if len(x_cuckoo) != len(y_cuckoo):
        print(f"⚠️ Skipping Cuckoo Filter plot due to mismatched data lengths ({len(x_cuckoo)} vs {len(y_cuckoo)})")
        return
    ax.plot(x_cuckoo, y_cuckoo, label="Total Elements in Cuckoo Filter")  # No markers

    ax.set_xlabel("Time (seconds)")  # Update x-axis label
    ax.set_ylabel("Total Elements")  # Generalized y-axis label
    ax.legend(loc="upper left", ncol=1)
    ax.set_title("")  # Keep minimal for paper inclusion

    ax.tick_params(axis='y', which='both', labelsize=8)
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    output_file = "figures/fes-comparison.svg"
    plt.savefig(output_file, format="svg")
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    main()
