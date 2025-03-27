import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import sys
import os

# import numpy np

#   {
#     "timestamp": "2025-03-23 16:30:01",
#     "available_memory_bit": 100000,
#     "n_benign_connections": 4000,
#     "n_test_packets": 10000,
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

def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)

def main(json_file):
    config_file = "figures/matplotlib_config.json"  # Path to the configuration file
    config = load_config(config_file)

    with open(json_file, 'r') as f:
        data = json.load(f)

    results = {}

    for entry in data:
        n_connections = entry['n_benign_connections']  # Extract number of connections
        n_test = entry['n_test_packets']

        for key, value in entry.items():
            if isinstance(value, dict) and 'fp_hits' in value:
                fp_hits = value['fp_hits']
                fp_rate = fp_hits / n_test * 100  # in percent

                if key not in results:
                    results[key] = {'connections': [], 'fp_rate': []}

                results[key]['connections'].append(n_connections)  # Use connections instead of memory
                results[key]['fp_rate'].append(fp_rate)

    # === Apply Matplotlib Configuration from JSON ===
    mpl.rcParams.update({
        "figure.figsize": tuple(config["matplotlib_config"]["figure"]["figsize"]),
        "font.size": config["matplotlib_config"]["font"]["size"],
        "font.family": config["matplotlib_config"]["font"]["family"],
        "font.sans-serif": config["matplotlib_config"]["font"]["sans-serif"],
        "axes.grid": config["matplotlib_config"]["axes"]["grid"],
        "axes.edgecolor": config["matplotlib_config"]["axes"]["edgecolor"],
        "axes.linewidth": config["matplotlib_config"]["axes"]["linewidth"],
        "lines.linewidth": config["matplotlib_config"]["lines"]["linewidth"],
        "lines.markersize": config["matplotlib_config"]["lines"]["markersize"],
        "legend.frameon": config["matplotlib_config"]["legend"]["frameon"],
        "legend.fontsize": config["matplotlib_config"]["legend"]["fontsize"],
        "xtick.direction": config["matplotlib_config"]["ticks"]["xtick_direction"],
        "ytick.direction": config["matplotlib_config"]["ticks"]["ytick_direction"],
        "pdf.fonttype": config["matplotlib_config"]["output"]["pdf_fonttype"],
        "svg.fonttype": config["matplotlib_config"]["output"]["svg_fonttype"]
    })

    filter_colors = config["filter_colors"]
    filter_styles = config.get("filter_styles", {})

    # Use figure dimensions from the configuration
    fig_width = config["figure_dimensions"]["width"]
    fig_height = config["figure_dimensions"]["height"]
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))

    bloom_filters = ["bloom_part_3", "varbloom", "varbloom_time_decay"]
    cuckoo_filters = ["cuckoo", "cuckoo_var_load"]

    ordered_keys = bloom_filters + cuckoo_filters
    for filter_type, values in sorted(
        results.items(),
        key=lambda x: ordered_keys.index(x[0]) if x[0] in ordered_keys else len(ordered_keys)
    ):
        if filter_type in ['bloom_part_2', 'bloom_std']:
            continue
        connections = values['connections']
        fpr = values['fp_rate']
        if len(connections) != len(fpr):
            print(f"⚠️ Skipping '{filter_type}' due to mismatched data lengths ({len(connections)} vs {len(fpr)})")
            continue
        color = filter_colors.get(filter_type, "#000000")  # Default to black if filter_type not in filter_colors
        style = filter_styles.get(filter_type, {"linestyle": (0, (1, 1)), "marker": "o"})  # Default style
        name = config.get("graph_names", {}).get(filter_type, filter_type)  # Use graph name or default to key
        ax.plot(connections, fpr, label=name, color=color, linestyle=tuple(style["linestyle"]), marker=style["marker"])

    ax.set_yscale("log")  # Set y-axis to logarithmic scale
    ax.yaxis.set_major_formatter(mpl.ticker.PercentFormatter())
    ax.yaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda y, _: f"{y:.4f}%"))
    ax.tick_params(axis='y', which='both', labelsize=8)
    ax.set_xlabel("Number of Connections")  # Update x-axis label
    ax.set_ylabel("False Positive Rate")
    
    ax.set_xlim(left=min(min(values['connections']) for values in results.values() if values['connections']),
                right=max(max(values['connections']) for values in results.values() if values['connections']))  # Adjust x-axis limits

    
    if "bbox_to_anchor" in config["matplotlib_config"]["legend"]:
        ax.legend(
            loc=config["matplotlib_config"]["legend"]["loc"],
            bbox_to_anchor=config["matplotlib_config"]["legend"]["bbox_to_anchor"],
            ncol=config["matplotlib_config"]["legend"].get("ncol", 1),
            columnspacing=config["matplotlib_config"]["legend"].get("column_spacing", 0.5),
            handletextpad=config["matplotlib_config"]["legend"].get("handletextpad", 0.3)
        )
    else:
        ax.legend(
            loc=config["matplotlib_config"]["legend"]["loc"],
            ncol=config["matplotlib_config"]["legend"].get("ncol", 1),
            columnspacing=config["matplotlib_config"]["legend"].get("column_spacing", 0.5),
            handletextpad=config["matplotlib_config"]["legend"].get("handletextpad", 0.3)
        )
    ax.set_ylim(bottom=0.0001)  # Adjust bottom limit for log scale
    ax.set_title("")  # Keep minimal for paper inclusion

    fig.tight_layout()
    output_file = "figures/fp-var_connections.svg"
    plt.savefig(output_file, format="svg")
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    json_file_name = "results/fp-var_connections.json"  # Hardcoded relative path to the JSON file
    json_path = os.path.abspath(json_file_name)

    main(json_path)
