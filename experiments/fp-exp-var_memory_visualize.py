import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import sys
import os

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

def load_config(config_path):
    with open(config_path, 'r') as f:
        return json.load(f)

def main(json_file, config_file):
    config = load_config(config_file)
    # print(config)
    mpl_config = config["matplotlib_config"]
    filter_colors = config["filter_colors"]
    filter_styles = config.get("filter_styles", {})

    # Apply matplotlib configuration
    mpl.rcParams.update({
        "figure.figsize": (config["figure_dimensions"]["width"], config["figure_dimensions"]["height"]),
        "font.size": mpl_config["font"]["size"],
        "font.family": mpl_config["font"]["family"],
        "font.sans-serif": mpl_config["font"]["sans-serif"],
        "axes.grid": mpl_config["axes"]["grid"],
        "axes.edgecolor": mpl_config["axes"]["edgecolor"],
        "axes.linewidth": mpl_config["axes"]["linewidth"],
        "lines.linewidth": mpl_config["lines"]["linewidth"],
        "lines.markersize": mpl_config["lines"]["markersize"],
        "legend.frameon": mpl_config["legend"]["frameon"],
        "legend.fontsize": mpl_config["legend"]["fontsize"],
        "xtick.direction": mpl_config["ticks"]["xtick_direction"],
        "ytick.direction": mpl_config["ticks"]["ytick_direction"],
        "pdf.fonttype": mpl_config["output"]["pdf_fonttype"],
        "svg.fonttype": mpl_config["output"]["svg_fonttype"]
    })

    with open(json_file, 'r') as f:
        data = json.load(f)

    results = {}

    for entry in data:
        memory_bits = entry['available_memory_bit']
        n_test = entry['n_test_packets']

        for key, value in entry.items():
            if isinstance(value, dict) and 'fp_hits' in value:
                fp_hits = value['fp_hits']
                fp_rate = fp_hits / n_test * 100

                if key not in results:
                    results[key] = {'memory': [], 'fp_rate': []}

                results[key]['memory'].append(memory_bits)
                results[key]['fp_rate'].append(fp_rate)

    fig, ax = plt.subplots()

    bloom_filters = ["bloom_part_3", "varbloom", "varbloom_time_decay"]
    cuckoo_filters = ["cuckoo", "cuckoo_var_load"]

    ordered_keys = bloom_filters + cuckoo_filters
    for filter_type, values in sorted(
        results.items(),
        key=lambda x: ordered_keys.index(x[0]) if x[0] in ordered_keys else len(ordered_keys)
    ):
        if filter_type in ['bloom_part_2', 'bloom_std']:
            continue
        mem = values['memory']
        fpr = values['fp_rate']
        if len(mem) != len(fpr):
            print(f"⚠️ Skipping '{filter_type}' due to mismatched data lengths ({len(mem)} vs {len(fpr)})")
            continue
        color = filter_colors.get(filter_type, "#000000")  # Default to black if filter type not in dict
        style = filter_styles.get(filter_type, {"linestyle": (0, (1, 1)), "marker": "o"})  # Default style
        name = config.get("graph_names", {}).get(filter_type, filter_type)  # Use graph name or default to key
        if 'bloom' in filter_type:
            ax.plot(mem, fpr, label=name, color=color, linestyle=tuple(style["linestyle"]), marker=style["marker"])
        else:
            ax.step(mem, fpr, label=f"{name}", color=color, where='post', linestyle=tuple(style["linestyle"]), marker=style["marker"])

    ax.set_yscale("log")  # Set y-axis to logarithmic scale
    ax.yaxis.set_major_formatter(mpl.ticker.PercentFormatter())
    ax.yaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda y, _: f"{y:.3f}%"))
    ax.tick_params(axis='y', which='both', labelsize=mpl_config["font"]["size"])

    ax.set_xlabel("Available Memory (bits)")
    ax.set_ylabel("False Positive Rate")
    ax.set_xlim(left=min(min(values['memory']) for values in results.values() if values['memory']),
                right=max(max(values['memory']) for values in results.values() if values['memory']))  # Adjust x-axis limits

    if "bbox_to_anchor" in config["matplotlib_config"]["legend"]:
        ax.legend(
            loc=config["matplotlib_config"]["legend"]["loc"],
            bbox_to_anchor=mpl_config["legend"]["bbox_to_anchor"],
            ncol=config["matplotlib_config"]["legend"].get("ncol", 1),
            columnspacing=mpl_config["legend"].get("column_spacing", 0.5),
            handletextpad=mpl_config["legend"].get("handletextpad", 0.3)
        )
    else:
        ax.legend(
            loc=config["matplotlib_config"]["legend"]["loc"],
            ncol=config["matplotlib_config"]["legend"].get("ncol", 1),
            columnspacing=config["matplotlib_config"]["legend"].get("column_spacing", 0.5),
            handletextpad=config["matplotlib_config"]["legend"].get("handletextpad", 0.3)
        )
    ax.set_ylim(bottom=0.001)  # Adjust bottom limit for log scale
    ax.set_title("")  # Keep minimal for paper inclusion

    fig.tight_layout()
    output_file = "figures/fp-var_memory.svg"
    plt.savefig(output_file, format="svg", transparent=False, bbox_inches='tight', pad_inches=0)
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    json_file_name = "results/fp-var_memory.json"  # Hardcoded relative path to the JSON file
    config_file_name = "figures/matplotlib_config.json"  # Path to the configuration file
    json_path = os.path.abspath(json_file_name)
    config_path = os.path.abspath(config_file_name)

    main(json_path, config_path)
