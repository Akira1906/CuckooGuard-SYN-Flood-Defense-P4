import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import sys
import os

import numpy as np

def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)

def main(json_file, config_file):
    config = load_config(config_file)
    mpl_config = config.get("matplotlib_config")

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

    # === Apply Configuration from JSON ===
    mpl.rcParams.update({
        "figure.figsize": (config["figure_dimensions"]["width"], config["figure_dimensions"]["height"]),
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

    # Define static colors for each filter type
    filter_colors = config["filter_colors"]
    filter_styles = config.get("filter_styles", {})

    fig, ax = plt.subplots()

    bloom_filters = ["bloom_part_3", "varbloom", "varbloom_time_decay"]
    cuckoo_filters = ["cuckoo", "cuckoo_var_load"]

    ordered_keys = bloom_filters + cuckoo_filters
    for filter_type, values in sorted(
        results.items(),
        key=lambda x: ordered_keys.index(x[0]) if x[0] in ordered_keys else len(ordered_keys)
    ):
        if filter_type in ["bloom_part_2", "bloom_std"]:
            continue
        load_factors = values['load_factor']
        fpr = values['fp_rate']
        if len(load_factors) != len(fpr):
            print(f"⚠️ Skipping '{filter_type}' due to mismatched data lengths ({len(load_factors)} vs {len(fpr)})")
            continue
        color = filter_colors.get(filter_type, "#7f7f7f")  # Default to gray if not in dictionary
        style = filter_styles.get(filter_type, {"linestyle": (0, (1, 1)), "marker": "o"})  # Default style
        name = config.get("graph_names", {}).get(filter_type, filter_type)  # Use graph name or default to key
        if filter_type == "cuckoo_var_load": name = "Cuckoo Filter (var. LF)"
        ax.plot(load_factors, fpr, label=name, color=color, linestyle=tuple(style["linestyle"]), marker=style["marker"])

    ax.set_yscale("log")  # Set y-axis to logarithmic scale
    ax.yaxis.set_major_formatter(mpl.ticker.PercentFormatter())
    ax.yaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda y, _: f"{y:.2f}%"))
    ax.tick_params(axis='y', which='both', labelsize=mpl_config["font"]["size"])
    ax.set_xlabel("Maximum Load Factor")  # Update x-axis label
    ax.set_ylabel("False Positive Rate")
    ax.set_xlim(left=min(min(values['load_factor']) for values in results.values() if values['load_factor']),
                right=max(max(values['load_factor']) for values in results.values() if values['load_factor']))
    
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
    ax.set_ylim(bottom=0.01)  # Adjust bottom limit for log scale
    ax.set_title("")  # Keep minimal for paper inclusion

    fig.tight_layout()
    output_file = "figures/fp-var_cf_load_factor.svg"
    plt.savefig(output_file, format="svg")
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    json_file_name = "results/fp-var_cf_load_factor.json"  # Hardcoded relative path to the JSON file
    config_file_name = "figures/matplotlib_config.json"  # Hardcoded relative path to the configuration file

    json_path = os.path.abspath(json_file_name)
    config_path = os.path.abspath(config_file_name)

    main(json_path, config_path)
