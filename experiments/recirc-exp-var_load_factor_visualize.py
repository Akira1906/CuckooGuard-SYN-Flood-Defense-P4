import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import sys
import os
from collections import defaultdict
import math

def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)

def main(json_file, config_file):
    config = load_config(config_file)
    mpl_config = config.get("matplotlib_config")

    with open(json_file, 'r') as f:
        data = json.load(f)

    aggregated_results = defaultdict(list)

    for entry in data:
        load_factor = entry['load_factor']
        n_test = entry['n_test_packets']
        packet_count = entry['packet_count']
        # if load_factor == 0.6:
        #     print (packet_count)
        recirc_overhead = (packet_count - n_test) / n_test * 100  # Calculate y-axis value

        aggregated_results[load_factor].append(recirc_overhead)

    # Calculate averages for each unique load factor
    results = {'load_factor': [], 'recirc_overhead': []}
    for load_factor, overheads in aggregated_results.items():
        results['load_factor'].append(load_factor)
        results['recirc_overhead'].append(sum(overheads) / len(overheads))
    print(results)
    # Calculate the standard deviation for each unique load factor
    results['recirc_overhead_std'] = []
    for load_factor, overheads in aggregated_results.items():
        mean = sum(overheads) / len(overheads)
        variance = sum((x - mean) ** 2 for x in overheads) / len(overheads)
        stddev = math.sqrt(variance)
        results['recirc_overhead_std'].append(stddev)

    # === Apply Matplotlib Configuration from JSON ===
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
    
    # Extract filter colors and graph names from config
    filter_colors = config["filter_colors"]
    filter_styles = config.get("filter_styles", {})
    graph_names = config.get("graph_names", {})

    fig, ax = plt.subplots()

    ordered_keys = ["cuckoo_var_load"]
    for filter_type, (x, y, yerr) in sorted(
        {"cuckoo_var_load": (results['load_factor'], results['recirc_overhead'], results['recirc_overhead_std'])}.items(),
        key=lambda x: ordered_keys.index(x[0]) if x[0] in ordered_keys else len(ordered_keys)
    ):
        if len(x) != len(y):
            print(f"⚠️ Skipping '{filter_type}' due to mismatched data lengths ({len(x)} vs {len(y)})")
            continue
        color = filter_colors.get(filter_type, "#000000")  # Default to black if not in dictionary
        name = graph_names.get(filter_type, filter_type)  # Use graph name or default to key
        style = filter_styles.get(filter_type, {"linestyle": (0, (1, 1)), "marker": "o"})  # Default style
        # Plot with error bars
          # Plot mean line
        ax.plot(x, y, label="Cuckoo Filter (var. α)", color=color,
                linestyle=tuple(style["linestyle"]), marker=style["marker"])
        # Fill between mean ± stddev
        y_lower = [a - b for a, b in zip(y, yerr)]
        y_upper = [a + b for a, b in zip(y, yerr)]
        ax.fill_between(x, y_lower, y_upper, color=color, alpha=0.25, label="Std. Dev. (σ)")
        # Highlight x=0.85
        highlight_x = 0.85
        if highlight_x in x:
            highlight_y = y[x.index(highlight_x)]
            # Vertical line stopping at the graph
            ax.plot([highlight_x, highlight_x], [0.01, highlight_y], color="blue", linestyle="--", linewidth=0.6)
            # Horizontal line extending left
            ax.plot([0.1, highlight_x], [highlight_y, highlight_y], color="blue", linestyle="--", linewidth=0.6)
            # ax.axhline(y=highlight_y, xmax=highlight_x / max(x), color="blue", linestyle="--", linewidth=0.6)
            ax.annotate(
                f"({highlight_y:.2f}%)",
                xy=(highlight_x, highlight_y),
                xytext=(highlight_x - 0.2, highlight_y + 50),
                # arrowprops=dict(arrowstyle="->", color="blue"),
                fontsize=mpl_config["font"]["size"]
            )

    ax.set_yscale("log")
    ax.set_xlabel("Load Factor (α)")  # Update x-axis label
    ax.set_ylabel("Recirculation Overhead")  # Update y-axis label
    ax.set_xlim(left=0.4, right=0.95) # min(results['load_factor']) max(results['load_factor']
    
    if "bbox_to_anchor" in config["matplotlib_config"]["legend"]:
        ax.legend(
            loc=config["matplotlib_config"]["legend"]["loc"],
            bbox_to_anchor=(
                config["matplotlib_config"]["legend"]["bbox_to_anchor"][0],
                (config["matplotlib_config"]["legend"]["bbox_to_anchor"][1])), # - 0.2
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
    ax.set_title("")  # Keep minimal for paper inclusion

    ax.yaxis.set_major_formatter(mpl.ticker.PercentFormatter())
    ax.yaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda y, _: f"{y:.1f}%"))
    ax.tick_params(axis='y', which='both', labelsize=mpl_config["font"]["size"])
    ax.set_ylim(bottom=0.05)

    fig.tight_layout()
    output_file = "figures/recirc-var_load_factor.svg"
    plt.savefig(output_file, format="svg", transparent=True, bbox_inches='tight', pad_inches=0)
    print(f"✅ Plot saved as '{output_file}'")
    output_file = "figures/recirc-var_load_factor.png"
    plt.savefig(output_file, format="png", dpi=600, transparent=False, bbox_inches='tight', pad_inches=0)
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    json_file_name = "results/new-recirc-experiment_history.json"  # Hardcoded relative path to the JSON file
    config_file_name = "figures/matplotlib_config.json"  # Path to the configuration file
    json_path = os.path.abspath(json_file_name)
    config_path = os.path.abspath(config_file_name)

    main(json_path, config_path)
