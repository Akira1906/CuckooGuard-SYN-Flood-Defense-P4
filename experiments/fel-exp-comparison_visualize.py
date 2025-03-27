import json
import matplotlib.pyplot as plt
import matplotlib as mpl
import os

def load_config(config_path):
    if not os.path.exists(config_path):
        print(f"Error: Configuration file '{config_path}' not found.")
        return None
    with open(config_path, 'r') as f:
        return json.load(f)

def main():
    config_path = os.path.join(os.path.dirname(__file__), "figures/matplotlib_config.json")
    config = load_config(config_path)
    # print(config)
    if config is None:
        return

    # Apply Matplotlib configuration
    mpl_config = config.get("matplotlib_config", {})
    figure_dimensions = config.get("figure_dimensions", {})
    fig_width = figure_dimensions.get("width", 6)
    fig_height = figure_dimensions.get("height", 3.2)
    mpl.rcParams.update({
        "figure.figsize": (fig_width, fig_height),
        "font.size": mpl_config.get("font", {}).get("size", 9),
        "font.family": mpl_config.get("font", {}).get("family", "sans-serif"),
        "font.sans-serif": mpl_config.get("font", {}).get("sans-serif", ["DejaVu Sans"]),
        "axes.grid": mpl_config.get("axes", {}).get("grid", True),
        "axes.edgecolor": mpl_config.get("axes", {}).get("edgecolor", "#444444"),
        "axes.linewidth": mpl_config.get("axes", {}).get("linewidth", 0.8),
        "lines.linewidth": mpl_config.get("lines", {}).get("linewidth", 1.2),
        "lines.markersize": 0,
        "legend.frameon": mpl_config.get("legend", {}).get("frameon", False),
        "legend.fontsize": mpl_config.get("legend", {}).get("fontsize", 8),
        "xtick.direction": mpl_config.get("ticks", {}).get("xtick_direction", "in"),
        "ytick.direction": mpl_config.get("ticks", {}).get("ytick_direction", "in"),
        "pdf.fonttype": mpl_config.get("output", {}).get("pdf_fonttype", 42),
        "svg.fonttype": mpl_config.get("output", {}).get("svg_fonttype", "none")
    })

    # Extract filter colors and graph names from config
    filter_colors = config.get("filter_colors", {})
    filter_styles = config.get("filter_styles", {})
    graph_names = config.get("graph_names", {})

    json_file = os.path.join(os.path.dirname(__file__), "results/fel-varbloom_results.json")
    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found.")
        return

    with open(json_file, 'r') as f:
        data = json.load(f)

    # Parse Bloom Filter data
    results = {'time_seconds': [], 'total_elements': []}
    for entry in data:
        time_seconds = entry['timestamp_ns'] / 1e9
        total_elements = entry['reg_bloom_0_size'] + entry['reg_bloom_1_size']
        results['time_seconds'].append(time_seconds)
        results['total_elements'].append(total_elements)

    cuckoo_file = os.path.join(os.path.dirname(__file__), "results/fel-cuckoo_results.json")
    if not os.path.exists(cuckoo_file):
        print(f"Error: File '{cuckoo_file}' not found.")
        return

    with open(cuckoo_file, 'r') as f:
        cuckoo_data = json.load(f)

    cuckoo_results = {'time_seconds': [], 'n_elements': []}
    for entry in cuckoo_data:
        time_seconds = entry['timestamp_ns'] / 1e9
        n_elements = entry['n_elements']
        cuckoo_results['time_seconds'].append(time_seconds)
        cuckoo_results['n_elements'].append(n_elements)

    fig, ax = plt.subplots(figsize=(fig_width, fig_height))

    bloom_filters = ["varbloom"]
    cuckoo_filters = ["cuckoo"]

    ordered_keys = bloom_filters + cuckoo_filters
    for filter_type, (x, y) in sorted(
        {"varbloom": (results['time_seconds'], results['total_elements']),
         "cuckoo": (cuckoo_results['time_seconds'], cuckoo_results['n_elements'])}.items(),
        key=lambda x: ordered_keys.index(x[0]) if x[0] in ordered_keys else len(ordered_keys)
    ):
        if len(x) != len(y):
            print(f"⚠️ Skipping '{filter_type}' due to mismatched data lengths ({len(x)} vs {len(y)})")
            continue
        color = filter_colors.get(filter_type, "#000000")  # Default to black if not in dictionary
        style = filter_styles.get(filter_type, {"linestyle": (0, (1, 1)), "marker": "o"})  # Default style
        name = graph_names.get(filter_type, filter_type)  # Use graph name or default to key
        # ax.plot(x, y, label=f"{name}", color=color, linestyle=tuple(style["linestyle"]), marker=style["marker"])
        ax.step(x, y, label=f"{name}", color=color, where='post', linestyle=tuple(style["linestyle"]), marker=style["marker"])  # 'post' ensures the step remains at the previous value until the next change
        
        
    ax.set_xlabel("Time (seconds)")
    ax.set_ylabel("Connections Tracked in Filter")
    
    # Add vertical lines at 5, 35, and 40 seconds
    for x in [5, 35, 40]:
        ax.axvline(x=x, color='blue', linestyle='--', linewidth=0.6)

    # Ensure x-axis starts at 0
    ax.set_xlim(left=0)

    if "bbox_to_anchor" in config["matplotlib_config"]["legend"]:
        ax.legend(
            loc=config["matplotlib_config"]["legend"]["loc"],
            bbox_to_anchor=(
                config["matplotlib_config"]["legend"]["bbox_to_anchor"][0],  # Reduce horizontal distance
                config["matplotlib_config"]["legend"]["bbox_to_anchor"][1] - 0.2   # Reduce vertical distance
            ),
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
    ax.set_title("")

    ax.tick_params(axis='y', which='both', labelsize=mpl_config["font"]["size"])
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    output_file = "figures/fel-comparison.svg"
    plt.savefig(output_file, format="svg")
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    main()
