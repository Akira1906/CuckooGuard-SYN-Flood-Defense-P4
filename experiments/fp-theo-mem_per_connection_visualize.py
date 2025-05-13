import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np
import json
import os
from matplotlib.ticker import FuncFormatter

def load_config(config_path):
    with open(config_path, 'r') as f:
        return json.load(f)

def calculate_bloom_bits_per_item(fp_rate):
    """Calculate bits per item for Bloom Filters."""
    return 1.44 * np.log2(1 / fp_rate)

def calculate_cuckoo_bits_per_item(fp_rate, alpha=0.9555):
    """Calculate bits per item for Cuckoo Filters."""
    return (np.log2(1 / fp_rate) + 3) / alpha

def calculate_quotient_bits_per_item(fp_rate, alpha=0.95):
    """Calculate bits per item for Quotient Filters."""
    return (np.log2(1 / fp_rate) + 2.125) / alpha

def main(config_file):
    config = load_config(config_file)
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

    # Define the range of false positive rates (logarithmic scale)
    fp_rates = np.logspace(-1, -5, 100)  # From 10^-6 to 10^-1

    # Calculate bits per item for each filter type
    bloom_bits = calculate_bloom_bits_per_item(fp_rates)
    cuckoo_bits = calculate_cuckoo_bits_per_item(fp_rates)
    quotient_bits = calculate_quotient_bits_per_item(fp_rates)

    fig, ax = plt.subplots()

    # Plot each filter type
    ax.plot(fp_rates, bloom_bits, label="Bloom Filter", color=filter_colors.get("varbloom", "blue"),
            linestyle=tuple(filter_styles.get("varbloom", {}).get("linestyle", (0, (1, 1)))),
            marker=filter_styles.get("bloom", {}).get("marker", "o"))
    ax.plot(fp_rates, cuckoo_bits, label="Cuckoo Filter", color=filter_colors.get("cuckoo", "green"),
            linestyle=tuple(filter_styles.get("cuckoo", {}).get("linestyle", (0, (3, 1)))),
            marker=filter_styles.get("cuckoo", {}).get("marker", "s"))
    ax.plot(fp_rates, quotient_bits, label="Quotient Filter", color=filter_colors.get("quotient", "red"),
            linestyle=tuple(filter_styles.get("quotient", {}).get("linestyle", (0, (5, 2)))),
            marker=filter_styles.get("quotient", {}).get("marker", "^"))

    # Set axis scales and labels
    ax.set_xscale("log")
    ax.set_yscale("linear")
    ax.set_xlabel("False Positive Rate (ε)")
    ax.set_ylabel("Bits per Item")
    # ax.set_title("Memory Efficiency of Filters")

    # Set x-axis to display in percent and y-axis in bits
    
    ax.set_xlim(fp_rates.min(), fp_rates.max())
    ax.invert_xaxis()

    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x * 100:.3f}%"))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:.0f} bits"))

    # Configure legend
    if "bbox_to_anchor" in mpl_config["legend"]:
        ax.legend(
            loc=mpl_config["legend"]["loc"],
            bbox_to_anchor=mpl_config["legend"]["bbox_to_anchor"],
            ncol=mpl_config["legend"].get("ncol", 1),
            columnspacing=mpl_config["legend"].get("column_spacing", 0.5),
            handletextpad=mpl_config["legend"].get("handletextpad", 0.3)
        )
    else:
        ax.legend(
            loc=mpl_config["legend"]["loc"],
            ncol=mpl_config["legend"].get("ncol", 1),
            columnspacing=mpl_config["legend"].get("column_spacing", 0.5),
            handletextpad=mpl_config["legend"].get("handletextpad", 0.3)
        )

    # Save the plot
    output_file = "figures/fp-theo-memory_per_connection.svg"
    fig.tight_layout()
    plt.savefig(output_file, format="svg", transparent=False, bbox_inches='tight', pad_inches=0)
    print(f"✅ Plot saved as '{output_file}'")

if __name__ == "__main__":
    config_file_name = "figures/matplotlib_config.json"  # Path to the configuration file
    config_path = os.path.abspath(config_file_name)

    main(config_path)