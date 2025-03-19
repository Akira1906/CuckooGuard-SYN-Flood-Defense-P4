#!/bin/bash

# This script runs the analyze-split-proxy-ds.sh script for each solution to be tested,
# then analyzes the test results and generates a figure using a Python script.

# change the parameters in the P4 implementation
# use the markers in the P4 code to localize the lines that need to be changed,
# replace it with a line containing the new parameter + the markers should remain

rel_file_path="../split-proxy/implementation/split-proxy-crc.p4"

filter_bit_size=65536 # bits

bloom1_size=$filter_bit_size/2
bloom2_size=$bloom1_size

# pass on macros at compile time to the p4 script

# Run the analysis for the CRC-based solution
./analyze-split-proxy-ds.sh ../demo-split-proxy crc ptf-measure-fp-ds bloom_fp_test > results/fp_bloom_results.txt

# Run the analysis for the Cuckoo-based solution
./analyze-split-proxy-ds.sh ../demo-split-proxy-cuckoo cuckoo ptf-measure-fp-ds cuckoo_fp_test > results/fp_cuckoo_results.txt

# Add any additional commands to parse the results and generate figures using Python
# Example:

# Extract the false positive rates from the result files
fp_rate_bloom=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_bloom_results.txt)
fp_rate_cuckoo=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_cuckoo_results.txt)

# Print the extracted false positive rates
echo "Bloom Filter FP Rate: $fp_rate_bloom"
echo "Cuckoo Filter FP Rate: $fp_rate_cuckoo"
# python3 generate_figures.py bloomtest.txt cuckootest.txt