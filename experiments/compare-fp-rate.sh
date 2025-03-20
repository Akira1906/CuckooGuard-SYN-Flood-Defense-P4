#!/bin/bash

# This script runs the analyze-split-proxy-ds.sh script for each solution to be tested,
# then analyzes the test results and generates a figure using a Python script.

# parameters of the P4 implementation can be changed via arguments to analyze-splix-proxy-ds.sh

# global parameters

available_memory_bit=65536
n_benign_connections=5000
n_hostile_test_packets=100000

# Bloom Filter: compute local test parameters
rel_file_path="../split-proxy/implementation/split-proxy-crc.p4"

bloom_size=$(awk "BEGIN {print int($available_memory_bit / 2)}")

echo "Computed Bloom Filter Parameters:"
echo "  - Available Memory: $available_memory_bit bits"
echo "  - Bloom Filter Stage Size: $bloom_size bits"

# Run the analysis for the Bloom Filter-based solution
./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy" --fn_suffix crc \
    --fp_test ptf-measure-fp-ds --test_name bloom_fp_test \
    --filter_size $bloom_size \
    --fingerprint_size 0 \
    --n_buckets 0 \
    --n_benign_connections $n_benign_connections \
    --n_hostile_test_packets $n_hostile_test_packets \
    > results/fp_bloom_results.txt


# Cuckoo Filter: compute local test parameters
b=4 # number of entries per bucket
n=$n_benign_connections # number of items
a=0.95 # load factor

# Compute minimum needed entries (round down)
min_needed_empty_spaces=$(awk "BEGIN {print int($n / $a)}")
# Compute fingerprint size (round down)
fingerprint_size=$(awk "BEGIN {print int($available_memory_bit / $min_needed_empty_spaces)}")

# Compute number of buckets (round down)
n_buckets=$(awk "BEGIN {print int($available_memory_bit / ($fingerprint_size * $b))}")
# n_buckets=$(awk "BEGIN {print int(($min_needed_empty_spaces / 4) + 1)}") # round up [stick to exact a=0.95]

# Compute total number of fingerprints
n_fingerprints=$(awk "BEGIN {print int($n_buckets * $b)}")

# Output results
echo "Computed Cuckoo Filter Parameters:"
echo "  - Available Memory: $available_memory_bit bits"
echo "  - Number of Items: $n"
echo "  - Load Factor: $a"
echo "  - Minimum Needed Entries: $min_needed_empty_spaces"
echo "  - Fingerprint Size: $fingerprint_size bits"
echo "  - Number of Buckets: $n_buckets"
echo "  - Total Number of Fingerprints: $n_fingerprints"


# Run the analysis for the Cuckoo-based solution
./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy-cuckoo" --fn_suffix cuckoo \
    --fp_test ptf-measure-fp-ds --test_name cuckoo_fp_test \
    --filter_size $n_fingerprints \
    --fingerprint_size $fingerprint_size \
    --n_buckets $n_buckets \
    --n_benign_connections $n_benign_connections \
    --n_hostile_test_packets $n_hostile_test_packets \
    > results/fp_cuckoo_results.txt


# Extract the false positive rates from the result files
fp_hits_bloom=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_bloom_results.txt)
fp_hits_cuckoo=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_cuckoo_results.txt)

# Calculate the experimental FP rates
exp_fp_rate_bloom=$(awk "BEGIN {print ($fp_hits_bloom / ($n_hostile_test_packets))}")
exp_fp_rate_cuckoo=$(awk "BEGIN {print ($fp_hits_cuckoo / ($n_hostile_test_packets))}")



# Calculation of the expected exact ideal FP rates

# Partitioned Bloom Filter with 2 stages
exp_fp_rate_bloom=$(awk -v m="$available_memory_bit" -v n="$n_benign_connections" -v k="2" '
BEGIN {
    exp_fp_rate = (1 - (1 - k / m) ^ n) ^ k;
    print exp_fp_rate;
}')

# Cuckoo Filter
exp_fp_rate_cuckoo=$(awk -v b="$fingerprint_size" -v a="$a" '
BEGIN {
    exp_fp_rate = 1/(2^((b * a) - 3))
    print exp_fp_rate;
}')

# Cuckoo Filter with semi-sorting
exp_fp_rate_cuckoo_ss=$(awk -v b="$fingerprint_size" -v a="$a" '
BEGIN {
    exp_fp_rate = 1/(2^((b * a) - 2))
    print exp_fp_rate;
}')

# print the results

# Print the table header
echo "========================================================="
echo "|                  False Positive Rates                 |"
echo "========================================================="
printf "| %-30s | %-10s | %-10s |\n" "Filter Type" "Theore. FP" "Experi. FP"
echo "---------------------------------------------------------"

# Print the Bloom Filter results
printf "| %-30s | %-10s | %-10s |\n" "Bloom Filter" \
    "$exp_fp_rate_bloom" \
    "$(awk "BEGIN {print ($fp_hits_bloom / ($n_hostile_test_packets))}")"

# Print the Cuckoo Filter results
printf "| %-30s | %-10s | %-10s |\n" "Cuckoo Filter" \
    "$exp_fp_rate_cuckoo" \
    "$(awk "BEGIN {print ($fp_hits_cuckoo / ($n_hostile_test_packets))}")"

# Print the SS Cuckoo Filter results
printf "| %-30s | %-10s | %-10s |\n" "SS Cuckoo Filter" \
    "$exp_fp_rate_cuckoo_ss" \
    "N/A"  # Adjust this if you have experimental results for SS Cuckoo

# Print the footer
echo "---------------------------------------------------------"
echo "| (Cuckoo values are upper bounds; ideal values might be slightly higher) |"
echo "========================================================="
# python3 generate_figures.py bloomtest.txt cuckootest.txt