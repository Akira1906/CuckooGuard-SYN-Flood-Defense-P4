#!/bin/bash

# This script runs the analyze-split-proxy-ds.sh script for each solution to be tested,
# then analyzes the test results and generates a figure using a Python script.

# parameters of the P4 implementation can be changed via arguments to analyze-splix-proxy-ds.sh

# global parameters

available_memory_bit=65536
n_benign_connections=5000
n_hostile_test_packets=10000

# Bloom Filter: compute local test parameters
rel_file_path="../split-proxy/implementation/split-proxy-crc.p4"

bloom_size=$(awk "BEGIN {print int($available_memory_bit / 2)}")

echo "Computed Bloom Filter Parameters:"
echo "  - Available Memory: $available_memory_bit bits"
echo "  - Bloom Filter Stage Size: $bloom_size bits"

# Run the analysis for the CRC-based solution
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

# Compute minimum needed empty spaces (round down)
min_needed_empty_spaces=$(awk "BEGIN {print int($n / $a)}")
# Compute fingerprint size (round down)
fingerprint_size=$(awk "BEGIN {print int($available_memory_bit / $min_needed_empty_spaces)}")

# Compute number of buckets (round down)
n_buckets=$(awk "BEGIN {print int($available_memory_bit / ($fingerprint_size * $b))}")

# Compute total number of fingerprints
n_fingerprints=$(awk "BEGIN {print int($n_buckets * $b)}")

# Output results
echo "Computed Cuckoo Filter Parameters:"
echo "  - Available Memory: $available_memory_bit bits"
echo "  - Number of Items: $n"
echo "  - Load Factor: $a"
echo "  - Minimum Needed Empty Spaces: $min_needed_empty_spaces"
echo "  - Fingerprint Size: $fingerprint_size bits"
echo "  - Number of Buckets: $n_buckets"
echo "  - Total Number of Fingerprints: $n_fingerprints"


# Run the analysis for the Cuckoo-based solution
# ./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy-cuckoo" --fn_suffix cuckoo \
#     --fp_test ptf-measure-fp-ds --test_name cuckoo_fp_test \
#     --filter_size $n_fingerprints \
#     --fingerprint_size $fingerprint_size \
#     --n_buckets $n_buckets \
#     --n_benign_connections $n_benign_connections \
#     --n_hostile_test_packets $n_hostile_test_packets \
#     > results/fp_cuckoo_results.txt


# Extract the false positive rates from the result files
fp_rate_bloom=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_bloom_results.txt)
fp_rate_cuckoo=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_cuckoo_results.txt)

# Print the extracted false positive rates
echo "Bloom Filter FP Rate: $fp_rate_bloom"
echo "Cuckoo Filter FP Rate: $fp_rate_cuckoo"
# python3 generate_figures.py bloomtest.txt cuckootest.txt