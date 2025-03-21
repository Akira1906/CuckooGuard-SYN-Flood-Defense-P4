#!/bin/bash

# New global experiment parameters
AVAILABLE_MEMORY_BIT=65536
N_BENIGN_CONNECTIONS=5000
N_HOSTILE_TEST_PACKETS=100000
ALWAYS_RETEST="False"

# Process named arguments
    ARGS=$(getopt -o c:h:m:r: --long \
        n_benign_connections:,n_hostile_test_packets:,available_memory_bit:,always_retest: \
        -- "$@")

    if [[ $? -ne 0 ]]; then
        echo "Error: Invalid arguments"
        exit 1
    fi

    eval set -- "$ARGS"

    while true; do
        case "$1" in
            -c|--n_benign_connections) N_BENIGN_CONNECTIONS="$2"; shift 2 ;;
            -h|--n_hostile_test_packets) N_HOSTILE_TEST_PACKETS="$2"; shift 2 ;;
            -m|--available_memory_bit) AVAILABLE_MEMORY_BIT="$2"; shift 2 ;;
            -r|--always_retest) ALWAYS_RETEST="$2"; shift 2 ;;
            --) shift; break ;;
            *) break ;;
        esac
    done


save_experiment_json() {
    results_json="results/experiment_history.json"

    # Create new experiment entry
    new_entry=$(jq -n \
        --arg timestamp "$(date +"%Y-%m-%d %H:%M:%S")" \
        --arg available_memory_bit "$AVAILABLE_MEMORY_BIT" \
        --arg n_benign_connections "$N_BENIGN_CONNECTIONS" \
        --arg n_hostile_test_packets "$N_HOSTILE_TEST_PACKETS" \
        --arg bloom_size_part_2 "$bloom_size_part_2" \
        --arg bloom_size_part_3 "$bloom_size_part_3" \
        --arg bloom_size_std "$bloom_size_std" \
        --arg fp_hits_bloom_part_2 "$fp_hits_bloom_part_2" \
        --arg fp_hits_bloom_part_3 "$fp_hits_bloom_part_3" \
        --arg fp_hits_bloom_std "$fp_hits_bloom_std" \
        --arg fp_hits_cuckoo "$fp_hits_cuckoo" \
        --arg exp_fp_rate_bloom_part_2 "$exp_fp_rate_bloom_part_2" \
        --arg exp_fp_rate_bloom_part_3 "$exp_fp_rate_bloom_part_3" \
        --arg exp_fp_rate_bloom_std "$exp_fp_rate_bloom_std" \
        --arg exp_fp_rate_cuckoo "$exp_fp_rate_cuckoo" \
        --arg exp_fp_rate_cuckoo_ss "$exp_fp_rate_cuckoo_ss" \
        --arg fingerprint_size "$fingerprint_size" \
        --arg n_buckets "$n_buckets" \
        --arg n_fingerprints "$n_fingerprints" \
        '{
            "timestamp": $timestamp,
            "available_memory_bit": $available_memory_bit | tonumber,
            "n_benign_connections": $n_benign_connections | tonumber,
            "n_hostile_test_packets": $n_hostile_test_packets | tonumber,
            "bloom_part_2": {
                "size_bits": $bloom_size_part_2 | tonumber,
                "fp_hits": $fp_hits_bloom_part_2 | tonumber,
                "fp_rate": $exp_fp_rate_bloom_part_2 | tonumber
            },
            "bloom_part_3": {
                "size_bits": $bloom_size_part_3 | tonumber,
                "fp_hits": $fp_hits_bloom_part_3 | tonumber,
                "fp_rate": $exp_fp_rate_bloom_part_3 | tonumber
            },
            "bloom_std": {
                "size_bits": $bloom_size_std | tonumber,
                "fp_hits": $fp_hits_bloom_std | tonumber,
                "fp_rate": $exp_fp_rate_bloom_std | tonumber
            },
            "cuckoo": {
                "fingerprint_size": $fingerprint_size | tonumber,
                "n_buckets": $n_buckets | tonumber,
                "n_fingerprints": $n_fingerprints | tonumber,
                "fp_hits": $fp_hits_cuckoo | tonumber,
                "fp_rate": $exp_fp_rate_cuckoo | tonumber,
                "fp_rate_ss": $exp_fp_rate_cuckoo_ss | tonumber
            }
        }')

    # Check if history file exists
    if [ -f "$results_json" ]; then
        # Append new entry to existing JSON array
        jq --argjson new_entry "$new_entry" '. + [$new_entry]' "$results_json" > "$results_json.tmp" && mv "$results_json.tmp" "$results_json"
    else
        # Create a new JSON array with the first experiment entry
        echo "[$new_entry]" > "$results_json"
    fi

    echo "✅ Experiment saved to $results_json"
}

should_rerun_experiment() {
    # this function should not be executed in a subshell
    local filter_type="$1"
    results_json="results/experiment_history.json"

    # Default: Run the experiment
    should_rerun=true

    if [ -f "$results_json" ]; then
        last_exp=$(jq '.[-1]' "$results_json")

        last_available_memory_bit=$(echo "$last_exp" | jq '.available_memory_bit')
        last_n_benign_connections=$(echo "$last_exp" | jq '.n_benign_connections')
        last_n_hostile_test_packets=$(echo "$last_exp" | jq '.n_hostile_test_packets')

        if [[ "$last_available_memory_bit" == "$AVAILABLE_MEMORY_BIT" &&
              "$last_n_benign_connections" ==  "$N_BENIGN_CONNECTIONS" &&
              "$last_n_hostile_test_packets" == "$N_HOSTILE_TEST_PACKETS" ]]; then
                echo "global parameters the same"
            if [[ "$filter_type" == "bloom_part_2" ]]; then
                last_bloom_size_part_3=$(echo "$last_exp" | jq '.bloom_part_2.size_bits')
                
                if [[ "$last_bloom_size_part_3" == "$bloom_size_part_2" && "$ALWAYS_RETEST" == "False" ]]; then
                    echo "⚠️  Bloom Filter parameters unchanged — skipping test."
                    should_rerun=false
                    fp_hits_bloom_part_2=$(echo "$last_exp" | jq '.bloom_part_2.fp_hits')
                fi

            elif [[ "$filter_type" == "cuckoo" ]]; then
                last_cuckoo_fpsize=$(echo "$last_exp" | jq '.cuckoo.fingerprint_size')
                last_cuckoo_buckets=$(echo "$last_exp" | jq '.cuckoo.n_buckets')

                if [[ "$last_cuckoo_fpsize" == "$fingerprint_size" &&
                    "$last_cuckoo_buckets" == "$n_buckets" &&
                    "$ALWAYS_RETEST" == "False" ]]; then
                    echo "⚠️  Cuckoo Filter parameters unchanged — skipping test."
                    should_rerun=false
                    fp_hits_cuckoo=$(echo "$last_exp" | jq '.cuckoo.fp_hits')
                fi
            elif [[ "$filter_type" == "bloom_part_3" ]]; then
                last_bloom_size_part_3=$(echo "$last_exp" | jq '.bloom_part_3.size_bits')
                
                if [[ "$last_bloom_size_part_3" == "$bloom_size_part_3" && "$ALWAYS_RETEST" == "False" ]]; then
                    echo "⚠️  Bloom Filter (Part 3) parameters unchanged — skipping test."
                    should_rerun=false
                    fp_hits_bloom_part_3=$(echo "$last_exp" | jq '.bloom_part_3.fp_hits')
                fi

            elif [[ "$filter_type" == "bloom_std" ]]; then
                last_bloom_size_std=$(echo "$last_exp" | jq '.bloom_std.size_bits')
                
                if [[ "$last_bloom_size_std" == "$bloom_size_std" && "$ALWAYS_RETEST" == "False" ]]; then
                    echo "⚠️  Bloom Filter (Standard) parameters unchanged — skipping test."
                    should_rerun=false
                    fp_hits_bloom_std=$(echo "$last_exp" | jq '.bloom_std.fp_hits')
                fi
            fi
        fi
        
    fi

    if [ "$should_rerun" == "true" ]; then
        ran_experiment=true
    fi

}

# This script runs the analyze-split-proxy-ds.sh script for each solution to be tested,
# then analyzes the test results and generates a figure using a Python script.

# parameters of the P4 implementation can be changed via arguments to analyze-splix-proxy-ds.sh

# Bloom Filter (Partitioned with 2 stages):
    bloom_size_part_2=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / 2)}")

    echo "----------------------------------"
    echo "Computed Bloom Filter Parameters:"
    echo "  - Available Memory: $AVAILABLE_MEMORY_BIT bits"
    echo "  - Bloom Filter Stage Size: $bloom_size_part_2 bits"
    echo "----------------------------------"

    # Run the analysis for the Bloom Filter-based solution
    should_rerun_experiment "bloom_part_2"
    if [[ "$should_rerun" == "true" ]]; then
        echo "Running Bloom Filter (Part 2) experiment..."
        ./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy" --fn_suffix part2 \
            --fp_test ptf-measure-fp-ds --test_name bloom_part_2_fp_test \
            --filter_size $bloom_size_part_2 \
            --fingerprint_size 0 \
            --n_buckets 0 \
            --n_benign_connections $N_BENIGN_CONNECTIONS \
            --n_hostile_test_packets $N_HOSTILE_TEST_PACKETS \
            > results/fp_bloom_part_2_results.txt

        fp_hits_bloom_part_2=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_bloom_part_2_results.txt)
    else
        echo "Using cached Bloom Filter (Part 2) results"
    fi


# Bloom Filter (Partitioned with 3 stages)
    bloom_size_part_3=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / 3)}")

    echo "----------------------------------"
    echo "Computed Bloom Filter (Part 3) Parameters:"
    echo "  - Available Memory: $AVAILABLE_MEMORY_BIT bits"
    echo "  - Bloom Filter Stage Size: $bloom_size_part_3 bits"
    echo "----------------------------------"

    should_rerun_experiment "bloom_part_3"
    # should_rerun="true"
    if [[ "$should_rerun" == "true" ]]; then
        echo "Running Bloom Filter (Part 3) experiment..."
        ./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy" --fn_suffix part3 \
            --fp_test ptf-measure-fp-ds --test_name bloom_part_3_fp_test \
            --filter_size $bloom_size_part_3 \
            --fingerprint_size 0 \
            --n_buckets 0 \
            --n_benign_connections $N_BENIGN_CONNECTIONS \
            --n_hostile_test_packets $N_HOSTILE_TEST_PACKETS \
            > results/fp_bloom_part_3_results.txt

        fp_hits_bloom_part_3=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_bloom_part_3_results.txt)
    else
        echo "Using cached Bloom Filter (Part 3) results"
    fi

# Bloom Filter (Standard)
    bloom_size_std=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT)}")

    echo "----------------------------------"
    echo "Computed Bloom Filter (Standard) Parameters:"
    echo "  - Available Memory: $AVAILABLE_MEMORY_BIT bits"
    echo "  - Bloom Filter Size: $bloom_size_std bits"
    echo "----------------------------------"

    should_rerun_experiment "bloom_std"
    if [[ "$should_rerun" == "true" ]]; then
        echo "Running Bloom Filter (Standard) experiment..."
        ./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy" --fn_suffix part1 \
            --fp_test ptf-measure-fp-ds --test_name bloom_std_fp_test \
            --filter_size $bloom_size_std \
            --fingerprint_size 0 \
            --n_buckets 0 \
            --n_benign_connections $N_BENIGN_CONNECTIONS \
            --n_hostile_test_packets $N_HOSTILE_TEST_PACKETS \
            > results/fp_bloom_std_results.txt

        fp_hits_bloom_std=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_bloom_std_results.txt)
    else
        echo "Using cached Bloom Filter (Standard) results"
    fi


# Cuckoo Filter
    b=4 # number of entries per bucket
    n=$N_BENIGN_CONNECTIONS # number of items
    a=0.95 # load factor

    # Compute minimum needed entries (round down)
    min_needed_empty_spaces=$(awk "BEGIN {print int($n / $a)}")
    # Compute fingerprint size (round down)
    fingerprint_size=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / $min_needed_empty_spaces)}")

    # Compute number of buckets (round down)
    n_buckets=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / ($fingerprint_size * $b))}")
    # n_buckets=$(awk "BEGIN {print int(($min_needed_empty_spaces / 4) + 1)}") # round up [stick to exact a=0.95]

    # Compute total number of fingerprints
    n_fingerprints=$(awk "BEGIN {print int($n_buckets * $b)}")

    echo "----------------------------------"
    echo "Computed Cuckoo Filter Parameters:"
    echo "  - Available Memory: $AVAILABLE_MEMORY_BIT bits"
    echo "  - Number of Items: $n"
    echo "  - Load Factor: $a"
    echo "  - Minimum Needed Entries: $min_needed_empty_spaces"
    echo "  - Fingerprint Size: $fingerprint_size bits"
    echo "  - Number of Buckets: $n_buckets"
    echo "  - Total Number of Fingerprints: $n_fingerprints"
    echo "----------------------------------"

    should_rerun_experiment "cuckoo"
    if [[ "$should_rerun" == "true" ]]; then
        echo "Running Cuckoo Filter experiment..."
        # Run the analysis for the Cuckoo-based solution
        ./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy-cuckoo" --fn_suffix cuckoo \
            --fp_test ptf-measure-fp-ds --test_name cuckoo_fp_test \
            --filter_size $n_fingerprints \
            --fingerprint_size $fingerprint_size \
            --n_buckets $n_buckets \
            --n_benign_connections $N_BENIGN_CONNECTIONS \
            --n_hostile_test_packets $N_HOSTILE_TEST_PACKETS \
            > results/fp_cuckoo_results.txt

        fp_hits_cuckoo=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_cuckoo_results.txt)
        else
        echo "Using cached Cuckoo Filter results."
    fi

    # Run Cuckoo Python Experiment
    python3 ../demo-python-cuckoo/tests/fp_rate_test.py \
            --filter_size $n_fingerprints \
            --fingerprint_size $fingerprint_size \
            --n_buckets $n_buckets \
            --n_benign_connections $N_BENIGN_CONNECTIONS \
            --n_hostile_test_packets $N_HOSTILE_TEST_PACKETS \
            > results/fp_cucko_py_results.txt

    fp_hits_cuckoo_py=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_cucko_py_results.txt)




# Calculate the experimental FP rates
    exp_fp_rate_bloom_part_2=$(awk "BEGIN {print ($fp_hits_bloom_part_2 / ($N_HOSTILE_TEST_PACKETS))}")
    exp_fp_rate_bloom_part_3=$(awk "BEGIN {print ($fp_hits_bloom_part_3 / ($N_HOSTILE_TEST_PACKETS))}")
    exp_fp_rate_bloom_std=$(awk "BEGIN {print ($fp_hits_bloom_std / ($N_HOSTILE_TEST_PACKETS))}")
    exp_fp_rate_cuckoo=$(awk "BEGIN {print ($fp_hits_cuckoo / ($N_HOSTILE_TEST_PACKETS))}")
    exp_fp_rate_cuckoo_ss=0
    exp_fp_rate_cuckoo_py=$(awk "BEGIN {print ($fp_hits_cuckoo_py / ($N_HOSTILE_TEST_PACKETS))}")


# Calculation of the expected theoretical exact ideal FP rates

    # Partitioned Bloom Filter with 2 stages
    theo_fp_rate_bloom_part_2=$(awk -v m="$AVAILABLE_MEMORY_BIT" -v n="$N_BENIGN_CONNECTIONS" -v k="2" '
    BEGIN {
        exp_fp_rate = (1 - (1 - k / m) ^ n) ^ k;
        print exp_fp_rate;
    }')

    # Partitioned Bloom Filter with 3 stages
    theo_fp_rate_bloom_part_3=$(awk -v m="$AVAILABLE_MEMORY_BIT" -v n="$N_BENIGN_CONNECTIONS" -v k="3" '
    BEGIN {
        exp_fp_rate = (1 - (1 - k / m) ^ n) ^ k;
        print exp_fp_rate;
    }')

    # Standard Bloom Filter
    theo_fp_rate_bloom_std=$(awk -v m="$AVAILABLE_MEMORY_BIT" -v n="$N_BENIGN_CONNECTIONS" -v k="1" '
    BEGIN {
        exp_fp_rate = (1 - (1 - k / m) ^ n) ^ k;
        print exp_fp_rate;
    }')

    # Cuckoo Filter
    real_a=$(awk "BEGIN {print ($N_BENIGN_CONNECTIONS / $n_fingerprints)}")
    echo $real_a
    b=$(awk "BEGIN {print ($AVAILABLE_MEMORY_BIT / $N_BENIGN_CONNECTIONS)}")
    theo_fp_rate_cuckoo=$(awk -v b="$b" -v a="$real_a" '
    BEGIN {
        exp_fp_rate = 1/(2^((b * a) - 3))
        print exp_fp_rate;
    }')

    # Cuckoo Filter with semi-sorting
    theo_fp_rate_cuckoo_ss=$(awk -v b="$b" -v a="$real_a" '
    BEGIN {
        exp_fp_rate = 1/(2^((b * a) - 2))
        print exp_fp_rate;
    }')

# Print the results
    echo "========================================================="
    echo "|                  False Positive Rates                 |"
    echo "========================================================="
    printf "| %-30s | %-10s | %-10s |\n" "Filter Type" "Theore. FP" "Experi. FP"
    echo "---------------------------------------------------------"

    # Print the Bloom Filter (Standard) results
    printf "| %-30s | %-10s | %-10s |\n" "Bloom Filter (1 Part.)" \
        "$theo_fp_rate_bloom_std" \
        "$exp_fp_rate_bloom_std"

    # Print the Bloom Filter (Part 2) results
    printf "| %-30s | %-10s | %-10s |\n" "Bloom Filter (2 Part.)" \
        "$theo_fp_rate_bloom_part_2" \
        "$exp_fp_rate_bloom_part_2"

    # Print the Bloom Filter (Part 3) results
    printf "| %-30s | %-10s | %-10s |\n" "Bloom Filter (3 Part.)" \
        "$theo_fp_rate_bloom_part_3" \
        "$exp_fp_rate_bloom_part_3"

    # Print the Cuckoo Filter results
    printf "| %-30s | %-10s | %-10s |\n" "Cuckoo Filter" \
        "$theo_fp_rate_cuckoo" \
        "$exp_fp_rate_cuckoo"

    printf "| %-30s | %-10s | %-10s |\n" "Cuckoo Filter Python" \
        "$theo_fp_rate_cuckoo" \
        "$exp_fp_rate_cuckoo_py"

    # Print the SS Cuckoo Filter results
    printf "| %-30s | %-10s | %-10s |\n" "SS Cuckoo Filter" \
        "$theo_fp_rate_cuckoo_ss" \
        "$exp_fp_rate_cuckoo_ss"

    # Print the footer
    echo "---------------------------------------------------------"
    echo "| (Cuckoo theoretical values are upper bounds; ideal values might be slightly lower) |"
    echo "========================================================="


# Save the results to file
    if [ "$ran_experiment" == "true" ]; then
        save_experiment_json
    fi