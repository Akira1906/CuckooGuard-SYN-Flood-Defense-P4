#!/bin/bash

# Global experiment parameters
    AVAILABLE_MEMORY_BIT=84227
    N_BENIGN_CONNECTIONS=5000
    N_HOSTILE_TEST_PACKETS=40000
    ALWAYS_RETEST=false

    run_bloom_part1=false
    run_bloom_part2=false
    run_bloom_part3=false
    run_varbloom=true
    run_varbloom_time_decay=true
    run_cuckoo=true
    

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


# Helper Functions

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
            --arg varbloom_size "$varbloom_size" \
            --arg varbloom_time_decay_size "$varbloom_time_decay_size" \
            --arg fp_hits_bloom_part_2 "$fp_hits_bloom_part_2" \
            --arg fp_hits_bloom_part_3 "$fp_hits_bloom_part_3" \
            --arg fp_hits_bloom_std "$fp_hits_bloom_std" \
            --arg fp_hits_varbloom "$fp_hits_varbloom" \
            --arg fp_hits_varbloom_time_decay "$fp_hits_varbloom_time_decay" \
            --arg fp_hits_cuckoo "$fp_hits_cuckoo" \
            --arg exp_fp_rate_bloom_part_2 "$exp_fp_rate_bloom_part_2" \
            --arg exp_fp_rate_bloom_part_3 "$exp_fp_rate_bloom_part_3" \
            --arg exp_fp_rate_bloom_std "$exp_fp_rate_bloom_std" \
            --arg exp_fp_rate_varbloom "$exp_fp_rate_varbloom" \
            --arg exp_fp_rate_varbloom_time_decay "$exp_fp_rate_varbloom_time_decay" \
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
                "varbloom": {
                    "size_bits": $varbloom_size | tonumber,
                    "fp_hits": $fp_hits_varbloom | tonumber,
                    "fp_rate": $exp_fp_rate_varbloom | tonumber
                },
                "varbloom_time_decay": {
                    "size_bits": $varbloom_time_decay_size | tonumber,
                    "fp_hits": $fp_hits_varbloom_time_decay | tonumber,
                    "fp_rate": $exp_fp_rate_varbloom_time_decay | tonumber
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
                    last_bloom_size_part_2=$(echo "$last_exp" | jq '.bloom_part_2.size_bits')
                    
                    if [[ "$last_bloom_size_part_2" == "$bloom_size_part_2" && "$ALWAYS_RETEST" == "false" && "$run_bloom_part2" == "false" ]]; then
                        echo "⚠️  Bloom Filter parameters unchanged — skipping test."
                        should_rerun=false
                        fp_hits_bloom_part_2=$(echo "$last_exp" | jq '.bloom_part_2.fp_hits')
                    fi

                elif [[ "$filter_type" == "cuckoo" ]]; then
                    last_cuckoo_fpsize=$(echo "$last_exp" | jq '.cuckoo.fingerprint_size')
                    last_cuckoo_buckets=$(echo "$last_exp" | jq '.cuckoo.n_buckets')

                    if [[ "$last_cuckoo_fpsize" == "$fingerprint_size" &&
                        "$last_cuckoo_buckets" == "$n_buckets" &&
                        "$ALWAYS_RETEST" == "false"  && "$run_cuckoo" == "false" ]]; then
                        echo "⚠️  Cuckoo Filter parameters unchanged — skipping test."
                        should_rerun=false
                        fp_hits_cuckoo=$(echo "$last_exp" | jq '.cuckoo.fp_hits')
                    fi
                elif [[ "$filter_type" == "bloom_part_3" ]]; then
                    last_bloom_size_part_3=$(echo "$last_exp" | jq '.bloom_part_3.size_bits')
                    
                    if [[ "$last_bloom_size_part_3" == "$bloom_size_part_3" && "$ALWAYS_RETEST" == "false"  && "$run_bloom_part3" == "false" ]]; then
                        echo "⚠️  Bloom Filter (Part 3) parameters unchanged — skipping test."
                        should_rerun=false
                        fp_hits_bloom_part_3=$(echo "$last_exp" | jq '.bloom_part_3.fp_hits')
                    fi

                elif [[ "$filter_type" == "bloom_std" ]]; then
                    last_bloom_size_std=$(echo "$last_exp" | jq '.bloom_std.size_bits')
                    
                    if [[ "$last_bloom_size_std" == "$bloom_size_std" && "$ALWAYS_RETEST" == "false"  && "$run_bloom_part1" == "false" ]]; then
                        echo "⚠️  Bloom Filter (Part 1) parameters unchanged — skipping test."
                        should_rerun=false
                        fp_hits_bloom_std=$(echo "$last_exp" | jq '.bloom_std.fp_hits')
                    fi
                elif [[ "$filter_type" == "varbloom" ]]; then
                    last_varbloom_size=$(echo "$last_exp" | jq '.varbloom.size_bits')
                    
                    if [[ "$last_varbloom_size" == "$varbloom_size" && "$ALWAYS_RETEST" == "false"  && "$run_varbloom" == "false" ]]; then
                        echo "⚠️  VarBloom Filter parameters unchanged — skipping test."
                        should_rerun=false
                        fp_hits_varbloom=$(echo "$last_exp" | jq '.varbloom.fp_hits')
                    fi
                elif [[ "$filter_type" == "varbloom_time_decay" ]]; then
                    last_varbloom_time_decay_size=$(echo "$last_exp" | jq '.varbloom_time_decay.size_bits')
                    
                    if [[ "$last_varbloom_time_decay_size" == "$varbloom_time_decay_size" && "$ALWAYS_RETEST" == "false"  && "$run_varbloom_time_decay" == "false" ]]; then
                        echo "⚠️  VarBloom Time-Decay Filter parameters unchanged — skipping test."
                        should_rerun=false
                        fp_hits_varbloom_time_decay=$(echo "$last_exp" | jq '.varbloom_time_decay.fp_hits')
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

# Initialize Experiment Results to zero
    fp_hits_bloom_part_2=0
    fp_hits_bloom_part_3=0
    fp_hits_bloom_std=0
    fp_hits_varbloom=0
    fp_hits_varbloom_time_decay=0
    fp_hits_cuckoo=0

# Bloom Filter (Partitioned with 1 stage)
    bloom_size_std=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT)}")

    echo "----------------------------------"
    echo "Computed Bloom Filter (Part 1) Parameters:"
    echo "  - Available Memory: $AVAILABLE_MEMORY_BIT bits"
    echo "  - Bloom Filter Size: $bloom_size_std bits"
    echo "----------------------------------"

    should_rerun_experiment "bloom_std"
    if [[ "$should_rerun" == "true" && "$run_bloom_part1" == "true" ]]; then
        echo "Running Bloom Filter (Part 1) experiment..."
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
        echo "Using cached Bloom Filter (Part 1) results"
    fi


# Bloom Filter (Partitioned with 2 stages):
    bloom_size_part_2=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / 2)}")

    echo "----------------------------------"
    echo "Computed Bloom Filter Parameters:"
    echo "  - Available Memory: $AVAILABLE_MEMORY_BIT bits"
    echo "  - Bloom Filter Stage Size: $bloom_size_part_2 bits"
    echo "----------------------------------"

    # Run the analysis for the Bloom Filter-based solution
    should_rerun_experiment "bloom_part_2"
    if [[ "$should_rerun" == "true" && "$run_bloom_part2" == "true" ]]; then
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
    if [[ "$should_rerun" == "true" && "$run_bloom_part3" == "true" ]]; then
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


# VarBloom Filter: compute local test parameters
    varbloom_size=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT)}")
    hash_k=9

    get_best_k() {
        local m="$AVAILABLE_MEMORY_BIT"  # AVAILABLE_MEMORY_BIT
        local n="$N_BENIGN_CONNECTIONS"  # N_BENIGN_CONNECTIONS

        best_k=-1
        best_fp=1  # start with worst possible FP rate (100%)

        for k in {1..30}; do
            fp=$(awk -v m="$m" -v n="$n" -v k="$k" 'BEGIN {
                p = (1 - (1 / m));
                pow_inner = p^(k * n);
                fp_rate = (1 - pow_inner)^k;
                print fp_rate
            }')

            if awk "BEGIN {exit ($fp < $best_fp) ? 0 : 1}"; then
                best_fp="$fp"
                best_k="$k"
            fi
        done

        echo "$best_k"
        }
    
    hash_k=$(get_best_k) 
    
    echo "----------------------------------"
    echo "Computed VarBloom Filter Parameters:"
    echo "  - Available Memory: $AVAILABLE_MEMORY_BIT bits"
    echo "  - VarBloom Filter Size: $varbloom_size bits"
    echo "  - Ideal k: $hash_k"
    echo "----------------------------------"

    should_rerun_experiment "varbloom"
    if [[ "$should_rerun" == "true" && "$run_varbloom" == "true" ]]; then
        echo "Running VarBloom Filter experiment..."
        ./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy" --fn_suffix varbloom \
            --fp_test ptf-measure-fp-ds --test_name varbloom_fp_test \
            --filter_size $varbloom_size \
            --fingerprint_size 0 \
            --n_buckets $hash_k \
            --n_benign_connections $N_BENIGN_CONNECTIONS \
            --n_hostile_test_packets $N_HOSTILE_TEST_PACKETS \
            > results/fp_varbloom_results.txt

        fp_hits_varbloom=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_varbloom_results.txt)
    else
        echo "Using cached VarBloom Filter results"
    fi


# VarBloom Time-Decay Filter: compute local test parameters
    varbloom_time_decay_size=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / 2)}")
    hash_k_time_decay=9

    get_best_k_time_decay() {
        local m="$varbloom_time_decay_size"  # Half of AVAILABLE_MEMORY_BIT
        local n="$N_BENIGN_CONNECTIONS"      # N_BENIGN_CONNECTIONS

        best_k=-1
        best_fp=1  # start with worst possible FP rate (100%)

        for k in {1..30}; do
            fp=$(awk -v m="$m" -v n="$n" -v k="$k" 'BEGIN {
                p = (1 - (1 / m));
                pow_inner = p^(k * n);
                fp_rate = (1 - pow_inner)^k;
                print fp_rate
            }')

            if awk "BEGIN {exit ($fp < $best_fp) ? 0 : 1}"; then
                best_fp="$fp"
                best_k="$k"
            fi
        done

        echo "$best_k"
    }

    hash_k_time_decay=$(get_best_k_time_decay)

    echo "----------------------------------"
    echo "Computed VarBloom Time-Decay Filter Parameters:"
    echo "  - Available Memory: $varbloom_time_decay_size bits"
    echo "  - VarBloom Filter Size: $varbloom_time_decay_size bits"
    echo "  - Ideal k: $hash_k_time_decay"
    echo "----------------------------------"

    should_rerun_experiment "varbloom_time_decay"
    if [[ "$should_rerun" == "true" && "$run_varbloom_time_decay" == "true" ]]; then
        echo "Running VarBloom Time-Decay Filter experiment..."
        ./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy" --fn_suffix varbloom \
            --fp_test ptf-measure-fp-ds --test_name varbloom_time_decay_fp_test \
            --filter_size $varbloom_time_decay_size \
            --fingerprint_size 0 \
            --n_buckets $hash_k_time_decay \
            --n_benign_connections $N_BENIGN_CONNECTIONS \
            --n_hostile_test_packets $N_HOSTILE_TEST_PACKETS \
            > results/fp_varbloom_time_decay_results.txt

        fp_hits_varbloom_time_decay=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/fp_varbloom_time_decay_results.txt)
    else
        echo "Using cached VarBloom Time-Decay Filter results"
    fi


# Cuckoo Filter
    b=4 # number of entries per bucket
    n=$N_BENIGN_CONNECTIONS # number of items
    a=0.95 # load factor

    # Compute minimum needed entries (round down)
    min_needed_empty_spaces=$(awk "BEGIN {print int($n / $a)}")
    # Compute fingerprint size (round down)
    fingerprint_size=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / $min_needed_empty_spaces)}")
    # # fingerprint_size=$(bits per item * 0.95)
    # e=0.0001
    # result=$(awk -v a="$a" 'BEGIN {
    # log2_1_over_e = log(1/e) / log(2);  # log2(1/e)
    # result = (log2_1_over_e + 3);
    # print result
    # }')
    # echo "Result: $result"

    # $(awk -v a="$a" 'BEGIN {print(log(1/0.0001) / log(2)) }')

    # Compute number of buckets (round down)
    n_buckets=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / ($fingerprint_size * $b))}")
    # n_buckets=$(awk "BEGIN {print int(($min_needed_empty_spaces / 4) + 1)}") # round up [stick to exact a=0.95]

    # Compute total number of fingerprints
    n_fingerprints=$(awk "BEGIN {print int($n_buckets * $b)}")

    # Compute theoretical perfect amount of memory to achieve a=0.95
    ideal_fingerprint_size=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / $min_needed_empty_spaces)}")
    ideal_memory_bit=$(awk "BEGIN {print int(($n / $a) * $fingerprint_size)}")

    echo "----------------------------------"
    echo "Computed Cuckoo Filter Parameters:"
    echo "  - Available Memory: $AVAILABLE_MEMORY_BIT bits"
    echo "  - Number of Items: $n"
    echo "  - Load Factor: $a"
    echo "  - Minimum Needed Entries: $min_needed_empty_spaces"
    echo "  - Fingerprint Size: $fingerprint_size bits"
    echo "  - Number of Buckets: $n_buckets"
    echo "  - Total Number of Fingerprints: $n_fingerprints"
    echo "  - Theoretical Ideal Memory: $ideal_memory_bit bits"
    echo "  - Theoretical Ideal Fingerprint Size: $ideal_fingerprint_size bits"
    echo "----------------------------------"

    should_rerun_experiment "cuckoo"
    if [[ "$should_rerun" == "true" && "$run_cuckoo" == "true" ]]; then
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
    exp_fp_rate_varbloom=$(awk "BEGIN {print ($fp_hits_varbloom / ($N_HOSTILE_TEST_PACKETS))}")
    exp_fp_rate_varbloom_time_decay=$(awk "BEGIN {print ($fp_hits_varbloom_time_decay / ($N_HOSTILE_TEST_PACKETS))}")
    exp_fp_rate_cuckoo=$(awk "BEGIN {print ($fp_hits_cuckoo / ($N_HOSTILE_TEST_PACKETS))}")
    exp_fp_rate_cuckoo_ss=0
    exp_fp_rate_cuckoo_py=$(awk "BEGIN {print ($fp_hits_cuckoo_py / ($N_HOSTILE_TEST_PACKETS))}")


# Calculation of the theoretical exact ideal FP rates

    # Partitioned Bloom Filter with 2 stages
    theo_fp_rate_bloom_part_2=$(awk -v m="$AVAILABLE_MEMORY_BIT" -v n="$N_BENIGN_CONNECTIONS" -v k="2" '
    BEGIN {
        theo_fp_rate = (1 - (1 - k / m) ^ n) ^ k;
        print theo_fp_rate;
    }')

    # Partitioned Bloom Filter with 3 stages
    theo_fp_rate_bloom_part_3=$(awk -v m="$AVAILABLE_MEMORY_BIT" -v n="$N_BENIGN_CONNECTIONS" -v k="3" '
    BEGIN {
        theo_fp_rate = (1 - (1 - k / m) ^ n) ^ k;
        print theo_fp_rate;
    }')

    # Standard Bloom Filter
    theo_fp_rate_bloom_std=$(awk -v m="$AVAILABLE_MEMORY_BIT" -v n="$N_BENIGN_CONNECTIONS" -v k="1" '
    BEGIN {
        theo_fp_rate = (1 - (1 - k / m) ^ n) ^ k;
        print theo_fp_rate;
    }')

    # VarBloom Filter
    theo_fp_rate_varbloom=$(awk -v m="$AVAILABLE_MEMORY_BIT" -v n="$N_BENIGN_CONNECTIONS" -v k=$hash_k '
    BEGIN {
        theo_fp_rate = (1 - ((1 - (1 / m)) ^ (k * n))) ^ k;
        print theo_fp_rate;
    }')

    #Var Partitioned Bloom Filter
    theo_fp_rate_bloom_part_k=$(awk -v m="$AVAILABLE_MEMORY_BIT" -v n="$N_BENIGN_CONNECTIONS" -v k=$hash_k '
    BEGIN {
        theo_fp_rate = (1 - (1 - k / m) ^ n) ^ k;
        print theo_fp_rate;
    }')

    # VarBloom Time-Decay Filter
    theo_fp_rate_varbloom_time_decay=$(awk -v m="$varbloom_time_decay_size" -v n="$N_BENIGN_CONNECTIONS" -v k=$hash_k_time_decay '
    BEGIN {
        theo_fp_rate = (1 - ((1 - (1 / m)) ^ (k * n))) ^ k;
        print theo_fp_rate;
    }')

    # Cuckoo Filter
    real_a=$(awk "BEGIN {print ($N_BENIGN_CONNECTIONS / $n_fingerprints)}")
    echo $real_a
    b=$(awk "BEGIN {print ($AVAILABLE_MEMORY_BIT / $N_BENIGN_CONNECTIONS)}")
    theo_fp_rate_cuckoo=$(awk -v b="$b" -v a="$real_a" '
    BEGIN {
        theo_fp_rate = 1/(2^((b * a) - 3))
        print theo_fp_rate;
    }')

    # Cuckoo Filter with semi-sorting
    theo_fp_rate_cuckoo_ss=$(awk -v b="$b" -v a="$real_a" '
    BEGIN {
        theo_fp_rate = 1/(2^((b * a) - 2))
        print theo_fp_rate;
    }')

# Print the results
    echo "========================================================="
    echo "|                  False Positive Rates                 |"
    echo "========================================================="
    printf "| %-30s | %-12s | %-10s |\n" "Filter Type" "Theore. FP" "Experi. FP"
    echo "---------------------------------------------------------"

    printf "| %-30s | %-12s | %-10s |\n" "Bloom Filter (1 Part.)" \
        "$theo_fp_rate_bloom_std" \
        "$exp_fp_rate_bloom_std"

    printf "| %-30s | %-12s | %-10s |\n" "Bloom Filter (2 Part.)" \
        "$theo_fp_rate_bloom_part_2" \
        "$exp_fp_rate_bloom_part_2"

    printf "| %-30s | %-12s | %-10s |\n" "Bloom Filter (3 Part.)" \
        "$theo_fp_rate_bloom_part_3" \
        "$exp_fp_rate_bloom_part_3"

    printf "| %-30s | %-12s | %-10s |\n" "Partitioned 'VarBloom' Filter" \
        "$theo_fp_rate_bloom_part_k" \
        "N/A"

    printf "| %-30s | %-12s | %-10s |\n" "'VarBloom' Filter" \
        "$theo_fp_rate_varbloom" \
        "$exp_fp_rate_varbloom"

    printf "| %-30s | %-12s | %-10s |\n" "'VarBloom Time-Decay' Filter" \
        "$theo_fp_rate_varbloom_time_decay" \
        "$exp_fp_rate_varbloom_time_decay"

    printf "| %-30s | %-12s | %-10s |\n" "Cuckoo Filter" \
        "$theo_fp_rate_cuckoo" \
        "$exp_fp_rate_cuckoo"

    printf "| %-30s | %-12s | %-10s |\n" "Cuckoo Filter Python" \
        "$theo_fp_rate_cuckoo" \
        "$exp_fp_rate_cuckoo_py"

    printf "| %-30s | %-12s | %-10s |\n" "SS Cuckoo Filter" \
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