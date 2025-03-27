AVAILABLE_MEMORY_BIT=84227
N_BENIGN_CONNECTIONS=5000 # standard at 0.95
N_TEST_PACKETS=3000
a=0.95

b=4 # number of entries per bucket
n=$N_BENIGN_CONNECTIONS # number of items

# Compute minimum needed entries (round down)
min_needed_empty_spaces=$(awk "BEGIN {print int($n / $a)}")
# Compute fingerprint size (round down)
fingerprint_size=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / $min_needed_empty_spaces)}")

# Compute number of buckets (round down)
n_buckets=$(awk "BEGIN {print int($AVAILABLE_MEMORY_BIT / ($fingerprint_size * $b))}")
# n_buckets=$(awk "BEGIN {print int(($min_needed_empty_spaces / 4) + 1)}") # round up [stick to exact a=0.95]

# Compute total number of fingerprints
n_fingerprints=$(awk "BEGIN {print int($n_buckets * $b)}")

save_experiment_json() {
    results_json="results/recirc-experiment_history.json"

    # Create new experiment entry
    new_entry=$(jq -n \
        --arg timestamp "$(date +"%Y-%m-%d %H:%M:%S")" \
        --arg load_factor "$load_factor" \
        --arg n_preloaded_connections "$n_preloaded_connections" \
        --arg fingerprint_size "$fingerprint_size" \
        --arg n_buckets "$n_buckets" \
        --arg n_benign_connections "$N_BENIGN_CONNECTIONS" \
        --arg n_test_packets "$N_TEST_PACKETS" \
        --arg packet_count "$packet_count" \
        '{
            "timestamp": $timestamp,
            "load_factor": $load_factor | tonumber,
            "n_preloaded_connections": $n_preloaded_connections | tonumber,
            "fingerprint_size": $fingerprint_size | tonumber,
            "n_buckets": $n_buckets | tonumber,
            "n_benign_connections": $n_benign_connections | tonumber,
            "n_test_packets": $n_test_packets | tonumber,
            "packet_count": $packet_count | tonumber
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

for load_factor in $(seq 0.3 0.05 0.95); do
    echo "Start experiment run with load factor: $load_factor"

    for i in {1..4}; do
        echo "Iteration $i for load factor: $load_factor"

        n_preloaded_connections=$(awk "BEGIN {print int($n_fingerprints * $load_factor)}")

        ./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy-cuckoo" --fn_suffix cuckoo \
                --fp_test ptf-measure-recirc-ds --test_name cuckoo_recirculation_test \
                --filter_size 84227\
                --fingerprint_size $fingerprint_size \
                --n_buckets $n_buckets \
                --n_benign_connections $n_preloaded_connections \
                --n_test_packets $N_TEST_PACKETS \
                --no_controller \
                > results/recirc_cuckoo_results.txt

        packet_count=$(awk '/START RESULT/{flag=1;next}/END RESULT/{flag=0}flag' results/recirc_cuckoo_results.txt)
        echo "packet_count: $packet_count"
        # Save experiment results to JSON history
        save_experiment_json
    done
done

python recirc-exp-var_load_factor_visualize.py
done

python recirc-exp-var_load_factor_visualize.py