
for memory in $(seq 30000 2500 100000); do
    echo "Start experiment run with $memory bits available memory"
    ./compare-fp-rate.sh \
        --n_benign_connections 5000 \
        --n_hostile_test_packets 100000 \
        --available_memory_bit $memory \
        --always_retest True \
        --output_file results/fp-var_memory.json
done