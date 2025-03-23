
for connections in $(seq 4000 100 9000); do
    echo "Start experiment run with $connections connections"
    ./compare-fp-rate.sh \
        --n_benign_connections $connections \
        --n_hostile_test_packets 1000000000 \
        --available_memory_bit 100000 \
        --always_retest True \
        --output_file results/fp-var_connections.json
done