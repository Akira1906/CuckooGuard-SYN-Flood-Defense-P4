
for connections in $(seq 4000 1000 10000); do
    echo "Start experiment run with $memory bits available memory"
    ./compare-fp-rate.sh \
        --n_benign_connections $connections \
        --n_hostile_test_packets 100000 \
        --available_memory_bit 100000 \
        --always_retest True
done