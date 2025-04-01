
for memory in $(seq 45000 1000 100000); do
    echo "Start experiment run with $memory bits available memory"
    ./compare-fp-rate.sh \
        --n_benign_connections 5000 \
        --n_test_packets 100000 \
        --available_memory_bit $memory \
        --always_retest True \
        --output_file results/fp-var_memory.json \
        --fake
done

python fp-exp-var_memory_visualize.py
python fp-exp-var_mem_per_connection_visualize.py