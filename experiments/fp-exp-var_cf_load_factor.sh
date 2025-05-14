

for load_factor in $(seq 0.3 0.05 0.95); do
    echo "Start experiment run with load factor $load_factor"
    ./compare-fp-rate.sh \
        --n_benign_connections 5000 \
        --n_test_packets 100000 \
        --available_memory_bit 84227 \
        --always_retest True \
        --output_file results/fp-var_cf_load_factor.json\
        --cuckoo_var_load $load_factor \
        --test
done

python fp-exp-var_cf_load_factor_visualize.py