



AVAILABLE_MEMORY_BIT=84227
N_BENIGN_CONNECTIONS=5000
N_TEST_PACKETS=10000
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

TEST_NAME=filter-elements-comparison
FP_TEST=ptf-measure-fel-ds

n_constant_connections=$(awk "BEGIN {print($N_BENIGN_CONNECTIONS - 3000)}")

# 1. Run with Cuckoo Filter
FN_SUFFIX=cuckoo
./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy-cuckoo" --fn_suffix $FN_SUFFIX \
        --fp_test $FP_TEST --test_name $TEST_NAME \
        --filter_size 84227 \
        --fingerprint_size $fingerprint_size \
        --n_buckets $n_buckets \
        --n_benign_connections $n_constant_connections \
        --n_test_packets $N_TEST_PACKETS \
        --filter_time_decay 16 \
        --debug \
        > results/filter_elements_cuckoo_results.txt


cuckoo_p4_debug_fn="logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log"


# 2. Run Bloom Filter with enabled time-decaying
FN_SUFFIX=varbloom

./analyze-split-proxy-ds.sh --app_path "../demo-split-proxy" --fn_suffix $FN_SUFFIX \
        --fp_test $FP_TEST --test_name $TEST_NAME \
        --filter_size 84227 \
        --fingerprint_size $fingerprint_size \
        --n_buckets $hash_k \
        --n_benign_connections $n_constant_connections \
        --n_test_packets $N_TEST_PACKETS \
        --filter_time_decay 16 \
        --debug \
        > results/filter_elements_varbloom_results.txt 


python fel-exp-comparison-result_extraction.py
python fel-exp-comparison_visualize.py