AVAILABLE_MEMORY_BIT=65536
N_BENIGN_CONNECTIONS=5000

m = AVAILABLE_MEMORY_BIT
n = N_BENIGN_CONNECTIONS
# Find best k for partitioned Bloom Filter
best = (float('inf'), float('inf')) # FP, k
for k in range(1,30):
    curr = (pow(1 - pow((1 - k / m), n), k), k)
    best = min(curr, best)
    # print(f"k:{curr[1]} - {curr[0]}")

print(best)

# Find best k for standard Bloom Filter
# best = (float('inf'), float('inf')) # FP, k
# for k in range(1,30):
#     fp = 0
#     for i in range(1, m+1):
#         fp += * pow((i / m), k)
        
#     curr = (fp, k)
#     best = min(curr, best)
#     print(f"k:{curr[1]} - {curr[0]}")

# print(best)

# Find best k for standard Bloom Filter approximation
best = (float('inf'), float('inf')) # FP, k
for k in range(1,30):
    curr = (pow(1 - pow((1 - (1 / m)), k * n), k), k)
    best = min(curr, best)
    # print(f"k:{curr[1]} - {curr[0]}")

print(best)

# exp_fp_rate = 1/(2^((b * a) - 3))