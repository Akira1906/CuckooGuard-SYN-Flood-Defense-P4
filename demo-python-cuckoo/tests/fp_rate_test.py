from implementation.cuckoofilter import CuckooFilter
import random
import argparse
import struct


def ip_to_int(ip_str):
    parts = list(map(int, ip_str.split(".")))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def pack_connection_tuple(src_ip, dst_ip, src_port, dst_port):
    """Pack the 4-tuple into bytes like in P4 CRC32 hash input."""
    return struct.pack("!IIHH", ip_to_int(src_ip), ip_to_int(dst_ip), src_port, dst_port)


def generate_connections(n, avoid_set=None):
    items = set()
    while len(items) < n:
        src_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        dst_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        item = (src_ip, dst_ip, src_port, dst_port)
        if avoid_set and item in avoid_set:
            continue
        items.add(item)
    return items


def main():
    parser = argparse.ArgumentParser(description="Test Cuckoo Filter FP rate (4-tuple format)")

    parser.add_argument("--filter_size", type=int, required=False)
    parser.add_argument("--fingerprint_size", type=int, required=False, default=12)
    parser.add_argument("--n_buckets", type=int, required=False, default=1365)
    parser.add_argument("--n_benign_connections", type=int, required=False, default=5000)
    parser.add_argument("--n_hostile_test_packets", type=int, required=False, default=10000)

    args = parser.parse_args()

    filter = CuckooFilter(
        capacity=args.n_buckets,
        fingerprint_size=args.fingerprint_size,
        bucket_size=4,
        max_kicks=500
    )

    benign_set = generate_connections(args.n_benign_connections)
    packed_benign = {pack_connection_tuple(*conn) for conn in benign_set}

    for i, item in enumerate(packed_benign):
        try:
            filter.insert(item)
        except:
            print(f"⚠️  Insertion failed at {i}(filter may be full).")

    test_set = generate_connections(args.n_hostile_test_packets, avoid_set=benign_set)
    packed_test = [pack_connection_tuple(*conn) for conn in test_set]

    false_positives = sum(1 for item in packed_test if filter.contains(item))
    # fp_rate = false_positives / args.n_hostile_test_packets

    print("START RESULT")
    print(false_positives)
    print("END RESULT")


if __name__ == "__main__":
    main()