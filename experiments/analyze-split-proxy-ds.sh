#!/bin/bash

set -e # Exit on error
# set -x # Debugging output

# Default values (if applicable)
APP_PATH=""
FN_SUFFIX=""
FP_TEST=""
TEST_NAME=""
FILTER_SIZE=""
FINGERPRINT_SIZE=""
N_BUCKETS=""
N_BENIGN_CONNECTIONS=""
N_HOSTILE_TEST_PACKETS=""

# Process named arguments
ARGS=$(getopt -o a:f:p:t:s:g:b:c:h: --long app_path:,fn_suffix:,fp_test:,test_name:,filter_size:,fingerprint_size:,n_buckets:,n_benign_connections:,n_hostile_test_packets: -- "$@")
if [[ $? -ne 0 ]]; then
    echo "Error: Invalid arguments"
    exit 1
fi

eval set -- "$ARGS"

while true; do
    case "$1" in
        -a|--app_path) APP_PATH="$2"; shift 2 ;;
        -f|--fn_suffix) FN_SUFFIX="$2"; shift 2 ;;
        -p|--fp_test) FP_TEST="$2"; shift 2 ;;
        -t|--test_name) TEST_NAME="$2"; shift 2 ;;
        -s|--filter_size) FILTER_SIZE="$2"; shift 2 ;;
        -g|--fingerprint_size) FINGERPRINT_SIZE="$2"; shift 2 ;;
        -b|--n_buckets) N_BUCKETS="$2"; shift 2 ;;
        -c|--n_benign_connections) N_BENIGN_CONNECTIONS="$2"; shift 2 ;;
        -h|--n_hostile_test_packets) N_HOSTILE_TEST_PACKETS="$2"; shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done

# Ensure required parameters are provided
if [[ -z "$APP_PATH" || -z "$FN_SUFFIX" || -z "$FP_TEST" || -z "$TEST_NAME" || -z "$FILTER_SIZE" || -z "$FINGERPRINT_SIZE" || -z "$N_BUCKETS" || -z "$N_BENIGN_CONNECTIONS" || -z "$N_HOSTILE_TEST_PACKETS" ]]; then
    echo "Usage: $0 --app_path <path> --fn_suffix <suffix> --fp_test <test_folder> --test_name <name> --filter_size <size> --fingerprint_size <size> --n_buckets <count> --n_benign_connections <count> --n_hostile_test_packets <count>"
    exit 1
fi

cleanup() {
    sudo pkill --f simple_switch_grpc || true
    sudo pkill -f "controller_grpc_$FN_SUFFIX.py" || true
    sudo pkill -2 -f tc_load.py || true
    sudo pkill -2 -f xdp_load.py || true
    sudo pkill -f /sys/kernel/tracing/trace_pipe || true
    echo "cleaning up"
    # sudo ip link del veth0 || true
    # sudo ip link del veth2 || true
    # sudo ip link del veth4 || true
    # sudo ip link del veth6 || true
}
# trap cleanup EXIT
set +e
trap cleanup EXIT ERR

# Compute dependent values
FILTER_SIZE_MINUS_ONE=$((FILTER_SIZE - 1))
FILTER_SIZE_MINUS_ONE="32w$FILTER_SIZE_MINUS_ONE"
FILTER_SIZE="32w$FILTER_SIZE"

N_BUCKETS_MINUS_ONE=$((N_BUCKETS - 1))
N_BUCKETS_MINUS_ONE="$N_BUCKETS_MINUS_ONE"


# Compile P4 Program
p4c --target bmv2 \
    --arch v1model \
    --p4runtime-files "$APP_PATH/implementation/p4src/split-proxy-$FN_SUFFIX.p4info.txtpb" \
    "$APP_PATH/implementation/p4src/split-proxy-$FN_SUFFIX.p4" \
    "-D FILTER_SIZE=$FILTER_SIZE" \
    "-D FILTER_SIZE_MINUS_ONE=$FILTER_SIZE_MINUS_ONE" \
    "-D FINGERPRINT_SIZE=$FINGERPRINT_SIZE" \
    "-D N_BUCKETS=$N_BUCKETS" \
    "-D N_BUCKETS_MINUS_ONE=$N_BUCKETS_MINUS_ONE" \
    -o "$APP_PATH/implementation/p4src/"
echo "compiled P4 program.."

P=${HOME}'/p4dev-python-venv/bin/python'

echo "P is: $P"
source ${HOME}/p4dev-python-venv/bin/activate

# Create veth pairs correctly
sudo ip link add veth0 type veth peer name veth1 || true
sudo ip link add veth2 type veth peer name veth3 || true
sudo ip link add veth4 type veth peer name veth5 || true
sudo ip link add veth6 type veth peer name veth7 || true

# Bring up root namespace interfaces
sudo ip link set veth0 up || true
sudo ip link set veth2 up || true
sudo ip link set veth4 up || true
sudo ip link set veth1 up || true
sudo ip link set veth3 up || true
sudo ip link set veth5 up || true
sudo ip link set veth6 up || true
sudo ip link set veth7 up || true
sudo sysctl net.ipv6.conf.veth0.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth1.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth2.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth3.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth4.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth5.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth6.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth7.disable_ipv6=1

# Remove old log files

/bin/rm -f "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log.txt"
/bin/rm -f "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log.1.txt"
/bin/rm -f "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log.2.txt"
/bin/rm -f "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log.3.txt"
/bin/rm -f "logs/$TEST_NAME-ebpf-$FN_SUFFIX.log"

sudo simple_switch_grpc \
     --device-id 1 \
     -i 1@veth0 \
     -i 2@veth2 \
     -i 3@veth4 \
     -i 68@veth6 \
     -i 196@veth7 \
     --no-p4 &
    #  --log-file "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log" \
    #  --log-flush \
    #  --dump-packet-data 10000 \
echo "Started simple_switch_grpc..."

BPFIFACE="veth5"

echo "Unloading any existing eBPF programs on $BPFIFACE..."

# Ensure any previously attached XDP program is removed
sudo ip link set dev "$BPFIFACE" xdp off 2>/dev/null || true
# Delete the existing BPF Map if it exists
sudo rm -rf /sys/fs/bpf/my_nonpercpu_map
# Ensure any previously attached TC programs are removed
sudo tc qdisc del dev "$BPFIFACE" clsact 2>/dev/null || true


echo "Loading new TC program on $BPFIFACE..."
sudo /bin/python3 "$APP_PATH/implementation/ebpf/tc_load.py" None "$BPFIFACE" &

# Wait a moment to ensure TC is properly attached
sleep 1

echo "Loading new XDP program on $BPFIFACE..."
sudo /bin/python3 "$APP_PATH/implementation/ebpf/xdp_load.py" None "$BPFIFACE" &

# Wait a moment to ensure XDP is properly attached
sleep 1

# Start logging eBPF trace_pipe output to file
sudo cat /sys/kernel/tracing/trace_pipe >> "logs/$TEST_NAME-ebpf-$FN_SUFFIX.log" 2>/dev/null &

echo "Attached eBPF programs to the server's interface ($BPFIFACE)"


echo "Start SYN-Cookie Control Plane application"
cd "$APP_PATH/implementation"
python3 -u "controller_grpc_$FN_SUFFIX.py" &> "../../experiments/logs/$TEST_NAME-controller-$FN_SUFFIX.log" &
cd ../../experiments

sleep 1

# Note that the mapping between switch port number and Linux interface
# names is best to make it correspond with those given when starting
# the simple_switch_grpc process.  The `ptf` process has no other way
# of getting this mapping other than by telling it on its command
# line.

sudo -E ${P4_EXTRA_SUDO_OPTS} $(which ptf) \
    --pypath "$P" \
    -i 1@veth1 \
    -i 2@veth3 \
    -i 3@veth5 \
    -i 4@veth4 \
    --test-params="grpcaddr='localhost:9559';n_benign_connections='$N_BENIGN_CONNECTIONS';n_hostile_test_packets='$N_HOSTILE_TEST_PACKETS'" \
    --test-dir $FP_TEST

echo "PTF test finished.  Waiting 2 seconds before cleanup"
sleep 2
