#!/bin/bash

# example usage; script_name ../demo-split-proxy crc

APP_PATH=$1 # root directory of the according demo-implementation
FN_SUFFIX=$2 # according file suffix to be used, e.g. crc, cuckoo
FP_TEST=$3 # file path to the folder of the ptf test to run e.g. ptf-analyze-split-proxy-ds
TEST_NAME=$4

# APP_PATH="../demo-split-proxy"
# FN_SUFFIX="crc"

set -e # Exit on error
# set -x # Debugging output

cleanup() {
    sudo pkill --f simple_switch_grpc || true
    sudo pkill -f "controller_grpc_$FN_SUFFIX.py" || true
    sudo pkill -2 -f tc_load.py || true
    sudo pkill -2 -f xdp_load.py || true
    sudo pkill -f /sys/kernel/tracing/trace_pipe || true
    # sudo ip link del veth0 || true
    # sudo ip link del veth2 || true
    # sudo ip link del veth4 || true
    # sudo ip link del veth6 || true
}

trap cleanup EXIT

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


# Compile P4 Program
p4c --target bmv2 \
    --arch v1model \
    --p4runtime-files "$APP_PATH/implementation/p4src/split-proxy-$FN_SUFFIX.p4info.txtpb" \
    "$APP_PATH/implementation/p4src/split-proxy-$FN_SUFFIX.p4"\
    -o "$APP_PATH/implementation/p4src/"

# Remove old log file

/bin/rm -f "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log.txt"
/bin/rm -f "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log.1.txt"
/bin/rm -f "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log.2.txt"
/bin/rm -f "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log.3.txt"
/bin/rm -f "logs/$TEST_NAME-ebpf-$FN_SUFFIX.log"

sudo simple_switch_grpc \
     --device-id 1 \
     --log-file "logs/$TEST_NAME-split-proxy-$FN_SUFFIX-log" \
     --log-flush \
     --dump-packet-data 10000 \
     -i 1@veth0 \
     -i 2@veth2 \
     -i 3@veth4 \
     -i 68@veth6 \
     -i 196@veth7 \
     --no-p4 &

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
    -i 68@veth6 \
    -i 196@veth7 \
    --test-params="grpcaddr='localhost:9559';p4info='$APP_PATH/implementation/p4src/split-proxy-$FN_SUFFIX.p4info.txtpb';config='$APP_PATH/implementation/p4src/split-proxy-$FN_SUFFIX.json'" \
    --test-dir $FP_TEST

echo "PTF test finished.  Waiting 2 seconds before cleanup"
sleep 2
