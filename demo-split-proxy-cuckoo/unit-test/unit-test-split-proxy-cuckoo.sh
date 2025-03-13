#! /bin/bash

set -e # Exit on error
# set -x # Debugging output

cleanup() {
    sudo pkill --f simple_switch_grpc || true
    sudo pkill -f controller_grpc_cuckoo.py || true
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

# Only show a list of tests
#ptf --pypath "$P" --test-dir ptf --list
#exit 0

# Clean up existing veth pairs and namespaces
# sudo ip link del veth0 || true
# sudo ip link del veth2 || true
# sudo ip link del veth4 || true

# sudo ip netns del net1 || true
# sudo ip netns del net2 || true

# Recreate namespaces
# sudo ip netns add net1
# sudo ip netns add net2

# Create veth pairs correctly
sudo ip link add veth0 type veth peer name veth1 || true
sudo ip link add veth2 type veth peer name veth3 || true
sudo ip link add veth4 type veth peer name veth5 || true
sudo ip link add veth6 type veth peer name veth7 || true

# Move veth interfaces into namespaces
# sudo ip link set veth1 netns net1
# sudo ip link set veth3 netns net1
# sudo ip link set veth5 netns net1

# Bring up interfaces inside namespaces
# sudo ip netns exec net1 ip link set veth1 up
# sudo ip netns exec net1 ip link set veth3 up
# sudo ip netns exec net1 ip link set veth5 up

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
    --p4runtime-files ../implementation/p4src/split-proxy-cuckoo.p4info.txtpb \
    ../implementation/p4src/split-proxy-cuckoo.p4\
    -o ../implementation/p4src/

# Remove old log file

/bin/rm -f split-proxy-cuckoo-log.txt
/bin/rm -f ebpf-cuckoo.log

sudo simple_switch_grpc \
     --device-id 1 \
     --log-file split-proxy-cuckoo-log \
     --log-flush \
     --dump-packet-data 10000 \
     -i 1@veth0 \
     -i 2@veth2 \
     -i 3@veth4 \
     --no-p4 &

    #  -i 68@veth6 \
    #  -i 196@veth7 \

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
sudo /bin/python3 ../implementation/ebpf/tc_load.py None "$BPFIFACE" &

# Wait a moment to ensure TC is properly attached
sleep 1

echo "Loading new XDP program on $BPFIFACE..."
sudo /bin/python3 ../implementation/ebpf/xdp_load.py None "$BPFIFACE" &

# Wait a moment to ensure XDP is properly attached
sleep 1

# Start logging eBPF trace_pipe output to file
sudo cat /sys/kernel/tracing/trace_pipe >> "ebpf-cuckoo.log" 2>/dev/null &

echo "Attached eBPF programs to the server's interface ($BPFIFACE)"


echo "Start SYN-Cookie Control Plane application"
cd ../implementation
python3 -u controller_grpc_cuckoo.py &> ../unit-test/controller-cuckoo.log &
cd ../unit-test

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
    --test-params="grpcaddr='localhost:9559';p4info='../implementation/p4src/split-proxy-cuckoo.p4info.txtpb';config='../implementation/p4src/split-proxy-cuckoo.json'" \
    --test-dir ptf

echo "PTF test finished.  Waiting 2 seconds before cleanup"
sleep 2
