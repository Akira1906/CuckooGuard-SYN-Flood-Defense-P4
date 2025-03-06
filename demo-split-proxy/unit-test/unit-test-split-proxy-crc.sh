#! /bin/bash

set -e # Exit on error
set -x # Debugging output

cleanup() {
    sudo pkill --f simple_switch_grpc || true
    sudo pkill -f controller_grpc_crc.py || true
    sudo pkill -f tc_load.py || true
    sudo pkill -f xdp_load.py || true
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
sudo sysctl net.ipv6.conf.veth0.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth1.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth2.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth3.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth4.disable_ipv6=1
sudo sysctl net.ipv6.conf.veth5.disable_ipv6=1

# sleep 30



# Compile P4 Program
p4c --target bmv2 \
    --arch v1model \
    --p4runtime-files ../implementation/p4src/split-proxy-crc.p4info.txtpb \
    ../implementation/p4src/split-proxy-crc.p4\
    -o ../implementation/p4src/

# Remove old log file

/bin/rm -f split-proxy-crc-log.txt

sudo simple_switch_grpc \
     --device-id 1 \
     --log-file split-proxy-crc-log \
     --log-flush \
     --dump-packet-data 10000 \
     -i 1@veth0 \
     -i 2@veth2 \
     -i 3@veth4 \
     --no-p4 &

echo "Started simple_switch_grpc..."

sudo /bin/python3 ../implementation/ebpf/xdp_load.py None veth1 &
# XDP_PID=$!

# unload loaded TC programs
sudo tc qdisc del dev veth1 clsact 2>/dev/null || true

sudo /bin/python3 ../implementation/ebpf/tc_load.py None veth1 &
# TC_PID=$!

echo "Attached eBPF program to the servers interface (veth1)"

echo "Waiting 2 seconds before starting PTF test ..."
sleep 2

# Note that the mapping between switch port number and Linux interface
# names is best to make it correspond with those given when starting
# the simple_switch_grpc process.  The `ptf` process has no other way
# of getting this mapping other than by telling it on its command
# line.
# source /home/tristan/p4dev-python-venv/bin/activate
echo "Start SYN-Cookie Control Plane application"
cd ../implementation
python3 -u controller_grpc_crc.py &> ../unit-test/controller.log &
cd ../unit-test

sleep 1

# sudo -E ${P4_EXTRA_SUDO_OPTS} $(which ptf) \
#     --pypath "$P" \
#     -i 1@veth1 \
#     -i 2@veth3 \
#     -i 3@veth5 \
#     --test-params="grpcaddr='localhost:9559';p4info='../implementation/p4src/split-proxy.p4info.txtpb';config='../implementation/p4src/split-proxy.json'" \
#     --test-dir ptf

echo "PTF test finished.  Waiting 2 seconds before cleanup"
sleep 2
