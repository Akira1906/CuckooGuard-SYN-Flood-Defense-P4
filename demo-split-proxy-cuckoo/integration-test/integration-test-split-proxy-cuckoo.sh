#! /bin/bash

set -e # Exit on error
# set -x # Debugging output

cleanup() {
    # sudo pkill --f simple_switch_grpc || true
    sudo pkill -f controller_grpc_cuckoo.py || true
    sudo pkill -2 -f tc_load.py || true
    sudo pkill -2 -f xdp_load.py || true
    sudo pkill -f /sys/kernel/tracing/trace_pipe || true
    sudo pkill -f setup_mininet.py || true
    sudo ip netns del $MN_SERVER_NS || true
}

trap cleanup EXIT

/bin/rm -f controller.log
/bin/rm -f mininet.log
sudo /bin/rm -f pcap/*
/bin/rm -f server.log
sudo /bin/rm -f log/*
/bin/rm -f controller-cuckoo.log
/bin/rm -f ebpf-cuckoo.log

P="$HOME/p4dev-python-venv/bin/python"



echo "Start SYN-Cookie Control Plane application"
python3 -u ../implementation/controller_grpc_cuckoo.py --delay 5 --p4rt p4src/split-proxy-cuckoo_p4rt.txt &> controller-cuckoo.log &

echo "Setup Mininet"
sudo "${HOME}/p4dev-python-venv/bin/python" setup_mininet.py &

sleep 3
echo "Initialize eBPF debugging"
# Delete the existing BPF Map if it exists
sudo rm -rf /sys/fs/bpf/my_nonpercpu_map
# Start logging eBPF trace_pipe output to file
sudo cat /sys/kernel/tracing/trace_pipe >> "ebpf-cuckoo.log" 2>/dev/null &

sleep 1
MN_SERVER_NS='mininet-server-namespace'
# sudo lsns | grep server | grep "net "
MN_SERVER_PID=$(sudo lsns | grep "mininet:server" | grep "net " | awk '{print $4}')

sudo ip netns attach $MN_SERVER_NS $MN_SERVER_PID

BPFIFACE='server-eth0' # This needs to be set manually, mininet will automatically create these interfaces on startup
# Detach existing TC if
# sleep 2
# sudo ip netns exec $MN_SERVER_NS tc qdisc del dev $BPFIFACE clsact

echo "Loading new TC program on $BPFIFACE..."
sudo /bin/python3 ../implementation/ebpf/tc_load.py $MN_SERVER_NS $BPFIFACE 2 &

# sleep 2
# sudo ip netns exec $MN_SERVER_NS tc qdisc show dev server-eth0
# sudo ip netns exec $MN_SERVER_NS tc filter show dev server-eth0

# echo "+++++=========++++++++++"


sleep 1

echo "Loading new XDP program on $BPFIFACE..."
sudo /bin/python3 ../implementation/ebpf/xdp_load.py $MN_SERVER_NS $BPFIFACE XDP_FLAGS_SKB_MODE &

echo "Testing..."
sleep 15

LOG_FILE="log/server_scheduler.log"
SEARCH_STRING='"GET / HTTP/1.1" 200'

[[ -f "$LOG_FILE" ]] || { echo "❌ Log file not found!"; exit 1; }

COUNT=$(grep -c "$SEARCH_STRING" "$LOG_FILE")

[[ "$COUNT" -eq 2 ]] && echo "✅ Found twice!" || echo "❌ Found $COUNT times (Expected: 2)"
exit $(( COUNT != 2 ))