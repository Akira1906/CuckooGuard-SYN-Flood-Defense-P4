#! /bin/bash

P=${HOME}'/p4dev-python-venv/bin/python'

echo "P is: $P"
source ${HOME}/p4dev-python-venv/bin/activate

# Only show a list of tests
#ptf --pypath "$P" --test-dir ptf --list
#exit 0

# set -x
p4c --target bmv2 \
    --arch v1model \
    --p4runtime-files p4src/split-proxy.p4info.txtpb \
    p4src/split-proxy.p4\
    -o p4src/

# Remove any log file written in an earlier run, otherwise
# simple_switch_grpc will append the new log messages to the end of
# the existing file.
/bin/rm -f ss-log.txt

sudo simple_switch_grpc \
     --device-id 1 \
     --log-file ../implementation/split-proxy-log \
     --log-flush \
     --dump-packet-data 10000 \
     -i 1@veth0 \
     -i 2@veth2 \
     -i 3@veth4 \
     --no-p4 &
echo ""
echo "Started simple_switch_grpc..."

sudo ${P} xdp_load.py None veth5

sudo ${P} tc_load.py None veth5

echo "Attached eBPF program to the servers interface (veth5)"

echo "Waiting 2 seconds before starting PTF test ..."
sleep 2
    #  -i 3@veth6 \
    #  -i 4@veth8 \
    #  -i 5@veth10 \
    #  -i 6@veth12 \
    #  -i 7@veth14 \
# Note that the mapping between switch port number and Linux interface
# names is best to make it correspond with those given when starting
# the simple_switch_grpc process.  The `ptf` process has no other way
# of getting this mapping other than by telling it on its command
# line.
# source /home/tristan/p4dev-python-venv/bin/activate
# echo "Start SYN-Cookie Control Plane application"
# cd ../implementation
# python3 -u controller_grpc.py &> controller.log &
# cd ../unit-test
# sleep 2
# sudo netstat -tulnp
# sleep 20

sudo -E ${P4_EXTRA_SUDO_OPTS} $(which ptf) \
    --pypath "$P" \
    -i 1@veth1 \
    -i 2@veth3 \
    -i 3@veth5 \
    --test-params="grpcaddr='localhost:9559';p4info='../implementation/p4src/split-proxy.p4info.txtpb';config='../implementation/p4src/split-proxy.json'" \
    --test-dir ptf
    # -i 3@veth7 \
    # -i 4@veth9 \
    # -i 5@veth11 \
    # -i 6@veth13 \
    # -i 7@veth15 \

echo ""
echo "PTF test finished.  Waiting 2 seconds before killing simple_switch_grpc ..."
sleep 2
sudo pkill --signal 9 --list-name simple_switch_grpc
# sudo pkill --signal 15 -f controller-grpc.py
echo ""
echo "Verifying that there are no simple_switch_grpc processes running any longer in 4 seconds ..."
sleep 4
ps axguwww | grep simple_switch_grpc
