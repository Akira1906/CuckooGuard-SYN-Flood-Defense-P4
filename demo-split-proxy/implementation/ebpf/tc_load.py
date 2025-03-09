#!/usr/bin/python
"SmartCookie project, © Sophia Yoo, Xiaoqi Chen @ Princeton University. License: AGPLv3"

from bcc import BPF
import pyroute2
import time
import sys
from ctypes import CDLL  # Import CDLL for namespace switching
import os
from tc_helper import get_ifindex

def main(namespace, device, IFINDEX = None):
    # Define the namespace switching constant
    CLONE_NEWNET = 0x40000000
    libc = CDLL("libc.so.6")  # Load the C standard library
    script_dir = script_dir = os.path.dirname(os.path.abspath(__file__))

    offload_device = None

    # CONSTANTS TO PASS TO THE BPF program
    DEBUG_MODE = 1
    print(f"IFINDEX{IFINDEX}") 
    if not IFINDEX:
        IFINDEX = get_ifindex(device) # this can also be set manually, check ip -a

    flags = 0
    mode = BPF.SCHED_CLS

    # Switch to the specified namespace
    if namespace != "None":
        try:
            ns_fd = os.open(f"/var/run/netns/{namespace}", os.O_RDONLY)
            libc.setns(ns_fd, CLONE_NEWNET)
            os.close(ns_fd)
        except OSError as e:
            print(f"Failed to switch to namespace {namespace}: {e}")
            sys.exit(1)

    # Load the eBPF program
    with open(os.path.join(script_dir, 'egress.c'), 'r') as f:
        bpf_src = f.read()

    # print("path::" + os.path.join(script_dir, 'include'))

    b = BPF(
        text=bpf_src,
        device=offload_device,
        cflags=['-Ofast', '-I' + os.path.join(script_dir, 'include'),
                f'-DDEBUG={DEBUG_MODE}',
                f'-DIFINDEX={IFINDEX}'
            ]
    )
    fn = b.load_func("tc_egress", mode, offload_device)

    # Attach the eBPF program using pyroute2
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index

    # Add clsact qdisc and attach the filter
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
        parent="ffff:fff3", classid=1, direct_action=True)

    print(
        f"SmartCookie Server Agent: TC egress program is loaded in namespace '{namespace}', hit CTRL+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nRemoving filter from device")
        ip.tc("del", "clsact", idx)

    # Release resources
    ipdb.release()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:   python3 {} <namespace> <if_name>".format(sys.argv[0]))
        print("Example: python3 {} net1 veth1".format(sys.argv[0]))
        print("Alternatively:")
        print("Usage:   python3 {} <namespace> <if_name> <if_index>".format(sys.argv[0]))
        print("Example: python3 {} net1 veth1 3")
        sys.exit(-1)

    namespace = sys.argv[1]
    device = sys.argv[2]
    if len(sys.argv) == 4:
        IFINDEX = sys.argv[3]
        main(namespace, device, IFINDEX)
    else:
        main(namespace, device)
