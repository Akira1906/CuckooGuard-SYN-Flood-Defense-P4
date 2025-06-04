#!/usr/bin/python

import os
import time
import sys
from bcc import BPF  # this needs apt install python3-bpfcc and then use system wide python3
from ctypes import CDLL

def main(namespace, device, xdp_offload_mode="XDP_FLAGS_DRV_MODE"):
    # CONSTANT TO PASS TO THE BPF program
    DEBUG_MODE = 1

    CLONE_NEWNET = 0x40000000
    libc = CDLL("libc.so.6")
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Enter the namespace
    if namespace != "None":
        ns_fd = os.open("/var/run/netns/{}".format(namespace), os.O_RDONLY)
        libc.setns(ns_fd, CLONE_NEWNET)

    if xdp_offload_mode == "XDP_FLAGS_DRV_MODE":
        # Flags for XDP mode
        XDP_FLAGS_DRV_MODE = 1 << 2
        flags = XDP_FLAGS_DRV_MODE
    elif xdp_offload_mode == "XDP_FLAGS_SKB_MODE":
        XDP_FLAGS_SKB_MODE = 1 << 1
        flags = XDP_FLAGS_SKB_MODE  # Use SKB (generic) mode for veth interfaces
    else:
        raise Exception("Unknown <XDP OFFLOAD MODE>")

    mode = BPF.XDP

    # Load BPF program
    with open(os.path.join(script_dir, 'ingress.c'), 'r') as f:
        bpf_src = f.read()

    b = BPF(text=bpf_src, cflags=[
            '-Ofast', '-I' + os.path.join(script_dir, 'include'), f'-DDEBUG={DEBUG_MODE}'])
    fn = b.load_func("xdp_ingress", mode)
    b.attach_xdp(device, fn, flags)

    print("CuckooGuard Server Agent: XDP ingress program loaded in namespace '{}', hit CTRL+C to stop.".format(namespace))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nRemoving filter from device")
        b.remove_xdp(device, flags)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:   python3 {} <namespace> <if_name>".format(sys.argv[0]))
        print("Example: python3 {} net1 veth1".format(sys.argv[0]))
        print("Alternatively:")
        print("Usage:   python3 {} <namespace> <if_name> <XDP_OFFLOAD_MODE>".format(sys.argv[0]))
        sys.exit(-1)
    
    
    namespace = sys.argv[1]
    device = sys.argv[2]
    if len(sys.argv) == 4:
        xdp_offload_mode = sys.argv[3]
        main(namespace, device, xdp_offload_mode)
    else:
        main(namespace, device)
