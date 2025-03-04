import os
import time
import sys
from bcc import BPF
from ctypes import CDLL 

CLONE_NEWNET = 0x40000000
libc = CDLL("libc.so.6")

if len(sys.argv) < 3:
    print("Usage:   python3 {} <namespace> <if_name>".format(sys.argv[0]))
    print("Example: python3 {} net1 veth1".format(sys.argv[0]))
    sys.exit(-1)

namespace = sys.argv[1]
device = sys.argv[2]

# Enter the namespace
if namespace is not "None":
    ns_fd = os.open("/var/run/netns/{}".format(namespace), os.O_RDONLY)
    libc.setns(ns_fd, CLONE_NEWNET)

# Flags for XDP mode
XDP_FLAGS_DRV_MODE = 1 << 2
flags = XDP_FLAGS_DRV_MODE
mode = BPF.XDP

# Load BPF program
with open('ingress.c', 'r') as f:
    bpf_src = f.read()

b = BPF(text=bpf_src, cflags=['-Ofast', '-I./include/'])
fn = b.load_func("xdp_ingress", mode)
b.attach_xdp(device, fn, flags)

print("XDP ingress program loaded in namespace '{}', hit CTRL+C to stop.".format(namespace))
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nRemoving filter from device")
    b.remove_xdp(device, flags)