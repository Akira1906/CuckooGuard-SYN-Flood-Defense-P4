import socket
import fcntl
import struct
from pyroute2 import IPRoute

def get_ifindex(device, namespace = "None"):
    if namespace == "None":
        SIOCGIFINDEX = 0x8933  # IOCTL code to get interface index
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack('256s', device.encode('utf-8')[:15])
        result = fcntl.ioctl(sock.fileno(), SIOCGIFINDEX, ifreq)
        return struct.unpack('i', result[16:20])[0]  # Extract index
    else:
        """Get the network namespace-specific interface index"""
        ip = IPRoute()
        try:
            idx = None
            if namespace != "None":
                # Run inside the namespace to get the correct local index
                with ip.netns(namespace):
                    idx = ip.link_lookup(ifname=device)[0]
            else:
                # Get global ifindex (when running in root namespace)
                idx = ip.link_lookup(ifname=device)[0]
            
            print(f"Using ifindex {idx} for device {device} in namespace {namespace}")
            return idx
        finally:
            ip.close()
# # Example usage:
# if_index = get_ifindex("veth0")
# print(f"Interface Index of veth1: {if_index}")
