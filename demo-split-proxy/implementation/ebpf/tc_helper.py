import socket
import fcntl
import struct

def get_ifindex(interface_name):
    SIOCGIFINDEX = 0x8933  # IOCTL code to get interface index
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', interface_name.encode('utf-8')[:15])
    result = fcntl.ioctl(sock.fileno(), SIOCGIFINDEX, ifreq)
    return struct.unpack('i', result[16:20])[0]  # Extract index

# # Example usage:
# if_index = get_ifindex("veth0")
# print(f"Interface Index of veth1: {if_index}")
