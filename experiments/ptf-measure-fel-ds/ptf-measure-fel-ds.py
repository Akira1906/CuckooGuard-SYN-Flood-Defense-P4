# Note: 9559 is the default TCP port number on which the
# simple_switch_grpc process is listening for incoming TCP connections,
# over which a client program can send P4Runtime API messages to
# simple_switch_grpc.

# p4c --target bmv2 --arch v1model --p4runtime-files proxy.p4info.txtpb proxy.p4

from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
import argparse
import os
from p4utils.utils.helper import load_topo
import logging
import ptf.mask as mask
import ptf
import ptf.testutils as tu
from ptf.base_tests import BaseTest
import p4runtime_sh.shell as sh
import ptf.testutils
from scapy.all import Ether, IP, TCP, Raw
from time import sleep
import random
import asyncio

######################################################################
# Configure logging
######################################################################


logger = logging.getLogger(None)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


def get_packet_mask(pkt):
    pkt_mask = mask.Mask(pkt)

    pkt_mask.set_do_not_care_all()

    return pkt_mask


class Test(BaseTest):

    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

    def tearDown(self):
        logging.debug("tearDown()")
        # sh.teardown()


class RecircTest(Test):

    def __init__(self):
        super().__init__()
        self.packet_lock = asyncio.Lock()  # Lock for synchronizing packet sending

    # def setUp(self):
    #     super().setUp()  # Call the parent class's setUp method to initialize self.ss

    def runTest(self):
        self.client_mac = "00:00:0a:00:01:01"  # h1 MAC
        self.attacker_mac = "00:00:0a:00:01:02"  # h2 MAC
        self.server_mac = "00:00:0a:00:01:03"  # h3 MAC
        self.switch_client_mac = "00:01:0a:00:01:01"  # s1 client MAC
        self.switch_attacker_mac = "00:01:0a:00:01:01"  # s1 attacker MAC
        self.switch_server_mac = "00:01:0a:00:01:01"  # s1 server MAC

        self.client_ip = "10.0.1.1"
        self.attacker_ip = "10.0.1.2"
        self.server_ip = "10.0.1.3"

        self.client_port = 1234
        self.server_port = 81
        self.attacker_port = 5555

        self.client_iface = 1  # h1 -> s1
        self.attacker_iface = 2  # h2 -> s1
        self.server_iface = 3  # h3 -> s1
        self.ebpf_iface = 4

        n_benign_connections = int(tu.test_param_get("n_benign_connections"))
        self.n_test_packets = int(tu.test_param_get("n_test_packets"))

        self.packet_processing_delay = 0.001
        self.connection_iat = 0.005

        # Add and remove a new element repeatedly
        new_connections_set = set()
        while len(new_connections_set) < self.n_test_packets:
            test_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
            test_port = random.randint(1024, 65535)
            new_connections_set.add((test_ip, test_port))

        # Use the current event loop instead of asyncio.run()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.simulate_connections(new_connections_set))
        
    def generate_n_connections(self, n_connections):
        connections_ip_port = set()  # e.g. (10.0.0.1, 3737)

        while len(connections_ip_port) < n_connections:
            ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
            if ip == self.server_ip:
                continue
            port = random.randint(1024, 65535)
            connections_ip_port.add((ip, port))
        return connections_ip_port

    async def simulate_connections(self, new_connections_set, delay=5):
        for i, (test_ip, test_port) in enumerate(new_connections_set):
            time_offset = 1 + (i * self.connection_iat)
            logging.debug(f"Scheduling connection simulation for {test_ip}:{test_port} at time offset {time_offset}")
            asyncio.create_task(self.simulate_connection(test_ip, test_port, delay, time_offset))
            # await asyncio.sleep(self.connection_iat)  # Add delay between starting each connection
        await asyncio.sleep((self.connection_iat * self.n_test_packets) + 15)
    async def simulate_connection(self, test_ip, test_port, delay, start_offset):
        await asyncio.sleep(start_offset)  # Ensure the connection starts at the correct time
        logging.debug(f"Simulating connection insertion for {test_ip}:{test_port}")
        await self.filter_connection_insertion(test_ip, test_port)
        logging.debug(f"Waiting for {delay} seconds before sending normal packet and removal for {test_ip}:{test_port}")
        await asyncio.sleep(delay)  # Wait for the designated delay
        await self.filter_send_normal_packet(test_ip, test_port)
        logging.debug(f"Simulating connection removal for {test_ip}:{test_port}")
        await self.remove_connection_from_filter(test_ip, test_port)

    async def remove_connection_from_filter(self, client_ip, client_port):
        async with self.packet_lock:  # Ensure only one coroutine sends a packet at a time
            logging.debug(f"Triggering removal of connection: {client_ip}:{client_port}")
            remove_pkt = (
                Ether(dst=self.switch_server_mac, src=self.server_mac, type=0x0800) /
                IP(src=self.server_ip, dst=client_ip, ttl=64, proto=6, id=random.randint(1, 65535), flags=0) /  # Randomize ID
                TCP(sport=self.server_port, dport=client_port,
                    flags="UEA", seq=random.randint(1, 10000), ack=38, window=502)  # Randomize seq
            )
            logging.debug(f"Sending removal packet for {client_ip}:{client_port}")
            tu.send_packet(self, self.ebpf_iface, remove_pkt)
            # await asyncio.sleep(self.packet_processing_delay)  # Add delay after sending the packet
            logging.debug(f"Removal packet sent for {client_ip}:{client_port}")

    async def filter_connection_insertion(self, client_ip, client_port):
        async with self.packet_lock:  # Ensure only one coroutine sends a packet at a time
            ack_pkt = (
                Ether(dst=self.server_mac, src=self.switch_server_mac, type=0x0800) /
                IP(src=client_ip, dst=self.server_ip, ttl=64, proto=6, id=random.randint(1, 65535), flags=0) /  # Randomize ID
                TCP(sport=client_port, dport=self.server_port,
                    flags="E", seq=random.randint(1, 10000), ack=38, window=502)  # Randomize seq
            )
            logging.debug(f"Sending insertion packet for {client_ip}:{client_port}")
            tu.send_packet(self, self.ebpf_iface, ack_pkt)
            # await asyncio.sleep(self.packet_processing_delay)  # Add delay after sending the packet
            logging.debug(f"Insertion packet sent for {client_ip}:{client_port}")
    
    async def filter_send_normal_packet(self, client_ip, client_port):
        async with self.packet_lock:  # Ensure only one coroutine sends a packet at a time
            tcp_load = b"GET /index.html HTTP/1.1\r\nHost: 10.0.1.3\r\n\r\n"
            ack_pkt = (
                Ether(dst=self.switch_client_mac, src=self.client_mac, type=0x0800) /
                IP(src=client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
                TCP(sport=client_port, dport=self.server_port, flags="PA", seq=1, ack=32454) /
                Raw(load=tcp_load)
            )
            tu.send_packet(self, self.client_iface, ack_pkt)