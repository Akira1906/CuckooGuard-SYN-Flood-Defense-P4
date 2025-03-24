# Note: 9559 is the default TCP port number on which the
# simple_switch_grpc process is listening for incoming TCP connections,
# over which a client program can send P4Runtime API messages to
# simple_switch_grpc.

# p4c --target bmv2 --arch v1model --p4runtime-files proxy.p4info.txtpb proxy.p4

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

    # pkt_mask.set_care_packet(Ether, "src")
    # pkt_mask.set_care_packet(Ether, "dst")
    # pkt_mask.set_care_packet(IP, "src")
    # pkt_mask.set_care_packet(IP, "dst")
    # # pkt_mask.set_care_packet(IP, "ttl")
    # pkt_mask.set_care_packet(TCP, "sport")
    # pkt_mask.set_care_packet(TCP, "dport")
    # pkt_mask.set_care_packet(TCP, "flags")
    # pkt_mask.set_care_packet(TCP, "seq")
    # pkt_mask.set_care_packet(TCP, "ack")

    return pkt_mask

from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.helper import load_topo
from time import sleep
import os
import argparse


class Test(BaseTest):

    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        


    def tearDown(self):
        logging.debug("tearDown()")
        # sh.teardown()


class RecircTest(Test):

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
        n_test_packets = int(tu.test_param_get("n_test_packets"))
        
        self.packet_processing_delay = 0.00025
        self.connection_iat = 0.004
        

        # Step 1: Fill the filter with benign connections
        connections_set = self.generate_n_connections(n_connections=n_benign_connections)
        self.add_connections_to_filter(connections_set)

        # Step 2: Add and remove a new element repeatedly
        self.perform_add_remove_test(n_test_packets, connections_set)

        
    def read_counter(self):
        return self.ss.counter_read("ingressCounter", 0)[1]

    def perform_add_remove_test(self, n_test_packets, connections_in_filter):
        for i in range(n_test_packets):
            logging.debug(f"Test iteration {i + 1}/{n_test_packets}: Starting add-remove sequence.")
            sleep(self.connection_iat)
            # Ensure the new element is not already in the filter
            while True:
                test_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
                test_port = random.randint(1024, 65535)
                if (test_ip, test_port) not in connections_in_filter:
                    break

            # Add the new element to the filter
            logging.debug(f"Adding connection {i + 1}: {test_ip}:{test_port}")
            self.filter_connection_insertion(test_ip, test_port)
            connections_in_filter.add((test_ip, test_port))

            sleep(self.packet_processing_delay)

            # Randomly select an element that is already in the filter to remove
            remove_ip, remove_port = random.choice(list(connections_in_filter))
            logging.debug(f"Removing connection {i + 1}: {remove_ip}:{remove_port}")
            self.remove_connection_from_filter(remove_ip, remove_port)
            sleep(self.packet_processing_delay)
            connections_in_filter.remove((remove_ip, remove_port))

    def remove_connection_from_filter(self, client_ip, client_port):
        logging.debug(f"Triggering removal of connection: {client_ip}:{client_port}")
        remove_pkt = (
            Ether(dst=self.switch_server_mac, src=self.server_mac, type=0x0800) /
            IP(src=self.server_ip, dst=client_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.server_port, dport=client_port, flags="AUE", seq=1, ack=38, window=502)
        )
        tu.send_packet(self, self.ebpf_iface, remove_pkt)
        
        # ack_pkt = (
        #     Ether(dst=self.client_mac, src=self.switch_client_mac, type=0x0800) /
        #     IP(src=self.server_ip, dst=client_ip, ttl=63, proto=6, id=1, flags=0) /
        #     TCP(sport=self.server_port, dport=client_port, flags="A", seq=1, ack=38, window=502)
        # )
        
        # tu.verify_packet(self, ack_pkt, self.client_iface)

    def generate_n_connections(self, n_connections):
        connections_ip_port = set()  # e.g. (10.0.0.1, 3737)

        while len(connections_ip_port) < n_connections:
            ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
            if ip == self.server_ip:
                continue
            port = random.randint(1024, 65535)
            connections_ip_port.add((ip, port))
        return connections_ip_port
    
    def filter_connection_insertion(self, client_ip, client_port):
        # Step 1: trigger insertion into Filter (packet from ebpf to P4 signaling to add the connection to the Filter)

        ack_pkt = (
            Ether(dst=self.server_mac, src=self.switch_server_mac, type=0x0800) /
            IP(src=client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=client_port, dport=self.server_port,
                flags="E", seq=1, ack=38, window=502)
        )

        tu.send_packet(self, self.ebpf_iface, ack_pkt)

    def add_connections_to_filter(self, connections_ip_port):

        for i, connection in enumerate(connections_ip_port):
            client_ip, client_port = connection
            logging.debug(f"Adding connection {i + 1}/{len(connections_ip_port)}: {client_ip}:{client_port}")
            self.safe_filter_connection_insertion(client_ip, client_port)

    def safe_filter_connection_insertion(self, client_ip, client_port):
        repeat = 0
        while repeat < 10:
            logging.debug(f"Attempting to insert connection: {client_ip}:{client_port}, attempt {repeat + 1}")
            # Step 1: trigger insertion into Filter (packet from ebpf to P4 signaling to add the connection to the Filter)

            ack_pkt = (
                Ether(dst=self.server_mac, src=self.switch_server_mac, type=0x0800) /
                IP(src=client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
                TCP(sport=client_port, dport=self.server_port,
                    flags="E", seq=1, ack=38, window=502)
            )

            tu.send_packet(self, self.ebpf_iface, ack_pkt)

            sleep(self.packet_processing_delay)

            # Step 2: send legitimate TCP packet through P4 check if it gets through Filter operation was successful
            self.packet_processing_delay
            tcp_load = b"GET /index.html HTTP/1.1\r\nHost: 10.0.1.3\r\n\r\n"
            ack_pkt = (
                Ether(dst=self.switch_client_mac, src=self.client_mac, type=0x0800) /
                IP(src=client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
                TCP(sport=client_port, dport=self.server_port, flags="PA", seq=1, ack=32454) /
                Raw(load=tcp_load)
            )
            tu.send_packet(self, self.client_iface, ack_pkt)

            ack_pkt = (
                Ether(dst=self.server_mac, src=self.switch_server_mac, type=0x0800) /
                IP(src=client_ip, dst=self.server_ip, ttl=63, proto=6, id=1, flags=0) /
                TCP(sport=client_port, dport=self.server_port, flags="PA", seq=1, ack=32454) /
                Raw(load=tcp_load)
            )

            try:
                tu.verify_packet(self, ack_pkt, self.ebpf_iface)
                logging.debug(f"Successfully inserted connection: {client_ip}:{client_port}")
                repeat = float('inf')
            except AssertionError:
                logging.debug(f"Insertion failed for connection: {client_ip}:{client_port}, retrying...")
                if repeat >= 10:
                    logging.debug(f"Final failure: Could not insert connection {client_ip}:{client_port}")
                    raise AssertionError(f"Insertion failed: {client_ip}:{client_port}")
                else:
                    repeat += 1