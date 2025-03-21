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


class Test(BaseTest):

    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        print("Data Plane is of type:")
        print(type(self.dataplane))

        logging.debug("setUp()")
        grpc_addr = tu.test_param_get("grpcaddr")
        if grpc_addr is None:
            grpc_addr = "localhost:9559"

        grpc_addr = '127.0.1.0:9559'
        my_dev1_id = 1
        
        sh.setup(device_id=my_dev1_id,
                 grpc_addr=grpc_addr,
                 election_id=(0, 1),  # (high_32bits, lo_32bits)
                 # config=sh.FwdPipeConfig(p4info_txt_fname, p4prog_binary_fname),
                 verbose=True)

    def tearDown(self):
        logging.debug("tearDown()")
        sh.teardown()


class FPTest(Test):

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
        n_hostile_test_packets = int(tu.test_param_get("n_hostile_test_packets"))
        
        self.packet_processing_delay = 0.00025


        connections_set = self.generate_n_connections(n_connections=n_benign_connections)

        self.add_connections_to_filter(connections_set)

        fp_rate = self.test_fp_rate(
            n_samples=n_hostile_test_packets, benign_connections_set=connections_set)

        print("START RESULT")
        print(str(fp_rate))
        print("END RESULT")

    def test_fp_rate(self, n_samples, benign_connections_set):
        # generate test sample connections

        n_false_positives = 0
        test_connections = []
        while len(test_connections) < n_samples:
            ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
            port = random.randint(1024, 65535)
            if (ip, port) not in benign_connections_set:
                test_connections.append((ip, port))

        for i, connection in enumerate(test_connections):
            client_ip, client_port = connection
            # print(f"test {i}")
            # send test packet to P4 and check if filter mistakenly let the packet through
            tcp_load = b"GET /index.html HTTP/1.1\r\nHost: 10.0.1.3\r\n\r\n"
            ack_pkt = (
                Ether(dst=self.switch_client_mac, src=self.client_mac, type=0x0800) /
                IP(src=client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
                TCP(sport=client_port, dport=self.server_port, flags="PA", seq=1, ack=32454) /
                Raw(load=tcp_load)
            )
            tu.send_packet(self, self.client_iface, ack_pkt)
            
            if i % 200 == 0:
                n_false_positives += tu.count_matched_packets(self, get_packet_mask(ack_pkt), self.ebpf_iface, timeout=self.packet_processing_delay)
        
        # catch packets that went through in a delayed manner
        while(True):
            count_packets = tu.count_matched_packets(self, get_packet_mask(ack_pkt), self.ebpf_iface, timeout=0.5)
            print(f"processing overflow: #{count_packets}")
            if count_packets == 0:
                break
            n_false_positives += count_packets

        return n_false_positives

    def generate_n_connections(self, n_connections):
        connections_ip_port = set()  # e.g. (10.0.0.1, 3737)

        while len(connections_ip_port) < n_connections:
            ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
            if ip == self.server_ip:
                continue
            port = random.randint(1024, 65535)
            connections_ip_port.add((ip, port))
        return connections_ip_port

    def add_connections_to_filter(self, connections_ip_port):

        for i, connection in enumerate(connections_ip_port):
            client_ip, client_port = connection
            # Safe (verified) insertion into the Filter
            print(f"add connection {i}")
            self.safe_filter_connection_insertion(client_ip, client_port)

    def safe_filter_connection_insertion(self, client_ip, client_port):
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
        except AssertionError:
            print(f"insertion of connection {client_ip}:{client_port} failed")
            raise AssertionError(f"Insertion failed: {client_ip}:{client_port}")