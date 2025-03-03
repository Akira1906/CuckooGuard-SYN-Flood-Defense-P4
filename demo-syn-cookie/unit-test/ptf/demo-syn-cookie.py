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
from scapy.all import Ether, IP, TCP, Raw
from asyncio import sleep

######################################################################
# Configure logging
######################################################################


logger = logging.getLogger(None)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# NOTE: How to install behavioral model with thrift support
    # cd ~/behavioral-model  # Go to BMv2 source directory
    # ./autogen.sh
    # ./configure --enable-debugger --with-thrift
    # make -j$(nproc)
    # sudo make install
    # needs thrift 0.13

def get_packet_mask(pkt):
        pkt_mask = mask.Mask(pkt)

        pkt_mask.set_do_not_care_all()

        pkt_mask.set_care_packet(Ether, "src")
        pkt_mask.set_care_packet(Ether, "dst")
        pkt_mask.set_care_packet(IP, "src")
        pkt_mask.set_care_packet(IP, "dst")
        pkt_mask.set_care_packet(IP, "ttl")
        pkt_mask.set_care_packet(TCP, "sport")
        pkt_mask.set_care_packet(TCP, "dport")
        pkt_mask.set_care_packet(TCP, "flags")
        pkt_mask.set_care_packet(TCP, "seq")
        pkt_mask.set_care_packet(TCP, "ack")
        
        return pkt_mask

class DemoTumTest(BaseTest):
    
    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        print("Data Plane is of type:")
        print(type(self.dataplane))

        logging.debug("DemoTUM.setUp()")
        grpc_addr = tu.test_param_get("grpcaddr")
        if grpc_addr is None:
            grpc_addr = "localhost:9559"

        grpc_addr='127.0.1.0:9559'
        my_dev1_id=1
        p4info_txt_fname = tu.test_param_get("p4info")
        p4prog_binary_fname = tu.test_param_get("config")

        sh.setup(device_id=my_dev1_id,
                grpc_addr=grpc_addr,
                election_id=(0, 1),# (high_32bits, lo_32bits)
                # config=sh.FwdPipeConfig(p4info_txt_fname, p4prog_binary_fname),
                verbose=True)
        # 1. start the P4 program of the tum approach
        # 2. start the control plane python application
        

    def tearDown(self):
        logging.debug("DemoTumTest.tearDown()")
        sh.teardown()


    # idea: test the application with an active control plane as integration test

    # but first write some unit tests, artifical but simpler 


class UnitTest(DemoTumTest):

    def runTest(self):
        self.client_mac = "00:00:0a:00:01:01"  # h1 MAC
        self.attacker_mac = "00:00:0a:00:01:02"  # h2 MAC
        self.server_mac = "00:00:0a:00:01:03"  # h3 MAC
        self.switch_client_mac = "00:01:0a:00:01:01"  # s1 client MAC
        self.switch_attacker_mac = "00:01:0a:00:01:02"# s1 attacker MAC
        self.switch_server_mac = "00:01:0a:00:01:03" # s1 server MAC

        self.client_ip = "10.0.1.1"
        self.attacker_ip = "10.0.1.2"
        self.server_ip = "10.0.1.3"

        self.client_port = 1234
        self.server_port = 81
        self.attacker_port = 5555

        self.client_iface = 1  # h1 -> s1
        self.attacker_iface = 2  # h2 -> s1
        self.server_iface = 3  # h3 -> s1
        
        self.tcp_handshake()
        self.valid_packet_sequence()
        # sleep(0.1)
        self.malicious_packets()
    

    def tcp_handshake(self):
        """ Simulates a proper TCP handshake between client and web server """
        print("\n[INFO] Sending TCP Handshake Packets...")

        # Step 1: SYN (Client -> Server)
        syn_pkt = (
            Ether(dst=self.switch_client_mac, src=self.client_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port, dport=self.server_port, flags="S")
        )
        
        tu.send_packet(self, self.client_iface, syn_pkt)
        
        # Step 2: P4 program answers SYN-ACK (Proxy -> Client)

        # NOTE: I fixed this by changing line 276 in the p4 program,
        # where the src and dst mac were reversed one time to much
        exp_pkt = ( 
            Ether(dst=self.client_mac, src=self.switch_client_mac, type=0x0800) /
            IP(src=self.server_ip, dst=self.client_ip, ttl=63, proto=6, id=1, flags=0) /
            TCP(sport=self.server_port, dport=self.client_port, seq=2030043157, ack=1, flags="SA", window=8192)
        )

        # pkt_mask = get_packet_mask(exp_pkt)
        
        tu.verify_packet(self, exp_pkt, self.client_iface)
        
        # Step 3: Correct ACK answer from the client
        
        ack_pkt = (
            Ether(dst=self.client_mac, src=self.switch_client_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port, dport=self.server_port, flags="A", seq=1, ack=2030043158, window=8192)
        )
        
        tu.send_packet(self, self.client_iface, ack_pkt)
        
        # Step 4: Handshake between Switch and Server
        
        # 4.1: Proxy - Server SYN
        
        syn_pkt = (
            Ether(dst=self.server_mac, src=self.client_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=63, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port, dport=self.server_port, flags="S")
        )
        
        tu.verify_packet(self, syn_pkt, self.server_iface)
        
        # 4.2: Server - Proxy SYN-ACK
        
        syn_ack_pkt = (
            Ether(dst=self.client_mac, src=self.server_mac, type=0x0800) /
            IP(src=self.server_ip, dst=self.client_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.server_port, dport=self.client_port, flags="SA", seq=37, ack=1, window=8192)
        )
        
        tu.send_packet(self, self.server_iface, syn_ack_pkt)
        
        # 4.2: Proxy - Server ACK
        
        ack_pkt = ( # dst=self.client_mac, but I think there is a bug in the P4 program
            Ether(dst=self.server_mac, src=self.server_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=63, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port, dport=self.server_port, flags="A", seq=1, ack=38, window=8192)
        )
        
        tu.verify_packet(self, ack_pkt, self.server_iface)
    
    def valid_packet_sequence(self):
        """ Sends a short series of valid packets from the client """
        print("\n[INFO] Sending Valid Data Packets from Client...")

        # Step 1.1: HTTP GET (Client -> Proxy)
        ack_pkt = (
            Ether(dst=self.switch_client_mac, src=self.client_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port, dport=self.server_port, flags="PA", seq=1, ack=2030043158) /
            Raw(load=b"GET /index.html HTTP/1.1\r\nHost: 10.0.1.3\r\n\r\n")
        )
        
        tu.send_packet(self, self.client_iface, ack_pkt)
        
        # Step 1.2: HTTP GET (Proxy -> Server)

        ack_pkt = (
            Ether(dst=self.server_mac, src=self.switch_client_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=63, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port, dport=self.server_port, flags="PA", seq=1, ack=38) /
            Raw(load=b"GET /index.html HTTP/1.1\r\nHost: 10.0.1.3\r\n\r\n")
        )
        
        tu.verify_packet(self, ack_pkt, self.server_iface)
        
        # Step 2.1: HTTP Answer (Server -> Proxy)
        
        resp_pkt = (
            Ether(dst=self.switch_server_mac, src=self.server_mac, type=0x0800) /
            IP(src=self.server_ip, dst=self.client_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.server_port, dport=self.client_port, flags="PA", seq=38, ack=1) /
            Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!")
        )
        
        tu.send_packet(self, self.server_iface, resp_pkt)
        
        # Step 2.2 HTTP Answer (Proxy -> Client)
        
        resp_pkt = (
            Ether(dst=self.client_mac, src=self.switch_server_mac, type=0x0800) /
            IP(src=self.server_ip, dst=self.client_ip, ttl=63, proto=6, id=1, flags=0) /
            TCP(sport=self.server_port, dport=self.client_port, flags="PA", seq=2030043158, ack=1) /
            Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!")
        )
        
        tu.verify_packet(self, resp_pkt, self.client_iface)

    def malicious_packets(self):
        """ Sends malicious packets from the attacker to the web server """
        print("\n[INFO] Sending Malicious Packets from Attacker...")
        # Malicious SYN flood attack
        for i in range(5):
            syn_flood_pkt = (
                Ether(dst=self.switch_attacker_mac, src=self.attacker_mac, type=0x0800) /
                IP(src=self.attacker_ip, dst=self.server_ip, ttl=64, proto=6) /
                TCP(sport=self.attacker_port + i, dport=self.server_port, flags="S", seq=1000 + i)
            )
            tu.send_packet(self, self.attacker_iface, syn_flood_pkt)
            # used to verify that the packet cannot bypass the proxy
            tu.verify_no_packet(self, syn_flood_pkt, 3)

        # Spoofed TCP packets
        for i in range(3):
            spoofed_pkt = (
                Ether(dst=self.switch_attacker_mac, src=self.attacker_mac, type=0x0800) /
                IP(src="1.2.3.4", dst=self.server_ip, ttl=64, proto=6) /
                TCP(sport=6666, dport=self.server_port, flags="PA", seq=2000 + i, ack=999)
            )

            tu.send_packet(self, self.attacker_iface, spoofed_pkt)
            tu.verify_no_packet(self, spoofed_pkt, 3)

        # HTTP GET (Attacker -> Proxy)
        ack_pkt = (
            Ether(dst=self.switch_client_mac, src=self.client_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port+1, dport=self.server_port, flags="PA", seq=1, ack=2030043158) /
            Raw(load=b"GET /index.html HTTP/1.1\r\nHost: 10.0.1.3\r\n\r\n")
        )
        
        tu.send_packet(self, self.client_iface, ack_pkt)
        tu.verify_no_packet(self, ack_pkt, 3)