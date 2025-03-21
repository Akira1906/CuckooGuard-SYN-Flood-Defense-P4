from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from time import sleep
import os
import argparse


class P4RuntimeController():

    def __init__(self, file_suffix, p4rt_path=""):
        if not p4rt_path:
            p4rt_path=f"p4src/split-proxy{file_suffix}.p4info.txtpb"
        script_dir = os.path.dirname(os.path.abspath(__file__))
        p4rt_path = os.path.join(script_dir, p4rt_path)
        json_path = f"p4src/split-proxy{file_suffix}.json"
        json_path = os.path.join(script_dir, json_path)
        self.topo = load_topo(os.path.join(
            script_dir, "../integration-test/topology.json"))
        # print(f"p4rt_path : {p4rt_path}")
        # print(f"script_dir: {script_dir}")
        self.ss = SimpleSwitchP4RuntimeAPI(
            device_id=1,
            grpc_port=9559,
            p4rt_path=p4rt_path,
            json_path=json_path
        )

        self.configureTables()

    def configureTables(self):
        """Configures the necessary table entries in the P4 switch."""

        CALLBACK_TYPE_SYNACK = 1
        CALLBACK_TYPE_TAGACK = 2

        # Configure tb_triage_pkt_types_nextstep
        self.ss.table_add("tb_triage_pkt_types_nextstep", "drop",
                          ["0", "1", "1", "0&&&0", "0&&&0", "0&&&0", "0&&&0", "0&&&0"], [], prio=10)
        self.ss.table_add("tb_triage_pkt_types_nextstep", "start_crc_calc_synack",
                          ["1", "0", "0", "1", "0", "0&&&0", "0&&&0", "0&&&0"], [], prio=10)
        self.ss.table_add("tb_triage_pkt_types_nextstep", "start_crc_calc_tagack",
                          ["1", "0", "0", "0", "0&&&0", "0&&&0", "0&&&0", "0"], [], prio=10)
        self.ss.table_add("tb_triage_pkt_types_nextstep", "client_to_server_nonsyn_ongoing",
                          ["1", "0", "0", "0", "0&&&0", "0&&&0", "0&&&0", "1"], [], prio=10)
        self.ss.table_add("tb_triage_pkt_types_nextstep", "drop",
                          ["1", "0", "1", "0&&&0", "0&&&0", "1", "0&&&0", "0&&&0"], [], prio=10)
        self.ss.table_add("tb_triage_pkt_types_nextstep", "server_to_client_normal_traffic",
                          ["1", "0", "1", "0&&&0", "0&&&0", "0", "0&&&0", "0&&&0"], [], prio=10)
        self.ss.table_add("tb_triage_pkt_types_nextstep", "non_tcp_traffic",
                          ["0", "1", "0&&&0", "0&&&0", "0&&&0", "0&&&0", "0&&&0", "0&&&0"], [], prio=10)
        self.ss.table_add("tb_triage_pkt_types_nextstep", "non_tcp_traffic",
                          ["0", "0", "0&&&0", "0&&&0", "0&&&0", "0&&&0", "0&&&0", "0&&&0"], [], prio=10)

        self.ss.table_add("tb_decide_output_type", "craft_synack_reply",
                          ["1", str(CALLBACK_TYPE_SYNACK)], [], prio=10)
        self.ss.table_add("tb_decide_output_type", "verify_ack",
                          ["1", str(CALLBACK_TYPE_TAGACK)], [], prio=10)

        
        # self.ss.table_add('tb_bloom_time_decay', 'bloom_time_decay', ["1"], [])

        for neigh in self.topo.get_neighbors('s1'):
            if self.topo.isHost(neigh):
                self.ss.table_add('tb_ipv4_lpm',
                                  'ipv4_forward',
                                  [self.topo.get_host_ip(neigh)],
                                  [self.topo.node_to_node_mac(neigh, 's1'), str(self.topo.node_to_node_port_num('s1', neigh))])

        print("Table entries configured successfully!")
        

class ThriftController():
    
    def __init__(self, file_suffix, time_decay):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = f"p4src/split-proxy{file_suffix}.json"
        json_path = os.path.join(script_dir, json_path)
        
        self.ss = SimpleSwitchThriftAPI(thrift_port=9090, json_path = json_path)
        
        self.time_decay = time_decay
        self.periodicRegisterReset()
        
    def periodicRegisterReset(self):
        delete_bloom_id = 1

        while(True):
            sleep(self.time_decay/2)
            print(f"Reset Bloom Register: reg_bloom_{delete_bloom_id}_*")
            self.ss.register_reset(f"reg_bloom_{delete_bloom_id}_1")
            self.ss.register_reset(f"reg_bloom_{delete_bloom_id}_2")
            
            delete_bloom_id = (delete_bloom_id + 1) % 2

def main():

    # Create the parser
    parser = argparse.ArgumentParser(
        description="Syn Cookie Control Plane Application.")

    # Add arguments
    parser.add_argument('--delay', type=int, required=False,
                        help='Delay before starting the application in seconds',
                        default = 0)
    parser.add_argument('--p4rt', type=str, required=False,
                        help='Set P4 Runtime filepath manually')
    parser.add_argument('--time_decay', type=int, required=False,
                        help="Set time duration after which a connection decays automatically (i.e. both bloom filter registers should resetted twice)",
                        default=20)
    parser.add_argument('--file_suffix', type=str, required=False,
                        help="Set the file suffix of the .p4 p4rt ... files to use",
                        default="")

    # Parse the arguments
    args = parser.parse_args()

    # Access the arguments
    sleep(args.delay)
    
    if args.file_suffix:
        file_suffix = "-" + args.file_suffix
    else:
        file_suffix =  args.file_suffix
    
    if args.p4rt:
        P4RuntimeController(p4rt_path = args.p4rt, file_suffix = file_suffix)
    else:
        P4RuntimeController(file_suffix = file_suffix)
        
    if args.time_decay:
        ThriftController(time_decay = args.time_decay, file_suffix = file_suffix)
    else:
        ThriftController(file_suffix = file_suffix)
if __name__ == "__main__":
    main()
