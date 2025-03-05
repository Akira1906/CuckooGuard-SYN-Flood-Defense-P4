from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.helper import load_topo
from time import sleep
import os
import argparse

class DigestController():

    def __init__(self):
        script_dir = os.path.dirname(__file__)
        topo = load_topo(os.path.join(script_dir, "integration-test/topology.json"))
        nodes = topo.get_nodes()
        self.ss = SimpleSwitchP4RuntimeAPI(
            device_id = 1,
            grpc_port = 9559,
            p4rt_path="p4src/split-proxy-crc.p4i",
            json_path="p4src/split-proxy-crc.json",
        )
        
        self.configure_tables()
        
    def configure_tables(self):
        """Configures the necessary table entries in the P4 switch."""
        
        CALLBACK_TYPE_SYNACK = 1
        CALLBACK_TYPE_TAGACK = 2

        
        # Configure tb_triage_pkt_types_nextstep
        self.ss.table_add("tb_triage_pkt_types_nextstep", "drop", ["0", "0", "1", "1", "*", "*", "*", "*", "*"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "start_crc_calc_synack", ["0", "1", "0", "0", "1", "0", "*", "*", "*"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "start_crc_calc_tagack", ["0", "1", "0", "0", "0", "*", "*", "*", "0"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "client_to_server_nonsyn_ongoing", ["0", "1", "0", "0", "0", "*", "*", "*", "1"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "drop", ["0", "1", "0", "1", "*", "*", "1", "*", "*"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "server_to_client_normal_traffic", ["0", "1", "0", "1", "*", "*", "0", "*", "*"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "non_tcp_traffic", ["0", "0", "1", "*", "*", "*", "*", "*", "*"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "non_tcp_traffic", ["0", "0", "0", "*", "*", "*", "*", "*", "*"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "pre_finalize_tagack", ["8", "1", "0", "*", "*", "*", "*", "2", "*"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "pre_finalize_synack", ["8", "1", "0", "*", "*", "*", "*", "1", "*"], [])
        self.ss.table_add("tb_triage_pkt_types_nextstep", "finalize_tagack", ["12", "1", "0", "*", "*", "*", "*", "2", "*"], [])

        # Configure tb_decide_output_type_1
        self.ss.table_add("tb_decide_output_type_1", "craft_synack_reply", ["1", "1", "12", str(CALLBACK_TYPE_SYNACK)], [])
        self.ss.table_add("tb_decide_output_type_1", "sip_final_xor_with_ackm1", ["1", "1", "12", str(CALLBACK_TYPE_TAGACK)], [])
        self.ss.table_add("tb_decide_output_type_1", "clean_up", ["1", "1", "12", "*"], [])

        # Configure tb_decide_output_type_2
        self.ss.table_add("tb_decide_output_type_2", "sip_final_xor_with_time", ["1", "1", "12", str(CALLBACK_TYPE_SYNACK)], [])
        self.ss.table_add("tb_decide_output_type_2", "verify_timediff", ["1", "1", "12", str(CALLBACK_TYPE_TAGACK)], [])

        print("Table entries configured successfully!")

        
# table_add tb_triage_pkt_types_nextstep drop  0 0 1 1 * * * * * =>
# table_add tb_triage_pkt_types_nextstep start_crc_calc_synack  0 1 0 0 1 0 * * * =>
# table_add tb_triage_pkt_types_nextstep start_crc_calc_tagack  0 1 0 0 0 * * * 0 =>
# table_add tb_triage_pkt_types_nextstep client_to_server_nonsyn_ongoing  0 1 0 0 0 * * * 1 =>
# table_add tb_triage_pkt_types_nextstep drop  0 1 0 1 * * 1 * * =>
# table_add tb_triage_pkt_types_nextstep server_to_client_normal_traffic  0 1 0 1 * * 0 * * =>
# table_add tb_triage_pkt_types_nextstep non_tcp_traffic  0 0 1 * * * * * * =>
# table_add tb_triage_pkt_types_nextstep non_tcp_traffic  0 0 0 * * * * * * =>
# table_add tb_triage_pkt_types_nextstep pre_finalize_tagack  8 1 0 * * * * 2 * =>
# table_add tb_triage_pkt_types_nextstep pre_finalize_synack  8 1 0 * * * * 1 * =>
# table_add tb_triage_pkt_types_nextstep finalize_tagack  12 1 0 * * * * 2 * =>


# table_add tb_decide_output_type_1 craft_synack_reply  1 1 12 CALLBACK_TYPE_SYNACK => 
# table_add tb_decide_output_type_1 sip_final_xor_with_ackm1  1 1 12 CALLBACK_TYPE_TAGACK => 
# table_add tb_decide_output_type_1 clean_up  1 1 12 * => 

# table_add tb_decide_output_type_2 sip_final_xor_with_time  1 1 12 CALLBACK_TYPE_SYNACK => 
# table_add tb_decide_output_type_2 verify_timediff  1 1 12 CALLBACK_TYPE_TAGACK => 
        
        # for neigh in topo.get_neighbors('s1'):
        #     if topo.isHost(neigh):
        #         self.ss.table_add('ipv4_lpm',
        #                             'ipv4_forward',
        #                             [topo.get_host_ip(neigh)],
        #                             [topo.node_to_node_mac(neigh, 's1'), str(topo.node_to_node_port_num('s1', neigh))])
        # # add mirroring_add 100 4 legacy, was used for debugging



def main():
    
    # Create the parser
    parser = argparse.ArgumentParser(description="Syn Cookie Control Plane Application.")

    # Add arguments
    parser.add_argument('--delay', type=int, required=False, help='Delay before starting the application in seconds')

    # Parse the arguments
    args = parser.parse_args()

    # Access the arguments
    delay = args.delay
    if delay:
        sleep(delay)
    
    DigestController()


if __name__ == "__main__":
    main()
