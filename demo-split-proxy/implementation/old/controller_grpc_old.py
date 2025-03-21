import struct
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
        # self.ss = SimpleSwitchP4RuntimeAPI(
        #     nodes['s1']['device_id'],
        #     nodes['s1']['grpc_port'],
        #     p4rt_path=nodes['s1']['p4rt_path'],
        #     json_path=nodes['s1']['json_path']
        # )
        
        self.ss = SimpleSwitchP4RuntimeAPI(
            device_id=1,
            grpc_port=9559,
            p4rt_path="p4src/proxy.p4info.txtpb",
            json_path="p4src/proxy.json"
        )
        
        # for the siphash algorithm standard values have to be set in the tb_maybe_sip_init table
        
    #         const entries={
    #     (false, true, _): sip_init_default_key(); //change key from control plane
    #     (true, true, 4): sip_continue_round4();
    #     (true, true, 8): sip_continue_round8();
    #     (true, true, 12): sip_end_round12_tagack_verify();
    # }
#     table_add tb_maybe_sip_init sip_init_default_key  0 1   => 
# table_add tb_maybe_sip_init sip_continue_round4  1 1 4 =>
# table_add tb_maybe_sip_init sip_continue_round8  1 1 8 =>
# table_add tb_maybe_sip_init sip_end_round12_tagack_verify 1 1 12 =>

# table_add tb_triage_pkt_types_nextstep drop  0 0 1   1 0 0  * *  => 
# table_add tb_triage_pkt_types_nextstep start_sipcalc_synack  0 1 0   0 1 0  * *  => 
# table_add tb_triage_pkt_types_nextstep start_sipcalc_tagack  0 1 0   0 0 *  * 0  => 
# table_add tb_triage_pkt_types_nextstep client_to_server_nonsyn_ongoing  0 1 0   0 0 *  * 1  => 
# table_add tb_triage_pkt_types_nextstep drop  0 1 0   1 * *  * *  => 
# table_add tb_triage_pkt_types_nextstep server_to_client_normal_traffic  0 1 0   1 * 0  * *  => 
# table_add tb_triage_pkt_types_nextstep non_tcp_traffic  0 0 1   * * *  * *  => 
# table_add tb_triage_pkt_types_nextstep non_tcp_traffic  0 0 0   * * *  * *  => 
# table_add tb_triage_pkt_types_nextstep continue_sipcalc_round4to6  4 1 0   * * *  * *  => 
# table_add tb_triage_pkt_types_nextstep pre_finalize_tagack  8 1 0   * * *  CALLBACK_TYPE_TAGACK *  => 
# table_add tb_triage_pkt_types_nextstep pre_finalize_synack  8 1 0   * * *  CALLBACK_TYPE_SYNACK *  => 
# table_add tb_triage_pkt_types_nextstep finalize_tagack  12 1 0   * * *  CALLBACK_TYPE_TAGACK *  => 



# table_add tb_decide_output_type_1 craft_synack_reply  1 1 12 CALLBACK_TYPE_SYNACK => 
# table_add tb_decide_output_type_1 sip_final_xor_with_ackm1  1 1 12 CALLBACK_TYPE_TAGACK => 
# table_add tb_decide_output_type_1 clean_up  1 1 12 * => 

# table_add tb_decide_output_type_2 sip_final_xor_with_time  1 1 12 CALLBACK_TYPE_SYNACK => 
# table_add tb_decide_output_type_2 verify_timediff  1 1 12 CALLBACK_TYPE_TAGACK => 
        
        for neigh in topo.get_neighbors('s1'):
            if topo.isHost(neigh):
                self.ss.table_add('ipv4_lpm',
                                    'ipv4_forward',
                                    [topo.get_host_ip(neigh)],
                                    [topo.node_to_node_mac(neigh, 's1'), str(topo.node_to_node_port_num('s1', neigh))])
        # add mirroring_add 100 4 legacy, was used for debugging

        self.configure_digest()

    def configure_digest(self):
        """Configures the P4 digest handling for connection tracking."""
        self.ss.digest_enable("learn_connection_t")
        self.ss.digest_enable("learn_debug_t")

    def raw_digest_message(self, digest_msg):
        raw_data_list = []
        for data in digest_msg.data:
            struct_members = data.struct.members

            # if len(struct_members) != 5:
            #     print("Error: Digest struct does not have the expected 5 fields.")
            #     continue

            raw_data = [member.bitstring for member in struct_members]
            raw_data_list.append(raw_data)

        return raw_data_list

    def recv_msg_digest(self, msg):
        raw_data_list = self.raw_digest_message(msg)

        for raw_data in raw_data_list:
            msg_type = struct.unpack('!B', raw_data[0])[0]
            arg1 = struct.unpack('!I', b'\0\0' + raw_data[1])[0]
            arg2 = struct.unpack('!I', raw_data[2])[0]
            arg3 = struct.unpack('!I', b'\0\0' + raw_data[3])[0]
            arg4 = struct.unpack('!I', raw_data[4])[0]
            # print(f"{msg_type}, {arg1}, {arg2}, {arg3}, {arg4}")

            if msg_type == 0:
                print("------------------------------------------------------------")
                print("This is a debug message --> action is executed successfully!")
                print(f"Message: {msg_type}, data: {arg1}, extra: {arg2}")
                print("------------------------------------------------------------")

            elif msg_type == 2:
                print(
                    f"message type: {msg_type}, connection added with Hash: {arg1}, diff: {arg2}")
                self.add_connection_entry(arg1, arg2)

                print(
                    f"message type: {msg_type}, connection added with Hash: {arg3}, diff: {arg4}")
                self.add_connection_entry(arg3, arg4)

            else:
                print("Unknown message type!")

    def add_connection_entry(self, connection_hash, diff_value):
        self.ss.table_add("connections", "saveDifferenceValue", [
                          str(connection_hash)], [str(diff_value)])

    def run_digest_loop(self):
        print("Listening for digest messages via gRPC...")

        while True:
            try:
                message = self.ss.get_digest_list()
                if message:
                    print(f"Digest Message received: {type(message)}{message}")
                    self.recv_msg_digest(message)

            except Exception as e:
                print(f"Error processing digests: {e}")


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
    
    controller = DigestController()
    controller.run_digest_loop()


if __name__ == "__main__":
    main()
