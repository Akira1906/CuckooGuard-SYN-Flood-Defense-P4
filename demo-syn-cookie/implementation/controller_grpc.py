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
        self.ss = SimpleSwitchP4RuntimeAPI(
            nodes['s1']['device_id'],
            nodes['s1']['grpc_port'],
            p4rt_path=nodes['s1']['p4rt_path'],
            json_path=nodes['s1']['json_path']
        )

        
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
