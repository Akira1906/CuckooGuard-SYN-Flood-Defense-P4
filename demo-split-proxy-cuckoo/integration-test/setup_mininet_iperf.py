from p4utils.mininetlib.network_API import NetworkAPI
# import controller_grpc as controller
import os
from time import sleep

script_dir = os.path.dirname(__file__)

def setup_network():
    net = NetworkAPI()
    # net.setLogLevel('debug')
    net.setLogLevel('info')  # or 'warning', 'error'


    net.setCompiler(p4rt=True)
    net.addP4RuntimeSwitch(name = 's1')
    net.addHost('client')
    net.addHost('attacker')
    net.addHost('server')

    net.setP4Source('s1', os.path.join(script_dir, '../implementation/p4src/split-proxy-cuckoo.p4'))
    net.addLink('s1', 'client')
    net.addLink('s1', 'attacker')
    net.addLink('s1', 'server')

    net.setIntfPort('s1', 'client', 1)
    net.setIntfPort('s1', 'attacker', 2)
    net.setIntfPort('s1', 'server', 3)

    net.setIntfIp('client', 's1', '10.0.1.1/24')
    net.setIntfMac('client','s1', '00:00:0a:00:01:01')
    net.setIntfIp('attacker', 's1', '10.0.1.2/24')
    net.setIntfMac('attacker','s1', '00:00:0a:00:01:02')
    net.setIntfIp('server', 's1', '10.0.1.3/24')
    net.setIntfMac('server','s1', '00:00:0a:00:01:03')

    net.setIntfMac('s1', 'client', '00:01:0a:00:01:01')
    net.setIntfMac('s1', 'attacker', '00:01:0a:00:01:02')
    net.setIntfMac('s1', 'server', '00:01:0a:00:01:03')
    # net.enableLogAll()
    # net.enablePcapDump('s1')
    # net.enableCli()
    net.disableCli()
    net.addTaskFile(os.path.join(script_dir,'tasks_iperf.txt'))
    net.startNetwork()
    # exit(1)
    sleep(30)
    
    net.stopNetwork()
    
if __name__ == "__main__":
    setup_network()

# net.setP4CliInput('s1', 's1-commands.txt')


