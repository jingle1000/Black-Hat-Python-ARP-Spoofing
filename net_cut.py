from netfilterqueue import NetfilterQueue
import scapy.all as scapy

##need to add ipv6 support...
#program does not work

# def process_packet(packet):
#     scapy_packet = scapy.IP(packet.get_payload())
#     if scapy_packet.haslayer(scapy.DNSRR):
#         print(scapy_packet.show())
#     packet.accept()

def delete_this_function(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet.show())

queue = NetfilterQueue()
#queue.bind(0, process_packet)
queue.bind(0, delete_this_function)
queue.run()
