#Johnathan Ingle
#Network Scanner based on Zsecurity script
#Version 0.2
#Example useage: python network_scanner_optparse.py -i 10.0.0.1 -s 24

import scapy.all as scapy
import optparse

def lineSep():
    print('-'*50)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]


    client_list = []
    for element in answered_list:
        client_dict = {'IP': element[1].psrc, 'MAC': element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def show_output(scan_results):
    print("IP:\t\t\t\tMAC:")
    lineSep()
    for client in scan_results:
        print(client['IP'] + '\t\t' + client['MAC'])

def get_args():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--ip', dest='ip', help='ip address of target')
    parser.add_option('-s', '--subnet', dest='subnet', help='number of bits assigned to the network (subnet)')
    (options, arguments) = parser.parse_args()
    ip = options.ip
    subnet = '/' + options.subnet
    request = ip + subnet
    return request


scan_results = scan(get_args())
show_output(scan_results)