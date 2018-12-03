# Black-Hat-Python-ARP-Spoofing
Spoof IP and MAC of device on LAN to intercept traffic

NETWORK SCANNER:
Useage: python3 network_scanner_optparse.py -i -<default gateway ip> -s <cidr notation of network submask>
Example: python3 network_scanner_optparse.py -i 10.0.0.1 -s 24
    
   The network scanner optparse python program is designed to provide an easy to read, and more effective, way to find out the    ip and mac addresses of all devices on a local area network. 
    
PACKET SNIFFER:
Useage: python3 packet_sniff.py
In main code make sure to change wireless interface name inside main function to match your local machine.
    The program will look for IPV4 http packets on port 80 that contain various strings to identify it as a username or             password. It will then print it to the console
    
ARP SPOOF:
Usage: python3 working_arp_spoof_optparse.py -i <interface name> -t <target ip> -g <gateway ip>
    Sends arp response packets to both the default gateway and the target machine. Both devices update their ARP tables to         recognize that the attacking machine running the script is the computer in which traffic should be sent to. IP forwarding       is automatically enabled and disabled as the program starts and ends. The network configuration is restored upon keyboard       interrupt.
