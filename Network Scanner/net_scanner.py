#! usr/bin/env python

import scapy.all as scapy

def scan(ip):
    # do scapy.ls(scapy.ARP())/scapy.ls(scapy.Ether()) to see all fields that can be set for ARP/Ether class
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # do print(broadcast.summary())/print(arp_request.summary()) to see output/summary
    arp_request_broadcast=broadcast/arp_request #to append/combine Ether and ARP
    
    #do arp_request_broadcast.show() for more detailed info
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    print("IP\t\t\tMAC Address\n------------------------------------------------")
    
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)      # to print ip source i.e client ip and to print MAC source i.e client MAC
        
scan("10.0.2.1/24")      # provide the range of subnet that you are working on or the subnet you want to scan.
