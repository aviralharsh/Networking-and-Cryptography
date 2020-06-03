#! usr/bin/env python
import scapy.all as scapy
import optparse
import os
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="Enter Ip range to search for")
    (options, arguments) = parser.parse_args()
    return options.ip

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    client_list = []
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    for element in answered_list:
        #print(element[1].psrc + "\t\t" + element[1].hwsrc)
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return(client_list)

def print_func(returned_list):
    print("IP\t\t\tMAC Address\t\t\tOS\n-------------------------------------------------------------------")
    for client in returned_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t\t" + os.name)


ip = get_arguments()
scan_result = scan(ip)
print_func(scan_result)
