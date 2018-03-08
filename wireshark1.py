#!/usr/bin/python
# 
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets), 
#2) list distinct source IP addresses and number of packets for each IP address, in descending order 
#3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order 

import dpkt
import socket
import argparse 
from collections import OrderedDict

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code 
def main():
    number_of_packets = 0             # you can use these structures if you wish 
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing 
    input_data=dpkt.pcap.Reader(open(filename,'rb'))

    # this main loop reads the packets one at a time from the pcap file
    count = 0
    ipCount = 0
    tcpCount = 0
    iptcpCount = 0
    for timestamp, packet in input_data:
	count=count+1
	eth = dpkt.ethernet.Ethernet(packet)
	if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
		continue
	ip = eth.data
	ip_address = socket.inet_ntoa(ip.src)
	if ip_address in list_of_ips:
		list_of_ips[ip_address] += 1
	else:
		list_of_ips[ip_address] = 1

	if hasattr(ip, 'p') and ip.p == dpkt.ip.IP_PROTO_TCP:
		tcp = ip.data
		port = tcp.dport
		ip_tcp_port_combo = ip_address + ":" + str(port)
		
		if str(port) in list_of_tcp_ports:
			list_of_tcp_ports[str(port)] += 1
		else:
			list_of_tcp_ports[str(port)] = 1

		if ip_tcp_port_combo in list_of_ip_tcp_ports:
			list_of_ip_tcp_ports[ip_tcp_port_combo] += 1
		else:
			list_of_ip_tcp_ports[ip_tcp_port_combo] = 1
        # ... your code goes here ...

    print 'CS 352 Wireshark, part 1'
    print 'Total number of packets,',count
    print 'Source IP addresse, count'
    sorted_ip = sorted(list_of_ips, key=lambda x: list_of_ips[x], reverse = True)
    for k in sorted_ip:
    	print("{},{}".format(k, list_of_ips[k]))

    print 'Destination TCP ports,count'
    sorted_tcp = sorted(list_of_tcp_ports, key=lambda x: list_of_tcp_ports[x], reverse = True)
    for k in sorted_tcp:
    	print("{},{}".format(k, list_of_tcp_ports[k]))

    print 'Source IPs/Destination TCP ports,count'
    sorted_ip_tcp = sorted(list_of_ip_tcp_ports, key=lambda x: list_of_ip_tcp_ports[x], reverse = True)
    for k in sorted_ip_tcp:
    	print("{},{}".format(k, list_of_ip_tcp_ports[k]))


# execute a main function in Python
if __name__ == "__main__":
    main()  
