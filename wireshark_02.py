#! / usr / bin / env python

import dpkt
import datetime
import socket
import argparse


''' 

Goal: To read in a pcap file and to identify all probes and scans in the file stream that have a destination ip that 
matches our specified target ip. Once identified, it will sort them by UDP and TCP type packets and sort them by 
increasing port number.

A probe is when an agent makes repeated attempts to access or discover a service on a port. 

A scan is a when an agent tries to map large parts of the IP address/port space to see if there are any running services
on those ports. 


Size is O(N) because the largest structure we are making is 6 lists of potentially biggest size N 

Runtime is O(NlogN) because we perform a sort on our 2 of our lists
'''
def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']
    list_of_port_tcp = []
    list_of_port_udp = []

    input_data = dpkt.pcap.Reader(open(file_name, 'r'))

    for timestamp, packet in input_data:
    	
        # this converts the packet arrival time in unix timestamp format to a printable-string
        time_string = datetime.datetime.utcfromtimestamp(timestamp)
        eth = dpkt.ethernet.Ethernet(packet)
        
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        # Check for TCP packets
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            if inet_to_str(ip.dst) != target_ip:
                # skip this packet
                continue

            # collect this packet
            ip_address = socket.inet_ntoa(ip.src)
            tcp = ip.data
            port = tcp.dport
            list_of_port_tcp.insert(0, (time_string, ip_address, port))


        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            if inet_to_str(ip.dst) != target_ip:
                # skip this packet
                continue

            # collect this packet
            ip_address = socket.inet_ntoa(ip.src)
            udp = ip.data
            port = udp.dport
            list_of_port_udp.insert(0, (time_string, ip_address, port))

	 # Sort the tcp and udp list by port number
    list_of_port_tcp = sorted(list_of_port_tcp, key=lambda port: port[2])
    list_of_port_udp = sorted(list_of_port_udp, key=lambda port: port[2])

    # PROBES TCP
    probeTCPCount = 0
    probeListT = []
    probeListT, probeTCPCount = listCheck(list_of_port_tcp, 0, W_p, N_p)

    # SCANS TCP
    scanTCPCount = 0
    scanListT = []
    scanListT, scanTCPCount = listCheck(list_of_port_tcp, 1, W_s, N_s)

    # PROBES UDP
    probeUDPCount = 0
    probeListU = []
    probeListU, probeUDPCount = listCheck(list_of_port_udp, 0, W_p, N_p)

    # SCANS UDP
    scanUDPCount = 0
    scanListU = []
    scanListU, scanUDPCount = listCheck(list_of_port_udp,1, W_s, N_s)

   
	 # Print out in clean format
    Counter = str(probeTCPCount)
    print('CS 352 Wireshark (Part 2)')
    print('Reports for TCP')
    print('Found ' + Counter + ' probes')
    if (probeTCPCount != 0):
        for path in probeListT:
            length = len(path)
            print 'Probe: [', length, ' Packets]'
            for x in range(0, length):
                print 'Packet[Timestamp:', path[length - x - 1][0], ' Port:', path[length - x - 1][2], ' Source IP:', \
                path[length - x - 1][1] + ']'

    Counter = str(scanTCPCount)
    print 'Found ' + Counter + ' scans'
    if (scanTCPCount != 0):
        for path in scanListT:
            length = len(path)
            print 'Scan: [', length, ' Packets]'
            for x in range(0, length):
                print 'Packet[Timestamp:', path[x][0], ' Port:', path[x][2], ' Source IP:', path[x][1] + ']'

    Counter = str(probeUDPCount)
    print 'Reports for UDP'
    print 'Found ' + Counter + ' probes'
    if (probeUDPCount != 0):
        for path in probeListU:
            length = len(path)
            print 'Probe: [', length, ' Packets]'
            for x in range(0, length):
                print ('Packet[Timestamp:', path[length - x - 1][0], ' Port:', path[length - x - 1][2], ' Source IP:', \
                path[length - x - 1][1] + ']')

    Counter = str(scanUDPCount)
    print 'Found ' + Counter + ' scans'
    if (scanUDPCount != 0):
        for path in scanListU:
            length = len(path)
            print 'Scan: [', length, ' Packets]'
            for x in range(0, length):
                print 'Packet[Timestamp:', path[x][0], ' Port:', path[x][2], ' Source IP:', path[x][1] + ']'



# convert IP addresses to printable strings
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


''' 

Goal: Depending on whether we are given a Probe or a Scan request, we are going to do one of two things:
	
	1. For a Probe, we will store a port number and compare it to the port number of following entries in 
	the listTotal. If it matches, then we will check to see if its within our designated time requirement
	and if so add it to our currProbe list. If it fails then we check to see if our currProbe's count is large
	enough to be considered a probe and if it is we will add it to the finalList
	
	2. For a Scan, we will compare the port numbers of the previous and current path, if it is within our designated
	range we will add it to our currScan, if not we will check to see if its count is big enough to be considered a
	scan. If so we will add it our finalList

	
	Arguments
	-----------------------	
	listTotal is the current list we will be cycling though looking for probes or scans	

   Type == 0 is Probe search
   Type == 1 is Scan search
   
   Width is the width of time that packets need to be sent in to be considered a part of a probe, and the width of ports
   that is checked in packets to see if they are a part of scan
   
	NumNeeded is the number of packets needed to be in a probe or a scan   
   
    
Size is O(N) because the largest structure we are making is a list of potential size N

Runtime is O(N) because we perform a sort on a list
'''


def listCheck(listTotal, Type, Width, NumNeeded):


    finalList = []
    currCount = 0
    Count= 0
    prev = None
    
    #Type Probe
    if Type == 0:
        currPort = -1
        currProbe = []
    
        for path in listTotal:

				# Checks to see if our currCount is zero to see if we need to start keeping track of this current packets' port number
            if (currCount == 0):
                prev = path
                currProbe.insert(currCount, path)
                currCount = 1
                currPort = path[2]

				# Checks whether path's port matches our current probe's port number 
            elif (currPort == path[2]):
            	
            	# Check whether these two packets were sent within the required Width time frame, if so add it to our currProbe list
                if ((prev[0] - path[0]).total_seconds() <= Width):
                    currProbe.insert(currCount, path)
                    currCount = currCount + 1
                    currPort = path[2]
                    prev = path
                
                # If they failed, we look to see if our currCount is big enough to be considered a probe
                # If it is we add it to the finalList and reset our currProbe and currCount
                elif (currCount >= NumNeeded):
                    prev = path
                    finalList.append(currProbe)
                    Count = Count + 1
                    currProbe = []
                    currProbe.insert(0, path)
                    currCount = 1
                
                # Since our probe is not big enough to be added, we reset currProbe and currCount and add
                # the current path to a new probe
                else:
                    prev = path
                    currProbe = []
                    currCount = 0
                    currProbe.insert(0, path)
                    currCount = 1

				# Since the ports do not match, we look to see if our currCount is big enough to be considered a probe
            # If it is we add it to the finalList and reset our currProbe and currCount
            elif (currCount >= NumNeeded):
                prev = path
                finalList.append(currProbe)
                Count = Count + 1
                currPort = path[2]
                currProbe = []
                currProbe.insert(0, path)
                currCount = 1

				# Since our probe is not big enough to be added, we reset currProbe and currCount and add
            # the current path to a new probe
            else:
                prev = path
                currPort = path[2]
                currProbe = []
                currProbe.insert(0, path)
                currCount = 1

        #Finished cycling through list and has to check if the remaining currProbe is big enough to be considered a probe
        if (currCount >= NumNeeded):
           finalList.append(currProbe)
           Count = Count + 1
        return finalList, Count         
           

	 #Type Scan
    elif Type == 1:
        currScan = []

        for path in listTotal:

				# Checks to see if our currCount is zero to see if we need to start keeping track of this current packet
            if (currCount == 0):
                prev = path
                currScan.insert(currCount, path)
                currCount = 1

				# Checks to see if the current iterations port and the previous iterations port are within range to be considered in a scan
            elif ((path[2] - prev[2]) <= Width):
                currScan.insert(currCount, path)
                currCount = currCount + 1
                prev = path

				# Checks to see if the currScan's count is big enough to be considered a scan, if so it adds it to the finalList
            elif (currCount >= NumNeeded):
                prev = path
                finalList.append(currScan)
                Count = Count + 1
                currScan = []
                currScan.insert(0, path)
                currCount = 1

				# Since it failed it resets the currScan
            else:
                prev = path
                currScan = []
                currScan.insert(0, path)
                currCount = 1

        #Finished cycling through list and has to check if the remaining currProbe is big enough to be considered a scan

        if (currCount >= NumNeeded):
            finalList.append(currScan)
            Count = Count + 1
        return finalList, Count


# execute a main function in Python
if __name__ == "__main__":
    main()