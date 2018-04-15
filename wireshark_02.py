#! / usr / bin / env python

import dpkt
import datetime
import socket
import argparse


# convert IP addresses to printable strings
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


# add your own function/class/method defines here.

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
    list_of_time_tcp = []
    list_of_port_tcp = []
    list_of_time_udp = []
    list_of_port_udp = []

    input_data = dpkt.pcap.Reader(open(file_name, 'r'))

    for timestamp, packet in input_data:
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        time_string = datetime.datetime.utcfromtimestamp(timestamp)
        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        # TCP packets
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            if inet_to_str(ip.dst) != target_ip:
                continue
            # skip this packet

            ip_address = socket.inet_ntoa(ip.src)
            tcp = ip.data
            port = tcp.dport
            list_of_time_tcp.insert(0, (time_string, ip_address, port))
            list_of_port_tcp.insert(0, (time_string, ip_address, port))


        # collect this packet

        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            if inet_to_str(ip.dst) != target_ip:
                continue
            # skip this packet

            ip_address = socket.inet_ntoa(ip.src)
            udp = ip.data
            port = udp.dport
            list_of_time_udp.insert(0, (time_string, ip_address, port))
            list_of_port_udp.insert(0, (time_string, ip_address, port))

        # your code goes here ...
    list_of_port_tcp = sorted(list_of_port_tcp, key=lambda port: port[2])
    list_of_time_tcp.reverse()
    list_of_port_udp = sorted(list_of_port_udp, key=lambda port: port[2])
    list_of_time_udp.reverse()

    # PROBES
    count = 0
    currPort = -1
    probeList = []
    currProbe = []
    currCount = 0
    prev = None

    for path in list_of_port_tcp:
        if (currCount == 0):
            prev = path
            currProbe.insert(currCount, path)
            currCount = 1
            currPort = path[2]
        elif (currPort == path[2]):
            if ((prev[0] - path[0]).total_seconds() <= W_p):
                currProbe.insert(currCount, path)
                currCount = currCount + 1
                currPort = path[2]
                prev = path
            elif (currCount >= N_p):
                prev = path
                probeList.append(currProbe)
                count = count + 1
                currProbe = []
                currCount = 0
                currProbe.insert(0, path)
                currCount = 1
            else:
                prev = path
                currProbe = []
                currCount = 0
                currProbe.insert(0, path)
                currCount = 1

        elif (currCount >= N_p):
            prev = path
            probeList.append(currProbe)
            count = count + 1
            currPort = path[2]
            currProbe = []
            currProbe.insert(0, path)
            currCount = 1

        else:
            prev = path
            currPort = path[2]
            currProbe = []
            currProbe.insert(0, path)
            currCount = 1
		
	
    # SCANS
    if(currCount >= N_p):
		probeList.append(currProbe)
		count = count + 1
		currProbe = []
    count2 = 0
    currPort = -1
    scanList = []
    currScan = []
    currCount = 0
    prev = None

    for path in list_of_port_tcp:
        if (currCount == 0):
            prev = path
            currScan.insert(currCount, path)
            currCount = 1
            currPort = path[2]
        elif ((path[2] - prev[2]) <= W_s):
            currScan.insert(currCount, path)
            currCount = currCount + 1
            prev = path

        elif (currCount >= N_s):
            prev = path
            scanList.append(currScan)
            count2 = count2 + 1
            currScan = []
            currScan.insert(0, path)
            currCount = 1

        else:
            prev = path
            currScan = []
            currScan.insert(0, path)
            currCount = 1

    # PROBES UDP
    if (currCount >= N_s):
    	scanList.append(currScan)
    	count2 = count2 + 1
    	currScan = []
    	currScan.insert(0, path)
    	currCount = 1
    count3 = 0
    currPortU = -1
    probeListU = []
    currProbeU = []
    currCountU = 0
    prevU = None

    for path in list_of_port_udp:
        if (currCountU == 0):
            prevU = path
            currProbeU.insert(currCountU, path)
            currCountU = 1
            currPortU = path[2]
        elif (currPortU == path[2]):
        	#print (prevU[0] -path[0]), path[0], prevU[0]
        	if((prevU[0] - path[0]).total_seconds() <= W_p):
        		currProbeU.insert(currCountU, path)
        		currCountU = currCountU + 1
        		currPortU = path[2]
        		prevU = path
        	elif (currCountU >= N_p):
        		prevU = path
        		probeListU.append(currProbeU)
        		count3 = count3 + 1
        		currProbeU = []
        		currProbeU.insert(0, path)
        		currCountU = 1
        	else:
        		prevU = path
        		currProbeU = []
        		currCountU = 0
        		currProbeU.insert(0, path)
        		currCountU = 1

        elif (currCountU >= N_p):
            prevU = path
            probeListU.append(currProbeU)
            count3 = count3 + 1
            currPortU = path[2]
            currProbeU = []
            currProbeU.insert(0, path)
            currCountU = 1

        else:
            prevU = path
            currPortU = path[2]
            currProbeU = []
            currProbeU.insert(0, path)
            currCountU = 1

    # SCANS UDP
    if(currCountU >= N_p):
		probeListU.append(currProbeU)
		count3 = count3 + 1
		currProbeU = []
    count4 = 0
    currPortU = -1
    scanListU = []
    currScanU = []
    currCountU = 0
    prevU = None

    for path in list_of_port_udp:
        if (currCountU == 0):
            prevU = path
            currScanU.insert(currCountU, path)
            currCountU = 1
            currPortU = path[2]
        elif ((path[2] - prevU[2]) <= W_s):
            currScanU.insert(currCountU, path)
            currCountU = currCountU + 1
            prevU = path

        elif (currCountU >= N_s):
            prevU = path
            scanListU.append(currScanU)
            count4 = count4 + 1
            currScanU = []
            currScanU.insert(0, path)
            currCountU = 1

        else:
            prevU = path
            currScanU = []
            currScanU.insert(0, path)
            currCountU = 1



    if (currCountU >= N_s):
    	scanListU.append(currScanU)
    	count4 = count4 + 1
    	currScanU = []
    	currScanU.insert(0, path)
    	currCountU = 1
    	
    Counter = str(count)
    print'CS 352 Wireshark (Part 2)'
    print'Reports for TCP'
    print'Found ' + Counter + ' probes'
    if (count != 0):
        for path in probeList:
            length = len(path)
            print'Probe: [', length, ' Packets]'
            for x in range(0, length):
                print'Packet[Timestamp:', path[length - x - 1][0], ' Port:', path[length - x - 1][2], ' Source IP:', \
                path[length - x - 1][1] + ']'

    Counter = str(count2)
    print'Found ' + Counter + ' scans'
    if (count2 != 0):
        for path in scanList:
            length = len(path)
            print'Scan: [', length, ' Packets]'
            for x in range(0, length):
                print 'Packet[Timestamp:', path[x][0], ' Port:', path[x][2], ' Source IP:', path[x][1] + ']'

    Counter = str(count3)
    print 'Reports for UDP'
    print 'Found ' + Counter + ' probes'
    if (count3 != 0):
        for path in probeListU:
            length = len(path)
            print 'Probe: [', length, ' Packets]'
            for x in range(0, length):
                print 'Packet[Timestamp:', path[length - x - 1][0], ' Port:', path[length - x - 1][2], ' Source IP:', \
                path[length - x - 1][1] + ']'

    Counter = str(count4)
    print 'Found ' + Counter + ' scans'
    if (count4 != 0):
        for path in scanListU:
            length = len(path)
            print 'Scan: [', length, ' Packets]'
            for x in range(0, length):
                print 'Packet[Timestamp:', path[x][0], ' Port:', path[x][2], ' Source IP:', path[x][1] + ']'

# execute a main function in Python
if __name__ == "__main__":
    main()
