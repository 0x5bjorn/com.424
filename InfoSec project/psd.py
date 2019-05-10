#!/usr/bin/env python

# 2 main libraries: pcapy and impacket
import pcapy, impacket
from impacket import ImpactDecoder, ImpactPacket
import sys, socket

# packet counters
totalCounter = 0
tcpCounter = 0
udpCounter = 0
icmpCounter = 0
otherProtoCounter = 0

# main dictionary for storing possible scans
scans = {}

ICMP_ECHOREQ = 8

# scan counters
udpScanCount = 0
halfOpenCount = 0
icmpEchoCount = 0
xmasScanCount = 0
nullScanCount = 0

# custom class Scan for detecting possible scans from one source port to many destination ports
class Scan(object):
    def __init__(self):
        self.sport = 0
        self.dports = set()
        self.protocol = ""
        self.seconds = 0
        self.microseconds = 0
        self.tcpFlags = set()
        self.weight = 0

# __MAIN___________________________________________________
def main():
    global totalCounter, tcpCounter, udpCounter, icmpCounter, otherProtoCounter, halfOpenCount, udpScanCount, icmpEchoCount, xmasScanCount, nullScanCount, scans

    if len(sys.argv) <= 1:
        print(sys.argv[0] + ": needs a filepath to a PCAP file")
        sys.exit(-1)

    try:
        pcapFile = pcapy.open_offline(sys.argv[1])
        ethDecoder = ImpactDecoder.EthDecoder()

        while True:
            (pktHeader, pktPayload) = pcapFile.next()
            if not pktHeader:
                break

            totalCounter += 1

            (seconds, microseconds) = pktHeader.getts()
            # if totalCounter > 1 :
            #     print "%d: %f %f" % ( totalCounter, ts, ts - lastTime )
            # lastTime = ts

            ethernet = ethDecoder.decode(pktPayload)
            if not ethernet:
                continue

            ip = ethernet.child()
            if ethernet.get_ether_type() != ImpactPacket.IP.ethertype:
                continue

            srcIP = ip.get_ip_src()
            dstIP = ip.get_ip_dst()

            # Using a dictionary to store possible scans.
            # key - 'IP source address->IP destination address'
            # value - custom class Scan()
            key = srcIP + "->" + dstIP
            scan = Scan()
            if ip.get_ip_p() == ImpactPacket.TCP.protocol:                                      # TCP Proto
                tcpCounter += 1
                scan.protocol = "TCP"
                if key not in scans:
                    scans[key] = []
                    scan.sport = ip.child().get_th_sport()
                    scan.dports.add(ip.child().get_th_dport())
                    if ip.child().get_th_dport() < 1024:
                        scan.weight += 4
                    else:
                        scan.weight += 1
                    scan.tcpFlags.add(ip.child().get_th_flags())
                    scans[key].append(scan)
                    scans[key] = list(set(scans[key]))
                else:
                    i = 0
                    while i < len(scans[key]):
                        if scans[key][i].sport == ip.child().get_th_sport():
                            if ip.child().get_th_dport() not in scans[key][i].dports:
                                scans[key][i].dports.add(ip.child().get_th_dport())
                                if ip.child().get_th_dport() < 1024:
                                    scans[key][i].weight += 4
                                else:
                                    scans[key][i].weight += 1
                                scans[key][i].tcpFlags.add(ip.child().get_th_flags())
                            else:
                                scans[key][i].tcpFlags.add(ip.child().get_th_flags())
                            break
                        elif i == len(scans[key])-1:
                            scan.sport = ip.child().get_th_sport()
                            scan.dports.add(ip.child().get_th_dport())
                            if ip.child().get_th_dport() < 1024:
                                scan.weight += 4
                            else:
                                scan.weight += 1
                            scan.tcpFlags.add(ip.child().get_th_flags())
                            scans[key].append(scan)
                            scans[key] = list(set(scans[key]))
                            break
                        i += 1

            elif ip.get_ip_p() == ImpactPacket.UDP.protocol:                                    # UDP Proto
                udpCounter += 1
                scan.protocol = "UDP"
                if ip.child().get_uh_ulen() == 8:                                    # Check if udp packet is empty
                    if key not in scans:
                        scans[key] = []
                        scan.sport = ip.child().get_uh_sport()
                        scan.dports.add(ip.child().get_uh_dport())
                        if ip.child().get_uh_dport() < 1024:
                            scan.weight += 4
                        else:
                            scan.weight += 1
                        scan.tcpFlags.add(None)
                        scans[key].append(scan)
                        scans[key] = list(set(scans[key]))
                    else:
                        i = 0
                        while i < len(scans[key]):
                            if scans[key][i].sport == ip.child().get_uh_sport():
                                if ip.child().get_uh_dport() not in scans[key][i].dports:
                                    scans[key][i].dports.add(ip.child().get_uh_dport())
                                    if ip.child().get_uh_dport() < 1024:
                                        scans[key][i].weight += 4
                                    else:
                                        scans[key][i].weight += 1
                                break
                            elif i == len(scans[key])-1:
                                scan.sport = ip.child().get_uh_sport()
                                scan.dports.add(ip.child().get_uh_dport())
                                if ip.child().get_uh_dport() < 1024:
                                    scan.weight += 4
                                else:
                                    scan.weight += 1
                                scan.tcpFlags.add(None)
                                scans[key].append(scan)
                                scans[key] = list(set(scans[key]))
                                break
                            i += 1

            elif ip.get_ip_p() == ImpactPacket.ICMP.protocol:                                  # ICMP Proto
                icmpCounter += 1
                if ip.child().get_icmp_type() == ICMP_ECHOREQ:              # Checking ICMP Echo request during filling dictionary
                    icmpEchoCount += 1
                    if key not in scans:
                        scans[key] = []
                        scan.protocol = "ICMP"
                        scans[key].append(scan)
                        scans[key] = list(set(scans[key]))
                    else:
                        scans[key].append(scan)
                        scans[key] = list(set(scans[key]))
            else:
                otherProtoCounter += 1

    except pcapy.PcapError:
        print("Cannot open file: " + sys.argv[1])
        sys.exit(-1)

    print("Total number of packets:         " + str(totalCounter))
    print("Number of TCP packets:           " + str(tcpCounter))
    print("Number of UDP packets:           " + str(udpCounter))
    print("Number of ICMP packets:          " + str(icmpCounter))
    print("Number of other packets:         " + str(otherProtoCounter))
    print "\n",

    # Process of detecting scans
    for key in scans:
        for scan in scans[key]:
            if scan.protocol == "TCP":
                if scan.weight > 20:
                    if 41 in scan.tcpFlags:                                                # Xmas scan detection
                        xmasScanCount += len(scan.dports)
                        print "-----Xmas Scan detected!!!-----"
                        print "IP addresses:              " + key
                        print "Source port:               " + str(scan.sport)
                        print "Number of ports scanned:   " + str(len(scan.dports))
                        columnCounter = 0
                        for dport in scan.dports:
                            if columnCounter == 12:
                                print "\n",
                                columnCounter = 0
                            print str(dport).rjust(5),
                            columnCounter += 1
                        print "\n"
                    elif 0 in scan.tcpFlags:
                        nullScanCount += len(scan.dports)                                 # Null scan detection
                        print "-----Null Scan detected!!!-----"
                        print "IP addresses:              " + key
                        print "Source port:               " + str(scan.sport)
                        print "Number of ports scanned:   " + str(len(scan.dports))
                        columnCounter = 0
                        for dport in scan.dports:
                            if columnCounter == 12:
                                print "\n",
                                columnCounter = 0
                            print str(dport).rjust(5),
                            columnCounter += 1
                        print "\n"
                    elif 2 in scan.tcpFlags:
                        halfOpenCount += len(scan.dports)                                 # Halfopen scan detection
                        print "-----Halfopen Scan detected!!!-----"
                        print "IP addresses:              " + key
                        print "Source port:               " + str(scan.sport)
                        print "Number of ports scanned:   " + str(len(scan.dports))
                        columnCounter = 0
                        for dport in scan.dports:
                            if columnCounter == 12:
                                print "\n",
                                columnCounter = 0
                            print str(dport).rjust(5),
                            columnCounter += 1
                        print "\n"
            elif scan.protocol == "UDP":                                                  # UDP scan detection
                if scan.weight > 20:
                    udpScanCount += len(scan.dports)
                    print "-----UDP Scan detected!!!-----"
                    print "IP addresses:              " + key
                    print "Source port:               " + str(scan.sport)
                    print "Number of ports scanned:   " + str(len(scan.dports))
                    columnCounter = 0
                    for dport in scan.dports:
                        if columnCounter == 12:
                            print "\n",
                            columnCounter = 0
                        print str(dport).rjust(5),
                        columnCounter += 1
                    print "\n"
            elif scan.protocol == "ICMP":
                print "-----ICMP Echo requests detected!!!-----"
                print "IP addresses:                " + key
                print "\n",

    print("Number of TCP scans:             " + str(nullScanCount+xmasScanCount+halfOpenCount))
    print("Number of TCP-Null scans:        " + str(nullScanCount))
    print("Number of TCP-Xmas scans:        " + str(xmasScanCount))
    print("Number of TCP-Halfopen scans:    " + str(halfOpenCount))
    print("Number of UDP scans:             " + str(udpScanCount))
    print("Number of ICMP echo requests:    " + str(icmpEchoCount))
    print "\n",

if __name__ == "__main__":
        main()
