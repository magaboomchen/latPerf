#!/usr/bin/python
# -*- coding: UTF-8 -*-

import scapy
import logging
from scapy.all import *
from scapy.utils import PcapWriter

# tester
# 7: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
#     link/ether 00:1b:21:c0:8f:ae brd ff:ff:ff:ff:ff:ff

# bess
# 9: enp4s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
#     link/ether 00:1b:21:c0:8f:98 brd ff:ff:ff:ff:ff:ff

# dut type
SWITCH = "SWITCH"
CLASSIFIER = "CLASSIFIER"
FWD = "FWD"
FW = "FW"
LB = "LB"
MONITOR = "MONITOR"
NAT = "NAT"
VPN = "VPN"

# addresses
TESTER_DATAPATH_MAC = "f4:e9:d4:a3:80:80"
DUT_DATAPATH_MAC = "00:1b:21:c0:8f:98"

TESTER_DATAPATH_IP = "192.168.111.2"
DUT_DATAPATH_IP = "192.168.111.3"

INNER_SRC_IP = "1.1.1.1"
INNER_DST_IP = "2.2.2.2"

FWD_DATAPATH_IP = "10.16.1.1"
FW_DATAPATH_IP = "10.32.1.1"
MONITOR_DATAPATH_IP = "10.64.1.1"
LB_DATAPATH_IP = "10.80.1.1"
NAT_DATAPATH_IP = "10.112.1.1"
VPN_DATAPATH_IP = "10.128.1.1"

SFF1_DATAPATH_IP = "2.2.0.38"
CLASSIFIER_DATAPATH_IP = "2.2.0.36"
CLASSIFIER_DECAP_DATAPATH_IP = "10.0.1.1"


class PktTemplateGenerator(object):
    def __init__(self):
        pass

    def genPktTemplate(self, DUTType):
        # single port loop back test
        # ++++++++
        # |      |  Tester(server)
        # ++++++++
        #    |
        #    |
        # ++++++++
        # |      |  DUT
        # ++++++++
        if DUTType == SWITCH:
            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=TESTER_DATAPATH_IP,dst=DUT_DATAPATH_IP, tos=0x18)
            udp = UDP(sport=80,dport=1234)
            senderTemplate = ether / ip1 / udp /Raw(load=data)

            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=TESTER_DATAPATH_IP,dst=DUT_DATAPATH_IP, tos=0x18)
            udp = UDP(sport=80,dport=1234)
            recvTemplate = ether / ip1 / udp /Raw(load=data)
        elif DUTType == CLASSIFIER:
            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP, tos=0x18)
            udp = UDP(sport=80,dport=1234)
            senderTemplate = ether / ip1 / udp /Raw(load=data)

            data = "X" * 22
            ether = Ether(src=DUT_DATAPATH_MAC, dst=TESTER_DATAPATH_MAC)
            ip1 = IP(src=CLASSIFIER_DATAPATH_IP,dst=FWD_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            recvTemplate = ether / ip1 / ip2 / udp /Raw(load=data)
        elif DUTType == FWD:
            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=TESTER_DATAPATH_IP,dst=FWD_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            senderTemplate = ether / ip1 / ip2 / udp /Raw(load=data)

            data = "X" * 22
            ether = Ether(src=DUT_DATAPATH_MAC, dst=TESTER_DATAPATH_MAC)
            ip1 = IP(src=SFF1_DATAPATH_IP,dst=CLASSIFIER_DECAP_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            recvTemplate = ether / ip1 / ip2 / udp /Raw(load=data)
        elif DUTType == FW:
            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=TESTER_DATAPATH_IP,dst=FW_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            senderTemplate = ether / ip1 / ip2 / udp /Raw(load=data)

            data = "X" * 22
            ether = Ether(src=DUT_DATAPATH_MAC, dst=TESTER_DATAPATH_MAC)
            ip1 = IP(src=SFF1_DATAPATH_IP,dst=CLASSIFIER_DECAP_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            recvTemplate = ether / ip1 / ip2 / udp /Raw(load=data)
        elif DUTType == MONITOR:
            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=TESTER_DATAPATH_IP,dst=MONITOR_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            senderTemplate = ether / ip1 / ip2 / udp /Raw(load=data)

            data = "X" * 22
            ether = Ether(src=DUT_DATAPATH_MAC, dst=TESTER_DATAPATH_MAC)
            ip1 = IP(src=SFF1_DATAPATH_IP,dst=CLASSIFIER_DECAP_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            recvTemplate = ether / ip1 / ip2 / udp /Raw(load=data)
        elif DUTType == LB:
            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=TESTER_DATAPATH_IP,dst=LB_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            senderTemplate = ether / ip1 / ip2 / udp /Raw(load=data)

            data = "X" * 22
            ether = Ether(src=DUT_DATAPATH_MAC, dst=TESTER_DATAPATH_MAC)
            ip1 = IP(src=SFF1_DATAPATH_IP,dst=CLASSIFIER_DECAP_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            recvTemplate = ether / ip1 / ip2 / udp /Raw(load=data)
        elif DUTType == NAT:
            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=TESTER_DATAPATH_IP,dst=NAT_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            senderTemplate = ether / ip1 / ip2 / udp /Raw(load=data)

            data = "X" * 22
            ether = Ether(src=DUT_DATAPATH_MAC, dst=TESTER_DATAPATH_MAC)
            ip1 = IP(src=SFF1_DATAPATH_IP,dst=CLASSIFIER_DECAP_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            recvTemplate = ether / ip1 / ip2 / udp /Raw(load=data)
        elif DUTType == VPN:
            data = "X" * 22
            ether = Ether(src=TESTER_DATAPATH_MAC, dst=DUT_DATAPATH_MAC)
            ip1 = IP(src=TESTER_DATAPATH_IP,dst=VPN_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            senderTemplate = ether / ip1 / ip2 / udp /Raw(load=data)

            data = "X" * 22
            ether = Ether(src=DUT_DATAPATH_MAC, dst=TESTER_DATAPATH_MAC)
            ip1 = IP(src=SFF1_DATAPATH_IP,dst=CLASSIFIER_DECAP_DATAPATH_IP, tos=0x18)
            ip2 = IP(src=INNER_SRC_IP,dst=INNER_DST_IP)
            udp = UDP(sport=80,dport=1234)
            recvTemplate = ether / ip1 / ip2 / udp /Raw(load=data)
        else:
            pass

        return [senderTemplate, recvTemplate]

    def saveTemplate(self, pT, savePath):
        wrpcap(savePath, pT, append=False)  #appends packet to output file

if __name__ == "__main__":
    pTG = PktTemplateGenerator()

    for dutType in [SWITCH, CLASSIFIER, FWD, FW, MONITOR, LB, NAT, VPN]:
        [senderTemplate, recvTemplate] = pTG.genPktTemplate(dutType)
        pTG.saveTemplate(senderTemplate, "./sender_" + dutType + ".pcap")
        pTG.saveTemplate(recvTemplate, "./receiver_" + dutType + ".pcap")
