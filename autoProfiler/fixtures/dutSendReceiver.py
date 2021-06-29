#!/usr/bin/python
# -*- coding: UTF-8 -*-

'''
Send Recveiver
'''

import time

from scapy.all import *
from getmac import get_mac_address

from fixtures.sendArpReply import sendArpReply

BACKGROUND_TRAFFIC_TOS = 0x00
LATENCY_MEASUREMENT_TRAFFIC_TOS = 0x18
IP_PROTO_TCP = 0x06
DELTA_TIMEOUT = 0.1
TIMEOUT = 0.8


class DUTSendReceiver(object):
    def __init__(self, iface, dmac, sip, dip):
        self._initialTryNum = 3
        self._maxPktNum = 2
        self._interval = 1
        self.iface = iface
        self.smac = self._getHwAddrInKernel(iface)
        self.dmac = dmac
        self.sip = sip
        self.dip = dip
        self.dutIP = "1.1.1.1"
        self.condition = None

    def start(self):
        self._init()
        self._sendRecv()
        self._waitRecvProcess()
        return self.condition

    def _init(self):
        sendArpReply(outIntf=self.iface, psrc=self.sip, replyIP=self.dutIP,
                        hwsrc=self.smac, hwdst=self.dmac)
        for tryNum in range(self._initialTryNum):
            self.sendInboundTraffic2DUT(self.iface, self.sip, self.dip)

    def _sendRecv(self):
        # formal send
        self.recvTraffic(self.iface, self.smac, self.sip, self.dip)
        self.asyncSniffer.start()
        count = 0
        try:
            while True:
                print("send {0}-th pkt".format(count))
                count = count + 1
                self.sendInboundTraffic2DUT(self.iface, self.sip, self.dip)
                if count >= self._maxPktNum:
                    break
                else:
                    time.sleep(self._interval)
        except:
            print("close scapy!")
            self.asyncSniffer.stop()
        finally:
            pass

    def sendInboundTraffic2DUT(self, iface, sip, dip):
        # smac = "00:00:00:00:00:01"
        # dmac = "00:00:00:00:00:02"
        dmac = self.dmac
        ether = Ether(src=self.smac, dst=dmac)
        ip = IP(src=sip, dst=dip, tos=BACKGROUND_TRAFFIC_TOS)
        tcp = TCP(sport=1234, dport=80)
        data = "Hello World"
        frame = ether / ip / tcp /Raw(load=data)
        sendp(frame, iface=iface, verbose=0)

    def _getHwAddrInKernel(self, ifName):
        ethMac = get_mac_address(interface=ifName)
        return ethMac.lower()

    def recvTraffic(self, iface, dmac, sip, dip):
        self.asyncSniffer = AsyncSniffer(
            filter="ether dst " + str(dmac) +
                    " and ip and dst " + self.dip,
                    iface=iface, prn=self.frame_callback,
                    count=0, store=0)

    def frame_callback(self, frame): 
        print("get a frame")
        # frame.show()

        self.condition = (
            frame[Ether].dst == self.smac
            and frame[IP].src == self.sip
            and frame[IP].dst == self.dip
            and frame[IP].proto == IP_PROTO_TCP)

        assert self.condition == True

    def _waitRecvProcess(self):
        elapse = 0
        while True:
            if self.condition != None:
                self.asyncSniffer.stop()
                return 
            elif elapse > TIMEOUT:
                self.asyncSniffer.stop()
                self.condition = "TIMEOUT"
                return 
            else:
                elapse = elapse + DELTA_TIMEOUT
            time.sleep(DELTA_TIMEOUT)
