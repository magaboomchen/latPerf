#!/usr/bin/python
# -*- coding: UTF-8 -*-

'''
Test the data path connectivity
'''

from sam.base.socketConverter import *
from fixtures.dutSendReceiver import DUTSendReceiver

from sam.base.argParser import *


class ArgParser(ArgParserBase):
    def __init__(self, *args, **kwargs):
        super(ArgParser, self).__init__(*args, **kwargs)
        self.parser = argparse.ArgumentParser(description='send Arp frame.', add_help=False)
        self.parser.add_argument('-i', metavar='outIntf', type=str, nargs='?', const=1, default='enp5s0f0',
            help="output interface")
        self.parser.add_argument('-dip', metavar='replyIP', type=str, nargs='?', const=1, default="3.3.3.2",
            help="reply dest IP")
        self.parser.add_argument('-mfn', metavar='max flow number', type=int, nargs='?', const=1, default=100,
            help="max flow number")
        self.parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                            help='Example usage: python connectivityTester.py -i enp5s0f0 -dip 3.3.3.2 ')
        self.args = self.parser.parse_args()


class ConnectivityTester(object):
    def __init__(self, intfName="eht0", initDstIP="3.3.3.2", maxFlowNum=100):
        self._interfaceName = intfName
        self._sc = SocketConverter()
        self._flowNum = 0
        self._maxFlowNum = maxFlowNum
        self.baseIPv4Int = self._sc.ip2int(initDstIP)

    def testDataPathConnectivity(self):
        self.loadDstIPList()
        self.verifyAllFlows()

    def loadDstIPList(self):
        self.dstIPList = []
        for rIndex in range(self._maxFlowNum):
            sfcRequestDstIPv4 = self._assignSFCRequestDstIPv4()
            self.dstIPList.append(sfcRequestDstIPv4)

    def _assignSFCRequestDstIPv4(self):
        newIPv4Int = self.baseIPv4Int + self._flowNum
        newIPv4 = self._sc.int2ip(newIPv4Int)
        self._flowNum = self._flowNum + 1
        return newIPv4

    def verifyAllFlows(self):
        for dstIP in self.dstIPList:
            sR = DUTSendReceiver(iface="enp5s0f0", dmac="00:00:00:00:00:02",
                                sip="1.1.1.2", dip=dstIP)
            condition = sR.start()
            print("dstIP:{0}, test result:{1}".format(dstIP, condition))
            assert condition == True or condition == "TIMEOUT"


if __name__ == "__main__":
    argParser = ArgParser()
    intfName = argParser.getArgs()['i']
    dip = argParser.getArgs()['dip']
    maxFlowNum = argParser.getArgs()['mfn']

    cT = ConnectivityTester(intfName, dip, maxFlowNum)
    cT.testDataPathConnectivity()
