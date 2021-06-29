#!/usr/bin/python
# -*- coding: UTF-8 -*-

import scapy

from autoProfiler import AutoProfiler


class Profiler(object):
    def __init__(self):
        self.aP = AutoProfiler()

    def highPerformanceProfile(self):
        pass
        # self.setNetMap(self.aP)
        # self.switchProfileWithNetmap(self.aP)
        # self.classifierProfile(self.aP)
        # self.fwdProfile(self.aP)
        # self.fwProfile(self.aP)
        # self.monitorProfile(self.aP)
        # self.lbProfile(self.aP)

    def lowPerformanceProfile(self):
        self.setKernelNIC(self.aP)
        self.natProfile(self.aP)
        # self.vpnProfile(self.aP)

    def setNetMap(self, aP):
        self.aP.multiplierRange = [
            40000.0,
            100000.0,
            150000.0,
            170000.0,
            178000.0,
            181000.0,
            184000.0,
            187000.0,
            190000.0,
            200000.0
        ]

        self.aP.xticklabels = range(10, 110, 10)
        self.aP.tcpreplayInterface ="enp4s0"
        self.aP.netmapEnable = True

    def setKernelNIC(self, aP):
        self.aP.multiplierRange = range(1,11,1)
        self.aP.xticklabels = range(1, 11, 1)
        self.aP.tcpreplayInterface ="enp4s0"
        self.aP.netmapEnable = False

    def switchProfileWithNetmap(self, aP):
        self.aP.startSwitchProfiling(latPerfInterface="eno2")
        self.aP.startProfileAnalysis()
        self.aP.drawSwitchStatistic()

    def classifierProfile(self, aP):
        self.aP.startClassifierProfiling(latPerfInterface="eno2")
        self.aP.startProfileAnalysis()
        self.aP.drawSwitchStatistic()

    def fwdProfile(self, aP):
        self.aP.startFWDProfiling(latPerfInterface="eno2")
        self.aP.startProfileAnalysis()
        self.aP.drawSwitchStatistic()

    def fwProfile(self, aP):
        self.aP.startFWProfiling(latPerfInterface="eno2")
        self.aP.startProfileAnalysis()
        self.aP.drawSwitchStatistic()

    def monitorProfile(self, aP):
        self.aP.startMonitorProfiling(latPerfInterface="eno2")
        self.aP.startProfileAnalysis()
        self.aP.drawSwitchStatistic()

    def lbProfile(self, aP):
        self.aP.startLBProfiling(latPerfInterface="eno2")
        self.aP.startProfileAnalysis()
        self.aP.drawSwitchStatistic()

    def natProfile(self, aP):
        self.aP.startNATProfiling(latPerfInterface="eno2")
        self.aP.startProfileAnalysis()
        self.aP.drawSwitchStatistic()

    def vpnProfile(self, aP):
        self.aP.startVPNProfiling(latPerfInterface="eno2")
        self.aP.startProfileAnalysis()
        self.aP.drawSwitchStatistic()


if __name__ == "__main__":
<<<<<<< HEAD
    p = Profiler()
    p.highPerformanceProfile()
    # p.lowPerformanceProfile()
=======
    ap = AutoProfiler()

    setNetMap(ap)
    # switchProfileWithNetmap(ap)
    # classifierProfile(ap)
    # fwdProfile(ap)
    fwProfile(ap)
    # monitorProfile(ap)
    # lbProfile(ap)

    # setKernelNIC(ap)
    # natProfile(ap)
    # vpnProfile(ap)
>>>>>>> 6ffbaca67589f2ad639f94572edb24b19adfb27e
