#!/usr/bin/python
# -*- coding: UTF-8 -*-

from autoProfiler import AutoProfiler


def setNetMap(ap):
    ap.multiplierRange = [
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

    ap.xticklabels = range(10, 110, 10)
    ap.tcpreplayInterface ="enp4s0"
    ap.netmapEnable = True

def setKernelNIC(ap):
    ap.multiplierRange = range(1,11,1)
    ap.xticklabels = range(1, 11, 1)
    ap.tcpreplayInterface ="enp4s0"
    ap.netmapEnable = False

def switchProfileWithNetmap(ap):
    ap.startSwitchProfiling(latPerfInterface="eno2")
    ap.startProfileAnalysis()
    ap.drawSwitchStatistic()

def classifierProfile(ap):
    ap.startClassifierProfiling(latPerfInterface="eno2")
    ap.startProfileAnalysis()
    ap.drawSwitchStatistic()

def fwdProfile(ap):
    ap.startFWDProfiling(latPerfInterface="eno2")
    ap.startProfileAnalysis()
    ap.drawSwitchStatistic()

def fwProfile(ap):
    ap.startFWProfiling(latPerfInterface="eno2")
    ap.startProfileAnalysis()
    ap.drawSwitchStatistic()

def monitorProfile(ap):
    ap.startMonitorProfiling(latPerfInterface="eno2")
    ap.startProfileAnalysis()
    ap.drawSwitchStatistic()

def lbProfile(ap):
    ap.startLBProfiling(latPerfInterface="eno2")
    ap.startProfileAnalysis()
    ap.drawSwitchStatistic()

def natProfile(ap):
    ap.startNATProfiling(latPerfInterface="eno2")
    ap.startProfileAnalysis()
    ap.drawSwitchStatistic()

def vpnProfile(ap):
    ap.startVPNProfiling(latPerfInterface="eno2")
    ap.startProfileAnalysis()
    ap.drawSwitchStatistic()

if __name__ == "__main__":
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
