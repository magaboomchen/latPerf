#!/usr/bin/python
# -*- coding: UTF-8 -*-

import time
import os

import numpy as np

from base.shellProcessor import ShellProcessor
from base.loggerConfigurator import LoggerConfigurator
from profilePlotter import ProfilePlotter


class AutoProfiler(object):
    def __init__(self, pcapFilePath = "~/HaoChen/Datasets/imc10DC/22.pcap"):
        logConfigur = LoggerConfigurator('AutoProfiler',
            './log', 'all.log', level='debug')
        self.logger = logConfigur.getLogger()
        self.sp = ShellProcessor()
        self.latPerfInterface = None
        self.tcpreplayInterface = None
        self.netmapEnable = False
        self.pcapFilePath = pcapFilePath
        self.xticklabels = range(1, 11, 1)
        self.multiplierRange = range(1, 11, 1)

    def startSwitchProfiling(self, latPerfInterface="enp5s0f0"):
        self.latPerfInterface = latPerfInterface
        self.fileDir = "../profile/switchProfile"
        self._mkdir(self.fileDir)
        self.sptp = "../pktTemplate/sender_SWITCH.pcap"
        self.rptp = "../pktTemplate/receiver_SWITCH.pcap"
        self._startProfiling()

    def startClassifierProfiling(self, latPerfInterface="enp5s0f0"):
        self.latPerfInterface = latPerfInterface
        self.fileDir = "../profile/classifierProfile"
        self._mkdir(self.fileDir)
        self.sptp = "../pktTemplate/sender_CLASSIFIER.pcap"
        self.rptp = "../pktTemplate/receiver_CLASSIFIER.pcap"
        self.pcapFilePath = "../pcapRewrite/pcap/classifierProfiling.pcap"
        self._startProfiling()

    def startFWDProfiling(self, latPerfInterface="enp5s0f0"):
        self.latPerfInterface = latPerfInterface
        self.fileDir = "../profile/fwdProfile"
        self._mkdir(self.fileDir)
        self.sptp = "../pktTemplate/sender_FWD.pcap"
        self.rptp = "../pktTemplate/receiver_FWD.pcap"
        self.pcapFilePath = "../pcapRewrite/pcap/fwdProfiling.pcap"
        self._startProfiling()

    def startFWProfiling(self, latPerfInterface="enp5s0f0"):
        self.latPerfInterface = latPerfInterface
        self.fileDir = "../profile/fwProfile"
        self._mkdir(self.fileDir)
        self.sptp = "../pktTemplate/sender_FW.pcap"
        self.rptp = "../pktTemplate/receiver_FW.pcap"
        self.pcapFilePath = "../pcapRewrite/pcap/fwProfiling.pcap"
        self._startProfiling()

    def startMonitorProfiling(self, latPerfInterface="enp5s0f0"):
        self.latPerfInterface = latPerfInterface
        self.fileDir = "../profile/monitorProfile"
        self._mkdir(self.fileDir)
        self.sptp = "../pktTemplate/sender_MONITOR.pcap"
        self.rptp = "../pktTemplate/receiver_MONITOR.pcap"
        self.pcapFilePath = "../pcapRewrite/pcap/monitorProfiling.pcap"
        self._startProfiling()

    def startLBProfiling(self, latPerfInterface="enp5s0f0"):
        self.latPerfInterface = latPerfInterface
        self.fileDir = "../profile/lbProfile"
        self._mkdir(self.fileDir)
        self.sptp = "../pktTemplate/sender_LB.pcap"
        self.rptp = "../pktTemplate/receiver_LB.pcap"
        self.pcapFilePath = "../pcapRewrite/pcap/lbProfiling.pcap"
        self._startProfiling()

    def startNATProfiling(self, latPerfInterface="enp5s0f0"):
        self.latPerfInterface = latPerfInterface
        self.fileDir = "../profile/natProfile"
        self._mkdir(self.fileDir)
        self.sptp = "../pktTemplate/sender_NAT.pcap"
        self.rptp = "../pktTemplate/receiver_NAT.pcap"
        self.pcapFilePath = "../pcapRewrite/pcap/natProfiling.pcap"
        self._startProfiling()

    def startVPNProfiling(self, latPerfInterface="enp5s0f0"):
        self.latPerfInterface = latPerfInterface
        self.fileDir = "../profile/vpnProfile"
        self._mkdir(self.fileDir)
        self.sptp = "../pktTemplate/sender_VPN.pcap"
        self.rptp = "../pktTemplate/receiver_VPN.pcap"
        self.pcapFilePath = "../pcapRewrite/pcap/vpnProfiling.pcap"
        self._startProfiling()

    def _mkdir(self, fileDir):
        try:
            os.mkdir(fileDir)
        except:
            pass

    def _startProfiling(self):
        for multiplier in self.multiplierRange:
            self._startTcpReplay(float(multiplier))
            time.sleep(15)
            if self._isTcpReplayRun():
                outputFile = self.fileDir + "/profile_m=" + str(multiplier)
                self._startLatPerf(self.latPerfInterface, self.sptp,
                    self.rptp, 10, 10000, outputFile)
                self._stopTcpReplay()
            else:
                raise ValueError("tcp start failed!")

    def _startTcpReplay(self, multiplier):
        self.logger.debug("start tcpreplay")
        if self.netmapEnable:
            netmap = " --netmap "
        else:
            netmap = " "
        self.sp.runPythonScript("./runTcpReplay.py -m " + str(multiplier) \
            + " -i " + self.tcpreplayInterface + netmap + " -f " + self.pcapFilePath)
        # ./runTcpReplay.py -m 1 -i enp5s0f0 -f ./22.pcap

    def _isTcpReplayRun(self):
        tcpreplayStatus = self.sp.isProcessRun("tcpreplay")
        self.logger.debug("tcpreplayStatus: {0}".format(tcpreplayStatus))
        return tcpreplayStatus

    def _stopTcpReplay(self):
        self.logger.debug("kill tcpreplay")
        self.sp.killPythonScript("runTcpReplay.py")
        self.sp.killProcess("tcpreplay")
        tcpreplayStatus = self.sp.isProcessRun("tcpreplay")
        self.logger.debug("tcpreplayStatus: {0}".format(tcpreplayStatus))

    def _startLatPerf(self, latPerfInterface, sptp, rptp, d, pps, output):
        cmd = "sudo ../latPerf -i " + str(latPerfInterface) \
            + " -sptp " + str(sptp) \
            + " -rptp " + str(rptp) + " -d " + str(d) + " -pps " + str(pps) \
            + " -o " + str(output)
        self.sp.runProcess(cmd)

    def startProfileAnalysis(self):
        self._readProfile()
        self._genStatistic()
        self._saveStatistic()

    def _readProfile(self):
        self.latencysDict = {}
        for multiplier in self.multiplierRange:
            self.latencysDict[multiplier] = {"latencyList":[]}
            with open(self.fileDir + '/profile_m='+str(multiplier), 'r') as f:
                lines = f.readlines()
                for line in lines:
                    latency = int(line.strip("\n"))
                    self.latencysDict[multiplier]["latencyList"].append(latency)

    def _genStatistic(self):
        for key in self.latencysDict.iterkeys():
            latencyList = self.latencysDict[key]["latencyList"]
            # min, p25, median, p75, max, avg
            self.latencysDict[key]["min"] = np.min(latencyList)
            self.latencysDict[key]["0.25"] = np.percentile(latencyList, 25)
            self.latencysDict[key]["median"] = np.median(latencyList)
            self.latencysDict[key]["0.75"] = np.percentile(latencyList, 75)
            self.latencysDict[key]["max"] = np.max(latencyList)
            self.latencysDict[key]["avg"] = np.mean(latencyList)

    def _saveStatistic(self):
        with open(self.fileDir + '/statistic', 'w') as f:
            f.write("multiplier\tmin\t0.25\tmedian\t0.75\tmax\tavg\n")
            for key in self.latencysDict.iterkeys():
                f.write("{0}\t\t\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\n".format(
                    key,
                    self.latencysDict[key]["min"],
                    self.latencysDict[key]["0.25"],
                    self.latencysDict[key]["median"],
                    self.latencysDict[key]["0.75"],
                    self.latencysDict[key]["max"],
                    self.latencysDict[key]["avg"]
                ))

    def drawSwitchStatistic(self):
        p = ProfilePlotter()
        p.addLatencyDict(self.latencysDict, self.xticklabels)
        p.drawProfile("Multiplier(x)", "Latency(us)",
            "Latency Profile",
            ["measurement"])
        p.saveFig(self.fileDir + "/statistic.pdf")

