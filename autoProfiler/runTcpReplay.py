#!/usr/bin/python
# -*- coding: UTF-8 -*-

from sam.base.shellProcessor import ShellProcessor
from sam.base.loggerConfigurator import LoggerConfigurator
from sam.base.argParser import *


class ArgParser(ArgParserBase):
    def __init__(self, *args, **kwargs):
        super(ArgParser, self).__init__(*args, **kwargs)
        self.parser = argparse.ArgumentParser(description='run tcpreplay', add_help=False)
        self.parser.add_argument('-m', metavar='m', type=float,
            help='multiplier of traffic rate')
        self.parser.add_argument('-i', metavar='i', type=str,
            help='interface')
        self.parser.add_argument('-f', metavar='f', type=str,
            help='pcap file')
        self.parser.add_argument("--netmap", help="netmap arg",
           action="store_true")
        self.parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                            help='Show this help message and exit. Example usage: python runTcpReplay 10.0')
        self.args = self.parser.parse_args()


if __name__ == "__main__":
    argParser = ArgParser()
    multiplier = argParser.getArgs()['m']   # example: 0000:00:08.0
    interface = argParser.getArgs()['i']    # example: enp4s0
    pcapFilePath = argParser.getArgs()['f']    # example: "~/HaoChen/Projects/pcapRewrite/pcap/classifeirProfiling.pcap";"~/HaoChen/Datasets/imc10DC/22.pcap"
    netmapEnable = argParser.args.netmap

    logConfigur = LoggerConfigurator('runTcpReplay', './log', 'tcpReplayStarter.log', level='debug')
    logger = logConfigur.getLogger()

    sp = ShellProcessor()
    logger.info("run tcpreplay")
    if netmapEnable:
        netmap = " --netmap "
    else:
        netmap = " "
    sp.runShellCommand(
        "sudo tcpreplay -i " + str(interface) \
            + " -K --multiplier=" + str(multiplier) + netmap \
            + " --loop 500 " + pcapFilePath)
    # sudo tcpreplay -i enp5s0f0 --loop 10 -K --multiplier=1000 ./22.pcap 
