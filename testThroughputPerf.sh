#!/bin/bash

sudo taskset -c 6 ./latPerf -mode throughput -i enp5s0f0 -sptp ./pktTemplate/sender_CLASSIFIER.pcap -rptp ./pktTemplate/receiver_CLASSIFIER.pcap -d 200 -pps 50 -o ./output.txt
