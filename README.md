# latency profiling tool based on libpcap

## Prerequisites
```
libcap-devel
gcc-c++
gFlags: sudo apt-get install libgflags-dev
gLog: sudo apt-get install -y libgoogle-glog-dev
Tcpreplay with/without netmap: https://tcpreplay.appneta.com/
```

## Install LatPerf
```
mkdir build
cd build
cmake ..
make
```

## Overview
```
LatPerf sends probes (i.e. packets with special tag) to Device Under Test(DUT).
DUT will forward back these probes to LatPerf.
LatPerf record all probes' timestamps when they are sent out and received in.
These timestamps are store in DRAM to make sure high performance.
More information can be obtained in /latPerf/doc/
```

## Usage
latPerft sends traffic based on packet template

```
./latPerf -i ${INTERFACE} \
    -sptp ${SEND_PKT_TEMPLATE_PCAP} \
    -rptp ${RECV_PKT_TEMPLATE_PCAP} \
    -d ${DURATION} \
    -pps ${PACKET_PER_SECOND} \
    -o ${OUTPUT_FILE}
```

* Use pktTemplateGen to generate packet template, e.g. generate a packet with IP-in-IP tunnel, etc.
* Cautions
    * latPerf sets outter ip header's TOS to 0x03 to distinct measurement packet from background traffic.
    * the production of ${DURATION} and ${PACKET_PER_SECOND} can't exceed the DRAM size.

## Usage Example
#### Manual
```
sudo ./latPerf -i enp4s0 -sptp ./pktTemplate/sender_SWITCH.pcap \
    -rptp ./pktTemplate/receiver_SWITCH.pcap -d 2 -pps 5 -o ./output.txt

sudo ./latPerf -i enp5s0f0 -sptp ./pktTemplate/sender_CLASSIFIER.pcap \
    -rptp ./pktTemplate/receiver_CLASSIFIER.pcap -d 2 -pps 5 -o ./output.txt

sudo ./latPerf -i enp5s0f0 -sptp ./pktTemplate/sender_FW.pcap \
    -rptp ./pktTemplate/receiver_FW.pcap -d 10 -pps 1000 -o ./output.txt

sudo ./latPerf -i eno2 -sptp ./pktTemplate/sender_SWITCH.pcap \
    -rptp ./pktTemplate/receiver_SWITCH.pcap -d 2 -pps 5 -o ./output.txt
```

#### Scripts
```
cd autoProfiler
python ./main.py
```

```
sudo ./latPerf -i enp5s0f0 -sptp ./pktTemplate/senderSFF.pcap \
    -rptp ./pktTemplate/receiverSFF.pcap -d 2 -pps 5 -o ./output.txt
```

## Output file format
packet e2e latency, e.g.:
```
14
15
102
32
INF
34
12
Duplicate
18
Error
18
89
```

# BUG LIST

# TODO LIST
* Measure N flows' end-to-end latency 
