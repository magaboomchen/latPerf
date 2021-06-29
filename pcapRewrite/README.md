# pcapRewrite

# Prerequest
```
gflags
glog
cmake
g++
```

# Installation
```
cd build
cmake ..
make
```

# example
```
./pcapRewrite -f ./pcap/slice/delVlan_00000_20091218013025 -w ./pcap/test.pcap -dstipmap 2.2.2.2 -osrcip 2.2.0.36 -odstip 10.16.1.1 -trunMTU=1418
```

# classifier traffic
```
Maunal 

tcprewrite -m 1414 --mtu-trunc --enet-vlan=del --infile=./pcap/univ1_pt20.pcap --outfile=./pcap/univ1_pt20_delVLAN.pcap

./pcapRewrite -f ./pcap/univ1_pt20_delVLAN.pcap -w ./pcap/univ1_pt20_delVLAN_mapDstip.pcap -dstipmap 2.2.2.2

tcprewrite --fixlen=pad -C --infile=./pcap/univ1_pt20_delVLAN_mapDstip.pcap --outfile=./pcap/classifeirProfiling.pcap

```


```
script

cd profilePcapGen

python ./profilePcapGen.py
```