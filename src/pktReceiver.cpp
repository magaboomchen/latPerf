#include <iostream>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>	//close
#include <netinet/in.h>
#include <net/if.h>// struct ifreq
#include <sys/ioctl.h> // ioctl, SIOCGIFADDR
#include <sys/socket.h> // socket
#include <netinet/ether.h> // ETH_P_ALL, ETHER_ADDR_LEN
#include <netpacket/packet.h> // struct sockaddr_ll
#include <linux/ip.h> //iphdr
#include <arpa/inet.h> // inet_ntoa, in_addr

#include "pktReceiver.h"
#include "pktTemplates.h"

using namespace std;


PktReceiver::PktReceiver(void){
    LOG(INFO) << "Initial packet receiver." ;
}

PktReceiver::PktReceiver(string interfaceName, PktTemplates &t){
    LOG(INFO) << "Initial packet receiver." ;

    memcpy(ifName, interfaceName.c_str(), IFNAMSIZ);
    LOG(INFO) << "ifName: " << ifName;

    this->t = t;

    // check interface status
    dev = ifName;
    LOG(INFO) << "dev is " << dev;

    // sniff the dev
    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL){
        LOG(ERROR) << "pcap_open_live() failed: " << errbuf ;
        throw std::invalid_argument("pcap_open_live() failed");
    }

}

void PktReceiver::setBPF(string totalBPF){
    int rv = pcap_compile(descr, &filter, totalBPF.c_str(), 1, 0);
    if(rv != 0){
        LOG(ERROR) << "pcap_compile failed: " <<  pcap_geterr(descr);
        throw std::invalid_argument("pcap_compile failed");
    }
    rv = pcap_setfilter(descr, &filter);
    if(rv != 0){
        LOG(ERROR) << "pcap_setfilter failed: " <<  pcap_geterr(descr);
        throw std::invalid_argument("pcap_setfilter failed");
    }
}

void PktReceiver::startListen(void){
    LOG(INFO) << "start listen on interface: " << ifName ;
    // capture packets
    buffer.reserve(bufferExpectedSize);
    PcapLoopArg pla = {buffer};
    int rv = pcap_loop(descr, -1, packetHandler, (u_char*)&pla);
    if (rv != -2){
        LOG(ERROR) << "pcap_loop() failed: " <<  pcap_geterr(descr);
        throw std::invalid_argument("pcap_loop() failed");
    }else{
        LOG(INFO) << "pcap_loop() stop successul." ;
    }
    pcap_close(descr);
}

static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    // LOG(INFO) << "recev an pkt!" ;
    
    struct TemplateEntry te;
    struct pcap_pkthdr header;
    memcpy(&header, pkthdr, sizeof(struct pcap_pkthdr));
    te.header = header;
    u_char data[MAX_PACKET_LENGTH];
    memcpy(data, packet, sizeof(data));
    memcpy(te.data, data, sizeof(data));

    PcapLoopArg pla = *(struct PcapLoopArg *)userData;
    vector<struct TemplateEntry> &buffer = pla.buffer;
    buffer.push_back(te);
}

void PktReceiver::stopListen(void){
    pcap_breakloop(descr);
}

vector<struct TemplateEntry> PktReceiver::getBuffer(void){
    return buffer;
}

void PktReceiver::setBufferExpSize(int bufferExpectedSize){
    this->bufferExpectedSize = bufferExpectedSize;
}