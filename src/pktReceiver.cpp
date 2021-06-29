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
#include <sys/time.h>

#include "pktReceiver.h"
#include "pktTemplates.h"

using namespace std;

DECLARE_string(mode);
DECLARE_int32(gra);

long long PKT_COUNT = 0;
long long BYTE_COUNT = 0;
bool receiverQuitFlag = false;


PktReceiver::PktReceiver(void){
    LOG(INFO) << "Initial packet receiver." ;
}

PktReceiver::PktReceiver(string interfaceName, PktTemplates &t){
    LOG(INFO) << "Initial packet receiver." ;

    this->pktCount = 0;
    this->byteCount = 0;
    this->lastTimePoint = this->getCurrentTimeInMillisecondUnit();
    this->currentTimePoint = this->getCurrentTimeInMillisecondUnit();

    memcpy(ifName, interfaceName.c_str(), IFNAMSIZ);
    LOG(INFO) << "ifName: " << ifName;

    this->t = t;

    // check interface status
    dev = ifName;
    LOG(INFO) << "dev is " << dev;

    // sniff the dev
    if (FLAGS_mode == "latency"){
        descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    }else if (FLAGS_mode == "throughput"){
        LOG(INFO) << "snapLen: 64" ;
        descr = pcap_open_live(dev, 64, 1, -1, errbuf);
    }

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
    struct PcapLoopArg pla = {buffer};
    int rv = pcap_loop(descr, -1, packetHandler, (u_char*)&pla);
    if(rv != -2){
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

    struct PcapLoopArg pla = *(struct PcapLoopArg *)userData;
    vector<struct TemplateEntry> &buffer = pla.buffer;
    buffer.push_back(te);
}

void PktReceiver::startThroughputListen(void){
    LOG(INFO) << "start listen on interface: " << ifName ;
    // capture packets
    int rv = pcap_loop(descr, -1, packetHandlerForThroughput, NULL);
    if(rv != -2){
        LOG(ERROR) << "pcap_loop() failed: " <<  pcap_geterr(descr);
        throw std::invalid_argument("pcap_loop() failed");
    }else{
        LOG(INFO) << "pcap_loop() stop successul." ;
    }
    pcap_close(descr);
}

static void packetHandlerForThroughput(u_char *userData,
                                        const struct pcap_pkthdr *pkthdr,
                                        const u_char *packet){
    PKT_COUNT += 1;
    BYTE_COUNT += pkthdr->len;
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

long long PktReceiver::getCurrentTimeInMillisecondUnit(void){
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long long ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    return ms;
}

static long long getCurrentTimeInMillisecondUnit(void){
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long long ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    return ms;
}

void PktReceiver::recordThroughput(void){
    long long LAST_PKT_COUNT = 0;
    long long LAST_BYTE_COUNT = 0;
    float timePoint = 0;
    while(!receiverQuitFlag){
        float elapse = FLAGS_gra/1000.0;    // unit: seconds
        usleep(elapse * 1000.0 * 1000.0);
        timePoint += elapse * 1000.0;
        long long deltaPktCount = PKT_COUNT - LAST_PKT_COUNT;
        long long deltaByteCount = BYTE_COUNT - LAST_BYTE_COUNT;
        float throughput = (deltaByteCount * 8 /1000.0 /1000.0)/elapse;
        long long pps = deltaPktCount / elapse;
        struct ThroughputDataPoint tdp = {currentTimePoint:timePoint,
                                            throughtput:throughput,
                                            pps:pps};
        this->throughputDataPoints.push_back(tdp);

        LAST_PKT_COUNT = PKT_COUNT;
        LAST_BYTE_COUNT = BYTE_COUNT;
    }

}

void PktReceiver::logThroughputDataPoints(void){
    LOG(INFO) << "logThroughputDataPoints:";
    for(int i=0;i<throughputDataPoints.size();i++){
        struct ThroughputDataPoint dataPoint = throughputDataPoints.at(i);
        LOG(INFO)<< "timePoint: " << dataPoint.currentTimePoint
                    << "ms \t throughput: " << dataPoint.throughtput
                    << "Mbps \t pkt count: " << dataPoint.pps;
        google::FlushLogFiles(google::INFO);
    }
}
