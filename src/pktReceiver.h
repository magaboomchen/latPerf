#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <string>
#include <netinet/ether.h>  // ETHER_ADDR_LEN

#include "pktTemplates.h"
#include "networkHeader.h"

using namespace std;

#ifndef PKTRECEIVER_H
#define PKTRECEIVER_H

struct PcapLoopArg{
    vector<struct TemplateEntry> &buffer;
};

struct ThroughputDataPoint{
    long long currentTimePoint;
    float throughtput;
    long long pps;
};

struct PcapLoopThroughputArg{
    vector<struct ThroughputDataPoint> &throughputDataPoints;
    long long &currentTimePoint;
    long long &lastTimePoint;
    long long &pktCount;
    long long &byteCount;
};

struct PcapLoopThroughputSubArg{
    long long &pktCount;
    long long &byteCount;
};

/*
pktRecveiver: 
function:
recv(recv pkt and store it in buffer)
*/
class PktReceiver{
    public:
        PktReceiver(void);
        PktReceiver(string interfaceName, PktTemplates &t);
        void setBPF(string totalBPF);
        void startListen(void);
        void startThroughputListen(void);
        void stopListen(void);
        vector<struct TemplateEntry> getBuffer(void);
        void setBufferExpSize(int bufferExpectedSize);
        long long getCurrentTimeInMillisecondUnit(void);
        bool canRecordThroughput(void);
        void recordThroughput(void);
        void logThroughputDataPoints(void);
    private:
        char ifName[IFNAMSIZ];
        PktTemplates t;

        char *dev;
        pcap_t *descr;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;

        int bufferExpectedSize;
        vector<struct TemplateEntry> buffer;
        vector<struct ThroughputDataPoint> throughputDataPoints;

        long long pktCount;
        long long byteCount;
        long long lastTimePoint;
        long long currentTimePoint;
};

static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
static void packetHandlerForThroughput(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
static long long getCurrentTimeInMillisecondUnit(void);
static bool canRecordThroughput(long long currentTimePoint, long long lastTimePoint);
static struct ThroughputDataPoint getThroughputDataPoint(long long currentTimePoint, long long byteCount);

#endif