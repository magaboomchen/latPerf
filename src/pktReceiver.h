#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <string>
#include <netinet/ether.h>  // ETHER_ADDR_LEN

#include "pktTemplates.h"
#include "networkHeader.h"

#ifndef PKTRECEIVER_H
#define PKTRECEIVER_H

using namespace std;


struct PcapLoopArg{
    vector<struct TemplateEntry> &buffer;
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
        void stopListen(void);
        vector<struct TemplateEntry> getBuffer(void);
        void setBufferExpSize(int bufferExpectedSize);
    private:
        char ifName[IFNAMSIZ];
        PktTemplates t;

        char *dev;
        pcap_t *descr;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;

        int bufferExpectedSize;
        vector<struct TemplateEntry> buffer;
};

static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif