#include <iostream>
#include <stdexcept>

#include <pcap.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "global.h"
#include "pktTemplates.h"
#include "networkHeader.h"
#include "pktSender.h"

using namespace std;

DECLARE_int32(pps);


PktSender::PktSender(string interfaceName, PktTemplates &t){
    memcpy(ifName, interfaceName.c_str(), IFNAMSIZ);
    LOG(INFO) << "ifName: " << ifName;

    this->t = t;

    // initial raw socket
    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock_r<0){
        perror("Create raw socket: ");
		exit(1);
	}
	LOG(INFO) << "Create raw socket successfully.";

    // raw socket structure
    struct ifreq req;

    strncpy(req.ifr_name, interfaceName.c_str(), IFNAMSIZ);
    if(-1 == ioctl(sock_r, SIOCGIFINDEX, &req)){
        perror("ioctl");
        close(sock_r);
        exit(1);
    }

    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = req.ifr_ifindex;
}

void PktSender::startSend(void){
    vector<struct TemplateEntry> txList = t.getTxList();
    unsigned int sleepMicroseconds = 1.0 / FLAGS_pps * 1000.0 * 1000.0;
    for(int i=0;i<txList.size();i++){
        // LOG(INFO)<<"send " << i << "th pkt";
        struct TemplateEntry te = txList.at(i);
        sendPkt((u_char *)(te.data), te.header.len);
        usleep(sleepMicroseconds);
    }
}

void PktSender::sendPkt(u_char * data, int dataLength){
    // printf("data length: %d\n",dataLength);
    int len = sendto(sock_r, data, dataLength, 0, (struct sockaddr *)&sll, sizeof(sll));
    if(len == -1)
    {
        perror("sendto");
        exit(1);
    }
    // LOG(INFO) << "send ok!" ;
}