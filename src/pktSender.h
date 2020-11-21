#include <iostream>
#include <vector>
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>	// memset
#include <stdlib.h>	// malloc, free, exit
#include <pthread.h>
#include <unistd.h>	//close
#include <netinet/in.h>
#include <net/if.h>// struct ifreq
#include <sys/ioctl.h> // ioctl, SIOCGIFADDR
#include <sys/socket.h> // socket
#include <netinet/ether.h> // ETH_P_ALL, ETHER_ADDR_LEN
#include <netpacket/packet.h> // struct sockaddr_ll
#include <linux/ip.h> //iphdr
#include <arpa/inet.h> // inet_ntoa, in_addr

#include <pcap.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "global.h"

using namespace std;

#ifndef PKTSENDER_H
#define PKTSENDER_H


/*
pktSender: sendp according to configuration
function:
sendp
*/
class PktSender{
    public:
        PktSender(string interfaceName, PktTemplates &t);
        void startSend(void);

    private:
        u_char ifName[IFNAMSIZ];
        PktTemplates t;
        int sock_r;
        struct sockaddr_ll sll;
        u_char send_msg[MAX_PACKET_LENGTH];

        void sendPkt(u_char * data, int dataLength);
};

#endif