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
#include <netinet/ether.h> // ETH_P_ALL
#include <netpacket/packet.h> // struct sockaddr_ll
#include <linux/ip.h> //iphdr
#include <arpa/inet.h> // inet_ntoa, in_addr

#include <pcap.h>

#include "global.h"
#include "pktReceiver.h"
#include "recieverThread.h"

using namespace std;


void *receiverThread(void *arg){
    ReceiverThreadArg rta = *(ReceiverThreadArg *)arg;
    PktReceiver &pr = rta.pr;
    pr.setBPF(rta.totalBPF);
    pr.startListen();
}