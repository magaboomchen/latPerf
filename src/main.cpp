/*
reference
https://www.tcpdump.org/pcap.html
*/

#include <iostream>
#include <stdio.h>
#include <stdint.h>
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
#include <signal.h> // ctrl-c, free RAM

#include <pcap.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "global.h"
#include "networkHeader.h"
#include "pktTemplates.h"
#include "bpfGenerator.h"
#include "pktSender.h"
#include "pktReceiver.h"
#include "recieverThread.h"
#include "latAnalyser.h"

using namespace std;

DECLARE_string(mode);
DECLARE_string(i);
DECLARE_string(sptp);
DECLARE_string(rptp);
DECLARE_int32(d);
DECLARE_int32(pps);
DECLARE_string(o);
DECLARE_int32(gra);


void profileLatency(void){
    PktTemplates t(FLAGS_d, FLAGS_pps, PKTID_IP_IDFO);
    t.readPktTemplates(FLAGS_sptp);
    t.genTxPktTemplates();
    t.readPktTemplates(FLAGS_rptp);
    t.genRxPktTemplates();

    struct TemplateEntry txTE = t.getTxTemplate();
    struct TemplateEntry rxTE = t.getRxTemplate();
    BPFGenerator bpfG;
    string txBPF = bpfG.genBPF(txTE);
    string rxBPF = bpfG.genBPF(rxTE);
    string totalBPF = bpfG.combBPF(txBPF, rxBPF);
    LOG(INFO) << txBPF ;
    LOG(INFO) << rxBPF ;
    LOG(INFO) << totalBPF ;

    PktReceiver pr(FLAGS_i, t);
    pr.setBufferExpSize(FLAGS_d * FLAGS_pps);
    ReceiverThreadArg rta={pr, totalBPF};
    pthread_t threadReceiver;
    pthread_create(&threadReceiver, NULL, &receiverThread, &rta);

    PktSender ps(FLAGS_i, t);
    ps.startSend();
    sleep(1);
    pr.stopListen();

    vector<struct TemplateEntry> buffer = pr.getBuffer();
    LatAnalyser la(t, buffer);
    la.startAnalyse();
    la.saveFile(FLAGS_o);

    pthread_join(threadReceiver,NULL);

    return ;
}

void signal_callback_handler(int signum) {
    receiverQuitFlag = true;
}

void profileThroughput(void){
    PktTemplates t(FLAGS_d, FLAGS_pps, PKTID_IP_IDFO);
    t.readPktTemplates(FLAGS_sptp);
    t.genTxPktTemplates();
    t.readPktTemplates(FLAGS_rptp);
    t.genRxPktTemplates();

    // string totalBPF = "ether[12:2] == 0X0800 ";
    string totalBPF = " ";
    BPFGenerator bpfG;
    // string totalBPF = " ether src  " + bpfG.getInterfaceMACAdress(FLAGS_i);

    PktReceiver pr(FLAGS_i, t);
    pr.setBufferExpSize(FLAGS_d * FLAGS_pps);
    ReceiverThreadArg rta={pr, totalBPF};
    pthread_t threadReceiver;
    pthread_create(&threadReceiver, NULL, &receiverThread, &rta);

    // Register signal and signal handler
    signal(SIGINT, signal_callback_handler);

    pr.recordThroughput();
    pr.stopListen();
    pr.logThroughputDataPoints();

    pthread_join(threadReceiver, NULL);

    return ;
}


int main(int argc, char **argv){
    google::ParseCommandLineFlags(&argc, &argv, true);

    // FLAGS_alsologtostderr = 1;
    FLAGS_log_dir = "./log";
    FLAGS_colorlogtostderr = true;
    // google::SetCommandLineOption("GLOG_minloglevel", "2");
    google::InitGoogleLogging(argv[0]);

    if(FLAGS_mode == "latency"){
        LOG(INFO) << "latency profiling";
        profileLatency();
    }else if(FLAGS_mode == "throughput"){
        LOG(INFO) << "throughput profiling";
        profileThroughput();
    }else{
        throw std::invalid_argument("Unknown profiling mode.");
    }

    LOG(INFO) << "finish" ;

    return 0;
}
