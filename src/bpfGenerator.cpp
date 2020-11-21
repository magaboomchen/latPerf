#include <iostream>
#include <iomanip>
#include <string>
#include <arpa/inet.h> // inet_ntoa, ntohs(),in_addr

#include <pcap.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "global.h"
#include "pktTemplates.h"
#include "bpfGenerator.h"
#include "networkHeader.h"

/*
match ethernet
match first ip header
*/
string BPFGenerator::genBPF(struct TemplateEntry te){
    const u_char *packet = te.data;

    // Ethernet
    const struct sniff_ethernet *ethernet = (struct sniff_ethernet*)(packet);
    u_short etherType = ethernet->ether_type;

    if(ntohs(etherType) != 0x0800){
        LOG(ERROR) << "Template pkt is not an ip pkt";
        throw std::invalid_argument("only support ip over ethernet.");
    }

    // The IP header
	const struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
        LOG(ERROR) << "* Invalid IP header length: " << size_ip << " bytes\n";
		throw std::invalid_argument("invalid ip header");
	}

    u_char ipProto = ip->ip_p;
    if(ipProto != 0x04 && ipProto != 0x06 && ipProto != 0x11){
        LOG(ERROR) << "Unsupport template pkt";
        throw std::invalid_argument("only support tcp/udp/ip over ip.");
    }

    string bpf = " ether[12:2] == 0X0800 ";
    bpf += " && ether dst " + charArray2Hex(ethernet->ether_dhost, ETHER_ADDR_LEN);
    bpf += " && ether src " + charArray2Hex(ethernet->ether_shost, ETHER_ADDR_LEN);
    bpf += " && ip proto " + to_string(ipProto);
    string str1(inet_ntoa(ip->ip_src));
    bpf += " && src net " + str1;
    string str2(inet_ntoa(ip->ip_dst));
    bpf += " && dst net " + str2;
    bpf += " && ip[1:1] == 0x03 ";

    return bpf;
}

string BPFGenerator::charArray2Hex(const u_char *array, int num){
    std::stringstream ss;
    int i = 0;
    for(i=0; i<num; i++){
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)array[i];
        if( i != num - 1 ){
            ss << std::setw(1) << ":";
        }
    }
    std::string mystr = ss.str();
    return mystr;
}

string BPFGenerator::combBPF(string BPF1, string BPF2){
    string totalBPF = "(" + BPF1 + ") || (" + BPF2 + ")";
    return totalBPF;
}