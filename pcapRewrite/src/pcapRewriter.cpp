#include <string>
#include <arpa/inet.h> // inet_ntoa, ntohs(),in_addr
#include <exception>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "pcapRewriter.h"
#include "pcapReader.h"
#include "pcapWriter.h"
#include "parser.h"
#include "networkHeader.h"

using namespace std;


PcapRewriter::PcapRewriter(PcapReader pr, PcapWriter pw){
    LOG(INFO) << "Initial PcapRewriter" ;
    this->pr = pr;
    this->pw = pw;
}

void PcapRewriter::setPolicy(string dstipmap, string osrcip, string odstip, int trunMTU){
    this->dstipmap = dstipmap;
    this->osrcip = osrcip;
    this->odstip = odstip;
    this->trunMTU = trunMTU;
}

void PcapRewriter::rewrite(void){
    int count = 0;
    bool flag = true;
    while(flag){
        // read a pkt
        pcap_pkt pcapPkt;
        try{
            count++;
            pcap_pkt pcapPkt = pr.getNextPkt();
        }catch (std::invalid_argument){
            LOG(INFO) << "End of pcap file.";
            LOG(INFO) << "count: " << count;
            flag = false;
            break;
        }

        // validate packet
        if(!isValidPkt(pcapPkt)){
            continue;
        }

        // rewrite dst ip
        if(dstipmap != OPTIONAL_ARG){
            // LOG(INFO) << "rewrite dst ip" ;
            rewriteDstIP(pcapPkt);
        }

        // trun packet length
        trun(pcapPkt);

        // add outter ip tunnel
        if(osrcip != OPTIONAL_ARG && odstip != OPTIONAL_ARG){
            // LOG(INFO) << "add ip tunnel" ;
            addIPTunnel(pcapPkt);
        }

        // write a pkt
        pw.appendPkt(pcapPkt);
    }
}

bool PcapRewriter::isValidPkt(pcap_pkt pcapPkt){
    // valid packet format: ethernet / IPv4 / Tcp or Udp

    // Ethernet
    const struct sniff_ethernet *ethernet = (struct sniff_ethernet *)(pcapPkt.data);
    u_short ether_type = ethernet->ether_type;
    if(ntohs(ether_type) != 0x0800){
        LOG(WARNING) << "Unsupport ethernet type: " << ntohs(ether_type);
        return false;
    }

    // The IP header
    const struct sniff_ip *ip = (struct sniff_ip*)(pcapPkt.data + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
    if(size_ip < 20){
        LOG(ERROR) << "* Invalid IP header length: " << size_ip << " bytes\n";
        return false;
    }

    u_char ipProto = ip->ip_p;
    if(ipProto != 0x06 && ipProto != 0x11){
        LOG(WARNING) << "Unsupport ip proto";
        return false;
    }

    return true;
}

void PcapRewriter::rewriteDstIP(pcap_pkt &pcapPkt){
    // Ethernet
    struct sniff_ethernet *ethernet = (struct sniff_ethernet *)(pcapPkt.data);

    // The IP header
    struct sniff_ip *ip = (struct sniff_ip*)(pcapPkt.data + SIZE_ETHERNET);
    int rv = inet_aton(dstipmap.c_str(), &(ip->ip_dst));
    if(rv == 0){
        LOG(ERROR) << "New dst ip is invalid" ;
        throw std::invalid_argument("New dst ip is invalid.");
    }
}

void PcapRewriter::trun(pcap_pkt &pcapPkt){
    // Ethernet
    struct sniff_ethernet *ethernet = (struct sniff_ethernet *)(pcapPkt.data);

    // The IP header
    struct sniff_ip *ip = (struct sniff_ip*)(pcapPkt.data + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
    u_short ipLen = ntohs(ip->ip_len);

    if(ipLen + SIZE_ETHERNET > this->trunMTU){
        LOG(INFO) << "trun packet to new mtu" ;
        ip->ip_len = htons(trunMTU - SIZE_ETHERNET);
        pcapPkt.header.caplen = pcapPkt.header.caplen<=trunMTU ? pcapPkt.header.caplen : trunMTU;
        pcapPkt.header.len = pcapPkt.header.len<=trunMTU ? pcapPkt.header.len : trunMTU;
    }
}

void PcapRewriter::addIPTunnel(pcap_pkt &pcapPkt){
    // Ethernet
    struct sniff_ethernet *ethernet = (struct sniff_ethernet *)(pcapPkt.data);

    // The IP header
    struct sniff_ip *ip = (struct sniff_ip*)(pcapPkt.data + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
    u_short ipLen = ntohs(ip->ip_len);

    // LOG(INFO) << "ipLen: " << ipLen ;

    // copy ip pkt to buffer
    u_char buffer[MAX_PACKET_LENGTH];
    memcpy(buffer, pcapPkt.data + SIZE_ETHERNET, ipLen);

    // construct outter ip
    struct sniff_ip outterIP;
    memcpy(&outterIP, pcapPkt.data + SIZE_ETHERNET, sizeof(outterIP));
    outterIP.ip_vhl = 0x45;
	outterIP.ip_len = htons(ntohs(outterIP.ip_len) + 20);
	outterIP.ip_ttl = 0xFE;
	outterIP.ip_p = 0x04;
    int rv = inet_aton(osrcip.c_str(), &(outterIP.ip_src));
    if(rv == 0){
        LOG(ERROR) << "New src ip is invalid" ;
        throw std::invalid_argument("New src ip is invalid.");
    }
    rv = inet_aton(odstip.c_str(), &(outterIP.ip_dst));
    if(rv == 0){
        LOG(ERROR) << "New dst ip is invalid" ;
        throw std::invalid_argument("New dst ip is invalid.");
    }

    // debug
    // LOG(INFO) << "buffer == *ip: " << memcmp(buffer, ip, ipLen);
    // LOG(INFO) << "ipLen: "<< ipLen ;
    // LOG(INFO) << "sizeof outter ip: "<< sizeof(outterIP) ;

    // copy outter ip to pcap pkt
    memcpy(pcapPkt.data + SIZE_ETHERNET, &outterIP, sizeof(outterIP));

    // copy buffer back to pcap pkt
    memcpy(pcapPkt.data + SIZE_ETHERNET + sizeof(outterIP), buffer, ipLen);

    // update header
    pcapPkt.header.len = pcapPkt.header.len + 20;
    pcapPkt.header.caplen = pcapPkt.header.caplen + 20;

}