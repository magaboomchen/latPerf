#include <iostream>
#include <stdexcept>

#include <pcap.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "global.h"
#include "pktTemplates.h"
#include "networkHeader.h"

using namespace std;

PktTemplates::PktTemplates(void){
    LOG(INFO) << "initial pkt templages";
}

PktTemplates::PktTemplates(int duration, int pps, string pktIDLocation){
    LOG(INFO) << "initial pkt templages";
    this->duration = duration;
    this->pps = pps;
    this->pktIDLocation = pktIDLocation;
}

void PktTemplates::readPktTemplates(string file){
    LOG(INFO) << "read pkt templates";

    pcap = pcap_open_offline(file.c_str(), errbuff);
    if(pcap == NULL){
        LOG(ERROR) << "open pcap file: " << errbuff;
        throw std::invalid_argument("invalid pcap file path");
    }

    if(int returnValue = pcap_next_ex(pcap, &header, &data) < 0){
        LOG(ERROR) << "empty pcap templates file";
        throw std::invalid_argument("empty pcap templates file");
    }
}

void PktTemplates::genTxPktTemplates(void){
    memcpy(&txTemplate.header, header, sizeof(struct pcap_pkthdr));
    memcpy(&txTemplate.data, data, sizeof(txTemplate.data));

    // debug
    // LOG(INFO) << txTemplatePCAPHeader.ts.tv_sec;
    // LOG(INFO) << txTemplatePCAPHeader.ts.tv_usec;
    // LOG(INFO) << txTemplatePCAPHeader.caplen ;
    // LOG(INFO) << txTemplatePCAPHeader.len;
    // LOG(INFO) << data;
    // for (u_int i=0; (i < header->caplen ) ; i++)
    // {
    //     if ( (i % 16) == 0) printf("\n");
    //     printf("%.2x ", txTemplate.data[i]);
    // }

    // construct tx packet list
    int totalPktNum = duration * pps;
    txList.clear();
    txList.resize(totalPktNum, txTemplate);
    for(int i=0;i<totalPktNum;i++){
        struct TemplateEntry te;
        memcpy(&te.header, header, sizeof(struct pcap_pkthdr));
        memcpy(&te.data, data, sizeof(txTemplate.data));
        te.visited = false;
        te = addPktID(te, i);
        txList.at(i) = te;
    }
}

void PktTemplates::genRxPktTemplates(void){
    memcpy(&rxTemplate.header, header, sizeof(struct pcap_pkthdr));
    memcpy(&rxTemplate.data, data, sizeof(rxTemplate.data));

    // construct rx packet list
    int totalPktNum = duration * pps;
    rxList.clear();
    rxList.resize(totalPktNum, rxTemplate);
    LOG(INFO) << "totalPktNum: " << totalPktNum ;
    for(int i=0;i<totalPktNum;i++){
        struct TemplateEntry te;
        memcpy(&te.header, header, sizeof(struct pcap_pkthdr));
        memcpy(&te.data, data, sizeof(rxTemplate.data));
        te.visited = false;
        te = addPktID(te, i);
        rxList.at(i) = te;
    }
}

vector<struct TemplateEntry> PktTemplates::getTxList(void){
    return this->txList;
}

vector<struct TemplateEntry> PktTemplates::getRxList(void){
    return this->rxList;
}

struct TemplateEntry PktTemplates::getTxTemplate(void){
    return txTemplate;
}

struct TemplateEntry PktTemplates::getRxTemplate(void){
    return rxTemplate;
}

struct TemplateEntry PktTemplates::addPktID(struct TemplateEntry te, int pktID){
    validatePktID(pktID);
    if(pktIDLocation == PKTID_PAYLOAD){
        u_char * payload = getPayload(te);
        memcpy(payload, &pktID, sizeof(pktID));
        return te;
    }else if(pktIDLocation == PKTID_IP_IDFO){
        setFragmentOffset(te, u_short(pktID & 0x1FFF));
        setIPIdentification(te, u_short(pktID >> 13));
        return te;
    }else{
        LOG(ERROR) << "Wrong packet id location" ;
        throw std::invalid_argument("invalid packet location");
    }

}

int PktTemplates::getPktID(struct TemplateEntry te){
    int pktID = 0;
    if(pktIDLocation == PKTID_PAYLOAD){
        u_char * payload = getPayload(te);
        memcpy(&pktID, payload, sizeof(pktID));
        return pktID;
    }else if(pktIDLocation == PKTID_IP_IDFO){
        pktID += getFragmentOffset(te);
        pktID += (getIPIdentification(te) << 13);
        return pktID;
    }else{
        LOG(ERROR) << "Wrong packet id location" ;
        throw std::invalid_argument("invalid packet location");
    }
}

u_char * PktTemplates::getToS(struct TemplateEntry &te){
    const u_char *packet = te.data;

    // The IP header
    struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
    u_char *ip_tos = &(ip->ip_tos);
    return ip_tos;
}

u_char * PktTemplates::getPayload(struct TemplateEntry &te){
    const u_char *packet = te.data;

    // The IP header
	const struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
        LOG(ERROR) << "* Invalid IP header length: " << size_ip << " bytes\n";
		throw std::invalid_argument("invalid ip header");
	}

    // check whether tcp or udp
    if(ip->ip_p == 0x06){
        // The TCP header
        const struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        u_int size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            LOG(ERROR) << "* Invalid TCP header length: " << size_tcp << " bytes\n";
            throw std::invalid_argument("invalid tcp header");
        }
        // Payload
        u_char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        return payload;

    }else if(ip->ip_p == 0x11){
        // The UDP header
        const struct sniff_udp *udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
        u_int size_udp = 8;
        // Payload
        u_char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
        return payload;

    }else if(ip->ip_p == 0x04){
        // The IP-in-IP header
        const struct sniff_ip *ipInip = (struct sniff_ip*)(packet + SIZE_ETHERNET + size_ip);
        u_int size_ipInip = IP_HL(ipInip)*4;
        if (size_ipInip < 20) {
            LOG(ERROR) << "* Invalid IP header length: " << size_ipInip << " bytes\n";
            throw std::invalid_argument("invalid ip header");
        }

        if(ipInip->ip_p == 0x06){
            // The TCP header
            const struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip + size_ipInip);
            u_int size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                LOG(ERROR) << "* Invalid TCP header length: " << size_tcp << " bytes\n";
                throw std::invalid_argument("invalid tcp header");
            }
            // Payload
            u_char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_ipInip + size_tcp);
            return payload;

        }else if(ipInip->ip_p == 0x11){
            // The UDP header
            const struct sniff_udp *udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip + size_ipInip);
            u_int size_udp = 8;
            // Payload
            u_char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_ipInip + size_udp);
            return payload;

        }else{
            throw std::invalid_argument("ip-in-ip: invalid ip protocol number");
        }

    }else{
        throw std::invalid_argument("invalid ip protocol number");
    }

}

int PktTemplates::getPPS(void){
    return pps;
}

int PktTemplates::getDuration(void){
    return duration;
}

void PktTemplates::validatePktID(int pktID){
    if(!(pktID >= 0 && pktID <= MAX_PKT_ID && pktID < pps * duration)){
        throw std::invalid_argument("invalid packet id");
    }
}

void PktTemplates::setFragmentOffset(struct TemplateEntry &te, u_short fragOffset){
    const u_char *packet = te.data;

    // The IP header
	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
    ip->ip_off = fragOffset & IP_OFFMASK;
}

void PktTemplates::setIPIdentification(struct TemplateEntry &te, u_short id){
    const u_char *packet = te.data;

    // The IP header
	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
    ip->ip_id = id;
}

short PktTemplates::getFragmentOffset(struct TemplateEntry &te){
    const u_char *packet = te.data;

    // The IP header
	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    return ip->ip_off & IP_OFFMASK;
}

short PktTemplates::getIPIdentification(struct TemplateEntry &te){
    const u_char *packet = te.data;

    // The IP header
	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip)*4;
    return ip->ip_id;
}