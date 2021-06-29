#include <iostream>
#include <iomanip>
#include <string>
#include <arpa/inet.h> // inet_ntoa, ntohs(),in_addr
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>

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
    bpf += " && ip[1:1] == 0x18 ";

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

string BPFGenerator::getInterfaceMACAdress(string interfaceName)
{
    // https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    // for (; it != end; ++it) {
        // strcpy(ifr.ifr_name, it->ifr_name);
        strcpy(ifr.ifr_name, interfaceName.c_str());
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    // break;
                }
            }
        }else{
            /* handle error */
            throw std::invalid_argument("Unkown interface name " + interfaceName);
        }
    // }

    unsigned char mac_address[6];

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
    string mac_address_string(macStr);

    LOG(INFO) << "mac address is " << mac_address_string;
    return mac_address_string;
}
