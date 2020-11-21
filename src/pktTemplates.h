#include <iostream>
#include <vector>

#include <pcap.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "global.h"

using namespace std;

#ifndef TEMPLATE_H
#define TEMPLATE_H


struct TemplateEntry{
      struct pcap_pkthdr header; // store time stamp
      u_char data[MAX_PACKET_LENGTH];
      bool visited;
      TemplateEntry(): visited(false) { }   // default Constructor
};

/*
Packet Templates:
Used to store sender and receiver's packet templates.
Sender will only send sender template packets.
Receiver will only caputure recveiver template packets.
*/
class PktTemplates{
   public:
      PktTemplates(void);
      PktTemplates(int duration, int pps, string pktIDLocation);
      void readPktTemplates(string file);
      void genTxPktTemplates(void);
      void genRxPktTemplates(void);
      vector<struct TemplateEntry> getTxList(void);
      vector<struct TemplateEntry> getRxList(void);
      struct TemplateEntry getTxTemplate(void);
      struct TemplateEntry getRxTemplate(void);
      int getPPS(void);
      int getDuration(void);
      int getPktID(struct TemplateEntry);
      void validatePktID(int pktID);
      u_char * getToS(struct TemplateEntry &te);  // te is input arg
   private:
      int duration;
      int pps;
      char errbuff[PCAP_ERRBUF_SIZE];
      pcap_t* pcap;
      struct pcap_pkthdr *header;
      const u_char *data;
      struct TemplateEntry txTemplate;
      struct TemplateEntry rxTemplate;
      vector<struct TemplateEntry> txList;
      vector<struct TemplateEntry> rxList;
      string pktIDLocation;

      struct TemplateEntry addPktID(struct TemplateEntry te, int pktID);
      u_char * getPayload(struct TemplateEntry &te);  // te is input arg
      void setFragmentOffset(struct TemplateEntry &te, u_short fragOffset);
      void setIPIdentification(struct TemplateEntry &te, u_short id);
      short getFragmentOffset(struct TemplateEntry &te);
      short getIPIdentification(struct TemplateEntry &te);
};

#endif