#include <iostream>
#include <string>

#include <pcap.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include "global.h"
#include "pktTemplates.h"

#ifndef BPFGEN_H
#define BPFGEN_H

/*
bpfGen: generate bpf
genBPF
*/
class BPFGenerator{
    public:
        string genBPF(struct TemplateEntry te);
        string combBPF(string BPF1, string BPF2);
        string getInterfaceMACAdress(string interfaceName);
    private:
        string charArray2Hex(const u_char * array, int num);
};

#endif