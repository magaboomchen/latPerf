#include <iostream>
#include <fstream>

#include "latAnalyser.h"

using namespace std;


LatAnalyser::LatAnalyser(PktTemplates t, vector<struct TemplateEntry> buffer){
    this->t = t;
    this->buffer = buffer;
    txList = t.getTxList();
    rxList = t.getRxList();
}

void LatAnalyser::startAnalyse(void){
    // populate timestamp
    for(int i=0;i<buffer.size();i++){
        struct TemplateEntry te = buffer.at(i);
        te.visited = true;
        if(*(t.getToS(te)) != 0x18){
            LOG(ERROR) << "Bpf error" ;
            continue;
        }
        int pktID = t.getPktID(te);
        try{
            t.validatePktID(pktID);
        }catch (std::invalid_argument){
            LOG(ERROR) << "Invalid pkt id: " << pktID ;
            continue;
        }
        LOG(INFO) << "pktID: " << pktID ;
        int index = pktID;
        if(txList.at(index).visited == false){
            // LOG(INFO) << "tx pkt" ;
            txList.at(index) = te;
        }else if(rxList.at(index).visited == false){
            // LOG(INFO) << "rx pkt" ;
            rxList.at(index) = te;
        }else{
            LOG(WARNING) << "duplicated pkt." ;
        }
    }

    // calculate latency
    for(int i=0; i< txList.size(); i++){
        if(txList.at(i).visited == true && rxList.at(i).visited == true){
            int latency = getLatency(txList.at(i).header.ts,
                rxList.at(i).header.ts);
            latencyList.push_back(latency);
            // LOG(INFO) << "latency: " << latency ;
        }
    }
}

int LatAnalyser::getLatency(struct timeval ts1, struct timeval ts2){
    int seconds = ts2.tv_sec - ts1.tv_sec;
    int useconds = ts2.tv_usec - ts1.tv_usec;
    return seconds * 1000 * 1000 + useconds;
}

void LatAnalyser::saveFile(const string filePath){
	ofstream fout;

    fout.open(filePath.c_str());
	if(!fout.is_open()){
        LOG(ERROR) << "fout open file failed." ;
        throw std::invalid_argument("fout open file failed.");
    }

	for(int i=0;i<latencyList.size();i++){
        fout << latencyList.at(i) << '\n';
    }

	fout.close();
}