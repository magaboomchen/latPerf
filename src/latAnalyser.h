#include "pktTemplates.h"

using namespace std;

#ifndef LATANALYSER_H
#define LATANALYSER_H

/*
latAnalyser: calculate latency accroding to txList and rxList
output analysis file
*/
class LatAnalyser{
    public:
        LatAnalyser(PktTemplates t, vector<struct TemplateEntry> buffer);
        void startAnalyse(void);
        void saveFile(const string filePath);
    private:
        PktTemplates t;
        vector<struct TemplateEntry> buffer;
        vector<struct TemplateEntry> txList;
        vector<struct TemplateEntry> rxList;
        vector<int> latencyList;

        int getLatency(struct timeval ts1, struct timeval ts2);
};

#endif