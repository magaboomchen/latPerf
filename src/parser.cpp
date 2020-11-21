#include <stdio.h>

#include <gflags/gflags.h>

#include "global.h"

using namespace std;

static bool ValidateNum(const char *flagname, int value){
    if(value > 0){
        return true;
    }
    printf("Invalid value for --%s:%d\n", flagname, (int) value);
    return false;
}

static bool ValidateString(const char *flagname, const std::string& value){
    if(value == "none"){
        printf("Invalid value for --%s:%s\n", flagname, value.c_str());
        return false;
    }
    return true;
}

DEFINE_string(i, "none", "network interface card");
DEFINE_validator(i, &ValidateString);
DEFINE_string(sptp, "none", "sender packet templage pcap file");
DEFINE_validator(sptp, &ValidateString);
DEFINE_string(rptp, "none", "receiver packet templage pcap file");
DEFINE_validator(rptp, &ValidateString);
DEFINE_int32(d, 10, "duration");
DEFINE_validator(d, &ValidateNum);
DEFINE_int32(pps, 1000, "packer per seconds");
DEFINE_validator(pps, &ValidateNum);
DEFINE_string(o, "none", "output file");
DEFINE_validator(o, &ValidateString);