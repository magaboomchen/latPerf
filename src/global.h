#include <arpa/inet.h>
#include <stdio.h>
#include <stdexcept>

using namespace std;

#ifndef GLOBAL_H
#define GLOBAL_H

#define MAX_PACKET_LENGTH 2000
#define PKTID_IP_IDFO "PktIDLocateInIPHeaderIdentificationAndFragmentationOffset"
#define PKTID_PAYLOAD "PktIDLocateInPayLoad"
#define MAX_PKT_ID 65536/8*65536 // ignore flags in ip header

typedef int32_t int32;

#endif