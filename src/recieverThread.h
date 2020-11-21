#include "pktReceiver.h"

#ifndef RECEIVERTHREAD_H
#define RECEIVERTHREAD_H

struct ReceiverThreadArg{
    PktReceiver &pr;
    string totalBPF;
};

void *receiverThread(void *arg);

#endif