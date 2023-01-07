#pragma once
#include <pcap.h>
#include <map>
#include <string>
#include "mac.h"

struct APInfo {
    std::string ESSID;
    int beaconNum;
};

void usage();
void airodump(pcap_t* handle);
bool pkt_handle(const u_char* pkt);
void printInfo();