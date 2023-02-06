#pragma once
#include <pcap.h>
#include "mac.h"

void usage();
void signal_strenth(pcap_t* handle, Mac mac);
void pkt_handle(const u_char* pkt, Mac mac);
