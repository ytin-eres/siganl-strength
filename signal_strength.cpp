#include <string>
#include <iostream>

#include "signal_strength.h"
#include "radiotaphdr.h"
#include "beaconhdr.h"
#include "mac.h"

using namespace std;


void usage(){
    std::cout << "syntax : signal-strength <interface> <mac>\n";
    std::cout << "sample : signal-strength mon0 00:11:22:33:44:55\n"; 
}

void signal_strenth(pcap_t* handle, Mac mac){
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;
    while(true){
        res = pcap_next_ex(handle,&header,&packet);
        if(res==0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
        }        
        pkt_handle(packet, mac);
    }
}

void pkt_handle(const u_char* pkt, Mac mac){
    PRadiotapHdr radiotapHdr = (PRadiotapHdr) pkt;
    PBeaconHdr beaconHdr = (PBeaconHdr) (pkt+radiotapHdr->len_);
    if (beaconHdr->ta() == mac){
        printf("Signal Strength: %d dBm\n", *((char*)beaconHdr-2));
    }
}