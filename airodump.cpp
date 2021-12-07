#include <string>
#include <iostream>
#include "airodump.h"
#include "radiotaphdr.h"
#include "beaconhdr.h"
#include "mac.h"

using std::string;

std::map<Mac, APInfo> APmap;

void usage(){
    std::cout << "syntax : airodump <interface>\n";
    std::cout << "sample : airodump mon0\n"; 
}

void printInfo(){
    extern std::map <Mac, APInfo> APmap;

    system("clear");
    std::cout << "BSSID\t\t" << "ESSID\t\t" << "Beacons\n"; 
    for(auto itr = APmap.begin();itr!=APmap.end();itr++){
        std::cout<< itr->first.operator std::string() << '\t' << itr->second.ESSID << '\t' << itr->second.beaconNum << '\n'; 
    }
}

void airodump(pcap_t* handle){
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
        if(pkt_handle(packet)) continue;
        printInfo();
    }

}

bool pkt_handle(const u_char* pkt){
    extern std::map <Mac, APInfo> APmap;

    PRadiotapHdr radiotapHdr = (PRadiotapHdr) pkt;
    PBeaconHdr beaconHdr = (PBeaconHdr) (pkt+radiotapHdr->len_);
    Mac bssid = beaconHdr->bssid();
    string essid;
    APInfo apInfo;

    if(beaconHdr->type_ != BeaconHdr::Beacon) return true;
    auto itr = APmap.find(bssid);
    if(itr!=APmap.end()){
        itr->second.beaconNum++;
    }
    else{
        essid = string((char*)beaconHdr->tag()->next(),beaconHdr->tag()->len_);
        apInfo.ESSID = essid;
        apInfo.beaconNum = 1;
        APmap[bssid] = apInfo;
    }
    return false;
}