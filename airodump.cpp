#include <string>
#include <iostream>
#include <iomanip>

#include "airodump.h"
#include "radiotaphdr.h"
#include "beaconhdr.h"
#include "mac.h"

using std::string;

std::map<Mac, APInfo> APmap;
std::map<Mac, APInfo> Probemap;

void usage(){
    std::cout << "syntax : airodump <interface>\n";
    std::cout << "sample : airodump mon0\n"; 
}

void printInfo(){
    extern std::map <Mac, APInfo> APmap;
    extern std::map <Mac, APInfo> Probemap;

    system("clear");
    std::cout << "BSSID\t\t\t" << "ESSID\t\t" << "Beacons" << std::endl;; 
    for(auto itr = APmap.begin();itr!=APmap.end();itr++){
        std::cout<< itr->first.operator std::string() << '\t' << itr->second.ESSID << '\t' << itr->second.beaconNum << std::endl; 
    }

    std::cout << "BSSID\t\t\t" << "ESSID\t\t" << "Beacons" << std::endl;; 
    for(auto itr = Probemap.begin();itr!=Probemap.end();itr++){
        std::cout<< itr->first.operator std::string() << '\t' << itr->second.ESSID << '\t' << itr->second.beaconNum << std::endl; 
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
    if(beaconHdr->subtype_ != BeaconHdr::Beacon && beaconHdr->subtype_ != BeaconHdr::ProbeRequest) return true;
    

    if(beaconHdr->subtype_ == BeaconHdr::Beacon){
        auto itr = APmap.find(bssid);
        if(itr!=APmap.end()){
            itr->second.beaconNum++;
        }
        else{
            essid = string((char*)beaconHdr->tag()+2,beaconHdr->tag()->len_);
            int essidLen = beaconHdr->tag()->len_;
            if(essidLen<=0 || essidLen>16) essid = string("<length:" + std::to_string(essidLen) + ">");
            apInfo.ESSID = essid;
            apInfo.beaconNum = 1;
            APmap[bssid] = apInfo;
        } 
    }

    if(beaconHdr->subtype_ == BeaconHdr::ProbeRequest){
        auto itr = Probemap.find(bssid);
        if(itr!=Probemap.end()){
            itr->second.beaconNum++;
        }
        else{
            essid = string((char*)beaconHdr->tag()+2,beaconHdr->tag()->len_);
            int essidLen = beaconHdr->tag()->len_;
            if(essidLen<=0 || essidLen>16) essid = string("<length:" + std::to_string(essidLen) + ">");
            apInfo.ESSID = essid;
            apInfo.beaconNum = 1;
            ProbeRequest[bssid] = apInfo;
        } 
    }

   return false;
}