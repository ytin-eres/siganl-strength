#include <pcap.h>
#include <map>
#include "airodump.h"

extern std::map <Mac, APInfo> APmap;


int main(int argc, char** argv) {
    if(argc!=2){
        usage();
        exit(0);
    }

    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    airodump(handle);
}