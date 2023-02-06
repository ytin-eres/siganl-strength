#include <pcap.h>
#include "signal_strength.h"


int main(int argc, char** argv) {
    if(argc!=3){
        usage();
        exit(0);
    }

    char* dev = argv[1];
    Mac mac = Mac(argv[2]);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    
    signal_strenth(handle, mac);
}