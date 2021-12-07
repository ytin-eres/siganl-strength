#pragma once
#include <stdint.h>
#include "dot11hdr.h"
#include "mac.h"

#pragma pack(push, 1)
struct BeaconHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	uint8_t frag_:4;
	uint16_t seq_:12;

	Mac ra() { return addr1_;}
	Mac da() { return addr1_; }
	Mac ta() { return addr2_; }
	Mac sa() { return addr2_; }
	Mac bssid() { return addr3_; }

	struct __attribute__((packed)) Fix {
		uint64_t timestamp_; // microsecond
		uint16_t beaconInterval_; // millisecond
		uint16_t capabilities_;
	} fix_;

	struct Tag {
		uint8_t num_;
		uint8_t len_;
		Tag* next() {
			char* res = (char*)this;
			res += sizeof(Tag) + this->len_;
			return PTag(res);
		}
	};
	typedef Tag *PTag;
	Tag* tag() {
		char* p = (char*)(this);
		p += sizeof(BeaconHdr);
		return PTag(p);
	}

	// tagged parameter number
	enum: uint8_t {
		tagSsidParameterSet = 0,
		tagSupportedRated = 1,
		tagTrafficIndicationMap = 5
	};

	struct TrafficIndicationMap : Tag {
		uint8_t count_;
		uint8_t period_;
		uint8_t control_;
		uint8_t bitmap_;
	};
	typedef TrafficIndicationMap *PTrafficIndicationMap;

};
typedef BeaconHdr *PBeaconHdr;
#pragma pack(pop)
