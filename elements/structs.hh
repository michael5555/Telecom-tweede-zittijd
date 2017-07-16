#ifndef STRUCTS_HH
#define STRUCTS_HH
	
struct group_record {
	uint8_t type;
	uint8_t aux_len;//=0
	uint16_t numsources;
	IPAddress multicast;
	//Vector<IPAddress> addresses;

	group_record(uint8_t ty, IPAddress mc) {
		type = ty;
		multicast = mc;
		aux_len = 0;
		numsources = 0;
	}
};

struct igmp_report_packet {
	uint8_t querytype;//=0x22
	uint8_t reserved;//=0
	uint16_t checksum;
	uint16_t reserved2;//=0
	uint16_t numgroups;//??
};

struct routing_state {
	IPAddress groupaddress;
	IPAddress source;
	uint8_t type;

	routing_state(uint8_t ty, IPAddress ga, IPAddress s) {
		type = ty;
		groupaddress = ga;
		source = s;
	}
};

struct resv_s_qrv {
	uint8_t qrv : 3;
	uint8_t s : 1;
	uint8_t resv : 4;

	resv_s_qrv(uint8_t r, uint8_t ss, uint8_t q) {

		resv = r;
		s = ss;
		qrv = q;
	}
};


struct igmp_query_packet {

	uint8_t querytype;//=0x11
	uint8_t maxrespcode;//100, change using handler
	uint16_t checksum;
	IPAddress groupaddress;//HANDLER!!!
	resv_s_qrv  fields;
	uint8_t qqic;//125, change using handler
	uint16_t numsources;//=0
						//Vector<IPAddress> source_addresses;//empty
};


#endif