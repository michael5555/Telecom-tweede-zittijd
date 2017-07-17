#ifndef CLICK_MEMBERSHIPQUERYSOURCE_HH
#define CLICK_MEMBERSHIPQUERYSOURCE_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
#include "structs.hh"

CLICK_DECLS

class MembershipQuerySource : public Element { 
	public:
		MembershipQuerySource();
		~MembershipQuerySource();
		
		const char *class_name() const	{ return "MembershipQuerySource"; }
		const char *port_count() const	{ return "0-1/2"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void push(int,Packet*);

	private:
		Packet* make_packet();
		void setIPFields(click_ip*,WritablePacket *);
		void setIGMPFields(igmp_query_packet*);
		bool compareSubNetWork(IPAddress,IPAddress);

		int s;
		int qrv;
		uint8_t maxrespcode;
		uint8_t qqic;
		IPAddress group;

		IPAddress _srcIP;
		IPAddress _dstIP;
		uint32_t _sequence;

		Vector<struct routing_state> state;
};

CLICK_ENDDECLS
#endif

