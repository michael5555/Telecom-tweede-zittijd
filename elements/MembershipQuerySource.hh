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

		//void run_timer(Timer*);

		static int writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh);
		static int ipwriter(const String &conf, Element *e, void *thunk, ErrorHandler* errh);
		void add_handlers();

		void push(int,Packet*);

	private:
		Packet* make_packet();
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

