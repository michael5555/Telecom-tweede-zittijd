#ifndef CLICK_MEMBERSHIPREPORTSOURCE_HH
#define CLICK_MEMBERSHIPREPORTSOURCE_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
#include "structs.hh"

CLICK_DECLS

class MembershipReportSource : public Element {
	public:
		MembershipReportSource();
		~MembershipReportSource();

		const char *class_name() const { return "MembershipReportSource"; }
		const char *port_count() const { return "0-1/2"; }
		const char *processing() const { return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);

		static int writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh);
		void add_handlers();

	private:
		Packet* make_packet(int);

		IPAddress _srcIP;
		IPAddress _dstIP;
		uint32_t _sequence;

		Vector<struct group_record> groups;
};

CLICK_ENDDECLS
#endif

