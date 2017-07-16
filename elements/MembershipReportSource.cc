#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "MembershipReportSource.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>


CLICK_DECLS
MembershipReportSource::MembershipReportSource()
{}

MembershipReportSource::~MembershipReportSource()
{}

int MembershipReportSource::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_srcIP, cpEnd) < 0) return -1;
	_dstIP = IPAddress(String("224.0.0.22"));


	return 0;
}

void MembershipReportSource::push(int, Packet* p) {
	click_ip *iph = (click_ip*)p->data();
	if (iph->ip_p != IP_PROTO_IGMP) {
		for (int i = 0; i < groups.size(); i++) {
			if (iph->ip_dst == groups[i].multicast) {
				if (groups[i].type == 2) {
					output(1).push(p);
				}
				break;
			}
		}
		return;
	}
	igmp_query_packet *igmph = (igmp_query_packet *)(iph + 1);
	if (igmph->querytype != 0x11) {
		return;
	}
	output(0).push(make_packet(-1));
}

int MembershipReportSource::writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh) {
	MembershipReportSource* me = (MembershipReportSource *)e;
	IPAddress address;
	if (cp_va_kparse(conf, me, errh, "ADDR", cpkM, cpIPAddress, &address, cpEnd) < 0) return -1;
	int send;
	bool done;
	switch ((intptr_t)thunk) {
	case 0:
		send = -1;
		done = false;
		for (int i = 0; i < me->groups.size(); i++) {
			send = i;
			if (address == me->groups[i].multicast) {
				if (me->groups[i].type == 1) {
					done = true;
					send = -1;
					break;
				}
				me->groups[i].type = 1;
				done = true;
				break;
			}
		}
		if (!done) {
			me->groups.push_back(group_record(1, address));
		}
		if (send != -1) {
			Packet* p = me->make_packet(send);
			me->output(0).push(p);
			click_chatter("I left %s FeelsBadMan", address.unparse().c_str()); //add address to this!
		}
		break;
	case 1:
		send = -1;
		done = false;
		for (int i = 0; i < me->groups.size(); i++) {
			send = i;
			if (address == me->groups[i].multicast) {
				if (me->groups[i].type == 2) {
					done = true;
					send = -1;
					break;
				}
				me->groups[i].type = 2;
				done = true;
				break;
			}
		}
		if (!done) {
			me->groups.push_back(group_record(2, address));
			send = me->groups.size()-1;
		}
		if (send != -1) {
			Packet* p = me->make_packet(send);
			me->output(0).push(p);
			click_chatter("I joined %s FeelsGoodMan", address.unparse().c_str()); //add address to this!
		}
		break;
	}
	return 0;
}

void MembershipReportSource::add_handlers() {
	add_write_handler("leave", writer, 0);
	add_write_handler("join", writer, 1);
}

Packet* MembershipReportSource::make_packet(int mode) {
	int headroom = sizeof(click_ether);
	WritablePacket *q = Packet::make(headroom, 0, sizeof(click_ip) + sizeof(struct igmp_report_packet) + groups.size() * sizeof(struct group_record), 0);
	if (!q)
		return 0;
	memset(q->data(), '\0', sizeof(click_ip) + sizeof(struct igmp_report_packet));

	click_ip *iph = (click_ip *)q->data();

	iph->ip_v = 4;
	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(q->length());
	uint16_t ip_id = ((_sequence) % 0xFFFF) + 1;
	iph->ip_id = htons(ip_id);
	iph->ip_p = 2;
	iph->ip_ttl = 1;
	iph->ip_src = _srcIP;
	iph->ip_dst = _dstIP;
	iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

	igmp_report_packet *igmph = (igmp_report_packet *)(iph + 1);

	igmph->querytype = 0x22;
	igmph->numgroups = htons(this->groups.size());

	group_record* gr = (group_record*)(igmph + 1);
	for (int i = 0; i < groups.size(); i++) {
		if (i == mode){
			groups[i].type = groups[i].type + 2;
		}
		gr->type = groups[i].type;
		gr->aux_len = groups[i].aux_len;
		gr->numsources = groups[i].numsources;
		gr->multicast = groups[i].multicast;
		group_record* ngr = (group_record*)(gr+1);
		gr = ngr;
		if (i == mode) {
			groups[i].type = groups[i].type - 2;
		}
	}

	_sequence++;

	igmph->checksum = click_in_cksum((const unsigned char *)igmph, sizeof(igmp_report_packet) + groups.size() * sizeof(group_record));

	q->set_dst_ip_anno(_dstIP);

	return q;
}






CLICK_ENDDECLS
EXPORT_ELEMENT(MembershipReportSource)

