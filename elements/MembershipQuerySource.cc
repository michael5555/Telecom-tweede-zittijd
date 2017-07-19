#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "MembershipQuerySource.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

CLICK_DECLS
MembershipQuerySource::MembershipQuerySource()
{
}

MembershipQuerySource::~MembershipQuerySource()
{
}

int MembershipQuerySource::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_srcIP, cpEnd) < 0)
		return -1;
	this->s = 0;
	this->qrv = 2;
	this->maxrespcode = 100;
	this->qqic = 125;
	this->group = IPAddress(String("0.0.0.0"));

	return 0;
}

void MembershipQuerySource::push(int, Packet *p)
{
	click_ip *iph = (click_ip *)p->data();
	if (iph->ip_p != IP_PROTO_IGMP)
	{
		for (int i = 0; i < state.size(); i++)
		{
			if (compareSubNetWork(_srcIP, state[i].source))
			{

				if (state[i].type == 2)
				{
					output(1).push(p);
				}
				break;
			}
		}
		return;
	}
	igmp_report_packet *igmph = (igmp_report_packet *)(iph + 1);
	if (igmph->querytype != 0x22)
	{
		return;
	}
	group_record *gr = (group_record *)(igmph + 1);
	for (int i = 0; i < htons(igmph->numgroups); i++)
	{
		bool found = false;
		switch (gr->type)
		{
		case 1:
			for (int j = 0; j < state.size(); j++)
			{
				if (state[j].groupaddress == gr->multicast)
				{
					found = true;
					break;
				}
			}
			if (!found)
			{
				state.push_back(routing_state(1, gr->multicast, iph->ip_src));
			}
			found = false;
			break;
		case 2:
			for (int j = 0; j < state.size(); j++)
			{
				if (state[j].groupaddress == gr->multicast)
				{
					state[j].type = 2;
					found = true;
					break;
				}
			}
			if (!found)
			{
				state.push_back(routing_state(2, gr->multicast, iph->ip_src));
			}
			found = false;
			break;
		case 3:
			for (int j = 0; j < state.size(); j++)
			{
				if (state[j].groupaddress == gr->multicast)
				{
					state.erase(state.begin() + j);
					this->group = gr->multicast;
					Packet *q = make_packet();
					output(0).push(q);
					break;
				}
			}
			break;
		case 4:
			for (int j = 0; j < state.size(); j++)
			{
				if (state[j].groupaddress == gr->multicast)
				{
					if (state[j].type != 2)
					{
						state[j].type = 2;
					}
					found = true;
					break;
				}
			}
			if (!found)
			{
				state.push_back(routing_state(2, gr->multicast, iph->ip_src));
			}
			found = false;
			break;
		}
		group_record *ngr = (group_record *)(gr + 1);
		gr = ngr;
	}
}

void MembershipQuerySource::setIPFields(click_ip *iph, WritablePacket *q)
{

	iph->ip_v = 4;
	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(q->length());
	uint16_t ip_id = ((_sequence) % 0xFFFF) + 1;
	iph->ip_id = htons(ip_id);
	iph->ip_p = IP_PROTO_IGMP;
	iph->ip_ttl = 1;
	iph->ip_src = _srcIP;
	if (group == IPAddress(String("0.0.0.0")))
	{
		_dstIP = IPAddress(String("224.0.0.1"));
	}
	else
	{
		_dstIP = group;
	}
	iph->ip_dst = _dstIP; //depends on grp
	iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
}

void MembershipQuerySource::setIGMPFields(igmp_query_packet *igmph)
{
	igmph->querytype = 0x11;
	struct resv_s_qrv field = resv_s_qrv(0, 0, 2);

	igmph->fields = field;

	igmph->maxrespcode = this->maxrespcode;
	igmph->qqic = 125;
	igmph->groupaddress = this->group;
	igmph->numsources = 0;
	_sequence++;

	igmph->checksum = click_in_cksum((const unsigned char *)igmph, sizeof(igmp_query_packet));
}

Packet *MembershipQuerySource::make_packet()
{
	int headroom = sizeof(click_ether);
	WritablePacket *q = Packet::make(headroom, 0, sizeof(click_ip) + sizeof(struct igmp_query_packet), 0);
	if (!q)
		return 0;
	memset(q->data(), '\0', sizeof(click_ip) + sizeof(struct igmp_query_packet));

	click_ip *iph = (click_ip *)q->data();

	this->setIPFields(iph, q);

	q->set_dst_ip_anno(_dstIP);
	igmp_query_packet *igmph = (igmp_query_packet *)(iph + 1);

	this->setIGMPFields(igmph);
	return q;
}

bool MembershipQuerySource::compareSubNetWork(IPAddress addr1, IPAddress addr2)
{

	int count = 0;
	String s1 = addr1.unparse();
	String s2 = addr2.unparse();

	int l = s1.length();
	for (int i = 0; i < l; i++)
	{

		if (s1.at(i) == s2.at(i))
		{
			count += 1;
		}
		else
		{
			break;
		}
	}

	if (count >= 10)
	{
		return true;
	}
	return false;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MembershipQuerySource)
