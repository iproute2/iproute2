
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <string.h>

#include "utils.h"
#include "br_common.h"

static const char *port_states[] = {
	[BR_STATE_DISABLED] = "disabled",
	[BR_STATE_LISTENING] = "listening",
	[BR_STATE_LEARNING] = "learning",
	[BR_STATE_FORWARDING] = "forwarding",
	[BR_STATE_BLOCKING] = "blocking",
};

extern char *if_indextoname (unsigned int __ifindex, char *__ifname);

static void print_link_flags(FILE *fp, unsigned flags)
{
	fprintf(fp, "<");
	if (flags & IFF_UP && !(flags & IFF_RUNNING))
		fprintf(fp, "NO-CARRIER%s", flags ? "," : "");
	flags &= ~IFF_RUNNING;
#define _PF(f) if (flags&IFF_##f) { \
                  flags &= ~IFF_##f ; \
                  fprintf(fp, #f "%s", flags ? "," : ""); }
	_PF(LOOPBACK);
	_PF(BROADCAST);
	_PF(POINTOPOINT);
	_PF(MULTICAST);
	_PF(NOARP);
	_PF(ALLMULTI);
	_PF(PROMISC);
	_PF(MASTER);
	_PF(SLAVE);
	_PF(DEBUG);
	_PF(DYNAMIC);
	_PF(AUTOMEDIA);
	_PF(PORTSEL);
	_PF(NOTRAILERS);
	_PF(UP);
	_PF(LOWER_UP);
	_PF(DORMANT);
	_PF(ECHO);
#undef _PF
        if (flags)
		fprintf(fp, "%x", flags);
	fprintf(fp, "> ");
}

static const char *oper_states[] = {
	"UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN",
	"TESTING", "DORMANT",	 "UP"
};

static void print_operstate(FILE *f, __u8 state)
{
	if (state >= sizeof(oper_states)/sizeof(oper_states[0]))
		fprintf(f, "state %#x ", state);
	else
		fprintf(f, "state %s ", oper_states[state]);
}

int print_linkinfo(const struct sockaddr_nl *who,
		   struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	int len = n->nlmsg_len;
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct rtattr * tb[IFLA_MAX+1];
	char b1[IFNAMSIZ];

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0) {
		fprintf(stderr, "Message too short!\n");
		return -1;
        }

	if (!(ifi->ifi_family == AF_BRIDGE || ifi->ifi_family == AF_UNSPEC))
		return 0;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (tb[IFLA_IFNAME] == NULL) {
		fprintf(stderr, "BUG: nil ifname\n");
		return -1;
	}

	if (n->nlmsg_type == RTM_DELLINK)
		fprintf(fp, "Deleted ");

	fprintf(fp, "%d: %s ", ifi->ifi_index,
		tb[IFLA_IFNAME] ? rta_getattr_str(tb[IFLA_IFNAME]) : "<nil>");

	if (tb[IFLA_OPERSTATE])
		print_operstate(fp, rta_getattr_u8(tb[IFLA_OPERSTATE]));

	if (tb[IFLA_LINK]) {
		SPRINT_BUF(b1);
		int iflink = rta_getattr_u32(tb[IFLA_LINK]);
		if (iflink == 0)
			fprintf(fp, "@NONE: ");
		else
			fprintf(fp, "@%s: ",
				if_indextoname(iflink, b1));
	} else
		fprintf(fp, ": ");

	print_link_flags(fp, ifi->ifi_flags);

	if (tb[IFLA_MTU])
		fprintf(fp, "mtu %u ", rta_getattr_u32(tb[IFLA_MTU]));

	if (tb[IFLA_MASTER])
		fprintf(fp, "master %s ",
			if_indextoname(rta_getattr_u32(tb[IFLA_MASTER]), b1));

	if (tb[IFLA_PROTINFO]) {
		__u8 state = rta_getattr_u8(tb[IFLA_PROTINFO]);
		if (state <= BR_STATE_BLOCKING)
			fprintf(fp, "state %s", port_states[state]);
		else
			fprintf(fp, "state (%d)", state);
	}


	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}
