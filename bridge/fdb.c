/*
 * Get/set/delete fdb table with netlink
 *
 * TODO: merge/replace this with ip neighbour
 *
 * Authors:	Stephen Hemminger <shemminger@vyatta.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/neighbour.h>
#include <string.h>
#include <limits.h>
#include <json_writer.h>
#include <stdbool.h>

#include "libnetlink.h"
#include "br_common.h"
#include "rt_names.h"
#include "utils.h"

static unsigned int filter_index, filter_vlan, filter_state;

json_writer_t *jw_global;

static void usage(void)
{
	fprintf(stderr,
		"Usage: bridge fdb { add | append | del | replace } ADDR dev DEV\n"
		"              [ self ] [ master ] [ use ] [ router ]\n"
		"              [ local | static | dynamic ] [ dst IPADDR ] [ vlan VID ]\n"
		"              [ port PORT] [ vni VNI ] [ via DEV ]\n"
		"       bridge fdb [ show [ br BRDEV ] [ brport DEV ] [ vlan VID ] [ state STATE ] ]\n");
	exit(-1);
}

static const char *state_n2a(unsigned int s)
{
	static char buf[32];

	if (s & NUD_PERMANENT)
		return "permanent";

	if (s & NUD_NOARP)
		return "static";

	if (s & NUD_STALE)
		return "stale";

	if (s & NUD_REACHABLE)
		return "";

	sprintf(buf, "state=%#x", s);
	return buf;
}

static int state_a2n(unsigned int *s, const char *arg)
{
	if (matches(arg, "permanent") == 0)
		*s = NUD_PERMANENT;
	else if (matches(arg, "static") == 0 || matches(arg, "temp") == 0)
		*s = NUD_NOARP;
	else if (matches(arg, "stale") == 0)
		*s = NUD_STALE;
	else if (matches(arg, "reachable") == 0 || matches(arg, "dynamic") == 0)
		*s = NUD_REACHABLE;
	else if (strcmp(arg, "all") == 0)
		*s = ~0;
	else if (get_unsigned(s, arg, 0))
		return -1;

	return 0;
}

static void start_json_fdb_flags_array(bool *fdb_flags)
{
	if (*fdb_flags)
		return;
	jsonw_name(jw_global, "flags");
	jsonw_start_array(jw_global);
	*fdb_flags = true;
}

int print_fdb(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	struct ndmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[NDA_MAX+1];
	__u16 vid = 0;
	bool fdb_flags = false;
	const char *state_s;

	if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
		fprintf(stderr, "Not RTM_NEWNEIGH: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (r->ndm_family != AF_BRIDGE)
		return 0;

	if (filter_index && filter_index != r->ndm_ifindex)
		return 0;

	if (filter_state && !(r->ndm_state & filter_state))
		return 0;

	parse_rtattr(tb, NDA_MAX, NDA_RTA(r),
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (tb[NDA_VLAN])
		vid = rta_getattr_u16(tb[NDA_VLAN]);

	if (filter_vlan && filter_vlan != vid)
		return 0;

	if (jw_global) {
		jsonw_pretty(jw_global, 1);
		jsonw_start_object(jw_global);
	}

	if (n->nlmsg_type == RTM_DELNEIGH) {
		if (jw_global)
			jsonw_string_field(jw_global, "opCode", "deleted");
		else
			fprintf(fp, "Deleted ");
	}

	if (tb[NDA_LLADDR]) {
		SPRINT_BUF(b1);
		ll_addr_n2a(RTA_DATA(tb[NDA_LLADDR]),
			    RTA_PAYLOAD(tb[NDA_LLADDR]),
			    ll_index_to_type(r->ndm_ifindex),
			    b1, sizeof(b1));
		if (jw_global)
			jsonw_string_field(jw_global, "mac", b1);
		else
			fprintf(fp, "%s ", b1);
	}

	if (!filter_index && r->ndm_ifindex) {
		if (jw_global)
			jsonw_string_field(jw_global, "dev",
					   ll_index_to_name(r->ndm_ifindex));
		else
			fprintf(fp, "dev %s ",
				ll_index_to_name(r->ndm_ifindex));
	}

	if (tb[NDA_DST]) {
		int family = AF_INET;
		const char *abuf_s;

		if (RTA_PAYLOAD(tb[NDA_DST]) == sizeof(struct in6_addr))
			family = AF_INET6;

		abuf_s = format_host(family,
				     RTA_PAYLOAD(tb[NDA_DST]),
				     RTA_DATA(tb[NDA_DST]));
		if (jw_global)
			jsonw_string_field(jw_global, "dst", abuf_s);
		else
			fprintf(fp, "dst %s ", abuf_s);
	}

	if (vid) {
		if (jw_global)
			jsonw_uint_field(jw_global, "vlan", vid);
		else
			fprintf(fp, "vlan %hu ", vid);
	}

	if (tb[NDA_PORT]) {
		if (jw_global)
			jsonw_uint_field(jw_global, "port",
					 rta_getattr_be16(tb[NDA_PORT]));
		else
			fprintf(fp, "port %d ",
				rta_getattr_be16(tb[NDA_PORT]));
	}

	if (tb[NDA_VNI]) {
		if (jw_global)
			jsonw_uint_field(jw_global, "vni",
					 rta_getattr_u32(tb[NDA_VNI]));
		else
			fprintf(fp, "vni %d ",
				rta_getattr_u32(tb[NDA_VNI]));
	}

	if (tb[NDA_IFINDEX]) {
		unsigned int ifindex = rta_getattr_u32(tb[NDA_IFINDEX]);

		if (ifindex) {
			char ifname[IF_NAMESIZE];

			if (!tb[NDA_LINK_NETNSID] &&
			    if_indextoname(ifindex, ifname)) {
				if (jw_global)
					jsonw_string_field(jw_global, "viaIf",
							   ifname);
				else
					fprintf(fp, "via %s ", ifname);
			} else {
				if (jw_global)
					jsonw_uint_field(jw_global, "viaIfIndex",
							 ifindex);
				else
					fprintf(fp, "via ifindex %u ", ifindex);
			}
		}
	}

	if (tb[NDA_LINK_NETNSID]) {
		if (jw_global)
			jsonw_uint_field(jw_global, "linkNetNsId",
					 rta_getattr_u32(tb[NDA_LINK_NETNSID]));
		else
			fprintf(fp, "link-netnsid %d ",
				rta_getattr_u32(tb[NDA_LINK_NETNSID]));
	}

	if (show_stats && tb[NDA_CACHEINFO]) {
		struct nda_cacheinfo *ci = RTA_DATA(tb[NDA_CACHEINFO]);
		int hz = get_user_hz();

		if (jw_global) {
			jsonw_uint_field(jw_global, "used",
				ci->ndm_used/hz);
			jsonw_uint_field(jw_global, "updated",
				ci->ndm_updated/hz);
		} else {
			fprintf(fp, "used %d/%d ", ci->ndm_used/hz,
					ci->ndm_updated/hz);
		}
	}

	if (jw_global) {
		if (r->ndm_flags & NTF_SELF) {
			start_json_fdb_flags_array(&fdb_flags);
			jsonw_string(jw_global, "self");
		}
		if (r->ndm_flags & NTF_ROUTER) {
			start_json_fdb_flags_array(&fdb_flags);
			jsonw_string(jw_global, "router");
		}
		if (r->ndm_flags & NTF_EXT_LEARNED) {
			start_json_fdb_flags_array(&fdb_flags);
			jsonw_string(jw_global, "extern_learn");
		}
		if (r->ndm_flags & NTF_OFFLOADED) {
			start_json_fdb_flags_array(&fdb_flags);
			jsonw_string(jw_global, "offload");
		}
		if (r->ndm_flags & NTF_MASTER)
			jsonw_string(jw_global, "master");
		if (fdb_flags)
			jsonw_end_array(jw_global);

		if (tb[NDA_MASTER])
			jsonw_string_field(jw_global,
					   "master",
					   ll_index_to_name(rta_getattr_u32(tb[NDA_MASTER])));

	} else {
		if (r->ndm_flags & NTF_SELF)
			fprintf(fp, "self ");
		if (r->ndm_flags & NTF_ROUTER)
			fprintf(fp, "router ");
		if (r->ndm_flags & NTF_EXT_LEARNED)
			fprintf(fp, "extern_learn ");
		if (r->ndm_flags & NTF_OFFLOADED)
			fprintf(fp, "offload ");
		if (tb[NDA_MASTER]) {
			fprintf(fp, "master %s ",
				ll_index_to_name(rta_getattr_u32(tb[NDA_MASTER])));
		} else if (r->ndm_flags & NTF_MASTER) {
			fprintf(fp, "master ");
		}
	}

	state_s = state_n2a(r->ndm_state);
	if (jw_global) {
		if (state_s[0])
			jsonw_string_field(jw_global, "state", state_s);

		jsonw_end_object(jw_global);
	} else {
		fprintf(fp, "%s\n", state_s);

		fflush(fp);
	}

	return 0;
}

static int fdb_show(int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct ifinfomsg	ifm;
		char			buf[256];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.ifm.ifi_family = PF_BRIDGE,
	};

	char *filter_dev = NULL;
	char *br = NULL;
	int msg_size = sizeof(struct ifinfomsg);

	while (argc > 0) {
		if ((strcmp(*argv, "brport") == 0) || strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			filter_dev = *argv;
		} else if (strcmp(*argv, "br") == 0) {
			NEXT_ARG();
			br = *argv;
		} else if (strcmp(*argv, "vlan") == 0) {
			NEXT_ARG();
			if (filter_vlan)
				duparg("vlan", *argv);
			filter_vlan = atoi(*argv);
		} else if (strcmp(*argv, "state") == 0) {
			unsigned int state;

			NEXT_ARG();
			if (state_a2n(&state, *argv))
				invarg("invalid state", *argv);
			filter_state |= state;
		} else {
			if (matches(*argv, "help") == 0)
				usage();
		}
		argc--; argv++;
	}

	if (br) {
		int br_ifindex = ll_name_to_index(br);

		if (br_ifindex == 0) {
			fprintf(stderr, "Cannot find bridge device \"%s\"\n", br);
			return -1;
		}
		addattr32(&req.n, sizeof(req), IFLA_MASTER, br_ifindex);
		msg_size += RTA_LENGTH(4);
	}

	/*we'll keep around filter_dev for older kernels */
	if (filter_dev) {
		filter_index = if_nametoindex(filter_dev);
		if (filter_index == 0) {
			fprintf(stderr, "Cannot find device \"%s\"\n",
				filter_dev);
			return -1;
		}
		req.ifm.ifi_index = filter_index;
	}

	if (rtnl_dump_request(&rth, RTM_GETNEIGH, &req.ifm, msg_size) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (json_output) {
		jw_global = jsonw_new(stdout);
		if (!jw_global) {
			fprintf(stderr, "Error allocation json object\n");
			exit(1);
		}
		jsonw_start_array(jw_global);
	}
	if (rtnl_dump_filter(&rth, print_fdb, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}
	if (jw_global) {
		jsonw_end_array(jw_global);
		jsonw_destroy(&jw_global);
	}

	return 0;
}

static int fdb_modify(int cmd, int flags, int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct ndmsg		ndm;
		char			buf[256];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | flags,
		.n.nlmsg_type = cmd,
		.ndm.ndm_family = PF_BRIDGE,
		.ndm.ndm_state = NUD_NOARP,
	};
	char *addr = NULL;
	char *d = NULL;
	char abuf[ETH_ALEN];
	int dst_ok = 0;
	inet_prefix dst;
	unsigned long port = 0;
	unsigned long vni = ~0;
	unsigned int via = 0;
	char *endptr;
	short vid = -1;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "dst") == 0) {
			NEXT_ARG();
			if (dst_ok)
				duparg2("dst", *argv);
			get_addr(&dst, *argv, preferred_family);
			dst_ok = 1;
		} else if (strcmp(*argv, "port") == 0) {

			NEXT_ARG();
			port = strtoul(*argv, &endptr, 0);
			if (endptr && *endptr) {
				struct servent *pse;

				pse = getservbyname(*argv, "udp");
				if (!pse)
					invarg("invalid port\n", *argv);
				port = ntohs(pse->s_port);
			} else if (port > 0xffff)
				invarg("invalid port\n", *argv);
		} else if (strcmp(*argv, "vni") == 0) {
			NEXT_ARG();
			vni = strtoul(*argv, &endptr, 0);
			if ((endptr && *endptr) ||
			    (vni >> 24) || vni == ULONG_MAX)
				invarg("invalid VNI\n", *argv);
		} else if (strcmp(*argv, "via") == 0) {
			NEXT_ARG();
			via = if_nametoindex(*argv);
			if (via == 0)
				invarg("invalid device\n", *argv);
		} else if (strcmp(*argv, "self") == 0) {
			req.ndm.ndm_flags |= NTF_SELF;
		} else if (matches(*argv, "master") == 0) {
			req.ndm.ndm_flags |= NTF_MASTER;
		} else if (matches(*argv, "router") == 0) {
			req.ndm.ndm_flags |= NTF_ROUTER;
		} else if (matches(*argv, "local") == 0 ||
			   matches(*argv, "permanent") == 0) {
			req.ndm.ndm_state |= NUD_PERMANENT;
		} else if (matches(*argv, "temp") == 0 ||
			   matches(*argv, "static") == 0) {
			req.ndm.ndm_state |= NUD_REACHABLE;
		} else if (matches(*argv, "dynamic") == 0) {
			req.ndm.ndm_state |= NUD_REACHABLE;
			req.ndm.ndm_state &= ~NUD_NOARP;
		} else if (matches(*argv, "vlan") == 0) {
			if (vid >= 0)
				duparg2("vlan", *argv);
			NEXT_ARG();
			vid = atoi(*argv);
		} else if (matches(*argv, "use") == 0) {
			req.ndm.ndm_flags |= NTF_USE;
		} else {
			if (strcmp(*argv, "to") == 0)
				NEXT_ARG();

			if (matches(*argv, "help") == 0)
				usage();
			if (addr)
				duparg2("to", *argv);
			addr = *argv;
		}
		argc--; argv++;
	}

	if (d == NULL || addr == NULL) {
		fprintf(stderr, "Device and address are required arguments.\n");
		return -1;
	}

	/* Assume self */
	if (!(req.ndm.ndm_flags&(NTF_SELF|NTF_MASTER)))
		req.ndm.ndm_flags |= NTF_SELF;

	/* Assume permanent */
	if (!(req.ndm.ndm_state&(NUD_PERMANENT|NUD_REACHABLE)))
		req.ndm.ndm_state |= NUD_PERMANENT;

	if (sscanf(addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   abuf, abuf+1, abuf+2,
		   abuf+3, abuf+4, abuf+5) != 6) {
		fprintf(stderr, "Invalid mac address %s\n", addr);
		return -1;
	}

	addattr_l(&req.n, sizeof(req), NDA_LLADDR, abuf, ETH_ALEN);
	if (dst_ok)
		addattr_l(&req.n, sizeof(req), NDA_DST, &dst.data, dst.bytelen);

	if (vid >= 0)
		addattr16(&req.n, sizeof(req), NDA_VLAN, vid);

	if (port) {
		unsigned short dport;

		dport = htons((unsigned short)port);
		addattr16(&req.n, sizeof(req), NDA_PORT, dport);
	}
	if (vni != ~0)
		addattr32(&req.n, sizeof(req), NDA_VNI, vni);
	if (via)
		addattr32(&req.n, sizeof(req), NDA_IFINDEX, via);

	req.ndm.ndm_ifindex = ll_name_to_index(d);
	if (req.ndm.ndm_ifindex == 0) {
		fprintf(stderr, "Cannot find device \"%s\"\n", d);
		return -1;
	}

	if (rtnl_talk(&rth, &req.n, NULL, 0) < 0)
		return -1;

	return 0;
}

int do_fdb(int argc, char **argv)
{
	ll_init_map(&rth);

	if (argc > 0) {
		if (matches(*argv, "add") == 0)
			return fdb_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_EXCL, argc-1, argv+1);
		if (matches(*argv, "append") == 0)
			return fdb_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_APPEND, argc-1, argv+1);
		if (matches(*argv, "replace") == 0)
			return fdb_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_REPLACE, argc-1, argv+1);
		if (matches(*argv, "delete") == 0)
			return fdb_modify(RTM_DELNEIGH, 0, argc-1, argv+1);
		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return fdb_show(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return fdb_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"bridge fdb help\".\n", *argv);
	exit(-1);
}
