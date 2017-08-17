/*
 * link_ip6tnl.c	ip6tnl driver module
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Nicolas Dichtel <nicolas.dichtel@6wind.com>
 *
 */

#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"
#include "tunnel.h"

#define IP6_FLOWINFO_TCLASS	htonl(0x0FF00000)
#define IP6_FLOWINFO_FLOWLABEL	htonl(0x000FFFFF)

#define DEFAULT_TNL_HOP_LIMIT	(64)

static void print_usage(FILE *f)
{
	fprintf(f,
		"Usage: ... ip6tnl [ mode { ip6ip6 | ipip6 | any } ]\n"
		"                  [ remote ADDR ]\n"
		"                  [ local ADDR ]\n"
		"                  [ dev PHYS_DEV ]\n"
		"                  [ encaplimit ELIM ]\n"
		"                  [ hoplimit HLIM ]\n"
		"                  [ tclass TCLASS ]\n"
		"                  [ flowlabel FLOWLABEL ]\n"
		"                  [ dscp inherit ]\n"
		"                  [ fwmark MARK ]\n"
		"                  [ noencap ]\n"
		"                  [ encap { fou | gue | none } ]\n"
		"                  [ encap-sport PORT ]\n"
		"                  [ encap-dport PORT ]\n"
		"                  [ [no]encap-csum ]\n"
		"                  [ [no]encap-csum6 ]\n"
		"                  [ [no]encap-remcsum ]\n"
		"                  [ external ]\n"
		"\n"
		"Where: ADDR      := IPV6_ADDRESS\n"
		"       ELIM      := { none | 0..255 }(default=%d)\n"
		"       HLIM      := 0..255 (default=%d)\n"
		"       TCLASS    := { 0x0..0xff | inherit }\n"
		"       FLOWLABEL := { 0x0..0xfffff | inherit }\n"
		"       MARK      := { 0x0..0xffffffff | inherit }\n",
		IPV6_DEFAULT_TNL_ENCAP_LIMIT, DEFAULT_TNL_HOP_LIMIT
	);
}

static void usage(void) __attribute__((noreturn));
static void usage(void)
{
	print_usage(stderr);
	exit(-1);
}

static int ip6tunnel_parse_opt(struct link_util *lu, int argc, char **argv,
			       struct nlmsghdr *n)
{
	struct ifinfomsg *ifi = (struct ifinfomsg *)(n + 1);
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[2048];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(*ifi)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_GETLINK,
		.i.ifi_family = preferred_family,
		.i.ifi_index = ifi->ifi_index,
	};
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtattr *linkinfo[IFLA_INFO_MAX+1];
	struct rtattr *iptuninfo[IFLA_IPTUN_MAX + 1];
	int len;
	struct in6_addr laddr = {};
	struct in6_addr raddr = {};
	__u8 hop_limit = DEFAULT_TNL_HOP_LIMIT;
	__u8 encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
	__u32 flowinfo = 0;
	__u32 flags = 0;
	__u32 link = 0;
	__u8 proto = 0;
	__u16 encaptype = 0;
	__u16 encapflags = TUNNEL_ENCAP_FLAG_CSUM6;
	__u16 encapsport = 0;
	__u16 encapdport = 0;
	__u8 metadata = 0;
	__u32 fwmark = 0;

	if (!(n->nlmsg_flags & NLM_F_CREATE)) {
		if (rtnl_talk(&rth, &req.n, &req.n, sizeof(req)) < 0) {
get_failed:
			fprintf(stderr,
				"Failed to get existing tunnel info.\n");
			return -1;
		}

		len = req.n.nlmsg_len;
		len -= NLMSG_LENGTH(sizeof(*ifi));
		if (len < 0)
			goto get_failed;

		parse_rtattr(tb, IFLA_MAX, IFLA_RTA(&req.i), len);

		if (!tb[IFLA_LINKINFO])
			goto get_failed;

		parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

		if (!linkinfo[IFLA_INFO_DATA])
			goto get_failed;

		parse_rtattr_nested(iptuninfo, IFLA_IPTUN_MAX,
				    linkinfo[IFLA_INFO_DATA]);

		if (iptuninfo[IFLA_IPTUN_LOCAL])
			memcpy(&laddr, RTA_DATA(iptuninfo[IFLA_IPTUN_LOCAL]),
			       sizeof(laddr));

		if (iptuninfo[IFLA_IPTUN_REMOTE])
			memcpy(&raddr, RTA_DATA(iptuninfo[IFLA_IPTUN_REMOTE]),
			       sizeof(raddr));

		if (iptuninfo[IFLA_IPTUN_TTL])
			hop_limit = rta_getattr_u8(iptuninfo[IFLA_IPTUN_TTL]);

		if (iptuninfo[IFLA_IPTUN_ENCAP_LIMIT])
			encap_limit = rta_getattr_u8(iptuninfo[IFLA_IPTUN_ENCAP_LIMIT]);

		if (iptuninfo[IFLA_IPTUN_FLOWINFO])
			flowinfo = rta_getattr_u32(iptuninfo[IFLA_IPTUN_FLOWINFO]);

		if (iptuninfo[IFLA_IPTUN_FLAGS])
			flags = rta_getattr_u32(iptuninfo[IFLA_IPTUN_FLAGS]);

		if (iptuninfo[IFLA_IPTUN_LINK])
			link = rta_getattr_u32(iptuninfo[IFLA_IPTUN_LINK]);

		if (iptuninfo[IFLA_IPTUN_PROTO])
			proto = rta_getattr_u8(iptuninfo[IFLA_IPTUN_PROTO]);
		if (iptuninfo[IFLA_IPTUN_COLLECT_METADATA])
			metadata = 1;

		if (iptuninfo[IFLA_IPTUN_FWMARK])
			fwmark = rta_getattr_u32(iptuninfo[IFLA_IPTUN_FWMARK]);
	}

	while (argc > 0) {
		if (matches(*argv, "mode") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "ipv6/ipv6") == 0 ||
			    strcmp(*argv, "ip6ip6") == 0)
				proto = IPPROTO_IPV6;
			else if (strcmp(*argv, "ip/ipv6") == 0 ||
				 strcmp(*argv, "ipv4/ipv6") == 0 ||
				 strcmp(*argv, "ipip6") == 0 ||
				 strcmp(*argv, "ip4ip6") == 0)
				proto = IPPROTO_IPIP;
			else if (strcmp(*argv, "any/ipv6") == 0 ||
				 strcmp(*argv, "any") == 0)
				proto = 0;
			else
				invarg("Cannot guess tunnel mode.", *argv);
		} else if (strcmp(*argv, "remote") == 0) {
			inet_prefix addr;

			NEXT_ARG();
			get_prefix(&addr, *argv, preferred_family);
			if (addr.family == AF_UNSPEC)
				invarg("\"remote\" address family is AF_UNSPEC", *argv);
			memcpy(&raddr, addr.data, addr.bytelen);
		} else if (strcmp(*argv, "local") == 0) {
			inet_prefix addr;

			NEXT_ARG();
			get_prefix(&addr, *argv, preferred_family);
			if (addr.family == AF_UNSPEC)
				invarg("\"local\" address family is AF_UNSPEC", *argv);
			memcpy(&laddr, addr.data, addr.bytelen);
		} else if (matches(*argv, "dev") == 0) {
			NEXT_ARG();
			link = if_nametoindex(*argv);
			if (link == 0)
				invarg("\"dev\" is invalid", *argv);
		} else if (strcmp(*argv, "hoplimit") == 0 ||
			   strcmp(*argv, "ttl") == 0 ||
			   strcmp(*argv, "hlim") == 0) {
			__u8 uval;

			NEXT_ARG();
			if (get_u8(&uval, *argv, 0))
				invarg("invalid HLIM", *argv);
			hop_limit = uval;
		} else if (strcmp(*argv, "encaplimit") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "none") == 0) {
				flags |= IP6_TNL_F_IGN_ENCAP_LIMIT;
			} else {
				__u8 uval;

				if (get_u8(&uval, *argv, 0) < -1)
					invarg("invalid ELIM", *argv);
				encap_limit = uval;
				flags &= ~IP6_TNL_F_IGN_ENCAP_LIMIT;
			}
		} else if (strcmp(*argv, "tclass") == 0 ||
			   strcmp(*argv, "tc") == 0 ||
			   strcmp(*argv, "tos") == 0 ||
			   matches(*argv, "dsfield") == 0) {
			__u8 uval;

			NEXT_ARG();
			flowinfo &= ~IP6_FLOWINFO_TCLASS;
			if (strcmp(*argv, "inherit") == 0)
				flags |= IP6_TNL_F_USE_ORIG_TCLASS;
			else {
				if (get_u8(&uval, *argv, 16))
					invarg("invalid TClass", *argv);
				flowinfo |= htonl((__u32)uval << 20) & IP6_FLOWINFO_TCLASS;
				flags &= ~IP6_TNL_F_USE_ORIG_TCLASS;
			}
		} else if (strcmp(*argv, "flowlabel") == 0 ||
			   strcmp(*argv, "fl") == 0) {
			__u32 uval;

			NEXT_ARG();
			flowinfo &= ~IP6_FLOWINFO_FLOWLABEL;
			if (strcmp(*argv, "inherit") == 0)
				flags |= IP6_TNL_F_USE_ORIG_FLOWLABEL;
			else {
				if (get_u32(&uval, *argv, 16))
					invarg("invalid Flowlabel", *argv);
				if (uval > 0xFFFFF)
					invarg("invalid Flowlabel", *argv);
				flowinfo |= htonl(uval) & IP6_FLOWINFO_FLOWLABEL;
				flags &= ~IP6_TNL_F_USE_ORIG_FLOWLABEL;
			}
		} else if (strcmp(*argv, "dscp") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "inherit") != 0)
				invarg("not inherit", *argv);
			flags |= IP6_TNL_F_RCV_DSCP_COPY;
		} else if (strcmp(*argv, "fwmark") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "inherit") == 0) {
				flags |= IP6_TNL_F_USE_ORIG_FWMARK;
				fwmark = 0;
			} else {
				if (get_u32(&fwmark, *argv, 0))
					invarg("invalid fwmark\n", *argv);
				flags &= ~IP6_TNL_F_USE_ORIG_FWMARK;
			}
		} else if (strcmp(*argv, "noencap") == 0) {
			encaptype = TUNNEL_ENCAP_NONE;
		} else if (strcmp(*argv, "encap") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "fou") == 0)
				encaptype = TUNNEL_ENCAP_FOU;
			else if (strcmp(*argv, "gue") == 0)
				encaptype = TUNNEL_ENCAP_GUE;
			else if (strcmp(*argv, "none") == 0)
				encaptype = TUNNEL_ENCAP_NONE;
			else
				invarg("Invalid encap type.", *argv);
		} else if (strcmp(*argv, "encap-sport") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "auto") == 0)
				encapsport = 0;
			else if (get_u16(&encapsport, *argv, 0))
				invarg("Invalid source port.", *argv);
		} else if (strcmp(*argv, "encap-dport") == 0) {
			NEXT_ARG();
			if (get_u16(&encapdport, *argv, 0))
				invarg("Invalid destination port.", *argv);
		} else if (strcmp(*argv, "encap-csum") == 0) {
			encapflags |= TUNNEL_ENCAP_FLAG_CSUM;
		} else if (strcmp(*argv, "noencap-csum") == 0) {
			encapflags &= ~TUNNEL_ENCAP_FLAG_CSUM;
		} else if (strcmp(*argv, "encap-udp6-csum") == 0) {
			encapflags |= TUNNEL_ENCAP_FLAG_CSUM6;
		} else if (strcmp(*argv, "noencap-udp6-csum") == 0) {
			encapflags &= ~TUNNEL_ENCAP_FLAG_CSUM6;
		} else if (strcmp(*argv, "encap-remcsum") == 0) {
			encapflags |= TUNNEL_ENCAP_FLAG_REMCSUM;
		} else if (strcmp(*argv, "noencap-remcsum") == 0) {
			encapflags |= ~TUNNEL_ENCAP_FLAG_REMCSUM;
		} else if (strcmp(*argv, "external") == 0) {
			metadata = 1;
		} else
			usage();
		argc--, argv++;
	}

	addattr8(n, 1024, IFLA_IPTUN_PROTO, proto);
	if (metadata) {
		addattr_l(n, 1024, IFLA_IPTUN_COLLECT_METADATA, NULL, 0);
		return 0;
	}
	addattr_l(n, 1024, IFLA_IPTUN_LOCAL, &laddr, sizeof(laddr));
	addattr_l(n, 1024, IFLA_IPTUN_REMOTE, &raddr, sizeof(raddr));
	addattr8(n, 1024, IFLA_IPTUN_TTL, hop_limit);
	addattr8(n, 1024, IFLA_IPTUN_ENCAP_LIMIT, encap_limit);
	addattr32(n, 1024, IFLA_IPTUN_FLOWINFO, flowinfo);
	addattr32(n, 1024, IFLA_IPTUN_FLAGS, flags);
	addattr32(n, 1024, IFLA_IPTUN_LINK, link);
	addattr32(n, 1024, IFLA_IPTUN_FWMARK, fwmark);

	addattr16(n, 1024, IFLA_IPTUN_ENCAP_TYPE, encaptype);
	addattr16(n, 1024, IFLA_IPTUN_ENCAP_FLAGS, encapflags);
	addattr16(n, 1024, IFLA_IPTUN_ENCAP_SPORT, htons(encapsport));
	addattr16(n, 1024, IFLA_IPTUN_ENCAP_DPORT, htons(encapdport));

	return 0;
}

static void ip6tunnel_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	char s2[64];
	int flags = 0;
	__u32 flowinfo = 0;

	if (!tb)
		return;

	if (tb[IFLA_IPTUN_FLAGS])
		flags = rta_getattr_u32(tb[IFLA_IPTUN_FLAGS]);

	if (tb[IFLA_IPTUN_FLOWINFO])
		flowinfo = rta_getattr_u32(tb[IFLA_IPTUN_FLOWINFO]);

	if (tb[IFLA_IPTUN_PROTO]) {
		switch (rta_getattr_u8(tb[IFLA_IPTUN_PROTO])) {
		case IPPROTO_IPIP:
			print_string(PRINT_ANY, "proto", "%s ", "ipip6");
			break;
		case IPPROTO_IPV6:
			print_string(PRINT_ANY, "proto", "%s ", "ip6ip6");
			break;
		case 0:
			print_string(PRINT_ANY, "proto", "%s ", "any");
			break;
		}
	}

	if (tb[IFLA_IPTUN_REMOTE]) {
		print_string(PRINT_ANY,
			     "remote",
			     "remote %s ",
			     rt_addr_n2a_rta(AF_INET6, tb[IFLA_IPTUN_REMOTE]));
	}

	if (tb[IFLA_IPTUN_LOCAL]) {
		print_string(PRINT_ANY,
			     "local",
			     "local %s ",
			     rt_addr_n2a_rta(AF_INET6, tb[IFLA_IPTUN_LOCAL]));
	}

	if (tb[IFLA_IPTUN_LINK] && rta_getattr_u32(tb[IFLA_IPTUN_LINK])) {
		unsigned int link = rta_getattr_u32(tb[IFLA_IPTUN_LINK]);
		const char *n = if_indextoname(link, s2);

		if (n)
			print_string(PRINT_ANY, "link", "dev %s ", n);
		else
			print_uint(PRINT_ANY, "link_index", "dev %u ", link);
	}

	if (flags & IP6_TNL_F_IGN_ENCAP_LIMIT)
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_ign_encap_limit",
			   "encaplimit none ",
			   true);
	else if (tb[IFLA_IPTUN_ENCAP_LIMIT])
		print_uint(PRINT_ANY,
			   "encap_limit",
			   "encaplimit %u ",
			   rta_getattr_u8(tb[IFLA_IPTUN_ENCAP_LIMIT]));

	if (tb[IFLA_IPTUN_TTL])
		print_uint(PRINT_ANY,
			   "ttl",
			   "hoplimit %u ",
			   rta_getattr_u8(tb[IFLA_IPTUN_TTL]));

	if (flags & IP6_TNL_F_USE_ORIG_TCLASS)
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_use_orig_tclass",
			   "tclass inherit ",
			   true);
	else if (tb[IFLA_IPTUN_FLOWINFO]) {
		__u32 val = ntohl(flowinfo & IP6_FLOWINFO_TCLASS);

		if (is_json_context()) {
			SPRINT_BUF(b1);

			snprintf(b1, sizeof(b1), "0x%02x", (__u8)(val >> 20));
			print_string(PRINT_JSON, "flowinfo_tclass", NULL, b1);
		} else {
			printf("tclass 0x%02x ", (__u8)(val >> 20));
		}
	}

	if (flags & IP6_TNL_F_USE_ORIG_FLOWLABEL) {
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_use_orig_flowlabel",
			   "flowlabel inherit ",
			   true);
	} else {
		if (is_json_context()) {
			SPRINT_BUF(b1);

			snprintf(b1, sizeof(b1), "0x%05x",
				 ntohl(flowinfo & IP6_FLOWINFO_FLOWLABEL));
			print_string(PRINT_JSON, "flowlabel", NULL, b1);
		} else {
			printf("flowlabel 0x%05x ",
			       ntohl(flowinfo & IP6_FLOWINFO_FLOWLABEL));
		}
	}

	if (is_json_context()) {
		SPRINT_BUF(flwinfo);

		snprintf(flwinfo, sizeof(flwinfo), "0x%08x", ntohl(flowinfo));
		print_string(PRINT_JSON, "flowinfo", NULL, flwinfo);
	} else {
		printf("(flowinfo 0x%08x) ", ntohl(flowinfo));

	}

	if (flags & IP6_TNL_F_RCV_DSCP_COPY)
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_rcv_dscp_copy",
			   "dscp inherit ",
			   true);

	if (flags & IP6_TNL_F_MIP6_DEV)
		print_bool(PRINT_ANY, "ip6_tnl_f_mip6_dev", "mip6 ", true);

	if (flags & IP6_TNL_F_USE_ORIG_FWMARK) {
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_use_orig_fwmark",
			   "fwmark inherit ",
			   true);
	} else if (tb[IFLA_IPTUN_FWMARK]) {
		__u32 fwmark = rta_getattr_u32(tb[IFLA_IPTUN_FWMARK]);

		if (fwmark) {
			SPRINT_BUF(b1);

			snprintf(b1, sizeof(b1), "0x%x", fwmark);
			print_string(PRINT_ANY, "fwmark", "fwmark %s ", b1);
		}
	}

	if (tb[IFLA_IPTUN_ENCAP_TYPE] &&
	    rta_getattr_u16(tb[IFLA_IPTUN_ENCAP_TYPE]) != TUNNEL_ENCAP_NONE) {
		__u16 type = rta_getattr_u16(tb[IFLA_IPTUN_ENCAP_TYPE]);
		__u16 flags = rta_getattr_u16(tb[IFLA_IPTUN_ENCAP_FLAGS]);
		__u16 sport = rta_getattr_u16(tb[IFLA_IPTUN_ENCAP_SPORT]);
		__u16 dport = rta_getattr_u16(tb[IFLA_IPTUN_ENCAP_DPORT]);

		open_json_object("encap");
		print_string(PRINT_FP, NULL, "encap ", NULL);
		switch (type) {
		case TUNNEL_ENCAP_FOU:
			print_string(PRINT_ANY, "type", "%s ", "fou");
			break;
		case TUNNEL_ENCAP_GUE:
			print_string(PRINT_ANY, "type", "%s ", "gue");
			break;
		default:
			print_null(PRINT_ANY, "type", "unknown ", NULL);
			break;
		}

		if (is_json_context()) {
			print_uint(PRINT_JSON,
				   "sport",
				   NULL,
				   sport ? ntohs(sport) : 0);
			print_uint(PRINT_JSON, "dport", NULL, ntohs(dport));
			print_bool(PRINT_JSON, "csum", NULL,
				   flags & TUNNEL_ENCAP_FLAG_CSUM);
			print_bool(PRINT_JSON, "csum6", NULL,
				   flags & TUNNEL_ENCAP_FLAG_CSUM6);
			print_bool(PRINT_JSON, "remcsum", NULL,
				   flags & TUNNEL_ENCAP_FLAG_REMCSUM);
			close_json_object();
		} else {
			if (sport == 0)
				fputs("encap-sport auto ", f);
			else
				fprintf(f, "encap-sport %u", ntohs(sport));

			fprintf(f, "encap-dport %u ", ntohs(dport));

			if (flags & TUNNEL_ENCAP_FLAG_CSUM)
				fputs("encap-csum ", f);
			else
				fputs("noencap-csum ", f);

			if (flags & TUNNEL_ENCAP_FLAG_CSUM6)
				fputs("encap-csum6 ", f);
			else
				fputs("noencap-csum6 ", f);

			if (flags & TUNNEL_ENCAP_FLAG_REMCSUM)
				fputs("encap-remcsum ", f);
			else
				fputs("noencap-remcsum ", f);
		}
	}
}

static void ip6tunnel_print_help(struct link_util *lu, int argc, char **argv,
				 FILE *f)
{
	print_usage(f);
}

struct link_util ip6tnl_link_util = {
	.id = "ip6tnl",
	.maxattr = IFLA_IPTUN_MAX,
	.parse_opt = ip6tunnel_parse_opt,
	.print_opt = ip6tunnel_print_opt,
	.print_help = ip6tunnel_print_help,
};
