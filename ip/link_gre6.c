/*
 * link_gre6.c	gre driver module
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Dmitry Kozlov <xeb@mail.ru>
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
		"Usage: ... { ip6gre | ip6gretap | ip6erspan} [ remote ADDR ]\n"
		"                                  [ local ADDR ]\n"
		"                                  [ [i|o]seq ]\n"
		"                                  [ [i|o]key KEY ]\n"
		"                                  [ [i|o]csum ]\n"
		"                                  [ hoplimit TTL ]\n"
		"                                  [ encaplimit ELIM ]\n"
		"                                  [ tclass TCLASS ]\n"
		"                                  [ flowlabel FLOWLABEL ]\n"
		"                                  [ dscp inherit ]\n"
		"                                  [ fwmark MARK ]\n"
		"                                  [ dev PHYS_DEV ]\n"
		"                                  [ noencap ]\n"
		"                                  [ encap { fou | gue | none } ]\n"
		"                                  [ encap-sport PORT ]\n"
		"                                  [ encap-dport PORT ]\n"
		"                                  [ [no]encap-csum ]\n"
		"                                  [ [no]encap-csum6 ]\n"
		"                                  [ [no]encap-remcsum ]\n"
		"                                  [ erspan IDX ]\n"
		"\n"
		"Where: ADDR      := IPV6_ADDRESS\n"
		"       TTL       := { 0..255 } (default=%d)\n"
		"       KEY       := { DOTTED_QUAD | NUMBER }\n"
		"       ELIM      := { none | 0..255 }(default=%d)\n"
		"       TCLASS    := { 0x0..0xff | inherit }\n"
		"       FLOWLABEL := { 0x0..0xfffff | inherit }\n"
		"       MARK      := { 0x0..0xffffffff | inherit }\n",
		DEFAULT_TNL_HOP_LIMIT, IPV6_DEFAULT_TNL_ENCAP_LIMIT
	);
}

static void usage(void) __attribute__((noreturn));
static void usage(void)
{
	print_usage(stderr);
	exit(-1);
}

static int gre_parse_opt(struct link_util *lu, int argc, char **argv,
			 struct nlmsghdr *n)
{
	struct ifinfomsg *ifi = (struct ifinfomsg *)(n + 1);
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(*ifi)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_GETLINK,
		.i.ifi_family = preferred_family,
		.i.ifi_index = ifi->ifi_index,
	};
	struct nlmsghdr *answer;
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtattr *linkinfo[IFLA_INFO_MAX+1];
	struct rtattr *greinfo[IFLA_GRE_MAX + 1];
	__u16 iflags = 0;
	__u16 oflags = 0;
	__be32 ikey = 0;
	__be32 okey = 0;
	struct in6_addr raddr = IN6ADDR_ANY_INIT;
	struct in6_addr laddr = IN6ADDR_ANY_INIT;
	unsigned int link = 0;
	unsigned int flowinfo = 0;
	unsigned int flags = 0;
	__u8 hop_limit = DEFAULT_TNL_HOP_LIMIT;
	__u8 encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
	__u16 encaptype = 0;
	__u16 encapflags = TUNNEL_ENCAP_FLAG_CSUM6;
	__u16 encapsport = 0;
	__u16 encapdport = 0;
	int len;
	__u32 fwmark = 0;
	__u32 erspan_idx = 0;

	if (!(n->nlmsg_flags & NLM_F_CREATE)) {
		if (rtnl_talk(&rth, &req.n, &answer) < 0) {
get_failed:
			fprintf(stderr,
				"Failed to get existing tunnel info.\n");
			return -1;
		}

		len = answer->nlmsg_len;
		len -= NLMSG_LENGTH(sizeof(*ifi));
		if (len < 0)
			goto get_failed;

		parse_rtattr(tb, IFLA_MAX, IFLA_RTA(NLMSG_DATA(answer)), len);

		if (!tb[IFLA_LINKINFO])
			goto get_failed;

		parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

		if (!linkinfo[IFLA_INFO_DATA])
			goto get_failed;

		parse_rtattr_nested(greinfo, IFLA_GRE_MAX,
				    linkinfo[IFLA_INFO_DATA]);

		if (greinfo[IFLA_GRE_IKEY])
			ikey = rta_getattr_u32(greinfo[IFLA_GRE_IKEY]);

		if (greinfo[IFLA_GRE_OKEY])
			okey = rta_getattr_u32(greinfo[IFLA_GRE_OKEY]);

		if (greinfo[IFLA_GRE_IFLAGS])
			iflags = rta_getattr_u16(greinfo[IFLA_GRE_IFLAGS]);

		if (greinfo[IFLA_GRE_OFLAGS])
			oflags = rta_getattr_u16(greinfo[IFLA_GRE_OFLAGS]);

		if (greinfo[IFLA_GRE_LOCAL])
			memcpy(&laddr, RTA_DATA(greinfo[IFLA_GRE_LOCAL]), sizeof(laddr));

		if (greinfo[IFLA_GRE_REMOTE])
			memcpy(&raddr, RTA_DATA(greinfo[IFLA_GRE_REMOTE]), sizeof(raddr));

		if (greinfo[IFLA_GRE_TTL])
			hop_limit = rta_getattr_u8(greinfo[IFLA_GRE_TTL]);

		if (greinfo[IFLA_GRE_LINK])
			link = rta_getattr_u32(greinfo[IFLA_GRE_LINK]);

		if (greinfo[IFLA_GRE_ENCAP_LIMIT])
			encap_limit = rta_getattr_u8(greinfo[IFLA_GRE_ENCAP_LIMIT]);

		if (greinfo[IFLA_GRE_FLOWINFO])
			flowinfo = rta_getattr_u32(greinfo[IFLA_GRE_FLOWINFO]);

		if (greinfo[IFLA_GRE_FLAGS])
			flags = rta_getattr_u32(greinfo[IFLA_GRE_FLAGS]);

		if (greinfo[IFLA_GRE_ENCAP_TYPE])
			encaptype = rta_getattr_u16(greinfo[IFLA_GRE_ENCAP_TYPE]);

		if (greinfo[IFLA_GRE_ENCAP_FLAGS])
			encapflags = rta_getattr_u16(greinfo[IFLA_GRE_ENCAP_FLAGS]);

		if (greinfo[IFLA_GRE_ENCAP_SPORT])
			encapsport = rta_getattr_u16(greinfo[IFLA_GRE_ENCAP_SPORT]);

		if (greinfo[IFLA_GRE_ENCAP_DPORT])
			encapdport = rta_getattr_u16(greinfo[IFLA_GRE_ENCAP_DPORT]);

		if (greinfo[IFLA_GRE_FWMARK])
			fwmark = rta_getattr_u32(greinfo[IFLA_GRE_FWMARK]);

		if (greinfo[IFLA_GRE_ERSPAN_INDEX])
			erspan_idx = rta_getattr_u32(greinfo[IFLA_GRE_ERSPAN_INDEX]);

		free(answer);
	}

	while (argc > 0) {
		if (!matches(*argv, "key")) {
			NEXT_ARG();
			iflags |= GRE_KEY;
			oflags |= GRE_KEY;
			ikey = okey = tnl_parse_key("key", *argv);
		} else if (!matches(*argv, "ikey")) {
			NEXT_ARG();
			iflags |= GRE_KEY;
			ikey = tnl_parse_key("ikey", *argv);
		} else if (!matches(*argv, "okey")) {
			NEXT_ARG();
			oflags |= GRE_KEY;
			okey = tnl_parse_key("okey", *argv);
		} else if (!matches(*argv, "seq")) {
			iflags |= GRE_SEQ;
			oflags |= GRE_SEQ;
		} else if (!matches(*argv, "iseq")) {
			iflags |= GRE_SEQ;
		} else if (!matches(*argv, "oseq")) {
			oflags |= GRE_SEQ;
		} else if (!matches(*argv, "csum")) {
			iflags |= GRE_CSUM;
			oflags |= GRE_CSUM;
		} else if (!matches(*argv, "icsum")) {
			iflags |= GRE_CSUM;
		} else if (!matches(*argv, "ocsum")) {
			oflags |= GRE_CSUM;
		} else if (!matches(*argv, "remote")) {
			inet_prefix addr;

			NEXT_ARG();
			get_addr(&addr, *argv, AF_INET6);
			memcpy(&raddr, &addr.data, sizeof(raddr));
		} else if (!matches(*argv, "local")) {
			inet_prefix addr;

			NEXT_ARG();
			get_addr(&addr, *argv, AF_INET6);
			memcpy(&laddr, &addr.data, sizeof(laddr));
		} else if (!matches(*argv, "dev")) {
			NEXT_ARG();
			link = ll_name_to_index(*argv);
			if (link == 0) {
				fprintf(stderr, "Cannot find device \"%s\"\n",
					*argv);
				exit(-1);
			}
		} else if (!matches(*argv, "ttl") ||
			   !matches(*argv, "hoplimit") ||
			   !matches(*argv, "hlim")) {
			NEXT_ARG();
			if (strcmp(*argv, "inherit") != 0) {
				if (get_u8(&hop_limit, *argv, 0))
					invarg("invalid HLIM\n", *argv);
			} else
				hop_limit = 0;
		} else if (!matches(*argv, "tos") ||
			   !matches(*argv, "tclass") ||
			   !matches(*argv, "dsfield")) {
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
			encapflags &= ~TUNNEL_ENCAP_FLAG_REMCSUM;
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
		} else if (strcmp(*argv, "encaplimit") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "none") == 0) {
				flags |= IP6_TNL_F_IGN_ENCAP_LIMIT;
			} else {
				__u8 uval;

				if (get_u8(&uval, *argv, 0))
					invarg("invalid ELIM", *argv);
				encap_limit = uval;
				flags &= ~IP6_TNL_F_IGN_ENCAP_LIMIT;
			}
		} else if (strcmp(*argv, "erspan") == 0) {
			NEXT_ARG();
			if (get_u32(&erspan_idx, *argv, 0))
				invarg("invalid erspan index\n", *argv);
			if (erspan_idx & ~((1<<20) - 1) || erspan_idx == 0)
				invarg("erspan index must be > 0 and <= 20-bit\n", *argv);
		} else
			usage();
		argc--; argv++;
	}

	addattr32(n, 1024, IFLA_GRE_IKEY, ikey);
	addattr32(n, 1024, IFLA_GRE_OKEY, okey);
	addattr_l(n, 1024, IFLA_GRE_IFLAGS, &iflags, 2);
	addattr_l(n, 1024, IFLA_GRE_OFLAGS, &oflags, 2);
	addattr_l(n, 1024, IFLA_GRE_LOCAL, &laddr, sizeof(laddr));
	addattr_l(n, 1024, IFLA_GRE_REMOTE, &raddr, sizeof(raddr));
	if (link)
		addattr32(n, 1024, IFLA_GRE_LINK, link);
	addattr_l(n, 1024, IFLA_GRE_TTL, &hop_limit, 1);
	addattr_l(n, 1024, IFLA_GRE_ENCAP_LIMIT, &encap_limit, 1);
	addattr_l(n, 1024, IFLA_GRE_FLOWINFO, &flowinfo, 4);
	addattr32(n, 1024, IFLA_GRE_FLAGS, flags);
	addattr32(n, 1024, IFLA_GRE_FWMARK, fwmark);
	if (erspan_idx != 0)
		addattr32(n, 1024, IFLA_GRE_ERSPAN_INDEX, erspan_idx);

	addattr16(n, 1024, IFLA_GRE_ENCAP_TYPE, encaptype);
	addattr16(n, 1024, IFLA_GRE_ENCAP_FLAGS, encapflags);
	addattr16(n, 1024, IFLA_GRE_ENCAP_SPORT, htons(encapsport));
	addattr16(n, 1024, IFLA_GRE_ENCAP_DPORT, htons(encapdport));

	return 0;
}

static void gre_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	char s2[64];
	const char *local = "any";
	const char *remote = "any";
	unsigned int iflags = 0;
	unsigned int oflags = 0;
	unsigned int flags = 0;
	__u32 flowinfo = 0;
	struct in6_addr in6_addr_any = IN6ADDR_ANY_INIT;
	__u8 ttl = 0;

	if (!tb)
		return;

	if (tb[IFLA_GRE_FLAGS])
		flags = rta_getattr_u32(tb[IFLA_GRE_FLAGS]);

	if (tb[IFLA_GRE_FLOWINFO])
		flowinfo = rta_getattr_u32(tb[IFLA_GRE_FLOWINFO]);

	if (tb[IFLA_GRE_REMOTE]) {
		struct in6_addr addr;

		memcpy(&addr, RTA_DATA(tb[IFLA_GRE_REMOTE]), sizeof(addr));

		if (memcmp(&addr, &in6_addr_any, sizeof(addr)))
			remote = format_host(AF_INET6, sizeof(addr), &addr);
	}

	print_string(PRINT_ANY, "remote", "remote %s ", remote);

	if (tb[IFLA_GRE_LOCAL]) {
		struct in6_addr addr;

		memcpy(&addr, RTA_DATA(tb[IFLA_GRE_LOCAL]), sizeof(addr));

		if (memcmp(&addr, &in6_addr_any, sizeof(addr)))
			local = format_host(AF_INET6, sizeof(addr), &addr);
	}

	print_string(PRINT_ANY, "local", "local %s ", local);

	if (tb[IFLA_GRE_LINK]) {
		unsigned int link = rta_getattr_u32(tb[IFLA_GRE_LINK]);

		if (link) {
			print_string(PRINT_ANY, "link", "dev %s ",
				     ll_index_to_name(link));
		}
	}

	if (tb[IFLA_GRE_TTL])
		ttl = rta_getattr_u8(tb[IFLA_GRE_TTL]);
	if (is_json_context() || ttl)
		print_uint(PRINT_ANY, "ttl", "hoplimit %u ", ttl);
	else
		print_string(PRINT_FP, NULL, "hoplimit %s ", "inherit");

	if (flags & IP6_TNL_F_IGN_ENCAP_LIMIT) {
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_ign_encap_limit",
			   "encaplimit none ",
			   true);
	} else if (tb[IFLA_GRE_ENCAP_LIMIT]) {
		__u8 val = rta_getattr_u8(tb[IFLA_GRE_ENCAP_LIMIT]);

		print_uint(PRINT_ANY, "encap_limit", "encaplimit %u ", val);
	}

	if (flags & IP6_TNL_F_USE_ORIG_TCLASS) {
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_use_orig_tclass",
			   "tclass inherit ",
			   true);
	} else if (tb[IFLA_GRE_FLOWINFO]) {
		__u32 val = ntohl(flowinfo & IP6_FLOWINFO_TCLASS) >> 20;

		snprintf(s2, sizeof(s2), "0x%02x", val);
		print_string(PRINT_ANY, "tclass", "tclass %s ", s2);
	}

	if (flags & IP6_TNL_F_USE_ORIG_FLOWLABEL) {
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_use_orig_flowlabel",
			   "flowlabel inherit ",
			   true);
	} else if (tb[IFLA_GRE_FLOWINFO]) {
		__u32 val = ntohl(flowinfo & IP6_FLOWINFO_FLOWLABEL);

		snprintf(s2, sizeof(s2), "0x%05x", val);
		print_string(PRINT_ANY, "flowlabel", "flowlabel %s ", s2);
	}

	if (flags & IP6_TNL_F_RCV_DSCP_COPY)
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_rcv_dscp_copy",
			   "dscp inherit ",
			   true);

	if (tb[IFLA_GRE_IFLAGS])
		iflags = rta_getattr_u16(tb[IFLA_GRE_IFLAGS]);

	if (tb[IFLA_GRE_OFLAGS])
		oflags = rta_getattr_u16(tb[IFLA_GRE_OFLAGS]);

	if ((iflags & GRE_KEY) && tb[IFLA_GRE_IKEY]) {
		inet_ntop(AF_INET, RTA_DATA(tb[IFLA_GRE_IKEY]), s2, sizeof(s2));
		print_string(PRINT_ANY, "ikey", "ikey %s ", s2);
	}

	if ((oflags & GRE_KEY) && tb[IFLA_GRE_OKEY]) {
		inet_ntop(AF_INET, RTA_DATA(tb[IFLA_GRE_OKEY]), s2, sizeof(s2));
		print_string(PRINT_ANY, "okey", "okey %s ", s2);
	}

	if (iflags & GRE_SEQ)
		print_bool(PRINT_ANY, "iseq", "iseq ", true);
	if (oflags & GRE_SEQ)
		print_bool(PRINT_ANY, "oseq", "oseq ", true);
	if (iflags & GRE_CSUM)
		print_bool(PRINT_ANY, "icsum", "icsum ", true);
	if (oflags & GRE_CSUM)
		print_bool(PRINT_ANY, "ocsum", "ocsum ", true);

	if (flags & IP6_TNL_F_USE_ORIG_FWMARK) {
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_use_orig_fwmark",
			   "fwmark inherit ",
			   true);
	} else if (tb[IFLA_GRE_FWMARK]) {
		__u32 fwmark = rta_getattr_u32(tb[IFLA_GRE_FWMARK]);

		if (fwmark) {
			print_0xhex(PRINT_ANY,
				    "fwmark", "fwmark 0x%x ", fwmark);
		}
	}

	if (tb[IFLA_GRE_ERSPAN_INDEX]) {
		__u32 erspan_idx = rta_getattr_u32(tb[IFLA_GRE_ERSPAN_INDEX]);

		print_uint(PRINT_ANY,
			   "erspan_index", "erspan_index %u ", erspan_idx);
	}

	tnl_print_encap(tb,
			IFLA_GRE_ENCAP_TYPE,
			IFLA_GRE_ENCAP_FLAGS,
			IFLA_GRE_ENCAP_SPORT,
			IFLA_GRE_ENCAP_DPORT);
}

static void gre_print_help(struct link_util *lu, int argc, char **argv,
	FILE *f)
{
	print_usage(f);
}

struct link_util ip6gre_link_util = {
	.id = "ip6gre",
	.maxattr = IFLA_GRE_MAX,
	.parse_opt = gre_parse_opt,
	.print_opt = gre_print_opt,
	.print_help = gre_print_help,
};

struct link_util ip6gretap_link_util = {
	.id = "ip6gretap",
	.maxattr = IFLA_GRE_MAX,
	.parse_opt = gre_parse_opt,
	.print_opt = gre_print_opt,
	.print_help = gre_print_help,
};

struct link_util ip6erspan_link_util = {
	.id = "ip6erspan",
	.maxattr = IFLA_GRE_MAX,
	.parse_opt = gre_parse_opt,
	.print_opt = gre_print_opt,
	.print_help = gre_print_help,
};
