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
		"Usage: ... { ip6gre | ip6gretap } [ remote ADDR ]\n"
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
		char buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(*ifi)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_GETLINK,
		.i.ifi_family = preferred_family,
		.i.ifi_index = ifi->ifi_index,
	};
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtattr *linkinfo[IFLA_INFO_MAX+1];
	struct rtattr *greinfo[IFLA_GRE_MAX + 1];
	__u16 iflags = 0;
	__u16 oflags = 0;
	unsigned int ikey = 0;
	unsigned int okey = 0;
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
	}

	while (argc > 0) {
		if (!matches(*argv, "key")) {
			unsigned int uval;

			NEXT_ARG();
			iflags |= GRE_KEY;
			oflags |= GRE_KEY;
			if (strchr(*argv, '.'))
				uval = get_addr32(*argv);
			else {
				if (get_unsigned(&uval, *argv, 0) < 0) {
					fprintf(stderr,
						"Invalid value for \"key\"\n");
					exit(-1);
				}
				uval = htonl(uval);
			}

			ikey = okey = uval;
		} else if (!matches(*argv, "ikey")) {
			unsigned int uval;

			NEXT_ARG();
			iflags |= GRE_KEY;
			if (strchr(*argv, '.'))
				uval = get_addr32(*argv);
			else {
				if (get_unsigned(&uval, *argv, 0) < 0) {
					fprintf(stderr, "invalid value of \"ikey\"\n");
					exit(-1);
				}
				uval = htonl(uval);
			}
			ikey = uval;
		} else if (!matches(*argv, "okey")) {
			unsigned int uval;

			NEXT_ARG();
			oflags |= GRE_KEY;
			if (strchr(*argv, '.'))
				uval = get_addr32(*argv);
			else {
				if (get_unsigned(&uval, *argv, 0) < 0) {
					fprintf(stderr, "invalid value of \"okey\"\n");
					exit(-1);
				}
				uval = htonl(uval);
			}
			okey = uval;
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
			get_prefix(&addr, *argv, preferred_family);
			if (addr.family == AF_UNSPEC)
				invarg("\"remote\" address family is AF_UNSPEC", *argv);
			memcpy(&raddr, &addr.data, sizeof(raddr));
		} else if (!matches(*argv, "local")) {
			inet_prefix addr;

			NEXT_ARG();
			get_prefix(&addr, *argv, preferred_family);
			if (addr.family == AF_UNSPEC)
				invarg("\"local\" address family is AF_UNSPEC", *argv);
			memcpy(&laddr, &addr.data, sizeof(laddr));
		} else if (!matches(*argv, "dev")) {
			NEXT_ARG();
			link = if_nametoindex(*argv);
			if (link == 0) {
				fprintf(stderr, "Cannot find device \"%s\"\n",
					*argv);
				exit(-1);
			}
		} else if (!matches(*argv, "ttl") ||
			   !matches(*argv, "hoplimit")) {
			__u8 uval;

			NEXT_ARG();
			if (get_u8(&uval, *argv, 0))
				invarg("invalid TTL", *argv);
			hop_limit = uval;
		} else if (!matches(*argv, "tos") ||
			   !matches(*argv, "tclass") ||
			   !matches(*argv, "dsfield")) {
			__u8 uval;

			NEXT_ARG();
			if (strcmp(*argv, "inherit") == 0)
				flags |= IP6_TNL_F_USE_ORIG_TCLASS;
			else {
				if (get_u8(&uval, *argv, 16))
					invarg("invalid TClass", *argv);
				flowinfo &= ~IP6_FLOWINFO_TCLASS;
				flowinfo |= htonl((__u32)uval << 20) & IP6_FLOWINFO_TCLASS;
				flags &= ~IP6_TNL_F_USE_ORIG_TCLASS;
			}
		} else if (strcmp(*argv, "flowlabel") == 0 ||
			   strcmp(*argv, "fl") == 0) {
			__u32 uval;

			NEXT_ARG();
			if (strcmp(*argv, "inherit") == 0)
				flags |= IP6_TNL_F_USE_ORIG_FLOWLABEL;
			else {
				if (get_u32(&uval, *argv, 16))
					invarg("invalid Flowlabel", *argv);
				if (uval > 0xFFFFF)
					invarg("invalid Flowlabel", *argv);
				flowinfo &= ~IP6_FLOWINFO_FLOWLABEL;
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

				if (get_u8(&uval, *argv, 0) < -1)
					invarg("invalid ELIM", *argv);
				encap_limit = uval;
				flags &= ~IP6_TNL_F_IGN_ENCAP_LIMIT;
			}
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
	unsigned int flowinfo = 0;
	struct in6_addr in6_addr_any = IN6ADDR_ANY_INIT;

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

	if (tb[IFLA_GRE_LINK] && rta_getattr_u32(tb[IFLA_GRE_LINK])) {
		unsigned int link = rta_getattr_u32(tb[IFLA_GRE_LINK]);
		const char *n = if_indextoname(link, s2);

		if (n)
			print_string(PRINT_ANY, "link", "dev %s ", n);
		else
			print_uint(PRINT_ANY, "link_index", "dev %u ", link);
	}

	if (tb[IFLA_GRE_TTL]) {
		__u8 ttl = rta_getattr_u8(tb[IFLA_GRE_TTL]);

		if (ttl)
			print_int(PRINT_ANY, "ttl", "hoplimit %d ", ttl);
		else
			print_int(PRINT_JSON, "ttl", NULL, ttl);
	}

	if (flags & IP6_TNL_F_IGN_ENCAP_LIMIT)
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_ign_encap_limit",
			   "encaplimit none ",
			   true);
	else if (tb[IFLA_GRE_ENCAP_LIMIT]) {
		int encap_limit = rta_getattr_u8(tb[IFLA_GRE_ENCAP_LIMIT]);

		print_int(PRINT_ANY,
			  "encap_limit",
			  "encaplimit %d ",
			  encap_limit);
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
			fprintf(f, "flowlabel 0x%05x ",
				ntohl(flowinfo & IP6_FLOWINFO_FLOWLABEL));
		}
	}

	if (flags & IP6_TNL_F_USE_ORIG_TCLASS) {
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_use_orig_tclass",
			   "tclass inherit ",
			   true);
	} else {
		if (is_json_context()) {
			SPRINT_BUF(b1);

			snprintf(b1, sizeof(b1), "0x%05x",
				 ntohl(flowinfo & IP6_FLOWINFO_TCLASS) >> 20);
			print_string(PRINT_JSON, "tclass", NULL, b1);
		} else {
			fprintf(f, "tclass 0x%02x ",
				 ntohl(flowinfo & IP6_FLOWINFO_TCLASS) >> 20);
		}
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

	if (flags & IP6_TNL_F_USE_ORIG_FWMARK)
		print_bool(PRINT_ANY,
			   "ip6_tnl_f_use_orig_fwmark",
			   "fwmark inherit ",
			   true);
	else if (tb[IFLA_GRE_FWMARK]) {
		__u32 fwmark = rta_getattr_u32(tb[IFLA_GRE_FWMARK]);

		if (fwmark) {
			snprintf(s2, sizeof(s2), "0x%x", fwmark);

			print_string(PRINT_ANY, "fwmark", "fwmark %s ", s2);
		}
	}

	if (tb[IFLA_GRE_ENCAP_TYPE] &&
	    rta_getattr_u16(tb[IFLA_GRE_ENCAP_TYPE]) != TUNNEL_ENCAP_NONE) {
		__u16 type = rta_getattr_u16(tb[IFLA_GRE_ENCAP_TYPE]);
		__u16 flags = rta_getattr_u16(tb[IFLA_GRE_ENCAP_FLAGS]);
		__u16 sport = rta_getattr_u16(tb[IFLA_GRE_ENCAP_SPORT]);
		__u16 dport = rta_getattr_u16(tb[IFLA_GRE_ENCAP_DPORT]);

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
