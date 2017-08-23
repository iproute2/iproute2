/*
 * link_gre.c	gre driver module
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Herbert Xu <herbert@gondor.apana.org.au>
 *
 */

#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"
#include "tunnel.h"

static void print_usage(FILE *f)
{
	fprintf(f,
		"Usage: ... { gre | gretap | erspan } [ remote ADDR ]\n"
		"                            [ local ADDR ]\n"
		"                            [ [i|o]seq ]\n"
		"                            [ [i|o]key KEY ]\n"
		"                            [ [i|o]csum ]\n"
		"                            [ ttl TTL ]\n"
		"                            [ tos TOS ]\n"
		"                            [ [no]pmtudisc ]\n"
		"                            [ [no]ignore-df ]\n"
		"                            [ dev PHYS_DEV ]\n"
		"                            [ noencap ]\n"
		"                            [ encap { fou | gue | none } ]\n"
		"                            [ encap-sport PORT ]\n"
		"                            [ encap-dport PORT ]\n"
		"                            [ [no]encap-csum ]\n"
		"                            [ [no]encap-csum6 ]\n"
		"                            [ [no]encap-remcsum ]\n"
		"                            [ fwmark MARK ]\n"
		"                            [ erspan IDX ]\n"
		"\n"
		"Where: ADDR := { IP_ADDRESS | any }\n"
		"       TOS  := { NUMBER | inherit }\n"
		"       TTL  := { 1..255 | inherit }\n"
		"       KEY  := { DOTTED_QUAD | NUMBER }\n"
		"       MARK := { 0x0..0xffffffff }\n"
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
		char buf[16384];
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
	unsigned int saddr = 0;
	unsigned int daddr = 0;
	unsigned int link = 0;
	__u8 pmtudisc = 1;
	__u8 ttl = 0;
	__u8 tos = 0;
	int len;
	__u16 encaptype = 0;
	__u16 encapflags = 0;
	__u16 encapsport = 0;
	__u16 encapdport = 0;
	__u8 metadata = 0;
	__u8 ignore_df = 0;
	__u32 fwmark = 0;
	__u32 erspan_idx = 0;

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
			saddr = rta_getattr_u32(greinfo[IFLA_GRE_LOCAL]);

		if (greinfo[IFLA_GRE_REMOTE])
			daddr = rta_getattr_u32(greinfo[IFLA_GRE_REMOTE]);

		if (greinfo[IFLA_GRE_PMTUDISC])
			pmtudisc = rta_getattr_u8(
				greinfo[IFLA_GRE_PMTUDISC]);

		if (greinfo[IFLA_GRE_TTL])
			ttl = rta_getattr_u8(greinfo[IFLA_GRE_TTL]);

		if (greinfo[IFLA_GRE_TOS])
			tos = rta_getattr_u8(greinfo[IFLA_GRE_TOS]);

		if (greinfo[IFLA_GRE_LINK])
			link = rta_getattr_u8(greinfo[IFLA_GRE_LINK]);

		if (greinfo[IFLA_GRE_ENCAP_TYPE])
			encaptype = rta_getattr_u16(greinfo[IFLA_GRE_ENCAP_TYPE]);
		if (greinfo[IFLA_GRE_ENCAP_FLAGS])
			encapflags = rta_getattr_u16(greinfo[IFLA_GRE_ENCAP_FLAGS]);
		if (greinfo[IFLA_GRE_ENCAP_SPORT])
			encapsport = rta_getattr_u16(greinfo[IFLA_GRE_ENCAP_SPORT]);
		if (greinfo[IFLA_GRE_ENCAP_DPORT])
			encapdport = rta_getattr_u16(greinfo[IFLA_GRE_ENCAP_DPORT]);

		if (greinfo[IFLA_GRE_COLLECT_METADATA])
			metadata = 1;

		if (greinfo[IFLA_GRE_IGNORE_DF])
			ignore_df =
				!!rta_getattr_u8(greinfo[IFLA_GRE_IGNORE_DF]);

		if (greinfo[IFLA_GRE_FWMARK])
			fwmark = rta_getattr_u32(greinfo[IFLA_GRE_FWMARK]);

		if (greinfo[IFLA_GRE_ERSPAN_INDEX])
			erspan_idx = rta_getattr_u32(greinfo[IFLA_GRE_ERSPAN_INDEX]);
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
						"Invalid value for \"key\": \"%s\"; it should be an unsigned integer\n", *argv);
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
					fprintf(stderr, "invalid value for \"ikey\": \"%s\"; it should be an unsigned integer\n", *argv);
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
					fprintf(stderr, "invalid value for \"okey\": \"%s\"; it should be an unsigned integer\n", *argv);
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
		} else if (!matches(*argv, "nopmtudisc")) {
			pmtudisc = 0;
		} else if (!matches(*argv, "pmtudisc")) {
			pmtudisc = 1;
		} else if (!matches(*argv, "remote")) {
			NEXT_ARG();
			if (strcmp(*argv, "any"))
				daddr = get_addr32(*argv);
		} else if (!matches(*argv, "local")) {
			NEXT_ARG();
			if (strcmp(*argv, "any"))
				saddr = get_addr32(*argv);
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
			unsigned int uval;

			NEXT_ARG();
			if (strcmp(*argv, "inherit") != 0) {
				if (get_unsigned(&uval, *argv, 0))
					invarg("invalid TTL\n", *argv);
				if (uval > 255)
					invarg("TTL must be <= 255\n", *argv);
				ttl = uval;
			}
		} else if (!matches(*argv, "tos") ||
			   !matches(*argv, "tclass") ||
			   !matches(*argv, "dsfield")) {
			__u32 uval;

			NEXT_ARG();
			if (strcmp(*argv, "inherit") != 0) {
				if (rtnl_dsfield_a2n(&uval, *argv))
					invarg("bad TOS value", *argv);
				tos = uval;
			} else
				tos = 1;
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
			encapflags |= ~TUNNEL_ENCAP_FLAG_CSUM6;
		} else if (strcmp(*argv, "encap-remcsum") == 0) {
			encapflags |= TUNNEL_ENCAP_FLAG_REMCSUM;
		} else if (strcmp(*argv, "noencap-remcsum") == 0) {
			encapflags |= ~TUNNEL_ENCAP_FLAG_REMCSUM;
		} else if (strcmp(*argv, "external") == 0) {
			metadata = 1;
		} else if (strcmp(*argv, "ignore-df") == 0) {
			ignore_df = 1;
		} else if (strcmp(*argv, "noignore-df") == 0) {
			/*
			 *only the lsb is significant, use 2 for presence
			 */
			ignore_df = 2;
		} else if (strcmp(*argv, "fwmark") == 0) {
			NEXT_ARG();
			if (get_u32(&fwmark, *argv, 0))
				invarg("invalid fwmark\n", *argv);
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

	if (!ikey && IN_MULTICAST(ntohl(daddr))) {
		ikey = daddr;
		iflags |= GRE_KEY;
	}
	if (!okey && IN_MULTICAST(ntohl(daddr))) {
		okey = daddr;
		oflags |= GRE_KEY;
	}
	if (IN_MULTICAST(ntohl(daddr)) && !saddr) {
		fprintf(stderr, "A broadcast tunnel requires a source address.\n");
		return -1;
	}

	if (!metadata) {
		addattr32(n, 1024, IFLA_GRE_IKEY, ikey);
		addattr32(n, 1024, IFLA_GRE_OKEY, okey);
		addattr_l(n, 1024, IFLA_GRE_IFLAGS, &iflags, 2);
		addattr_l(n, 1024, IFLA_GRE_OFLAGS, &oflags, 2);
		addattr_l(n, 1024, IFLA_GRE_LOCAL, &saddr, 4);
		addattr_l(n, 1024, IFLA_GRE_REMOTE, &daddr, 4);
		addattr_l(n, 1024, IFLA_GRE_PMTUDISC, &pmtudisc, 1);
		if (link)
			addattr32(n, 1024, IFLA_GRE_LINK, link);
		addattr_l(n, 1024, IFLA_GRE_TTL, &ttl, 1);
		addattr_l(n, 1024, IFLA_GRE_TOS, &tos, 1);
		addattr32(n, 1024, IFLA_GRE_FWMARK, fwmark);
		if (erspan_idx != 0)
			addattr32(n, 1024, IFLA_GRE_ERSPAN_INDEX, erspan_idx);
	} else {
		addattr_l(n, 1024, IFLA_GRE_COLLECT_METADATA, NULL, 0);
	}

	addattr16(n, 1024, IFLA_GRE_ENCAP_TYPE, encaptype);
	addattr16(n, 1024, IFLA_GRE_ENCAP_FLAGS, encapflags);
	addattr16(n, 1024, IFLA_GRE_ENCAP_SPORT, htons(encapsport));
	addattr16(n, 1024, IFLA_GRE_ENCAP_DPORT, htons(encapdport));

	if (ignore_df)
		addattr8(n, 1024, IFLA_GRE_IGNORE_DF, ignore_df & 1);

	return 0;
}

static void gre_print_direct_opt(FILE *f, struct rtattr *tb[])
{
	char s2[64];
	const char *local = "any";
	const char *remote = "any";
	unsigned int iflags = 0;
	unsigned int oflags = 0;

	if (tb[IFLA_GRE_REMOTE]) {
		unsigned int addr = rta_getattr_u32(tb[IFLA_GRE_REMOTE]);

		if (addr)
			remote = format_host(AF_INET, 4, &addr);
	}

	print_string(PRINT_ANY, "remote", "remote %s ", remote);

	if (tb[IFLA_GRE_LOCAL]) {
		unsigned int addr = rta_getattr_u32(tb[IFLA_GRE_LOCAL]);

		if (addr)
			local = format_host(AF_INET, 4, &addr);
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
			print_int(PRINT_ANY, "ttl", "ttl %d ", ttl);
		else
			print_int(PRINT_JSON, "ttl", NULL, ttl);
	} else {
		print_string(PRINT_FP, NULL, "ttl %s ", "inherit");
	}

	if (tb[IFLA_GRE_TOS] && rta_getattr_u8(tb[IFLA_GRE_TOS])) {
		int tos = rta_getattr_u8(tb[IFLA_GRE_TOS]);

		if (is_json_context()) {
			SPRINT_BUF(b1);

			snprintf(b1, sizeof(b1), "0x%x", tos);
			print_string(PRINT_JSON, "tos", NULL, b1);
		} else {
			fputs("tos ", f);
			if (tos == 1)
				fputs("inherit ", f);
			else
				fprintf(f, "0x%x ", tos);
		}
	}

	if (tb[IFLA_GRE_PMTUDISC]) {
		if (!rta_getattr_u8(tb[IFLA_GRE_PMTUDISC]))
			print_bool(PRINT_ANY, "pmtudisc", "nopmtudisc ", false);
		else
			print_bool(PRINT_JSON, "pmtudisc", NULL, true);
	}

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

	if (tb[IFLA_GRE_FWMARK]) {
		__u32 fwmark = rta_getattr_u32(tb[IFLA_GRE_FWMARK]);

		if (fwmark) {
			snprintf(s2, sizeof(s2), "0x%x", fwmark);

			print_string(PRINT_ANY, "fwmark", "fwmark %s ", s2);
		}
	}
}

static void gre_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	if (!tb)
		return;

	if (!tb[IFLA_GRE_COLLECT_METADATA])
		gre_print_direct_opt(f, tb);
	else
		print_bool(PRINT_ANY, "external", "external ", true);

	if (tb[IFLA_GRE_IGNORE_DF] && rta_getattr_u8(tb[IFLA_GRE_IGNORE_DF]))
		print_bool(PRINT_ANY, "ignore_df", "ignore-df ", true);

	if (tb[IFLA_GRE_ERSPAN_INDEX]) {
		__u32 erspan_idx = rta_getattr_u32(tb[IFLA_GRE_ERSPAN_INDEX]);

		fprintf(f, "erspan_index %u ", erspan_idx);
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
			print_null(PRINT_ANY, "type", "%s ", "unknown");
			break;
		}

		if (is_json_context()) {
			print_uint(PRINT_JSON,
				   "sport",
				   NULL,
				   sport ? ntohs(sport) : 0);
			print_uint(PRINT_JSON, "dport", NULL, ntohs(dport));

			print_bool(PRINT_JSON,
				   "csum",
				   NULL,
				   flags & TUNNEL_ENCAP_FLAG_CSUM);

			print_bool(PRINT_JSON,
				   "csum6",
				   NULL,
				   flags & TUNNEL_ENCAP_FLAG_CSUM6);

			print_bool(PRINT_JSON,
				   "remcsum",
				   NULL,
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

struct link_util gre_link_util = {
	.id = "gre",
	.maxattr = IFLA_GRE_MAX,
	.parse_opt = gre_parse_opt,
	.print_opt = gre_print_opt,
	.print_help = gre_print_help,
};

struct link_util gretap_link_util = {
	.id = "gretap",
	.maxattr = IFLA_GRE_MAX,
	.parse_opt = gre_parse_opt,
	.print_opt = gre_print_opt,
	.print_help = gre_print_help,
};

struct link_util erspan_link_util = {
	.id = "erspan",
	.maxattr = IFLA_GRE_MAX,
	.parse_opt = gre_parse_opt,
	.print_opt = gre_print_opt,
	.print_help = gre_print_help,
};
