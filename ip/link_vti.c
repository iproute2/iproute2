/*
 * link_vti.c	VTI driver module
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Herbert Xu <herbert@gondor.apana.org.au>
 *          Saurabh Mohan <saurabh.mohan@vyatta.com> Modified link_gre.c for VTI
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
		"Usage: ... vti [ remote ADDR ]\n"
		"               [ local ADDR ]\n"
		"               [ [i|o]key KEY ]\n"
		"               [ dev PHYS_DEV ]\n"
		"               [ fwmark MARK ]\n"
		"\n"
		"Where: ADDR := { IP_ADDRESS }\n"
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

static int vti_parse_opt(struct link_util *lu, int argc, char **argv,
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
	struct rtattr *vtiinfo[IFLA_VTI_MAX + 1];
	unsigned int ikey = 0;
	unsigned int okey = 0;
	unsigned int saddr = 0;
	unsigned int daddr = 0;
	unsigned int link = 0;
	unsigned int fwmark = 0;
	int len;

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

		parse_rtattr_nested(vtiinfo, IFLA_VTI_MAX,
				    linkinfo[IFLA_INFO_DATA]);

		if (vtiinfo[IFLA_VTI_IKEY])
			ikey = rta_getattr_u32(vtiinfo[IFLA_VTI_IKEY]);

		if (vtiinfo[IFLA_VTI_OKEY])
			okey = rta_getattr_u32(vtiinfo[IFLA_VTI_OKEY]);

		if (vtiinfo[IFLA_VTI_LOCAL])
			saddr = rta_getattr_u32(vtiinfo[IFLA_VTI_LOCAL]);

		if (vtiinfo[IFLA_VTI_REMOTE])
			daddr = rta_getattr_u32(vtiinfo[IFLA_VTI_REMOTE]);

		if (vtiinfo[IFLA_VTI_LINK])
			link = rta_getattr_u8(vtiinfo[IFLA_VTI_LINK]);

		if (vtiinfo[IFLA_VTI_FWMARK])
			fwmark = rta_getattr_u32(vtiinfo[IFLA_VTI_FWMARK]);
	}

	while (argc > 0) {
		if (!matches(*argv, "key")) {
			unsigned int uval;

			NEXT_ARG();
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
		} else if (!matches(*argv, "remote")) {
			NEXT_ARG();
			if (!strcmp(*argv, "any")) {
				fprintf(stderr, "invalid value for \"remote\": \"%s\"\n", *argv);
				exit(-1);
			} else {
				daddr = get_addr32(*argv);
			}
		} else if (!matches(*argv, "local")) {
			NEXT_ARG();
			if (!strcmp(*argv, "any")) {
				fprintf(stderr, "invalid value for \"local\": \"%s\"\n", *argv);
				exit(-1);
			} else {
				saddr = get_addr32(*argv);
			}
		} else if (!matches(*argv, "dev")) {
			NEXT_ARG();
			link = if_nametoindex(*argv);
			if (link == 0) {
				fprintf(stderr, "Cannot find device \"%s\"\n",
					*argv);
				exit(-1);
			}
		} else if (strcmp(*argv, "fwmark") == 0) {
			NEXT_ARG();
			if (get_u32(&fwmark, *argv, 0))
				invarg("invalid fwmark\n", *argv);
		} else
			usage();
		argc--; argv++;
	}

	addattr32(n, 1024, IFLA_VTI_IKEY, ikey);
	addattr32(n, 1024, IFLA_VTI_OKEY, okey);
	addattr_l(n, 1024, IFLA_VTI_LOCAL, &saddr, 4);
	addattr_l(n, 1024, IFLA_VTI_REMOTE, &daddr, 4);
	addattr32(n, 1024, IFLA_VTI_FWMARK, fwmark);
	if (link)
		addattr32(n, 1024, IFLA_VTI_LINK, link);

	return 0;
}

static void vti_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	const char *local = "any";
	const char *remote = "any";
	__u32 key;
	unsigned int link;
	char s2[IFNAMSIZ];

	if (!tb)
		return;

	if (tb[IFLA_VTI_REMOTE]) {
		unsigned int addr = rta_getattr_u32(tb[IFLA_VTI_REMOTE]);

		if (addr)
			remote = format_host(AF_INET, 4, &addr);
	}

	print_string(PRINT_ANY, "remote", "remote %s ", remote);

	if (tb[IFLA_VTI_LOCAL]) {
		unsigned int addr = rta_getattr_u32(tb[IFLA_VTI_LOCAL]);

		if (addr)
			local = format_host(AF_INET, 4, &addr);
	}

	print_string(PRINT_ANY, "local", "local %s ", local);

	if (tb[IFLA_VTI_LINK] &&
	    (link = rta_getattr_u32(tb[IFLA_VTI_LINK]))) {
		const char *n = if_indextoname(link, s2);

		if (n)
			print_string(PRINT_ANY, "link", "dev %s ", n);
		else
			print_uint(PRINT_ANY, "link_index", "dev %u ", link);
	}

	if (tb[IFLA_VTI_IKEY] &&
	    (key = rta_getattr_u32(tb[IFLA_VTI_IKEY])))
		print_0xhex(PRINT_ANY, "ikey", "ikey %#x ", ntohl(key));


	if (tb[IFLA_VTI_OKEY] &&
	    (key = rta_getattr_u32(tb[IFLA_VTI_OKEY])))
		print_0xhex(PRINT_ANY, "okey", "okey %#x ", ntohl(key));

	if (tb[IFLA_VTI_FWMARK]) {
		__u32 fwmark = rta_getattr_u32(tb[IFLA_VTI_FWMARK]);

		if (fwmark) {
			SPRINT_BUF(b1);

			snprintf(b1, sizeof(b1), "0x%x", fwmark);
			print_string(PRINT_ANY, "fwmark", "fwmark %s ", s2);
		}
	}
}

static void vti_print_help(struct link_util *lu, int argc, char **argv,
	FILE *f)
{
	print_usage(f);
}

struct link_util vti_link_util = {
	.id = "vti",
	.maxattr = IFLA_VTI_MAX,
	.parse_opt = vti_parse_opt,
	.print_opt = vti_print_opt,
	.print_help = vti_print_help,
};
