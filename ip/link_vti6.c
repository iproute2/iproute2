/*
 * link_vti6.c	VTI driver module
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Herbert Xu <herbert@gondor.apana.org.au>
 *		Saurabh Mohan <saurabh.mohan@vyatta.com> Modified link_gre.c for VTI
 *		Steffen Klassert <steffen.klassert@secunet.com> Modified link_vti.c for IPv6
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
		"Usage: ... vti6 [ remote ADDR ]\n"
		"                [ local ADDR ]\n"
		"                [ [i|o]key KEY ]\n"
		"                [ dev PHYS_DEV ]\n"
		"                [ fwmark MARK ]\n"
		"\n"
		"Where: ADDR := { IPV6_ADDRESS }\n"
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

static int vti6_parse_opt(struct link_util *lu, int argc, char **argv,
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
	struct rtattr *vtiinfo[IFLA_VTI_MAX + 1];
	struct in6_addr saddr = IN6ADDR_ANY_INIT;
	struct in6_addr daddr = IN6ADDR_ANY_INIT;
	__be32 ikey = 0;
	__be32 okey = 0;
	unsigned int link = 0;
	__u32 fwmark = 0;
	int len;

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

		parse_rtattr_nested(vtiinfo, IFLA_VTI_MAX,
				    linkinfo[IFLA_INFO_DATA]);

		if (vtiinfo[IFLA_VTI_IKEY])
			ikey = rta_getattr_u32(vtiinfo[IFLA_VTI_IKEY]);

		if (vtiinfo[IFLA_VTI_OKEY])
			okey = rta_getattr_u32(vtiinfo[IFLA_VTI_OKEY]);

		if (vtiinfo[IFLA_VTI_LOCAL])
			memcpy(&saddr, RTA_DATA(vtiinfo[IFLA_VTI_LOCAL]), sizeof(saddr));

		if (vtiinfo[IFLA_VTI_REMOTE])
			memcpy(&daddr, RTA_DATA(vtiinfo[IFLA_VTI_REMOTE]), sizeof(daddr));

		if (vtiinfo[IFLA_VTI_LINK])
			link = rta_getattr_u8(vtiinfo[IFLA_VTI_LINK]);

		if (vtiinfo[IFLA_VTI_FWMARK])
			fwmark = rta_getattr_u32(vtiinfo[IFLA_VTI_FWMARK]);

		free(answer);
	}

	while (argc > 0) {
		if (!matches(*argv, "key")) {
			NEXT_ARG();
			ikey = okey = tnl_parse_key("key", *argv);
		} else if (!matches(*argv, "ikey")) {
			NEXT_ARG();
			ikey = tnl_parse_key("ikey", *argv);
		} else if (!matches(*argv, "okey")) {
			NEXT_ARG();
			okey = tnl_parse_key("okey", *argv);
		} else if (!matches(*argv, "remote")) {
			inet_prefix addr;

			NEXT_ARG();
			get_addr(&addr, *argv, AF_INET6);
			memcpy(&daddr, addr.data, sizeof(daddr));
		} else if (!matches(*argv, "local")) {
			inet_prefix addr;

			NEXT_ARG();
			get_addr(&addr, *argv, AF_INET6);
			memcpy(&saddr, addr.data, sizeof(saddr));
		} else if (!matches(*argv, "dev")) {
			NEXT_ARG();
			link = ll_name_to_index(*argv);
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
	addattr_l(n, 1024, IFLA_VTI_LOCAL, &saddr, sizeof(saddr));
	addattr_l(n, 1024, IFLA_VTI_REMOTE, &daddr, sizeof(daddr));
	addattr32(n, 1024, IFLA_VTI_FWMARK, fwmark);
	if (link)
		addattr32(n, 1024, IFLA_VTI_LINK, link);

	return 0;
}

static void vti6_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	const char *local = "any";
	const char *remote = "any";
	struct in6_addr saddr;
	struct in6_addr daddr;
	char s2[64];

	if (!tb)
		return;

	if (tb[IFLA_VTI_REMOTE]) {
		memcpy(&daddr, RTA_DATA(tb[IFLA_VTI_REMOTE]), sizeof(daddr));

		remote = format_host(AF_INET6, 16, &daddr);
	}

	print_string(PRINT_ANY, "remote", "remote %s ", remote);

	if (tb[IFLA_VTI_LOCAL]) {
		memcpy(&saddr, RTA_DATA(tb[IFLA_VTI_LOCAL]), sizeof(saddr));

		local = format_host(AF_INET6, 16, &saddr);
	}

	print_string(PRINT_ANY, "local", "local %s ", local);

	if (tb[IFLA_VTI_LINK]) {
		unsigned int link = rta_getattr_u32(tb[IFLA_VTI_LINK]);

		if (link) {
			print_string(PRINT_ANY, "link", "dev %s ",
				     ll_index_to_name(link));
		}
	}

	if (tb[IFLA_VTI_IKEY]) {
		struct rtattr *rta = tb[IFLA_VTI_IKEY];
		__u32 key = rta_getattr_u32(rta);

		if (key && inet_ntop(AF_INET, RTA_DATA(rta), s2, sizeof(s2)))
			print_string(PRINT_ANY, "ikey", "ikey %s ", s2);
	}

	if (tb[IFLA_VTI_OKEY]) {
		struct rtattr *rta = tb[IFLA_VTI_OKEY];
		__u32 key = rta_getattr_u32(rta);

		if (key && inet_ntop(AF_INET, RTA_DATA(rta), s2, sizeof(s2)))
			print_string(PRINT_ANY, "okey", "okey %s ", s2);
	}

	if (tb[IFLA_VTI_FWMARK]) {
		__u32 fwmark = rta_getattr_u32(tb[IFLA_VTI_FWMARK]);

		if (fwmark) {
			print_0xhex(PRINT_ANY,
				    "fwmark", "fwmark 0x%x ", fwmark);
		}
	}
}

static void vti6_print_help(struct link_util *lu, int argc, char **argv,
	FILE *f)
{
	print_usage(f);
}

struct link_util vti6_link_util = {
	.id = "vti6",
	.maxattr = IFLA_VTI_MAX,
	.parse_opt = vti6_parse_opt,
	.print_opt = vti6_print_opt,
	.print_help = vti6_print_help,
};
