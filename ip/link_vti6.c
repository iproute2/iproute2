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


static void usage(void) __attribute__((noreturn));
static void usage(void)
{
	fprintf(stderr, "Usage: ip link { add | set | change | replace | del } NAME\n");
	fprintf(stderr, "          type { vti6 } [ remote ADDR ] [ local ADDR ]\n");
	fprintf(stderr, "          [ [i|o]key KEY ]\n");
	fprintf(stderr, "          [ dev PHYS_DEV ]\n");
	fprintf(stderr, "          [ fwmark MARK ]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where: NAME := STRING\n");
	fprintf(stderr, "       ADDR := { IPV6_ADDRESS }\n");
	fprintf(stderr, "       KEY  := { DOTTED_QUAD | NUMBER }\n");
	fprintf(stderr, "       MARK := { 0x0..0xffffffff }\n");
	exit(-1);
}

static int vti6_parse_opt(struct link_util *lu, int argc, char **argv,
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
	struct in6_addr saddr = IN6ADDR_ANY_INIT;
	struct in6_addr daddr = IN6ADDR_ANY_INIT;
	unsigned int ikey = 0;
	unsigned int okey = 0;
	unsigned int link = 0;
	__u32 fwmark = 0;
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
			memcpy(&saddr, RTA_DATA(vtiinfo[IFLA_VTI_LOCAL]), sizeof(saddr));

		if (vtiinfo[IFLA_VTI_REMOTE])
			memcpy(&daddr, RTA_DATA(vtiinfo[IFLA_VTI_REMOTE]), sizeof(daddr));

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
				inet_prefix addr;

				get_prefix(&addr, *argv, AF_INET6);
				memcpy(&daddr, addr.data, addr.bytelen);
			}
		} else if (!matches(*argv, "local")) {
			NEXT_ARG();
			if (!strcmp(*argv, "any")) {
				fprintf(stderr, "invalid value for \"local\": \"%s\"\n", *argv);
				exit(-1);
			} else {
				inet_prefix addr;

				get_prefix(&addr, *argv, AF_INET6);
				memcpy(&saddr, addr.data, addr.bytelen);
			}
		} else if (!matches(*argv, "dev")) {
			NEXT_ARG();
			link = if_nametoindex(*argv);
			if (link == 0)
				exit(-1);
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

	if (memcmp(&saddr, &in6addr_any, sizeof(in6addr_any)))
	    addattr_l(n, 1024, IFLA_VTI_LOCAL, &saddr, sizeof(saddr));
	if (memcmp(&daddr, &in6addr_any, sizeof(in6addr_any)))
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
	unsigned int link;
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

	if (tb[IFLA_VTI_LINK] && (link = rta_getattr_u32(tb[IFLA_VTI_LINK]))) {
		const char *n = if_indextoname(link, s2);

		if (n)
			print_string(PRINT_ANY, "link", "dev %s ", n);
		else
			print_uint(PRINT_ANY, "link_index", "dev %u ", link);
	}

	if (tb[IFLA_VTI_IKEY]) {
		inet_ntop(AF_INET, RTA_DATA(tb[IFLA_VTI_IKEY]), s2, sizeof(s2));
		print_string(PRINT_ANY, "ikey", "ikey %s ", s2);
	}

	if (tb[IFLA_VTI_OKEY]) {
		inet_ntop(AF_INET, RTA_DATA(tb[IFLA_VTI_OKEY]), s2, sizeof(s2));
		print_string(PRINT_ANY, "okey", "okey %s ", s2);
	}

	if (tb[IFLA_VTI_FWMARK]) {
		__u32 fwmark = rta_getattr_u32(tb[IFLA_VTI_FWMARK]);

		if (fwmark) {
			snprintf(s2, sizeof(s2), "0x%x", fwmark);

			print_string(PRINT_ANY, "fwmark", "fwmark %s ", s2);
		}
	}
}

struct link_util vti6_link_util = {
	.id = "vti6",
	.maxattr = IFLA_VTI_MAX,
	.parse_opt = vti6_parse_opt,
	.print_opt = vti6_print_opt,
};
