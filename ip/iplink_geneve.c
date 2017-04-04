/*
 * iplink_geneve.c	GENEVE device support
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     John W. Linville <linville@tuxdriver.com>
 */

#include <stdio.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

static void print_explain(FILE *f)
{
	fprintf(f,
		"Usage: ... geneve id VNI\n"
		"                  remote ADDR\n"
		"                  [ ttl TTL ]\n"
		"                  [ tos TOS ]\n"
		"                  [ flowlabel LABEL ]\n"
		"                  [ dstport PORT ]\n"
		"                  [ [no]external ]\n"
		"                  [ [no]udpcsum ]\n"
		"                  [ [no]udp6zerocsumtx ]\n"
		"                  [ [no]udp6zerocsumrx ]\n"
		"\n"
		"Where: VNI   := 0-16777215\n"
		"       ADDR  := IP_ADDRESS\n"
		"       TOS   := { NUMBER | inherit }\n"
		"       TTL   := { 1..255 | inherit }\n"
		"       LABEL := 0-1048575\n"
	);
}

static void explain(void)
{
	print_explain(stderr);
}

static int geneve_parse_opt(struct link_util *lu, int argc, char **argv,
			  struct nlmsghdr *n)
{
	__u32 vni = 0;
	int vni_set = 0;
	__u32 daddr = 0;
	struct in6_addr daddr6 = IN6ADDR_ANY_INIT;
	__u32 label = 0;
	__u8 ttl = 0;
	__u8 tos = 0;
	__u16 dstport = 0;
	bool metadata = 0;
	__u8 udpcsum = 0;
	bool udpcsum_set = false;
	__u8 udp6zerocsumtx = 0;
	bool udp6zerocsumtx_set = false;
	__u8 udp6zerocsumrx = 0;
	bool udp6zerocsumrx_set = false;

	while (argc > 0) {
		if (!matches(*argv, "id") ||
		    !matches(*argv, "vni")) {
			NEXT_ARG();
			if (get_u32(&vni, *argv, 0) ||
			    vni >= 1u << 24)
				invarg("invalid id", *argv);
			vni_set = 1;
		} else if (!matches(*argv, "remote")) {
			NEXT_ARG();
			if (!inet_get_addr(*argv, &daddr, &daddr6)) {
				fprintf(stderr, "Invalid address \"%s\"\n", *argv);
				return -1;
			}
			if (IN6_IS_ADDR_MULTICAST(&daddr6) || IN_MULTICAST(ntohl(daddr)))
				invarg("invalid remote address", *argv);
		} else if (!matches(*argv, "ttl") ||
			   !matches(*argv, "hoplimit")) {
			unsigned int uval;

			NEXT_ARG();
			if (strcmp(*argv, "inherit") != 0) {
				if (get_unsigned(&uval, *argv, 0))
					invarg("invalid TTL", *argv);
				if (uval > 255)
					invarg("TTL must be <= 255", *argv);
				ttl = uval;
			}
		} else if (!matches(*argv, "tos") ||
			   !matches(*argv, "dsfield")) {
			__u32 uval;

			NEXT_ARG();
			if (strcmp(*argv, "inherit") != 0) {
				if (rtnl_dsfield_a2n(&uval, *argv))
					invarg("bad TOS value", *argv);
				tos = uval;
			} else
				tos = 1;
		} else if (!matches(*argv, "label") ||
			   !matches(*argv, "flowlabel")) {
			__u32 uval;

			NEXT_ARG();
			if (get_u32(&uval, *argv, 0) ||
			    (uval & ~LABEL_MAX_MASK))
				invarg("invalid flowlabel", *argv);
			label = htonl(uval);
		} else if (!matches(*argv, "dstport")) {
			NEXT_ARG();
			if (get_u16(&dstport, *argv, 0))
				invarg("dstport", *argv);
		} else if (!matches(*argv, "external")) {
			metadata = true;
		} else if (!matches(*argv, "noexternal")) {
			metadata = false;
		} else if (!matches(*argv, "udpcsum")) {
			udpcsum = 1;
			udpcsum_set = true;
		} else if (!matches(*argv, "noudpcsum")) {
			udpcsum = 0;
			udpcsum_set = true;
		} else if (!matches(*argv, "udp6zerocsumtx")) {
			udp6zerocsumtx = 1;
			udp6zerocsumtx_set = true;
		} else if (!matches(*argv, "noudp6zerocsumtx")) {
			udp6zerocsumtx = 0;
			udp6zerocsumtx_set = true;
		} else if (!matches(*argv, "udp6zerocsumrx")) {
			udp6zerocsumrx = 1;
			udp6zerocsumrx_set = true;
		} else if (!matches(*argv, "noudp6zerocsumrx")) {
			udp6zerocsumrx = 0;
			udp6zerocsumrx_set = true;
		} else if (matches(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "geneve: unknown command \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--, argv++;
	}

	if (metadata && vni_set) {
		fprintf(stderr, "geneve: both 'external' and vni cannot be specified\n");
		return -1;
	}

	if (!metadata) {
		/* parameter checking make sense only for full geneve tunnels */
		if (!vni_set) {
			fprintf(stderr, "geneve: missing virtual network identifier\n");
			return -1;
		}

		if (!daddr && IN6_IS_ADDR_UNSPECIFIED(&daddr6)) {
			fprintf(stderr, "geneve: remote link partner not specified\n");
			return -1;
		}
	}

	addattr32(n, 1024, IFLA_GENEVE_ID, vni);
	if (daddr)
		addattr_l(n, 1024, IFLA_GENEVE_REMOTE, &daddr, 4);
	if (!IN6_IS_ADDR_UNSPECIFIED(&daddr6))
		addattr_l(n, 1024, IFLA_GENEVE_REMOTE6, &daddr6, sizeof(struct in6_addr));
	addattr32(n, 1024, IFLA_GENEVE_LABEL, label);
	addattr8(n, 1024, IFLA_GENEVE_TTL, ttl);
	addattr8(n, 1024, IFLA_GENEVE_TOS, tos);
	if (dstport)
		addattr16(n, 1024, IFLA_GENEVE_PORT, htons(dstport));
	if (metadata)
		addattr(n, 1024, IFLA_GENEVE_COLLECT_METADATA);
	if (udpcsum_set)
		addattr8(n, 1024, IFLA_GENEVE_UDP_CSUM, udpcsum);
	if (udp6zerocsumtx_set)
		addattr8(n, 1024, IFLA_GENEVE_UDP_ZERO_CSUM6_TX, udp6zerocsumtx);
	if (udp6zerocsumrx_set)
		addattr8(n, 1024, IFLA_GENEVE_UDP_ZERO_CSUM6_RX, udp6zerocsumrx);

	return 0;
}

static void geneve_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	__u32 vni;
	__u8 tos;

	if (!tb)
		return;

	if (!tb[IFLA_GENEVE_ID] ||
	    RTA_PAYLOAD(tb[IFLA_GENEVE_ID]) < sizeof(__u32))
		return;

	vni = rta_getattr_u32(tb[IFLA_GENEVE_ID]);
	fprintf(f, "id %u ", vni);

	if (tb[IFLA_GENEVE_REMOTE]) {
		__be32 addr = rta_getattr_u32(tb[IFLA_GENEVE_REMOTE]);

		if (addr)
			fprintf(f, "remote %s ",
				format_host(AF_INET, 4, &addr));
	} else if (tb[IFLA_GENEVE_REMOTE6]) {
		struct in6_addr addr;

		memcpy(&addr, RTA_DATA(tb[IFLA_GENEVE_REMOTE6]), sizeof(struct in6_addr));
		if (!IN6_IS_ADDR_UNSPECIFIED(&addr)) {
			if (!IN6_IS_ADDR_MULTICAST(&addr))
				fprintf(f, "remote %s ",
					format_host(AF_INET6, sizeof(struct in6_addr), &addr));
		}
	}

	if (tb[IFLA_GENEVE_TTL]) {
		__u8 ttl = rta_getattr_u8(tb[IFLA_GENEVE_TTL]);

		if (ttl)
			fprintf(f, "ttl %d ", ttl);
	}

	if (tb[IFLA_GENEVE_TOS] &&
	    (tos = rta_getattr_u8(tb[IFLA_GENEVE_TOS]))) {
		if (tos == 1)
			fprintf(f, "tos inherit ");
		else
			fprintf(f, "tos %#x ", tos);
	}

	if (tb[IFLA_GENEVE_LABEL]) {
		__u32 label = rta_getattr_u32(tb[IFLA_GENEVE_LABEL]);

		if (label)
			fprintf(f, "flowlabel %#x ", ntohl(label));
	}

	if (tb[IFLA_GENEVE_PORT])
		fprintf(f, "dstport %u ",
			rta_getattr_be16(tb[IFLA_GENEVE_PORT]));

	if (tb[IFLA_GENEVE_COLLECT_METADATA])
		fputs("external ", f);

	if (tb[IFLA_GENEVE_UDP_CSUM]) {
		if (!rta_getattr_u8(tb[IFLA_GENEVE_UDP_CSUM]))
			fputs("no", f);
		fputs("udpcsum ", f);
	}

	if (tb[IFLA_GENEVE_UDP_ZERO_CSUM6_TX]) {
		if (!rta_getattr_u8(tb[IFLA_GENEVE_UDP_ZERO_CSUM6_TX]))
			fputs("no", f);
		fputs("udp6zerocsumtx ", f);
	}

	if (tb[IFLA_GENEVE_UDP_ZERO_CSUM6_RX]) {
		if (!rta_getattr_u8(tb[IFLA_GENEVE_UDP_ZERO_CSUM6_RX]))
			fputs("no", f);
		fputs("udp6zerocsumrx ", f);
	}
}

static void geneve_print_help(struct link_util *lu, int argc, char **argv,
	FILE *f)
{
	print_explain(f);
}

struct link_util geneve_link_util = {
	.id		= "geneve",
	.maxattr	= IFLA_GENEVE_MAX,
	.parse_opt	= geneve_parse_opt,
	.print_opt	= geneve_print_opt,
	.print_help	= geneve_print_help,
};
