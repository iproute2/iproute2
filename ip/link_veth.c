/*
 * link_veth.c	veth driver module
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Pavel Emelianov <xemul@openvz.org>
 *
 */

#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "ip_common.h"
#include "veth.h"

#define ETH_ALEN	6

static void usage(void)
{
	printf("Usage: ip link add ... type veth "
			"[peer <peer-name>] [mac <mac>] [peer_mac <mac>]\n");
}

static int veth_parse_opt(struct link_util *lu, int argc, char **argv,
		struct nlmsghdr *hdr)
{
	__u8 mac[ETH_ALEN];

	for (; argc != 0; argv++, argc--) {
		if (strcmp(*argv, "peer") == 0) {
			argv++;
			argc--;
			if (argc == 0) {
				usage();
				return -1;
			}

			addattr_l(hdr, 1024, VETH_INFO_PEER,
					*argv, strlen(*argv));

			continue;
		}

		if (strcmp(*argv, "mac") == 0) {
			argv++;
			argc--;
			if (argc == 0) {
				usage();
				return -1;
			}

			if (hexstring_a2n(*argv, mac, sizeof(mac)) == NULL)
				return -1;

			addattr_l(hdr, 1024, VETH_INFO_MAC,
					mac, ETH_ALEN);
			continue;
		}

		if (strcmp(*argv, "peer_mac") == 0) {
			argv++;
			argc--;
			if (argc == 0) {
				usage();
				return -1;
			}

			if (hexstring_a2n(*argv, mac, sizeof(mac)) == NULL)
				return -1;

			addattr_l(hdr, 1024, VETH_INFO_PEER_MAC,
					mac, ETH_ALEN);
			continue;
		}

		usage();
		return -1;
	}

	return 0;
}

struct link_util veth_link_util = {
	.id = "veth",
	.parse_opt = veth_parse_opt,
};
