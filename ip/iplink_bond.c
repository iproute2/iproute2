/*
 * iplink_bond.c	Bonding device support
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jiri Pirko <jiri@resnulli.us>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <net/if.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... bond [ mode BONDMODE ] [ active_slave SLAVE_DEV ]\n"
		"                [ clear_active_slave ]\n"
		"\n"
		"BONDMODE := 0-6\n"
	);
}

static int bond_parse_opt(struct link_util *lu, int argc, char **argv,
			  struct nlmsghdr *n)
{
	__u8 mode;
	unsigned ifindex;

	while (argc > 0) {
		if (matches(*argv, "mode") == 0) {
			NEXT_ARG();
			if (get_u8(&mode, *argv, 0)) {
				invarg("mode %s is invalid", *argv);
				return -1;
			}
			addattr8(n, 1024, IFLA_BOND_MODE, mode);
		} else if (matches(*argv, "active_slave") == 0) {
			NEXT_ARG();
			ifindex = if_nametoindex(*argv);
			if (!ifindex)
				return -1;
			addattr32(n, 1024, IFLA_BOND_ACTIVE_SLAVE, ifindex);
		} else if (matches(*argv, "clear_active_slave") == 0) {
			addattr32(n, 1024, IFLA_BOND_ACTIVE_SLAVE, 0);
		} else {
			fprintf(stderr, "bond: unknown command \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--, argv++;
	}

	return 0;
}

static void bond_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	unsigned ifindex;

	if (!tb)
		return;

	if (tb[IFLA_BOND_MODE])
		fprintf(f, "mode %u ", rta_getattr_u8(tb[IFLA_BOND_MODE]));

	if (tb[IFLA_BOND_ACTIVE_SLAVE] &&
	    (ifindex = rta_getattr_u32(tb[IFLA_BOND_ACTIVE_SLAVE]))) {
		char buf[IFNAMSIZ];
		const char *n = if_indextoname(ifindex, buf);

		if (n)
			fprintf(f, "active_slave %s ", n);
		else
			fprintf(f, "active_slave %u ", ifindex);
	}
}

struct link_util bond_link_util = {
	.id		= "bond",
	.maxattr	= IFLA_BOND_MAX,
	.parse_opt	= bond_parse_opt,
	.print_opt	= bond_print_opt,
};
