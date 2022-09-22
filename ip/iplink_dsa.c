/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iplink_dsa.c		DSA switch support
 */

#include "utils.h"
#include "ip_common.h"

static void print_usage(FILE *f)
{
	fprintf(f, "Usage: ... dsa [ conduit DEVICE ]\n");
}

static int dsa_parse_opt(struct link_util *lu, int argc, char **argv,
			 struct nlmsghdr *n)
{
	while (argc > 0) {
		if (strcmp(*argv, "conduit") == 0 ||
		    strcmp(*argv, "master") == 0) {
			__u32 ifindex;

			NEXT_ARG();
			ifindex = ll_name_to_index(*argv);
			if (!ifindex)
				invarg("Device does not exist\n", *argv);
			addattr_l(n, 1024, IFLA_DSA_MASTER, &ifindex, 4);
		} else if (strcmp(*argv, "help") == 0) {
			print_usage(stderr);
			return -1;
		} else {
			fprintf(stderr, "dsa: unknown command \"%s\"?\n", *argv);
			print_usage(stderr);
			return -1;
		}
		argc--;
		argv++;
	}

	return 0;
}

static void dsa_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	if (!tb)
		return;

	if (tb[IFLA_DSA_MASTER]) {
		__u32 conduit = rta_getattr_u32(tb[IFLA_DSA_MASTER]);

		print_string(PRINT_ANY,
			     "conduit", "conduit %s ",
			     ll_index_to_name(conduit));
	}
}

static void dsa_print_help(struct link_util *lu, int argc, char **argv,
			   FILE *f)
{
	print_usage(f);
}

struct link_util dsa_link_util = {
	.id		= "dsa",
	.maxattr	= IFLA_DSA_MAX,
	.parse_opt	= dsa_parse_opt,
	.print_opt	= dsa_print_opt,
	.print_help     = dsa_print_help,
};
