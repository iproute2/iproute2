/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * q_ingress.c             INGRESS.
 *
 * Authors:    J Hadi Salim
 */

#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... ingress\n");
}

static int ingress_parse_opt(const struct qdisc_util *qu, int argc, char **argv,
			     struct nlmsghdr *n, const char *dev)
{
	while (argc > 0) {
		if (strcmp(*argv, "handle") == 0) {
			NEXT_ARG();
			argc--; argv++;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
	}

	return 0;
}

static int ingress_print_opt(const struct qdisc_util *qu, FILE *f,
			     struct rtattr *opt)
{
	print_string(PRINT_FP, NULL, "---------------- ", NULL);
	return 0;
}

struct qdisc_util ingress_qdisc_util = {
	.id		= "ingress",
	.parse_qopt	= ingress_parse_opt,
	.print_qopt	= ingress_print_opt,
};
