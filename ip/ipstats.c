// SPDX-License-Identifier: GPL-2.0+
#include "utils.h"
#include "ip_common.h"

static int do_help(void)
{
	fprintf(stderr,
		"Usage: ip stats help\n"
		);

	return 0;
}

int do_ipstats(int argc, char **argv)
{
	int rc;

	if (argc == 0) {
		do_help();
		rc = -1;
	} else if (strcmp(*argv, "help") == 0) {
		do_help();
		rc = 0;
	} else {
		fprintf(stderr, "Command \"%s\" is unknown, try \"ip stats help\".\n",
			*argv);
		rc = -1;
	}

	return rc;
}
