/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * tc_stab.c		"tc qdisc ... stab *".
 *
 * Authors:	Jussi Kivilinna, <jussi.kivilinna@mbnet.fi>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <malloc.h>

#include "utils.h"
#include "tc_util.h"
#include "tc_core.h"
#include "tc_common.h"

static void stab_help(void)
{
	fprintf(stderr,
		"Usage: ... stab [ mtu BYTES ] [ tsize SLOTS ] [ mpu BYTES ]\n"
		"                [ overhead BYTES ] [ linklayer TYPE ] ...\n"
		"   mtu       : max packet size we create rate map for {2047}\n"
		"   tsize     : how many slots should size table have {512}\n"
		"   mpu       : minimum packet size used in rate computations\n"
		"   overhead  : per-packet size overhead used in rate computations\n"
		"   linklayer : adapting to a linklayer e.g. atm\n"
		"Example: ... stab overhead 20 linklayer atm\n");

}

int check_size_table_opts(struct tc_sizespec *s)
{
	return s->linklayer >= LINKLAYER_ETHERNET || s->mpu != 0 ||
							s->overhead != 0;
}

int parse_size_table(int *argcp, char ***argvp, struct tc_sizespec *sp)
{
	char **argv = *argvp;
	int argc = *argcp;
	struct tc_sizespec s = {};

	NEXT_ARG();
	if (matches(*argv, "help") == 0) {
		stab_help();
		return -1;
	}
	while (argc > 0) {
		if (matches(*argv, "mtu") == 0) {
			NEXT_ARG();
			if (s.mtu)
				duparg("mtu", *argv);
			if (get_u32(&s.mtu, *argv, 10))
				invarg("mtu", "invalid mtu");
		} else if (matches(*argv, "mpu") == 0) {
			NEXT_ARG();
			if (s.mpu)
				duparg("mpu", *argv);
			if (get_u32(&s.mpu, *argv, 10))
				invarg("mpu", "invalid mpu");
		} else if (matches(*argv, "overhead") == 0) {
			NEXT_ARG();
			if (s.overhead)
				duparg("overhead", *argv);
			if (get_integer(&s.overhead, *argv, 10))
				invarg("overhead", "invalid overhead");
		} else if (matches(*argv, "tsize") == 0) {
			NEXT_ARG();
			if (s.tsize)
				duparg("tsize", *argv);
			if (get_u32(&s.tsize, *argv, 10))
				invarg("tsize", "invalid table size");
		} else if (matches(*argv, "linklayer") == 0) {
			NEXT_ARG();
			if (s.linklayer != LINKLAYER_UNSPEC)
				duparg("linklayer", *argv);
			if (get_linklayer(&s.linklayer, *argv))
				invarg("linklayer", "invalid linklayer");
		} else
			break;
		argc--; argv++;
	}

	if (!check_size_table_opts(&s))
		return -1;

	*sp = s;
	*argvp = argv;
	*argcp = argc;
	return 0;
}

void print_size_table(struct rtattr *rta)
{
	struct rtattr *tb[TCA_STAB_MAX + 1];

	SPRINT_BUF(b1);

	parse_rtattr_nested(tb, TCA_STAB_MAX, rta);

	if (tb[TCA_STAB_BASE]) {
		struct tc_sizespec s = {0};

		memcpy(&s, RTA_DATA(tb[TCA_STAB_BASE]),
				MIN(RTA_PAYLOAD(tb[TCA_STAB_BASE]), sizeof(s)));

		open_json_object("stab");
		print_string(PRINT_FP, NULL, " ", NULL);

		if (s.linklayer)
			print_string(PRINT_ANY, "linklayer",
				     "linklayer %s ",
				     sprint_linklayer(s.linklayer, b1));
		if (s.overhead)
			print_int(PRINT_ANY, "overhead",
				  "overhead %d ", s.overhead);
		if (s.mpu)
			print_uint(PRINT_ANY, "mpu",
				   "mpu %u ", s.mpu);
		if (s.mtu)
			print_uint(PRINT_ANY, "mtu",
				   "mtu %u ", s.mtu);
		if (s.tsize)
			print_uint(PRINT_ANY, "tsize",
				   "tsize %u ", s.tsize);
		close_json_object();
	}
}
