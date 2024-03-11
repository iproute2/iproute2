/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * q_mqprio.c	MQ prio qdisc
 *
 * Author:	John Fastabend, <john.r.fastabend@intel.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... mqprio	[num_tc NUMBER] [map P0 P1 ...]\n"
		"			[queues count1@offset1 count2@offset2 ...] "
		"[hw 1|0]\n"
		"			[fp FP0 FP1 FP2 ...]\n"
		"			[mode dcb|channel]\n"
		"			[shaper bw_rlimit SHAPER_PARAMS]\n"
		"Where: SHAPER_PARAMS := { min_rate MIN_RATE1 MIN_RATE2 ...|\n"
		"			  max_rate MAX_RATE1 MAX_RATE2 ... }\n");
}

static void add_tc_entries(struct nlmsghdr *n, __u32 fp[TC_QOPT_MAX_QUEUE],
			   int num_fp_entries)
{
	struct rtattr *l;
	__u32 tc;

	for (tc = 0; tc < num_fp_entries; tc++) {
		l = addattr_nest(n, 1024, TCA_MQPRIO_TC_ENTRY | NLA_F_NESTED);

		addattr32(n, 1024, TCA_MQPRIO_TC_ENTRY_INDEX, tc);
		addattr32(n, 1024, TCA_MQPRIO_TC_ENTRY_FP, fp[tc]);

		addattr_nest_end(n, l);
	}
}

static int mqprio_parse_opt(const struct qdisc_util *qu, int argc,
			    char **argv, struct nlmsghdr *n, const char *dev)
{
	int idx;
	struct tc_mqprio_qopt opt = {
		.num_tc = 8,
		.prio_tc_map = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 1, 1, 3, 3, 3, 3 },
		.hw = 1,
		.count = { },
		.offset = { },
	};
	__u64 min_rate64[TC_QOPT_MAX_QUEUE] = {0};
	__u64 max_rate64[TC_QOPT_MAX_QUEUE] = {0};
	__u16 shaper = TC_MQPRIO_SHAPER_DCB;
	__u32 fp[TC_QOPT_MAX_QUEUE] = { };
	__u16 mode = TC_MQPRIO_MODE_DCB;
	bool have_tc_entries = false;
	int num_fp_entries = 0;
	int cnt_off_pairs = 0;
	struct rtattr *tail;
	__u32 flags = 0;

	while (argc > 0) {
		idx = 0;
		if (strcmp(*argv, "num_tc") == 0) {
			NEXT_ARG();
			if (get_u8(&opt.num_tc, *argv, 10)) {
				fprintf(stderr, "Illegal \"num_tc\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "map") == 0) {
			while (idx < TC_QOPT_MAX_QUEUE && NEXT_ARG_OK()) {
				NEXT_ARG();
				if (get_u8(&opt.prio_tc_map[idx], *argv, 10)) {
					PREV_ARG();
					break;
				}
				idx++;
			}
			for ( ; idx < TC_QOPT_MAX_QUEUE; idx++)
				opt.prio_tc_map[idx] = 0;
		} else if (strcmp(*argv, "queues") == 0) {
			char *tmp, *tok;

			while (idx < TC_QOPT_MAX_QUEUE && NEXT_ARG_OK()) {
				NEXT_ARG();

				tmp = strdup(*argv);
				if (!tmp)
					break;

				tok = strtok(tmp, "@");
				if (get_u16(&opt.count[idx], tok, 10)) {
					free(tmp);
					PREV_ARG();
					break;
				}
				tok = strtok(NULL, "@");
				if (get_u16(&opt.offset[idx], tok, 10)) {
					free(tmp);
					PREV_ARG();
					break;
				}
				free(tmp);
				idx++;
				cnt_off_pairs++;
			}
		} else if (strcmp(*argv, "fp") == 0) {
			while (idx < TC_QOPT_MAX_QUEUE && NEXT_ARG_OK()) {
				NEXT_ARG();
				if (strcmp(*argv, "E") == 0) {
					fp[idx] = TC_FP_EXPRESS;
				} else if (strcmp(*argv, "P") == 0) {
					fp[idx] = TC_FP_PREEMPTIBLE;
				} else {
					PREV_ARG();
					break;
				}
				num_fp_entries++;
				idx++;
			}
			have_tc_entries = true;
		} else if (strcmp(*argv, "hw") == 0) {
			NEXT_ARG();
			if (get_u8(&opt.hw, *argv, 10)) {
				fprintf(stderr, "Illegal \"hw\"\n");
				return -1;
			}
			idx++;
		} else if (opt.hw && strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
			if (matches(*argv, "dcb") == 0) {
				mode = TC_MQPRIO_MODE_DCB;
			} else if (matches(*argv, "channel") == 0) {
				mode = TC_MQPRIO_MODE_CHANNEL;
			}  else {
				fprintf(stderr, "Illegal mode (%s)\n",
					*argv);
				return -1;
			}
			if (mode != TC_MQPRIO_MODE_DCB)
				flags |= TC_MQPRIO_F_MODE;
			idx++;
		} else if (opt.hw && strcmp(*argv, "shaper") == 0) {
			NEXT_ARG();
			if (matches(*argv, "dcb") == 0) {
				shaper = TC_MQPRIO_SHAPER_DCB;
			} else if (matches(*argv, "bw_rlimit") == 0) {
				shaper = TC_MQPRIO_SHAPER_BW_RATE;
				if (!NEXT_ARG_OK()) {
					fprintf(stderr, "Incomplete shaper arguments\n");
					return -1;
				}
			}  else {
				fprintf(stderr, "Illegal shaper (%s)\n",
					*argv);
				return -1;
			}
			if (shaper != TC_MQPRIO_SHAPER_DCB)
				flags |= TC_MQPRIO_F_SHAPER;
			idx++;
		} else if ((shaper == TC_MQPRIO_SHAPER_BW_RATE) &&
			   strcmp(*argv, "min_rate") == 0) {
			while (idx < TC_QOPT_MAX_QUEUE && NEXT_ARG_OK()) {
				NEXT_ARG();
				if (get_rate64(&min_rate64[idx], *argv)) {
					PREV_ARG();
					break;
				}
				idx++;
			}
			if (idx < opt.num_tc && !NEXT_ARG_OK()) {
				fprintf(stderr, "Incomplete arguments, min_rate values expected\n");
				return -1;
			}
			flags |= TC_MQPRIO_F_MIN_RATE;
		} else if ((shaper == TC_MQPRIO_SHAPER_BW_RATE) &&
			   strcmp(*argv, "max_rate") == 0) {
			while (idx < TC_QOPT_MAX_QUEUE && NEXT_ARG_OK()) {
				NEXT_ARG();
				if (get_rate64(&max_rate64[idx], *argv)) {
					PREV_ARG();
					break;
				}
				idx++;
			}
			if (idx < opt.num_tc && !NEXT_ARG_OK()) {
				fprintf(stderr, "Incomplete arguments, max_rate values expected\n");
				return -1;
			}
			flags |= TC_MQPRIO_F_MAX_RATE;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			invarg("unknown argument", *argv);
		}
		argc--; argv++;
	}

	if (cnt_off_pairs > opt.num_tc) {
		fprintf(stderr, "queues count/offset pair count %d can not be higher than given num_tc %d\n",
			cnt_off_pairs, opt.num_tc);
		return -1;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, &opt, sizeof(opt));

	if (flags & TC_MQPRIO_F_MODE)
		addattr_l(n, 1024, TCA_MQPRIO_MODE,
			  &mode, sizeof(mode));
	if (flags & TC_MQPRIO_F_SHAPER)
		addattr_l(n, 1024, TCA_MQPRIO_SHAPER,
			  &shaper, sizeof(shaper));

	if (have_tc_entries)
		add_tc_entries(n, fp, num_fp_entries);

	if (flags & TC_MQPRIO_F_MIN_RATE) {
		struct rtattr *start;

		start = addattr_nest(n, 1024,
				     TCA_MQPRIO_MIN_RATE64 | NLA_F_NESTED);

		for (idx = 0; idx < TC_QOPT_MAX_QUEUE; idx++)
			addattr_l(n, 1024, TCA_MQPRIO_MIN_RATE64,
				  &min_rate64[idx], sizeof(min_rate64[idx]));

		addattr_nest_end(n, start);
	}

	if (flags & TC_MQPRIO_F_MAX_RATE) {
		struct rtattr *start;

		start = addattr_nest(n, 1024,
				     TCA_MQPRIO_MAX_RATE64 | NLA_F_NESTED);

		for (idx = 0; idx < TC_QOPT_MAX_QUEUE; idx++)
			addattr_l(n, 1024, TCA_MQPRIO_MAX_RATE64,
				  &max_rate64[idx], sizeof(max_rate64[idx]));

		addattr_nest_end(n, start);
	}

	tail->rta_len = (void *)NLMSG_TAIL(n) - (void *)tail;

	return 0;
}

static void dump_tc_entry(struct rtattr *rta, __u32 fp[TC_QOPT_MAX_QUEUE],
			  int *max_tc_fp)
{
	struct rtattr *tb[TCA_MQPRIO_TC_ENTRY_MAX + 1];
	__u32 tc, val = 0;

	parse_rtattr_nested(tb, TCA_MQPRIO_TC_ENTRY_MAX, rta);

	if (!tb[TCA_MQPRIO_TC_ENTRY_INDEX]) {
		fprintf(stderr, "Missing tc entry index\n");
		return;
	}

	tc = rta_getattr_u32(tb[TCA_MQPRIO_TC_ENTRY_INDEX]);
	/* Prevent array out of bounds access */
	if (tc >= TC_QOPT_MAX_QUEUE) {
		fprintf(stderr, "Unexpected tc entry index %d\n", tc);
		return;
	}

	if (tb[TCA_MQPRIO_TC_ENTRY_FP]) {
		val = rta_getattr_u32(tb[TCA_MQPRIO_TC_ENTRY_FP]);
		fp[tc] = val;

		if (*max_tc_fp < (int)tc)
			*max_tc_fp = tc;
	}
}

static void dump_tc_entries(FILE *f, struct rtattr *opt, int len)
{
	__u32 fp[TC_QOPT_MAX_QUEUE] = {};
	int max_tc_fp = -1;
	struct rtattr *rta;
	int tc;

	for (rta = opt; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type != (TCA_MQPRIO_TC_ENTRY | NLA_F_NESTED))
			continue;

		dump_tc_entry(rta, fp, &max_tc_fp);
	}

	if (max_tc_fp >= 0) {
		open_json_array(PRINT_ANY,
				is_json_context() ? "fp" : "\n             fp:");
		for (tc = 0; tc <= max_tc_fp; tc++) {
			print_string(PRINT_ANY, NULL, " %s",
				     fp[tc] == TC_FP_PREEMPTIBLE ? "P" :
				     fp[tc] == TC_FP_EXPRESS ? "E" :
				     "?");
		}
		close_json_array(PRINT_ANY, "");

		print_nl();
	}
}

static int mqprio_print_opt(const struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	int i;
	struct tc_mqprio_qopt *qopt;
	__u64 min_rate64[TC_QOPT_MAX_QUEUE] = {0};
	__u64 max_rate64[TC_QOPT_MAX_QUEUE] = {0};
	int len;

	if (opt == NULL)
		return 0;

	len = RTA_PAYLOAD(opt) - RTA_ALIGN(sizeof(*qopt));
	if (len < 0) {
		fprintf(stderr, "options size error\n");
		return -1;
	}

	qopt = RTA_DATA(opt);

	print_uint(PRINT_ANY, "tc", "tc %u ", qopt->num_tc);
	open_json_array(PRINT_ANY, is_json_context() ? "map" : "map ");
	for (i = 0; i <= TC_PRIO_MAX; i++)
		print_uint(PRINT_ANY, NULL, "%u ", qopt->prio_tc_map[i]);
	close_json_array(PRINT_ANY, "");
	open_json_array(PRINT_ANY, is_json_context() ? "queues" : "\n             queues:");
	for (i = 0; i < qopt->num_tc; i++) {
		open_json_array(PRINT_JSON, NULL);
		print_uint(PRINT_ANY, NULL, "(%u:", qopt->offset[i]);
		print_uint(PRINT_ANY, NULL, "%u) ", qopt->offset[i] + qopt->count[i] - 1);
		close_json_array(PRINT_JSON, NULL);
	}
	close_json_array(PRINT_ANY, "");

	if (len > 0) {
		struct rtattr *tb[TCA_MQPRIO_MAX + 1];

		parse_rtattr(tb, TCA_MQPRIO_MAX,
			     RTA_DATA(opt) + RTA_ALIGN(sizeof(*qopt)),
			     len);

		if (tb[TCA_MQPRIO_MODE]) {
			__u16 *mode = RTA_DATA(tb[TCA_MQPRIO_MODE]);

			if (*mode == TC_MQPRIO_MODE_CHANNEL)
				print_string(PRINT_ANY, "mode", "\n             mode:%s", "channel");
		} else {
			print_string(PRINT_ANY, "mode", "\n             mode:%s", "dcb");
		}

		if (tb[TCA_MQPRIO_SHAPER]) {
			__u16 *shaper = RTA_DATA(tb[TCA_MQPRIO_SHAPER]);

			if (*shaper == TC_MQPRIO_SHAPER_BW_RATE)
				print_string(PRINT_ANY, "shaper", "\n             shaper:%s", "bw_rlimit");
		} else {
			print_string(PRINT_ANY, "shaper", "\n             shaper:%s", "dcb");
		}

		if (tb[TCA_MQPRIO_MIN_RATE64]) {
			struct rtattr *r;
			int rem = RTA_PAYLOAD(tb[TCA_MQPRIO_MIN_RATE64]);
			__u64 *min = min_rate64;

			for (r = RTA_DATA(tb[TCA_MQPRIO_MIN_RATE64]);
			     RTA_OK(r, rem); r = RTA_NEXT(r, rem)) {
				if (r->rta_type != TCA_MQPRIO_MIN_RATE64)
					return -1;
				*(min++) = rta_getattr_u64(r);
			}
			open_json_array(PRINT_ANY, is_json_context() ? "min_rate" : "	min_rate:");
			for (i = 0; i < qopt->num_tc; i++)
				tc_print_rate(PRINT_ANY, NULL, "%s ", min_rate64[i]);
			close_json_array(PRINT_ANY, "");
		}

		if (tb[TCA_MQPRIO_MAX_RATE64]) {
			struct rtattr *r;
			int rem = RTA_PAYLOAD(tb[TCA_MQPRIO_MAX_RATE64]);
			__u64 *max = max_rate64;

			for (r = RTA_DATA(tb[TCA_MQPRIO_MAX_RATE64]);
			     RTA_OK(r, rem); r = RTA_NEXT(r, rem)) {
				if (r->rta_type != TCA_MQPRIO_MAX_RATE64)
					return -1;
				*(max++) = rta_getattr_u64(r);
			}
			open_json_array(PRINT_ANY, is_json_context() ? "max_rate" : "	max_rate:");
			for (i = 0; i < qopt->num_tc; i++)
				tc_print_rate(PRINT_ANY, NULL, "%s ", max_rate64[i]);
			close_json_array(PRINT_ANY, "");
		}

		dump_tc_entries(f, RTA_DATA(opt) + RTA_ALIGN(sizeof(*qopt)), len);
	}

	return 0;
}

struct qdisc_util mqprio_qdisc_util = {
	.id		= "mqprio",
	.parse_qopt	= mqprio_parse_opt,
	.print_qopt	= mqprio_print_opt,
};
