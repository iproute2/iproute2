// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright (C) 2024 Nokia
 *
 * Author: Koen De Schepper <koen.de_schepper@nokia-bell-labs.com>
 * Author: Olga Albisser <olga@albisser.org>
 * Author: Henrik Steen <henrist@henrist.net>
 * Author: Olivier Tilmans <olivier.tilmans@nokia.com>
 * Author: Chia-Yu Chang <chia-yu.chang@nokia-bell-labs.com>
 *
 * DualPI Improved with a Square (dualpi2):
 * - Supports congestion controls that comply with the Prague requirements
 *   in RFC9331 (e.g. TCP-Prague)
 * - Supports coupled dual-queue with PI2 as defined in RFC9332
 * - Supports ECN L4S-identifier (IP.ECN==0b*1)
 *
 * note: Although DCTCP and BBRv3 can use shallow-threshold ECN marks,
 *   they do not meet the 'Prague L4S Requirements' listed in RFC 9331
 *   Section 4, so they can only be used with DualPI2 in a datacenter
 *   context.
 *
 * References:
 * - RFC9332: https://datatracker.ietf.org/doc/html/rfc9332
 * - De Schepper, Koen, et al. "PI 2: A linearized AQM for both classic and
 *   scalable TCP."  in proc. ACM CoNEXT'16, 2016.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "utils.h"
#include "tc_util.h"

#define MAX_PROB ((uint32_t)(~0U))
#define DEFAULT_ALPHA_BETA ((uint32_t)(~0U))
#define ALPHA_BETA_MAX ((2 << 23) - 1) /* see net/sched/sch_dualpi2.c */
#define ALPHA_BETA_SCALE (1 << 8)
#define RTT_TYP_TO_MAX 6

static const char *get_credit_queue(int credit)
{
	return credit > 0 ? "C-queue" : "L-queue";
}

static const char *get_ecn_type(uint8_t ect)
{
	switch (ect & TC_DUALPI2_ECN_MASK_ANY_ECT) {
	case TC_DUALPI2_ECN_MASK_L4S_ECT: return "l4s_ect";
	case TC_DUALPI2_ECN_MASK_CLA_ECT:
	case TC_DUALPI2_ECN_MASK_ANY_ECT: return "any_ect";
	default:
		fprintf(stderr,
			"Warning: Unexpected ecn type %u!\n", ect);
		return "";
	}
}

static const char *get_ecn_type_json(uint8_t ect)
{
	switch (ect & TC_DUALPI2_ECN_MASK_ANY_ECT) {
	case TC_DUALPI2_ECN_MASK_L4S_ECT: return "l4s-ect";
	case TC_DUALPI2_ECN_MASK_CLA_ECT:
	case TC_DUALPI2_ECN_MASK_ANY_ECT: return "any-ect";
	default:
		fprintf(stderr,
			"Warning: Unexpected ecn type %u!\n", ect);
		return "";
	}
}

static void explain(void)
{
	fprintf(stderr, "Usage: ... dualpi2\n");
	fprintf(stderr, "               [limit PACKETS]\n");
	fprintf(stderr, "               [memlimit BYTES]\n");
	fprintf(stderr, "               [coupling_factor NUMBER]\n");
	fprintf(stderr, "               [step_thresh TIME|PACKETS]\n");
	fprintf(stderr, "               [min_qlen_step PACKETS]\n");
	fprintf(stderr, "               [drop_on_overload|overflow]\n");
	fprintf(stderr, "               [drop_enqueue|drop_dequeue]\n");
	fprintf(stderr, "               [classic_protection PERCENTAGE]\n");
	fprintf(stderr, "               [max_rtt TIME [typical_rtt TIME]]\n");
	fprintf(stderr, "               [target TIME] [tupdate TIME]\n");
	fprintf(stderr, "               [alpha ALPHA] [beta BETA]\n");
	fprintf(stderr, "               [split_gso|no_split_gso]\n");
}

static int get_packets(uint32_t *val, const char *arg)
{
	const char *suffixes[] = {"p", "pkt", "pkts", "packet", "packets"};
	size_t suffix_cnt = sizeof(suffixes) / sizeof(suffixes[0]);
	unsigned long res;
	char *ptr;
	size_t i;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, 10);
	if (!ptr || ptr == arg)
		return -1;
	for (i = 0; i < suffix_cnt; i++) {
		if (strcmp(ptr, suffixes[i]) == 0)
			break;
	}
	if (i == suffix_cnt)
		return -1;
	if (res == ULONG_MAX && errno == ERANGE)
		return -1;
	if (res > 0xFFFFFFFFUL)
		return -1;
	*val = res;

	return 0;
}

static int parse_alpha_beta(const char *name, char *argv, uint32_t *field)
{
	float field_f;

	if (get_float_min_max(&field_f, argv, 0.0, ALPHA_BETA_MAX)) {
		fprintf(stderr, "Illegal \"%s\"\n", name);
		return -1;
	} else if (field_f < 1.0f / ALPHA_BETA_SCALE)
		fprintf(stderr,
			"Warning: \"%s\" is too small and will be rounded to zero.\n",
			name);
	*field = (uint32_t)(field_f * ALPHA_BETA_SCALE);

	return 0;
}

static int try_get_percent(int *val, const char *arg)
{
	double per;

	if (parse_percent(&per, arg))
		return -1;

	*val = rint(per * 100);

	return 0;
}

static int dualpi2_parse_opt(const struct qdisc_util *qu, int argc,
			     char **argv, struct nlmsghdr *n, const char *dev)
{
	uint8_t drop_overload = __TCA_DUALPI2_DROP_OVERLOAD_MAX;
	uint8_t drop_early = __TCA_DUALPI2_DROP_EARLY_MAX;
	uint8_t split_gso = __TCA_DUALPI2_SPLIT_GSO_MAX;
	uint32_t alpha = DEFAULT_ALPHA_BETA;
	uint32_t beta = DEFAULT_ALPHA_BETA;
	int step_unit = __TCA_DUALPI2_MAX;
	bool set_min_qlen_step = false;
	int32_t coupling_factor = -1;
	uint32_t min_qlen_step = 0;
	uint32_t memory_limit = 0;
	uint32_t step_thresh = 0;
	int c_protection = -1;
	uint32_t tupdate = 0;
	uint8_t ecn_mask = 0;
	uint32_t rtt_max = 0;
	uint32_t rtt_typ = 0;
	uint32_t target = 0;
	struct rtattr *tail;
	uint32_t limit = 0;

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_u32(&limit, *argv, 10)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "memlimit") == 0) {
			NEXT_ARG();
			if (get_u32(&memory_limit, *argv, 10)) {
				fprintf(stderr, "Illegal \"memlimit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "target") == 0) {
			NEXT_ARG();
			if (get_time(&target, *argv)) {
				fprintf(stderr, "Illegal \"target\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "tupdate") == 0) {
			NEXT_ARG();
			if (get_time(&tupdate, *argv)) {
				fprintf(stderr, "Illegal \"tupdate\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "alpha") == 0) {
			NEXT_ARG();
			if (parse_alpha_beta("alpha", *argv, &alpha))
				return -1;
		} else if (strcmp(*argv, "beta") == 0) {
			NEXT_ARG();
			if (parse_alpha_beta("beta", *argv, &beta))
				return -1;
		} else if (strcmp(*argv, "coupling_factor") == 0) {
			NEXT_ARG();
			if (get_s32(&coupling_factor, *argv, 0) ||
			    coupling_factor > 0xFFUL || coupling_factor < 0) {
				fprintf(stderr,
					"Illegal \"coupling_factor\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "l4s_ect") == 0)
			ecn_mask = TC_DUALPI2_ECN_MASK_L4S_ECT;
		else if (strcmp(*argv, "any_ect") == 0)
			ecn_mask = TC_DUALPI2_ECN_MASK_ANY_ECT;
		else if (strcmp(*argv, "step_thresh") == 0) {
			NEXT_ARG();
			/* First assume that this is specified in time */
			if (get_time(&step_thresh, *argv)) {
				/* Then packets */
				if (get_packets(&step_thresh, *argv)) {
					fprintf(stderr,
						"Illegal \"step_thresh\"\n");
					return -1;
				}
				step_unit = TCA_DUALPI2_STEP_THRESH_PKTS;
			} else {
				step_unit = TCA_DUALPI2_STEP_THRESH_US;
			}
		} else if (strcmp(*argv, "min_qlen_step") == 0) {
			NEXT_ARG();
			if (get_u32(&min_qlen_step, *argv, 10)) {
				fprintf(stderr, "Illegal \"min_qlen_step\"\n");
				return -1;
			}
			set_min_qlen_step = true;
		} else if (strcmp(*argv, "overflow") == 0) {
			drop_overload = TC_DUALPI2_DROP_OVERLOAD_OVERFLOW;
		} else if (strcmp(*argv, "drop_on_overload") == 0) {
			drop_overload = TC_DUALPI2_DROP_OVERLOAD_DROP;
		} else if (strcmp(*argv, "drop_enqueue") == 0) {
			drop_early = TC_DUALPI2_DROP_EARLY_DROP_ENQUEUE;
		} else if (strcmp(*argv, "drop_dequeue") == 0) {
			drop_early = TC_DUALPI2_DROP_EARLY_DROP_DEQUEUE;
		} else if (strcmp(*argv, "split_gso") == 0) {
			split_gso = TC_DUALPI2_SPLIT_GSO_SPLIT_GSO;
		} else if (strcmp(*argv, "no_split_gso") == 0) {
			split_gso = TC_DUALPI2_SPLIT_GSO_NO_SPLIT_GSO;
		} else if (strcmp(*argv, "classic_protection") == 0) {
			NEXT_ARG();
			if (try_get_percent(&c_protection, *argv) ||
			    c_protection > 100 ||
			    c_protection < 0) {
				fprintf(stderr,
					"Illegal \"classic_protection\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "max_rtt") == 0) {
			NEXT_ARG();
			if (get_time(&rtt_max, *argv)) {
				fprintf(stderr, "Illegal \"max_rtt\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "typical_rtt") == 0) {
			NEXT_ARG();
			if (get_time(&rtt_typ, *argv)) {
				fprintf(stderr, "Illegal \"typical_rtt\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		--argc;
		++argv;
	}

	if (rtt_max || rtt_typ) {
		double alpha_f, beta_f;

		SPRINT_BUF(max_rtt_t);
		SPRINT_BUF(typ_rtt_t);
		SPRINT_BUF(tupdate_t);
		SPRINT_BUF(target_t);

		if (!rtt_typ)
			rtt_typ = max(rtt_max / RTT_TYP_TO_MAX, 1U);
		else if (!rtt_max)
			rtt_max = rtt_typ * RTT_TYP_TO_MAX;
		else if (rtt_typ > rtt_max) {
			fprintf(stderr, "typical_rtt must be <= max_rtt!\n");
			return -1;
		}
		if (alpha != DEFAULT_ALPHA_BETA || beta != DEFAULT_ALPHA_BETA ||
		    tupdate || target)
			fprintf(stderr,
				"rtt_max is specified, ignore alpha/beta/tupdate/target\n");
		target = rtt_typ;
		tupdate = (double)rtt_typ < (double)rtt_max / 3.0f ?
			rtt_typ : (double)rtt_max / 3.0f;
		tupdate = max(tupdate, 1U);
		alpha_f = (double)tupdate / rtt_max / rtt_max
			* TIME_UNITS_PER_SEC * 0.1f;
		beta_f = 0.3f / (double)rtt_max * TIME_UNITS_PER_SEC;
		if (beta_f > ALPHA_BETA_MAX) {
			fprintf(stderr,
				"max_rtt=%s is too low and cause beta to overflow!\n",
				sprint_time(rtt_max, max_rtt_t));
			return -1;
		}
		if (alpha_f < 1.0f / ALPHA_BETA_SCALE ||
		    beta_f < 1.0f / ALPHA_BETA_SCALE) {
			fprintf(stderr,
				"Large max_rtt=%s rounds down alpha=%f and/or beta=%f!\n",
				sprint_time(rtt_max, max_rtt_t),
				alpha_f, beta_f);
			return -1;
		}
		fprintf(stderr,
			"Auto-config [max_rtt: %s, typical_rtt: %s]: target=%s tupdate=%s alpha=%f beta=%f\n",
			sprint_time(rtt_max, max_rtt_t),
			sprint_time(rtt_typ, typ_rtt_t),
			sprint_time(target, target_t),
			sprint_time(tupdate, tupdate_t), alpha_f, beta_f);
		alpha = alpha_f * ALPHA_BETA_SCALE;
		beta = beta_f * ALPHA_BETA_SCALE;
	}

	tail = addattr_nest(n, 1024, TCA_OPTIONS | NLA_F_NESTED);
	if (limit)
		addattr32(n, 1024, TCA_DUALPI2_LIMIT, limit);
	if (memory_limit)
		addattr32(n, 1024, TCA_DUALPI2_MEMORY_LIMIT, memory_limit);
	if (tupdate)
		addattr32(n, 1024, TCA_DUALPI2_TUPDATE, tupdate);
	if (target)
		addattr32(n, 1024, TCA_DUALPI2_TARGET, target);
	if (alpha != DEFAULT_ALPHA_BETA)
		addattr32(n, 1024, TCA_DUALPI2_ALPHA, alpha);
	if (beta != DEFAULT_ALPHA_BETA)
		addattr32(n, 1024, TCA_DUALPI2_BETA, beta);
	if (ecn_mask != 0)
		addattr8(n, 1024, TCA_DUALPI2_ECN_MASK, ecn_mask);
	if (drop_overload != __TCA_DUALPI2_DROP_OVERLOAD_MAX)
		addattr8(n, 1024, TCA_DUALPI2_DROP_OVERLOAD, drop_overload);
	if (coupling_factor != -1)
		addattr8(n, 1024, TCA_DUALPI2_COUPLING, coupling_factor);
	if (split_gso != __TCA_DUALPI2_SPLIT_GSO_MAX)
		addattr8(n, 1024, TCA_DUALPI2_SPLIT_GSO, split_gso);
	if (step_thresh) {
		if (step_unit == TCA_DUALPI2_STEP_THRESH_PKTS ||
		    step_unit == TCA_DUALPI2_STEP_THRESH_US)
			addattr32(n, 1024, step_unit, step_thresh);
	}
	if (set_min_qlen_step)
		addattr32(n, 1024, TCA_DUALPI2_MIN_QLEN_STEP, min_qlen_step);
	if (drop_early != __TCA_DUALPI2_DROP_EARLY_MAX)
		addattr8(n, 1024, TCA_DUALPI2_DROP_EARLY, drop_early);
	if (c_protection != -1)
		addattr8(n, 1024, TCA_DUALPI2_C_PROTECTION, c_protection);
	addattr_nest_end(n, tail);

	return 0;
}

static float get_scaled_alpha_beta(struct rtattr *tb)
{
	if (!tb)
		return 0;

	if (RTA_PAYLOAD(tb) < sizeof(__u32))
		return -1;

	return ((float)rta_getattr_u32(tb)) / ALPHA_BETA_SCALE;
}

static int dualpi2_print_opt(const struct qdisc_util *qu, FILE *f,
			     struct rtattr *opt)
{
	struct rtattr *tb[TCA_DUALPI2_MAX + 1];
	uint8_t drop_overload;
	uint32_t step_thresh;
	uint8_t drop_early;
	uint8_t split_gso;
	uint32_t tupdate;
	uint8_t ecn_type;
	uint32_t target;

	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_DUALPI2_MAX, opt);

	if (tb[TCA_DUALPI2_LIMIT] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_LIMIT]) >= sizeof(__u32))
		print_uint(PRINT_ANY, "limit", "limit %up ",
			   rta_getattr_u32(tb[TCA_DUALPI2_LIMIT]));
	if (tb[TCA_DUALPI2_MEMORY_LIMIT] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_MEMORY_LIMIT]) >= sizeof(__u32))
		print_uint(PRINT_ANY, "memory-limit", "memlimit %uB ",
			   rta_getattr_u32(tb[TCA_DUALPI2_MEMORY_LIMIT]));
	if (tb[TCA_DUALPI2_TARGET] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_TARGET]) >= sizeof(__u32)) {
		target = rta_getattr_u32(tb[TCA_DUALPI2_TARGET]);
		print_uint(PRINT_JSON, "target", NULL, target);
		print_string(PRINT_FP, NULL, "target %s ",
			     sprint_time(target, b1));
	}
	if (tb[TCA_DUALPI2_TUPDATE] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_TUPDATE]) >= sizeof(__u32)) {
		tupdate = rta_getattr_u32(tb[TCA_DUALPI2_TUPDATE]);
		print_uint(PRINT_JSON, "tupdate", NULL, tupdate);
		print_string(PRINT_FP, NULL, "tupdate %s ",
			     sprint_time(tupdate, b1));
	}
	if (tb[TCA_DUALPI2_ALPHA] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_ALPHA]) >= sizeof(__u32))
		print_float(PRINT_ANY, "alpha", "alpha %f ",
			    get_scaled_alpha_beta(tb[TCA_DUALPI2_ALPHA]));
	if (tb[TCA_DUALPI2_BETA] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_BETA]) >= sizeof(__u32))
		print_float(PRINT_ANY, "beta", "beta %f ",
			    get_scaled_alpha_beta(tb[TCA_DUALPI2_BETA]));
	if (tb[TCA_DUALPI2_STEP_THRESH_PKTS] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_STEP_THRESH_PKTS]) >= sizeof(__u32))
		print_uint(PRINT_ANY, "step-thresh-pkts", "step_thresh %up ",
			   rta_getattr_u32(tb[TCA_DUALPI2_STEP_THRESH_PKTS]));
	if (tb[TCA_DUALPI2_STEP_THRESH_US] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_STEP_THRESH_US]) >= sizeof(__u32)) {
		step_thresh = rta_getattr_u32(tb[TCA_DUALPI2_STEP_THRESH_US]);
		print_uint(PRINT_JSON, "step-thresh-us", NULL, step_thresh);
		print_string(PRINT_FP, NULL, "step_thresh %s ",
			     sprint_time(step_thresh, b1));
	}
	if (tb[TCA_DUALPI2_MIN_QLEN_STEP] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_MIN_QLEN_STEP]) >= sizeof(__u32))
		print_uint(PRINT_ANY, "min-qlen-step", "min_qlen_step %up ",
			   rta_getattr_u32(tb[TCA_DUALPI2_MIN_QLEN_STEP]));
	if (tb[TCA_DUALPI2_COUPLING] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_COUPLING]) >= sizeof(__u8))
		print_uint(PRINT_ANY, "coupling", "coupling_factor %u ",
			   rta_getattr_u8(tb[TCA_DUALPI2_COUPLING]));
	if (tb[TCA_DUALPI2_DROP_OVERLOAD] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_DROP_OVERLOAD]) >= sizeof(__u8)) {
		drop_overload = rta_getattr_u8(tb[TCA_DUALPI2_DROP_OVERLOAD]);
		print_string(PRINT_FP, NULL, "%s ",
			     drop_overload ? "drop_on_overload" : "overflow");
		print_string(PRINT_JSON, "drop-overload", NULL,
			     drop_overload ? "drop" : "overflow");
	}
	if (tb[TCA_DUALPI2_DROP_EARLY] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_DROP_EARLY]) >= sizeof(__u8)) {
		drop_early = rta_getattr_u8(tb[TCA_DUALPI2_DROP_EARLY]);
		print_string(PRINT_FP, NULL, "%s ",
			     drop_early ? "drop_enqueue" : "drop_dequeue");
		print_string(PRINT_JSON, "drop-early", NULL,
			     drop_early ? "drop-enqueue" : "drop-dequeue");
	}
	if (tb[TCA_DUALPI2_C_PROTECTION] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_C_PROTECTION]) >= sizeof(__u8))
		print_uint(PRINT_ANY, "c-protection",
			   "classic_protection %u%% ",
			   rta_getattr_u8(tb[TCA_DUALPI2_C_PROTECTION]));
	if (tb[TCA_DUALPI2_ECN_MASK] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_ECN_MASK]) >= sizeof(__u8)) {
		ecn_type = rta_getattr_u8(tb[TCA_DUALPI2_ECN_MASK]);
		print_string(PRINT_FP, NULL, "%s ", get_ecn_type(ecn_type));
		print_string(PRINT_JSON, "ecn-mask", NULL,
			     get_ecn_type_json(ecn_type));
	}
	if (tb[TCA_DUALPI2_SPLIT_GSO] &&
	    RTA_PAYLOAD(tb[TCA_DUALPI2_SPLIT_GSO]) >= sizeof(__u8)) {
		split_gso = rta_getattr_u8(tb[TCA_DUALPI2_SPLIT_GSO]);
		print_string(PRINT_FP, NULL, "%ssplit_gso ", split_gso ? "" : "no_");
		if (split_gso)
			print_null(PRINT_JSON, "split-gso", NULL, NULL);
	}

	return 0;
}

static int dualpi2_print_xstats(const struct qdisc_util *qu, FILE *f,
				struct rtattr *xstats)
{
	struct tc_dualpi2_xstats *st;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);
	print_float(PRINT_ANY, "prob", "prob %f ", (double)st->prob / (double)MAX_PROB);
	print_uint(PRINT_ANY, "delay-c", "delay_c %uus ", st->delay_c);
	print_uint(PRINT_ANY, "delay-l", "delay_l %uus", st->delay_l);
	print_nl();

	print_uint(PRINT_ANY, "pkts-in-c", "pkts_in_c %u ", st->packets_in_c);
	print_uint(PRINT_ANY, "pkts-in-l", "pkts_in_l %u ", st->packets_in_l);
	print_uint(PRINT_ANY, "maxq", "maxq %u", st->maxq);
	print_nl();

	print_uint(PRINT_ANY, "ecn-mark", "ecn_mark %u ", st->ecn_mark);
	print_uint(PRINT_ANY, "step-mark", "step_mark %u", st->step_marks);
	print_nl();

	print_int(PRINT_ANY, "credit", "credit %d ", st->credit);
	print_string(PRINT_FP, NULL, "(%s)", get_credit_queue(st->credit));
	print_nl();

	print_uint(PRINT_ANY, "memory-used", "memory_used %u ", st->memory_used);
	print_uint(PRINT_ANY, "max-memory-used", "(max %u) ", st->max_memory_used);
	print_uint(PRINT_ANY, "memory-limit", "of memory limit %u", st->memory_limit);
	print_nl();

	return 0;
}

struct qdisc_util dualpi2_qdisc_util = {
	.id		= "dualpi2",
	.parse_qopt	= dualpi2_parse_opt,
	.print_qopt	= dualpi2_print_opt,
	.print_xstats	= dualpi2_print_xstats,
};
