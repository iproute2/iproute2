// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Fair Queue
 *
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... fq	[ limit PACKETS ] [ flow_limit PACKETS ]\n"
		"		[ quantum BYTES ] [ initial_quantum BYTES ]\n"
		"		[ maxrate RATE ] [ buckets NUMBER ]\n"
		"		[ [no]pacing ] [ refill_delay TIME ]\n"
		"		[ bands 3 priomap P0 P1 ... P14 P15 ]\n"
		"		[ weights W1 W2 W3 ]\n"
		"		[ low_rate_threshold RATE ]\n"
		"		[ orphan_mask MASK]\n"
		"		[ timer_slack TIME]\n"
		"		[ ce_threshold TIME ]\n"
		"		[ horizon TIME ]\n"
		"		[ horizon_{cap|drop} ]\n"
		"		[ offload_horizon TIME ]\n");
}

static unsigned int ilog2(unsigned int val)
{
	unsigned int res = 0;

	val--;
	while (val) {
		res++;
		val >>= 1;
	}
	return res;
}

static int fq_parse_opt(const struct qdisc_util *qu, int argc, char **argv,
			struct nlmsghdr *n, const char *dev)
{
	struct tc_prio_qopt prio2band;
	unsigned int plimit;
	unsigned int flow_plimit;
	unsigned int quantum;
	unsigned int initial_quantum;
	unsigned int buckets = 0;
	unsigned int maxrate;
	unsigned int low_rate_threshold;
	unsigned int defrate;
	unsigned int refill_delay;
	unsigned int orphan_mask;
	unsigned int ce_threshold;
	unsigned int timer_slack;
	unsigned int horizon;
	unsigned int offload_horizon;
	__u8 horizon_drop = 255;
	bool set_plimit = false;
	bool set_flow_plimit = false;
	bool set_quantum = false;
	bool set_initial_quantum = false;
	bool set_maxrate = false;
	bool set_defrate = false;
	bool set_refill_delay = false;
	bool set_orphan_mask = false;
	bool set_low_rate_threshold = false;
	bool set_ce_threshold = false;
	bool set_timer_slack = false;
	bool set_horizon = false;
	bool set_priomap = false;
	bool set_weights = false;
	bool set_offload_horizon = false;
	int weights[FQ_BANDS];
	int pacing = -1;
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
			set_plimit = true;
		} else if (strcmp(*argv, "flow_limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&flow_plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"flow_limit\"\n");
				return -1;
			}
			set_flow_plimit = true;
		} else if (strcmp(*argv, "buckets") == 0) {
			NEXT_ARG();
			if (get_unsigned(&buckets, *argv, 0)) {
				fprintf(stderr, "Illegal \"buckets\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "maxrate") == 0) {
			NEXT_ARG();
			if (strchr(*argv, '%')) {
				if (get_percent_rate(&maxrate, *argv, dev)) {
					fprintf(stderr, "Illegal \"maxrate\"\n");
					return -1;
				}
			} else if (get_rate(&maxrate, *argv)) {
				fprintf(stderr, "Illegal \"maxrate\"\n");
				return -1;
			}
			set_maxrate = true;
		} else if (strcmp(*argv, "low_rate_threshold") == 0) {
			NEXT_ARG();
			if (get_rate(&low_rate_threshold, *argv)) {
				fprintf(stderr, "Illegal \"low_rate_threshold\"\n");
				return -1;
			}
			set_low_rate_threshold = true;
		} else if (strcmp(*argv, "ce_threshold") == 0) {
			NEXT_ARG();
			if (get_time(&ce_threshold, *argv)) {
				fprintf(stderr, "Illegal \"ce_threshold\"\n");
				return -1;
			}
			set_ce_threshold = true;
		} else if (strcmp(*argv, "timer_slack") == 0) {
			__s64 t64;

			NEXT_ARG();
			if (get_time64(&t64, *argv)) {
				fprintf(stderr, "Illegal \"timer_slack\"\n");
				return -1;
			}
			timer_slack = t64;
			if (timer_slack != t64) {
				fprintf(stderr, "Illegal (out of range) \"timer_slack\"\n");
				return -1;
			}
			set_timer_slack = true;
		} else if (strcmp(*argv, "horizon_drop") == 0) {
			horizon_drop = 1;
		} else if (strcmp(*argv, "horizon_cap") == 0) {
			horizon_drop = 0;
		} else if (strcmp(*argv, "horizon") == 0) {
			NEXT_ARG();
			if (get_time(&horizon, *argv)) {
				fprintf(stderr, "Illegal \"horizon\"\n");
				return -1;
			}
			set_horizon = true;
		} else if (strcmp(*argv, "offload_horizon") == 0) {
			NEXT_ARG();
			if (get_time(&offload_horizon, *argv)) {
				fprintf(stderr, "Illegal \"offload_horizon\"\n");
				return -1;
			}
			set_offload_horizon = true;
		} else if (strcmp(*argv, "defrate") == 0) {
			NEXT_ARG();
			if (strchr(*argv, '%')) {
				if (get_percent_rate(&defrate, *argv, dev)) {
					fprintf(stderr, "Illegal \"defrate\"\n");
					return -1;
				}
			} else if (get_rate(&defrate, *argv)) {
				fprintf(stderr, "Illegal \"defrate\"\n");
				return -1;
			}
			set_defrate = true;
		} else if (strcmp(*argv, "quantum") == 0) {
			NEXT_ARG();
			if (get_unsigned(&quantum, *argv, 0)) {
				fprintf(stderr, "Illegal \"quantum\"\n");
				return -1;
			}
			set_quantum = true;
		} else if (strcmp(*argv, "initial_quantum") == 0) {
			NEXT_ARG();
			if (get_unsigned(&initial_quantum, *argv, 0)) {
				fprintf(stderr, "Illegal \"initial_quantum\"\n");
				return -1;
			}
			set_initial_quantum = true;
		} else if (strcmp(*argv, "orphan_mask") == 0) {
			NEXT_ARG();
			if (get_unsigned(&orphan_mask, *argv, 0)) {
				fprintf(stderr, "Illegal \"initial_quantum\"\n");
				return -1;
			}
			set_orphan_mask = true;
		} else if (strcmp(*argv, "refill_delay") == 0) {
			NEXT_ARG();
			if (get_time(&refill_delay, *argv)) {
				fprintf(stderr, "Illegal \"refill_delay\"\n");
				return -1;
			}
			set_refill_delay = true;
		} else if (strcmp(*argv, "pacing") == 0) {
			pacing = 1;
		} else if (strcmp(*argv, "nopacing") == 0) {
			pacing = 0;
		} else if (strcmp(*argv, "bands") == 0) {
			int idx;

			if (set_priomap) {
				fprintf(stderr, "Duplicate \"bands\"\n");
				return -1;
			}
			memset(&prio2band, 0, sizeof(prio2band));
			NEXT_ARG();
			if (get_integer(&prio2band.bands, *argv, 10)) {
				fprintf(stderr, "Illegal \"bands\"\n");
				return -1;
			}
			if (prio2band.bands != 3) {
				fprintf(stderr, "\"bands\" must be 3\n");
				return -1;
			}
			NEXT_ARG();
			if (strcmp(*argv, "priomap") != 0) {
				fprintf(stderr, "\"priomap\" expected\n");
				return -1;
			}
			for (idx = 0; idx <= TC_PRIO_MAX; ++idx) {
				unsigned band;

				if (!NEXT_ARG_OK()) {
					fprintf(stderr, "Not enough elements in priomap\n");
					return -1;
				}
				NEXT_ARG();
				if (get_unsigned(&band, *argv, 10)) {
					fprintf(stderr, "Illegal \"priomap\" element, number in [0..%u] expected\n",
							prio2band.bands - 1);
					return -1;
				}
				if (band >= prio2band.bands) {
					fprintf(stderr, "\"priomap\" element %u too big\n", band);
					return -1;
				}
				prio2band.priomap[idx] = band;
			}
			set_priomap = true;
		} else if (strcmp(*argv, "weights") == 0) {
			int idx;

			if (set_weights) {
				fprintf(stderr, "Duplicate \"weights\"\n");
				return -1;
			}
			for (idx = 0; idx < FQ_BANDS; ++idx) {
				int val;

				if (!NEXT_ARG_OK()) {
					fprintf(stderr, "Not enough elements in weights\n");
					return -1;
				}
				NEXT_ARG();
				if (get_integer(&val, *argv, 10)) {
					fprintf(stderr, "Illegal \"weights\" element, positive number expected\n");
					return -1;
				}
				if (val < FQ_MIN_WEIGHT) {
					fprintf(stderr, "\"weight\" element %d too small\n", val);
					return -1;
				}
				weights[idx] = val;
			}
			set_weights = true;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	tail = addattr_nest(n, 1024, TCA_OPTIONS);
	if (buckets) {
		unsigned int log = ilog2(buckets);

		addattr_l(n, 1024, TCA_FQ_BUCKETS_LOG,
			  &log, sizeof(log));
	}
	if (set_plimit)
		addattr_l(n, 1024, TCA_FQ_PLIMIT,
			  &plimit, sizeof(plimit));
	if (set_flow_plimit)
		addattr_l(n, 1024, TCA_FQ_FLOW_PLIMIT,
			  &flow_plimit, sizeof(flow_plimit));
	if (set_quantum)
		addattr_l(n, 1024, TCA_FQ_QUANTUM, &quantum, sizeof(quantum));
	if (set_initial_quantum)
		addattr_l(n, 1024, TCA_FQ_INITIAL_QUANTUM,
			  &initial_quantum, sizeof(initial_quantum));
	if (pacing != -1)
		addattr_l(n, 1024, TCA_FQ_RATE_ENABLE,
			  &pacing, sizeof(pacing));
	if (set_maxrate)
		addattr_l(n, 1024, TCA_FQ_FLOW_MAX_RATE,
			  &maxrate, sizeof(maxrate));
	if (set_low_rate_threshold)
		addattr_l(n, 1024, TCA_FQ_LOW_RATE_THRESHOLD,
			  &low_rate_threshold, sizeof(low_rate_threshold));
	if (set_defrate)
		addattr_l(n, 1024, TCA_FQ_FLOW_DEFAULT_RATE,
			  &defrate, sizeof(defrate));
	if (set_refill_delay)
		addattr_l(n, 1024, TCA_FQ_FLOW_REFILL_DELAY,
			  &refill_delay, sizeof(refill_delay));
	if (set_orphan_mask)
		addattr_l(n, 1024, TCA_FQ_ORPHAN_MASK,
			  &orphan_mask, sizeof(orphan_mask));
	if (set_ce_threshold)
		addattr_l(n, 1024, TCA_FQ_CE_THRESHOLD,
			  &ce_threshold, sizeof(ce_threshold));
	if (set_timer_slack)
		addattr_l(n, 1024, TCA_FQ_TIMER_SLACK,
			  &timer_slack, sizeof(timer_slack));
	if (set_horizon)
		addattr_l(n, 1024, TCA_FQ_HORIZON,
			  &horizon, sizeof(horizon));
	if (horizon_drop != 255)
		addattr_l(n, 1024, TCA_FQ_HORIZON_DROP,
			  &horizon_drop, sizeof(horizon_drop));
	if (set_priomap)
		addattr_l(n, 1024, TCA_FQ_PRIOMAP,
			  &prio2band, sizeof(prio2band));
	if (set_weights)
		addattr_l(n, 1024, TCA_FQ_WEIGHTS,
			  weights, sizeof(weights));
	if (set_offload_horizon)
		addattr_l(n, 1024, TCA_FQ_OFFLOAD_HORIZON,
			  &offload_horizon, sizeof(offload_horizon));
	addattr_nest_end(n, tail);
	return 0;
}

static int fq_print_opt(const struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_FQ_MAX + 1];
	unsigned int plimit, flow_plimit;
	unsigned int buckets_log;
	int pacing;
	unsigned int rate, quantum;
	unsigned int refill_delay;
	unsigned int orphan_mask;
	unsigned int ce_threshold;
	unsigned int timer_slack;
	__u32 offload_horizon;
	unsigned int horizon;
	__u8 horizon_drop;

	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_FQ_MAX, opt);

	if (tb[TCA_FQ_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PLIMIT]) >= sizeof(__u32)) {
		plimit = rta_getattr_u32(tb[TCA_FQ_PLIMIT]);
		print_uint(PRINT_ANY, "limit", "limit %up ", plimit);
	}
	if (tb[TCA_FQ_FLOW_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_FQ_FLOW_PLIMIT]) >= sizeof(__u32)) {
		flow_plimit = rta_getattr_u32(tb[TCA_FQ_FLOW_PLIMIT]);
		print_uint(PRINT_ANY, "flow_limit", "flow_limit %up ",
			   flow_plimit);
	}
	if (tb[TCA_FQ_BUCKETS_LOG] &&
	    RTA_PAYLOAD(tb[TCA_FQ_BUCKETS_LOG]) >= sizeof(__u32)) {
		buckets_log = rta_getattr_u32(tb[TCA_FQ_BUCKETS_LOG]);
		print_uint(PRINT_ANY, "buckets", "buckets %u ",
			   1U << buckets_log);
	}
	if (tb[TCA_FQ_ORPHAN_MASK] &&
	    RTA_PAYLOAD(tb[TCA_FQ_ORPHAN_MASK]) >= sizeof(__u32)) {
		orphan_mask = rta_getattr_u32(tb[TCA_FQ_ORPHAN_MASK]);
		print_uint(PRINT_ANY, "orphan_mask", "orphan_mask %u ",
			   orphan_mask);
	}
	if (tb[TCA_FQ_RATE_ENABLE] &&
	    RTA_PAYLOAD(tb[TCA_FQ_RATE_ENABLE]) >= sizeof(int)) {
		pacing = rta_getattr_u32(tb[TCA_FQ_RATE_ENABLE]);
		if (pacing == 0)
			print_bool(PRINT_ANY, "pacing", "nopacing ", false);
	}
	if (tb[TCA_FQ_PRIOMAP] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PRIOMAP]) >= sizeof(struct tc_prio_qopt)) {
		struct tc_prio_qopt *prio2band = RTA_DATA(tb[TCA_FQ_PRIOMAP]);
		int i;

		print_uint(PRINT_ANY, "bands", "bands %u ", prio2band->bands);
		open_json_array(PRINT_ANY, "priomap ");
		for (i = 0; i <= TC_PRIO_MAX; i++)
			print_uint(PRINT_ANY, NULL, "%d ", prio2band->priomap[i]);
		close_json_array(PRINT_ANY, "");
	}
	if (tb[TCA_FQ_WEIGHTS] &&
	    RTA_PAYLOAD(tb[TCA_FQ_WEIGHTS]) >= FQ_BANDS * sizeof(int)) {
		const int *weights = RTA_DATA(tb[TCA_FQ_WEIGHTS]);
		int i;

		open_json_array(PRINT_ANY, "weights ");
		for (i = 0; i < FQ_BANDS; ++i)
			print_uint(PRINT_ANY, NULL, "%d ", weights[i]);
		close_json_array(PRINT_ANY, "");
	}
	if (tb[TCA_FQ_QUANTUM] &&
	    RTA_PAYLOAD(tb[TCA_FQ_QUANTUM]) >= sizeof(__u32)) {
		quantum = rta_getattr_u32(tb[TCA_FQ_QUANTUM]);
		print_size(PRINT_ANY, "quantum", "quantum %s ", quantum);
	}
	if (tb[TCA_FQ_INITIAL_QUANTUM] &&
	    RTA_PAYLOAD(tb[TCA_FQ_INITIAL_QUANTUM]) >= sizeof(__u32)) {
		quantum = rta_getattr_u32(tb[TCA_FQ_INITIAL_QUANTUM]);
		print_size(PRINT_ANY, "initial_quantum", "initial_quantum %s ",
			   quantum);
	}
	if (tb[TCA_FQ_FLOW_MAX_RATE] &&
	    RTA_PAYLOAD(tb[TCA_FQ_FLOW_MAX_RATE]) >= sizeof(__u32)) {
		rate = rta_getattr_u32(tb[TCA_FQ_FLOW_MAX_RATE]);

		if (rate != ~0U)
			tc_print_rate(PRINT_ANY,
				      "maxrate", "maxrate %s ", rate);
	}
	if (tb[TCA_FQ_FLOW_DEFAULT_RATE] &&
	    RTA_PAYLOAD(tb[TCA_FQ_FLOW_DEFAULT_RATE]) >= sizeof(__u32)) {
		rate = rta_getattr_u32(tb[TCA_FQ_FLOW_DEFAULT_RATE]);

		if (rate != 0)
			tc_print_rate(PRINT_ANY,
				      "defrate", "defrate %s ", rate);
	}
	if (tb[TCA_FQ_LOW_RATE_THRESHOLD] &&
	    RTA_PAYLOAD(tb[TCA_FQ_LOW_RATE_THRESHOLD]) >= sizeof(__u32)) {
		rate = rta_getattr_u32(tb[TCA_FQ_LOW_RATE_THRESHOLD]);

		if (rate != 0)
			tc_print_rate(PRINT_ANY, "low_rate_threshold",
				      "low_rate_threshold %s ", rate);
	}
	if (tb[TCA_FQ_FLOW_REFILL_DELAY] &&
	    RTA_PAYLOAD(tb[TCA_FQ_FLOW_REFILL_DELAY]) >= sizeof(__u32)) {
		refill_delay = rta_getattr_u32(tb[TCA_FQ_FLOW_REFILL_DELAY]);
		print_uint(PRINT_JSON, "refill_delay", NULL, refill_delay);
		print_string(PRINT_FP, NULL, "refill_delay %s ",
			     sprint_time(refill_delay, b1));
	}

	if (tb[TCA_FQ_CE_THRESHOLD] &&
	    RTA_PAYLOAD(tb[TCA_FQ_CE_THRESHOLD]) >= sizeof(__u32)) {
		ce_threshold = rta_getattr_u32(tb[TCA_FQ_CE_THRESHOLD]);
		if (ce_threshold != ~0U) {
			print_uint(PRINT_JSON, "ce_threshold", NULL,
				   ce_threshold);
			print_string(PRINT_FP, NULL, "ce_threshold %s ",
				     sprint_time(ce_threshold, b1));
		}
	}

	if (tb[TCA_FQ_TIMER_SLACK] &&
	    RTA_PAYLOAD(tb[TCA_FQ_TIMER_SLACK]) >= sizeof(__u32)) {
		timer_slack = rta_getattr_u32(tb[TCA_FQ_TIMER_SLACK]);
		print_uint(PRINT_JSON, "timer_slack", NULL, timer_slack);
		print_string(PRINT_FP, NULL, "timer_slack %s ",
			     sprint_time64(timer_slack, b1));
	}

	if (tb[TCA_FQ_HORIZON] &&
	    RTA_PAYLOAD(tb[TCA_FQ_HORIZON]) >= sizeof(__u32)) {
		horizon = rta_getattr_u32(tb[TCA_FQ_HORIZON]);
		print_uint(PRINT_JSON, "horizon", NULL, horizon);
		print_string(PRINT_FP, NULL, "horizon %s ",
			     sprint_time(horizon, b1));
	}

	if (tb[TCA_FQ_HORIZON_DROP] &&
	    RTA_PAYLOAD(tb[TCA_FQ_HORIZON_DROP]) >= sizeof(__u8)) {
		horizon_drop = rta_getattr_u8(tb[TCA_FQ_HORIZON_DROP]);
		if (!horizon_drop)
			print_null(PRINT_ANY, "horizon_cap", "horizon_cap ", NULL);
		else
			print_null(PRINT_ANY, "horizon_drop", "horizon_drop ", NULL);
	}

	if (tb[TCA_FQ_OFFLOAD_HORIZON] &&
	    RTA_PAYLOAD(tb[TCA_FQ_OFFLOAD_HORIZON]) >= sizeof(__u32)) {
		offload_horizon = rta_getattr_u32(tb[TCA_FQ_OFFLOAD_HORIZON]);
		print_uint(PRINT_JSON, "offload_horizon", NULL, offload_horizon);
		print_string(PRINT_FP, NULL, "offload_horizon %s ",
			     sprint_time(offload_horizon, b1));
	}

	return 0;
}

static int fq_print_xstats(const struct qdisc_util *qu, FILE *f,
			   struct rtattr *xstats)
{
	struct tc_fq_qd_stats *st, _st;

	SPRINT_BUF(b1);

	if (xstats == NULL)
		return 0;

	memset(&_st, 0, sizeof(_st));
	memcpy(&_st, RTA_DATA(xstats), min(RTA_PAYLOAD(xstats), sizeof(*st)));

	st = &_st;

	print_uint(PRINT_ANY, "flows", "  flows %u", st->flows);
	print_uint(PRINT_ANY, "inactive", " (inactive %u", st->inactive_flows);
	print_uint(PRINT_ANY, "throttled", " throttled %u)",
		   st->throttled_flows);

	print_uint(PRINT_ANY, "band0_pkts", " band0_pkts %u", st->band_pkt_count[0]);
	print_uint(PRINT_ANY, "band1_pkts", " band1_pkts %u", st->band_pkt_count[1]);
	print_uint(PRINT_ANY, "band2_pkts", " band2_pkts %u", st->band_pkt_count[2]);

	if (st->time_next_delayed_flow > 0) {
		print_lluint(PRINT_JSON, "next_packet_delay", NULL,
			     st->time_next_delayed_flow);
		print_string(PRINT_FP, NULL, " next_packet_delay %s",
			     sprint_time64(st->time_next_delayed_flow, b1));
	}

	print_nl();
	print_lluint(PRINT_ANY, "gc", "  gc %llu", st->gc_flows);
	print_lluint(PRINT_ANY, "highprio", " highprio %llu",
		     st->highprio_packets);

	if (st->fastpath_packets)
		print_lluint(PRINT_ANY, "fastpath", " fastpath %llu",
			     st->fastpath_packets);

	if (st->tcp_retrans)
		print_lluint(PRINT_ANY, "retrans", " retrans %llu",
			     st->tcp_retrans);

	print_lluint(PRINT_ANY, "throttled", " throttled %llu", st->throttled);

	if (st->unthrottle_latency_ns) {
		print_uint(PRINT_JSON, "latency", NULL,
			   st->unthrottle_latency_ns);
		print_string(PRINT_FP, NULL, " latency %s",
			     sprint_time64(st->unthrottle_latency_ns, b1));
	}

	if (st->ce_mark)
		print_lluint(PRINT_ANY, "ce_mark", " ce_mark %llu",
			     st->ce_mark);

	if (st->flows_plimit)
		print_lluint(PRINT_ANY, "flows_plimit", " flows_plimit %llu",
			     st->flows_plimit);

	if (st->pkts_too_long || st->allocation_errors ||
	    st->horizon_drops || st->horizon_caps ||
	    st->band_drops[0] ||
	    st->band_drops[1] ||
	    st->band_drops[2]) {
		print_nl();
		if (st->pkts_too_long)
			print_lluint(PRINT_ANY, "pkts_too_long",
				     " pkts_too_long %llu",
				     st->pkts_too_long);
		if (st->allocation_errors)
			print_lluint(PRINT_ANY, "alloc_errors",
				     " alloc_errors %llu",
				     st->allocation_errors);
		if (st->horizon_drops)
			print_lluint(PRINT_ANY, "horizon_drops",
				     " horizon_drops %llu",
				     st->horizon_drops);
		if (st->horizon_caps)
			print_lluint(PRINT_ANY, "horizon_caps",
				     "  horizon_caps %llu",
				     st->horizon_caps);
		if (st->band_drops[0])
			print_lluint(PRINT_ANY, "band0_drops",
				     " band0_drops %llu",
				     st->band_drops[0]);
		if (st->band_drops[1])
			print_lluint(PRINT_ANY, "band1_drops",
				     " band1_drops %llu",
				     st->band_drops[1]);
		if (st->band_drops[2])
			print_lluint(PRINT_ANY, "band2_drops",
				     " band2_drops %llu",
				     st->band_drops[2]);
	}

	return 0;
}

struct qdisc_util fq_qdisc_util = {
	.id		= "fq",
	.parse_qopt	= fq_parse_opt,
	.print_qopt	= fq_print_opt,
	.print_xstats	= fq_print_xstats,
};
