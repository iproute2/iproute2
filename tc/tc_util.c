/*
 * tc_util.c		Misc TC utility functions.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "utils.h"
#include "names.h"
#include "tc_util.h"
#include "tc_common.h"

#ifndef LIBDIR
#define LIBDIR "/usr/lib"
#endif

static struct db_names *cls_names;

#define NAMES_DB "/etc/iproute2/tc_cls"

int cls_names_init(char *path)
{
	int ret;

	cls_names = db_names_alloc();
	if (!cls_names)
		return -1;

	ret = db_names_load(cls_names, path ?: NAMES_DB);
	if (ret == -ENOENT && path) {
		fprintf(stderr, "Can't open class names file: %s\n", path);
		return -1;
	}
	if (ret) {
		db_names_free(cls_names);
		cls_names = NULL;
	}

	return 0;
}

void cls_names_uninit(void)
{
	db_names_free(cls_names);
}

const char *get_tc_lib(void)
{
	const char *lib_dir;

	lib_dir = getenv("TC_LIB_DIR");
	if (!lib_dir)
		lib_dir = LIBDIR "/tc/";

	return lib_dir;
}

int get_qdisc_handle(__u32 *h, const char *str)
{
	__u32 maj;
	char *p;

	maj = TC_H_UNSPEC;
	if (strcmp(str, "none") == 0)
		goto ok;
	maj = strtoul(str, &p, 16);
	if (p == str || maj >= (1 << 16))
		return -1;
	maj <<= 16;
	if (*p != ':' && *p != 0)
		return -1;
ok:
	*h = maj;
	return 0;
}

int get_tc_classid(__u32 *h, const char *str)
{
	__u32 maj, min;
	char *p;

	maj = TC_H_ROOT;
	if (strcmp(str, "root") == 0)
		goto ok;
	maj = TC_H_UNSPEC;
	if (strcmp(str, "none") == 0)
		goto ok;
	maj = strtoul(str, &p, 16);
	if (p == str) {
		maj = 0;
		if (*p != ':')
			return -1;
	}
	if (*p == ':') {
		if (maj >= (1<<16))
			return -1;
		maj <<= 16;
		str = p+1;
		min = strtoul(str, &p, 16);
		if (*p != 0)
			return -1;
		if (min >= (1<<16))
			return -1;
		maj |= min;
	} else if (*p != 0)
		return -1;

ok:
	*h = maj;
	return 0;
}

int print_tc_classid(char *buf, int blen, __u32 h)
{
	SPRINT_BUF(handle) = {};
	int hlen = SPRINT_BSIZE - 1;

	if (h == TC_H_ROOT)
		sprintf(handle, "root");
	else if (h == TC_H_UNSPEC)
		snprintf(handle, hlen, "none");
	else if (TC_H_MAJ(h) == 0)
		snprintf(handle, hlen, ":%x", TC_H_MIN(h));
	else if (TC_H_MIN(h) == 0)
		snprintf(handle, hlen, "%x:", TC_H_MAJ(h) >> 16);
	else
		snprintf(handle, hlen, "%x:%x", TC_H_MAJ(h) >> 16, TC_H_MIN(h));

	if (use_names) {
		char clname[IDNAME_MAX] = {};

		if (id_to_name(cls_names, h, clname))
			snprintf(buf, blen, "%s#%s", clname, handle);
		else
			snprintf(buf, blen, "%s", handle);
	} else {
		snprintf(buf, blen, "%s", handle);
	}

	return 0;
}

char *sprint_tc_classid(__u32 h, char *buf)
{
	if (print_tc_classid(buf, SPRINT_BSIZE-1, h))
		strcpy(buf, "???");
	return buf;
}

/* See http://physics.nist.gov/cuu/Units/binary.html */
static const struct rate_suffix {
	const char *name;
	double scale;
} suffixes[] = {
	{ "bit",	1. },
	{ "Kibit",	1024. },
	{ "kbit",	1000. },
	{ "mibit",	1024.*1024. },
	{ "mbit",	1000000. },
	{ "gibit",	1024.*1024.*1024. },
	{ "gbit",	1000000000. },
	{ "tibit",	1024.*1024.*1024.*1024. },
	{ "tbit",	1000000000000. },
	{ "Bps",	8. },
	{ "KiBps",	8.*1024. },
	{ "KBps",	8000. },
	{ "MiBps",	8.*1024*1024. },
	{ "MBps",	8000000. },
	{ "GiBps",	8.*1024.*1024.*1024. },
	{ "GBps",	8000000000. },
	{ "TiBps",	8.*1024.*1024.*1024.*1024. },
	{ "TBps",	8000000000000. },
	{ NULL }
};


int get_rate(unsigned int *rate, const char *str)
{
	char *p;
	double bps = strtod(str, &p);
	const struct rate_suffix *s;

	if (p == str)
		return -1;

	for (s = suffixes; s->name; ++s) {
		if (strcasecmp(s->name, p) == 0) {
			bps *= s->scale;
			p += strlen(p);
			break;
		}
	}

	if (*p)
		return -1; /* unknown suffix */

	bps /= 8; /* -> bytes per second */
	*rate = bps;
	/* detect if an overflow happened */
	if (*rate != floor(bps))
		return -1;
	return 0;
}

int get_rate64(__u64 *rate, const char *str)
{
	char *p;
	double bps = strtod(str, &p);
	const struct rate_suffix *s;

	if (p == str)
		return -1;

	for (s = suffixes; s->name; ++s) {
		if (strcasecmp(s->name, p) == 0) {
			bps *= s->scale;
			p += strlen(p);
			break;
		}
	}

	if (*p)
		return -1; /* unknown suffix */

	bps /= 8; /* -> bytes per second */
	*rate = bps;
	return 0;
}

void print_rate(char *buf, int len, __u64 rate)
{
	extern int use_iec;
	unsigned long kilo = use_iec ? 1024 : 1000;
	const char *str = use_iec ? "i" : "";
	static char *units[5] = {"", "K", "M", "G", "T"};
	int i;

	rate <<= 3; /* bytes/sec -> bits/sec */

	for (i = 0; i < ARRAY_SIZE(units) - 1; i++)  {
		if (rate < kilo)
			break;
		if (((rate % kilo) != 0) && rate < 1000*kilo)
			break;
		rate /= kilo;
	}

	snprintf(buf, len, "%.0f%s%sbit", (double)rate, units[i], str);
}

char *sprint_rate(__u64 rate, char *buf)
{
	print_rate(buf, SPRINT_BSIZE-1, rate);
	return buf;
}

int get_time(unsigned int *time, const char *str)
{
	double t;
	char *p;

	t = strtod(str, &p);
	if (p == str)
		return -1;

	if (*p) {
		if (strcasecmp(p, "s") == 0 || strcasecmp(p, "sec") == 0 ||
		    strcasecmp(p, "secs") == 0)
			t *= TIME_UNITS_PER_SEC;
		else if (strcasecmp(p, "ms") == 0 || strcasecmp(p, "msec") == 0 ||
			 strcasecmp(p, "msecs") == 0)
			t *= TIME_UNITS_PER_SEC/1000;
		else if (strcasecmp(p, "us") == 0 || strcasecmp(p, "usec") == 0 ||
			 strcasecmp(p, "usecs") == 0)
			t *= TIME_UNITS_PER_SEC/1000000;
		else
			return -1;
	}

	*time = t;
	return 0;
}


void print_time(char *buf, int len, __u32 time)
{
	double tmp = time;

	if (tmp >= TIME_UNITS_PER_SEC)
		snprintf(buf, len, "%.1fs", tmp/TIME_UNITS_PER_SEC);
	else if (tmp >= TIME_UNITS_PER_SEC/1000)
		snprintf(buf, len, "%.1fms", tmp/(TIME_UNITS_PER_SEC/1000));
	else
		snprintf(buf, len, "%uus", time);
}

char *sprint_time(__u32 time, char *buf)
{
	print_time(buf, SPRINT_BSIZE-1, time);
	return buf;
}

char *sprint_ticks(__u32 ticks, char *buf)
{
	return sprint_time(tc_core_tick2time(ticks), buf);
}

int get_size(unsigned int *size, const char *str)
{
	double sz;
	char *p;

	sz = strtod(str, &p);
	if (p == str)
		return -1;

	if (*p) {
		if (strcasecmp(p, "kb") == 0 || strcasecmp(p, "k") == 0)
			sz *= 1024;
		else if (strcasecmp(p, "gb") == 0 || strcasecmp(p, "g") == 0)
			sz *= 1024*1024*1024;
		else if (strcasecmp(p, "gbit") == 0)
			sz *= 1024*1024*1024/8;
		else if (strcasecmp(p, "mb") == 0 || strcasecmp(p, "m") == 0)
			sz *= 1024*1024;
		else if (strcasecmp(p, "mbit") == 0)
			sz *= 1024*1024/8;
		else if (strcasecmp(p, "kbit") == 0)
			sz *= 1024/8;
		else if (strcasecmp(p, "b") != 0)
			return -1;
	}

	*size = sz;
	return 0;
}

int get_size_and_cell(unsigned int *size, int *cell_log, char *str)
{
	char *slash = strchr(str, '/');

	if (slash)
		*slash = 0;

	if (get_size(size, str))
		return -1;

	if (slash) {
		int cell;
		int i;

		if (get_integer(&cell, slash+1, 0))
			return -1;
		*slash = '/';

		for (i = 0; i < 32; i++) {
			if ((1<<i) == cell) {
				*cell_log = i;
				return 0;
			}
		}
		return -1;
	}
	return 0;
}

void print_size(char *buf, int len, __u32 sz)
{
	double tmp = sz;

	if (sz >= 1024*1024 && fabs(1024*1024*rint(tmp/(1024*1024)) - sz) < 1024)
		snprintf(buf, len, "%gMb", rint(tmp/(1024*1024)));
	else if (sz >= 1024 && fabs(1024*rint(tmp/1024) - sz) < 16)
		snprintf(buf, len, "%gKb", rint(tmp/1024));
	else
		snprintf(buf, len, "%ub", sz);
}

char *sprint_size(__u32 size, char *buf)
{
	print_size(buf, SPRINT_BSIZE-1, size);
	return buf;
}

void print_qdisc_handle(char *buf, int len, __u32 h)
{
	snprintf(buf, len, "%x:", TC_H_MAJ(h)>>16);
}

char *sprint_qdisc_handle(__u32 h, char *buf)
{
	print_qdisc_handle(buf, SPRINT_BSIZE-1, h);
	return buf;
}

static const char *action_n2a(int action)
{
	static char buf[64];

	if (TC_ACT_EXT_CMP(action, TC_ACT_GOTO_CHAIN))
		return "goto";
	if (TC_ACT_EXT_CMP(action, TC_ACT_JUMP))
		return "jump";
	switch (action) {
	case TC_ACT_UNSPEC:
		return "continue";
	case TC_ACT_OK:
		return "pass";
	case TC_ACT_SHOT:
		return "drop";
	case TC_ACT_RECLASSIFY:
		return "reclassify";
	case TC_ACT_PIPE:
		return "pipe";
	case TC_ACT_STOLEN:
		return "stolen";
	case TC_ACT_TRAP:
		return "trap";
	default:
		snprintf(buf, 64, "%d", action);
		return buf;
	}
}

/* Convert action branch name into numeric format.
 *
 * Parameters:
 * @arg - string to parse
 * @result - pointer to output variable
 * @allow_num - whether @arg may be in numeric format already
 *
 * In error case, returns -1 and does not touch @result. Otherwise returns 0.
 */
static int action_a2n(char *arg, int *result, bool allow_num)
{
	int n;
	char dummy;
	struct {
		const char *a;
		int n;
	} a2n[] = {
		{"continue", TC_ACT_UNSPEC},
		{"drop", TC_ACT_SHOT},
		{"shot", TC_ACT_SHOT},
		{"pass", TC_ACT_OK},
		{"ok", TC_ACT_OK},
		{"reclassify", TC_ACT_RECLASSIFY},
		{"pipe", TC_ACT_PIPE},
		{"goto", TC_ACT_GOTO_CHAIN},
		{"jump", TC_ACT_JUMP},
		{"trap", TC_ACT_TRAP},
		{ NULL },
	}, *iter;

	for (iter = a2n; iter->a; iter++) {
		if (matches(arg, iter->a) != 0)
			continue;
		*result = iter->n;
		return 0;
	}
	if (!allow_num || sscanf(arg, "%d%c", &n, &dummy) != 1)
		return -1;

	*result = n;
	return 0;
}

static int __parse_action_control(int *argc_p, char ***argv_p, int *result_p,
				  bool allow_num, bool ignore_a2n_miss)
{
	int argc = *argc_p;
	char **argv = *argv_p;
	int result;

	if (!argc)
		return -1;
	if (action_a2n(*argv, &result, allow_num) == -1) {
		if (!ignore_a2n_miss)
			fprintf(stderr, "Bad action type %s\n", *argv);
		return -1;
	}
	if (result == TC_ACT_GOTO_CHAIN) {
		__u32 chain_index;

		NEXT_ARG();
		if (matches(*argv, "chain") != 0) {
			fprintf(stderr, "\"chain index\" expected\n");
			return -1;
		}
		NEXT_ARG();
		if (get_u32(&chain_index, *argv, 10) ||
		    chain_index > TC_ACT_EXT_VAL_MASK) {
			fprintf(stderr, "Illegal \"chain index\"\n");
			return -1;
		}
		result |= chain_index;
	}
	if (result == TC_ACT_JUMP) {
		__u32 jump_cnt = 0;

		NEXT_ARG();
		if (get_u32(&jump_cnt, *argv, 10) ||
		    jump_cnt > TC_ACT_EXT_VAL_MASK) {
			fprintf(stderr, "Invalid \"jump count\" (%s)\n", *argv);
			return -1;
		}
		result |= jump_cnt;
	}
	NEXT_ARG_FWD();
	*argc_p = argc;
	*argv_p = argv;
	*result_p = result;
	return 0;
}

/* Parse action control including possible options.
 *
 * Parameters:
 * @argc_p - pointer to argc to parse
 * @argv_p - pointer to argv to parse
 * @result_p - pointer to output variable
 * @allow_num - whether action may be in numeric format already
 *
 * In error case, returns -1 and does not touch @result_1p. Otherwise returns 0.
 */
int parse_action_control(int *argc_p, char ***argv_p,
			 int *result_p, bool allow_num)
{
	return __parse_action_control(argc_p, argv_p, result_p,
				      allow_num, false);
}

/* Parse action control including possible options.
 *
 * Parameters:
 * @argc_p - pointer to argc to parse
 * @argv_p - pointer to argv to parse
 * @result_p - pointer to output variable
 * @allow_num - whether action may be in numeric format already
 * @default_result - set as a result in case of parsing error
 *
 * In case there is an error during parsing, the default result is used.
 */
void parse_action_control_dflt(int *argc_p, char ***argv_p,
			       int *result_p, bool allow_num,
			       int default_result)
{
	if (__parse_action_control(argc_p, argv_p, result_p, allow_num, true))
		*result_p = default_result;
}

static int parse_action_control_slash_spaces(int *argc_p, char ***argv_p,
					     int *result1_p, int *result2_p,
					     bool allow_num)
{
	int argc = *argc_p;
	char **argv = *argv_p;
	int result1, result2;
	int *result_p = &result1;
	int ok = 0;
	int ret;

	while (argc > 0) {
		switch (ok) {
		case 1:
			if (strcmp(*argv, "/") != 0)
				goto out;
			result_p = &result2;
			NEXT_ARG();
			/* fall-through */
		case 0: /* fall-through */
		case 2:
			ret = parse_action_control(&argc, &argv,
						   result_p, allow_num);
			if (ret)
				return ret;
			ok++;
			break;
		default:
			goto out;
		}
	}
out:
	*result1_p = result1;
	if (ok == 2)
		*result2_p = result2;
	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

/* Parse action control with slash including possible options.
 *
 * Parameters:
 * @argc_p - pointer to argc to parse
 * @argv_p - pointer to argv to parse
 * @result1_p - pointer to the first (before slash) output variable
 * @result2_p - pointer to the second (after slash) output variable
 * @allow_num - whether action may be in numeric format already
 *
 * In error case, returns -1 and does not touch @result*. Otherwise returns 0.
 */
int parse_action_control_slash(int *argc_p, char ***argv_p,
			       int *result1_p, int *result2_p, bool allow_num)
{
	char **argv = *argv_p;
	int result1, result2;
	char *p = strchr(*argv, '/');

	if (!p)
		return parse_action_control_slash_spaces(argc_p, argv_p,
							 result1_p, result2_p,
							 allow_num);
	*p = 0;
	if (action_a2n(*argv, &result1, allow_num)) {
		if (p)
			*p = '/';
		return -1;
	}

	*p = '/';
	if (action_a2n(p + 1, &result2, allow_num))
		return -1;

	*result1_p = result1;
	*result2_p = result2;
	return 0;
}

void print_action_control(FILE *f, const char *prefix,
			  int action, const char *suffix)
{
	fprintf(f, "%s%s", prefix, action_n2a(action));
	if (TC_ACT_EXT_CMP(action, TC_ACT_GOTO_CHAIN))
		fprintf(f, " chain %u", action & TC_ACT_EXT_VAL_MASK);
	if (TC_ACT_EXT_CMP(action, TC_ACT_JUMP))
		fprintf(f, " %u", action & TC_ACT_EXT_VAL_MASK);
	fprintf(f, "%s", suffix);
}

int get_linklayer(unsigned int *val, const char *arg)
{
	int res;

	if (matches(arg, "ethernet") == 0)
		res = LINKLAYER_ETHERNET;
	else if (matches(arg, "atm") == 0)
		res = LINKLAYER_ATM;
	else if (matches(arg, "adsl") == 0)
		res = LINKLAYER_ATM;
	else
		return -1; /* Indicate error */

	*val = res;
	return 0;
}

void print_linklayer(char *buf, int len, unsigned int linklayer)
{
	switch (linklayer) {
	case LINKLAYER_UNSPEC:
		snprintf(buf, len, "%s", "unspec");
		return;
	case LINKLAYER_ETHERNET:
		snprintf(buf, len, "%s", "ethernet");
		return;
	case LINKLAYER_ATM:
		snprintf(buf, len, "%s", "atm");
		return;
	default:
		snprintf(buf, len, "%s", "unknown");
		return;
	}
}

char *sprint_linklayer(unsigned int linklayer, char *buf)
{
	print_linklayer(buf, SPRINT_BSIZE-1, linklayer);
	return buf;
}

void print_tm(FILE *f, const struct tcf_t *tm)
{
	int hz = get_user_hz();

	if (tm->install != 0)
		fprintf(f, " installed %u sec", (unsigned int)(tm->install/hz));
	if (tm->lastuse != 0)
		fprintf(f, " used %u sec", (unsigned int)(tm->lastuse/hz));
	if (tm->expires != 0)
		fprintf(f, " expires %u sec", (unsigned int)(tm->expires/hz));
}

void print_tcstats2_attr(FILE *fp, struct rtattr *rta, char *prefix, struct rtattr **xstats)
{
	SPRINT_BUF(b1);
	struct rtattr *tbs[TCA_STATS_MAX + 1];

	parse_rtattr_nested(tbs, TCA_STATS_MAX, rta);

	if (tbs[TCA_STATS_BASIC]) {
		struct gnet_stats_basic bs = {0};

		memcpy(&bs, RTA_DATA(tbs[TCA_STATS_BASIC]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_BASIC]), sizeof(bs)));
		fprintf(fp, "%sSent %llu bytes %u pkt",
			prefix, (unsigned long long) bs.bytes, bs.packets);
	}

	if (tbs[TCA_STATS_QUEUE]) {
		struct gnet_stats_queue q = {0};

		memcpy(&q, RTA_DATA(tbs[TCA_STATS_QUEUE]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_QUEUE]), sizeof(q)));
		fprintf(fp, " (dropped %u, overlimits %u requeues %u) ",
			q.drops, q.overlimits, q.requeues);
	}

	if (tbs[TCA_STATS_RATE_EST64]) {
		struct gnet_stats_rate_est64 re = {0};

		memcpy(&re, RTA_DATA(tbs[TCA_STATS_RATE_EST64]),
		       MIN(RTA_PAYLOAD(tbs[TCA_STATS_RATE_EST64]),
			   sizeof(re)));
		fprintf(fp, "\n%srate %s %llupps ",
			prefix, sprint_rate(re.bps, b1), re.pps);
	} else if (tbs[TCA_STATS_RATE_EST]) {
		struct gnet_stats_rate_est re = {0};

		memcpy(&re, RTA_DATA(tbs[TCA_STATS_RATE_EST]),
		       MIN(RTA_PAYLOAD(tbs[TCA_STATS_RATE_EST]), sizeof(re)));
		fprintf(fp, "\n%srate %s %upps ",
			prefix, sprint_rate(re.bps, b1), re.pps);
	}

	if (tbs[TCA_STATS_QUEUE]) {
		struct gnet_stats_queue q = {0};

		memcpy(&q, RTA_DATA(tbs[TCA_STATS_QUEUE]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_QUEUE]), sizeof(q)));
		if (!tbs[TCA_STATS_RATE_EST])
			fprintf(fp, "\n%s", prefix);
		fprintf(fp, "backlog %s %up requeues %u ",
			sprint_size(q.backlog, b1), q.qlen, q.requeues);
	}

	if (xstats)
		*xstats = tbs[TCA_STATS_APP] ? : NULL;
}

void print_tcstats_attr(FILE *fp, struct rtattr *tb[], char *prefix, struct rtattr **xstats)
{
	SPRINT_BUF(b1);

	if (tb[TCA_STATS2]) {
		print_tcstats2_attr(fp, tb[TCA_STATS2], prefix, xstats);
		if (xstats && NULL == *xstats)
			goto compat_xstats;
		return;
	}
	/* backward compatibility */
	if (tb[TCA_STATS]) {
		struct tc_stats st = {};

		/* handle case where kernel returns more/less than we know about */
		memcpy(&st, RTA_DATA(tb[TCA_STATS]), MIN(RTA_PAYLOAD(tb[TCA_STATS]), sizeof(st)));

		fprintf(fp, "%sSent %llu bytes %u pkts (dropped %u, overlimits %u) ",
			prefix, (unsigned long long)st.bytes, st.packets, st.drops,
			st.overlimits);

		if (st.bps || st.pps || st.qlen || st.backlog) {
			fprintf(fp, "\n%s", prefix);
			if (st.bps || st.pps) {
				fprintf(fp, "rate ");
				if (st.bps)
					fprintf(fp, "%s ", sprint_rate(st.bps, b1));
				if (st.pps)
					fprintf(fp, "%upps ", st.pps);
			}
			if (st.qlen || st.backlog) {
				fprintf(fp, "backlog ");
				if (st.backlog)
					fprintf(fp, "%s ", sprint_size(st.backlog, b1));
				if (st.qlen)
					fprintf(fp, "%up ", st.qlen);
			}
		}
	}

compat_xstats:
	if (tb[TCA_XSTATS] && xstats)
		*xstats = tb[TCA_XSTATS];
}
