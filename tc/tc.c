/*
 * tc.c		"tc" utility frontend.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Fixes:
 *
 * Petri Mattila <petri@prihateam.fi> 990308: wrong memset's resulted in faults
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "SNAPSHOT.h"
#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"

int show_stats = 0;
int show_details = 0;
int show_raw = 0;
int resolve_hosts = 0;
int use_iec = 0;
struct rtnl_handle rth;

static void *BODY;	/* cached handle dlopen(NULL) */
static struct qdisc_util * qdisc_list;
static struct filter_util * filter_list;

static int print_noqopt(struct qdisc_util *qu, FILE *f, 
			struct rtattr *opt)
{
	if (opt && RTA_PAYLOAD(opt))
		fprintf(f, "[Unknown qdisc, optlen=%u] ", 
			(unsigned) RTA_PAYLOAD(opt));
	return 0;
}

static int parse_noqopt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	if (argc) {
		fprintf(stderr, "Unknown qdisc \"%s\", hence option \"%s\" is unparsable\n", qu->id, *argv);
		return -1;
	}
	return 0;
}

static int print_nofopt(struct filter_util *qu, FILE *f, struct rtattr *opt, __u32 fhandle)
{
	if (opt && RTA_PAYLOAD(opt))
		fprintf(f, "fh %08x [Unknown filter, optlen=%u] ", 
			fhandle, (unsigned) RTA_PAYLOAD(opt));
	else if (fhandle)
		fprintf(f, "fh %08x ", fhandle);
	return 0;
}

static int parse_nofopt(struct filter_util *qu, char *fhandle, int argc, char **argv, struct nlmsghdr *n)
{
	__u32 handle;

	if (argc) {
		fprintf(stderr, "Unknown filter \"%s\", hence option \"%s\" is unparsable\n", qu->id, *argv);
		return -1;
	}
	if (fhandle) {
		struct tcmsg *t = NLMSG_DATA(n);
		if (get_u32(&handle, fhandle, 16)) {
			fprintf(stderr, "Unparsable filter ID \"%s\"\n", fhandle);
			return -1;
		}
		t->tcm_handle = handle;
	}
	return 0;
}

struct qdisc_util *get_qdisc_kind(const char *str)
{
	void *dlh;
	char buf[256];
	struct qdisc_util *q;

	for (q = qdisc_list; q; q = q->next)
		if (strcmp(q->id, str) == 0)
			return q;

	snprintf(buf, sizeof(buf), "/usr/lib/tc/q_%s.so", str);
	dlh = dlopen(buf, RTLD_LAZY);
	if (!dlh) {
		/* look in current binary, only open once */
		dlh = BODY;
		if (dlh == NULL) {
			dlh = BODY = dlopen(NULL, RTLD_LAZY);
			if (dlh == NULL)
				goto noexist;
		}
	}

	snprintf(buf, sizeof(buf), "%s_qdisc_util", str);
	q = dlsym(dlh, buf);
	if (q == NULL)
		goto noexist;

reg:
	q->next = qdisc_list;
	qdisc_list = q;
	return q;

noexist:
	q = malloc(sizeof(*q));
	if (q) {

		memset(q, 0, sizeof(*q));
		q->id = strcpy(malloc(strlen(str)+1), str);
		q->parse_qopt = parse_noqopt;
		q->print_qopt = print_noqopt;
		goto reg;
	}
	return q;
}


struct filter_util *get_filter_kind(const char *str)
{
	void *dlh;
	char buf[256];
	struct filter_util *q;

	for (q = filter_list; q; q = q->next)
		if (strcmp(q->id, str) == 0)
			return q;

	snprintf(buf, sizeof(buf), "/usr/lib/tc/f_%s.so", str);
	dlh = dlopen(buf, RTLD_LAZY);
	if (dlh == NULL) {
		dlh = BODY;
		if (dlh == NULL) {
			dlh = BODY = dlopen(NULL, RTLD_LAZY);
			if (dlh == NULL)
				goto noexist;
		}
	}

	snprintf(buf, sizeof(buf), "%s_filter_util", str);
	q = dlsym(dlh, buf);
	if (q == NULL)
		goto noexist;

reg:
	q->next = filter_list;
	filter_list = q;
	return q;
noexist:
	q = malloc(sizeof(*q));
	if (q) {
		memset(q, 0, sizeof(*q));
		strncpy(q->id, str, 15);
		q->parse_fopt = parse_nofopt;
		q->print_fopt = print_nofopt;
		goto reg;
	}
	return q;
}

static void usage(void)
{
	fprintf(stderr, "Usage: tc [ OPTIONS ] OBJECT { COMMAND | help }\n"
	                "where  OBJECT := { qdisc | class | filter | action }\n"
	                "       OPTIONS := { -s[tatistics] | -d[etails] | -r[aw] | -b[atch] file }\n");
}

static int do_cmd(int argc, char **argv)
{
	if (matches(*argv, "qdisc") == 0)
		return do_qdisc(argc-1, argv+1);

	if (matches(*argv, "class") == 0)
		return do_class(argc-1, argv+1);

	if (matches(*argv, "filter") == 0)
		return do_filter(argc-1, argv+1);

	if (matches(*argv, "actions") == 0)
		return do_action(argc-1, argv+1);

	if (matches(*argv, "help") == 0) {
		usage();
		return 0;
	}
	
	fprintf(stderr, "Object \"%s\" is unknown, try \"tc help\".\n", 
		*argv);
	return -1;
}

static int makeargs(char *line, char *argv[], int maxargs)
{
	static const char ws[] = " \t\r\n";
	char *cp;
	int argc = 0;

	for (cp = strtok(line, ws); cp; cp = strtok(NULL, ws)) {
		if (argc >= maxargs) {
			fprintf(stderr, "Too many arguments to command\n");
			exit(1);
		}
		argv[argc++] = cp;
	}
	argv[argc] = NULL;

	return argc;
}

static int batch(const char *name)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t cc;
	int lineno = 0;
	char *largv[100];
	int largc, ret = 0;

	if (strcmp(name, "-") != 0) {
		if (freopen(name, "r", stdin) == NULL) {
			fprintf(stderr, "Cannot open file \"%s\" for reading: %s=n",
				name, strerror(errno));
			return -1;
		}
	}

	tc_core_init();

	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		return -1;
	}

	while ((cc = getline(&line, &len, stdin)) != -1) {
		++lineno;

		/* ignore blank lines and comments */
		if (*line == '\n' || *line == '#')
			continue;

		/* handle continuation lines */
		while (cc >= 2 && strcmp(line+cc-2, "\\\n") == 0) {
			char *line1 = NULL;
			ssize_t len1 = 0;
			int cc1;
			cc1 = getline(&line1, &len1, stdin);

			if (cc1 < 0) {
				fprintf(stderr, "Missing continuation line\n");
				return -1;
			}
			++lineno;
			line = realloc(line, cc + cc1);
			if (!line) {
				fprintf(stderr, "Out of memory\n");
				return -1;
			}

			strcpy(line+cc-2, line1);
			cc += cc1 - 2;
			free(line1);
		}

		largc = makeargs(line, largv, 100);

		ret = do_cmd(largc, largv);
		if (ret) {
			fprintf(stderr, "Command failed %s:%d\n", name, lineno);
			break;
		}
	}

	rtnl_close(&rth);
	return ret;
}


int main(int argc, char **argv)
{
	int ret;

	while (argc > 1) {
		if (argv[1][0] != '-')
			break;
		if (matches(argv[1], "-stats") == 0 ||
			 matches(argv[1], "-statistics") == 0) {
			++show_stats;
		} else if (matches(argv[1], "-details") == 0) {
			++show_details;
		} else if (matches(argv[1], "-raw") == 0) {
			++show_raw;
		} else if (matches(argv[1], "-Version") == 0) {
			printf("tc utility, iproute2-ss%s\n", SNAPSHOT);
			return 0;
		} else if (matches(argv[1], "-iec") == 0) {
			++use_iec;
		} else if (matches(argv[1], "-help") == 0) {
			usage();
			return 0;
		} else 	if (matches(argv[1], "-batch") == 0) {
			if (argc < 3) {
				fprintf(stderr, "Wrong number of arguments in batch mode\n");
				return -1;
			}

			return batch(argv[2]);
		} else {
			fprintf(stderr, "Option \"%s\" is unknown, try \"tc -help\".\n", argv[1]);
			return -1;
		}
		argc--;	argv++;
	}

	if (argc <= 1) {
		usage();
		return 0;
	}

	tc_core_init();
	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		exit(1);
	}

	ret = do_cmd(argc-1, argv+1);
	rtnl_close(&rth);

	return ret;
}
