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
#include "namespace.h"

int show_stats;
int show_details;
int show_raw;
int show_graph;
int timestamp;

int batch_mode;
int use_iec;
int force;
bool use_names;
int json;
int color;
int oneline;

static char *conf_file;

struct rtnl_handle rth;

static void *BODY;	/* cached handle dlopen(NULL) */
static struct qdisc_util *qdisc_list;
static struct filter_util *filter_list;

static int print_noqopt(struct qdisc_util *qu, FILE *f,
			struct rtattr *opt)
{
	if (opt && RTA_PAYLOAD(opt))
		fprintf(f, "[Unknown qdisc, optlen=%u] ",
			(unsigned int) RTA_PAYLOAD(opt));
	return 0;
}

static int parse_noqopt(struct qdisc_util *qu, int argc, char **argv,
			struct nlmsghdr *n, const char *dev)
{
	if (argc) {
		fprintf(stderr,
			"Unknown qdisc \"%s\", hence option \"%s\" is unparsable\n",
			qu->id, *argv);
		return -1;
	}
	return 0;
}

static int print_nofopt(struct filter_util *qu, FILE *f, struct rtattr *opt, __u32 fhandle)
{
	if (opt && RTA_PAYLOAD(opt))
		fprintf(f, "fh %08x [Unknown filter, optlen=%u] ",
			fhandle, (unsigned int) RTA_PAYLOAD(opt));
	else if (fhandle)
		fprintf(f, "fh %08x ", fhandle);
	return 0;
}

static int parse_nofopt(struct filter_util *qu, char *fhandle,
			int argc, char **argv, struct nlmsghdr *n)
{
	__u32 handle;

	if (argc) {
		fprintf(stderr,
			"Unknown filter \"%s\", hence option \"%s\" is unparsable\n",
			qu->id, *argv);
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

	snprintf(buf, sizeof(buf), "%s/q_%s.so", get_tc_lib(), str);
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
	q = calloc(1, sizeof(*q));
	if (q) {
		q->id = strdup(str);
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

	snprintf(buf, sizeof(buf), "%s/f_%s.so", get_tc_lib(), str);
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
	q = calloc(1, sizeof(*q));
	if (q) {
		strncpy(q->id, str, 15);
		q->parse_fopt = parse_nofopt;
		q->print_fopt = print_nofopt;
		goto reg;
	}
	return q;
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: tc [ OPTIONS ] OBJECT { COMMAND | help }\n"
		"       tc [-force] -batch filename\n"
		"where  OBJECT := { qdisc | class | filter | chain |\n"
		"                   action | monitor | exec }\n"
		"       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | -r[aw] |\n"
		"                    -o[neline] | -j[son] | -p[retty] | -c[olor]\n"
		"                    -b[atch] [filename] | -n[etns] name |\n"
		"                    -nm | -nam[es] | { -cf | -conf } path }\n");
}

static int do_cmd(int argc, char **argv, void *buf, size_t buflen)
{
	if (matches(*argv, "qdisc") == 0)
		return do_qdisc(argc-1, argv+1);
	if (matches(*argv, "class") == 0)
		return do_class(argc-1, argv+1);
	if (matches(*argv, "filter") == 0)
		return do_filter(argc-1, argv+1, buf, buflen);
	if (matches(*argv, "chain") == 0)
		return do_chain(argc-1, argv+1, buf, buflen);
	if (matches(*argv, "actions") == 0)
		return do_action(argc-1, argv+1, buf, buflen);
	if (matches(*argv, "monitor") == 0)
		return do_tcmonitor(argc-1, argv+1);
	if (matches(*argv, "exec") == 0)
		return do_exec(argc-1, argv+1);
	if (matches(*argv, "help") == 0) {
		usage();
		return 0;
	}

	fprintf(stderr, "Object \"%s\" is unknown, try \"tc help\".\n",
		*argv);
	return -1;
}

#define TC_MAX_SUBC	10
static bool batchsize_enabled(int argc, char *argv[])
{
	struct {
		char *c;
		char *subc[TC_MAX_SUBC];
	} table[] = {
		{ "filter", { "add", "delete", "change", "replace", NULL} },
		{ "actions", { "add", "change", "replace", NULL} },
		{ NULL },
	}, *iter;
	char *s;
	int i;

	if (argc < 2)
		return false;

	for (iter = table; iter->c; iter++) {
		if (matches(argv[0], iter->c))
			continue;
		for (i = 0; i < TC_MAX_SUBC; i++) {
			s = iter->subc[i];
			if (s && matches(argv[1], s) == 0)
				return true;
		}
	}

	return false;
}

struct batch_buf {
	struct batch_buf	*next;
	char			buf[16420];	/* sizeof (struct nlmsghdr) +
						   max(sizeof (struct tcmsg) +
						   sizeof (struct tcamsg)) +
						   MAX_MSG */
};

static struct batch_buf *get_batch_buf(struct batch_buf **pool,
				       struct batch_buf **head,
				       struct batch_buf **tail)
{
	struct batch_buf *buf;

	if (*pool == NULL)
		buf = calloc(1, sizeof(struct batch_buf));
	else {
		buf = *pool;
		*pool = (*pool)->next;
		memset(buf, 0, sizeof(struct batch_buf));
	}

	if (*head == NULL)
		*head = *tail = buf;
	else {
		(*tail)->next = buf;
		(*tail) = buf;
	}

	return buf;
}

static void put_batch_bufs(struct batch_buf **pool,
			   struct batch_buf **head,
			   struct batch_buf **tail)
{
	if (*head == NULL || *tail == NULL)
		return;

	if (*pool == NULL)
		*pool = *head;
	else {
		(*tail)->next = *pool;
		*pool = *head;
	}
	*head = NULL;
	*tail = NULL;
}

static void free_batch_bufs(struct batch_buf **pool)
{
	struct batch_buf *buf;

	for (buf = *pool; buf != NULL; buf = *pool) {
		*pool = buf->next;
		free(buf);
	}
	*pool = NULL;
}

static int batch(const char *name)
{
	struct batch_buf *head = NULL, *tail = NULL, *buf_pool = NULL;
	char *largv[100], *largv_next[100];
	char *line, *line_next = NULL;
	bool bs_enabled = false;
	bool lastline = false;
	int largc, largc_next;
	bool bs_enabled_saved;
	bool bs_enabled_next;
	int batchsize = 0;
	size_t len = 0;
	int ret = 0;
	int err;
	bool send;

	batch_mode = 1;
	if (name && strcmp(name, "-") != 0) {
		if (freopen(name, "r", stdin) == NULL) {
			fprintf(stderr,
				"Cannot open file \"%s\" for reading: %s\n",
				name, strerror(errno));
			return -1;
		}
	}

	tc_core_init();

	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		return -1;
	}

	cmdlineno = 0;
	if (getcmdline(&line, &len, stdin) == -1)
		goto Exit;
	largc = makeargs(line, largv, 100);
	bs_enabled = batchsize_enabled(largc, largv);
	do {
		if (getcmdline(&line_next, &len, stdin) == -1)
			lastline = true;

		largc_next = makeargs(line_next, largv_next, 100);
		bs_enabled_next = batchsize_enabled(largc_next, largv_next);
		if (bs_enabled) {
			struct batch_buf *buf;

			buf = get_batch_buf(&buf_pool, &head, &tail);
			if (!buf) {
				fprintf(stderr,
					"failed to allocate batch_buf\n");
				return -1;
			}
			++batchsize;
		}

		/*
		 * In batch mode, if we haven't accumulated enough commands
		 * and this is not the last command and this command & next
		 * command both support the batchsize feature, don't send the
		 * message immediately.
		 */
		if (!lastline && bs_enabled && bs_enabled_next
		    && batchsize != MSG_IOV_MAX)
			send = false;
		else
			send = true;

		line = line_next;
		line_next = NULL;
		len = 0;
		bs_enabled_saved = bs_enabled;
		bs_enabled = bs_enabled_next;

		if (largc == 0) {
			largc = largc_next;
			memcpy(largv, largv_next, largc * sizeof(char *));
			continue;	/* blank line */
		}

		err = do_cmd(largc, largv, tail == NULL ? NULL : tail->buf,
			     tail == NULL ? 0 : sizeof(tail->buf));
		fflush(stdout);
		if (err != 0) {
			fprintf(stderr, "Command failed %s:%d\n", name,
				cmdlineno - 1);
			ret = 1;
			if (!force)
				break;
		}
		largc = largc_next;
		memcpy(largv, largv_next, largc * sizeof(char *));

		if (send && bs_enabled_saved) {
			struct iovec *iov, *iovs;
			struct batch_buf *buf;
			struct nlmsghdr *n;

			iov = iovs = malloc(batchsize * sizeof(struct iovec));
			for (buf = head; buf != NULL; buf = buf->next, ++iov) {
				n = (struct nlmsghdr *)&buf->buf;
				iov->iov_base = n;
				iov->iov_len = n->nlmsg_len;
			}

			err = rtnl_talk_iov(&rth, iovs, batchsize, NULL);
			put_batch_bufs(&buf_pool, &head, &tail);
			free(iovs);
			if (err < 0) {
				fprintf(stderr, "Command failed %s:%d\n", name,
					cmdlineno - (batchsize + err) - 1);
				ret = 1;
				if (!force)
					break;
			}
			batchsize = 0;
		}
	} while (!lastline);

	free_batch_bufs(&buf_pool);
Exit:
	free(line);
	rtnl_close(&rth);

	return ret;
}


int main(int argc, char **argv)
{
	int ret;
	char *batch_file = NULL;

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
		} else if (matches(argv[1], "-pretty") == 0) {
			++pretty;
		} else if (matches(argv[1], "-graph") == 0) {
			show_graph = 1;
		} else if (matches(argv[1], "-Version") == 0) {
			printf("tc utility, iproute2-ss%s\n", SNAPSHOT);
			return 0;
		} else if (matches(argv[1], "-iec") == 0) {
			++use_iec;
		} else if (matches(argv[1], "-help") == 0) {
			usage();
			return 0;
		} else if (matches(argv[1], "-force") == 0) {
			++force;
		} else if (matches(argv[1], "-batch") == 0) {
			argc--;	argv++;
			if (argc <= 1)
				usage();
			batch_file = argv[1];
		} else if (matches(argv[1], "-netns") == 0) {
			NEXT_ARG();
			if (netns_switch(argv[1]))
				return -1;
		} else if (matches(argv[1], "-names") == 0 ||
				matches(argv[1], "-nm") == 0) {
			use_names = true;
		} else if (matches(argv[1], "-cf") == 0 ||
				matches(argv[1], "-conf") == 0) {
			NEXT_ARG();
			conf_file = argv[1];
		} else if (matches_color(argv[1], &color)) {
		} else if (matches(argv[1], "-timestamp") == 0) {
			timestamp++;
		} else if (matches(argv[1], "-tshort") == 0) {
			++timestamp;
			++timestamp_short;
		} else if (matches(argv[1], "-json") == 0) {
			++json;
		} else if (matches(argv[1], "-oneline") == 0) {
			++oneline;
		} else {
			fprintf(stderr,
				"Option \"%s\" is unknown, try \"tc -help\".\n",
				argv[1]);
			return -1;
		}
		argc--;	argv++;
	}

	_SL_ = oneline ? "\\" : "\n";

	check_enable_color(color, json);

	if (batch_file)
		return batch(batch_file);

	if (argc <= 1) {
		usage();
		return 0;
	}

	tc_core_init();
	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		exit(1);
	}

	if (use_names && cls_names_init(conf_file)) {
		ret = -1;
		goto Exit;
	}

	ret = do_cmd(argc-1, argv+1, NULL, 0);
Exit:
	rtnl_close(&rth);

	if (use_names)
		cls_names_uninit();

	return ret;
}
