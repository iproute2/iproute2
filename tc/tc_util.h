#ifndef _TC_UTIL_H_
#define _TC_UTIL_H_ 1

#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include "tc_core.h"

struct qdisc_util
{
	struct qdisc_util *next;
	char	id[16];
	int	(*parse_qopt)(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n);
	int	(*print_qopt)(struct qdisc_util *qu, FILE *f, struct rtattr *opt);
	int 	(*print_xstats)(struct qdisc_util *qu, FILE *f, struct rtattr *xstats);

	int	(*parse_copt)(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n);
	int	(*print_copt)(struct qdisc_util *qu, FILE *f, struct rtattr *opt);
};

struct filter_util
{
	struct filter_util *next;
	char	id[16];
	int	(*parse_fopt)(struct filter_util *qu, char *fhandle, int argc, char **argv, struct nlmsghdr *n);
	int	(*print_fopt)(struct filter_util *qu, FILE *f, struct rtattr *opt, __u32 fhandle);
};


extern struct qdisc_util *get_qdisc_kind(char *str);
extern struct filter_util *get_filter_kind(char *str);

extern int get_qdisc_handle(__u32 *h, char *str);
extern int get_rate(unsigned *rate, char *str);
extern int get_size(unsigned *size, char *str);
extern int get_size_and_cell(unsigned *size, int *cell_log, char *str);
extern int get_usecs(unsigned *usecs, char *str);
extern int print_rate(char *buf, int len, __u32 rate);
extern int print_size(char *buf, int len, __u32 size);
extern int print_qdisc_handle(char *buf, int len, __u32 h);
extern int print_usecs(char *buf, int len, __u32 usecs);
extern char * sprint_rate(__u32 rate, char *buf);
extern char * sprint_size(__u32 size, char *buf);
extern char * sprint_qdisc_handle(__u32 h, char *buf);
extern char * sprint_tc_classid(__u32 h, char *buf);
extern char * sprint_usecs(__u32 usecs, char *buf);

extern void print_tcstats(FILE *fp, struct tc_stats *st);

extern int get_tc_classid(__u32 *h, char *str);
extern int print_tc_classid(char *buf, int len, __u32 h);
extern char * sprint_tc_classid(__u32 h, char *buf);

extern int tc_print_police(FILE *f, struct rtattr *tb);
extern int parse_police(int *, char ***, int, struct nlmsghdr *);


#endif
