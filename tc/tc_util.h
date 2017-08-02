#ifndef _TC_UTIL_H_
#define _TC_UTIL_H_ 1

#define MAX_MSG 16384
#include <limits.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/gen_stats.h>
#include "tc_core.h"

/* This is the deprecated multiqueue interface */
#ifndef TCA_PRIO_MAX
enum
{
	TCA_PRIO_UNSPEC,
	TCA_PRIO_MQ,
	__TCA_PRIO_MAX
};

#define TCA_PRIO_MAX    (__TCA_PRIO_MAX - 1)
#endif

struct qdisc_util {
	struct  qdisc_util *next;
	const char *id;
	int (*parse_qopt)(struct qdisc_util *qu, int argc,
			  char **argv, struct nlmsghdr *n);
	int (*print_qopt)(struct qdisc_util *qu,
			  FILE *f, struct rtattr *opt);
	int (*print_xstats)(struct qdisc_util *qu,
			    FILE *f, struct rtattr *xstats);

	int (*parse_copt)(struct qdisc_util *qu, int argc,
			  char **argv, struct nlmsghdr *n);
	int (*print_copt)(struct qdisc_util *qu, FILE *f, struct rtattr *opt);
};

extern __u16 f_proto;
struct filter_util {
	struct filter_util *next;
	char id[16];
	int (*parse_fopt)(struct filter_util *qu, char *fhandle,
			  int argc, char **argv, struct nlmsghdr *n);
	int (*print_fopt)(struct filter_util *qu,
			  FILE *f, struct rtattr *opt, __u32 fhandle);
};

struct action_util {
	struct action_util *next;
	char id[16];
	int (*parse_aopt)(struct action_util *a, int *argc,
			  char ***argv, int code, struct nlmsghdr *n);
	int (*print_aopt)(struct action_util *au, FILE *f, struct rtattr *opt);
	int (*print_xstats)(struct action_util *au,
			    FILE *f, struct rtattr *xstats);
};

struct exec_util {
	struct exec_util *next;
	char id[16];
	int (*parse_eopt)(struct exec_util *eu, int argc, char **argv);
};

const char *get_tc_lib(void);

struct qdisc_util *get_qdisc_kind(const char *str);
struct filter_util *get_filter_kind(const char *str);

int get_qdisc_handle(__u32 *h, const char *str);
int get_rate(unsigned int *rate, const char *str);
int get_rate64(__u64 *rate, const char *str);
int get_size(unsigned int *size, const char *str);
int get_size_and_cell(unsigned int *size, int *cell_log, char *str);
int get_time(unsigned int *time, const char *str);
int get_linklayer(unsigned int *val, const char *arg);

void print_rate(char *buf, int len, __u64 rate);
void print_size(char *buf, int len, __u32 size);
void print_qdisc_handle(char *buf, int len, __u32 h);
void print_time(char *buf, int len, __u32 time);
void print_linklayer(char *buf, int len, unsigned int linklayer);

char *sprint_rate(__u64 rate, char *buf);
char *sprint_size(__u32 size, char *buf);
char *sprint_qdisc_handle(__u32 h, char *buf);
char *sprint_tc_classid(__u32 h, char *buf);
char *sprint_time(__u32 time, char *buf);
char *sprint_ticks(__u32 ticks, char *buf);
char *sprint_linklayer(unsigned int linklayer, char *buf);

void print_tcstats_attr(FILE *fp, struct rtattr *tb[],
			char *prefix, struct rtattr **xstats);
void print_tcstats2_attr(FILE *fp, struct rtattr *rta,
			 char *prefix, struct rtattr **xstats);

int get_tc_classid(__u32 *h, const char *str);
int print_tc_classid(char *buf, int len, __u32 h);
char *sprint_tc_classid(__u32 h, char *buf);

int tc_print_police(FILE *f, struct rtattr *tb);
int parse_police(int *argc_p, char ***argv_p, int tca_id, struct nlmsghdr *n);

int parse_action_control(int *argc_p, char ***argv_p,
			 int *result_p, bool allow_num);
void parse_action_control_dflt(int *argc_p, char ***argv_p,
			       int *result_p, bool allow_num,
			       int default_result);
int parse_action_control_slash(int *argc_p, char ***argv_p,
			       int *result1_p, int *result2_p, bool allow_num);
void print_action_control(FILE *f, const char *prefix,
			  int action, const char *suffix);
int act_parse_police(struct action_util *a, int *argc_p,
		     char ***argv_p, int tca_id, struct nlmsghdr *n);
int print_police(struct action_util *a, FILE *f, struct rtattr *tb);
int police_print_xstats(struct action_util *a, FILE *f, struct rtattr *tb);
int tc_print_action(FILE *f, const struct rtattr *tb, unsigned short tot_acts);
int tc_print_ipt(FILE *f, const struct rtattr *tb);
int parse_action(int *argc_p, char ***argv_p, int tca_id, struct nlmsghdr *n);
void print_tm(FILE *f, const struct tcf_t *tm);
int prio_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt);

int cls_names_init(char *path);
void cls_names_uninit(void);

#endif
