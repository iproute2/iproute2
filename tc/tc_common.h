
#define TCA_BUF_MAX	(64*1024)

extern int do_qdisc(int argc, char **argv);
extern int do_class(int argc, char **argv);
extern int do_filter(int argc, char **argv);
extern int do_action(int argc, char **argv);

extern int parse_estimator(int *p_argc, char ***p_argv, struct tc_estimator *est);
