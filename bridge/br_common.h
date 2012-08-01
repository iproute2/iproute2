extern int print_linkinfo(const struct sockaddr_nl *who,
			  struct nlmsghdr *n,
			  void *arg);
extern int print_fdb(const struct sockaddr_nl *who,
		     struct nlmsghdr *n, void *arg);

extern int do_fdb(int argc, char **argv);
extern int do_monitor(int argc, char **argv);

extern int show_stats;
extern int show_detail;
extern int timestamp;
extern struct rtnl_handle rth;
