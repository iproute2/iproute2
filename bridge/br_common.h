#define MDB_RTA(r) \
		((struct rtattr *)(((char *)(r)) + RTA_ALIGN(sizeof(struct br_mdb_entry))))

#define MDB_RTR_RTA(r) \
		((struct rtattr *)(((char *)(r)) + RTA_ALIGN(sizeof(__u32))))

extern void print_vlan_info(FILE *fp, struct rtattr *tb, int ifindex);
extern int print_linkinfo(const struct sockaddr_nl *who,
			  struct nlmsghdr *n,
			  void *arg);
extern int print_fdb(const struct sockaddr_nl *who,
		     struct nlmsghdr *n, void *arg);
extern int print_mdb(const struct sockaddr_nl *who,
		     struct nlmsghdr *n, void *arg);

extern int do_fdb(int argc, char **argv);
extern int do_mdb(int argc, char **argv);
extern int do_monitor(int argc, char **argv);
extern int do_vlan(int argc, char **argv);
extern int do_link(int argc, char **argv);

extern int preferred_family;
extern int show_stats;
extern int show_details;
extern int timestamp;
extern int compress_vlans;
extern int json_output;
extern struct rtnl_handle rth;
