int get_operstate(const char *name);
int print_linkinfo(const struct sockaddr_nl *who,
		   struct nlmsghdr *n, void *arg);
int print_linkinfo_brief(const struct sockaddr_nl *who,
			 struct nlmsghdr *n, void *arg);
int print_addrinfo(const struct sockaddr_nl *who,
		   struct nlmsghdr *n, void *arg);
int print_addrlabel(const struct sockaddr_nl *who,
		    struct nlmsghdr *n, void *arg);
int print_neigh(const struct sockaddr_nl *who,
	        struct nlmsghdr *n, void *arg);
int ipaddr_list_link(int argc, char **argv);
void ipaddr_get_vf_rate(int, int *, int *, int);
void iplink_usage(void) __attribute__((noreturn));

void iproute_reset_filter(int ifindex);
void ipmroute_reset_filter(int ifindex);
void ipaddr_reset_filter(int oneline, int ifindex);
void ipneigh_reset_filter(int ifindex);
void ipnetconf_reset_filter(int ifindex);

int print_route(const struct sockaddr_nl *who,
		struct nlmsghdr *n, void *arg);
int print_mroute(const struct sockaddr_nl *who,
		 struct nlmsghdr *n, void *arg);
int print_prefix(const struct sockaddr_nl *who,
		 struct nlmsghdr *n, void *arg);
int print_rule(const struct sockaddr_nl *who,
	       struct nlmsghdr *n, void *arg);
int print_netconf(const struct sockaddr_nl *who,
		  struct rtnl_ctrl_data *ctrl,
		  struct nlmsghdr *n, void *arg);
void netns_map_init(void);
int print_nsid(const struct sockaddr_nl *who,
	       struct nlmsghdr *n, void *arg);
int do_ipaddr(int argc, char **argv);
int do_ipaddrlabel(int argc, char **argv);
int do_iproute(int argc, char **argv);
int do_iprule(int argc, char **argv);
int do_ipneigh(int argc, char **argv);
int do_ipntable(int argc, char **argv);
int do_iptunnel(int argc, char **argv);
int do_ip6tunnel(int argc, char **argv);
int do_iptuntap(int argc, char **argv);
int do_iplink(int argc, char **argv);
int do_ipmonitor(int argc, char **argv);
int do_multiaddr(int argc, char **argv);
int do_multiroute(int argc, char **argv);
int do_multirule(int argc, char **argv);
int do_netns(int argc, char **argv);
int do_xfrm(int argc, char **argv);
int do_ipl2tp(int argc, char **argv);
int do_ipfou(int argc, char **argv);
int do_tcp_metrics(int argc, char **argv);
int do_ipnetconf(int argc, char **argv);
int do_iptoken(int argc, char **argv);
int iplink_get(unsigned int flags, char *name, __u32 filt_mask);

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;
	if (tb[RTA_TABLE])
		table = rta_getattr_u32(tb[RTA_TABLE]);
	return table;
}

extern struct rtnl_handle rth;

#include <stdbool.h>

struct link_util
{
	struct link_util	*next;
	const char		*id;
	int			maxattr;
	int			(*parse_opt)(struct link_util *, int, char **,
					     struct nlmsghdr *);
	void			(*print_opt)(struct link_util *, FILE *,
					     struct rtattr *[]);
	void			(*print_xstats)(struct link_util *, FILE *,
					     struct rtattr *);
	void			(*print_help)(struct link_util *, int, char **,
					     FILE *);
	bool			slave;
};

struct link_util *get_link_kind(const char *kind);
struct link_util *get_link_slave_kind(const char *slave_kind);

#ifndef	INFINITY_LIFE_TIME
#define     INFINITY_LIFE_TIME      0xFFFFFFFFU
#endif
