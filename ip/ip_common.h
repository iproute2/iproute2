#ifndef _IP_COMMON_H_
#define _IP_COMMON_H_

#include <stdbool.h>

#include "json_print.h"

struct link_filter {
	int ifindex;
	int family;
	int oneline;
	int showqueue;
	inet_prefix pfx;
	int scope, scopemask;
	int flags, flagmask;
	int up;
	char *label;
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
	int group;
	int master;
	char *kind;
	char *slave_kind;
};

int get_operstate(const char *name);
int print_linkinfo(const struct sockaddr_nl *who,
		   struct nlmsghdr *n, void *arg);
int print_linkinfo_brief(const struct sockaddr_nl *who,
			 struct nlmsghdr *n, void *arg,
			 struct link_filter *filter);
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
void netns_nsid_socket_init(void);
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
int do_ipmacsec(int argc, char **argv);
int do_ipmonitor(int argc, char **argv);
int do_multiaddr(int argc, char **argv);
int do_multiroute(int argc, char **argv);
int do_multirule(int argc, char **argv);
int do_netns(int argc, char **argv);
int do_xfrm(int argc, char **argv);
int do_ipl2tp(int argc, char **argv);
int do_ipfou(int argc, char **argv);
extern int do_ipila(int argc, char **argv);
int do_tcp_metrics(int argc, char **argv);
int do_ipnetconf(int argc, char **argv);
int do_iptoken(int argc, char **argv);
int do_ipvrf(int argc, char **argv);
void vrf_reset(void);
int netns_identify_pid(const char *pidstr, char *name, int len);
int do_seg6(int argc, char **argv);

int iplink_get(unsigned int flags, char *name, __u32 filt_mask);
int iplink_ifla_xstats(int argc, char **argv);

int ip_linkaddr_list(int family, req_filter_fn_t filter_fn,
		     struct nlmsg_chain *linfo, struct nlmsg_chain *ainfo);
void free_nlmsg_chain(struct nlmsg_chain *info);

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;

	if (tb[RTA_TABLE])
		table = rta_getattr_u32(tb[RTA_TABLE]);
	return table;
}

extern struct rtnl_handle rth;

struct link_util {
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
	int			(*parse_ifla_xstats)(struct link_util *,
						     int, char **);
	int			(*print_ifla_xstats)(const struct sockaddr_nl *,
						     struct nlmsghdr *, void *);
};

struct link_util *get_link_kind(const char *kind);

void br_dump_bridge_id(const struct ifla_bridge_id *id, char *buf, size_t len);
int bridge_parse_xstats(struct link_util *lu, int argc, char **argv);
int bridge_print_xstats(const struct sockaddr_nl *who,
			struct nlmsghdr *n, void *arg);

__u32 ipvrf_get_table(const char *name);
int name_is_vrf(const char *name);

#ifndef	INFINITY_LIFE_TIME
#define     INFINITY_LIFE_TIME      0xFFFFFFFFU
#endif

#ifndef LABEL_MAX_MASK
#define     LABEL_MAX_MASK          0xFFFFFU
#endif

void print_num(FILE *fp, unsigned int width, uint64_t count);

#endif /* _IP_COMMON_H_ */
