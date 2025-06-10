/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _IP_COMMON_H_
#define _IP_COMMON_H_

#include <stdbool.h>
#include <linux/mpls.h>

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
	int down;
	char *label;
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
	int group;
	int master;
	char *kind;
	char *slave_kind;
	int target_nsid;
	bool have_proto;
	int proto;
	int vfinfo;
};

const char *get_ip_lib_dir(void);

int get_operstate(const char *name);
int print_linkinfo(struct nlmsghdr *n, void *arg);
int print_addrinfo(struct nlmsghdr *n, void *arg);
int print_addrlabel(struct nlmsghdr *n, void *arg);
int print_neigh(struct nlmsghdr *n, void *arg);
int ipaddr_list_link(int argc, char **argv);
void ipaddr_get_vf_rate(int, int *, int *, const char *);
void iplink_usage(void) __attribute__((noreturn));
void iplink_types_usage(void);

void iproute_reset_filter(int ifindex);
void ipmroute_reset_filter(int ifindex);
void ipaddr_reset_filter(int oneline, int ifindex);
void ipneigh_reset_filter(int ifindex);
void ipnetconf_reset_filter(int ifindex);

int print_route(struct nlmsghdr *n, void *arg);
int print_mroute(struct nlmsghdr *n, void *arg);
int print_prefix(struct nlmsghdr *n, void *arg);
int print_rule(struct nlmsghdr *n, void *arg);
int print_netconf(struct rtnl_ctrl_data *ctrl,
		  struct nlmsghdr *n, void *arg);
int print_nexthop_bucket(struct nlmsghdr *n, void *arg);
void netns_map_init(void);
void netns_nsid_socket_init(void);
int print_nsid(struct nlmsghdr *n, void *arg);
int ipstats_print(struct nlmsghdr *n, void *arg);
char *get_name_from_nsid(int nsid);
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
int do_ipila(int argc, char **argv);
int do_tcp_metrics(int argc, char **argv);
int do_ipnetconf(int argc, char **argv);
int do_iptoken(int argc, char **argv);
int do_ipvrf(int argc, char **argv);
void vrf_reset(void);
int netns_identify_pid(const char *pidstr, char *name, int len);
int do_seg6(int argc, char **argv);
int do_ipnh(int argc, char **argv);
int do_mptcp(int argc, char **argv);
int do_ioam6(int argc, char **argv);
int do_ipstats(int argc, char **argv);

int iplink_get(char *name, __u32 filt_mask);
int iplink_ifla_xstats(int argc, char **argv);

int ip_link_list(req_filter_fn_t filter_fn, struct nlmsg_chain *linfo);
void free_nlmsg_chain(struct nlmsg_chain *info);

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;

	if (tb[RTA_TABLE])
		table = rta_getattr_u32(tb[RTA_TABLE]);
	return table;
}

extern struct rtnl_handle rth;

struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char			buf[1024];
};

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
	int			(*print_ifla_xstats)(struct nlmsghdr *, void *);
};

struct link_util *get_link_kind(const char *kind);

int iplink_parse(int argc, char **argv, struct iplink_req *req, char **type);

/* iplink_bridge.c */
void br_dump_bridge_id(const struct ifla_bridge_id *id, char *buf, size_t len);
int bridge_parse_xstats(struct link_util *lu, int argc, char **argv);
int bridge_print_xstats(struct nlmsghdr *n, void *arg);
extern const struct ipstats_stat_desc ipstats_stat_desc_xstats_bridge_group;
extern const struct ipstats_stat_desc ipstats_stat_desc_xstats_slave_bridge_group;

/* iplink_bond.c */
int bond_parse_xstats(struct link_util *lu, int argc, char **argv);
int bond_print_xstats(struct nlmsghdr *n, void *arg);
extern const struct ipstats_stat_desc ipstats_stat_desc_xstats_bond_group;
extern const struct ipstats_stat_desc ipstats_stat_desc_xstats_slave_bond_group;

/* iproute_lwtunnel.c */
int lwt_parse_encap(struct rtattr *rta, size_t len, int *argcp, char ***argvp,
		    int encap_attr, int encap_type_attr);
void lwt_print_encap(FILE *fp, struct rtattr *encap_type, struct rtattr *encap);

/* iplink_xdp.c */
int xdp_parse(int *argc, char ***argv, struct iplink_req *req, const char *ifname,
	      bool generic, bool drv, bool offload);
void xdp_dump(FILE *fp, struct rtattr *tb, bool link, bool details);

/* iplink_vrf.c */
__u32 ipvrf_get_table(const char *name);
int name_is_vrf(const char *name);

/* ipstats.c */
enum ipstats_stat_desc_kind {
	IPSTATS_STAT_DESC_KIND_LEAF,
	IPSTATS_STAT_DESC_KIND_GROUP,
};

struct ipstats_stat_dump_filters;
struct ipstats_stat_show_attrs;

struct ipstats_stat_desc {
	const char *name;
	enum ipstats_stat_desc_kind kind;
	union {
		struct {
			const struct ipstats_stat_desc **subs;
			size_t nsubs;
		};
		struct {
			void (*pack)(struct ipstats_stat_dump_filters *filters,
				     const struct ipstats_stat_desc *desc);
			int (*show)(struct ipstats_stat_show_attrs *attrs,
				    const struct ipstats_stat_desc *desc);
		};
	};
};

struct ipstats_stat_desc_xstats {
	const struct ipstats_stat_desc desc;
	int xstats_at;
	int link_type_at;
	int inner_at;
	void (*show_cb)(const struct rtattr *at);
};

void ipstats_stat_desc_pack_xstats(struct ipstats_stat_dump_filters *filters,
				   const struct ipstats_stat_desc *desc);
int ipstats_stat_desc_show_xstats(struct ipstats_stat_show_attrs *attrs,
				  const struct ipstats_stat_desc *desc);

#define IPSTATS_STAT_DESC_XSTATS_LEAF(NAME) {		\
		.name = (NAME),				\
		.kind = IPSTATS_STAT_DESC_KIND_LEAF,	\
		.show = &ipstats_stat_desc_show_xstats,	\
		.pack = &ipstats_stat_desc_pack_xstats,	\
	}

#ifndef	INFINITY_LIFE_TIME
#define     INFINITY_LIFE_TIME      0xFFFFFFFFU
#endif

#ifndef LABEL_MAX_MASK
#define     LABEL_MAX_MASK          0xFFFFFU
#endif

void print_rt_flags(FILE *fp, unsigned int flags);
void print_rta_ifidx(FILE *fp, __u32 ifidx, const char *prefix);
void __print_rta_gateway(FILE *fp, unsigned char family, const char *gateway);
void size_columns(unsigned int cols[], unsigned int n, ...);
void print_stats64(FILE *fp, struct rtnl_link_stats64 *s,
		   const struct rtattr *carrier_changes, const char *what);
void print_mpls_link_stats(FILE *fp, const struct mpls_link_stats *stats,
			   const char *indent);
void print_headers(FILE *fp, const char *label);
#endif /* _IP_COMMON_H_ */
