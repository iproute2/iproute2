/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Get mdb table with netlink
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <limits.h>

#include "libnetlink.h"
#include "utils.h"
#include "br_common.h"
#include "rt_names.h"
#include "json_print.h"

#ifndef MDBA_RTA
#define MDBA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct br_port_msg))))
#endif

static unsigned int filter_index, filter_vlan;

static void usage(void)
{
	fprintf(stderr,
		"Usage: bridge mdb { add | del | replace } dev DEV port PORT grp GROUP [src SOURCE] [permanent | temp] [vid VID]\n"
		"              [ filter_mode { include | exclude } ] [ source_list SOURCE_LIST ] [ proto PROTO ] [ dst IPADDR ]\n"
		"              [ dst_port DST_PORT ] [ vni VNI ] [ src_vni SRC_VNI ] [ via DEV ]\n"
		"       bridge mdb {show} [ dev DEV ] [ vid VID ]\n"
		"       bridge mdb get dev DEV grp GROUP [ src SOURCE ] [ vid VID ] [ src_vni SRC_VNI ]\n"
		"       bridge mdb flush dev DEV [ port PORT ] [ vid VID ] [ src_vni SRC_VNI ] [ proto PROTO ]\n"
		"              [ [no]permanent ] [ dst IPADDR ] [ dst_port DST_PORT ] [ vni VNI ]\n");
	exit(-1);
}

static bool is_temp_mcast_rtr(__u8 type)
{
	return type == MDB_RTR_TYPE_TEMP_QUERY || type == MDB_RTR_TYPE_TEMP;
}

static const char *format_timer(__u32 ticks, int align)
{
	struct timeval tv;
	static char tbuf[32];

	__jiffies_to_tv(&tv, ticks);
	if (align)
		snprintf(tbuf, sizeof(tbuf), "%4lu.%.2lu",
			 (unsigned long)tv.tv_sec,
			 (unsigned long)tv.tv_usec / 10000);
	else
		snprintf(tbuf, sizeof(tbuf), "%lu.%.2lu",
			 (unsigned long)tv.tv_sec,
			 (unsigned long)tv.tv_usec / 10000);

	return tbuf;
}

void br_print_router_port_stats(struct rtattr *pattr)
{
	struct rtattr *tb[MDBA_ROUTER_PATTR_MAX + 1];

	parse_rtattr(tb, MDBA_ROUTER_PATTR_MAX, MDB_RTR_RTA(RTA_DATA(pattr)),
		     RTA_PAYLOAD(pattr) - RTA_ALIGN(sizeof(uint32_t)));

	if (tb[MDBA_ROUTER_PATTR_TIMER]) {
		__u32 timer = rta_getattr_u32(tb[MDBA_ROUTER_PATTR_TIMER]);

		print_string(PRINT_ANY, "timer", " %s",
			     format_timer(timer, 1));
	}

	if (tb[MDBA_ROUTER_PATTR_TYPE]) {
		__u8 type = rta_getattr_u8(tb[MDBA_ROUTER_PATTR_TYPE]);

		print_string(PRINT_ANY, "type", " %s",
			     is_temp_mcast_rtr(type) ? "temp" : "permanent");
	}
}

static void br_print_router_ports(FILE *f, struct rtattr *attr,
				  const char *brifname)
{
	int rem = RTA_PAYLOAD(attr);
	struct rtattr *i;

	if (is_json_context())
		open_json_array(PRINT_JSON, brifname);
	else if (!show_stats)
		fprintf(f, "router ports on %s: ", brifname);

	for (i = RTA_DATA(attr); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
		uint32_t *port_ifindex = RTA_DATA(i);
		const char *port_ifname = ll_index_to_name(*port_ifindex);

		if (is_json_context()) {
			open_json_object(NULL);
			print_string(PRINT_JSON, "port", NULL, port_ifname);

			if (show_stats)
				br_print_router_port_stats(i);
			close_json_object();
		} else if (show_stats) {
			fprintf(f, "router ports on %s: %s",
				brifname, port_ifname);

			br_print_router_port_stats(i);
			fprintf(f, "\n");
		} else {
			fprintf(f, "%s ", port_ifname);
		}
	}

	if (!show_stats)
		print_nl();

	close_json_array(PRINT_JSON, NULL);
}

static void print_src_entry(struct rtattr *src_attr, int af, const char *sep)
{
	struct rtattr *stb[MDBA_MDB_SRCATTR_MAX + 1];
	SPRINT_BUF(abuf);
	const char *addr;
	__u32 timer_val;

	parse_rtattr_nested(stb, MDBA_MDB_SRCATTR_MAX, src_attr);
	if (!stb[MDBA_MDB_SRCATTR_ADDRESS] || !stb[MDBA_MDB_SRCATTR_TIMER])
		return;

	addr = inet_ntop(af, RTA_DATA(stb[MDBA_MDB_SRCATTR_ADDRESS]), abuf,
			 sizeof(abuf));
	if (!addr)
		return;
	timer_val = rta_getattr_u32(stb[MDBA_MDB_SRCATTR_TIMER]);

	open_json_object(NULL);
	print_string(PRINT_FP, NULL, "%s", sep);
	print_color_string(PRINT_ANY, ifa_family_color(af),
			   "address", "%s", addr);
	print_string(PRINT_ANY, "timer", "/%s", format_timer(timer_val, 0));
	close_json_object();
}

static void print_dst(const struct rtattr *dst_attr)
{
	SPRINT_BUF(abuf);
	int af = AF_INET;
	const void *dst;

	if (RTA_PAYLOAD(dst_attr) == sizeof(struct in6_addr))
		af = AF_INET6;

	dst = (const void *)RTA_DATA(dst_attr);
	print_color_string(PRINT_ANY, ifa_family_color(af),
			   "dst", " dst %s",
			   inet_ntop(af, dst, abuf, sizeof(abuf)));
}

static void print_mdb_entry(FILE *f, int ifindex, const struct br_mdb_entry *e,
			    struct nlmsghdr *n, struct rtattr **tb)
{
	const void *grp, *src;
	const char *addr;
	SPRINT_BUF(abuf);
	const char *dev;
	int af;

	if (filter_vlan && e->vid != filter_vlan)
		return;

	if (!e->addr.proto) {
		af = AF_PACKET;
		grp = &e->addr.u.mac_addr;
	} else if (e->addr.proto == htons(ETH_P_IP)) {
		af = AF_INET;
		grp = &e->addr.u.ip4;
	} else {
		af = AF_INET6;
		grp = &e->addr.u.ip6;
	}
	dev = ll_index_to_name(ifindex);

	open_json_object(NULL);

	print_int(PRINT_JSON, "index", NULL, ifindex);
	print_color_string(PRINT_ANY, COLOR_IFNAME, "dev", "dev %s", dev);
	print_string(PRINT_ANY, "port", " port %s",
		     ll_index_to_name(e->ifindex));

	/* The ETH_ALEN argument is ignored for all cases but AF_PACKET */
	addr = rt_addr_n2a_r(af, ETH_ALEN, grp, abuf, sizeof(abuf));
	if (!addr)
		return;

	print_color_string(PRINT_ANY, ifa_family_color(af),
			    "grp", " grp %s", addr);

	if (tb && tb[MDBA_MDB_EATTR_SOURCE]) {
		src = (const void *)RTA_DATA(tb[MDBA_MDB_EATTR_SOURCE]);
		print_color_string(PRINT_ANY, ifa_family_color(af),
				   "src", " src %s",
				   inet_ntop(af, src, abuf, sizeof(abuf)));
	}
	print_string(PRINT_ANY, "state", " %s",
			   (e->state & MDB_PERMANENT) ? "permanent" : "temp");
	if (show_details && tb) {
		if (tb[MDBA_MDB_EATTR_GROUP_MODE]) {
			__u8 mode = rta_getattr_u8(tb[MDBA_MDB_EATTR_GROUP_MODE]);

			print_string(PRINT_ANY, "filter_mode", " filter_mode %s",
				     mode == MCAST_INCLUDE ? "include" :
							     "exclude");
		}
		if (tb[MDBA_MDB_EATTR_SRC_LIST]) {
			struct rtattr *i, *attr = tb[MDBA_MDB_EATTR_SRC_LIST];
			const char *sep = " ";
			int rem;

			open_json_array(PRINT_ANY, is_json_context() ?
								"source_list" :
								" source_list");
			rem = RTA_PAYLOAD(attr);
			for (i = RTA_DATA(attr); RTA_OK(i, rem);
			     i = RTA_NEXT(i, rem)) {
				print_src_entry(i, af, sep);
				sep = ",";
			}
			close_json_array(PRINT_JSON, NULL);
		}
		if (tb[MDBA_MDB_EATTR_RTPROT]) {
			__u8 rtprot = rta_getattr_u8(tb[MDBA_MDB_EATTR_RTPROT]);
			SPRINT_BUF(rtb);

			print_string(PRINT_ANY, "protocol", " proto %s",
				     rtnl_rtprot_n2a(rtprot, rtb, sizeof(rtb)));
		}
	}

	open_json_array(PRINT_JSON, "flags");
	if (e->flags & MDB_FLAGS_OFFLOAD)
		print_string(PRINT_ANY, NULL, " %s", "offload");
	if (e->flags & MDB_FLAGS_FAST_LEAVE)
		print_string(PRINT_ANY, NULL, " %s", "fast_leave");
	if (e->flags & MDB_FLAGS_STAR_EXCL)
		print_string(PRINT_ANY, NULL, " %s", "added_by_star_ex");
	if (e->flags & MDB_FLAGS_BLOCKED)
		print_string(PRINT_ANY, NULL, " %s", "blocked");
	if (e->flags & MDB_FLAGS_OFFLOAD_FAILED)
		print_string(PRINT_ANY, NULL, " %s", "offload_failed");
	close_json_array(PRINT_JSON, NULL);

	if (e->vid)
		print_uint(PRINT_ANY, "vid", " vid %u", e->vid);

	if (tb[MDBA_MDB_EATTR_DST])
		print_dst(tb[MDBA_MDB_EATTR_DST]);

	if (tb[MDBA_MDB_EATTR_DST_PORT])
		print_uint(PRINT_ANY, "dst_port", " dst_port %u",
			   rta_getattr_u16(tb[MDBA_MDB_EATTR_DST_PORT]));

	if (tb[MDBA_MDB_EATTR_VNI])
		print_uint(PRINT_ANY, "vni", " vni %u",
			   rta_getattr_u32(tb[MDBA_MDB_EATTR_VNI]));

	if (tb[MDBA_MDB_EATTR_SRC_VNI])
		print_uint(PRINT_ANY, "src_vni", " src_vni %u",
			   rta_getattr_u32(tb[MDBA_MDB_EATTR_SRC_VNI]));

	if (tb[MDBA_MDB_EATTR_IFINDEX]) {
		unsigned int ifindex;

		ifindex = rta_getattr_u32(tb[MDBA_MDB_EATTR_IFINDEX]);
		print_string(PRINT_ANY, "via", " via %s",
			     ll_index_to_name(ifindex));
	}

	if (show_stats && tb && tb[MDBA_MDB_EATTR_TIMER]) {
		__u32 timer = rta_getattr_u32(tb[MDBA_MDB_EATTR_TIMER]);

		print_string(PRINT_ANY, "timer", " %s",
			     format_timer(timer, 1));
	}

	print_nl();
	close_json_object();
}

static void br_print_mdb_entry(FILE *f, int ifindex, struct rtattr *attr,
			       struct nlmsghdr *n)
{
	struct rtattr *etb[MDBA_MDB_EATTR_MAX + 1];
	struct br_mdb_entry *e;
	struct rtattr *i;
	int rem;

	rem = RTA_PAYLOAD(attr);
	for (i = RTA_DATA(attr); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
		e = RTA_DATA(i);
		parse_rtattr_flags(etb, MDBA_MDB_EATTR_MAX, MDB_RTA(RTA_DATA(i)),
				   RTA_PAYLOAD(i) - RTA_ALIGN(sizeof(*e)),
				   NLA_F_NESTED);
		print_mdb_entry(f, ifindex, e, n, etb);
	}
}

static void print_mdb_entries(FILE *fp, struct nlmsghdr *n,
			      int ifindex,  struct rtattr *mdb)
{
	int rem = RTA_PAYLOAD(mdb);
	struct rtattr *i;

	for (i = RTA_DATA(mdb); RTA_OK(i, rem); i = RTA_NEXT(i, rem))
		br_print_mdb_entry(fp, ifindex, i, n);
}

static void print_router_entries(FILE *fp, struct nlmsghdr *n,
				 int ifindex, struct rtattr *router)
{
	const char *brifname = ll_index_to_name(ifindex);

	if (n->nlmsg_type == RTM_GETMDB) {
		if (show_details)
			br_print_router_ports(fp, router, brifname);
	} else {
		struct rtattr *i = RTA_DATA(router);
		uint32_t *port_ifindex = RTA_DATA(i);
		const char *port_name = ll_index_to_name(*port_ifindex);

		if (is_json_context()) {
			open_json_array(PRINT_JSON, brifname);
			open_json_object(NULL);

			print_string(PRINT_JSON, "port", NULL,
				     port_name);
			close_json_object();
			close_json_array(PRINT_JSON, NULL);
		} else {
			fprintf(fp, "router port dev %s master %s\n",
				port_name, brifname);
		}
	}
}

static int __parse_mdb_nlmsg(struct nlmsghdr *n, struct rtattr **tb)
{
	struct br_port_msg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;

	if (n->nlmsg_type != RTM_GETMDB &&
	    n->nlmsg_type != RTM_NEWMDB &&
	    n->nlmsg_type != RTM_DELMDB) {
		fprintf(stderr,
			"Not RTM_GETMDB, RTM_NEWMDB or RTM_DELMDB: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);

		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (filter_index && filter_index != r->ifindex)
		return 0;

	parse_rtattr(tb, MDBA_MAX, MDBA_RTA(r), n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	return 1;
}

static int print_mdbs(struct nlmsghdr *n, void *arg)
{
	struct br_port_msg *r = NLMSG_DATA(n);
	struct rtattr *tb[MDBA_MAX+1];
	FILE *fp = arg;
	int ret;

	ret = __parse_mdb_nlmsg(n, tb);
	if (ret != 1)
		return ret;

	if (tb[MDBA_MDB])
		print_mdb_entries(fp, n, r->ifindex, tb[MDBA_MDB]);

	return 0;
}

static int print_rtrs(struct nlmsghdr *n, void *arg)
{
	struct br_port_msg *r = NLMSG_DATA(n);
	struct rtattr *tb[MDBA_MAX+1];
	FILE *fp = arg;
	int ret;

	ret = __parse_mdb_nlmsg(n, tb);
	if (ret != 1)
		return ret;

	if (tb[MDBA_ROUTER])
		print_router_entries(fp, n, r->ifindex, tb[MDBA_ROUTER]);

	return 0;
}

int print_mdb_mon(struct nlmsghdr *n, void *arg)
{
	struct br_port_msg *r = NLMSG_DATA(n);
	struct rtattr *tb[MDBA_MAX+1];
	FILE *fp = arg;
	int ret;

	ret = __parse_mdb_nlmsg(n, tb);
	if (ret != 1)
		return ret;

	print_headers(fp, "[MDB]");

	if (n->nlmsg_type == RTM_DELMDB)
		print_bool(PRINT_ANY, "deleted", "Deleted ", true);

	if (tb[MDBA_MDB])
		print_mdb_entries(fp, n, r->ifindex, tb[MDBA_MDB]);

	if (tb[MDBA_ROUTER])
		print_router_entries(fp, n, r->ifindex, tb[MDBA_ROUTER]);

	return 0;
}

static int mdb_show(int argc, char **argv)
{
	char *filter_dev = NULL;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (filter_dev)
				duparg("dev", *argv);
			filter_dev = *argv;
		} else if (strcmp(*argv, "vid") == 0) {
			NEXT_ARG();
			if (filter_vlan)
				duparg("vid", *argv);
			filter_vlan = atoi(*argv);
		}
		argc--; argv++;
	}

	if (filter_dev) {
		filter_index = ll_name_to_index(filter_dev);
		if (!filter_index)
			return nodev(filter_dev);
	}

	new_json_obj(json);
	open_json_object(NULL);

	/* get mdb entries */
	if (rtnl_mdbdump_req(&rth, PF_BRIDGE) < 0) {
		perror("Cannot send dump request");
		delete_json_obj();
		return -1;
	}

	open_json_array(PRINT_JSON, "mdb");
	if (rtnl_dump_filter(&rth, print_mdbs, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		delete_json_obj();
		return -1;
	}
	close_json_array(PRINT_JSON, NULL);

	/* get router ports */
	if (rtnl_mdbdump_req(&rth, PF_BRIDGE) < 0) {
		perror("Cannot send dump request");
		delete_json_obj();
		return -1;
	}

	open_json_object("router");
	if (rtnl_dump_filter(&rth, print_rtrs, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		delete_json_obj();
		return -1;
	}
	close_json_object();

	close_json_object();
	delete_json_obj();
	fflush(stdout);

	return 0;
}

static int mdb_parse_grp(const char *grp, struct br_mdb_entry *e)
{
	if (inet_pton(AF_INET, grp, &e->addr.u.ip4)) {
		e->addr.proto = htons(ETH_P_IP);
		return 0;
	}
	if (inet_pton(AF_INET6, grp, &e->addr.u.ip6)) {
		e->addr.proto = htons(ETH_P_IPV6);
		return 0;
	}
	if (ll_addr_a2n((char *)e->addr.u.mac_addr, sizeof(e->addr.u.mac_addr),
			grp) == ETH_ALEN) {
		e->addr.proto = 0;
		return 0;
	}

	return -1;
}

static int mdb_parse_src(struct nlmsghdr *n, int maxlen, const char *src)
{
	struct in6_addr src_ip6;
	__be32 src_ip4;

	if (inet_pton(AF_INET, src, &src_ip4)) {
		addattr32(n, maxlen, MDBE_ATTR_SOURCE, src_ip4);
		return 0;
	}

	if (inet_pton(AF_INET6, src, &src_ip6)) {
		addattr_l(n, maxlen, MDBE_ATTR_SOURCE, &src_ip6,
			  sizeof(src_ip6));
		return 0;
	}

	return -1;
}

static int mdb_parse_mode(struct nlmsghdr *n, int maxlen, const char *mode)
{
	if (strcmp(mode, "include") == 0) {
		addattr8(n, maxlen, MDBE_ATTR_GROUP_MODE, MCAST_INCLUDE);
		return 0;
	}

	if (strcmp(mode, "exclude") == 0) {
		addattr8(n, maxlen, MDBE_ATTR_GROUP_MODE, MCAST_EXCLUDE);
		return 0;
	}

	return -1;
}

static int mdb_parse_src_entry(struct nlmsghdr *n, int maxlen, char *src_entry)
{
	struct in6_addr src_ip6;
	struct rtattr *nest;
	__be32 src_ip4;

	nest = addattr_nest(n, maxlen, MDBE_SRC_LIST_ENTRY | NLA_F_NESTED);

	if (inet_pton(AF_INET, src_entry, &src_ip4))
		addattr32(n, maxlen, MDBE_SRCATTR_ADDRESS, src_ip4);
	else if (inet_pton(AF_INET6, src_entry, &src_ip6))
		addattr_l(n, maxlen, MDBE_SRCATTR_ADDRESS, &src_ip6,
			  sizeof(src_ip6));
	else
		return -1;

	addattr_nest_end(n, nest);

	return 0;
}

static int mdb_parse_src_list(struct nlmsghdr *n, int maxlen, char *src_list)
{
	struct rtattr *nest;
	char *sep;

	nest = addattr_nest(n, maxlen, MDBE_ATTR_SRC_LIST | NLA_F_NESTED);

	do {
		sep = strchr(src_list, ',');
		if (sep)
			*sep = '\0';

		if (mdb_parse_src_entry(n, maxlen, src_list)) {
			fprintf(stderr, "Invalid source entry \"%s\" in source list\n",
				src_list);
			return -1;
		}

		src_list = sep + 1;
	} while (sep);

	addattr_nest_end(n, nest);

	return 0;
}

static int mdb_parse_proto(struct nlmsghdr *n, int maxlen, const char *proto)
{
	__u32 proto_id;
	int err;

	err = rtnl_rtprot_a2n(&proto_id, proto);
	if (err)
		return err;

	addattr8(n, maxlen, MDBE_ATTR_RTPROT, proto_id);

	return 0;
}

static int mdb_parse_dst(struct nlmsghdr *n, int maxlen, const char *dst)
{
	struct in6_addr dst_ip6;
	__be32 dst_ip4;

	if (inet_pton(AF_INET, dst, &dst_ip4)) {
		addattr32(n, maxlen, MDBE_ATTR_DST, dst_ip4);
		return 0;
	}

	if (inet_pton(AF_INET6, dst, &dst_ip6)) {
		addattr_l(n, maxlen, MDBE_ATTR_DST, &dst_ip6,
			  sizeof(dst_ip6));
		return 0;
	}

	return -1;
}

static int mdb_parse_dst_port(struct nlmsghdr *n, int maxlen,
			      const char *dst_port)
{
	unsigned long port;
	char *endptr;

	port = strtoul(dst_port, &endptr, 0);
	if (endptr && *endptr) {
		struct servent *pse;

		pse = getservbyname(dst_port, "udp");
		if (!pse)
			return -1;
		port = ntohs(pse->s_port);
	} else if (port > USHRT_MAX) {
		return -1;
	}

	addattr16(n, maxlen, MDBE_ATTR_DST_PORT, port);

	return 0;
}

static int mdb_parse_vni(struct nlmsghdr *n, int maxlen, const char *vni,
			 int attr_type)
{
	unsigned long vni_num;
	char *endptr;

	vni_num = strtoul(vni, &endptr, 0);
	if ((endptr && *endptr) || vni_num == ULONG_MAX)
		return -1;

	addattr32(n, maxlen, attr_type, vni_num);

	return 0;
}

static int mdb_parse_dev(struct nlmsghdr *n, int maxlen, const char *dev)
{
	unsigned int ifindex;

	ifindex = ll_name_to_index(dev);
	if (!ifindex)
		return -1;

	addattr32(n, maxlen, MDBE_ATTR_IFINDEX, ifindex);

	return 0;
}

static int mdb_modify(int cmd, int flags, int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct br_port_msg	bpm;
		char			buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_port_msg)),
		.n.nlmsg_flags = NLM_F_REQUEST | flags,
		.n.nlmsg_type = cmd,
		.bpm.family = PF_BRIDGE,
	};
	char *d = NULL, *p = NULL, *grp = NULL, *src = NULL, *mode = NULL;
	char *dst_port = NULL, *vni = NULL, *src_vni = NULL, *via = NULL;
	char *src_list = NULL, *proto = NULL, *dst = NULL;
	struct br_mdb_entry entry = {};
	bool set_attrs = false;
	short vid = 0;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "grp") == 0) {
			NEXT_ARG();
			grp = *argv;
		} else if (strcmp(*argv, "port") == 0) {
			NEXT_ARG();
			p = *argv;
		} else if (strcmp(*argv, "permanent") == 0) {
			if (cmd == RTM_NEWMDB)
				entry.state |= MDB_PERMANENT;
		} else if (strcmp(*argv, "temp") == 0) {
			;/* nothing */
		} else if (strcmp(*argv, "vid") == 0) {
			NEXT_ARG();
			vid = atoi(*argv);
		} else if (strcmp(*argv, "src") == 0) {
			NEXT_ARG();
			src = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "filter_mode") == 0) {
			NEXT_ARG();
			mode = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "source_list") == 0) {
			NEXT_ARG();
			src_list = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "proto") == 0) {
			NEXT_ARG();
			proto = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "dst") == 0) {
			NEXT_ARG();
			dst = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "dst_port") == 0) {
			NEXT_ARG();
			dst_port = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "vni") == 0) {
			NEXT_ARG();
			vni = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "src_vni") == 0) {
			NEXT_ARG();
			src_vni = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "via") == 0) {
			NEXT_ARG();
			via = *argv;
			set_attrs = true;
		} else {
			if (matches(*argv, "help") == 0)
				usage();
		}
		argc--; argv++;
	}

	if (d == NULL || grp == NULL || p == NULL) {
		fprintf(stderr, "Device, group address and port name are required arguments.\n");
		return -1;
	}

	req.bpm.ifindex = ll_name_to_index(d);
	if (!req.bpm.ifindex)
		return nodev(d);

	entry.ifindex = ll_name_to_index(p);
	if (!entry.ifindex)
		return nodev(p);

	if (mdb_parse_grp(grp, &entry)) {
		fprintf(stderr, "Invalid address \"%s\"\n", grp);
		return -1;
	}

	entry.vid = vid;
	addattr_l(&req.n, sizeof(req), MDBA_SET_ENTRY, &entry, sizeof(entry));
	if (set_attrs) {
		struct rtattr *nest = addattr_nest(&req.n, sizeof(req),
						   MDBA_SET_ENTRY_ATTRS);

		nest->rta_type |= NLA_F_NESTED;

		if (src && mdb_parse_src(&req.n, sizeof(req), src)) {
			fprintf(stderr, "Invalid source address \"%s\"\n", src);
			return -1;
		}

		if (mode && mdb_parse_mode(&req.n, sizeof(req), mode)) {
			fprintf(stderr, "Invalid filter mode \"%s\"\n", mode);
			return -1;
		}

		if (src_list && mdb_parse_src_list(&req.n, sizeof(req),
						   src_list))
			return -1;

		if (proto && mdb_parse_proto(&req.n, sizeof(req), proto)) {
			fprintf(stderr, "Invalid protocol value \"%s\"\n",
				proto);
			return -1;
		}

		if (dst && mdb_parse_dst(&req.n, sizeof(req), dst)) {
			fprintf(stderr, "Invalid underlay destination address \"%s\"\n",
				dst);
			return -1;
		}

		if (dst_port && mdb_parse_dst_port(&req.n, sizeof(req),
						   dst_port)) {
			fprintf(stderr, "Invalid destination port \"%s\"\n", dst_port);
			return -1;
		}

		if (vni && mdb_parse_vni(&req.n, sizeof(req), vni,
					 MDBE_ATTR_VNI)) {
			fprintf(stderr, "Invalid destination VNI \"%s\"\n",
				vni);
			return -1;
		}

		if (src_vni && mdb_parse_vni(&req.n, sizeof(req), src_vni,
					     MDBE_ATTR_SRC_VNI)) {
			fprintf(stderr, "Invalid source VNI \"%s\"\n", src_vni);
			return -1;
		}

		if (via && mdb_parse_dev(&req.n, sizeof(req), via))
			return nodev(via);

		addattr_nest_end(&req.n, nest);
	}

	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -1;

	return 0;
}

static int mdb_get(int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct br_port_msg	bpm;
		char			buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_port_msg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_GETMDB,
		.bpm.family = PF_BRIDGE,
	};
	char *d = NULL, *grp = NULL, *src = NULL, *src_vni = NULL;
	struct br_mdb_entry entry = {};
	struct nlmsghdr *answer;
	bool get_attrs = false;
	short vid = 0;
	int ret = 0;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "grp") == 0) {
			NEXT_ARG();
			grp = *argv;
		} else if (strcmp(*argv, "vid") == 0) {
			NEXT_ARG();
			vid = atoi(*argv);
		} else if (strcmp(*argv, "src") == 0) {
			NEXT_ARG();
			src = *argv;
			get_attrs = true;
		} else if (strcmp(*argv, "src_vni") == 0) {
			NEXT_ARG();
			src_vni = *argv;
			get_attrs = true;
		} else {
			if (strcmp(*argv, "help") == 0)
				usage();
		}
		argc--; argv++;
	}

	if (d == NULL || grp == NULL) {
		fprintf(stderr, "Device and group address are required arguments.\n");
		return -1;
	}

	req.bpm.ifindex = ll_name_to_index(d);
	if (!req.bpm.ifindex)
		return nodev(d);

	if (mdb_parse_grp(grp, &entry)) {
		fprintf(stderr, "Invalid address \"%s\"\n", grp);
		return -1;
	}

	entry.vid = vid;
	addattr_l(&req.n, sizeof(req), MDBA_GET_ENTRY, &entry, sizeof(entry));
	if (get_attrs) {
		struct rtattr *nest = addattr_nest(&req.n, sizeof(req),
						   MDBA_GET_ENTRY_ATTRS);

		nest->rta_type |= NLA_F_NESTED;

		if (src && mdb_parse_src(&req.n, sizeof(req), src)) {
			fprintf(stderr, "Invalid source address \"%s\"\n", src);
			return -1;
		}

		if (src_vni && mdb_parse_vni(&req.n, sizeof(req), src_vni,
					     MDBE_ATTR_SRC_VNI)) {
			fprintf(stderr, "Invalid source VNI \"%s\"\n", src_vni);
			return -1;
		}

		addattr_nest_end(&req.n, nest);
	}

	if (rtnl_talk(&rth, &req.n, &answer) < 0)
		return -2;

	new_json_obj(json);

	if (print_mdbs(answer, stdout) < 0)
		ret = -1;

	delete_json_obj();
	free(answer);

	return ret;
}

static int mdb_flush(int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct br_port_msg	bpm;
		char			buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_port_msg)),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_BULK,
		.n.nlmsg_type = RTM_DELMDB,
		.bpm.family = PF_BRIDGE,
	};
	char *d = NULL, *p = NULL, *src_vni = NULL, *proto = NULL, *dst = NULL;
	char *dst_port = NULL, *vni = NULL;
	struct br_mdb_entry entry = {};
	unsigned short state_mask = 0;
	bool set_attrs = false;
	short vid = 0;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "port") == 0) {
			NEXT_ARG();
			p = *argv;
		} else if (strcmp(*argv, "vid") == 0) {
			NEXT_ARG();
			vid = atoi(*argv);
		} else if (strcmp(*argv, "src_vni") == 0) {
			NEXT_ARG();
			src_vni = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "proto") == 0) {
			NEXT_ARG();
			proto = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "permanent") == 0) {
			entry.state |= MDB_PERMANENT;
			state_mask |= MDB_PERMANENT;
			set_attrs = true;
		} else if (strcmp(*argv, "nopermanent") == 0) {
			entry.state &= ~MDB_PERMANENT;
			state_mask |= MDB_PERMANENT;
			set_attrs = true;
		} else if (strcmp(*argv, "dst") == 0) {
			NEXT_ARG();
			dst = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "dst_port") == 0) {
			NEXT_ARG();
			dst_port = *argv;
			set_attrs = true;
		} else if (strcmp(*argv, "vni") == 0) {
			NEXT_ARG();
			vni = *argv;
			set_attrs = true;
		} else {
			if (strcmp(*argv, "help") == 0)
				usage();
		}
		argc--; argv++;
	}

	if (d == NULL) {
		fprintf(stderr, "Device is a required argument.\n");
		return -1;
	}

	req.bpm.ifindex = ll_name_to_index(d);
	if (!req.bpm.ifindex)
		return nodev(d);

	if (p) {
		entry.ifindex = ll_name_to_index(p);
		if (!entry.ifindex)
			return nodev(p);
	}

	entry.vid = vid;
	addattr_l(&req.n, sizeof(req), MDBA_SET_ENTRY, &entry, sizeof(entry));
	if (set_attrs) {
		struct rtattr *nest = addattr_nest(&req.n, sizeof(req),
						   MDBA_SET_ENTRY_ATTRS);

		nest->rta_type |= NLA_F_NESTED;

		if (proto && mdb_parse_proto(&req.n, sizeof(req), proto)) {
			fprintf(stderr, "Invalid protocol value \"%s\"\n",
				proto);
			return -1;
		}

		if (dst && mdb_parse_dst(&req.n, sizeof(req), dst)) {
			fprintf(stderr, "Invalid underlay destination address \"%s\"\n",
				dst);
			return -1;
		}

		if (dst_port && mdb_parse_dst_port(&req.n, sizeof(req),
						   dst_port)) {
			fprintf(stderr, "Invalid destination port \"%s\"\n", dst_port);
			return -1;
		}

		if (vni && mdb_parse_vni(&req.n, sizeof(req), vni,
					 MDBE_ATTR_VNI)) {
			fprintf(stderr, "Invalid destination VNI \"%s\"\n",
				vni);
			return -1;
		}

		if (src_vni && mdb_parse_vni(&req.n, sizeof(req), src_vni,
					     MDBE_ATTR_SRC_VNI)) {
			fprintf(stderr, "Invalid source VNI \"%s\"\n", src_vni);
			return -1;
		}

		if (state_mask)
			addattr8(&req.n, sizeof(req), MDBE_ATTR_STATE_MASK,
				 state_mask);

		addattr_nest_end(&req.n, nest);
	}

	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -1;

	return 0;
}

int do_mdb(int argc, char **argv)
{
	ll_init_map(&rth);
	timestamp = 0;

	if (argc > 0) {
		if (matches(*argv, "add") == 0)
			return mdb_modify(RTM_NEWMDB, NLM_F_CREATE|NLM_F_EXCL, argc-1, argv+1);
		if (strcmp(*argv, "replace") == 0)
			return mdb_modify(RTM_NEWMDB, NLM_F_CREATE|NLM_F_REPLACE, argc-1, argv+1);
		if (matches(*argv, "delete") == 0)
			return mdb_modify(RTM_DELMDB, 0, argc-1, argv+1);

		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return mdb_show(argc-1, argv+1);
		if (strcmp(*argv, "get") == 0)
			return mdb_get(argc-1, argv+1);
		if (strcmp(*argv, "flush") == 0)
			return mdb_flush(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return mdb_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"bridge mdb help\".\n", *argv);
	exit(-1);
}
