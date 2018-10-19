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

#include "libnetlink.h"
#include "br_common.h"
#include "rt_names.h"
#include "utils.h"
#include "json_print.h"

#ifndef MDBA_RTA
#define MDBA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct br_port_msg))))
#endif

static unsigned int filter_index, filter_vlan;

static void usage(void)
{
	fprintf(stderr, "Usage: bridge mdb { add | del } dev DEV port PORT grp GROUP [permanent | temp] [vid VID]\n");
	fprintf(stderr, "       bridge mdb {show} [ dev DEV ] [ vid VID ]\n");
	exit(-1);
}

static bool is_temp_mcast_rtr(__u8 type)
{
	return type == MDB_RTR_TYPE_TEMP_QUERY || type == MDB_RTR_TYPE_TEMP;
}

static const char *format_timer(__u32 ticks)
{
	struct timeval tv;
	static char tbuf[32];

	__jiffies_to_tv(&tv, ticks);
	snprintf(tbuf, sizeof(tbuf), "%4lu.%.2lu",
		 (unsigned long)tv.tv_sec,
		 (unsigned long)tv.tv_usec / 10000);

	return tbuf;
}

static void __print_router_port_stats(FILE *f, struct rtattr *pattr)
{
	struct rtattr *tb[MDBA_ROUTER_PATTR_MAX + 1];

	parse_rtattr(tb, MDBA_ROUTER_PATTR_MAX, MDB_RTR_RTA(RTA_DATA(pattr)),
		     RTA_PAYLOAD(pattr) - RTA_ALIGN(sizeof(uint32_t)));

	if (tb[MDBA_ROUTER_PATTR_TIMER]) {
		__u32 timer = rta_getattr_u32(tb[MDBA_ROUTER_PATTR_TIMER]);

		print_string(PRINT_ANY, "timer", " %s",
			     format_timer(timer));
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
				__print_router_port_stats(f, i);
			close_json_object();
		} else if (show_stats) {
			fprintf(f, "router ports on %s: %s",
				brifname, port_ifname);

			__print_router_port_stats(f, i);
			fprintf(f, "\n");
		} else {
			fprintf(f, "%s ", port_ifname);
		}
	}

	if (!show_stats)
		print_nl();

	close_json_array(PRINT_JSON, NULL);
}

static void print_mdb_entry(FILE *f, int ifindex, const struct br_mdb_entry *e,
			    struct nlmsghdr *n, struct rtattr **tb)
{
	SPRINT_BUF(abuf);
	const char *dev;
	const void *src;
	int af;

	if (filter_vlan && e->vid != filter_vlan)
		return;

	af = e->addr.proto == htons(ETH_P_IP) ? AF_INET : AF_INET6;
	src = af == AF_INET ? (const void *)&e->addr.u.ip4 :
			      (const void *)&e->addr.u.ip6;
	dev = ll_index_to_name(ifindex);

	open_json_object(NULL);

	if (n->nlmsg_type == RTM_DELMDB)
		print_bool(PRINT_ANY, "deleted", "Deleted ", true);

	print_int(PRINT_ANY, "index", "%u: ", ifindex);
	print_color_string(PRINT_ANY, COLOR_IFNAME, "dev", "%s ", dev);
	print_string(PRINT_ANY, "port", " %s ",
		     ll_index_to_name(e->ifindex));

	print_color_string(PRINT_ANY, ifa_family_color(af),
			    "grp", " %s ",
			    inet_ntop(af, src, abuf, sizeof(abuf)));

	print_string(PRINT_ANY, "state", " %s ",
			   (e->state & MDB_PERMANENT) ? "permanent" : "temp");

	open_json_array(PRINT_JSON, "flags");
	if (e->flags & MDB_FLAGS_OFFLOAD)
		print_string(PRINT_ANY, NULL, "%s ", "offload");
	close_json_array(PRINT_JSON, NULL);

	if (e->vid)
		print_uint(PRINT_ANY, "vid", " vid %u", e->vid);

	if (show_stats && tb && tb[MDBA_MDB_EATTR_TIMER]) {
		__u32 timer = rta_getattr_u32(tb[MDBA_MDB_EATTR_TIMER]);

		print_string(PRINT_ANY, "timer", " %s",
			     format_timer(timer));
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
		parse_rtattr(etb, MDBA_MDB_EATTR_MAX, MDB_RTA(RTA_DATA(i)),
			     RTA_PAYLOAD(i) - RTA_ALIGN(sizeof(*e)));
		print_mdb_entry(f, ifindex, e, n, etb);
	}
}

static void print_mdb_entries(FILE *fp, struct nlmsghdr *n,
			      int ifindex,  struct rtattr *mdb)
{
	int rem = RTA_PAYLOAD(mdb);
	struct rtattr *i;

	open_json_array(PRINT_JSON, "mdb");
	for (i = RTA_DATA(mdb); RTA_OK(i, rem); i = RTA_NEXT(i, rem))
		br_print_mdb_entry(fp, ifindex, i, n);
	close_json_array(PRINT_JSON, NULL);
}

static void print_router_entries(FILE *fp, struct nlmsghdr *n,
				 int ifindex, struct rtattr *router)
{
	const char *brifname = ll_index_to_name(ifindex);

	open_json_array(PRINT_JSON, "router");
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
	close_json_array(PRINT_JSON, NULL);
}

int print_mdb(struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	struct br_port_msg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[MDBA_MAX+1];

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

	/* get mdb entries*/
	if (rtnl_mdbdump_req(&rth, PF_BRIDGE) < 0) {
		perror("Cannot send dump request");
		return -1;
	}

	if (rtnl_dump_filter(&rth, print_mdb, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return -1;
	}

	delete_json_obj();
	fflush(stdout);

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
	struct br_mdb_entry entry = {};
	char *d = NULL, *p = NULL, *grp = NULL;
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

	if (!inet_pton(AF_INET, grp, &entry.addr.u.ip4)) {
		if (!inet_pton(AF_INET6, grp, &entry.addr.u.ip6)) {
			fprintf(stderr, "Invalid address \"%s\"\n", grp);
			return -1;
		} else
			entry.addr.proto = htons(ETH_P_IPV6);
	} else
		entry.addr.proto = htons(ETH_P_IP);

	entry.vid = vid;
	addattr_l(&req.n, sizeof(req), MDBA_SET_ENTRY, &entry, sizeof(entry));

	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -1;

	return 0;
}

int do_mdb(int argc, char **argv)
{
	ll_init_map(&rth);

	if (argc > 0) {
		if (matches(*argv, "add") == 0)
			return mdb_modify(RTM_NEWMDB, NLM_F_CREATE|NLM_F_EXCL, argc-1, argv+1);
		if (matches(*argv, "delete") == 0)
			return mdb_modify(RTM_DELMDB, 0, argc-1, argv+1);

		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return mdb_show(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return mdb_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"bridge mdb help\".\n", *argv);
	exit(-1);
}
