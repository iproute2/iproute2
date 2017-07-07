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
#include <json_writer.h>

#include "libnetlink.h"
#include "br_common.h"
#include "rt_names.h"
#include "utils.h"

#ifndef MDBA_RTA
#define MDBA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct br_port_msg))))
#endif

static unsigned int filter_index, filter_vlan;
json_writer_t *jw_global;
static bool print_mdb_entries = true;
static bool print_mdb_router = true;

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

static void __print_router_port_stats(FILE *f, struct rtattr *pattr)
{
	struct rtattr *tb[MDBA_ROUTER_PATTR_MAX + 1];
	struct timeval tv;
	__u8 type;

	parse_rtattr(tb, MDBA_ROUTER_PATTR_MAX, MDB_RTR_RTA(RTA_DATA(pattr)),
		     RTA_PAYLOAD(pattr) - RTA_ALIGN(sizeof(uint32_t)));
	if (tb[MDBA_ROUTER_PATTR_TIMER]) {
		__jiffies_to_tv(&tv,
				rta_getattr_u32(tb[MDBA_ROUTER_PATTR_TIMER]));
		if (jw_global) {
			char formatted_time[9];

			snprintf(formatted_time, sizeof(formatted_time),
				 "%4i.%.2i", (int)tv.tv_sec,
				 (int)tv.tv_usec/10000);
			jsonw_string_field(jw_global, "timer", formatted_time);
		} else {
			fprintf(f, " %4i.%.2i",
				(int)tv.tv_sec, (int)tv.tv_usec/10000);
		}
	}
	if (tb[MDBA_ROUTER_PATTR_TYPE]) {
		type = rta_getattr_u8(tb[MDBA_ROUTER_PATTR_TYPE]);
		if (jw_global)
			jsonw_string_field(jw_global, "type",
				is_temp_mcast_rtr(type) ? "temp" : "permanent");
		else
			fprintf(f, " %s",
				is_temp_mcast_rtr(type) ? "temp" : "permanent");
	}
}

static void br_print_router_ports(FILE *f, struct rtattr *attr, __u32 brifidx)
{
	uint32_t *port_ifindex;
	struct rtattr *i;
	int rem;

	rem = RTA_PAYLOAD(attr);
	if (jw_global) {
		jsonw_name(jw_global, ll_index_to_name(brifidx));
		jsonw_start_array(jw_global);
		for (i = RTA_DATA(attr); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
			port_ifindex = RTA_DATA(i);
			jsonw_start_object(jw_global);
			jsonw_string_field(jw_global,
					   "port",
					   ll_index_to_name(*port_ifindex));
			if (show_stats)
				__print_router_port_stats(f, i);
			jsonw_end_object(jw_global);
		}
		jsonw_end_array(jw_global);
	} else {
		if (!show_stats)
			fprintf(f, "router ports on %s: ",
				ll_index_to_name(brifidx));
		for (i = RTA_DATA(attr); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
			port_ifindex = RTA_DATA(i);
			if (show_stats) {
				fprintf(f, "router ports on %s: %s",
					ll_index_to_name(brifidx),
					ll_index_to_name(*port_ifindex));
				__print_router_port_stats(f, i);
				fprintf(f, "\n");
			} else{
				fprintf(f, "%s ",
					ll_index_to_name(*port_ifindex));
			}
		}
		if (!show_stats)
			fprintf(f, "\n");
	}
}

static void start_json_mdb_flags_array(bool *mdb_flags)
{
	if (*mdb_flags)
		return;
	jsonw_name(jw_global, "flags");
	jsonw_start_array(jw_global);
	*mdb_flags = true;
}

static void print_mdb_entry(FILE *f, int ifindex, struct br_mdb_entry *e,
			    struct nlmsghdr *n, struct rtattr **tb)
{
	SPRINT_BUF(abuf);
	const void *src;
	int af;
	bool mdb_flags = false;

	if (filter_vlan && e->vid != filter_vlan)
		return;
	af = e->addr.proto == htons(ETH_P_IP) ? AF_INET : AF_INET6;
	src = af == AF_INET ? (const void *)&e->addr.u.ip4 :
			      (const void *)&e->addr.u.ip6;
	if (jw_global)
		jsonw_start_object(jw_global);
	if (n->nlmsg_type == RTM_DELMDB) {
		if (jw_global)
			jsonw_string_field(jw_global, "opCode", "deleted");
		else
			fprintf(f, "Deleted ");
	}
	if (jw_global) {
		jsonw_string_field(jw_global, "dev", ll_index_to_name(ifindex));
		jsonw_string_field(jw_global,
				   "port",
				   ll_index_to_name(e->ifindex));
		jsonw_string_field(jw_global, "grp", inet_ntop(af, src,
			abuf, sizeof(abuf)));
		jsonw_string_field(jw_global, "state",
			(e->state & MDB_PERMANENT) ? "permanent" : "temp");
		if (e->flags & MDB_FLAGS_OFFLOAD) {
			start_json_mdb_flags_array(&mdb_flags);
			jsonw_string(jw_global, "offload");
		}
		if (mdb_flags)
			jsonw_end_array(jw_global);
	} else{
		fprintf(f, "dev %s port %s grp %s %s %s",
			ll_index_to_name(ifindex),
			ll_index_to_name(e->ifindex),
			inet_ntop(af, src, abuf, sizeof(abuf)),
			(e->state & MDB_PERMANENT) ? "permanent" : "temp",
			(e->flags & MDB_FLAGS_OFFLOAD) ? "offload" : "");
	}
	if (e->vid) {
		if (jw_global)
			jsonw_uint_field(jw_global, "vid", e->vid);
		else
			fprintf(f, " vid %hu", e->vid);
	}
	if (show_stats && tb && tb[MDBA_MDB_EATTR_TIMER]) {
		struct timeval tv;

		__jiffies_to_tv(&tv, rta_getattr_u32(tb[MDBA_MDB_EATTR_TIMER]));
		if (jw_global) {
			char formatted_time[9];

			snprintf(formatted_time, sizeof(formatted_time),
				 "%4i.%.2i", (int)tv.tv_sec,
				 (int)tv.tv_usec/10000);
			jsonw_string_field(jw_global, "timer", formatted_time);
		} else {
			fprintf(f, "%4i.%.2i", (int)tv.tv_sec,
				(int)tv.tv_usec/10000);
		}
	}
	if (jw_global)
		jsonw_end_object(jw_global);
	else
		fprintf(f, "\n");
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

int print_mdb(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	struct br_port_msg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[MDBA_MAX+1], *i;

	if (n->nlmsg_type != RTM_GETMDB && n->nlmsg_type != RTM_NEWMDB && n->nlmsg_type != RTM_DELMDB) {
		fprintf(stderr, "Not RTM_GETMDB, RTM_NEWMDB or RTM_DELMDB: %08x %08x %08x\n",
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

	if (tb[MDBA_MDB] && print_mdb_entries) {
		int rem = RTA_PAYLOAD(tb[MDBA_MDB]);

		for (i = RTA_DATA(tb[MDBA_MDB]); RTA_OK(i, rem); i = RTA_NEXT(i, rem))
			br_print_mdb_entry(fp, r->ifindex, i, n);
	}

	if (tb[MDBA_ROUTER] && print_mdb_router) {
		if (n->nlmsg_type == RTM_GETMDB) {
			if (show_details)
				br_print_router_ports(fp, tb[MDBA_ROUTER],
						      r->ifindex);
		} else {
			uint32_t *port_ifindex;

			i = RTA_DATA(tb[MDBA_ROUTER]);
			port_ifindex = RTA_DATA(i);
			if (n->nlmsg_type == RTM_DELMDB) {
				if (jw_global)
					jsonw_string_field(jw_global,
							   "opCode",
							   "deleted");
				else
					fprintf(fp, "Deleted ");
			}
			if (jw_global) {
				jsonw_name(jw_global,
					   ll_index_to_name(r->ifindex));
				jsonw_start_array(jw_global);
				jsonw_start_object(jw_global);
				jsonw_string_field(jw_global, "port",
					ll_index_to_name(*port_ifindex));
				jsonw_end_object(jw_global);
				jsonw_end_array(jw_global);
			} else {
				fprintf(fp, "router port dev %s master %s\n",
					ll_index_to_name(*port_ifindex),
					ll_index_to_name(r->ifindex));
			}
		}
	}

	if (!jw_global)
		fflush(fp);

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
		filter_index = if_nametoindex(filter_dev);
		if (filter_index == 0) {
			fprintf(stderr, "Cannot find device \"%s\"\n",
				filter_dev);
			return -1;
		}
	}

	/* get mdb entries*/
	if (rtnl_wilddump_request(&rth, PF_BRIDGE, RTM_GETMDB) < 0) {
		perror("Cannot send dump request");
		return -1;
	}

	if (!json_output) {
		/* Normal output */
		if (rtnl_dump_filter(&rth, print_mdb, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			return -1;
		}
		return 0;
	}
	/* Json output */
	jw_global = jsonw_new(stdout);
	jsonw_pretty(jw_global, 1);
	jsonw_start_object(jw_global);
	jsonw_name(jw_global, "mdb");
	jsonw_start_array(jw_global);

	/* print mdb entries */
	print_mdb_entries = true;
	print_mdb_router = false;
	if (rtnl_dump_filter(&rth, print_mdb, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return -1;
	}
	jsonw_end_array(jw_global);

	/* get router ports */
	if (rtnl_wilddump_request(&rth, PF_BRIDGE, RTM_GETMDB) < 0) {
		perror("Cannot send dump request");
		return -1;
	}
	jsonw_name(jw_global, "router");
	jsonw_start_object(jw_global);

	/* print router ports */
	print_mdb_entries = false;
	print_mdb_router = true;
	if (rtnl_dump_filter(&rth, print_mdb, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return -1;
	}
	jsonw_end_object(jw_global);
	jsonw_end_object(jw_global);
	jsonw_destroy(&jw_global);

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
	if (req.bpm.ifindex == 0) {
		fprintf(stderr, "Cannot find device \"%s\"\n", d);
		return -1;
	}

	entry.ifindex = ll_name_to_index(p);
	if (entry.ifindex == 0) {
		fprintf(stderr, "Cannot find device \"%s\"\n", p);
		return -1;
	}

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

	if (rtnl_talk(&rth, &req.n, NULL, 0) < 0)
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
