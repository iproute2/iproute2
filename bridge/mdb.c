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

#ifndef MDBA_RTA
#define MDBA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct br_port_msg))))
#endif

int filter_index;

static void usage(void)
{
	fprintf(stderr, "       bridge mdb {show} [ dev DEV ]\n");
	exit(-1);
}

static void br_print_router_ports(FILE *f, struct rtattr *attr)
{
	uint32_t *port_ifindex;
	struct rtattr *i;
	int rem;

	rem = RTA_PAYLOAD(attr);
	for (i = RTA_DATA(attr); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
		port_ifindex = RTA_DATA(i);
		fprintf(f, "%s ", ll_index_to_name(*port_ifindex));
	}

	fprintf(f, "\n");
}

static void print_mdb_entry(FILE *f, int ifindex, struct br_mdb_entry *e)
{
	SPRINT_BUF(abuf);

	if (e->addr.proto == htons(ETH_P_IP))
		fprintf(f, "bridge %s port %s group %s\n", ll_index_to_name(ifindex),
			ll_index_to_name(e->ifindex),
			inet_ntop(AF_INET, &e->addr.u.ip4, abuf, sizeof(abuf)));
	else
		fprintf(f, "bridge %s port %s group %s\n", ll_index_to_name(ifindex),
			ll_index_to_name(e->ifindex),
			inet_ntop(AF_INET6, &e->addr.u.ip6, abuf, sizeof(abuf)));
}

static void br_print_mdb_entry(FILE *f, int ifindex, struct rtattr *attr)
{
	struct rtattr *i;
	int rem;
	struct br_mdb_entry *e;

	rem = RTA_PAYLOAD(attr);
	for (i = RTA_DATA(attr); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
		e = RTA_DATA(i);
		print_mdb_entry(f, ifindex, e);
	}
}

int print_mdb(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	struct br_port_msg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[MDBA_MAX+1];

	if (n->nlmsg_type != RTM_GETMDB) {
		fprintf(stderr, "Not RTM_GETMDB: %08x %08x %08x\n",
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

	if (tb[MDBA_MDB]) {
		struct rtattr *i;
		int rem = RTA_PAYLOAD(tb[MDBA_MDB]);

		for (i = RTA_DATA(tb[MDBA_MDB]); RTA_OK(i, rem); i = RTA_NEXT(i, rem))
			br_print_mdb_entry(fp, r->ifindex, i);
	}

	if (tb[MDBA_ROUTER]) {
		if (show_details) {
			fprintf(fp, "router ports on %s: ", ll_index_to_name(r->ifindex));
			br_print_router_ports(fp, tb[MDBA_ROUTER]);
		}
	}

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

	if (rtnl_wilddump_request(&rth, PF_BRIDGE, RTM_GETMDB) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&rth, print_mdb, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	return 0;
}

int do_mdb(int argc, char **argv)
{
	ll_init_map(&rth);

	if (argc > 0) {
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
