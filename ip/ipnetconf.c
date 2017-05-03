/*
 * ipnetconf.c		"ip netconf".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Nicolas Dichtel, <nicolas.dichtel@6wind.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

static struct {
	int family;
	int ifindex;
} filter;

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr, "Usage: ip netconf show [ dev STRING ]\n");
	exit(-1);
}

static void print_onoff(FILE *f, const char *flag, __u32 val)
{
	fprintf(f, "%s %s ", flag, val ? "on" : "off");
}

static struct rtattr *netconf_rta(struct netconfmsg *ncm)
{
	return (struct rtattr *)((char *)ncm
				 + NLMSG_ALIGN(sizeof(struct netconfmsg)));
}

int print_netconf(const struct sockaddr_nl *who, struct rtnl_ctrl_data *ctrl,
		  struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct netconfmsg *ncm = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[NETCONFA_MAX+1];
	int ifindex = 0;

	if (n->nlmsg_type == NLMSG_ERROR)
		return -1;
	if (n->nlmsg_type != RTM_NEWNETCONF) {
		fprintf(stderr, "Not RTM_NEWNETCONF: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);

		return -1;
	}
	len -= NLMSG_SPACE(sizeof(*ncm));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (filter.family && filter.family != ncm->ncm_family)
		return 0;

	parse_rtattr(tb, NETCONFA_MAX, netconf_rta(ncm),
		     NLMSG_PAYLOAD(n, sizeof(*ncm)));

	if (tb[NETCONFA_IFINDEX])
		ifindex = rta_getattr_u32(tb[NETCONFA_IFINDEX]);

	if (filter.ifindex && filter.ifindex != ifindex)
		return 0;

	switch (ncm->ncm_family) {
	case AF_INET:
		fprintf(fp, "ipv4 ");
		break;
	case AF_INET6:
		fprintf(fp, "ipv6 ");
		break;
	case AF_MPLS:
		fprintf(fp, "mpls ");
		break;
	default:
		fprintf(fp, "unknown ");
		break;
	}

	if (tb[NETCONFA_IFINDEX]) {
		switch (ifindex) {
		case NETCONFA_IFINDEX_ALL:
			fprintf(fp, "all ");
			break;
		case NETCONFA_IFINDEX_DEFAULT:
			fprintf(fp, "default ");
			break;
		default:
			fprintf(fp, "dev %s ", ll_index_to_name(ifindex));
			break;
		}
	}

	if (tb[NETCONFA_FORWARDING])
		print_onoff(fp, "forwarding",
				rta_getattr_u32(tb[NETCONFA_FORWARDING]));
	if (tb[NETCONFA_RP_FILTER]) {
		__u32 rp_filter = rta_getattr_u32(tb[NETCONFA_RP_FILTER]);

		if (rp_filter == 0)
			fprintf(fp, "rp_filter off ");
		else if (rp_filter == 1)
			fprintf(fp, "rp_filter strict ");
		else if (rp_filter == 2)
			fprintf(fp, "rp_filter loose ");
		else
			fprintf(fp, "rp_filter unknown mode ");
	}
	if (tb[NETCONFA_MC_FORWARDING])
		print_onoff(fp, "mc_forwarding",
				rta_getattr_u32(tb[NETCONFA_MC_FORWARDING]));

	if (tb[NETCONFA_PROXY_NEIGH])
		print_onoff(fp, "proxy_neigh",
				rta_getattr_u32(tb[NETCONFA_PROXY_NEIGH]));

	if (tb[NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN])
		print_onoff(fp, "ignore_routes_with_linkdown",
		     rta_getattr_u32(tb[NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN]));

	if (tb[NETCONFA_INPUT])
		print_onoff(fp, "input", rta_getattr_u32(tb[NETCONFA_INPUT]));

	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

static int print_netconf2(const struct sockaddr_nl *who,
			  struct nlmsghdr *n, void *arg)
{
	return print_netconf(who, NULL, n, arg);
}

void ipnetconf_reset_filter(int ifindex)
{
	memset(&filter, 0, sizeof(filter));
	filter.ifindex = ifindex;
}

static int do_show(int argc, char **argv)
{
	struct {
		struct nlmsghdr		n;
		struct netconfmsg	ncm;
		char			buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct netconfmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.n.nlmsg_type = RTM_GETNETCONF,
	};

	ipnetconf_reset_filter(0);
	filter.family = preferred_family;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			filter.ifindex = ll_name_to_index(*argv);
			if (filter.ifindex <= 0) {
				fprintf(stderr, "Device \"%s\" does not exist.\n",
					*argv);
				return -1;
			}
		}
		argv++; argc--;
	}

	ll_init_map(&rth);

	if (filter.ifindex && filter.family != AF_UNSPEC) {
		req.ncm.ncm_family = filter.family;
		addattr_l(&req.n, sizeof(req), NETCONFA_IFINDEX,
			  &filter.ifindex, sizeof(filter.ifindex));

		if (rtnl_send(&rth, &req.n, req.n.nlmsg_len) < 0) {
			perror("Can not send request");
			exit(1);
		}
		rtnl_listen(&rth, print_netconf, stdout);
	} else {
		rth.flags = RTNL_HANDLE_F_SUPPRESS_NLERR;
dump:
		if (rtnl_wilddump_request(&rth, filter.family, RTM_GETNETCONF) < 0) {
			perror("Cannot send dump request");
			exit(1);
		}
		if (rtnl_dump_filter(&rth, print_netconf2, stdout) < 0) {
			/* kernel does not support netconf dump on AF_UNSPEC;
			 * fall back to requesting by family
			 */
			if (errno == EOPNOTSUPP &&
			    filter.family == AF_UNSPEC) {
				filter.family = AF_INET;
				goto dump;
			}
			perror("RTNETLINK answers");
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}
		if (preferred_family == AF_UNSPEC && filter.family == AF_INET) {
			preferred_family = AF_INET6;
			filter.family = AF_INET6;
			goto dump;
		}
	}
	return 0;
}

int do_ipnetconf(int argc, char **argv)
{
	if (argc > 0) {
		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return do_show(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return do_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip netconf help\".\n", *argv);
	exit(-1);
}
