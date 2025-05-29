/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ipmonitor.c		"ip monitor".
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "ip_common.h"
#include "nh_common.h"

static void usage(void) __attribute__((noreturn));
static int prefix_banner;
int listen_all_nsid;
struct rtnl_ctrl_data *ctrl_data;
int do_monitor;

static void usage(void)
{
	fprintf(stderr,
		"Usage: ip monitor [ all | OBJECTS ] [ FILE ] [ label ] [ all-nsid ]\n"
		"                  [ dev DEVICE ]\n"
		"OBJECTS :=  address | link | mroute | maddress | acaddress | neigh |\n"
		"            netconf | nexthop | nsid | prefix | route | rule | stats\n"
		"FILE := file FILENAME\n");
	exit(-1);
}

void print_headers(FILE *fp, const char *label)
{
	if (!do_monitor)
		return;

	if (timestamp)
		print_timestamp(fp);

	if (listen_all_nsid) {
		if (ctrl_data == NULL || ctrl_data->nsid < 0)
			fprintf(fp, "[nsid current]");
		else
			fprintf(fp, "[nsid %d]", ctrl_data->nsid);
	}

	if (prefix_banner)
		fprintf(fp, "%s", label);
}

static int accept_msg(struct rtnl_ctrl_data *ctrl,
		      struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;

	ctrl_data = ctrl;

	switch (n->nlmsg_type) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE: {
		struct rtmsg *r = NLMSG_DATA(n);
		int len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*r));

		if (len < 0) {
			fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
			return -1;
		}

		if (r->rtm_flags & RTM_F_CLONED)
			return 0;

		if (r->rtm_family == RTNL_FAMILY_IPMR ||
		    r->rtm_family == RTNL_FAMILY_IP6MR) {
			print_mroute(n, arg);
			return 0;
		} else {
			print_route(n, arg);
			return 0;
		}
	}

	case RTM_NEWNEXTHOP:
	case RTM_DELNEXTHOP:
		print_cache_nexthop(n, arg, true);
		return 0;

	case RTM_NEWNEXTHOPBUCKET:
	case RTM_DELNEXTHOPBUCKET:
		print_nexthop_bucket(n, arg);
		return 0;

	case RTM_NEWLINK:
	case RTM_DELLINK:
		ll_remember_index(n, NULL);
		print_linkinfo(n, arg);
		return 0;

	case RTM_NEWADDR:
	case RTM_DELADDR:
		print_addrinfo(n, arg);
		return 0;

	case RTM_NEWADDRLABEL:
	case RTM_DELADDRLABEL:
		print_addrlabel(n, arg);
		return 0;

	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
	case RTM_GETNEIGH:
		if (preferred_family) {
			struct ndmsg *r = NLMSG_DATA(n);

			if (r->ndm_family != preferred_family)
				return 0;
		}

		print_neigh(n, arg);
		return 0;

	case RTM_NEWPREFIX:
		print_prefix(n, arg);
		return 0;

	case RTM_NEWRULE:
	case RTM_DELRULE:
		print_rule(n, arg);
		return 0;

	case NLMSG_TSTAMP:
		print_nlmsg_timestamp(fp, n);
		return 0;

	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
		print_netconf(ctrl, n, arg);
		return 0;

	case RTM_DELNSID:
	case RTM_NEWNSID:
		print_nsid(n, arg);
		return 0;

	case RTM_NEWSTATS:
		ipstats_print(n, arg);
		return 0;

	case RTM_DELMULTICAST:
	case RTM_NEWMULTICAST:
	case RTM_DELANYCAST:
	case RTM_NEWANYCAST:
		print_addrinfo(n, arg);
		return 0;

	case NLMSG_ERROR:
	case NLMSG_NOOP:
	case NLMSG_DONE:
		break;	/* ignore */

	default:
		fprintf(stderr,
			"Unknown message: type=0x%08x(%d) flags=0x%08x(%d) len=0x%08x(%d)\n",
			n->nlmsg_type, n->nlmsg_type,
			n->nlmsg_flags, n->nlmsg_flags, n->nlmsg_len,
			n->nlmsg_len);
	}
	return 0;
}

#define IPMON_LLINK		BIT(0)
#define IPMON_LADDR		BIT(1)
#define IPMON_LROUTE		BIT(2)
#define IPMON_LMROUTE		BIT(3)
#define IPMON_LPREFIX		BIT(4)
#define IPMON_LNEIGH		BIT(5)
#define IPMON_LNETCONF		BIT(6)
#define IPMON_LSTATS		BIT(7)
#define IPMON_LRULE		BIT(8)
#define IPMON_LNSID		BIT(9)
#define IPMON_LNEXTHOP		BIT(10)
#define IPMON_LMADDR		BIT(11)
#define IPMON_LACADDR		BIT(12)

#define IPMON_L_ALL		(~0)

int do_ipmonitor(int argc, char **argv)
{
	unsigned int groups = 0, lmask = 0;
	/* "needed" mask, failure to enable is an error */
	unsigned int nmask;
	char *file = NULL;
	int ifindex = 0;

	rtnl_close(&rth);
	do_monitor = 1;

	while (argc > 0) {
		if (matches(*argv, "file") == 0) {
			NEXT_ARG();
			file = *argv;
		} else if (matches(*argv, "label") == 0) {
			prefix_banner = 1;
		} else if (matches(*argv, "link") == 0) {
			lmask |= IPMON_LLINK;
		} else if (matches(*argv, "address") == 0) {
			lmask |= IPMON_LADDR;
		} else if (matches(*argv, "maddress") == 0) {
			lmask |= IPMON_LMADDR;
		} else if (strcmp(*argv, "acaddress") == 0) {
			lmask |= IPMON_LACADDR;
		} else if (matches(*argv, "route") == 0) {
			lmask |= IPMON_LROUTE;
		} else if (matches(*argv, "mroute") == 0) {
			lmask |= IPMON_LMROUTE;
		} else if (matches(*argv, "prefix") == 0) {
			lmask |= IPMON_LPREFIX;
		} else if (matches(*argv, "neigh") == 0) {
			lmask |= IPMON_LNEIGH;
		} else if (matches(*argv, "netconf") == 0) {
			lmask |= IPMON_LNETCONF;
		} else if (matches(*argv, "rule") == 0) {
			lmask |= IPMON_LRULE;
		} else if (matches(*argv, "nsid") == 0) {
			lmask |= IPMON_LNSID;
		} else if (matches(*argv, "nexthop") == 0) {
			lmask |= IPMON_LNEXTHOP;
		} else if (strcmp(*argv, "stats") == 0) {
			lmask |= IPMON_LSTATS;
		} else if (strcmp(*argv, "all") == 0) {
			prefix_banner = 1;
		} else if (matches(*argv, "all-nsid") == 0) {
			listen_all_nsid = 1;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();

			ifindex = ll_name_to_index(*argv);
			if (!ifindex)
				invarg("Device does not exist\n", *argv);
		} else {
			fprintf(stderr, "Argument \"%s\" is unknown, try \"ip monitor help\".\n", *argv);
			exit(-1);
		}
		argc--;	argv++;
	}

	ipaddr_reset_filter(1, ifindex);
	iproute_reset_filter(ifindex);
	ipmroute_reset_filter(ifindex);
	ipneigh_reset_filter(ifindex);
	ipnetconf_reset_filter(ifindex);

	nmask = lmask;
	if (!lmask)
		lmask = IPMON_L_ALL;

	if (lmask & IPMON_LLINK)
		groups |= nl_mgrp(RTNLGRP_LINK);
	if (lmask & IPMON_LADDR) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_IFADDR);
	}
	if (lmask & IPMON_LROUTE) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_ROUTE);
		if (!preferred_family || preferred_family == AF_MPLS)
			groups |= nl_mgrp(RTNLGRP_MPLS_ROUTE);
	}
	if (lmask & IPMON_LMROUTE) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_MROUTE);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_MROUTE);
	}
	if (lmask & IPMON_LPREFIX) {
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_PREFIX);
	}
	if (lmask & IPMON_LNEIGH) {
		groups |= nl_mgrp(RTNLGRP_NEIGH);
	}
	if (lmask & IPMON_LNETCONF) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_NETCONF);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_NETCONF);
		if (!preferred_family || preferred_family == AF_MPLS)
			groups |= nl_mgrp(RTNLGRP_MPLS_NETCONF);
	}
	if (lmask & IPMON_LRULE) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_RULE);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_RULE);
	}
	if (lmask & IPMON_LNSID) {
		groups |= nl_mgrp(RTNLGRP_NSID);
	}

	if (file) {
		FILE *fp;
		int err;

		fp = fopen(file, "r");
		if (fp == NULL) {
			perror("Cannot fopen");
			exit(-1);
		}
		err = rtnl_from_file(fp, accept_msg, stdout);
		fclose(fp);
		return err;
	}

	if (rtnl_open(&rth, groups) < 0)
		exit(1);

	if (lmask & IPMON_LNEXTHOP &&
	    rtnl_add_nl_group(&rth, RTNLGRP_NEXTHOP) < 0) {
		if (errno != EINVAL) {
			fprintf(stderr, "Failed to add nexthop group to list\n");
			exit(1);
		}
	}

	if (lmask & IPMON_LSTATS &&
	    rtnl_add_nl_group(&rth, RTNLGRP_STATS) < 0 &&
	    nmask & IPMON_LSTATS) {
		if (errno != EINVAL) {
			fprintf(stderr, "Failed to add stats group to list\n");
			exit(1);
		}
	}

	if (lmask & IPMON_LMADDR) {
		if ((!preferred_family || preferred_family == AF_INET) &&
		    rtnl_add_nl_group(&rth, RTNLGRP_IPV4_MCADDR) < 0) {
			if (errno != EINVAL) {
				fprintf(stderr, "Failed to add ipv4 mcaddr group to list\n");
				exit(1);
			}
		}
		if ((!preferred_family || preferred_family == AF_INET6) &&
		    rtnl_add_nl_group(&rth, RTNLGRP_IPV6_MCADDR) < 0) {
			if (errno != EINVAL) {
				fprintf(stderr,
					"Failed to add ipv6 mcaddr group to list\n");
				exit(1);
			}
		}
	}

	if (lmask & IPMON_LACADDR) {
		if ((!preferred_family || preferred_family == AF_INET6) &&
		    rtnl_add_nl_group(&rth, RTNLGRP_IPV6_ACADDR) < 0) {
			if (errno != EINVAL) {
				fprintf(stderr, "Failed to add ipv6 acaddr group to list\n");
				exit(1);
			}
		}
	}

	if (listen_all_nsid && rtnl_listen_all_nsid(&rth) < 0)
		exit(1);

	ll_init_map(&rth);
	netns_nsid_socket_init();
	netns_map_init();

	if (rtnl_listen(&rth, accept_msg, stdout) < 0)
		exit(2);

	return 0;
}
