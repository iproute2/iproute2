/*
 * ipila.c	ILA (Identifier Locator Addressing) support
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:	Tom Herbert <tom@herbertland.com>
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/ila.h>
#include <linux/genetlink.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include "libgenl.h"
#include "utils.h"
#include "ip_common.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ip ila add loc_match LOCATOR_MATCH "
		"loc LOCATOR [ dev DEV ]\n");
	fprintf(stderr, "       ip ila del loc_match LOCATOR_MATCH "
		"[ loc LOCATOR ] [ dev DEV ]\n");
	fprintf(stderr, "       ip ila list\n");
	fprintf(stderr, "\n");

	exit(-1);
}

/* netlink socket */
static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

#define ILA_REQUEST(_req, _bufsiz, _cmd, _flags)	\
	GENL_REQUEST(_req, _bufsiz, genl_family, 0,	\
		     ILA_GENL_VERSION, _cmd, _flags)

#define ILA_RTA(g) ((struct rtattr *)(((char *)(g)) +	\
	NLMSG_ALIGN(sizeof(struct genlmsghdr))))

#define ADDR_BUF_SIZE sizeof("xxxx:xxxx:xxxx:xxxx")

static int print_addr64(__u64 addr, char *buff, size_t len)
{
	__u16 *words = (__u16 *)&addr;
	__u16 v;
	int i, ret;
	size_t written = 0;
	char *sep = ":";

	for (i = 0; i < 4; i++) {
		v = ntohs(words[i]);

		if (i == 3)
			sep = "";

		ret = snprintf(&buff[written], len - written, "%x%s", v, sep);
		if (ret < 0)
			return ret;

		written += ret;
	}

	return written;
}

static void print_ila_locid(FILE *fp, int attr, struct rtattr *tb[], int space)
{
	char abuf[256];
	size_t blen;
	int i;

	if (tb[attr]) {
		blen = print_addr64(rta_getattr_u32(tb[attr]),
				    abuf, sizeof(abuf));
		fprintf(fp, "%s", abuf);
	} else {
		fprintf(fp, "-");
		blen = 1;
	}

	for (i = 0; i < space - blen; i++)
		fprintf(fp, " ");
}

static int print_ila_mapping(const struct sockaddr_nl *who,
			     struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct genlmsghdr *ghdr;
	struct rtattr *tb[ILA_ATTR_MAX + 1];
	int len = n->nlmsg_len;

	if (n->nlmsg_type != genl_family)
		return 0;

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0)
		return -1;

	ghdr = NLMSG_DATA(n);
	parse_rtattr(tb, ILA_ATTR_MAX, (void *) ghdr + GENL_HDRLEN, len);

	print_ila_locid(fp, ILA_ATTR_LOCATOR_MATCH, tb, ADDR_BUF_SIZE);
	print_ila_locid(fp, ILA_ATTR_LOCATOR, tb, ADDR_BUF_SIZE);

	if (tb[ILA_ATTR_IFINDEX])
		fprintf(fp, "%s", ll_index_to_name(rta_getattr_u32(tb[ILA_ATTR_IFINDEX])));
	else
		fprintf(fp, "-");
	fprintf(fp, "\n");

	return 0;
}

#define NLMSG_BUF_SIZE 4096

static int do_list(int argc, char **argv)
{
	ILA_REQUEST(req, 1024, ILA_CMD_GET, NLM_F_REQUEST | NLM_F_DUMP);

	if (argc > 0) {
		fprintf(stderr, "\"ip ila show\" does not take "
			"any arguments.\n");
		return -1;
	}

	if (rtnl_send(&genl_rth, (void *)&req, req.n.nlmsg_len) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&genl_rth, print_ila_mapping, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return 1;
	}

	return 0;
}

static int ila_parse_opt(int argc, char **argv, struct nlmsghdr *n,
			 bool adding)
{
	__u64 locator = 0;
	__u64 locator_match = 0;
	int ifindex = 0;
	bool loc_set = false;
	bool loc_match_set = false;
	bool ifindex_set = false;

	while (argc > 0) {
		if (!matches(*argv, "loc")) {
			NEXT_ARG();

			if (get_addr64(&locator, *argv) < 0) {
				fprintf(stderr, "Bad locator: %s\n", *argv);
				return -1;
			}
			loc_set = true;
		} else if (!matches(*argv, "loc_match")) {
			NEXT_ARG();

			if (get_addr64(&locator_match, *argv) < 0) {
				fprintf(stderr, "Bad locator to match: %s\n",
					*argv);
				return -1;
			}
			loc_match_set = true;
		} else if (!matches(*argv, "dev")) {
			NEXT_ARG();

			ifindex = ll_name_to_index(*argv);
			if (ifindex == 0) {
				fprintf(stderr, "No such interface: %s\n",
					*argv);
				return -1;
			}
			ifindex_set = true;
		} else {
			usage();
			return -1;
		}
		argc--, argv++;
	}

	if (adding) {
		if (!loc_set) {
			fprintf(stderr, "ila: missing locator\n");
			return -1;
		}
		if (!loc_match_set) {
			fprintf(stderr, "ila: missing locator0match\n");
			return -1;
		}
	}

	if (loc_match_set)
		addattr64(n, 1024, ILA_ATTR_LOCATOR_MATCH, locator_match);

	if (loc_set)
		addattr64(n, 1024, ILA_ATTR_LOCATOR, locator);

	if (ifindex_set)
		addattr32(n, 1024, ILA_ATTR_IFINDEX, ifindex);

	return 0;
}

static int do_add(int argc, char **argv)
{
	ILA_REQUEST(req, 1024, ILA_CMD_ADD, NLM_F_REQUEST);

	ila_parse_opt(argc, argv, &req.n, true);

	if (rtnl_talk(&genl_rth, &req.n, NULL, 0) < 0)
		return -2;

	return 0;
}

static int do_del(int argc, char **argv)
{
	ILA_REQUEST(req, 1024, ILA_CMD_DEL, NLM_F_REQUEST);

	ila_parse_opt(argc, argv, &req.n, false);

	if (rtnl_talk(&genl_rth, &req.n, NULL, 0) < 0)
		return -2;

	return 0;
}

int do_ipila(int argc, char **argv)
{
	if (argc < 1)
		usage();

	if (matches(*argv, "help") == 0)
		usage();

	if (genl_init_handle(&genl_rth, ILA_GENL_NAME, &genl_family))
		exit(1);

	if (matches(*argv, "add") == 0)
		return do_add(argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return do_del(argc-1, argv+1);
	if (matches(*argv, "list") == 0)
		return do_list(argc-1, argv+1);

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip ila help\".\n",
		*argv);
	exit(-1);
}
