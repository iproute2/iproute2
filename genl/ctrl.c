/*
 * ctrl.c	generic netlink controller
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:  J Hadi Salim (hadi@cyberus.ca)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "genl_utils.h"

static int usage(void)
{
	fprintf(stderr,"Usage: ctrl <CMD>\n" \
		       "CMD   := get <PARMS> | list | monitor\n" \
		       "PARMS := name <name> | id <id>\n" \
		       "Examples:\n" \
		       "\tctrl ls\n" \
		       "\tctrl monitor\n" \
		       "\tctrl get name foobar\n" \
		       "\tctrl get id 0xF\n");
	return -1;
}

int genl_ctrl_resolve_family(const char *family)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	int ret = 0;
	struct {
		struct nlmsghdr         n;
		char                    buf[4096];
	} req;

	memset(&req, 0, sizeof(req));

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = GENL_ID_CTRL;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = CTRL_CMD_GETFAMILY;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC) < 0) {
		fprintf(stderr, "Cannot open generic netlink socket\n");
		exit(1);
	}

	addattr_l(nlh, 128, CTRL_ATTR_FAMILY_NAME, family, strlen(family) + 1);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL) < 0) {
		fprintf(stderr, "Error talking to the kernel\n");
		goto errout;
	}

	{
		struct rtattr *tb[CTRL_ATTR_MAX + 1];
		struct genlmsghdr *ghdr = NLMSG_DATA(nlh);
		int len = nlh->nlmsg_len;
		struct rtattr *attrs;

		if (nlh->nlmsg_type !=  GENL_ID_CTRL) {
			fprintf(stderr, "Not a controller message, nlmsg_len=%d "
				"nlmsg_type=0x%x\n", nlh->nlmsg_len, nlh->nlmsg_type);
			goto errout;
		}

		if (ghdr->cmd != CTRL_CMD_NEWFAMILY) {
			fprintf(stderr, "Unkown controller command %d\n", ghdr->cmd);
			goto errout;
		}

		len -= NLMSG_LENGTH(GENL_HDRLEN);

		if (len < 0) {
			fprintf(stderr, "wrong controller message len %d\n", len);
			return -1;
		}

		attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
		parse_rtattr(tb, CTRL_ATTR_MAX, attrs, len);

		if (tb[CTRL_ATTR_FAMILY_ID] == NULL) {
			fprintf(stderr, "Missing family id TLV\n");
			goto errout;
		}

		ret = *(__u16 *) RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
	}

errout:
	rtnl_close(&rth);
	return ret;
}

static int print_ctrl(const struct sockaddr_nl *who, struct nlmsghdr *n,
		      void *arg)
{
	struct rtattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *attrs;
	FILE *fp = (FILE *) arg;

	if (n->nlmsg_type !=  GENL_ID_CTRL) {
		fprintf(stderr, "Not a controller message, nlmsg_len=%d "
			"nlmsg_type=0x%x\n", n->nlmsg_len, n->nlmsg_type);
		return 0;
	}

	if (ghdr->cmd != CTRL_CMD_GETFAMILY &&
	    ghdr->cmd != CTRL_CMD_DELFAMILY &&
	    ghdr->cmd != CTRL_CMD_NEWFAMILY) {
		fprintf(stderr, "Unkown controller command %d\n", ghdr->cmd);
		return 0;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		fprintf(stderr, "wrong controller message len %d\n", len);
		return -1;
	}

	attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
	parse_rtattr(tb, CTRL_ATTR_MAX, attrs, len);

	if (tb[CTRL_ATTR_FAMILY_NAME]) {
		char *name = RTA_DATA(tb[CTRL_ATTR_FAMILY_NAME]);
		fprintf(fp, "Name: %s\n",name);
	}
	if (tb[CTRL_ATTR_FAMILY_ID]) {
		__u16 *id = RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
		fprintf(fp, "ID: 0x%x\n",*id);
	}

	fflush(fp);
	return 0;
}

static int ctrl_list(int cmd, int argc, char **argv)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	int ret = -1;
	char d[GENL_NAMSIZ];
	struct {
		struct nlmsghdr         n;
		char                    buf[4096];
	} req;

	memset(&req, 0, sizeof(req));

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = GENL_ID_CTRL;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = CTRL_CMD_GETFAMILY;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC) < 0) {
		fprintf(stderr, "Cannot open generic netlink socket\n");
		exit(1);
	}

	if (cmd == CTRL_CMD_GETFAMILY) {
		if (argc != 2) {
			fprintf(stderr, "Wrong number of params\n");
			return -1;
		}

		if (matches(*argv, "name") == 0) {
			NEXT_ARG();
			strncpy(d, *argv, sizeof (d) - 1);
			addattr_l(nlh, 128, CTRL_ATTR_FAMILY_NAME,
				  d, strlen(d) + 1);
		} else if (matches(*argv, "id") == 0) {
			__u16 id;
			NEXT_ARG();
			if (get_u16(&id, *argv, 0)) {
				fprintf(stderr, "Illegal \"id\"\n");
				goto ctrl_done;
			}

			addattr_l(nlh, 128, CTRL_ATTR_FAMILY_ID, &id, 2);

		} else {
			fprintf(stderr, "Wrong params\n");
			goto ctrl_done;
		}

		if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL) < 0) {
			fprintf(stderr, "Error talking to the kernel\n");
			goto ctrl_done;
		}

		if (print_ctrl(NULL, nlh, (void *) stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			goto ctrl_done;
		}

	}

	if (cmd == CTRL_CMD_UNSPEC) {
		nlh->nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
		nlh->nlmsg_seq = rth.dump = ++rth.seq;

		if (rtnl_send(&rth, (const char *) nlh, nlh->nlmsg_len) < 0) {
			perror("Failed to send dump request\n");
			goto ctrl_done;
		}

		rtnl_dump_filter(&rth, print_ctrl, stdout, NULL, NULL);

        }

	ret = 0;
ctrl_done:
	rtnl_close(&rth);
	return ret;
}

static int ctrl_listen(int argc, char **argv)
{
	struct rtnl_handle rth;

	if (rtnl_open_byproto(&rth, nl_mgrp(GENL_ID_CTRL), NETLINK_GENERIC) < 0) {
		fprintf(stderr, "Canot open generic netlink socket\n");
		return -1;
	}

	if (rtnl_listen(&rth, print_ctrl, (void *) stdout) < 0)
		return -1;

	return 0;
}

static int parse_ctrl(struct genl_util *a, int argc, char **argv)
{
	argv++;
	if (--argc <= 0) {
		fprintf(stderr, "wrong controller params\n");
		return -1;
	}

	if (matches(*argv, "monitor") == 0)
		return ctrl_listen(argc-1, argv+1);
	if (matches(*argv, "get") == 0)
		return ctrl_list(CTRL_CMD_GETFAMILY, argc-1, argv+1);
	if (matches(*argv, "list") == 0 ||
	    matches(*argv, "show") == 0 ||
	    matches(*argv, "lst") == 0)
		return ctrl_list(CTRL_CMD_UNSPEC, argc-1, argv+1);
	if (matches(*argv, "help") == 0)
		return usage();

	fprintf(stderr, "ctrl command \"%s\" is unknown, try \"ctrl -help\".\n",
		*argv);

	return -1;
}

struct genl_util ctrl_genl_util = {
	.name = "ctrl",
	.parse_genlopt = parse_ctrl,
	.print_genlopt = print_ctrl,
};
