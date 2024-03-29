/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ctrl.c	generic netlink controller
 *
 * Authors:	J Hadi Salim (hadi@cyberus.ca)
 *		Johannes Berg (johannes@sipsolutions.net)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "genl_utils.h"

#define GENL_MAX_FAM_OPS	256
#define GENL_MAX_FAM_GRPS	256

static int usage(void)
{
	fprintf(stderr,"Usage: ctrl <CMD>\n" \
		       "CMD   := get <PARMS> | list | monitor | policy <PARMS>\n" \
		       "PARMS := name <name> | id <id>\n" \
		       "Examples:\n" \
		       "\tctrl ls\n" \
		       "\tctrl monitor\n" \
		       "\tctrl get name foobar\n" \
		       "\tctrl get id 0xF\n"
		       "\tctrl policy name foobar\n"
		       "\tctrl policy id 0xF\n");
	return -1;
}

static void print_ctrl_cmd_flags(FILE *fp, __u32 fl)
{
	fprintf(fp, "\n\t\tCapabilities (0x%x):\n ", fl);
	if (!fl) {
		fprintf(fp, "\n");
		return;
	}
	fprintf(fp, "\t\t ");

	if (fl & GENL_ADMIN_PERM)
		fprintf(fp, " requires admin permission;");
	if (fl & GENL_CMD_CAP_DO)
		fprintf(fp, " can doit;");
	if (fl & GENL_CMD_CAP_DUMP)
		fprintf(fp, " can dumpit;");
	if (fl & GENL_CMD_CAP_HASPOL)
		fprintf(fp, " has policy");

	fprintf(fp, "\n");
}

static int print_ctrl_cmds(FILE *fp, struct rtattr *arg)
{
	struct rtattr *tb[CTRL_ATTR_OP_MAX + 1];

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, CTRL_ATTR_OP_MAX, arg);
	if (tb[CTRL_ATTR_OP_ID]) {
		__u32 *id = RTA_DATA(tb[CTRL_ATTR_OP_ID]);
		fprintf(fp, " ID-0x%x ",*id);
	}
	/* we are only gonna do this for newer version of the controller */
	if (tb[CTRL_ATTR_OP_FLAGS]) {
		__u32 *fl = RTA_DATA(tb[CTRL_ATTR_OP_FLAGS]);
		print_ctrl_cmd_flags(fp, *fl);
	}
	return 0;

}

static int print_ctrl_grp(FILE *fp, struct rtattr *arg)
{
	struct rtattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1];

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, CTRL_ATTR_MCAST_GRP_MAX, arg);
	if (tb[2]) {
		__u32 *id = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_ID]);
		fprintf(fp, " ID-0x%x ",*id);
	}
	if (tb[1]) {
		char *name = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_NAME]);
		fprintf(fp, " name: %s ", name);
	}
	return 0;

}

/*
 * The controller sends one nlmsg per family
*/
static int print_ctrl(struct rtnl_ctrl_data *ctrl,
		      struct nlmsghdr *n, void *arg)
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
	    ghdr->cmd != CTRL_CMD_NEWFAMILY &&
	    ghdr->cmd != CTRL_CMD_NEWMCAST_GRP &&
	    ghdr->cmd != CTRL_CMD_DELMCAST_GRP &&
	    ghdr->cmd != CTRL_CMD_GETPOLICY) {
		fprintf(stderr, "Unknown controller command %d\n", ghdr->cmd);
		return 0;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		fprintf(stderr, "wrong controller message len %d\n", len);
		return -1;
	}

	attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
	parse_rtattr_flags(tb, CTRL_ATTR_MAX, attrs, len, NLA_F_NESTED);

	if (tb[CTRL_ATTR_FAMILY_NAME]) {
		char *name = RTA_DATA(tb[CTRL_ATTR_FAMILY_NAME]);
		fprintf(fp, "\nName: %s\n",name);
	}
	if (tb[CTRL_ATTR_FAMILY_ID]) {
		__u16 *id = RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
		fprintf(fp, "\tID: 0x%x ",*id);
	}
	if (tb[CTRL_ATTR_VERSION]) {
		__u32 *v = RTA_DATA(tb[CTRL_ATTR_VERSION]);
		fprintf(fp, " Version: 0x%x ",*v);
	}
	if (tb[CTRL_ATTR_HDRSIZE]) {
		__u32 *h = RTA_DATA(tb[CTRL_ATTR_HDRSIZE]);
		fprintf(fp, " header size: %d ",*h);
	}
	if (tb[CTRL_ATTR_MAXATTR]) {
		__u32 *ma = RTA_DATA(tb[CTRL_ATTR_MAXATTR]);
		fprintf(fp, " max attribs: %d ",*ma);
	}
	if (tb[CTRL_ATTR_OP_POLICY]) {
		const struct rtattr *pos;

		rtattr_for_each_nested(pos, tb[CTRL_ATTR_OP_POLICY]) {
			struct rtattr *ptb[CTRL_ATTR_POLICY_DUMP_MAX + 1];
			struct rtattr *pattrs = RTA_DATA(pos);
			int plen = RTA_PAYLOAD(pos);

			parse_rtattr_flags(ptb, CTRL_ATTR_POLICY_DUMP_MAX,
					   pattrs, plen, NLA_F_NESTED);

			fprintf(fp, " op %d policies:",
				pos->rta_type & ~NLA_F_NESTED);

			if (ptb[CTRL_ATTR_POLICY_DO]) {
				__u32 *v = RTA_DATA(ptb[CTRL_ATTR_POLICY_DO]);

				fprintf(fp, " do=%d", *v);
			}

			if (ptb[CTRL_ATTR_POLICY_DUMP]) {
				__u32 *v = RTA_DATA(ptb[CTRL_ATTR_POLICY_DUMP]);

				fprintf(fp, " dump=%d", *v);
			}
		}
	}
	if (tb[CTRL_ATTR_POLICY])
		nl_print_policy(tb[CTRL_ATTR_POLICY], fp);

	/* end of family definitions .. */
	fprintf(fp,"\n");
	if (tb[CTRL_ATTR_OPS]) {
		struct rtattr *tb2[GENL_MAX_FAM_OPS];
		int i=0;
		parse_rtattr_nested(tb2, GENL_MAX_FAM_OPS, tb[CTRL_ATTR_OPS]);
		fprintf(fp, "\tcommands supported: \n");
		for (i = 0; i < GENL_MAX_FAM_OPS; i++) {
			if (tb2[i]) {
				fprintf(fp, "\t\t#%d: ", i);
				if (0 > print_ctrl_cmds(fp, tb2[i])) {
					fprintf(fp, "Error printing command\n");
				}
				/* for next command */
				fprintf(fp,"\n");
			}
		}

		/* end of family::cmds definitions .. */
		fprintf(fp,"\n");
	}

	if (tb[CTRL_ATTR_MCAST_GROUPS]) {
		struct rtattr *tb2[GENL_MAX_FAM_GRPS + 1];
		int i;

		parse_rtattr_nested(tb2, GENL_MAX_FAM_GRPS,
				    tb[CTRL_ATTR_MCAST_GROUPS]);
		fprintf(fp, "\tmulticast groups:\n");

		for (i = 0; i < GENL_MAX_FAM_GRPS; i++) {
			if (tb2[i]) {
				fprintf(fp, "\t\t#%d: ", i);
				if (0 > print_ctrl_grp(fp, tb2[i]))
					fprintf(fp, "Error printing group\n");
				/* for next group */
				fprintf(fp,"\n");
			}
		}

		/* end of family::groups definitions .. */
		fprintf(fp,"\n");
	}

	fflush(fp);
	return 0;
}

static int print_ctrl2(struct nlmsghdr *n, void *arg)
{
	return print_ctrl(NULL, n, arg);
}

static int ctrl_list(int cmd, int argc, char **argv)
{
	struct rtnl_handle rth;
	int ret = -1;
	char d[GENL_NAMSIZ];
	struct {
		struct nlmsghdr         n;
		struct genlmsghdr	g;
		char                    buf[4096];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.n.nlmsg_type = GENL_ID_CTRL,
		.g.cmd = CTRL_CMD_GETFAMILY,
	};
	struct nlmsghdr *nlh = &req.n;
	struct nlmsghdr *answer = NULL;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC) < 0) {
		fprintf(stderr, "Cannot open generic netlink socket\n");
		exit(1);
	}

	if (cmd == CTRL_CMD_GETFAMILY || cmd == CTRL_CMD_GETPOLICY) {
		req.g.cmd = cmd;

		if (argc != 2) {
			fprintf(stderr, "Wrong number of params\n");
			goto ctrl_done;
		}

		if (matches(*argv, "name") == 0) {
			NEXT_ARG();
			strlcpy(d, *argv, sizeof(d));
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
	}

	if (cmd == CTRL_CMD_GETFAMILY) {
		if (rtnl_talk(&rth, nlh, &answer) < 0) {
			fprintf(stderr, "Error talking to the kernel\n");
			goto ctrl_done;
		}

		if (print_ctrl2(answer, (void *) stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			goto ctrl_done;
		}

	}

	if (cmd == CTRL_CMD_UNSPEC || cmd == CTRL_CMD_GETPOLICY) {
		nlh->nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
		nlh->nlmsg_seq = rth.dump = ++rth.seq;

		if (rtnl_send(&rth, nlh, nlh->nlmsg_len) < 0) {
			perror("Failed to send dump request\n");
			goto ctrl_done;
		}

		rtnl_dump_filter(&rth, print_ctrl2, stdout);

	}

	ret = 0;
ctrl_done:
	free(answer);
	rtnl_close(&rth);
	return ret;
}

static int ctrl_listen(int argc, char **argv)
{
	struct rtnl_handle rth;

	if (rtnl_open_byproto(&rth, nl_mgrp(GENL_ID_CTRL), NETLINK_GENERIC) < 0) {
		fprintf(stderr, "Cannot open generic netlink socket\n");
		return -1;
	}

	if (rtnl_listen(&rth, print_ctrl, (void *) stdout) < 0)
		exit(2);
	
	rtnl_close(&rth);	
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
	if (matches(*argv, "policy") == 0)
		return ctrl_list(CTRL_CMD_GETPOLICY, argc-1, argv+1);
	if (matches(*argv, "help") == 0)
		return usage();

	fprintf(stderr, "ctrl command \"%s\" is unknown, try \"ctrl help\".\n",
		*argv);

	return -1;
}

struct genl_util ctrl_genl_util = {
	.name = "ctrl",
	.parse_genlopt = parse_ctrl,
	.print_genlopt = print_ctrl2,
};
