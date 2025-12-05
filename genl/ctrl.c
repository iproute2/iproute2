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

static void
print_ctrl_flag(const char *json_str, const char *fp_str)
{
	print_string(PRINT_JSON, NULL, NULL, json_str);
	print_string(PRINT_FP, NULL, " %s", fp_str);
}

static void print_ctrl_cmd_flags(__u32 fl)
{
	print_0xhex(PRINT_FP, "flags", "\n\t\tCapabilities (0x%x):\n ", fl);
	open_json_array(PRINT_JSON, "capabilities");

	if (fl != 0)
		print_string(PRINT_FP, NULL, "\t\t ", NULL);

	if (fl & GENL_ADMIN_PERM)
		print_ctrl_flag("admin", "requires admin permission;");
	if (fl & GENL_CMD_CAP_DO)
		print_ctrl_flag("do", "can doit;");
	if (fl & GENL_CMD_CAP_DUMP)
		print_ctrl_flag("dump", "can dumpit;");
	if (fl & GENL_CMD_CAP_HASPOL)
		print_ctrl_flag("policy", "has policy");
	close_json_array(PRINT_ANY, "\n");
}

static void
print_ctrl_cmd(const struct rtattr *arg)
{
	struct rtattr *tb[CTRL_ATTR_OP_MAX + 1];

	parse_rtattr_nested(tb, CTRL_ATTR_OP_MAX, arg);
	if (tb[CTRL_ATTR_OP_ID])
		print_0xhex(PRINT_ANY, "id", " ID-0x%x ",
			    rta_getattr_u32(tb[CTRL_ATTR_OP_ID]));

	/* we are only gonna do this for newer version of the controller */
	if (tb[CTRL_ATTR_OP_FLAGS])
		print_ctrl_cmd_flags(rta_getattr_u32(tb[CTRL_ATTR_OP_FLAGS]));
}

static void
print_ctrl_ops(const struct rtattr *attr)
{
	struct rtattr *tb2[GENL_MAX_FAM_OPS];
	unsigned int i;

	parse_rtattr_nested(tb2, GENL_MAX_FAM_OPS, attr);

	open_json_array(PRINT_JSON, "operations");
	print_string(PRINT_FP, NULL, "\tcommands supported: \n", NULL);

	for (i = 0; i < GENL_MAX_FAM_OPS; i++) {
		if (!tb2[i])
			continue;

		open_json_object(NULL);
		print_uint(PRINT_FP, NULL, "\t\t#%u: ", i);
		print_ctrl_cmd(tb2[i]);
		print_string(PRINT_FP, NULL, "\n", NULL);
		close_json_object();
	}

	/* end of family::cmds definitions .. */
	close_json_array(PRINT_JSON, NULL);
	print_string(PRINT_FP, NULL, "\n", NULL);
}

static void print_ctrl_grp(const struct rtattr *arg)
{
	struct rtattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1];

	open_json_object(NULL);

	parse_rtattr_nested(tb, CTRL_ATTR_MCAST_GRP_MAX, arg);
	if (tb[CTRL_ATTR_MCAST_GRP_ID])
		print_0xhex(PRINT_ANY, "id", " ID-0x%x ",
			    rta_getattr_u32(tb[CTRL_ATTR_MCAST_GRP_ID]));
	if (tb[CTRL_ATTR_MCAST_GRP_NAME]) {
		const char *name = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_NAME]);
		print_string(PRINT_ANY, "name", " name: %s ", name);
	}
	close_json_object();
}

static void print_ops(const struct rtattr *attr)
{
	const struct rtattr *pos;

	open_json_array(PRINT_JSON, "op");

	rtattr_for_each_nested(pos, attr) {
		struct rtattr *ptb[CTRL_ATTR_POLICY_DUMP_MAX + 1];
		struct rtattr *pattrs = RTA_DATA(pos);
		int plen = RTA_PAYLOAD(pos);

		parse_rtattr_flags(ptb, CTRL_ATTR_POLICY_DUMP_MAX, pattrs, plen, NLA_F_NESTED);

		print_uint(PRINT_ANY, "bits", " op %d policies:",
			   pos->rta_type & ~NLA_F_NESTED);

		if (ptb[CTRL_ATTR_POLICY_DO])
			print_uint(PRINT_ANY, "do", " do=%u",
				   rta_getattr_u32(ptb[CTRL_ATTR_POLICY_DO]));

		if (ptb[CTRL_ATTR_POLICY_DUMP])
			print_uint(PRINT_ANY, "dump", " dump=%d",
				   rta_getattr_u32(ptb[CTRL_ATTR_POLICY_DUMP]));

	}
	close_json_array(PRINT_JSON, NULL);
}

static void print_ctrl_mcast(const struct rtattr *attr)
{
	struct rtattr *tb2[GENL_MAX_FAM_GRPS + 1];
	unsigned int i;

	parse_rtattr_nested(tb2, GENL_MAX_FAM_GRPS, attr);

	open_json_array(PRINT_JSON, "mcast");
	print_string(PRINT_FP, NULL, "\tmulticast groups:\n", NULL);

	for (i = 0; i < GENL_MAX_FAM_GRPS; i++) {
		if (!tb2[i])
			continue;

		print_uint(PRINT_FP, NULL, "\t\t#%d: ", i);
		print_ctrl_grp(tb2[i]);

		/* for next group */
		print_string(PRINT_FP, NULL, "\n", NULL);
	}

	/* end of family::groups definitions .. */
	close_json_array(PRINT_JSON, NULL);
	print_string(PRINT_FP, NULL, "\n", NULL);
}

static const char *get_nla_type_str(unsigned int attr)
{
	switch (attr) {
#define C(x) case NL_ATTR_TYPE_ ## x: return #x
	C(U8);
	C(U16);
	C(U32);
	C(U64);
	C(STRING);
	C(FLAG);
	C(NESTED);
	C(NESTED_ARRAY);
	C(NUL_STRING);
	C(BINARY);
	C(S8);
	C(S16);
	C(S32);
	C(S64);
	C(BITFIELD32);
	default:
		return "unknown";
	}
}

static void print_policy_attr(const struct rtattr *attr)
{
	struct rtattr *tp[NL_POLICY_TYPE_ATTR_MAX + 1];

	parse_rtattr_nested(tp, ARRAY_SIZE(tp) - 1, attr);

	if (tp[NL_POLICY_TYPE_ATTR_TYPE]) {
		print_uint(PRINT_ANY, "attr", "attr[%u]:",
			   attr->rta_type & ~NLA_F_NESTED);
		print_string(PRINT_ANY, "type", " type=%s",
			get_nla_type_str(rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_TYPE])));
	}

	if (tp[NL_POLICY_TYPE_ATTR_POLICY_IDX])
		print_uint(PRINT_ANY, "policy", " policy:%u",
			rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_IDX]));

	if (tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE])
		print_uint(PRINT_ANY, "maxattr", " maxattr:%u",
			rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]));

	if (tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S] && tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]) {
		print_s64(PRINT_ANY, "min_value", " range:[%lld",
			  rta_getattr_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]));
		print_s64(PRINT_ANY, "max_value", "%lld]",
			  rta_getattr_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]));
	}

	if (tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U] && tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]) {
		print_u64(PRINT_ANY, "min_value", " range:[%llu",
			  rta_getattr_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]));
		print_u64(PRINT_ANY, "max_value", "%llu]",
			  rta_getattr_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]));
	}

	if (tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH])
		print_uint(PRINT_ANY, "min_length", " min len:%u",
			rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH]));

	if (tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH])
		print_uint(PRINT_ANY, "max_length", " max len:%u",
			rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH]));
}

static void print_policy(const struct rtattr *attr)
{
	const struct rtattr *pos;

	open_json_array(PRINT_JSON, NULL);
	rtattr_for_each_nested(pos, attr) {
		const struct rtattr *a;

		open_json_array(PRINT_JSON, NULL);

		print_uint(PRINT_ANY, "policy", " policy[%u]:", pos->rta_type & ~NLA_F_NESTED);

		rtattr_for_each_nested(a, pos) {
			open_json_object(NULL);
			print_policy_attr(a);
			close_json_object();
		}
		close_json_array(PRINT_JSON, NULL);
	}
	close_json_array(PRINT_JSON, NULL);
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
		const char *name = RTA_DATA(tb[CTRL_ATTR_FAMILY_NAME]);
		print_string(PRINT_ANY, "family", "\nName: %s\n", name);
	}

	if (tb[CTRL_ATTR_FAMILY_ID])
		print_0xhex(PRINT_ANY, "id", "\tID: 0x%x ",
			    rta_getattr_u16(tb[CTRL_ATTR_FAMILY_ID]));

	if (tb[CTRL_ATTR_VERSION])
		print_0xhex(PRINT_ANY, "version", " Version: 0x%x ",
			    rta_getattr_u32(tb[CTRL_ATTR_VERSION]));

	if (tb[CTRL_ATTR_HDRSIZE])
		print_uint(PRINT_ANY, "header_size", " header size: %u ",
			   rta_getattr_u32(tb[CTRL_ATTR_HDRSIZE]));

	if (tb[CTRL_ATTR_MAXATTR])
		print_uint(PRINT_ANY, "max_attr", " max attribs: %u ",
			   rta_getattr_u32(tb[CTRL_ATTR_MAXATTR]));

	if (tb[CTRL_ATTR_OP_POLICY])
		print_ops(tb[CTRL_ATTR_OP_POLICY]);

	if (tb[CTRL_ATTR_POLICY])
		print_policy(tb[CTRL_ATTR_POLICY]);

	/* end of family definitions .. */
	print_string(PRINT_FP, NULL,  "\n", NULL);

	if (tb[CTRL_ATTR_OPS])
		print_ctrl_ops(tb[CTRL_ATTR_OPS]);

	if (tb[CTRL_ATTR_MCAST_GROUPS])
		print_ctrl_mcast(tb[CTRL_ATTR_MCAST_GROUPS]);

	fflush(fp);
	return 0;
}

static int print_ctrl2(struct nlmsghdr *n, void *arg)
{
	open_json_object(NULL);
	print_ctrl(NULL, n, arg);
	close_json_object();
	return 0;
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

	new_json_obj(json);

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
	delete_json_obj();
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
