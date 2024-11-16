// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * sys.c	RDMA tool
 */

#include "rdma.h"

static int sys_help(struct rd *rd)
{
	pr_out("Usage: %s system show [ netns ]\n", rd->filename);
	pr_out("       %s system set netns { shared | exclusive }\n", rd->filename);
	return 0;
}

static const char *netns_modes_str[] = {
	"exclusive",
	"shared",
};

static int sys_show_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	uint8_t mon_mode = 0;
	bool cof = false;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);

	if (tb[RDMA_NLDEV_SYS_ATTR_NETNS_MODE]) {
		const char *mode_str;
		uint8_t netns_mode;

		netns_mode =
			mnl_attr_get_u8(tb[RDMA_NLDEV_SYS_ATTR_NETNS_MODE]);

		if (netns_mode < ARRAY_SIZE(netns_modes_str))
			mode_str = netns_modes_str[netns_mode];
		else
			mode_str = "unknown";

		print_string(PRINT_ANY, "netns", "netns %s ", mode_str);
	}

	if (tb[RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE]) {
		uint8_t mode;

		mode = mnl_attr_get_u8(tb[RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE]);

		print_on_off(PRINT_ANY, "privileged-qkey", "privileged-qkey %s ", mode);

	}

	if (tb[RDMA_NLDEV_SYS_ATTR_MONITOR_MODE])
		mon_mode = mnl_attr_get_u8(tb[RDMA_NLDEV_SYS_ATTR_MONITOR_MODE]);
	print_on_off(PRINT_ANY, "monitor", "monitor %s ", mon_mode);

	if (tb[RDMA_NLDEV_SYS_ATTR_COPY_ON_FORK])
		cof = mnl_attr_get_u8(tb[RDMA_NLDEV_SYS_ATTR_COPY_ON_FORK]);

	print_on_off(PRINT_ANY, "copy-on-fork", "copy-on-fork %s", cof);
	print_nl();

	return MNL_CB_OK;
}

static int sys_show_no_args(struct rd *rd)
{
	uint32_t seq;
	int ret;

	rd_prepare_msg(rd, RDMA_NLDEV_CMD_SYS_GET,
		       &seq, (NLM_F_REQUEST | NLM_F_ACK));
	ret = rd_send_msg(rd);
	if (ret)
		return ret;

	return rd_recv_msg(rd, sys_show_parse_cb, rd, seq);
}

static int sys_show(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,			sys_show_no_args},
		{ "netns",		sys_show_no_args},
		{ "privileged-qkey",	sys_show_no_args},
		{ "monitor",		sys_show_no_args},
		{ 0 }
	};

	return rd_exec_cmd(rd, cmds, "parameter");
}

static int sys_set_netns_cmd(struct rd *rd, bool enable)
{
	uint32_t seq;

	rd_prepare_msg(rd, RDMA_NLDEV_CMD_SYS_SET,
		       &seq, (NLM_F_REQUEST | NLM_F_ACK));
	mnl_attr_put_u8(rd->nlh, RDMA_NLDEV_SYS_ATTR_NETNS_MODE, enable);

	return rd_sendrecv_msg(rd, seq);
}

static int sys_set_privileged_qkey_cmd(struct rd *rd, bool enable)
{
	uint32_t seq;

	rd_prepare_msg(rd, RDMA_NLDEV_CMD_SYS_SET,
		       &seq, (NLM_F_REQUEST | NLM_F_ACK));
	mnl_attr_put_u8(rd->nlh, RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE, enable);

	return rd_sendrecv_msg(rd, seq);
}

static bool sys_valid_netns_cmd(const char *cmd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(netns_modes_str); i++) {
		if (!strcmp(cmd, netns_modes_str[i]))
			return true;
	}
	return false;
}

static int sys_set_netns_args(struct rd *rd)
{
	bool cmd;

	if (rd_no_arg(rd) || !sys_valid_netns_cmd(rd_argv(rd))) {
		pr_err("valid options are: { shared | exclusive }\n");
		return -EINVAL;
	}

	cmd = (strcmp(rd_argv(rd), "shared") == 0) ? true : false;

	return sys_set_netns_cmd(rd, cmd);
}

static int sys_set_privileged_qkey_args(struct rd *rd)
{
	bool cmd;
	int ret;

	if (rd_no_arg(rd)) {
		pr_err("valid options are: { on | off }\n");
		return -EINVAL;
	}

	cmd = parse_on_off("privileged-qkey", rd_argv(rd), &ret);
	if (ret)
		return -EINVAL;

	return sys_set_privileged_qkey_cmd(rd, cmd);
}

static int sys_set_help(struct rd *rd)
{
	pr_out("Usage: %s system set [PARAM] value\n", rd->filename);
	pr_out("            system set netns { shared | exclusive }\n");
	pr_out("            system set privileged-qkey { on | off }\n");
	return 0;
}

static int sys_set(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,			sys_set_help },
		{ "help",		sys_set_help },
		{ "netns",		sys_set_netns_args},
		{ "privileged-qkey",	sys_set_privileged_qkey_args},
		{ 0 }
	};

	return rd_exec_cmd(rd, cmds, "parameter");
}

int cmd_sys(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		sys_show },
		{ "show",	sys_show },
		{ "set",	sys_set },
		{ "help",	sys_help },
		{ 0 }
	};

	return rd_exec_cmd(rd, cmds, "system command");
}
