// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * monitor.c	RDMA tool
 * Authors:     Chiara Meiohas <cmeiohas@nvidia.com>
 */

#include "rdma.h"
#include "utils.h"

static int mon_is_supported_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	uint8_t *is_sup = data;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (tb[RDMA_NLDEV_SYS_ATTR_MONITOR_MODE])
		*is_sup = mnl_attr_get_u8(tb[RDMA_NLDEV_SYS_ATTR_MONITOR_MODE]);

	return MNL_CB_OK;
}

static int mon_is_supported(struct rd *rd, uint8_t *is_sup)
{
	uint32_t seq;
	int ret;

	*is_sup = 0;
	rd_prepare_msg(rd, RDMA_NLDEV_CMD_SYS_GET,
		       &seq, (NLM_F_REQUEST | NLM_F_ACK));
	ret = rd_send_msg(rd);
	if (ret)
		return ret;

	return rd_recv_msg(rd, mon_is_supported_cb, is_sup, seq);
}

static void mon_print_event_type(struct nlattr **tb)
{
	const char *const event_types_str[] = {
		[RDMA_REGISTER_EVENT] = "[REGISTER]",
		[RDMA_UNREGISTER_EVENT] = "[UNREGISTER]",
		[RDMA_NETDEV_ATTACH_EVENT] = "[NETDEV_ATTACH]",
		[RDMA_NETDEV_DETACH_EVENT] = "[NETDEV_DETACH]",
		[RDMA_RENAME_EVENT] = "[RENAME]",
		[RDMA_NETDEV_RENAME_EVENT] = "[NETDEV_RENAME]",
	};
	enum rdma_nl_notify_event_type etype;
	char unknown_type[32];

	if (!tb[RDMA_NLDEV_ATTR_EVENT_TYPE])
		return;

	etype = mnl_attr_get_u8(tb[RDMA_NLDEV_ATTR_EVENT_TYPE]);
	if (etype < ARRAY_SIZE(event_types_str) && event_types_str[etype]) {
		print_string(PRINT_ANY, "event_type", "%s\t",
			     event_types_str[etype]);
	} else {
		snprintf(unknown_type, sizeof(unknown_type), "[UNKNOWN 0x%02x]",
			 etype);
		print_string(PRINT_ANY, "event_type", "%s\t", unknown_type);
	}
}

static int mon_print_dev(struct nlattr **tb)
{
	const char *name;
	uint32_t idx;

	if (tb[RDMA_NLDEV_ATTR_DEV_INDEX]) {
		idx = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
		print_uint(PRINT_ANY, "rdma_index", "dev %u", idx);
	}

	if(tb[RDMA_NLDEV_ATTR_DEV_NAME]) {
		name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
		print_string(PRINT_ANY, "rdma_dev", " %s", name);
	}

	return 0;
}

static void mon_print_port_idx(struct nlattr **tb)
{
	uint32_t port;

	if (tb[RDMA_NLDEV_ATTR_PORT_INDEX]) {
		port = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_PORT_INDEX]);
		print_uint(PRINT_ANY, "port", " port %u", port);
	}
}

static void mon_print_netdev(struct nlattr **tb)
{
	uint32_t netdev_idx;
	const char *name;

	if (tb[RDMA_NLDEV_ATTR_NDEV_INDEX]) {
		netdev_idx = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_NDEV_INDEX]);
		print_uint(PRINT_ANY, "netdev_idx", " netdev %u", netdev_idx);
	}

	if(tb[RDMA_NLDEV_ATTR_NDEV_NAME]) {
		name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_NDEV_NAME]);
		print_string(PRINT_ANY, "netdev_name", " %s", name);
	}
}

static int mon_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX + 1] = {};

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_EVENT_TYPE])
		return MNL_CB_ERROR;

	open_json_object(NULL);

	mon_print_event_type(tb);
	mon_print_dev(tb);
	mon_print_port_idx(tb);
	mon_print_netdev(tb);

	close_json_object();
	newline();
	fflush(stdout);

	return MNL_CB_OK;
}

static int mon_show(struct rd* rd)
{
	unsigned int groups = 0;
	uint8_t is_sup = 0;
	int one = 1;
	char *buf;
	int err;

	err = mon_is_supported(rd, &is_sup);
	if (err) {
		pr_err("Failed to check if RDMA monitoring is supported\n");
		return err;
	}

	if (!is_sup) {
		pr_err("RDMA monitoring is not supported by the kernel\n");
		return -ENOENT;
	}

	buf = malloc(MNL_SOCKET_BUFFER_SIZE);
	if (!buf) {
		pr_err("Buffer allocation failed\n");
		return -ENOMEM;
	}

	rd->nl = mnl_socket_open(NETLINK_RDMA);
	if (!rd->nl) {
		pr_err("Failed to open NETLINK_RDMA socket. Error: %s\n",
		       strerror(errno));
		err = -ENODEV;
		goto err_free;
	}
	mnl_socket_setsockopt(rd->nl, NETLINK_CAP_ACK, &one, sizeof(one));
	mnl_socket_setsockopt(rd->nl, NETLINK_EXT_ACK, &one, sizeof(one));

	groups |= nl_mgrp(RDMA_NL_GROUP_NOTIFY);

	err = mnl_add_nl_group(rd->nl, groups);
	if (err < 0) {
		pr_err("Failed to add NETLINK_RDMA multicast group. Error: %s\n",
		       strerror(errno));
		goto err_close;
	}
	new_json_obj(json);

	err = mnlu_socket_recv_run(rd->nl, 0, buf, MNL_SOCKET_BUFFER_SIZE,
				   mon_show_cb, rd);
	if (err) {
		pr_err("Failed to listen to rdma socket\n");
		goto err_free_json;
	}

	return 0;

err_free_json:
	delete_json_obj();
err_close:
	mnl_socket_close(rd->nl);
err_free:
	free(buf);
	return err;
}

static int mon_help(struct rd *rd)
{
	pr_out("Usage: rdma monitor [ -j ]\n");
	return 0;
}

int cmd_mon(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		mon_show },
		{ "help",	mon_help },
		{ 0 }
	};

	return rd_exec_cmd(rd, cmds, "mon command");
}

