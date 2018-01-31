/*
 * res.c	RDMA tool
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Leon Romanovsky <leonro@mellanox.com>
 */

#include "rdma.h"
#include <inttypes.h>

static int res_help(struct rd *rd)
{
	pr_out("Usage: %s resource\n", rd->filename);
	pr_out("          resource show [DEV]\n");
	return 0;
}

static int res_print_summary(struct rd *rd, struct nlattr **tb)
{
	struct nlattr *nla_table = tb[RDMA_NLDEV_ATTR_RES_SUMMARY];
	struct nlattr *nla_entry;
	const char *name;
	uint64_t curr;
	int err;

	mnl_attr_for_each_nested(nla_entry, nla_table) {
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};
		char json_name[32];

		err = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (err != MNL_CB_OK)
			return -EINVAL;

		if (!nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_NAME] ||
		    !nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_CURR]) {
			return -EINVAL;
		}

		name = mnl_attr_get_str(nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_NAME]);
		curr = mnl_attr_get_u64(nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_CURR]);
		if (rd->json_output) {
			snprintf(json_name, 32, "%s", name);
			jsonw_lluint_field(rd->jw, json_name, curr);
		} else {
			pr_out("%s %"PRId64 " ", name, curr);
		}
	}
	return 0;
}

static int res_no_args_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct rd *rd = data;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_SUMMARY])
		return MNL_CB_ERROR;

	idx =  mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	if (rd->json_output) {
		jsonw_uint_field(rd->jw, "ifindex", idx);
		jsonw_string_field(rd->jw, "ifname", name);
	} else {
		pr_out("%u: %s: ", idx, name);
	}

	res_print_summary(rd, tb);

	if (!rd->json_output)
		pr_out("\n");
	return MNL_CB_OK;
}

static int _res_send_msg(struct rd *rd, uint32_t command, mnl_cb_t callback)
{
	uint32_t flags = NLM_F_REQUEST | NLM_F_ACK;
	uint32_t seq;
	int ret;

	if (command != RDMA_NLDEV_CMD_RES_GET)
		flags |= NLM_F_DUMP;

	rd_prepare_msg(rd, command, &seq, flags);
	mnl_attr_put_u32(rd->nlh, RDMA_NLDEV_ATTR_DEV_INDEX, rd->dev_idx);
	if (rd->port_idx)
		mnl_attr_put_u32(rd->nlh,
				 RDMA_NLDEV_ATTR_PORT_INDEX, rd->port_idx);

	ret = rd_send_msg(rd);
	if (ret)
		return ret;

	if (rd->json_output)
		jsonw_start_object(rd->jw);
	ret = rd_recv_msg(rd, callback, rd, seq);
	if (rd->json_output)
		jsonw_end_object(rd->jw);
	return ret;
}

#define RES_FUNC(name, command, valid_filters, strict_port) \
	static int _##name(struct rd *rd)\
	{ \
		return _res_send_msg(rd, command, name##_parse_cb); \
	} \
	static int name(struct rd *rd) \
	{\
		int ret = rd_build_filter(rd, valid_filters); \
		if (ret) \
			return ret; \
		if ((uintptr_t)valid_filters != (uintptr_t)NULL) { \
			ret = rd_set_arg_to_devname(rd); \
			if (ret) \
				return ret;\
		} \
		if (strict_port) \
			return rd_exec_dev(rd, _##name); \
		else \
			return rd_exec_link(rd, _##name, strict_port); \
	}

RES_FUNC(res_no_args,	RDMA_NLDEV_CMD_RES_GET,	NULL, true);

static int res_show(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		res_no_args	},
		{ 0 }
	};

	/*
	 * Special case to support "rdma res show DEV_NAME"
	 */
	if (rd_argc(rd) == 1 && dev_map_lookup(rd, false))
		return rd_exec_dev(rd, _res_no_args);

	return rd_exec_cmd(rd, cmds, "parameter");
}

int cmd_res(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		res_show },
		{ "show",	res_show },
		{ "list",	res_show },
		{ "help",	res_help },
		{ 0 }
	};

	return rd_exec_cmd(rd, cmds, "resource command");
}
