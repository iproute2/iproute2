// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * res.c	RDMA tool
 * Authors:     Leon Romanovsky <leonro@mellanox.com>
 */

#include "res.h"
#include <inttypes.h>

static int res_help(struct rd *rd)
{
	pr_out("Usage: %s resource\n", rd->filename);
	pr_out("          resource show [DEV]\n");
	pr_out("          resource show [qp|cm_id|pd|mr|cq]\n");
	pr_out("          resource show qp link [DEV/PORT]\n");
	pr_out("          resource show qp link [DEV/PORT] [FILTER-NAME FILTER-VALUE]\n");
	pr_out("          resource show cm_id link [DEV/PORT]\n");
	pr_out("          resource show cm_id link [DEV/PORT] [FILTER-NAME FILTER-VALUE]\n");
	pr_out("          resource show cq link [DEV/PORT]\n");
	pr_out("          resource show cq link [DEV/PORT] [FILTER-NAME FILTER-VALUE]\n");
	pr_out("          resource show pd dev [DEV]\n");
	pr_out("          resource show pd dev [DEV] [FILTER-NAME FILTER-VALUE]\n");
	pr_out("          resource show mr dev [DEV]\n");
	pr_out("          resource show mr dev [DEV] [FILTER-NAME FILTER-VALUE]\n");
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

		err = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (err != MNL_CB_OK)
			return -EINVAL;

		if (!nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_NAME] ||
		    !nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_CURR]) {
			return -EINVAL;
		}

		name = mnl_attr_get_str(nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_NAME]);
		curr = mnl_attr_get_u64(nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_CURR]);
		res_print_uint(
			rd, name, curr,
			nla_line[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_CURR]);
	}
	return 0;
}

static int res_no_args_idx_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	return MNL_CB_OK;
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

int _res_send_idx_msg(struct rd *rd, uint32_t command, mnl_cb_t callback,
		      uint32_t idx, uint32_t id)
{
	uint32_t flags = NLM_F_REQUEST | NLM_F_ACK;
	uint32_t seq;
	int ret;

	rd_prepare_msg(rd, command, &seq, flags);
	mnl_attr_put_u32(rd->nlh, RDMA_NLDEV_ATTR_DEV_INDEX, rd->dev_idx);
	if (rd->port_idx)
		mnl_attr_put_u32(rd->nlh,
				 RDMA_NLDEV_ATTR_PORT_INDEX, rd->port_idx);

	mnl_attr_put_u32(rd->nlh, id, idx);

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

int _res_send_msg(struct rd *rd, uint32_t command, mnl_cb_t callback)
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

const char *qp_types_to_str(uint8_t idx)
{
	static const char * const qp_types_str[] = { "SMI", "GSI", "RC",
						     "UC", "UD", "RAW_IPV6",
						     "RAW_ETHERTYPE",
						     "UNKNOWN", "RAW_PACKET",
						     "XRC_INI", "XRC_TGT" };

	if (idx < ARRAY_SIZE(qp_types_str))
		return qp_types_str[idx];
	return "UNKNOWN";
}

void print_comm(struct rd *rd, const char *str, struct nlattr **nla_line)
{
	char tmp[18];

	if (!str)
		return;

	if (rd->json_output) {
		/* Don't beatify output in JSON format */
		jsonw_string_field(rd->jw, "comm", str);
		return;
	}

	if (nla_line[RDMA_NLDEV_ATTR_RES_PID])
		snprintf(tmp, sizeof(tmp), "%s", str);
	else
		snprintf(tmp, sizeof(tmp), "[%s]", str);

	pr_out("comm %s ", tmp);
}

void print_dev(struct rd *rd, uint32_t idx, const char *name)
{
	if (rd->json_output) {
		jsonw_uint_field(rd->jw, "ifindex", idx);
		jsonw_string_field(rd->jw, "ifname", name);
	} else {
		pr_out("dev %s ", name);
	}
}

void print_link(struct rd *rd, uint32_t idx, const char *name, uint32_t port,
		struct nlattr **nla_line)
{
	if (rd->json_output) {
		jsonw_uint_field(rd->jw, "ifindex", idx);

		if (nla_line[RDMA_NLDEV_ATTR_PORT_INDEX])
			jsonw_uint_field(rd->jw, "port", port);

		jsonw_string_field(rd->jw, "ifname", name);
	} else {
		if (nla_line[RDMA_NLDEV_ATTR_PORT_INDEX])
			pr_out("link %s/%u ", name, port);
		else
			pr_out("link %s/- ", name);
	}
}

char *get_task_name(uint32_t pid)
{
	char *comm;
	FILE *f;

	if (asprintf(&comm, "/proc/%d/comm", pid) < 0)
		return NULL;

	f = fopen(comm, "r");
	free(comm);
	if (!f)
		return NULL;

	if (fscanf(f, "%ms\n", &comm) != 1)
		comm = NULL;

	fclose(f);

	return comm;
}

void print_key(struct rd *rd, const char *name, uint64_t val,
	       struct nlattr *nlattr)
{
	if (!nlattr)
		return;

	if (rd->json_output)
		jsonw_xint_field(rd->jw, name, val);
	else
		pr_out("%s 0x%" PRIx64 " ", name, val);
}

void res_print_uint(struct rd *rd, const char *name, uint64_t val,
		    struct nlattr *nlattr)
{
	if (!nlattr)
		return;

	if (rd->json_output)
		jsonw_u64_field(rd->jw, name, val);
	else
		pr_out("%s %" PRIu64 " ", name, val);
}

RES_FUNC(res_no_args,	RDMA_NLDEV_CMD_RES_GET,	NULL, true, 0);

static int res_show(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		res_no_args	},
		{ "qp",		res_qp		},
		{ "cm_id",	res_cm_id	},
		{ "cq",		res_cq		},
		{ "mr",		res_mr		},
		{ "pd",		res_pd		},
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
