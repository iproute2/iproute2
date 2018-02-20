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
	pr_out("          resource show [qp]\n");
	pr_out("          resource show qp link [DEV/PORT]\n");
	pr_out("          resource show qp link [DEV/PORT] [FILTER-NAME FILTER-VALUE]\n");
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

static const char *path_mig_to_str(uint8_t idx)
{
	static const char * const path_mig_str[] = { "MIGRATED",
						     "REARM", "ARMED" };

	if (idx < ARRAY_SIZE(path_mig_str))
		return path_mig_str[idx];
	return "UNKNOWN";
}

static const char *qp_states_to_str(uint8_t idx)
{
	static const char * const qp_states_str[] = { "RESET", "INIT",
						      "RTR", "RTS", "SQD",
						      "SQE", "ERR" };

	if (idx < ARRAY_SIZE(qp_states_str))
		return qp_states_str[idx];
	return "UNKNOWN";
}

static const char *qp_types_to_str(uint8_t idx)
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

static void print_lqpn(struct rd *rd, uint32_t val)
{
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "lqpn", val);
	else
		pr_out("lqpn %u ", val);
}

static void print_rqpn(struct rd *rd, uint32_t val, struct nlattr **nla_line)
{
	if (!nla_line[RDMA_NLDEV_ATTR_RES_RQPN])
		return;

	if (rd->json_output)
		jsonw_uint_field(rd->jw, "rqpn", val);
	else
		pr_out("rqpn %u ", val);
}

static void print_type(struct rd *rd, uint32_t val)
{
	if (rd->json_output)
		jsonw_string_field(rd->jw, "type",
				   qp_types_to_str(val));
	else
		pr_out("type %s ", qp_types_to_str(val));
}

static void print_state(struct rd *rd, uint32_t val)
{
	if (rd->json_output)
		jsonw_string_field(rd->jw, "state",
				   qp_states_to_str(val));
	else
		pr_out("state %s ", qp_states_to_str(val));
}

static void print_rqpsn(struct rd *rd, uint32_t val, struct nlattr **nla_line)
{
	if (!nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN])
		return;

	if (rd->json_output)
		jsonw_uint_field(rd->jw, "rq-psn", val);
	else
		pr_out("rq-psn %u ", val);
}

static void print_sqpsn(struct rd *rd, uint32_t val)
{
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "sq-psn", val);
	else
		pr_out("sq-psn %u ", val);
}

static void print_pathmig(struct rd *rd, uint32_t val,
			  struct nlattr **nla_line)
{
	if (!nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE])
		return;

	if (rd->json_output)
		jsonw_string_field(rd->jw,
				   "path-mig-state",
				   path_mig_to_str(val));
	else
		pr_out("path-mig-state %s ", path_mig_to_str(val));
}

static void print_pid(struct rd *rd, uint32_t val)
{
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "pid", val);
	else
		pr_out("pid %u ", val);
}

static void print_comm(struct rd *rd, const char *str,
		       struct nlattr **nla_line)
{
	char tmp[18];

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

static void print_link(struct rd *rd, uint32_t idx, const char *name,
		       uint32_t port, struct nlattr **nla_line)
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

static char *get_task_name(uint32_t pid)
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

static int res_qp_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_QP])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx =  mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	nla_table = tb[RDMA_NLDEV_ATTR_RES_QP];

	mnl_attr_for_each_nested(nla_entry, nla_table) {
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};
		uint32_t lqpn, rqpn = 0, rq_psn = 0, sq_psn;
		uint8_t type, state, path_mig_state = 0;
		uint32_t port = 0, pid = 0;
		char *comm = NULL;
		int err;

		err = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (err != MNL_CB_OK)
			return MNL_CB_ERROR;

		if (!nla_line[RDMA_NLDEV_ATTR_RES_LQPN] ||
		    !nla_line[RDMA_NLDEV_ATTR_RES_SQ_PSN] ||
		    !nla_line[RDMA_NLDEV_ATTR_RES_TYPE] ||
		    !nla_line[RDMA_NLDEV_ATTR_RES_STATE] ||
		    (!nla_line[RDMA_NLDEV_ATTR_RES_PID] &&
		     !nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME])) {
			return MNL_CB_ERROR;
		}

		if (nla_line[RDMA_NLDEV_ATTR_PORT_INDEX])
			port = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_PORT_INDEX]);

		if (port != rd->port_idx)
			continue;

		lqpn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_LQPN]);
		if (rd_check_is_filtered(rd, "lqpn", lqpn))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_RQPN]) {
			rqpn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_RQPN]);
			if (rd_check_is_filtered(rd, "rqpn", rqpn))
				continue;
		} else {
			if (rd_check_is_key_exist(rd, "rqpn"))
				continue;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN]) {
			rq_psn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN]);
			if (rd_check_is_filtered(rd, "rq-psn", rq_psn))
				continue;
		} else {
			if (rd_check_is_key_exist(rd, "rq-psn"))
				continue;
		}

		sq_psn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_SQ_PSN]);
		if (rd_check_is_filtered(rd, "sq-psn", sq_psn))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE]) {
			path_mig_state = mnl_attr_get_u8(nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE]);
			if (rd_check_is_string_filtered(rd, "path-mig-state", path_mig_to_str(path_mig_state)))
				continue;
		} else {
			if (rd_check_is_key_exist(rd, "path-mig-state"))
				continue;
		}

		type = mnl_attr_get_u8(nla_line[RDMA_NLDEV_ATTR_RES_TYPE]);
		if (rd_check_is_string_filtered(rd, "type", qp_types_to_str(type)))
			continue;

		state = mnl_attr_get_u8(nla_line[RDMA_NLDEV_ATTR_RES_STATE]);
		if (rd_check_is_string_filtered(rd, "state", qp_states_to_str(state)))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID]) {
			pid = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_PID]);
			comm = get_task_name(pid);
		}

		if (rd_check_is_filtered(rd, "pid", pid)) {
			free(comm);
			continue;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME])
			/* discard const from mnl_attr_get_str */
			comm = (char *)mnl_attr_get_str(nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME]);

		if (rd->json_output)
			jsonw_start_array(rd->jw);

		print_link(rd, idx, name, port, nla_line);

		print_lqpn(rd, lqpn);
		print_rqpn(rd, rqpn, nla_line);

		print_type(rd, type);
		print_state(rd, state);

		print_rqpsn(rd, rq_psn, nla_line);
		print_sqpsn(rd, sq_psn);

		print_pathmig(rd, path_mig_state, nla_line);
		print_pid(rd, pid);
		print_comm(rd, comm, nla_line);

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID])
			free(comm);

		if (rd->json_output)
			jsonw_end_array(rd->jw);
		else
			pr_out("\n");
	}
	return MNL_CB_OK;
}

RES_FUNC(res_no_args,	RDMA_NLDEV_CMD_RES_GET,	NULL, true);

static const struct
filters qp_valid_filters[MAX_NUMBER_OF_FILTERS] = {{ .name = "link",
						   .is_number = false },
						   { .name = "lqpn",
						   .is_number = true },
						   { .name = "rqpn",
						   .is_number = true },
						   { .name = "pid",
						   .is_number = true },
						   { .name = "sq-psn",
						   .is_number = true },
						   { .name = "rq-psn",
						   .is_number = true },
						   { .name = "type",
						   .is_number = false },
						   { .name = "path-mig-state",
						   .is_number = false },
						   { .name = "state",
						   .is_number = false } };

RES_FUNC(res_qp,	RDMA_NLDEV_CMD_RES_QP_GET, qp_valid_filters, false);

static int res_show(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		res_no_args	},
		{ "qp",		res_qp		},
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
