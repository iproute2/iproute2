// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * res-qp.c	RDMA tool
 * Authors:     Leon Romanovsky <leonro@mellanox.com>
 */

#include "res.h"
#include <inttypes.h>

static const char *path_mig_to_str(uint8_t idx)
{
	static const char *const path_mig_str[] = { "MIGRATED", "REARM",
						    "ARMED" };

	if (idx < ARRAY_SIZE(path_mig_str))
		return path_mig_str[idx];
	return "UNKNOWN";
}

static const char *qp_states_to_str(uint8_t idx)
{
	static const char *const qp_states_str[] = { "RESET", "INIT", "RTR",
						     "RTS",   "SQD",  "SQE",
						     "ERR" };

	if (idx < ARRAY_SIZE(qp_states_str))
		return qp_states_str[idx];
	return "UNKNOWN";
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
		jsonw_string_field(rd->jw, "type", qp_types_to_str(val));
	else
		pr_out("type %s ", qp_types_to_str(val));
}

static void print_state(struct rd *rd, uint32_t val)
{
	if (rd->json_output)
		jsonw_string_field(rd->jw, "state", qp_states_to_str(val));
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

static void print_pathmig(struct rd *rd, uint32_t val, struct nlattr **nla_line)
{
	if (!nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE])
		return;

	if (rd->json_output)
		jsonw_string_field(rd->jw, "path-mig-state",
				   path_mig_to_str(val));
	else
		pr_out("path-mig-state %s ", path_mig_to_str(val));
}

int res_qp_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] || !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_QP])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	nla_table = tb[RDMA_NLDEV_ATTR_RES_QP];

	mnl_attr_for_each_nested(nla_entry, nla_table) {
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};
		uint32_t lqpn, rqpn = 0, rq_psn = 0, sq_psn;
		uint8_t type, state, path_mig_state = 0;
		uint32_t port = 0, pid = 0;
		uint32_t pdn = 0;
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
			port = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_PORT_INDEX]);

		if (port != rd->port_idx)
			continue;

		lqpn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_LQPN]);
		if (rd_check_is_filtered(rd, "lqpn", lqpn))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_PDN])
			pdn = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_RES_PDN]);
		if (rd_check_is_filtered(rd, "pdn", pdn))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_RQPN]) {
			rqpn = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_RES_RQPN]);
			if (rd_check_is_filtered(rd, "rqpn", rqpn))
				continue;
		} else {
			if (rd_check_is_key_exist(rd, "rqpn"))
				continue;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN]) {
			rq_psn = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN]);
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
			path_mig_state = mnl_attr_get_u8(
				nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE]);
			if (rd_check_is_string_filtered(
				    rd, "path-mig-state",
				    path_mig_to_str(path_mig_state)))
				continue;
		} else {
			if (rd_check_is_key_exist(rd, "path-mig-state"))
				continue;
		}

		type = mnl_attr_get_u8(nla_line[RDMA_NLDEV_ATTR_RES_TYPE]);
		if (rd_check_is_string_filtered(rd, "type",
						qp_types_to_str(type)))
			continue;

		state = mnl_attr_get_u8(nla_line[RDMA_NLDEV_ATTR_RES_STATE]);
		if (rd_check_is_string_filtered(rd, "state",
						qp_states_to_str(state)))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID]) {
			pid = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_RES_PID]);
			comm = get_task_name(pid);
		}

		if (rd_check_is_filtered(rd, "pid", pid)) {
			free(comm);
			continue;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME])
			/* discard const from mnl_attr_get_str */
			comm = (char *)mnl_attr_get_str(
				nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME]);

		if (rd->json_output)
			jsonw_start_array(rd->jw);

		print_link(rd, idx, name, port, nla_line);

		print_lqpn(rd, lqpn);
		if (nla_line[RDMA_NLDEV_ATTR_RES_PDN])
			res_print_uint(rd, "pdn", pdn);
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

		print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
		newline(rd);
	}
	return MNL_CB_OK;
}
