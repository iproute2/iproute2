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

static void print_rqpn(uint32_t val, struct nlattr **nla_line)
{
	if (!nla_line[RDMA_NLDEV_ATTR_RES_RQPN])
		return;
	print_uint(PRINT_ANY, "rqpn", "rqpn %d ", val);
}

static void print_type(uint32_t val)
{
	print_string(PRINT_ANY, "type", "type %s ", qp_types_to_str(val));
}

/*
 * print the subtype only if the QPT is IB_QPT_DRIVER
 */
static void print_subtype(uint8_t type, const char *sub_type)
{
	if (type == 0xFF && sub_type)
		print_string(PRINT_ANY, "subtype", "subtype %s ", sub_type);
}

static void print_state(uint32_t val)
{
	print_string(PRINT_ANY, "state", "state %s ", qp_states_to_str(val));
}

static void print_rqpsn(uint32_t val, struct nlattr **nla_line)
{
	if (!nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN])
		return;

	print_uint(PRINT_ANY, "rq-psn", "rq-psn %d ", val);
}

static void print_pathmig(uint32_t val, struct nlattr **nla_line)
{
	if (!nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE])
		return;

	print_string(PRINT_ANY, "path-mig-state", "path-mig-state %s ", path_mig_to_str(val));
}

static int res_qp_line_raw(struct rd *rd, const char *name, int idx,
			   struct nlattr **nla_line)
{
	if (!nla_line[RDMA_NLDEV_ATTR_RES_RAW])
		return MNL_CB_ERROR;

	open_json_object(NULL);
	print_link(idx, name, rd->port_idx, nla_line);
	print_raw_data(rd, nla_line);
	close_json_object();
	newline();

	return MNL_CB_OK;
}

static int res_qp_line(struct rd *rd, const char *name, int idx,
		       struct nlattr **nla_line)
{
	uint32_t lqpn, rqpn = 0, rq_psn = 0, sq_psn;
	uint8_t type, state, path_mig_state = 0;
	const char *sub_type = NULL;
	uint32_t port = 0, pid = 0;
	uint32_t pdn = 0;
	char *comm = NULL;
	SPRINT_BUF(b);

	if (!nla_line[RDMA_NLDEV_ATTR_RES_LQPN] ||
	    !nla_line[RDMA_NLDEV_ATTR_RES_SQ_PSN] ||
	    !nla_line[RDMA_NLDEV_ATTR_RES_TYPE] ||
	    !nla_line[RDMA_NLDEV_ATTR_RES_STATE])
		return MNL_CB_ERROR;

	if (nla_line[RDMA_NLDEV_ATTR_PORT_INDEX])
		port = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_PORT_INDEX]);

	if (port != rd->port_idx)
		goto out;

	lqpn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_LQPN]);
	if (rd_is_filtered_attr(rd, "lqpn", lqpn,
				nla_line[RDMA_NLDEV_ATTR_RES_LQPN]))
		goto out;

	if (nla_line[RDMA_NLDEV_ATTR_RES_PDN])
		pdn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_PDN]);
	if (rd_is_filtered_attr(rd, "pdn", pdn,
				nla_line[RDMA_NLDEV_ATTR_RES_PDN]))
		goto out;

	if (nla_line[RDMA_NLDEV_ATTR_RES_RQPN])
		rqpn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_RQPN]);
	if (rd_is_filtered_attr(rd, "rqpn", rqpn,
				nla_line[RDMA_NLDEV_ATTR_RES_RQPN]))
		goto out;

	if (nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN])
		rq_psn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN]);
	if (rd_is_filtered_attr(rd, "rq-psn", rq_psn,
				nla_line[RDMA_NLDEV_ATTR_RES_RQ_PSN]))
		goto out;

	sq_psn = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_SQ_PSN]);
	if (rd_is_filtered_attr(rd, "sq-psn", sq_psn,
				nla_line[RDMA_NLDEV_ATTR_RES_SQ_PSN]))
		goto out;

	if (nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE])
		path_mig_state = mnl_attr_get_u8(
			nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE]);
	if (rd_is_string_filtered_attr(
		    rd, "path-mig-state", path_mig_to_str(path_mig_state),
		    nla_line[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE]))
		goto out;

	if (nla_line[RDMA_NLDEV_ATTR_RES_SUBTYPE])
		sub_type =
			mnl_attr_get_str(nla_line[RDMA_NLDEV_ATTR_RES_SUBTYPE]);

	type = mnl_attr_get_u8(nla_line[RDMA_NLDEV_ATTR_RES_TYPE]);
	if (rd_is_string_filtered_attr(rd, "type", qp_types_to_str(type),
				       nla_line[RDMA_NLDEV_ATTR_RES_TYPE]))
		goto out;

	state = mnl_attr_get_u8(nla_line[RDMA_NLDEV_ATTR_RES_STATE]);
	if (rd_is_string_filtered_attr(rd, "state", qp_states_to_str(state),
				       nla_line[RDMA_NLDEV_ATTR_RES_STATE]))
		goto out;

	if (nla_line[RDMA_NLDEV_ATTR_RES_PID]) {
		pid = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_PID]);
		if (!get_task_name(pid, b, sizeof(b)))
			comm = b;
	} else if (nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME]) {
		/* discard const from mnl_attr_get_str */
		comm = (char *)mnl_attr_get_str(
			nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME]);
	}

	if (rd_is_filtered_attr(rd, "pid", pid,
				nla_line[RDMA_NLDEV_ATTR_RES_PID]))
		goto out;

	open_json_object(NULL);
	print_link(idx, name, port, nla_line);
	res_print_u32("lqpn", lqpn, nla_line[RDMA_NLDEV_ATTR_RES_LQPN]);
	print_rqpn(rqpn, nla_line);

	print_type(type);
	print_subtype(type, sub_type);
	print_state(state);

	print_rqpsn(rq_psn, nla_line);
	res_print_u32("sq-psn", sq_psn, nla_line[RDMA_NLDEV_ATTR_RES_SQ_PSN]);

	print_pathmig(path_mig_state, nla_line);
	res_print_u32("pdn", pdn, nla_line[RDMA_NLDEV_ATTR_RES_PDN]);
	res_print_u32("pid", pid, nla_line[RDMA_NLDEV_ATTR_RES_PID]);
	print_comm(comm, nla_line);

	print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
	close_json_object();
	newline();
out:
	return MNL_CB_OK;
}

int res_qp_idx_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct rd *rd = data;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] || !tb[RDMA_NLDEV_ATTR_DEV_NAME])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);

	return (rd->show_raw) ? res_qp_line_raw(rd, name, idx, tb) :
		res_qp_line(rd, name, idx, tb);
}

int res_qp_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	int ret = MNL_CB_OK;
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

		ret = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (ret != MNL_CB_OK)
			break;

		ret = (rd->show_raw) ? res_qp_line_raw(rd, name, idx, nla_line) :
			res_qp_line(rd, name, idx, nla_line);
		if (ret != MNL_CB_OK)
			break;
	}
	return ret;
}
