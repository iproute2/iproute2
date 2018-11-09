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

static void print_dev(struct rd *rd, uint32_t idx, const char *name)
{
	if (rd->json_output) {
		jsonw_uint_field(rd->jw, "ifindex", idx);
		jsonw_string_field(rd->jw, "ifname", name);
	} else {
		pr_out("dev %s ", name);
	}
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

		print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
		newline(rd);
	}
	return MNL_CB_OK;
}

static void print_qp_type(struct rd *rd, uint32_t val)
{
	if (rd->json_output)
		jsonw_string_field(rd->jw, "qp-type",
				   qp_types_to_str(val));
	else
		pr_out("qp-type %s ", qp_types_to_str(val));
}

static const char *cm_id_state_to_str(uint8_t idx)
{
	static const char * const cm_id_states_str[] = {
		"IDLE", "ADDR_QUERY", "ADDR_RESOLVED", "ROUTE_QUERY",
		"ROUTE_RESOLVED", "CONNECT", "DISCONNECT", "ADDR_BOUND",
		"LISTEN", "DEVICE_REMOVAL", "DESTROYING" };

	if (idx < ARRAY_SIZE(cm_id_states_str))
		return cm_id_states_str[idx];
	return "UNKNOWN";
}

static const char *cm_id_ps_to_str(uint32_t ps)
{
	switch (ps) {
	case RDMA_PS_IPOIB:
		return "IPoIB";
	case RDMA_PS_IB:
		return "IPoIB";
	case RDMA_PS_TCP:
		return "TCP";
	case RDMA_PS_UDP:
		return "UDP";
	default:
		return "---";
	}
}

static void print_cm_id_state(struct rd *rd, uint8_t state)
{
	if (rd->json_output) {
		jsonw_string_field(rd->jw, "state", cm_id_state_to_str(state));
		return;
	}
	pr_out("state %s ", cm_id_state_to_str(state));
}

static void print_ps(struct rd *rd, uint32_t ps)
{
	if (rd->json_output) {
		jsonw_string_field(rd->jw, "ps", cm_id_ps_to_str(ps));
		return;
	}
	pr_out("ps %s ", cm_id_ps_to_str(ps));
}

static void print_ipaddr(struct rd *rd, const char *key, char *addrstr,
			 uint16_t port)
{
	if (rd->json_output) {
		int name_size = INET6_ADDRSTRLEN+strlen(":65535");
		char json_name[name_size];

		snprintf(json_name, name_size, "%s:%u", addrstr, port);
		jsonw_string_field(rd->jw, key, json_name);
		return;
	}
	pr_out("%s %s:%u ", key, addrstr, port);
}

static int ss_ntop(struct nlattr *nla_line, char *addr_str, uint16_t *port)
{
	struct __kernel_sockaddr_storage *addr;

	addr = (struct __kernel_sockaddr_storage *)
						mnl_attr_get_payload(nla_line);
	switch (addr->ss_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		if (!inet_ntop(AF_INET, (const void *)&sin->sin_addr, addr_str,
			       INET6_ADDRSTRLEN))
			return -EINVAL;
		*port = ntohs(sin->sin_port);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		if (!inet_ntop(AF_INET6, (const void *)&sin6->sin6_addr,
			       addr_str, INET6_ADDRSTRLEN))
			return -EINVAL;
		*port = ntohs(sin6->sin6_port);
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static int res_cm_id_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	const char *name;
	int idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_CM_ID])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx =  mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	nla_table = tb[RDMA_NLDEV_ATTR_RES_CM_ID];
	mnl_attr_for_each_nested(nla_entry, nla_table) {
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};
		char src_addr_str[INET6_ADDRSTRLEN];
		char dst_addr_str[INET6_ADDRSTRLEN];
		uint16_t src_port, dst_port;
		uint32_t port = 0, pid = 0;
		uint8_t type = 0, state;
		uint32_t lqpn = 0, ps;
		char *comm = NULL;
		int err;

		err = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (err != MNL_CB_OK)
			return -EINVAL;

		if (!nla_line[RDMA_NLDEV_ATTR_RES_STATE] ||
		    !nla_line[RDMA_NLDEV_ATTR_RES_PS] ||
		    (!nla_line[RDMA_NLDEV_ATTR_RES_PID] &&
		     !nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME])) {
			return MNL_CB_ERROR;
		}

		if (nla_line[RDMA_NLDEV_ATTR_PORT_INDEX])
			port = mnl_attr_get_u32(
					nla_line[RDMA_NLDEV_ATTR_PORT_INDEX]);

		if (port && port != rd->port_idx)
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_LQPN]) {
			lqpn = mnl_attr_get_u32(
					nla_line[RDMA_NLDEV_ATTR_RES_LQPN]);
			if (rd_check_is_filtered(rd, "lqpn", lqpn))
				continue;
		}
		if (nla_line[RDMA_NLDEV_ATTR_RES_TYPE]) {
			type = mnl_attr_get_u8(
					nla_line[RDMA_NLDEV_ATTR_RES_TYPE]);
			if (rd_check_is_string_filtered(rd, "qp-type",
							qp_types_to_str(type)))
				continue;
		}

		ps = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_PS]);
		if (rd_check_is_string_filtered(rd, "ps", cm_id_ps_to_str(ps)))
			continue;

		state = mnl_attr_get_u8(nla_line[RDMA_NLDEV_ATTR_RES_STATE]);
		if (rd_check_is_string_filtered(rd, "state",
						cm_id_state_to_str(state)))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_SRC_ADDR]) {
			if (ss_ntop(nla_line[RDMA_NLDEV_ATTR_RES_SRC_ADDR],
				    src_addr_str, &src_port))
				continue;
			if (rd_check_is_string_filtered(rd, "src-addr",
							src_addr_str))
				continue;
			if (rd_check_is_filtered(rd, "src-port", src_port))
				continue;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_DST_ADDR]) {
			if (ss_ntop(nla_line[RDMA_NLDEV_ATTR_RES_DST_ADDR],
				    dst_addr_str, &dst_port))
				continue;
			if (rd_check_is_string_filtered(rd, "dst-addr",
							dst_addr_str))
				continue;
			if (rd_check_is_filtered(rd, "dst-port", dst_port))
				continue;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID]) {
			pid = mnl_attr_get_u32(
					nla_line[RDMA_NLDEV_ATTR_RES_PID]);
			comm = get_task_name(pid);
		}

		if (rd_check_is_filtered(rd, "pid", pid)) {
			free(comm);
			continue;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME]) {
			/* discard const from mnl_attr_get_str */
			comm = (char *)mnl_attr_get_str(
				nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME]);
		}

		if (rd->json_output)
			jsonw_start_array(rd->jw);

		print_link(rd, idx, name, port, nla_line);
		if (nla_line[RDMA_NLDEV_ATTR_RES_LQPN])
			print_lqpn(rd, lqpn);
		if (nla_line[RDMA_NLDEV_ATTR_RES_TYPE])
			print_qp_type(rd, type);
		print_cm_id_state(rd, state);
		print_ps(rd, ps);
		print_pid(rd, pid);
		print_comm(rd, comm, nla_line);

		if (nla_line[RDMA_NLDEV_ATTR_RES_SRC_ADDR])
			print_ipaddr(rd, "src-addr", src_addr_str, src_port);
		if (nla_line[RDMA_NLDEV_ATTR_RES_DST_ADDR])
			print_ipaddr(rd, "dst-addr", dst_addr_str, dst_port);

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID])
			free(comm);

		print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
		newline(rd);
	}
	return MNL_CB_OK;
}

static void print_cqe(struct rd *rd, uint32_t val)
{
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "cqe", val);
	else
		pr_out("cqe %u ", val);
}

static void print_users(struct rd *rd, uint64_t val)
{
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "users", val);
	else
		pr_out("users %" PRIu64 " ", val);
}

static const char *poll_ctx_to_str(uint8_t idx)
{
	static const char * const cm_id_states_str[] = {
		"DIRECT", "SOFTIRQ", "WORKQUEUE"};

	if (idx < ARRAY_SIZE(cm_id_states_str))
		return cm_id_states_str[idx];
	return "UNKNOWN";
}

static void print_poll_ctx(struct rd *rd, uint8_t poll_ctx)
{
	if (rd->json_output) {
		jsonw_string_field(rd->jw, "poll-ctx",
				   poll_ctx_to_str(poll_ctx));
		return;
	}
	pr_out("poll-ctx %s ", poll_ctx_to_str(poll_ctx));
}

static int res_cq_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_CQ])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx =  mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	nla_table = tb[RDMA_NLDEV_ATTR_RES_CQ];

	mnl_attr_for_each_nested(nla_entry, nla_table) {
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};
		char *comm = NULL;
		uint32_t pid = 0;
		uint8_t poll_ctx = 0;
		uint64_t users;
		uint32_t cqe;
		int err;

		err = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (err != MNL_CB_OK)
			return MNL_CB_ERROR;

		if (!nla_line[RDMA_NLDEV_ATTR_RES_CQE] ||
		    !nla_line[RDMA_NLDEV_ATTR_RES_USECNT] ||
		    (!nla_line[RDMA_NLDEV_ATTR_RES_PID] &&
		     !nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME])) {
			return MNL_CB_ERROR;
		}

		cqe = mnl_attr_get_u32(nla_line[RDMA_NLDEV_ATTR_RES_CQE]);

		users = mnl_attr_get_u64(nla_line[RDMA_NLDEV_ATTR_RES_USECNT]);
		if (rd_check_is_filtered(rd, "users", users))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_POLL_CTX]) {
			poll_ctx = mnl_attr_get_u8(
					nla_line[RDMA_NLDEV_ATTR_RES_POLL_CTX]);
			if (rd_check_is_string_filtered(rd, "poll-ctx",
						poll_ctx_to_str(poll_ctx)))
				continue;
		}

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

		print_dev(rd, idx, name);
		print_cqe(rd, cqe);
		print_users(rd, users);
		if (nla_line[RDMA_NLDEV_ATTR_RES_POLL_CTX])
			print_poll_ctx(rd, poll_ctx);
		print_pid(rd, pid);
		print_comm(rd, comm, nla_line);

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID])
			free(comm);

		print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
		newline(rd);
	}
	return MNL_CB_OK;
}

static void print_key(struct rd *rd, const char *name, uint32_t val)
{
	if (rd->json_output)
		jsonw_xint_field(rd->jw, name, val);
	else
		pr_out("%s 0x%x ", name, val);
}

static void print_iova(struct rd *rd, uint64_t val)
{
	if (rd->json_output)
		jsonw_xint_field(rd->jw, "iova", val);
	else
		pr_out("iova 0x%" PRIx64 " ", val);
}

static void print_mrlen(struct rd *rd, uint64_t val)
{
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "mrlen", val);
	else
		pr_out("mrlen %" PRIu64 " ", val);
}

static int res_mr_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_MR])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx =  mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	nla_table = tb[RDMA_NLDEV_ATTR_RES_MR];

	mnl_attr_for_each_nested(nla_entry, nla_table) {
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};
		uint32_t rkey = 0, lkey = 0;
		uint64_t iova = 0, mrlen;
		char *comm = NULL;
		uint32_t pid = 0;
		int err;

		err = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (err != MNL_CB_OK)
			return MNL_CB_ERROR;

		if (!nla_line[RDMA_NLDEV_ATTR_RES_MRLEN] ||
		    (!nla_line[RDMA_NLDEV_ATTR_RES_PID] &&
		     !nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME])) {
			return MNL_CB_ERROR;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_RKEY])
			rkey = mnl_attr_get_u32(
					nla_line[RDMA_NLDEV_ATTR_RES_RKEY]);
		if (nla_line[RDMA_NLDEV_ATTR_RES_LKEY])
			lkey = mnl_attr_get_u32(
					nla_line[RDMA_NLDEV_ATTR_RES_LKEY]);
		if (nla_line[RDMA_NLDEV_ATTR_RES_IOVA])
			iova = mnl_attr_get_u64(
					nla_line[RDMA_NLDEV_ATTR_RES_IOVA]);

		mrlen = mnl_attr_get_u64(nla_line[RDMA_NLDEV_ATTR_RES_MRLEN]);
		if (rd_check_is_filtered(rd, "mrlen", mrlen))
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

		print_dev(rd, idx, name);
		if (nla_line[RDMA_NLDEV_ATTR_RES_RKEY])
			print_key(rd, "rkey", rkey);
		if (nla_line[RDMA_NLDEV_ATTR_RES_LKEY])
			print_key(rd, "lkey", lkey);
		if (nla_line[RDMA_NLDEV_ATTR_RES_IOVA])
			print_iova(rd, iova);
		print_mrlen(rd, mrlen);
		print_pid(rd, pid);
		print_comm(rd, comm, nla_line);

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID])
			free(comm);

		print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
		newline(rd);
	}
	return MNL_CB_OK;
}

static int res_pd_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_PD])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx =  mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	nla_table = tb[RDMA_NLDEV_ATTR_RES_PD];

	mnl_attr_for_each_nested(nla_entry, nla_table) {
		uint32_t local_dma_lkey = 0, unsafe_global_rkey = 0;
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};
		char *comm = NULL;
		uint32_t pid = 0;
		uint64_t users;
		int err;

		err = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (err != MNL_CB_OK)
			return MNL_CB_ERROR;

		if (!nla_line[RDMA_NLDEV_ATTR_RES_USECNT] ||
		    (!nla_line[RDMA_NLDEV_ATTR_RES_PID] &&
		     !nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME])) {
			return MNL_CB_ERROR;
		}

		if (nla_line[RDMA_NLDEV_ATTR_RES_LOCAL_DMA_LKEY])
			local_dma_lkey = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_RES_LOCAL_DMA_LKEY]);

		users = mnl_attr_get_u64(nla_line[RDMA_NLDEV_ATTR_RES_USECNT]);
		if (rd_check_is_filtered(rd, "users", users))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_UNSAFE_GLOBAL_RKEY])
			unsafe_global_rkey = mnl_attr_get_u32(
			      nla_line[RDMA_NLDEV_ATTR_RES_UNSAFE_GLOBAL_RKEY]);

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID]) {
			pid = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_RES_PID]);
			comm = get_task_name(pid);
		}

		if (rd_check_is_filtered(rd, "pid", pid))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME])
			/* discard const from mnl_attr_get_str */
			comm = (char *)mnl_attr_get_str(
				nla_line[RDMA_NLDEV_ATTR_RES_KERN_NAME]);

		if (rd->json_output)
			jsonw_start_array(rd->jw);

		print_dev(rd, idx, name);
		if (nla_line[RDMA_NLDEV_ATTR_RES_LOCAL_DMA_LKEY])
			print_key(rd, "local_dma_lkey", local_dma_lkey);
		print_users(rd, users);
		if (nla_line[RDMA_NLDEV_ATTR_RES_UNSAFE_GLOBAL_RKEY])
			print_key(rd, "unsafe_global_rkey", unsafe_global_rkey);
		print_pid(rd, pid);
		print_comm(rd, comm, nla_line);

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID])
			free(comm);

		print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
		newline(rd);
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

static const
struct filters cm_id_valid_filters[MAX_NUMBER_OF_FILTERS] = {
	{ .name = "link", .is_number = false },
	{ .name = "lqpn", .is_number = true },
	{ .name = "qp-type", .is_number = false },
	{ .name = "state", .is_number = false },
	{ .name = "ps", .is_number = false },
	{ .name = "dev-type", .is_number = false },
	{ .name = "transport-type", .is_number = false },
	{ .name = "pid", .is_number = true },
	{ .name = "src-addr", .is_number = false },
	{ .name = "src-port", .is_number = true },
	{ .name = "dst-addr", .is_number = false },
	{ .name = "dst-port", .is_number = true }
};

RES_FUNC(res_cm_id, RDMA_NLDEV_CMD_RES_CM_ID_GET, cm_id_valid_filters, false);

static const
struct filters cq_valid_filters[MAX_NUMBER_OF_FILTERS] = {
	{ .name = "dev", .is_number = false },
	{ .name = "users", .is_number = true },
	{ .name = "poll-ctx", .is_number = false },
	{ .name = "pid", .is_number = true }
};

RES_FUNC(res_cq, RDMA_NLDEV_CMD_RES_CQ_GET, cq_valid_filters, true);

static const
struct filters mr_valid_filters[MAX_NUMBER_OF_FILTERS] = {
	{ .name = "dev", .is_number = false },
	{ .name = "rkey", .is_number = true },
	{ .name = "lkey", .is_number = true },
	{ .name = "mrlen", .is_number = true },
	{ .name = "pid", .is_number = true }
};

RES_FUNC(res_mr, RDMA_NLDEV_CMD_RES_MR_GET, mr_valid_filters, true);

static const
struct filters pd_valid_filters[MAX_NUMBER_OF_FILTERS] = {
	{ .name = "dev", .is_number = false },
	{ .name = "users", .is_number = true },
	{ .name = "pid", .is_number = true }
};

RES_FUNC(res_pd, RDMA_NLDEV_CMD_RES_PD_GET, pd_valid_filters, true);

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
