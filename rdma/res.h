/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * res.h	RDMA tool
 * Authors:     Leon Romanovsky <leonro@mellanox.com>
 */
#ifndef _RDMA_TOOL_RES_H_
#define _RDMA_TOOL_RES_H_

#include "rdma.h"

int _res_send_msg(struct rd *rd, uint32_t command, mnl_cb_t callback);
int res_pd_parse_cb(const struct nlmsghdr *nlh, void *data);

#define RES_FUNC(name, command, valid_filters, strict_port) \
	static inline int _##name(struct rd *rd)\
	{ \
		return _res_send_msg(rd, command, name##_parse_cb); \
	} \
	static inline int name(struct rd *rd) \
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

static const
struct filters pd_valid_filters[MAX_NUMBER_OF_FILTERS] = {
	{ .name = "dev", .is_number = false },
	{ .name = "users", .is_number = true },
	{ .name = "pid", .is_number = true },
	{ .name = "ctxn", .is_number = true },
	{ .name = "pdn", .is_number = true },
	{ .name = "ctxn", .is_number = true }
};

RES_FUNC(res_pd, RDMA_NLDEV_CMD_RES_PD_GET, pd_valid_filters, true);

char *get_task_name(uint32_t pid);
void print_dev(struct rd *rd, uint32_t idx, const char *name);
void print_users(struct rd *rd, uint64_t val);
void print_key(struct rd *rd, const char *name, uint64_t val);
void res_print_uint(struct rd *rd, const char *name, uint64_t val);
void print_pid(struct rd *rd, uint32_t val);
void print_comm(struct rd *rd, const char *str, struct nlattr **nla_line);

#endif /* _RDMA_TOOL_RES_H_ */
