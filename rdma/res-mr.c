// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * res-mr.c	RDMA tool
 * Authors:     Leon Romanovsky <leonro@mellanox.com>
 */

#include "res.h"
#include <inttypes.h>

int res_mr_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] || !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_MR])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	nla_table = tb[RDMA_NLDEV_ATTR_RES_MR];

	mnl_attr_for_each_nested(nla_entry, nla_table) {
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};
		uint32_t rkey = 0, lkey = 0;
		uint64_t iova = 0, mrlen;
		char *comm = NULL;
		uint32_t pdn = 0;
		uint32_t mrn = 0;
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

		if (nla_line[RDMA_NLDEV_ATTR_RES_MRN])
			mrn = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_RES_MRN]);
		if (rd_check_is_filtered(rd, "mrn", mrn))
			continue;

		if (nla_line[RDMA_NLDEV_ATTR_RES_PDN])
			pdn = mnl_attr_get_u32(
				nla_line[RDMA_NLDEV_ATTR_RES_PDN]);
		if (rd_check_is_filtered(rd, "pdn", pdn))
			continue;

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
			print_key(rd, "iova", iova);
		res_print_uint(rd, "mrlen", mrlen);
		print_pid(rd, pid);
		print_comm(rd, comm, nla_line);

		if (nla_line[RDMA_NLDEV_ATTR_RES_MRN])
			res_print_uint(rd, "mrn", mrn);

		if (nla_line[RDMA_NLDEV_ATTR_RES_PDN])
			res_print_uint(rd, "pdn", pdn);

		if (nla_line[RDMA_NLDEV_ATTR_RES_PID])
			free(comm);

		print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
		newline(rd);
	}
	return MNL_CB_OK;
}

