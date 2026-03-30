// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * res-frmr-pools.c	RDMA tool
 * Authors:    Michael Guralnik <michaelgur@nvidia.com>
 */

#include "res.h"
#include <inttypes.h>

struct frmr_pool_key {
	uint64_t vendor_key;
	uint64_t num_dma_blocks;
	uint32_t access_flags;
	uint8_t ats;
};

/* vendor_key(16) + ':' + num_dma_blocks(16) + ':' + access_flags(8) + ':' + ats(1) + '\0' */
#define FRMR_POOL_KEY_MAX_LEN 45

static int res_frmr_pools_line(struct rd *rd, const char *name, int idx,
			       struct nlattr **nla_line)
{
	uint64_t in_use = 0, max_in_use = 0, kernel_vendor_key = 0;
	struct nlattr *key_tb[RDMA_NLDEV_ATTR_MAX] = {};
	char key_str[FRMR_POOL_KEY_MAX_LEN];
	struct frmr_pool_key key = { 0 };
	uint32_t queue_handles = 0;

	if (nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY]) {
		if (mnl_attr_parse_nested(
			    nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY],
			    rd_attr_cb, key_tb) != MNL_CB_OK)
			return MNL_CB_ERROR;

		if (key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_ATS])
			key.ats = mnl_attr_get_u8(
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_ATS]);
		if (key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_ACCESS_FLAGS])
			key.access_flags = mnl_attr_get_u32(
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_ACCESS_FLAGS]);
		if (key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_VENDOR_KEY])
			key.vendor_key = mnl_attr_get_u64(
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_VENDOR_KEY]);
		if (key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_NUM_DMA_BLOCKS])
			key.num_dma_blocks = mnl_attr_get_u64(
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_NUM_DMA_BLOCKS]);
		if (key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_KERNEL_VENDOR_KEY])
			kernel_vendor_key = mnl_attr_get_u64(
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_KERNEL_VENDOR_KEY]);

		if (rd_is_filtered_attr(
			    rd, "ats", key.ats,
			    key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_ATS]))
			goto out;

		if (rd_is_filtered_attr(
			    rd, "access_flags", key.access_flags,
			    key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_ACCESS_FLAGS]))
			goto out;

		if (rd_is_filtered_attr(
			    rd, "vendor_key", key.vendor_key,
			    key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_VENDOR_KEY]))
			goto out;

		if (rd_is_filtered_attr(
			    rd, "num_dma_blocks", key.num_dma_blocks,
			    key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_NUM_DMA_BLOCKS]))
			goto out;
	}

	if (nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_QUEUE_HANDLES])
		queue_handles = mnl_attr_get_u32(
			nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_QUEUE_HANDLES]);
	if (rd_is_filtered_attr(
		    rd, "queue", queue_handles,
		    nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_QUEUE_HANDLES]))
		goto out;

	if (nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_IN_USE])
		in_use = mnl_attr_get_u64(
			nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_IN_USE]);
	if (rd_is_filtered_attr(rd, "in_use", in_use,
				nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_IN_USE]))
		goto out;

	if (nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_MAX_IN_USE])
		max_in_use = mnl_attr_get_u64(
			nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_MAX_IN_USE]);
	if (rd_is_filtered_attr(
		    rd, "max_in_use", max_in_use,
		    nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_MAX_IN_USE]))
		goto out;

	open_json_object(NULL);
	print_dev(idx, name);

	if (nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY]) {
		snprintf(key_str, sizeof(key_str),
			 "%" PRIx64 ":%" PRIx64 ":%x:%s",
			 key.vendor_key, key.num_dma_blocks,
			 key.access_flags, key.ats ? "1" : "0");
		print_string(PRINT_ANY, "key", "key %s ", key_str);

		if (rd->show_details) {
			res_print_u32(
				"ats", key.ats,
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_ATS]);
			res_print_u32(
				"access_flags", key.access_flags,
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_ACCESS_FLAGS]);
			res_print_u64(
				"vendor_key", key.vendor_key,
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_VENDOR_KEY]);
			res_print_u64(
				"num_dma_blocks", key.num_dma_blocks,
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_NUM_DMA_BLOCKS]);
			res_print_u64(
				"kernel_vendor_key", kernel_vendor_key,
				key_tb[RDMA_NLDEV_ATTR_RES_FRMR_POOL_KEY_KERNEL_VENDOR_KEY]);
		}
	}

	res_print_u32("queue", queue_handles,
		      nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_QUEUE_HANDLES]);
	res_print_u64("in_use", in_use,
		      nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_IN_USE]);
	res_print_u64("max_in_use", max_in_use,
		      nla_line[RDMA_NLDEV_ATTR_RES_FRMR_POOL_MAX_IN_USE]);

	print_driver_table(rd, nla_line[RDMA_NLDEV_ATTR_DRIVER]);
	close_json_object();
	newline();

out:
	return MNL_CB_OK;
}

int res_frmr_pools_idx_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	return MNL_CB_OK;
}

int res_frmr_pools_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlattr *nla_table, *nla_entry;
	struct rd *rd = data;
	int ret = MNL_CB_OK;
	const char *name;
	uint32_t idx;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] || !tb[RDMA_NLDEV_ATTR_DEV_NAME] ||
	    !tb[RDMA_NLDEV_ATTR_RES_FRMR_POOLS])
		return MNL_CB_ERROR;

	name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);
	idx = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	nla_table = tb[RDMA_NLDEV_ATTR_RES_FRMR_POOLS];

	mnl_attr_for_each_nested(nla_entry, nla_table) {
		struct nlattr *nla_line[RDMA_NLDEV_ATTR_MAX] = {};

		ret = mnl_attr_parse_nested(nla_entry, rd_attr_cb, nla_line);
		if (ret != MNL_CB_OK)
			break;

		ret = res_frmr_pools_line(rd, name, idx, nla_line);
		if (ret != MNL_CB_OK)
			break;
	}
	return ret;
}
