/*
 * utils.c	RDMA tool
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Leon Romanovsky <leonro@mellanox.com>
 */

#include "rdma.h"

static int rd_argc(struct rd *rd)
{
	return rd->argc;
}

char *rd_argv(struct rd *rd)
{
	if (!rd_argc(rd))
		return NULL;
	return *rd->argv;
}

static int strcmpx(const char *str1, const char *str2)
{
	if (strlen(str1) > strlen(str2))
		return -1;
	return strncmp(str1, str2, strlen(str1));
}

static bool rd_argv_match(struct rd *rd, const char *pattern)
{
	if (!rd_argc(rd))
		return false;
	return strcmpx(rd_argv(rd), pattern) == 0;
}

void rd_arg_inc(struct rd *rd)
{
	if (!rd_argc(rd))
		return;
	rd->argc--;
	rd->argv++;
}

bool rd_no_arg(struct rd *rd)
{
	return rd_argc(rd) == 0;
}

uint32_t get_port_from_argv(struct rd *rd)
{
	char *slash;

	slash = strchr(rd_argv(rd), '/');
	/* if no port found, return 0 */
	return slash ? atoi(slash + 1) : 0;
}

static struct dev_map *dev_map_alloc(const char *dev_name)
{
	struct dev_map *dev_map;

	dev_map = calloc(1, sizeof(*dev_map));
	if (!dev_map)
		return NULL;
	dev_map->dev_name = strdup(dev_name);

	return dev_map;
}

static void dev_map_free(struct dev_map *dev_map)
{
	if (!dev_map)
		return;

	free(dev_map->dev_name);
	free(dev_map);
}

static void dev_map_cleanup(struct rd *rd)
{
	struct dev_map *dev_map, *tmp;

	list_for_each_entry_safe(dev_map, tmp,
				 &rd->dev_map_list, list) {
		list_del(&dev_map->list);
		dev_map_free(dev_map);
	}
}

static const enum mnl_attr_data_type nldev_policy[RDMA_NLDEV_ATTR_MAX] = {
	[RDMA_NLDEV_ATTR_DEV_INDEX] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_DEV_NAME] = MNL_TYPE_NUL_STRING,
	[RDMA_NLDEV_ATTR_PORT_INDEX] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_CAP_FLAGS] = MNL_TYPE_U64,
	[RDMA_NLDEV_ATTR_FW_VERSION] = MNL_TYPE_NUL_STRING,
	[RDMA_NLDEV_ATTR_NODE_GUID] = MNL_TYPE_U64,
	[RDMA_NLDEV_ATTR_SYS_IMAGE_GUID] = MNL_TYPE_U64,
	[RDMA_NLDEV_ATTR_LID] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_SM_LID] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_LMC] = MNL_TYPE_U8,
	[RDMA_NLDEV_ATTR_PORT_STATE] = MNL_TYPE_U8,
	[RDMA_NLDEV_ATTR_PORT_PHYS_STATE] = MNL_TYPE_U8,
	[RDMA_NLDEV_ATTR_DEV_NODE_TYPE] = MNL_TYPE_U8,
};

int rd_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	if (mnl_attr_type_valid(attr, RDMA_NLDEV_ATTR_MAX) < 0)
		return MNL_CB_ERROR;

	type = mnl_attr_get_type(attr);

	if (mnl_attr_validate(attr, nldev_policy[type]) < 0)
		return MNL_CB_ERROR;

	tb[type] = attr;
	return MNL_CB_OK;
}

int rd_dev_init_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct dev_map *dev_map;
	struct rd *rd = data;
	const char *dev_name;

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_NAME] || !tb[RDMA_NLDEV_ATTR_DEV_INDEX])
		return MNL_CB_ERROR;
	if (!tb[RDMA_NLDEV_ATTR_PORT_INDEX]) {
		pr_err("This tool doesn't support switches yet\n");
		return MNL_CB_ERROR;
	}

	dev_name = mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]);

	dev_map = dev_map_alloc(dev_name);
	if (!dev_map)
		/* The main function will cleanup the allocations */
		return MNL_CB_ERROR;
	list_add_tail(&dev_map->list, &rd->dev_map_list);

	dev_map->num_ports = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_PORT_INDEX]);
	dev_map->idx = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	return MNL_CB_OK;
}

void rd_free_devmap(struct rd *rd)
{
	if (!rd)
		return;
	dev_map_cleanup(rd);
}

int rd_exec_cmd(struct rd *rd, const struct rd_cmd *cmds, const char *str)
{
	const struct rd_cmd *c;

	/* First argument in objs table is default variant */
	if (rd_no_arg(rd))
		return cmds->func(rd);

	for (c = cmds + 1; c->cmd; ++c) {
		if (rd_argv_match(rd, c->cmd)) {
			/* Move to next argument */
			rd_arg_inc(rd);
			return c->func(rd);
		}
	}

	pr_err("Unknown %s '%s'.\n", str, rd_argv(rd));
	return 0;
}

void rd_prepare_msg(struct rd *rd, uint32_t cmd, uint32_t *seq, uint16_t flags)
{
	*seq = time(NULL);

	rd->nlh = mnl_nlmsg_put_header(rd->buff);
	rd->nlh->nlmsg_type = RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, cmd);
	rd->nlh->nlmsg_seq = *seq;
	rd->nlh->nlmsg_flags = flags;
}

int rd_send_msg(struct rd *rd)
{
	int ret;

	rd->nl = mnl_socket_open(NETLINK_RDMA);
	if (!rd->nl) {
		pr_err("Failed to open NETLINK_RDMA socket\n");
		return -ENODEV;
	}

	ret = mnl_socket_bind(rd->nl, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		pr_err("Failed to bind socket with err %d\n", ret);
		goto err;
	}

	ret = mnl_socket_sendto(rd->nl, rd->nlh, rd->nlh->nlmsg_len);
	if (ret < 0) {
		pr_err("Failed to send to socket with err %d\n", ret);
		goto err;
	}
	return 0;

err:
	mnl_socket_close(rd->nl);
	return ret;
}

int rd_recv_msg(struct rd *rd, mnl_cb_t callback, void *data, unsigned int seq)
{
	int ret;
	unsigned int portid;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	portid = mnl_socket_get_portid(rd->nl);
	do {
		ret = mnl_socket_recvfrom(rd->nl, buf, sizeof(buf));
		if (ret <= 0)
			break;

		ret = mnl_cb_run(buf, ret, seq, portid, callback, data);
	} while (ret > 0);

	mnl_socket_close(rd->nl);
	return ret;
}

struct dev_map *_dev_map_lookup(struct rd *rd, const char *dev_name)
{
	struct dev_map *dev_map;

	list_for_each_entry(dev_map, &rd->dev_map_list, list)
		if (strcmp(dev_name, dev_map->dev_name) == 0)
			return dev_map;

	return NULL;
}

struct dev_map *dev_map_lookup(struct rd *rd, bool allow_port_index)
{
	struct dev_map *dev_map;
	char *dev_name;
	char *slash;

	dev_name = strdup(rd_argv(rd));
	if (allow_port_index) {
		slash = strrchr(dev_name, '/');
		if (slash)
			*slash = '\0';
	}

	dev_map = _dev_map_lookup(rd, dev_name);
	free(dev_name);
	return dev_map;
}
