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
#include <ctype.h>
#include <inttypes.h>

int rd_argc(struct rd *rd)
{
	return rd->argc;
}

static char *rd_argv(struct rd *rd)
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

static void rd_arg_inc(struct rd *rd)
{
	if (!rd_argc(rd))
		return;
	rd->argc--;
	rd->argv++;
}

static bool rd_no_arg(struct rd *rd)
{
	return rd_argc(rd) == 0;
}

/*
 * Possible input:output
 * dev/port    | first port | is_dump_all
 * mlx5_1      | 0          | true
 * mlx5_1/     | 0          | true
 * mlx5_1/0    | 0          | false
 * mlx5_1/1    | 1          | false
 * mlx5_1/-    | 0          | false
 *
 * In strict mode, /- will return error.
 */
static int get_port_from_argv(struct rd *rd, uint32_t *port,
			      bool *is_dump_all, bool strict_port)
{
	char *slash;

	*port = 0;
	*is_dump_all = true;

	slash = strchr(rd_argv(rd), '/');
	/* if no port found, return 0 */
	if (slash++) {
		if (*slash == '-') {
			if (strict_port)
				return -EINVAL;
			*is_dump_all = false;
			return 0;
		}

		if (isdigit(*slash)) {
			*is_dump_all = false;
			*port = atoi(slash);
		}
		if (!*port && strlen(slash))
			return -EINVAL;
	}
	return 0;
}

static struct dev_map *dev_map_alloc(const char *dev_name)
{
	struct dev_map *dev_map;

	dev_map = calloc(1, sizeof(*dev_map));
	if (!dev_map)
		return NULL;
	dev_map->dev_name = strdup(dev_name);
	if (!dev_map->dev_name) {
		free(dev_map);
		return NULL;
	}

	return dev_map;
}

static void dev_map_cleanup(struct rd *rd)
{
	struct dev_map *dev_map, *tmp;

	list_for_each_entry_safe(dev_map, tmp,
				 &rd->dev_map_list, list) {
		list_del(&dev_map->list);
		free(dev_map->dev_name);
		free(dev_map);
	}
}

static int add_filter(struct rd *rd, char *key, char *value,
		      const struct filters valid_filters[])
{
	char cset[] = "1234567890,-";
	struct filter_entry *fe;
	bool key_found = false;
	int idx = 0;
	int ret;

	fe = calloc(1, sizeof(*fe));
	if (!fe)
		return -ENOMEM;

	while (idx < MAX_NUMBER_OF_FILTERS && valid_filters[idx].name) {
		if (!strcmpx(key, valid_filters[idx].name)) {
			key_found = true;
			break;
		}
		idx++;
	}
	if (!key_found) {
		pr_err("Unsupported filter option: %s\n", key);
		ret = -EINVAL;
		goto err;
	}

	/*
	 * Check the filter validity, not optimal, but works
	 *
	 * Actually, there are three types of filters
	 *  numeric - for example PID or QPN
	 *  string  - for example states
	 *  link    - user requested to filter on specific link
	 *            e.g. mlx5_1/1, mlx5_1/-, mlx5_1 ...
	 */
	if (valid_filters[idx].is_number &&
	    strspn(value, cset) != strlen(value)) {
		pr_err("%s filter accepts \"%s\" characters only\n", key, cset);
		ret = -EINVAL;
		goto err;
	}

	fe->key = strdup(key);
	fe->value = strdup(value);
	if (!fe->key || !fe->value) {
		ret = -ENOMEM;
		goto err_alloc;
	}

	for (idx = 0; idx < strlen(fe->value); idx++)
		fe->value[idx] = tolower(fe->value[idx]);

	list_add_tail(&fe->list, &rd->filter_list);
	return 0;

err_alloc:
	free(fe->value);
	free(fe->key);
err:
	free(fe);
	return ret;
}

int rd_build_filter(struct rd *rd, const struct filters valid_filters[])
{
	int ret = 0;
	int idx = 0;

	if (!valid_filters || !rd_argc(rd))
		goto out;

	if (rd_argc(rd) == 1) {
		pr_err("No filter data was supplied to filter option %s\n", rd_argv(rd));
		ret = -EINVAL;
		goto out;
	}

	if (rd_argc(rd) % 2) {
		pr_err("There is filter option without data\n");
		ret = -EINVAL;
		goto out;
	}

	while (idx != rd_argc(rd)) {
		/*
		 * We can do micro-optimization and skip "dev"
		 * and "link" filters, but it is not worth of it.
		 */
		ret = add_filter(rd, *(rd->argv + idx),
				 *(rd->argv + idx + 1), valid_filters);
		if (ret)
			goto out;
		idx += 2;
	}

out:
	return ret;
}

bool rd_check_is_key_exist(struct rd *rd, const char *key)
{
	struct filter_entry *fe;

	list_for_each_entry(fe, &rd->filter_list, list) {
		if (!strcmpx(fe->key, key))
			return true;
	}

	return false;
}

/*
 * Check if string entry is filtered:
 *  * key doesn't exist -> user didn't request -> not filtered
 */
bool rd_check_is_string_filtered(struct rd *rd,
				 const char *key, const char *val)
{
	bool key_is_filtered = false;
	struct filter_entry *fe;
	char *p = NULL;
	char *str;

	list_for_each_entry(fe, &rd->filter_list, list) {
		if (!strcmpx(fe->key, key)) {
			/* We found the key */
			p = strdup(fe->value);
			key_is_filtered = true;
			if (!p) {
				/*
				 * Something extremely wrong if we fail
				 * to allocate small amount of bytes.
				 */
				pr_err("Found key, but failed to allocate memory to store value\n");
				return key_is_filtered;
			}

			/*
			 * Need to check if value in range
			 * It can come in the following formats
			 * and their permutations:
			 * str
			 * str1,str2
			 */
			str = strtok(p, ",");
			while (str) {
				if (strlen(str) == strlen(val) &&
				    !strcasecmp(str, val)) {
					key_is_filtered = false;
					goto out;
				}
				str = strtok(NULL, ",");
			}
			goto out;
		}
	}

out:
	free(p);
	return key_is_filtered;
}

/*
 * Check if key is filtered:
 * key doesn't exist -> user didn't request -> not filtered
 */
bool rd_check_is_filtered(struct rd *rd, const char *key, uint32_t val)
{
	bool key_is_filtered = false;
	struct filter_entry *fe;

	list_for_each_entry(fe, &rd->filter_list, list) {
		uint32_t left_val = 0, fe_value = 0;
		bool range_check = false;
		char *p = fe->value;

		if (!strcmpx(fe->key, key)) {
			/* We found the key */
			key_is_filtered = true;
			/*
			 * Need to check if value in range
			 * It can come in the following formats
			 * (and their permutations):
			 * numb
			 * numb1,numb2
			 * ,numb1,numb2
			 * numb1-numb2
			 * numb1,numb2-numb3,numb4-numb5
			 */
			while (*p) {
				if (isdigit(*p)) {
					fe_value = strtol(p, &p, 10);
					if (fe_value == val ||
					    (range_check && left_val < val &&
					     val < fe_value)) {
						key_is_filtered = false;
						goto out;
					}
					range_check = false;
				} else {
					if (*p == '-') {
						left_val = fe_value;
						range_check = true;
					}
					p++;
				}
			}
			goto out;
		}
	}

out:
	return key_is_filtered;
}

static void filters_cleanup(struct rd *rd)
{
	struct filter_entry *fe, *tmp;

	list_for_each_entry_safe(fe, tmp,
				 &rd->filter_list, list) {
		list_del(&fe->list);
		free(fe->key);
		free(fe->value);
		free(fe);
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
	[RDMA_NLDEV_ATTR_RES_SUMMARY]	= MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY]	= MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_NAME] = MNL_TYPE_NUL_STRING,
	[RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_CURR] = MNL_TYPE_U64,
	[RDMA_NLDEV_ATTR_RES_QP]		= MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_QP_ENTRY]		= MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_LQPN]	= MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_RQPN]	= MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_RQ_PSN]		= MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_SQ_PSN]		= MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE]	= MNL_TYPE_U8,
	[RDMA_NLDEV_ATTR_RES_TYPE]		= MNL_TYPE_U8,
	[RDMA_NLDEV_ATTR_RES_STATE]		= MNL_TYPE_U8,
	[RDMA_NLDEV_ATTR_RES_PID]		= MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_KERN_NAME]	= MNL_TYPE_NUL_STRING,
	[RDMA_NLDEV_ATTR_RES_CM_ID]		= MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_CM_ID_ENTRY]	= MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_PS]		= MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_SRC_ADDR]		= MNL_TYPE_UNSPEC,
	[RDMA_NLDEV_ATTR_RES_DST_ADDR]		= MNL_TYPE_UNSPEC,
	[RDMA_NLDEV_ATTR_RES_CQ] = MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_CQ_ENTRY] = MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_CQE] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_USECNT] = MNL_TYPE_U64,
	[RDMA_NLDEV_ATTR_RES_POLL_CTX] = MNL_TYPE_U8,
	[RDMA_NLDEV_ATTR_RES_MR] = MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_MR_ENTRY] = MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_RES_RKEY] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_LKEY] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_RES_IOVA] = MNL_TYPE_U64,
	[RDMA_NLDEV_ATTR_RES_MRLEN] = MNL_TYPE_U64,
	[RDMA_NLDEV_ATTR_NDEV_INDEX]		= MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_NDEV_NAME]		= MNL_TYPE_NUL_STRING,
	[RDMA_NLDEV_ATTR_DRIVER] = MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_DRIVER_ENTRY] = MNL_TYPE_NESTED,
	[RDMA_NLDEV_ATTR_DRIVER_STRING] = MNL_TYPE_NUL_STRING,
	[RDMA_NLDEV_ATTR_DRIVER_PRINT_TYPE] = MNL_TYPE_U8,
	[RDMA_NLDEV_ATTR_DRIVER_S32] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_DRIVER_U32] = MNL_TYPE_U32,
	[RDMA_NLDEV_ATTR_DRIVER_S64] = MNL_TYPE_U64,
	[RDMA_NLDEV_ATTR_DRIVER_U64] = MNL_TYPE_U64,
};

static int rd_attr_check(const struct nlattr *attr, int *typep)
{
	int type;

	if (mnl_attr_type_valid(attr, RDMA_NLDEV_ATTR_MAX) < 0)
		return MNL_CB_ERROR;

	type = mnl_attr_get_type(attr);

	if (mnl_attr_validate(attr, nldev_policy[type]) < 0)
		return MNL_CB_ERROR;

	*typep = nldev_policy[type];
	return MNL_CB_OK;
}

int rd_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	if (mnl_attr_type_valid(attr, RDMA_NLDEV_ATTR_MAX - 1) < 0)
		/* We received unknown attribute */
		return MNL_CB_OK;

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

void rd_free(struct rd *rd)
{
	if (!rd)
		return;
	free(rd->buff);
	dev_map_cleanup(rd);
	filters_cleanup(rd);
}

int rd_set_arg_to_devname(struct rd *rd)
{
	int ret = 0;

	while (!rd_no_arg(rd)) {
		if (rd_argv_match(rd, "dev") || rd_argv_match(rd, "link")) {
			rd_arg_inc(rd);
			if (rd_no_arg(rd)) {
				pr_err("No device name was supplied\n");
				ret = -EINVAL;
			}
			goto out;
		}
		rd_arg_inc(rd);
	}
out:
	return ret;
}

int rd_exec_link(struct rd *rd, int (*cb)(struct rd *rd), bool strict_port)
{
	struct dev_map *dev_map;
	uint32_t port;
	int ret = 0;

	if (rd->json_output)
		jsonw_start_array(rd->jw);
	if (rd_no_arg(rd)) {
		list_for_each_entry(dev_map, &rd->dev_map_list, list) {
			rd->dev_idx = dev_map->idx;
			port = (strict_port) ? 1 : 0;
			for (; port < dev_map->num_ports + 1; port++) {
				rd->port_idx = port;
				ret = cb(rd);
				if (ret)
					goto out;
			}
		}

	} else {
		bool is_dump_all;

		dev_map = dev_map_lookup(rd, true);
		ret = get_port_from_argv(rd, &port, &is_dump_all, strict_port);
		if (!dev_map || port > dev_map->num_ports || (!port && ret)) {
			pr_err("Wrong device name\n");
			ret = -ENOENT;
			goto out;
		}
		rd_arg_inc(rd);
		rd->dev_idx = dev_map->idx;
		rd->port_idx = port;
		for (; rd->port_idx < dev_map->num_ports + 1; rd->port_idx++) {
			ret = cb(rd);
			if (ret)
				goto out;
			if (!is_dump_all)
				/*
				 * We got request to show link for devname
				 * with port index.
				 */
				break;
		}
	}

out:
	if (rd->json_output)
		jsonw_end_array(rd->jw);
	return ret;
}

int rd_exec_dev(struct rd *rd, int (*cb)(struct rd *rd))
{
	struct dev_map *dev_map;
	int ret = 0;

	if (rd->json_output)
		jsonw_start_array(rd->jw);
	if (rd_no_arg(rd)) {
		list_for_each_entry(dev_map, &rd->dev_map_list, list) {
			rd->dev_idx = dev_map->idx;
			ret = cb(rd);
			if (ret)
				goto out;
		}
	} else {
		dev_map = dev_map_lookup(rd, false);
		if (!dev_map) {
			pr_err("Wrong device name - %s\n", rd_argv(rd));
			ret = -ENOENT;
			goto out;
		}
		rd_arg_inc(rd);
		rd->dev_idx = dev_map->idx;
		ret = cb(rd);
	}
out:
	if (rd->json_output)
		jsonw_end_array(rd->jw);
	return ret;
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

static struct dev_map *_dev_map_lookup(struct rd *rd, const char *dev_name)
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

	if (rd_no_arg(rd))
		return NULL;

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

#define nla_type(attr) ((attr)->nla_type & NLA_TYPE_MASK)

void newline(struct rd *rd)
{
	if (rd->json_output)
		jsonw_end_array(rd->jw);
	else
		pr_out("\n");
}

static void newline_indent(struct rd *rd)
{
	newline(rd);
	if (!rd->json_output)
		pr_out("    ");
}

static int print_driver_string(struct rd *rd, const char *key_str,
				 const char *val_str)
{
	if (rd->json_output) {
		jsonw_string_field(rd->jw, key_str, val_str);
		return 0;
	} else {
		return pr_out("%s %s ", key_str, val_str);
	}
}

static int print_driver_s32(struct rd *rd, const char *key_str, int32_t val,
			      enum rdma_nldev_print_type print_type)
{
	if (rd->json_output) {
		jsonw_int_field(rd->jw, key_str, val);
		return 0;
	}
	switch (print_type) {
	case RDMA_NLDEV_PRINT_TYPE_UNSPEC:
		return pr_out("%s %d ", key_str, val);
	case RDMA_NLDEV_PRINT_TYPE_HEX:
		return pr_out("%s 0x%x ", key_str, val);
	default:
		return -EINVAL;
	}
}

static int print_driver_u32(struct rd *rd, const char *key_str, uint32_t val,
			      enum rdma_nldev_print_type print_type)
{
	if (rd->json_output) {
		jsonw_int_field(rd->jw, key_str, val);
		return 0;
	}
	switch (print_type) {
	case RDMA_NLDEV_PRINT_TYPE_UNSPEC:
		return pr_out("%s %u ", key_str, val);
	case RDMA_NLDEV_PRINT_TYPE_HEX:
		return pr_out("%s 0x%x ", key_str, val);
	default:
		return -EINVAL;
	}
}

static int print_driver_s64(struct rd *rd, const char *key_str, int64_t val,
			      enum rdma_nldev_print_type print_type)
{
	if (rd->json_output) {
		jsonw_int_field(rd->jw, key_str, val);
		return 0;
	}
	switch (print_type) {
	case RDMA_NLDEV_PRINT_TYPE_UNSPEC:
		return pr_out("%s %" PRId64 " ", key_str, val);
	case RDMA_NLDEV_PRINT_TYPE_HEX:
		return pr_out("%s 0x%" PRIx64 " ", key_str, val);
	default:
		return -EINVAL;
	}
}

static int print_driver_u64(struct rd *rd, const char *key_str, uint64_t val,
			      enum rdma_nldev_print_type print_type)
{
	if (rd->json_output) {
		jsonw_int_field(rd->jw, key_str, val);
		return 0;
	}
	switch (print_type) {
	case RDMA_NLDEV_PRINT_TYPE_UNSPEC:
		return pr_out("%s %" PRIu64 " ", key_str, val);
	case RDMA_NLDEV_PRINT_TYPE_HEX:
		return pr_out("%s 0x%" PRIx64 " ", key_str, val);
	default:
		return -EINVAL;
	}
}

static int print_driver_entry(struct rd *rd, struct nlattr *key_attr,
				struct nlattr *val_attr,
				enum rdma_nldev_print_type print_type)
{
	const char *key_str = mnl_attr_get_str(key_attr);
	int attr_type = nla_type(val_attr);

	switch (attr_type) {
	case RDMA_NLDEV_ATTR_DRIVER_STRING:
		return print_driver_string(rd, key_str,
				mnl_attr_get_str(val_attr));
	case RDMA_NLDEV_ATTR_DRIVER_S32:
		return print_driver_s32(rd, key_str,
				mnl_attr_get_u32(val_attr), print_type);
	case RDMA_NLDEV_ATTR_DRIVER_U32:
		return print_driver_u32(rd, key_str,
				mnl_attr_get_u32(val_attr), print_type);
	case RDMA_NLDEV_ATTR_DRIVER_S64:
		return print_driver_s64(rd, key_str,
				mnl_attr_get_u64(val_attr), print_type);
	case RDMA_NLDEV_ATTR_DRIVER_U64:
		return print_driver_u64(rd, key_str,
				mnl_attr_get_u64(val_attr), print_type);
	}
	return -EINVAL;
}

void print_driver_table(struct rd *rd, struct nlattr *tb)
{
	int print_type = RDMA_NLDEV_PRINT_TYPE_UNSPEC;
	struct nlattr *tb_entry, *key = NULL, *val;
	int type, cc = 0;
	int ret;

	if (!rd->show_driver_details || !tb)
		return;

	if (rd->pretty_output)
		newline_indent(rd);

	/*
	 * Driver attrs are tuples of {key, [print-type], value}.
	 * The key must be a string.  If print-type is present, it
	 * defines an alternate printf format type vs the native format
	 * for the attribute.  And the value can be any available
	 * driver type.
	 */
	mnl_attr_for_each_nested(tb_entry, tb) {

		if (cc > MAX_LINE_LENGTH) {
			if (rd->pretty_output)
				newline_indent(rd);
			cc = 0;
		}
		if (rd_attr_check(tb_entry, &type) != MNL_CB_OK)
			return;
		if (!key) {
			if (type != MNL_TYPE_NUL_STRING)
				return;
			key = tb_entry;
		} else if (type == MNL_TYPE_U8) {
			print_type = mnl_attr_get_u8(tb_entry);
		} else {
			val = tb_entry;
			ret = print_driver_entry(rd, key, val, print_type);
			if (ret < 0)
				return;
			cc += ret;
			print_type = RDMA_NLDEV_PRINT_TYPE_UNSPEC;
			key = NULL;
		}
	}
	return;
}
