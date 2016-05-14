/*
 * devlink.c	Devlink tool
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jiri Pirko <jiri@mellanox.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/devlink.h>
#include <libmnl/libmnl.h>

#include "SNAPSHOT.h"
#include "list.h"
#include "mnlg.h"

#define pr_err(args...) fprintf(stderr, ##args)
#define pr_out(args...) fprintf(stdout, ##args)

static int _mnlg_socket_recv_run(struct mnlg_socket *nlg,
				 mnl_cb_t data_cb, void *data)
{
	int err;

	err = mnlg_socket_recv_run(nlg, data_cb, data);
	if (err < 0) {
		pr_err("devlink answers: %s\n", strerror(errno));
		return -errno;
	}
	return 0;
}

static int _mnlg_socket_sndrcv(struct mnlg_socket *nlg,
			       const struct nlmsghdr *nlh,
			       mnl_cb_t data_cb, void *data)
{
	int err;

	err = mnlg_socket_send(nlg, nlh);
	if (err < 0) {
		pr_err("Failed to call mnlg_socket_send\n");
		return -errno;
	}
	return _mnlg_socket_recv_run(nlg, data_cb, data);
}

static int _mnlg_socket_group_add(struct mnlg_socket *nlg,
				  const char *group_name)
{
	int err;

	err = mnlg_socket_group_add(nlg, group_name);
	if (err < 0) {
		pr_err("Failed to call mnlg_socket_group_add\n");
		return -errno;
	}
	return 0;
}

struct ifname_map {
	struct list_head list;
	char *bus_name;
	char *dev_name;
	uint32_t port_index;
	char *ifname;
};

static struct ifname_map *ifname_map_alloc(const char *bus_name,
					   const char *dev_name,
					   uint32_t port_index,
					   const char *ifname)
{
	struct ifname_map *ifname_map;

	ifname_map = calloc(1, sizeof(*ifname_map));
	if (!ifname_map)
		return NULL;
	ifname_map->bus_name = strdup(bus_name);
	ifname_map->dev_name = strdup(dev_name);
	ifname_map->port_index = port_index;
	ifname_map->ifname = strdup(ifname);
	if (!ifname_map->bus_name || !ifname_map->dev_name ||
	    !ifname_map->ifname) {
		free(ifname_map->ifname);
		free(ifname_map->dev_name);
		free(ifname_map->bus_name);
		free(ifname_map);
		return NULL;
	}
	return ifname_map;
}

static void ifname_map_free(struct ifname_map *ifname_map)
{
	free(ifname_map->ifname);
	free(ifname_map->dev_name);
	free(ifname_map->bus_name);
	free(ifname_map);
}

#define BIT(nr)                 (1UL << (nr))
#define DL_OPT_HANDLE		BIT(0)
#define DL_OPT_HANDLEP		BIT(1)
#define DL_OPT_PORT_TYPE	BIT(2)
#define DL_OPT_PORT_COUNT	BIT(3)
#define DL_OPT_SB		BIT(4)
#define DL_OPT_SB_POOL		BIT(5)
#define DL_OPT_SB_SIZE		BIT(6)
#define DL_OPT_SB_TYPE		BIT(7)
#define DL_OPT_SB_THTYPE	BIT(8)
#define DL_OPT_SB_TH		BIT(9)
#define DL_OPT_SB_TC		BIT(10)

struct dl_opts {
	uint32_t present; /* flags of present items */
	char *bus_name;
	char *dev_name;
	uint32_t port_index;
	enum devlink_port_type port_type;
	uint32_t port_count;
	uint32_t sb_index;
	uint16_t sb_pool_index;
	uint32_t sb_pool_size;
	enum devlink_sb_pool_type sb_pool_type;
	enum devlink_sb_threshold_type sb_pool_thtype;
	uint32_t sb_threshold;
	uint16_t sb_tc_index;
};

struct dl {
	struct mnlg_socket *nlg;
	struct list_head ifname_map_list;
	int argc;
	char **argv;
	bool no_nice_names;
	struct dl_opts opts;
};

static int dl_argc(struct dl *dl)
{
	return dl->argc;
}

static char *dl_argv(struct dl *dl)
{
	if (dl_argc(dl) == 0)
		return NULL;
	return *dl->argv;
}

static void dl_arg_inc(struct dl *dl)
{
	if (dl_argc(dl) == 0)
		return;
	dl->argc--;
	dl->argv++;
}

static char *dl_argv_next(struct dl *dl)
{
	char *ret;

	if (dl_argc(dl) == 0)
		return NULL;

	ret = *dl->argv;
	dl_arg_inc(dl);
	return ret;
}

static char *dl_argv_index(struct dl *dl, unsigned int index)
{
	if (index >= dl_argc(dl))
		return NULL;
	return dl->argv[index];
}

static int strcmpx(const char *str1, const char *str2)
{
	if (strlen(str1) > strlen(str2))
		return -1;
	return strncmp(str1, str2, strlen(str1));
}

static bool dl_argv_match(struct dl *dl, const char *pattern)
{
	if (dl_argc(dl) == 0)
		return false;
	return strcmpx(dl_argv(dl), pattern) == 0;
}

static bool dl_no_arg(struct dl *dl)
{
	return dl_argc(dl) == 0;
}

static int attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, DEVLINK_ATTR_MAX) < 0)
		return MNL_CB_ERROR;

	if (type == DEVLINK_ATTR_BUS_NAME &&
	    mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_DEV_NAME &&
	    mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_PORT_INDEX &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_PORT_TYPE &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_PORT_DESIRED_TYPE &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_PORT_NETDEV_IFINDEX &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_PORT_NETDEV_NAME &&
	    mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_PORT_IBDEV_NAME &&
	    mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_INDEX &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_SIZE &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_INGRESS_POOL_COUNT &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_EGRESS_POOL_COUNT &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_INGRESS_TC_COUNT &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_EGRESS_TC_COUNT &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_POOL_INDEX &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_POOL_TYPE &&
	    mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_POOL_SIZE &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE &&
	    mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_THRESHOLD &&
	    mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		return MNL_CB_ERROR;
	if (type == DEVLINK_ATTR_SB_TC_INDEX &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	tb[type] = attr;
	return MNL_CB_OK;
}

static int ifname_map_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct dl *dl = data;
	struct ifname_map *ifname_map;
	const char *bus_name;
	const char *dev_name;
	uint32_t port_ifindex;
	const char *port_ifname;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_PORT_INDEX])
		return MNL_CB_ERROR;

	if (!tb[DEVLINK_ATTR_PORT_NETDEV_NAME])
		return MNL_CB_OK;

	bus_name = mnl_attr_get_str(tb[DEVLINK_ATTR_BUS_NAME]);
	dev_name = mnl_attr_get_str(tb[DEVLINK_ATTR_DEV_NAME]);
	port_ifindex = mnl_attr_get_u32(tb[DEVLINK_ATTR_PORT_INDEX]);
	port_ifname = mnl_attr_get_str(tb[DEVLINK_ATTR_PORT_NETDEV_NAME]);
	ifname_map = ifname_map_alloc(bus_name, dev_name,
				      port_ifindex, port_ifname);
	if (!ifname_map)
		return MNL_CB_ERROR;
	list_add(&ifname_map->list, &dl->ifname_map_list);

	return MNL_CB_OK;
}

static void ifname_map_fini(struct dl *dl)
{
	struct ifname_map *ifname_map, *tmp;

	list_for_each_entry_safe(ifname_map, tmp,
				 &dl->ifname_map_list, list) {
		list_del(&ifname_map->list);
		ifname_map_free(ifname_map);
	}
}

static int ifname_map_init(struct dl *dl)
{
	struct nlmsghdr *nlh;
	int err;

	INIT_LIST_HEAD(&dl->ifname_map_list);

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_PORT_GET,
			       NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);

	err = _mnlg_socket_sndrcv(dl->nlg, nlh, ifname_map_cb, dl);
	if (err) {
		ifname_map_fini(dl);
		return err;
	}
	return 0;
}

static int ifname_map_lookup(struct dl *dl, const char *ifname,
			     char **p_bus_name, char **p_dev_name,
			     uint32_t *p_port_index)
{
	struct ifname_map *ifname_map;

	list_for_each_entry(ifname_map, &dl->ifname_map_list, list) {
		if (strcmp(ifname, ifname_map->ifname) == 0) {
			*p_bus_name = ifname_map->bus_name;
			*p_dev_name = ifname_map->dev_name;
			*p_port_index = ifname_map->port_index;
			return 0;
		}
	}
	return -ENOENT;
}

static int ifname_map_rev_lookup(struct dl *dl, const char *bus_name,
				 const char *dev_name, uint32_t port_index,
				 char **p_ifname)
{
	struct ifname_map *ifname_map;

	list_for_each_entry(ifname_map, &dl->ifname_map_list, list) {
		if (strcmp(bus_name, ifname_map->bus_name) == 0 &&
		    strcmp(dev_name, ifname_map->dev_name) == 0 &&
		    port_index == ifname_map->port_index) {
			*p_ifname = ifname_map->ifname;
			return 0;
		}
	}
	return -ENOENT;
}

static unsigned int strslashcount(char *str)
{
	unsigned int count = 0;
	char *pos = str;

	while ((pos = strchr(pos, '/'))) {
		count++;
		pos++;
	}
	return count;
}

static int strslashrsplit(char *str, char **before, char **after)
{
	char *slash;

	slash = strrchr(str, '/');
	if (!slash)
		return -EINVAL;
	*slash = '\0';
	*before = str;
	*after = slash + 1;
	return 0;
}

static int strtouint32_t(const char *str, uint32_t *p_val)
{
	char *endptr;
	unsigned long int val;

	val = strtoul(str, &endptr, 10);
	if (endptr == str || *endptr != '\0')
		return -EINVAL;
	if (val > UINT_MAX)
		return -ERANGE;
	*p_val = val;
	return 0;
}

static int strtouint16_t(const char *str, uint16_t *p_val)
{
	char *endptr;
	unsigned long int val;

	val = strtoul(str, &endptr, 10);
	if (endptr == str || *endptr != '\0')
		return -EINVAL;
	if (val > USHRT_MAX)
		return -ERANGE;
	*p_val = val;
	return 0;
}

static int __dl_argv_handle(char *str, char **p_bus_name, char **p_dev_name)
{
	strslashrsplit(str, p_bus_name, p_dev_name);
	return 0;
}

static int dl_argv_handle(struct dl *dl, char **p_bus_name, char **p_dev_name)
{
	char *str = dl_argv_next(dl);

	if (!str) {
		pr_err("Devlink identification (\"bus_name/dev_name\") expected\n");
		return -EINVAL;
	}
	if (strslashcount(str) != 1) {
		pr_err("Wrong devlink identification string format.\n");
		pr_err("Expected \"bus_name/dev_name\".\n");
		return -EINVAL;
	}
	return __dl_argv_handle(str, p_bus_name, p_dev_name);
}

static int __dl_argv_handle_port(char *str,
				 char **p_bus_name, char **p_dev_name,
				 uint32_t *p_port_index)
{
	char *handlestr = handlestr;
	char *portstr = portstr;
	int err;

	strslashrsplit(str, &handlestr, &portstr);
	err = strtouint32_t(portstr, p_port_index);
	if (err) {
		pr_err("Port index \"%s\" is not a number or not within range\n",
		       portstr);
		return err;
	}
	strslashrsplit(handlestr, p_bus_name, p_dev_name);
	return 0;
}

static int __dl_argv_handle_port_ifname(struct dl *dl, char *str,
					char **p_bus_name, char **p_dev_name,
					uint32_t *p_port_index)
{
	int err;

	err = ifname_map_lookup(dl, str, p_bus_name, p_dev_name,
				p_port_index);
	if (err) {
		pr_err("Netdevice \"%s\" not found\n", str);
		return err;
	}
	return 0;
}

static int dl_argv_handle_port(struct dl *dl, char **p_bus_name,
			       char **p_dev_name, uint32_t *p_port_index)
{
	char *str = dl_argv_next(dl);
	unsigned int slash_count;

	if (!str) {
		pr_err("Port identification (\"bus_name/dev_name/port_index\" or \"netdev ifname\") expected.\n");
		return -EINVAL;
	}
	slash_count = strslashcount(str);
	if (slash_count != 2 && slash_count != 0) {
		pr_err("Wrong port identification string format.\n");
		pr_err("Expected \"bus_name/dev_name/port_index\" or \"netdev_ifname\".\n");
		return -EINVAL;
	}
	if (slash_count == 2) {
		return __dl_argv_handle_port(str, p_bus_name,
					     p_dev_name, p_port_index);
	} else if (slash_count == 0) {
		return __dl_argv_handle_port_ifname(dl, str, p_bus_name,
						    p_dev_name, p_port_index);
	}
	return 0;
}

static int dl_argv_handle_both(struct dl *dl, char **p_bus_name,
			       char **p_dev_name, uint32_t *p_port_index,
			       uint32_t *p_handle_bit)
{
	char *str = dl_argv_next(dl);
	unsigned int slash_count;
	int err;

	if (!str) {
		pr_err("One of following identifications expected:\n"
		       "Devlink identification (\"bus_name/dev_name\")\n"
		       "Port identification (\"bus_name/dev_name/port_index\" or \"netdev ifname\")\n");
		return -EINVAL;
	}
	slash_count = strslashcount(str);
	if (slash_count == 1) {
		err = __dl_argv_handle(str, p_bus_name, p_dev_name);
		if (err)
			return err;
		*p_handle_bit = DL_OPT_HANDLE;
	} else if (slash_count == 2) {
		err = __dl_argv_handle_port(str, p_bus_name,
					    p_dev_name, p_port_index);
		if (err)
			return err;
		*p_handle_bit = DL_OPT_HANDLEP;
	} else if (slash_count == 0) {
		err = __dl_argv_handle_port_ifname(dl, str, p_bus_name,
						   p_dev_name, p_port_index);
		if (err)
			return err;
		*p_handle_bit = DL_OPT_HANDLEP;
	} else {
		pr_err("Wrong port identification string format.\n");
		pr_err("Expected \"bus_name/dev_name\" or \"bus_name/dev_name/port_index\" or \"netdev_ifname\".\n");
		return -EINVAL;
	}
	return 0;
}

static int dl_argv_uint32_t(struct dl *dl, uint32_t *p_val)
{
	char *str = dl_argv_next(dl);
	int err;

	if (!str) {
		pr_err("Unsigned number argument expected\n");
		return -EINVAL;
	}

	err = strtouint32_t(str, p_val);
	if (err) {
		pr_err("\"%s\" is not a number or not within range\n", str);
		return err;
	}
	return 0;
}

static int dl_argv_uint16_t(struct dl *dl, uint16_t *p_val)
{
	char *str = dl_argv_next(dl);
	int err;

	if (!str) {
		pr_err("Unsigned number argument expected\n");
		return -EINVAL;
	}

	err = strtouint16_t(str, p_val);
	if (err) {
		pr_err("\"%s\" is not a number or not within range\n", str);
		return err;
	}
	return 0;
}

static int dl_argv_str(struct dl *dl, const char **p_str)
{
	const char *str = dl_argv_next(dl);

	if (!str) {
		pr_err("String parameter expected\n");
		return -EINVAL;
	}
	*p_str = str;
	return 0;
}

static int port_type_get(const char *typestr, enum devlink_port_type *p_type)
{
	if (strcmp(typestr, "auto") == 0) {
		*p_type = DEVLINK_PORT_TYPE_AUTO;
	} else if (strcmp(typestr, "eth") == 0) {
		*p_type = DEVLINK_PORT_TYPE_ETH;
	} else if (strcmp(typestr, "ib") == 0) {
		*p_type = DEVLINK_PORT_TYPE_IB;
	} else {
		pr_err("Unknown port type \"%s\"\n", typestr);
		return -EINVAL;
	}
	return 0;
}

static int pool_type_get(const char *typestr, enum devlink_sb_pool_type *p_type)
{
	if (strcmp(typestr, "ingress") == 0) {
		*p_type = DEVLINK_SB_POOL_TYPE_INGRESS;
	} else if (strcmp(typestr, "egress") == 0) {
		*p_type = DEVLINK_SB_POOL_TYPE_EGRESS;
	} else {
		pr_err("Unknown pool type \"%s\"\n", typestr);
		return -EINVAL;
	}
	return 0;
}

static int threshold_type_get(const char *typestr,
			      enum devlink_sb_threshold_type *p_type)
{
	if (strcmp(typestr, "static") == 0) {
		*p_type = DEVLINK_SB_THRESHOLD_TYPE_STATIC;
	} else if (strcmp(typestr, "dynamic") == 0) {
		*p_type = DEVLINK_SB_THRESHOLD_TYPE_DYNAMIC;
	} else {
		pr_err("Unknown threshold type \"%s\"\n", typestr);
		return -EINVAL;
	}
	return 0;
}

static int dl_argv_parse(struct dl *dl, uint32_t o_required,
			 uint32_t o_optional)
{
	struct dl_opts *opts = &dl->opts;
	uint32_t o_all = o_required | o_optional;
	uint32_t o_found = 0;
	int err;

	if (o_required & DL_OPT_HANDLE && o_required & DL_OPT_HANDLEP) {
		uint32_t handle_bit = handle_bit;

		err = dl_argv_handle_both(dl, &opts->bus_name, &opts->dev_name,
					  &opts->port_index, &handle_bit);
		if (err)
			return err;
		o_found |= handle_bit;
	} else if (o_required & DL_OPT_HANDLE) {
		err = dl_argv_handle(dl, &opts->bus_name, &opts->dev_name);
		if (err)
			return err;
		o_found |= DL_OPT_HANDLE;
	} else if (o_required & DL_OPT_HANDLEP) {
		err = dl_argv_handle_port(dl, &opts->bus_name, &opts->dev_name,
					  &opts->port_index);
		if (err)
			return err;
		o_found |= DL_OPT_HANDLEP;
	}

	while (dl_argc(dl)) {
		if (dl_argv_match(dl, "type") &&
		    (o_all & DL_OPT_PORT_TYPE)) {
			const char *typestr;

			dl_arg_inc(dl);
			err = dl_argv_str(dl, &typestr);
			if (err)
				return err;
			err = port_type_get(typestr, &opts->port_type);
			if (err)
				return err;
			o_found |= DL_OPT_PORT_TYPE;
		} else if (dl_argv_match(dl, "count") &&
			   (o_all & DL_OPT_PORT_COUNT)) {
			dl_arg_inc(dl);
			err = dl_argv_uint32_t(dl, &opts->port_count);
			if (err)
				return err;
			o_found |= DL_OPT_PORT_COUNT;
		} else if (dl_argv_match(dl, "sb") &&
			   (o_all & DL_OPT_SB)) {
			dl_arg_inc(dl);
			err = dl_argv_uint32_t(dl, &opts->sb_index);
			if (err)
				return err;
			o_found |= DL_OPT_SB;
		} else if (dl_argv_match(dl, "pool") &&
			   (o_all & DL_OPT_SB_POOL)) {
			dl_arg_inc(dl);
			err = dl_argv_uint16_t(dl, &opts->sb_pool_index);
			if (err)
				return err;
			o_found |= DL_OPT_SB_POOL;
		} else if (dl_argv_match(dl, "size") &&
			   (o_all & DL_OPT_SB_SIZE)) {
			dl_arg_inc(dl);
			err = dl_argv_uint32_t(dl, &opts->sb_pool_size);
			if (err)
				return err;
			o_found |= DL_OPT_SB_SIZE;
		} else if (dl_argv_match(dl, "type") &&
			   (o_all & DL_OPT_SB_TYPE)) {
			const char *typestr;

			dl_arg_inc(dl);
			err = dl_argv_str(dl, &typestr);
			if (err)
				return err;
			err = pool_type_get(typestr, &opts->sb_pool_type);
			if (err)
				return err;
			o_found |= DL_OPT_SB_TYPE;
		} else if (dl_argv_match(dl, "thtype") &&
			   (o_all & DL_OPT_SB_THTYPE)) {
			const char *typestr;

			dl_arg_inc(dl);
			err = dl_argv_str(dl, &typestr);
			if (err)
				return err;
			err = threshold_type_get(typestr,
						 &opts->sb_pool_thtype);
			if (err)
				return err;
			o_found |= DL_OPT_SB_THTYPE;
		} else if (dl_argv_match(dl, "th") &&
			   (o_all & DL_OPT_SB_TH)) {
			dl_arg_inc(dl);
			err = dl_argv_uint32_t(dl, &opts->sb_threshold);
			if (err)
				return err;
			o_found |= DL_OPT_SB_TH;
		} else if (dl_argv_match(dl, "tc") &&
			   (o_all & DL_OPT_SB_TC)) {
			dl_arg_inc(dl);
			err = dl_argv_uint16_t(dl, &opts->sb_tc_index);
			if (err)
				return err;
			o_found |= DL_OPT_SB_TC;
		} else {
			pr_err("Unknown option \"%s\"\n", dl_argv(dl));
			return -EINVAL;
		}
	}

	opts->present = o_found;

	if ((o_optional & DL_OPT_SB) && !(o_found & DL_OPT_SB)) {
		opts->sb_index = 0;
		opts->present |= DL_OPT_SB;
	}

	if ((o_required & DL_OPT_PORT_TYPE) && !(o_found & DL_OPT_PORT_TYPE)) {
		pr_err("Port type option expected.\n");
		return -EINVAL;
	}

	if ((o_required & DL_OPT_PORT_COUNT) &&
	    !(o_found & DL_OPT_PORT_COUNT)) {
		pr_err("Port split count option expected.\n");
		return -EINVAL;
	}

	if ((o_required & DL_OPT_SB_POOL) && !(o_found & DL_OPT_SB_POOL)) {
		pr_err("Pool index option expected.\n");
		return -EINVAL;
	}

	if ((o_required & DL_OPT_SB_SIZE) && !(o_found & DL_OPT_SB_SIZE)) {
		pr_err("Pool size option expected.\n");
		return -EINVAL;
	}

	if ((o_required & DL_OPT_SB_TYPE) && !(o_found & DL_OPT_SB_TYPE)) {
		pr_err("Pool type option expected.\n");
		return -EINVAL;
	}

	if ((o_required & DL_OPT_SB_THTYPE) && !(o_found & DL_OPT_SB_THTYPE)) {
		pr_err("Pool threshold type option expected.\n");
		return -EINVAL;
	}

	if ((o_required & DL_OPT_SB_TH) && !(o_found & DL_OPT_SB_TH)) {
		pr_err("Threshold option expected.\n");
		return -EINVAL;
	}

	if ((o_required & DL_OPT_SB_TC) && !(o_found & DL_OPT_SB_TC)) {
		pr_err("TC index option expected.\n");
		return -EINVAL;
	}
	return 0;
}

static void dl_opts_put(struct nlmsghdr *nlh, struct dl *dl)
{
	struct dl_opts *opts = &dl->opts;

	if (opts->present & DL_OPT_HANDLE) {
		mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, opts->bus_name);
		mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, opts->dev_name);
	} else if (opts->present & DL_OPT_HANDLEP) {
		mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, opts->bus_name);
		mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, opts->dev_name);
		mnl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX,
				 opts->port_index);
	}
	if (opts->present & DL_OPT_PORT_TYPE)
		mnl_attr_put_u16(nlh, DEVLINK_ATTR_PORT_TYPE,
				 opts->port_type);
	if (opts->present & DL_OPT_PORT_COUNT)
		mnl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_SPLIT_COUNT,
				 opts->port_count);
	if (opts->present & DL_OPT_SB)
		mnl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX,
				 opts->sb_index);
	if (opts->present & DL_OPT_SB_POOL)
		mnl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX,
				 opts->sb_pool_index);
	if (opts->present & DL_OPT_SB_SIZE)
		mnl_attr_put_u32(nlh, DEVLINK_ATTR_SB_POOL_SIZE,
				 opts->sb_pool_size);
	if (opts->present & DL_OPT_SB_TYPE)
		mnl_attr_put_u8(nlh, DEVLINK_ATTR_SB_POOL_TYPE,
				opts->sb_pool_type);
	if (opts->present & DL_OPT_SB_THTYPE)
		mnl_attr_put_u8(nlh, DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE,
				opts->sb_pool_thtype);
	if (opts->present & DL_OPT_SB_TH)
		mnl_attr_put_u32(nlh, DEVLINK_ATTR_SB_THRESHOLD,
				 opts->sb_threshold);
	if (opts->present & DL_OPT_SB_TC)
		mnl_attr_put_u16(nlh, DEVLINK_ATTR_SB_TC_INDEX,
				 opts->sb_tc_index);
}

static int dl_argv_parse_put(struct nlmsghdr *nlh, struct dl *dl,
			     uint32_t o_required, uint32_t o_optional)
{
	int err;

	err = dl_argv_parse(dl, o_required, o_optional);
	if (err)
		return err;
	dl_opts_put(nlh, dl);
	return 0;
}


static void cmd_dev_help(void)
{
	pr_out("Usage: devlink dev show [ DEV ]\n");
}

static void __pr_out_handle(const char *bus_name, const char *dev_name)
{
	pr_out("%s/%s", bus_name, dev_name);
}

static void pr_out_handle(struct nlattr **tb)
{
	__pr_out_handle(mnl_attr_get_str(tb[DEVLINK_ATTR_BUS_NAME]),
			mnl_attr_get_str(tb[DEVLINK_ATTR_DEV_NAME]));
}

static void __pr_out_port_handle(const char *bus_name, const char *dev_name,
				 uint32_t port_index)
{
	__pr_out_handle(bus_name, dev_name);
	pr_out("/%d", port_index);
}

static void pr_out_port_handle(struct nlattr **tb)
{
	__pr_out_port_handle(mnl_attr_get_str(tb[DEVLINK_ATTR_BUS_NAME]),
			     mnl_attr_get_str(tb[DEVLINK_ATTR_DEV_NAME]),
			     mnl_attr_get_u32(tb[DEVLINK_ATTR_PORT_INDEX]));
}

static void __pr_out_port_handle_nice(struct dl *dl, const char *bus_name,
				      const char *dev_name, uint32_t port_index)
{
	char *ifname;
	int err;

	if (dl->no_nice_names)
		goto no_nice_names;

	err = ifname_map_rev_lookup(dl, bus_name, dev_name,
				    port_index, &ifname);
	if (err)
		goto no_nice_names;
	pr_out("%s", ifname);
	return;

no_nice_names:
	__pr_out_port_handle(bus_name, dev_name, port_index);
}

static void pr_out_port_handle_nice(struct dl *dl, struct nlattr **tb)
{
	const char *bus_name;
	const char *dev_name;
	uint32_t port_index;

	bus_name = mnl_attr_get_str(tb[DEVLINK_ATTR_BUS_NAME]);
	dev_name = mnl_attr_get_str(tb[DEVLINK_ATTR_DEV_NAME]);
	port_index = mnl_attr_get_u32(tb[DEVLINK_ATTR_PORT_INDEX]);

	__pr_out_port_handle_nice(dl, bus_name, dev_name, port_index);
}

static void pr_out_dev(struct nlattr **tb)
{
	pr_out_handle(tb);
	pr_out("\n");
}

static int cmd_dev_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME])
		return MNL_CB_ERROR;
	pr_out_dev(tb);
	return MNL_CB_OK;
}

static int cmd_dev_show(struct dl *dl)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (dl_argc(dl) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_GET, flags);

	if (dl_argc(dl) > 0) {
		err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLE, 0);
		if (err)
			return err;
	}

	return _mnlg_socket_sndrcv(dl->nlg, nlh, cmd_dev_show_cb, NULL);
}

static int cmd_dev(struct dl *dl)
{
	if (dl_argv_match(dl, "help")) {
		cmd_dev_help();
		return 0;
	} else if (dl_argv_match(dl, "show") ||
		   dl_argv_match(dl, "list") || dl_no_arg(dl)) {
		dl_arg_inc(dl);
		return cmd_dev_show(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static void cmd_port_help(void)
{
	pr_out("Usage: devlink port show [ DEV/PORT_INDEX ]\n");
	pr_out("       devlink port set DEV/PORT_INDEX [ type { eth | ib | auto} ]\n");
	pr_out("       devlink port split DEV/PORT_INDEX count COUNT\n");
	pr_out("       devlink port unsplit DEV/PORT_INDEX\n");
}

static const char *port_type_name(uint32_t type)
{
	switch (type) {
	case DEVLINK_PORT_TYPE_NOTSET: return "notset";
	case DEVLINK_PORT_TYPE_AUTO: return "auto";
	case DEVLINK_PORT_TYPE_ETH: return "eth";
	case DEVLINK_PORT_TYPE_IB: return "ib";
	default: return "<unknown type>";
	}
}

static void pr_out_port(struct nlattr **tb)
{
	struct nlattr *pt_attr = tb[DEVLINK_ATTR_PORT_TYPE];
	struct nlattr *dpt_attr = tb[DEVLINK_ATTR_PORT_DESIRED_TYPE];

	pr_out_port_handle(tb);
	pr_out(":");
	if (pt_attr) {
		uint16_t port_type = mnl_attr_get_u16(pt_attr);

		pr_out(" type %s", port_type_name(port_type));
		if (dpt_attr) {
			uint16_t des_port_type = mnl_attr_get_u16(dpt_attr);

			if (port_type != des_port_type)
				pr_out("(%s)", port_type_name(des_port_type));
		}
	}
	if (tb[DEVLINK_ATTR_PORT_NETDEV_NAME])
		pr_out(" netdev %s",
		       mnl_attr_get_str(tb[DEVLINK_ATTR_PORT_NETDEV_NAME]));
	if (tb[DEVLINK_ATTR_PORT_IBDEV_NAME])
		pr_out(" ibdev %s",
		       mnl_attr_get_str(tb[DEVLINK_ATTR_PORT_IBDEV_NAME]));
	if (tb[DEVLINK_ATTR_PORT_SPLIT_GROUP])
		pr_out(" split_group %u",
		       mnl_attr_get_u32(tb[DEVLINK_ATTR_PORT_SPLIT_GROUP]));
	pr_out("\n");
}

static int cmd_port_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_PORT_INDEX])
		return MNL_CB_ERROR;
	pr_out_port(tb);
	return MNL_CB_OK;
}

static int cmd_port_show(struct dl *dl)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (dl_argc(dl) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_PORT_GET, flags);

	if (dl_argc(dl) > 0) {
		err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLEP, 0);
		if (err)
			return err;
	}

	return _mnlg_socket_sndrcv(dl->nlg, nlh, cmd_port_show_cb, NULL);
}

static int cmd_port_set(struct dl *dl)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_PORT_SET,
			       NLM_F_REQUEST | NLM_F_ACK);

	err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLEP | DL_OPT_PORT_TYPE, 0);
	if (err)
		return err;

	return _mnlg_socket_sndrcv(dl->nlg, nlh, NULL, NULL);
}

static int cmd_port_split(struct dl *dl)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_PORT_SPLIT,
			       NLM_F_REQUEST | NLM_F_ACK);

	err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLEP | DL_OPT_PORT_COUNT, 0);
	if (err)
		return err;

	return _mnlg_socket_sndrcv(dl->nlg, nlh, NULL, NULL);
}

static int cmd_port_unsplit(struct dl *dl)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_PORT_UNSPLIT,
			       NLM_F_REQUEST | NLM_F_ACK);

	err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLEP, 0);
	if (err)
		return err;

	return _mnlg_socket_sndrcv(dl->nlg, nlh, NULL, NULL);
}

static int cmd_port(struct dl *dl)
{
	if (dl_argv_match(dl, "help")) {
		cmd_port_help();
		return 0;
	} else if (dl_argv_match(dl, "show") ||
		   dl_argv_match(dl, "list") ||  dl_no_arg(dl)) {
		dl_arg_inc(dl);
		return cmd_port_show(dl);
	} else if (dl_argv_match(dl, "set")) {
		dl_arg_inc(dl);
		return cmd_port_set(dl);
	} else if (dl_argv_match(dl, "split")) {
		dl_arg_inc(dl);
		return cmd_port_split(dl);
	} else if (dl_argv_match(dl, "unsplit")) {
		dl_arg_inc(dl);
		return cmd_port_unsplit(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static void cmd_sb_help(void)
{
	pr_out("Usage: devlink sb show [ DEV [ sb SB_INDEX ] ]\n");
	pr_out("       devlink sb pool show [ DEV [ sb SB_INDEX ] pool POOL_INDEX ]\n");
	pr_out("       devlink sb pool set DEV [ sb SB_INDEX ] pool POOL_INDEX\n");
	pr_out("                           size POOL_SIZE thtype { static | dynamic }\n");
	pr_out("       devlink sb port pool show [ DEV/PORT_INDEX [ sb SB_INDEX ]\n");
	pr_out("                                   pool POOL_INDEX ]\n");
	pr_out("       devlink sb port pool set DEV/PORT_INDEX [ sb SB_INDEX ]\n");
	pr_out("                                pool POOL_INDEX th THRESHOLD\n");
	pr_out("       devlink sb tc bind show [ DEV/PORT_INDEX [ sb SB_INDEX ] tc TC_INDEX\n");
	pr_out("                                 type { ingress | egress } ]\n");
	pr_out("       devlink sb tc bind set DEV/PORT_INDEX [ sb SB_INDEX ] tc TC_INDEX\n");
	pr_out("                              type { ingress | egress } pool POOL_INDEX\n");
	pr_out("                              th THRESHOLD\n");
}

static void pr_out_sb(struct nlattr **tb)
{
	pr_out_handle(tb);
	pr_out(": sb %u size %u ing_pools %u eg_pools %u ing_tcs %u eg_tcs %u\n",
	       mnl_attr_get_u32(tb[DEVLINK_ATTR_SB_INDEX]),
	       mnl_attr_get_u32(tb[DEVLINK_ATTR_SB_SIZE]),
	       mnl_attr_get_u16(tb[DEVLINK_ATTR_SB_INGRESS_POOL_COUNT]),
	       mnl_attr_get_u16(tb[DEVLINK_ATTR_SB_EGRESS_POOL_COUNT]),
	       mnl_attr_get_u16(tb[DEVLINK_ATTR_SB_INGRESS_TC_COUNT]),
	       mnl_attr_get_u16(tb[DEVLINK_ATTR_SB_EGRESS_TC_COUNT]));
}

static int cmd_sb_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_SB_INDEX] || !tb[DEVLINK_ATTR_SB_SIZE] ||
	    !tb[DEVLINK_ATTR_SB_INGRESS_POOL_COUNT] ||
	    !tb[DEVLINK_ATTR_SB_EGRESS_POOL_COUNT] ||
	    !tb[DEVLINK_ATTR_SB_INGRESS_TC_COUNT] ||
	    !tb[DEVLINK_ATTR_SB_EGRESS_TC_COUNT])
		return MNL_CB_ERROR;
	pr_out_sb(tb);
	return MNL_CB_OK;
}

static int cmd_sb_show(struct dl *dl)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (dl_argc(dl) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_SB_GET, flags);

	if (dl_argc(dl) > 0) {
		err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLE, DL_OPT_SB);
		if (err)
			return err;
	}

	return _mnlg_socket_sndrcv(dl->nlg, nlh, cmd_sb_show_cb, NULL);
}

static const char *pool_type_name(uint8_t type)
{
	switch (type) {
	case DEVLINK_SB_POOL_TYPE_INGRESS: return "ingress";
	case DEVLINK_SB_POOL_TYPE_EGRESS: return "egress";
	default: return "<unknown type>";
	}
}

static const char *threshold_type_name(uint8_t type)
{
	switch (type) {
	case DEVLINK_SB_THRESHOLD_TYPE_STATIC: return "static";
	case DEVLINK_SB_THRESHOLD_TYPE_DYNAMIC: return "dynamic";
	default: return "<unknown type>";
	}
}

static void pr_out_sb_pool(struct nlattr **tb)
{
	pr_out_handle(tb);
	pr_out(": sb %u pool %u type %s size %u thtype %s\n",
	       mnl_attr_get_u32(tb[DEVLINK_ATTR_SB_INDEX]),
	       mnl_attr_get_u16(tb[DEVLINK_ATTR_SB_POOL_INDEX]),
	       pool_type_name(mnl_attr_get_u8(tb[DEVLINK_ATTR_SB_POOL_TYPE])),
	       mnl_attr_get_u32(tb[DEVLINK_ATTR_SB_POOL_SIZE]),
	       threshold_type_name(mnl_attr_get_u8(tb[DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE])));
}

static int cmd_sb_pool_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_SB_INDEX] || !tb[DEVLINK_ATTR_SB_POOL_INDEX] ||
	    !tb[DEVLINK_ATTR_SB_POOL_TYPE] || !tb[DEVLINK_ATTR_SB_POOL_SIZE] ||
	    !tb[DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE])
		return MNL_CB_ERROR;
	pr_out_sb_pool(tb);
	return MNL_CB_OK;
}

static int cmd_sb_pool_show(struct dl *dl)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (dl_argc(dl) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_SB_POOL_GET, flags);

	if (dl_argc(dl) > 0) {
		err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLE | DL_OPT_SB_POOL,
					DL_OPT_SB);
		if (err)
			return err;
	}

	return _mnlg_socket_sndrcv(dl->nlg, nlh, cmd_sb_pool_show_cb, NULL);
}

static int cmd_sb_pool_set(struct dl *dl)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_SB_POOL_SET,
			       NLM_F_REQUEST | NLM_F_ACK);

	err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLE | DL_OPT_SB_POOL |
				DL_OPT_SB_SIZE | DL_OPT_SB_THTYPE, DL_OPT_SB);
	if (err)
		return err;

	return _mnlg_socket_sndrcv(dl->nlg, nlh, NULL, NULL);
}

static int cmd_sb_pool(struct dl *dl)
{
	if (dl_argv_match(dl, "help")) {
		cmd_sb_help();
		return 0;
	} else if (dl_argv_match(dl, "show") ||
		   dl_argv_match(dl, "list") || dl_no_arg(dl)) {
		dl_arg_inc(dl);
		return cmd_sb_pool_show(dl);
	} else if (dl_argv_match(dl, "set")) {
		dl_arg_inc(dl);
		return cmd_sb_pool_set(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static void pr_out_sb_port_pool(struct dl *dl, struct nlattr **tb)
{
	pr_out_port_handle_nice(dl, tb);
	pr_out(": sb %u pool %u threshold %u\n",
	       mnl_attr_get_u32(tb[DEVLINK_ATTR_SB_INDEX]),
	       mnl_attr_get_u16(tb[DEVLINK_ATTR_SB_POOL_INDEX]),
	       mnl_attr_get_u32(tb[DEVLINK_ATTR_SB_THRESHOLD]));
}

static int cmd_sb_port_pool_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct dl *dl = data;
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_PORT_INDEX] || !tb[DEVLINK_ATTR_SB_INDEX] ||
	    !tb[DEVLINK_ATTR_SB_POOL_INDEX] || !tb[DEVLINK_ATTR_SB_THRESHOLD])
		return MNL_CB_ERROR;
	pr_out_sb_port_pool(dl, tb);
	return MNL_CB_OK;
}

static int cmd_sb_port_pool_show(struct dl *dl)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (dl_argc(dl) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_SB_PORT_POOL_GET, flags);

	if (dl_argc(dl) > 0) {
		err = dl_argv_parse_put(nlh, dl,
					DL_OPT_HANDLEP | DL_OPT_SB_POOL,
					DL_OPT_SB);
		if (err)
			return err;
	}

	return _mnlg_socket_sndrcv(dl->nlg, nlh, cmd_sb_port_pool_show_cb, dl);
}

static int cmd_sb_port_pool_set(struct dl *dl)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_SB_PORT_POOL_SET,
			       NLM_F_REQUEST | NLM_F_ACK);

	err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLEP | DL_OPT_SB_POOL |
				DL_OPT_SB_TH, DL_OPT_SB);
	if (err)
		return err;

	return _mnlg_socket_sndrcv(dl->nlg, nlh, NULL, NULL);
}

static int cmd_sb_port_pool(struct dl *dl)
{
	if (dl_argv_match(dl, "help")) {
		cmd_sb_help();
		return 0;
	} else if (dl_argv_match(dl, "show") ||
		   dl_argv_match(dl, "list") || dl_no_arg(dl)) {
		dl_arg_inc(dl);
		return cmd_sb_port_pool_show(dl);
	} else if (dl_argv_match(dl, "set")) {
		dl_arg_inc(dl);
		return cmd_sb_port_pool_set(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static int cmd_sb_port(struct dl *dl)
{
	if (dl_argv_match(dl, "help") || dl_no_arg(dl)) {
		cmd_sb_help();
		return 0;
	} else if (dl_argv_match(dl, "pool")) {
		dl_arg_inc(dl);
		return cmd_sb_port_pool(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static void pr_out_sb_tc_bind(struct dl *dl, struct nlattr **tb)
{
	pr_out_port_handle_nice(dl, tb);
	pr_out(": sb %u tc %u type %s pool %u threshold %u\n",
	       mnl_attr_get_u32(tb[DEVLINK_ATTR_SB_INDEX]),
	       mnl_attr_get_u16(tb[DEVLINK_ATTR_SB_TC_INDEX]),
	       pool_type_name(mnl_attr_get_u8(tb[DEVLINK_ATTR_SB_POOL_TYPE])),
	       mnl_attr_get_u16(tb[DEVLINK_ATTR_SB_POOL_INDEX]),
	       mnl_attr_get_u32(tb[DEVLINK_ATTR_SB_THRESHOLD]));
}

static int cmd_sb_tc_bind_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct dl *dl = data;
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_PORT_INDEX] || !tb[DEVLINK_ATTR_SB_INDEX] ||
	    !tb[DEVLINK_ATTR_SB_TC_INDEX] || !tb[DEVLINK_ATTR_SB_POOL_TYPE] ||
	    !tb[DEVLINK_ATTR_SB_POOL_INDEX] || !tb[DEVLINK_ATTR_SB_THRESHOLD])
		return MNL_CB_ERROR;
	pr_out_sb_tc_bind(dl, tb);
	return MNL_CB_OK;
}

static int cmd_sb_tc_bind_show(struct dl *dl)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (dl_argc(dl) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_SB_TC_POOL_BIND_GET, flags);

	if (dl_argc(dl) > 0) {
		err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLEP | DL_OPT_SB_TC |
					DL_OPT_SB_TYPE, DL_OPT_SB);
		if (err)
			return err;
	}

	return _mnlg_socket_sndrcv(dl->nlg, nlh, cmd_sb_tc_bind_show_cb, dl);
}

static int cmd_sb_tc_bind_set(struct dl *dl)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(dl->nlg, DEVLINK_CMD_SB_TC_POOL_BIND_SET,
			       NLM_F_REQUEST | NLM_F_ACK);

	err = dl_argv_parse_put(nlh, dl, DL_OPT_HANDLEP | DL_OPT_SB_TC |
				DL_OPT_SB_TYPE | DL_OPT_SB_POOL | DL_OPT_SB_TH,
				DL_OPT_SB);
	if (err)
		return err;

	return _mnlg_socket_sndrcv(dl->nlg, nlh, NULL, NULL);
}

static int cmd_sb_tc_bind(struct dl *dl)
{
	if (dl_argv_match(dl, "help")) {
		cmd_sb_help();
		return 0;
	} else if (dl_argv_match(dl, "show") ||
		   dl_argv_match(dl, "list") || dl_no_arg(dl)) {
		dl_arg_inc(dl);
		return cmd_sb_tc_bind_show(dl);
	} else if (dl_argv_match(dl, "set")) {
		dl_arg_inc(dl);
		return cmd_sb_tc_bind_set(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static int cmd_sb_tc(struct dl *dl)
{
	if (dl_argv_match(dl, "help") || dl_no_arg(dl)) {
		cmd_sb_help();
		return 0;
	} else if (dl_argv_match(dl, "bind")) {
		dl_arg_inc(dl);
		return cmd_sb_tc_bind(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static int cmd_sb(struct dl *dl)
{
	if (dl_argv_match(dl, "help")) {
		cmd_sb_help();
		return 0;
	} else if (dl_argv_match(dl, "show") ||
		   dl_argv_match(dl, "list") || dl_no_arg(dl)) {
		dl_arg_inc(dl);
		return cmd_sb_show(dl);
	} else if (dl_argv_match(dl, "pool")) {
		dl_arg_inc(dl);
		return cmd_sb_pool(dl);
	} else if (dl_argv_match(dl, "port")) {
		dl_arg_inc(dl);
		return cmd_sb_port(dl);
	} else if (dl_argv_match(dl, "tc")) {
		dl_arg_inc(dl);
		return cmd_sb_tc(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static const char *cmd_name(uint8_t cmd)
{
	switch (cmd) {
	case DEVLINK_CMD_UNSPEC: return "unspec";
	case DEVLINK_CMD_GET: return "get";
	case DEVLINK_CMD_SET: return "set";
	case DEVLINK_CMD_NEW: return "new";
	case DEVLINK_CMD_DEL: return "del";
	case DEVLINK_CMD_PORT_GET: return "get";
	case DEVLINK_CMD_PORT_SET: return "set";
	case DEVLINK_CMD_PORT_NEW: return "net";
	case DEVLINK_CMD_PORT_DEL: return "del";
	default: return "<unknown cmd>";
	}
}

static const char *cmd_obj(uint8_t cmd)
{
	switch (cmd) {
	case DEVLINK_CMD_UNSPEC: return "unspec";
	case DEVLINK_CMD_GET:
	case DEVLINK_CMD_SET:
	case DEVLINK_CMD_NEW:
	case DEVLINK_CMD_DEL:
		return "dev";
	case DEVLINK_CMD_PORT_GET:
	case DEVLINK_CMD_PORT_SET:
	case DEVLINK_CMD_PORT_NEW:
	case DEVLINK_CMD_PORT_DEL:
		return "port";
	default: return "<unknown obj>";
	}
}

static void pr_out_mon_header(uint8_t cmd)
{
	pr_out("[%s,%s] ", cmd_obj(cmd), cmd_name(cmd));
}

static bool cmd_filter_check(struct dl *dl, uint8_t cmd)
{
	const char *obj = cmd_obj(cmd);
	unsigned int index = 0;
	const char *cur_obj;

	if (dl_no_arg(dl))
		return true;
	while ((cur_obj = dl_argv_index(dl, index++))) {
		if (strcmp(cur_obj, obj) == 0 || strcmp(cur_obj, "all") == 0)
			return true;
	}
	return false;
}

static int cmd_mon_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct dl *dl = data;
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	uint8_t cmd = genl->cmd;

	if (!cmd_filter_check(dl, cmd))
		return MNL_CB_OK;

	switch (cmd) {
	case DEVLINK_CMD_GET: /* fall through */
	case DEVLINK_CMD_SET: /* fall through */
	case DEVLINK_CMD_NEW: /* fall through */
	case DEVLINK_CMD_DEL:
		mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
		if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME])
			return MNL_CB_ERROR;
		pr_out_mon_header(genl->cmd);
		pr_out_dev(tb);
		break;
	case DEVLINK_CMD_PORT_GET: /* fall through */
	case DEVLINK_CMD_PORT_SET: /* fall through */
	case DEVLINK_CMD_PORT_NEW: /* fall through */
	case DEVLINK_CMD_PORT_DEL:
		mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
		if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
		    !tb[DEVLINK_ATTR_PORT_INDEX])
			return MNL_CB_ERROR;
		pr_out_mon_header(genl->cmd);
		pr_out_port(tb);
		break;
	}
	return MNL_CB_OK;
}

static int cmd_mon_show(struct dl *dl)
{
	int err;
	unsigned int index = 0;
	const char *cur_obj;

	while ((cur_obj = dl_argv_index(dl, index++))) {
		if (strcmp(cur_obj, "all") != 0 &&
		    strcmp(cur_obj, "dev") != 0 &&
		    strcmp(cur_obj, "port") != 0) {
			pr_err("Unknown object \"%s\"\n", cur_obj);
			return -EINVAL;
		}
	}
	err = _mnlg_socket_group_add(dl->nlg, DEVLINK_GENL_MCGRP_CONFIG_NAME);
	if (err)
		return err;
	err = _mnlg_socket_recv_run(dl->nlg, cmd_mon_show_cb, dl);
	if (err)
		return err;
	return 0;
}

static void cmd_mon_help(void)
{
	pr_out("Usage: devlink monitor [ all | OBJECT-LIST ]\n"
	       "where  OBJECT-LIST := { dev | port }\n");
}

static int cmd_mon(struct dl *dl)
{
	if (dl_argv_match(dl, "help")) {
		cmd_mon_help();
		return 0;
	} else if (dl_no_arg(dl)) {
		dl_arg_inc(dl);
		return cmd_mon_show(dl);
	}
	pr_err("Command \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static void help(void)
{
	pr_out("Usage: devlink [ OPTIONS ] OBJECT { COMMAND | help }\n"
	       "where  OBJECT := { dev | port | sb | monitor }\n"
	       "       OPTIONS := { -V[ersion] | -n[no-nice-names] }\n");
}

static int dl_cmd(struct dl *dl)
{
	if (dl_argv_match(dl, "help") || dl_no_arg(dl)) {
		help();
		return 0;
	} else if (dl_argv_match(dl, "dev")) {
		dl_arg_inc(dl);
		return cmd_dev(dl);
	} else if (dl_argv_match(dl, "port")) {
		dl_arg_inc(dl);
		return cmd_port(dl);
	} else if (dl_argv_match(dl, "sb")) {
		dl_arg_inc(dl);
		return cmd_sb(dl);
	} else if (dl_argv_match(dl, "monitor")) {
		dl_arg_inc(dl);
		return cmd_mon(dl);
	}
	pr_err("Object \"%s\" not found\n", dl_argv(dl));
	return -ENOENT;
}

static int dl_init(struct dl *dl, int argc, char **argv)
{
	int err;

	dl->argc = argc;
	dl->argv = argv;

	dl->nlg = mnlg_socket_open(DEVLINK_GENL_NAME, DEVLINK_GENL_VERSION);
	if (!dl->nlg) {
		pr_err("Failed to connect to devlink Netlink\n");
		return -errno;
	}

	err = ifname_map_init(dl);
	if (err) {
		pr_err("Failed to create index map\n");
		goto err_ifname_map_create;
	}
	return 0;

err_ifname_map_create:
	mnlg_socket_close(dl->nlg);
	return err;
}

static void dl_fini(struct dl *dl)
{
	ifname_map_fini(dl);
	mnlg_socket_close(dl->nlg);
}

static struct dl *dl_alloc(void)
{
	struct dl *dl;

	dl = calloc(1, sizeof(*dl));
	if (!dl)
		return NULL;
	return dl;
}

static void dl_free(struct dl *dl)
{
	free(dl);
}

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "Version",		no_argument,		NULL, 'V' },
		{ "no-nice-names",	no_argument,		NULL, 'n' },
		{ NULL, 0, NULL, 0 }
	};
	struct dl *dl;
	int opt;
	int err;
	int ret;

	dl = dl_alloc();
	if (!dl) {
		pr_err("Failed to allocate memory for devlink\n");
		return EXIT_FAILURE;
	}

	while ((opt = getopt_long(argc, argv, "Vn",
				  long_options, NULL)) >= 0) {

		switch (opt) {
		case 'V':
			printf("devlink utility, iproute2-ss%s\n", SNAPSHOT);
			return EXIT_SUCCESS;
		case 'n':
			dl->no_nice_names = true;
			break;
		default:
			pr_err("Unknown option.\n");
			help();
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	err = dl_init(dl, argc, argv);
	if (err) {
		ret = EXIT_FAILURE;
		goto dl_free;
	}

	err = dl_cmd(dl);
	if (err) {
		ret = EXIT_FAILURE;
		goto dl_fini;
	}

	ret = EXIT_SUCCESS;

dl_fini:
	dl_fini(dl);
dl_free:
	dl_free(dl);

	return ret;
}
