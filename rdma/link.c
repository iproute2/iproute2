/*
 * link.c	RDMA tool
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Leon Romanovsky <leonro@mellanox.com>
 */

#include "rdma.h"

static int link_help(struct rd *rd)
{
	pr_out("Usage: %s link show [DEV/PORT_INDEX]\n", rd->filename);
	return 0;
}

static const char *caps_to_str(uint32_t idx)
{
#define RDMA_PORT_FLAGS(x) \
	x(SM, 1) \
	x(NOTICE, 2) \
	x(TRAP, 3) \
	x(OPT_IPD, 4) \
	x(AUTO_MIGR, 5) \
	x(SL_MAP, 6) \
	x(MKEY_NVRAM, 7) \
	x(PKEY_NVRAM, 8) \
	x(LED_INFO, 9) \
	x(SM_DISABLED, 10) \
	x(SYS_IMAGE_GUIG, 11) \
	x(PKEY_SW_EXT_PORT_TRAP, 12) \
	x(EXTENDED_SPEEDS, 14) \
	x(CM, 16) \
	x(SNMP_TUNNEL, 17) \
	x(REINIT, 18) \
	x(DEVICE_MGMT, 19) \
	x(VENDOR_CLASS, 20) \
	x(DR_NOTICE, 21) \
	x(CAP_MASK_NOTICE, 22) \
	x(BOOT_MGMT, 23) \
	x(LINK_LATENCY, 24) \
	x(CLIENT_REG, 25) \
	x(IP_BASED_GIDS, 26)

	enum { RDMA_PORT_FLAGS(RDMA_BITMAP_ENUM) };

	static const char * const
		rdma_port_names[] = { RDMA_PORT_FLAGS(RDMA_BITMAP_NAMES) };
	#undef RDMA_PORT_FLAGS

	if (idx < ARRAY_SIZE(rdma_port_names) && rdma_port_names[idx])
		return rdma_port_names[idx];
	return "UNKNOWN";
}

static void link_print_caps(struct rd *rd, struct nlattr **tb)
{
	uint64_t caps;
	uint32_t idx;

	if (!tb[RDMA_NLDEV_ATTR_CAP_FLAGS])
		return;

	caps = mnl_attr_get_u64(tb[RDMA_NLDEV_ATTR_CAP_FLAGS]);

	if (rd->json_output) {
		jsonw_name(rd->jw, "caps");
		jsonw_start_array(rd->jw);
	} else {
		pr_out("\n    caps: <");
	}
	for (idx = 0; caps; idx++) {
		if (caps & 0x1) {
			if (rd->json_output) {
				jsonw_string(rd->jw, caps_to_str(idx));
			} else {
				pr_out("%s", caps_to_str(idx));
				if (caps >> 0x1)
					pr_out(", ");
			}
		}
		caps >>= 0x1;
	}

	if (rd->json_output)
		jsonw_end_array(rd->jw);
	else
		pr_out(">");
}

static void link_print_subnet_prefix(struct rd *rd, struct nlattr **tb)
{
	uint64_t subnet_prefix;
	uint16_t vp[4];
	char str[32];

	if (!tb[RDMA_NLDEV_ATTR_SUBNET_PREFIX])
		return;

	subnet_prefix = mnl_attr_get_u64(tb[RDMA_NLDEV_ATTR_SUBNET_PREFIX]);
	memcpy(vp, &subnet_prefix, sizeof(uint64_t));
	snprintf(str, 32, "%04x:%04x:%04x:%04x", vp[3], vp[2], vp[1], vp[0]);
	if (rd->json_output)
		jsonw_string_field(rd->jw, "subnet_prefix", str);
	else
		pr_out("subnet_prefix %s ", str);
}

static void link_print_lid(struct rd *rd, struct nlattr **tb)
{
	uint32_t lid;

	if (!tb[RDMA_NLDEV_ATTR_LID])
		return;

	lid = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_LID]);
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "lid", lid);
	else
		pr_out("lid %u ", lid);
}

static void link_print_sm_lid(struct rd *rd, struct nlattr **tb)
{
	uint32_t sm_lid;

	if (!tb[RDMA_NLDEV_ATTR_SM_LID])
		return;

	sm_lid = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_SM_LID]);
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "sm_lid", sm_lid);
	else
		pr_out("sm_lid %u ", sm_lid);
}

static void link_print_lmc(struct rd *rd, struct nlattr **tb)
{
	uint8_t lmc;

	if (!tb[RDMA_NLDEV_ATTR_LMC])
		return;

	lmc = mnl_attr_get_u8(tb[RDMA_NLDEV_ATTR_LMC]);
	if (rd->json_output)
		jsonw_uint_field(rd->jw, "lmc", lmc);
	else
		pr_out("lmc %u ", lmc);
}

static const char *link_state_to_str(uint8_t link_state)
{
	static const char * const link_state_str[] = { "NOP", "DOWN",
						       "INIT", "ARMED",
						       "ACTIVE",
						       "ACTIVE_DEFER" };
	if (link_state < ARRAY_SIZE(link_state_str))
		return link_state_str[link_state];
	return "UNKNOWN";
}

static void link_print_state(struct rd *rd, struct nlattr **tb)
{
	uint8_t state;

	if (!tb[RDMA_NLDEV_ATTR_PORT_STATE])
		return;

	state = mnl_attr_get_u8(tb[RDMA_NLDEV_ATTR_PORT_STATE]);
	if (rd->json_output)
		jsonw_string_field(rd->jw, "state", link_state_to_str(state));
	else
		pr_out("state %s ", link_state_to_str(state));
}

static const char *phys_state_to_str(uint8_t phys_state)
{
	static const char * const phys_state_str[] = { "NOP", "SLEEP",
						       "POLLING", "DISABLED",
						       "ARMED", "LINK_UP",
						       "LINK_ERROR_RECOVER",
						       "PHY_TEST", "UNKNOWN",
						       "OPA_OFFLINE",
						       "UNKNOWN", "OPA_TEST" };
	if (phys_state < ARRAY_SIZE(phys_state_str))
		return phys_state_str[phys_state];
	return "UNKNOWN";
};

static void link_print_phys_state(struct rd *rd, struct nlattr **tb)
{
	uint8_t phys_state;

	if (!tb[RDMA_NLDEV_ATTR_PORT_PHYS_STATE])
		return;

	phys_state = mnl_attr_get_u8(tb[RDMA_NLDEV_ATTR_PORT_PHYS_STATE]);
	if (rd->json_output)
		jsonw_string_field(rd->jw, "physical_state",
				   phys_state_to_str(phys_state));
	else
		pr_out("physical_state %s ", phys_state_to_str(phys_state));
}

static int link_parse_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct rd *rd = data;
	uint32_t port, idx;
	char name[32];

	mnl_attr_parse(nlh, 0, rd_attr_cb, tb);
	if (!tb[RDMA_NLDEV_ATTR_DEV_INDEX] || !tb[RDMA_NLDEV_ATTR_DEV_NAME])
		return MNL_CB_ERROR;

	if (!tb[RDMA_NLDEV_ATTR_PORT_INDEX]) {
		pr_err("This tool doesn't support switches yet\n");
		return MNL_CB_ERROR;
	}

	idx = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	port = mnl_attr_get_u32(tb[RDMA_NLDEV_ATTR_PORT_INDEX]);
	snprintf(name, 32, "%s/%u",
		 mnl_attr_get_str(tb[RDMA_NLDEV_ATTR_DEV_NAME]), port);

	if (rd->json_output) {
		jsonw_uint_field(rd->jw, "ifindex", idx);
		jsonw_uint_field(rd->jw, "port", port);
		jsonw_string_field(rd->jw, "ifname", name);

	} else {
		pr_out("%u/%u: %s: ", idx, port, name);
	}

	link_print_subnet_prefix(rd, tb);
	link_print_lid(rd, tb);
	link_print_sm_lid(rd, tb);
	link_print_lmc(rd, tb);
	link_print_state(rd, tb);
	link_print_phys_state(rd, tb);
	if (rd->show_details)
		link_print_caps(rd, tb);

	if (!rd->json_output)
		pr_out("\n");
	return MNL_CB_OK;
}

static int link_no_args(struct rd *rd)
{
	uint32_t seq;
	int ret;

	rd_prepare_msg(rd, RDMA_NLDEV_CMD_PORT_GET, &seq,
		       (NLM_F_REQUEST | NLM_F_ACK));
	mnl_attr_put_u32(rd->nlh, RDMA_NLDEV_ATTR_DEV_INDEX, rd->dev_idx);
	mnl_attr_put_u32(rd->nlh, RDMA_NLDEV_ATTR_PORT_INDEX, rd->port_idx);
	ret = rd_send_msg(rd);
	if (ret)
		return ret;

	if (rd->json_output)
		jsonw_start_object(rd->jw);
	ret = rd_recv_msg(rd, link_parse_cb, rd, seq);
	if (rd->json_output)
		jsonw_end_object(rd->jw);
	return ret;
}

static int link_one_show(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		link_no_args},
		{ 0 }
	};

	return rd_exec_cmd(rd, cmds, "parameter");
}

static int link_show(struct rd *rd)
{
	struct dev_map *dev_map;
	uint32_t port;
	int ret = 0;

	if (rd->json_output)
		jsonw_start_array(rd->jw);
	if (rd_no_arg(rd)) {
		list_for_each_entry(dev_map, &rd->dev_map_list, list) {
			rd->dev_idx = dev_map->idx;
			for (port = 1; port < dev_map->num_ports + 1; port++) {
				rd->port_idx = port;
				ret = link_one_show(rd);
				if (ret)
					goto out;
			}
		}

	} else {
		dev_map = dev_map_lookup(rd, true);
		port = get_port_from_argv(rd);
		if (!dev_map || port > dev_map->num_ports) {
			pr_err("Wrong device name\n");
			ret = -ENOENT;
			goto out;
		}
		rd_arg_inc(rd);
		rd->dev_idx = dev_map->idx;
		rd->port_idx = port ? : 1;
		for (; rd->port_idx < dev_map->num_ports + 1; rd->port_idx++) {
			ret = link_one_show(rd);
			if (ret)
				goto out;
			if (port)
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

int cmd_link(struct rd *rd)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		link_show },
		{ "show",	link_show },
		{ "list",	link_show },
		{ "help",	link_help },
		{ 0 }
	};

	return rd_exec_cmd(rd, cmds, "link command");
}
