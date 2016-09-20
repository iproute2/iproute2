/*
 * link.c	TIPC link functionality.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <linux/tipc_netlink.h>
#include <linux/tipc.h>
#include <linux/genetlink.h>
#include <libmnl/libmnl.h>

#include "cmdl.h"
#include "msg.h"
#include "link.h"
#include "bearer.h"

static int link_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *info[TIPC_NLA_MAX + 1] = {};
	struct nlattr *attrs[TIPC_NLA_LINK_MAX + 1] = {};

	mnl_attr_parse(nlh, sizeof(*genl), parse_attrs, info);
	if (!info[TIPC_NLA_LINK])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(info[TIPC_NLA_LINK], parse_attrs, attrs);
	if (!attrs[TIPC_NLA_LINK_NAME])
		return MNL_CB_ERROR;

	printf("%s: ", mnl_attr_get_str(attrs[TIPC_NLA_LINK_NAME]));

	if (attrs[TIPC_NLA_LINK_UP])
		printf("up\n");
	else
		printf("down\n");

	return MNL_CB_OK;
}

static int cmd_link_list(struct nlmsghdr *nlh, const struct cmd *cmd,
			 struct cmdl *cmdl, void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];

	if (help_flag) {
		fprintf(stderr, "Usage: %s link list\n", cmdl->argv[0]);
		return -EINVAL;
	}

	nlh = msg_init(buf, TIPC_NL_LINK_GET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}

	return msg_dumpit(nlh, link_list_cb, NULL);
}

static int link_get_cb(const struct nlmsghdr *nlh, void *data)
{
	int *prop = data;
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *info[TIPC_NLA_MAX + 1] = {};
	struct nlattr *attrs[TIPC_NLA_LINK_MAX + 1] = {};
	struct nlattr *props[TIPC_NLA_PROP_MAX + 1] = {};

	mnl_attr_parse(nlh, sizeof(*genl), parse_attrs, info);
	if (!info[TIPC_NLA_LINK])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(info[TIPC_NLA_LINK], parse_attrs, attrs);
	if (!attrs[TIPC_NLA_LINK_PROP])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(attrs[TIPC_NLA_LINK_PROP], parse_attrs, props);
	if (!props[*prop])
		return MNL_CB_ERROR;

	printf("%u\n", mnl_attr_get_u32(props[*prop]));

	return MNL_CB_OK;
}

static int cmd_link_get_prop(struct nlmsghdr *nlh, const struct cmd *cmd,
			     struct cmdl *cmdl, void *data)
{
	int prop;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct opt *opt;
	struct opt opts[] = {
		{ "link",		OPT_KEYVAL,	NULL },
		{ NULL }
	};

	if (strcmp(cmd->cmd, "priority") == 0)
		prop = TIPC_NLA_PROP_PRIO;
	else if ((strcmp(cmd->cmd, "tolerance") == 0))
		prop = TIPC_NLA_PROP_TOL;
	else if ((strcmp(cmd->cmd, "window") == 0))
		prop = TIPC_NLA_PROP_WIN;
	else
		return -EINVAL;

	if (help_flag) {
		(cmd->help)(cmdl);
		return -EINVAL;
	}

	if (parse_opts(opts, cmdl) < 0)
		return -EINVAL;

	nlh = msg_init(buf, TIPC_NL_LINK_GET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}

	opt = get_opt(opts, "link");
	if (!opt) {
		fprintf(stderr, "error, missing link\n");
		return -EINVAL;
	}
	mnl_attr_put_strz(nlh, TIPC_NLA_LINK_NAME, opt->val);

	return msg_doit(nlh, link_get_cb, &prop);
}

static void cmd_link_get_help(struct cmdl *cmdl)
{
	fprintf(stderr, "Usage: %s link get PPROPERTY link LINK\n\n"
		"PROPERTIES\n"
		" tolerance             - Get link tolerance\n"
		" priority              - Get link priority\n"
		" window                - Get link window\n",
		cmdl->argv[0]);
}

static int cmd_link_get(struct nlmsghdr *nlh, const struct cmd *cmd,
			struct cmdl *cmdl, void *data)
{
	const struct cmd cmds[] = {
		{ "priority",	cmd_link_get_prop,	cmd_link_get_help },
		{ "tolerance",	cmd_link_get_prop,	cmd_link_get_help },
		{ "window",	cmd_link_get_prop,	cmd_link_get_help },
		{ NULL }
	};

	return run_cmd(nlh, cmd, cmds, cmdl, NULL);
}

static void cmd_link_stat_reset_help(struct cmdl *cmdl)
{
	fprintf(stderr, "Usage: %s link stat reset link LINK\n\n", cmdl->argv[0]);
}

static int cmd_link_stat_reset(struct nlmsghdr *nlh, const struct cmd *cmd,
			       struct cmdl *cmdl, void *data)
{
	char *link;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct opt *opt;
	struct nlattr *nest;
	struct opt opts[] = {
		{ "link",		OPT_KEYVAL,	NULL },
		{ NULL }
	};

	if (help_flag) {
		(cmd->help)(cmdl);
		return -EINVAL;
	}

	if (parse_opts(opts, cmdl) != 1) {
		(cmd->help)(cmdl);
		return -EINVAL;
	}

	nlh = msg_init(buf, TIPC_NL_LINK_RESET_STATS);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}

	opt = get_opt(opts, "link");
	if (!opt) {
		fprintf(stderr, "error, missing link\n");
		return -EINVAL;
	}
	link = opt->val;

	nest = mnl_attr_nest_start(nlh, TIPC_NLA_LINK);
	mnl_attr_put_strz(nlh, TIPC_NLA_LINK_NAME, link);
	mnl_attr_nest_end(nlh, nest);

	return msg_doit(nlh, NULL, NULL);
}

static uint32_t perc(uint32_t count, uint32_t total)
{
	return (count * 100 + (total / 2)) / total;
}

static int _show_link_stat(struct nlattr *attrs[], struct nlattr *prop[],
			   struct nlattr *stats[])
{
	uint32_t proft;

	if (attrs[TIPC_NLA_LINK_ACTIVE])
		printf("  ACTIVE");
	else if (attrs[TIPC_NLA_LINK_UP])
		printf("  STANDBY");
	else
		printf("  DEFUNCT");

	printf("  MTU:%u  Priority:%u  Tolerance:%u ms  Window:%u packets\n",
	       mnl_attr_get_u32(attrs[TIPC_NLA_LINK_MTU]),
	       mnl_attr_get_u32(prop[TIPC_NLA_PROP_PRIO]),
	       mnl_attr_get_u32(prop[TIPC_NLA_PROP_TOL]),
	       mnl_attr_get_u32(prop[TIPC_NLA_PROP_WIN]));

	printf("  RX packets:%u fragments:%u/%u bundles:%u/%u\n",
	       mnl_attr_get_u32(attrs[TIPC_NLA_LINK_RX]) -
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_INFO]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_FRAGMENTS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_FRAGMENTED]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_BUNDLES]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_BUNDLED]));

	printf("  TX packets:%u fragments:%u/%u bundles:%u/%u\n",
	       mnl_attr_get_u32(attrs[TIPC_NLA_LINK_TX]) -
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_INFO]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_FRAGMENTS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_FRAGMENTED]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_BUNDLES]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_BUNDLED]));

	proft = mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_PROF_TOT]);
	printf("  TX profile sample:%u packets  average:%u octets\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_CNT]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_TOT]) / proft);

	printf("  0-64:%u%% -256:%u%% -1024:%u%% -4096:%u%% -16384:%u%% -32768:%u%% -66000:%u%%\n",
	       perc(mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_P0]), proft),
	       perc(mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_P1]), proft),
	       perc(mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_P2]), proft),
	       perc(mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_P3]), proft),
	       perc(mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_P4]), proft),
	       perc(mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_P5]), proft),
	       perc(mnl_attr_get_u32(stats[TIPC_NLA_STATS_MSG_LEN_P6]), proft));

	printf("  RX states:%u probes:%u naks:%u defs:%u dups:%u\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_STATES]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_PROBES]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_NACKS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_DEFERRED]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_DUPLICATES]));

	printf("  TX states:%u probes:%u naks:%u acks:%u dups:%u\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_STATES]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_PROBES]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_NACKS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_ACKS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RETRANSMITTED]));

	printf("  Congestion link:%u  Send queue max:%u avg:%u\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_LINK_CONGS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_MAX_QUEUE]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_AVG_QUEUE]));

	return MNL_CB_OK;
}

static int _show_bc_link_stat(struct nlattr *prop[], struct nlattr *stats[])
{
	printf("  Window:%u packets\n",
	       mnl_attr_get_u32(prop[TIPC_NLA_PROP_WIN]));

	printf("  RX packets:%u fragments:%u/%u bundles:%u/%u\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_INFO]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_FRAGMENTS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_FRAGMENTED]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_BUNDLES]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_BUNDLED]));

	printf("  TX packets:%u fragments:%u/%u bundles:%u/%u\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_INFO]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_FRAGMENTS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_FRAGMENTED]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_BUNDLES]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_BUNDLED]));

	printf("  RX naks:%u defs:%u dups:%u\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_NACKS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RX_DEFERRED]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_DUPLICATES]));

	printf("  TX naks:%u acks:%u dups:%u\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_NACKS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_TX_ACKS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_RETRANSMITTED]));

	printf("  Congestion link:%u  Send queue max:%u avg:%u\n",
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_LINK_CONGS]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_MAX_QUEUE]),
	       mnl_attr_get_u32(stats[TIPC_NLA_STATS_AVG_QUEUE]));

	return MNL_CB_OK;
}

static int link_stat_show_cb(const struct nlmsghdr *nlh, void *data)
{
	const char *name;
	const char *link = data;
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *info[TIPC_NLA_MAX + 1] = {};
	struct nlattr *attrs[TIPC_NLA_LINK_MAX + 1] = {};
	struct nlattr *prop[TIPC_NLA_PROP_MAX + 1] = {};
	struct nlattr *stats[TIPC_NLA_STATS_MAX + 1] = {};

	mnl_attr_parse(nlh, sizeof(*genl), parse_attrs, info);
	if (!info[TIPC_NLA_LINK])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(info[TIPC_NLA_LINK], parse_attrs, attrs);
	if (!attrs[TIPC_NLA_LINK_NAME] || !attrs[TIPC_NLA_LINK_PROP] ||
	    !attrs[TIPC_NLA_LINK_STATS])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(attrs[TIPC_NLA_LINK_PROP], parse_attrs, prop);
	mnl_attr_parse_nested(attrs[TIPC_NLA_LINK_STATS], parse_attrs, stats);

	name = mnl_attr_get_str(attrs[TIPC_NLA_LINK_NAME]);

	/* If a link is passed, skip all but that link */
	if (link && (strcmp(name, link) != 0))
		return MNL_CB_OK;

	if (attrs[TIPC_NLA_LINK_BROADCAST]) {
		printf("Link <%s>\n", name);
		return _show_bc_link_stat(prop, stats);
	}

	printf("\nLink <%s>\n", name);

	return _show_link_stat(attrs, prop, stats);
}

static void cmd_link_stat_show_help(struct cmdl *cmdl)
{
	fprintf(stderr, "Usage: %s link stat show [ link LINK ]\n",
		cmdl->argv[0]);
}

static int cmd_link_stat_show(struct nlmsghdr *nlh, const struct cmd *cmd,
			      struct cmdl *cmdl, void *data)
{
	char *link = NULL;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct opt *opt;
	struct opt opts[] = {
		{ "link",		OPT_KEYVAL,	NULL },
		{ NULL }
	};

	if (help_flag) {
		(cmd->help)(cmdl);
		return -EINVAL;
	}

	nlh = msg_init(buf, TIPC_NL_LINK_GET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}

	if (parse_opts(opts, cmdl) < 0)
		return -EINVAL;

	opt = get_opt(opts, "link");
	if (opt)
		link = opt->val;

	return msg_dumpit(nlh, link_stat_show_cb, link);
}

static void cmd_link_stat_help(struct cmdl *cmdl)
{
	fprintf(stderr, "Usage: %s link stat COMMAND [ARGS]\n\n"
		"COMMANDS:\n"
		" reset                 - Reset link statistics for link\n"
		" show                  - Get link priority\n",
		cmdl->argv[0]);
}

static int cmd_link_stat(struct nlmsghdr *nlh, const struct cmd *cmd,
			 struct cmdl *cmdl, void *data)
{
	const struct cmd cmds[] = {
		{ "reset",	cmd_link_stat_reset,	cmd_link_stat_reset_help },
		{ "show",	cmd_link_stat_show,	cmd_link_stat_show_help },
		{ NULL }
	};

	return run_cmd(nlh, cmd, cmds, cmdl, NULL);
}

static void cmd_link_set_help(struct cmdl *cmdl)
{
	fprintf(stderr, "Usage: %s link set PPROPERTY link LINK\n\n"
		"PROPERTIES\n"
		" tolerance TOLERANCE   - Set link tolerance\n"
		" priority PRIORITY     - Set link priority\n"
		" window WINDOW         - Set link window\n",
		cmdl->argv[0]);
}

static int cmd_link_set_prop(struct nlmsghdr *nlh, const struct cmd *cmd,
			     struct cmdl *cmdl, void *data)
{
	int val;
	int prop;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlattr *props;
	struct nlattr *attrs;
	struct opt *opt;
	struct opt opts[] = {
		{ "link",		OPT_KEYVAL,	NULL },
		{ NULL }
	};

	if (strcmp(cmd->cmd, "priority") == 0)
		prop = TIPC_NLA_PROP_PRIO;
	else if ((strcmp(cmd->cmd, "tolerance") == 0))
		prop = TIPC_NLA_PROP_TOL;
	else if ((strcmp(cmd->cmd, "window") == 0))
		prop = TIPC_NLA_PROP_WIN;
	else
		return -EINVAL;

	if (help_flag) {
		(cmd->help)(cmdl);
		return -EINVAL;
	}

	if (cmdl->optind >= cmdl->argc) {
		fprintf(stderr, "error, missing value\n");
		return -EINVAL;
	}
	val = atoi(shift_cmdl(cmdl));

	if (parse_opts(opts, cmdl) < 0)
		return -EINVAL;

	nlh = msg_init(buf, TIPC_NL_LINK_SET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}
	attrs = mnl_attr_nest_start(nlh, TIPC_NLA_LINK);

	opt = get_opt(opts, "link");
	if (!opt) {
		fprintf(stderr, "error, missing link\n");
		return -EINVAL;
	}
	mnl_attr_put_strz(nlh, TIPC_NLA_LINK_NAME, opt->val);

	props = mnl_attr_nest_start(nlh, TIPC_NLA_LINK_PROP);
	mnl_attr_put_u32(nlh, prop, val);
	mnl_attr_nest_end(nlh, props);

	mnl_attr_nest_end(nlh, attrs);

	return msg_doit(nlh, link_get_cb, &prop);
}

static int cmd_link_set(struct nlmsghdr *nlh, const struct cmd *cmd,
			struct cmdl *cmdl, void *data)
{
	const struct cmd cmds[] = {
		{ "priority",	cmd_link_set_prop,	cmd_link_set_help },
		{ "tolerance",	cmd_link_set_prop,	cmd_link_set_help },
		{ "window",	cmd_link_set_prop,	cmd_link_set_help },
		{ NULL }
	};

	return run_cmd(nlh, cmd, cmds, cmdl, NULL);
}

static int cmd_link_mon_set_prop(struct nlmsghdr *nlh, const struct cmd *cmd,
				 struct cmdl *cmdl, void *data)
{
	int size;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlattr *attrs;

	if (cmdl->argc != cmdl->optind + 1) {
		fprintf(stderr, "error, missing value\n");
		return -EINVAL;
	}
	size = atoi(shift_cmdl(cmdl));

	nlh = msg_init(buf, TIPC_NL_MON_SET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}
	attrs = mnl_attr_nest_start(nlh, TIPC_NLA_MON);

	mnl_attr_put_u32(nlh, TIPC_NLA_MON_ACTIVATION_THRESHOLD, size);

	mnl_attr_nest_end(nlh, attrs);

	return msg_doit(nlh, NULL, NULL);
}

static int link_mon_summary_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *info[TIPC_NLA_MAX + 1] = {};
	struct nlattr *attrs[TIPC_NLA_MON_MAX + 1] = {};

	mnl_attr_parse(nlh, sizeof(*genl), parse_attrs, info);
	if (!info[TIPC_NLA_MON])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(info[TIPC_NLA_MON], parse_attrs, attrs);

	printf("\nbearer %s\n",
		mnl_attr_get_str(attrs[TIPC_NLA_MON_BEARER_NAME]));

	printf("    table_generation %u\n",
	       mnl_attr_get_u32(attrs[TIPC_NLA_MON_LISTGEN]));
	printf("    cluster_size %u\n",
		mnl_attr_get_u32(attrs[TIPC_NLA_MON_PEERCNT]));
	printf("    algorithm %s\n",
		attrs[TIPC_NLA_MON_ACTIVE] ? "overlapping-ring" : "full-mesh");

	return MNL_CB_OK;
}

static int cmd_link_mon_summary(struct nlmsghdr *nlh, const struct cmd *cmd,
				struct cmdl *cmdl, void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];

	if (help_flag) {
		fprintf(stderr,	"Usage: %s monitor summary\n", cmdl->argv[0]);
		return -EINVAL;
	}

	nlh = msg_init(buf, TIPC_NL_MON_GET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}

	return msg_dumpit(nlh, link_mon_summary_cb, NULL);
}

#define STATUS_WIDTH 7
#define MAX_NODE_WIDTH 14 /* 255.4095.4095 */
#define MAX_DOM_GEN_WIDTH 11 /* 65535 */
#define DIRECTLY_MON_WIDTH 10

#define APPL_NODE_STATUS_WIDTH 5

static int map_get(uint64_t up_map, int i)
{
	return (up_map & (1 << i)) >> i;
}

/* print the applied members, since we know the the members
 * are listed in ascending order, we print only the state
 */
static void link_mon_print_applied(uint16_t applied, uint64_t up_map)
{
	int i;
	char state;

	for (i = 0; i < applied; i++) {
		/* print the delimiter for every -n- entry */
		if (i && !(i % APPL_NODE_STATUS_WIDTH))
			printf(",");

		state = map_get(up_map, i) ? 'U' : 'D';
		printf("%c", state);
	}
}

/* print the non applied members, since we dont know
 * the members, we print them along with the state
 */
static void link_mon_print_non_applied(uint16_t applied, uint16_t member_cnt,
				       uint64_t up_map,  uint32_t *members)
{
	int i;
	char state;

	printf(" [");
	for (i = applied; i < member_cnt; i++) {
		char addr_str[16];

		/* print the delimiter for every entry */
		if (i != applied)
			printf(",");

		sprintf(addr_str, "%u.%u.%u:", tipc_zone(members[i]),
			tipc_cluster(members[i]), tipc_node(members[i]));
		state = map_get(up_map, i) ? 'U' : 'D';
		printf("%s%c", addr_str, state);
	}
	printf("]");
}

static void link_mon_print_peer_state(const uint32_t addr, const char *status,
				      const char *monitored,
				      const uint32_t dom_gen)
{
	char addr_str[16];

	sprintf(addr_str, "%u.%u.%u", tipc_zone(addr), tipc_cluster(addr),
		tipc_node(addr));

	printf("%-*s", MAX_NODE_WIDTH, addr_str);
	printf("%-*s", STATUS_WIDTH, status);
	printf("%-*s", DIRECTLY_MON_WIDTH, monitored);
	printf("%-*u", MAX_DOM_GEN_WIDTH, dom_gen);
}

static int link_mon_peer_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *attrs[TIPC_NLA_MON_PEER_MAX + 1] = {};
	struct nlattr *info[TIPC_NLA_MAX + 1] = {};
	uint16_t member_cnt;
	uint32_t applied;
	uint32_t dom_gen;
	uint64_t up_map;
	char status[16];
	char monitored[16];

	mnl_attr_parse(nlh, sizeof(*genl), parse_attrs, info);
	if (!info[TIPC_NLA_MON_PEER])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(info[TIPC_NLA_MON_PEER], parse_attrs, attrs);

	(attrs[TIPC_NLA_MON_PEER_LOCAL] || attrs[TIPC_NLA_MON_PEER_HEAD]) ?
		strcpy(monitored, "direct") :
		strcpy(monitored, "indirect");

	attrs[TIPC_NLA_MON_PEER_UP] ?
		strcpy(status, "up") :
		strcpy(status, "down");

	dom_gen = attrs[TIPC_NLA_MON_PEER_DOMGEN] ?
		mnl_attr_get_u32(attrs[TIPC_NLA_MON_PEER_DOMGEN]) : 0;

	link_mon_print_peer_state(mnl_attr_get_u32(attrs[TIPC_NLA_MON_PEER_ADDR]),
				  status, monitored, dom_gen);

	applied = mnl_attr_get_u32(attrs[TIPC_NLA_MON_PEER_APPLIED]);

	if (!applied)
		goto exit;

	up_map = mnl_attr_get_u64(attrs[TIPC_NLA_MON_PEER_UPMAP]);

	member_cnt = mnl_attr_get_payload_len(attrs[TIPC_NLA_MON_PEER_MEMBERS]);

	/* each tipc address occupies 4 bytes of payload, hence compensate it */
	member_cnt /= sizeof(uint32_t);

	link_mon_print_applied(applied, up_map);

	link_mon_print_non_applied(applied, member_cnt, up_map,
				   mnl_attr_get_payload(attrs[TIPC_NLA_MON_PEER_MEMBERS]));

exit:
	printf("\n");

	return MNL_CB_OK;
}

static int link_mon_peer_list(uint32_t mon_ref)
{
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlattr *nest;

	nlh = msg_init(buf, TIPC_NL_MON_PEER_GET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}

	nest = mnl_attr_nest_start(nlh, TIPC_NLA_MON);
	mnl_attr_put_u32(nlh, TIPC_NLA_MON_REF, mon_ref);
	mnl_attr_nest_end(nlh, nest);

	return msg_dumpit(nlh, link_mon_peer_list_cb, NULL);
}

static int link_mon_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *info[TIPC_NLA_MAX + 1] = {};
	struct nlattr *attrs[TIPC_NLA_MON_MAX + 1] = {};
	char *req_bearer = data;
	const char *bname;
	const char title[] =
	  "node          status monitored generation applied_node_status [non_applied_node:status]";

	mnl_attr_parse(nlh, sizeof(*genl), parse_attrs, info);
	if (!info[TIPC_NLA_MON])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(info[TIPC_NLA_MON], parse_attrs, attrs);

	bname = mnl_attr_get_str(attrs[TIPC_NLA_MON_BEARER_NAME]);

	if (*req_bearer && (strcmp(req_bearer, bname) != 0))
		return MNL_CB_OK;

	printf("\nbearer %s\n", bname);
	printf("%s\n", title);

	if (mnl_attr_get_u32(attrs[TIPC_NLA_MON_PEERCNT]))
		link_mon_peer_list(mnl_attr_get_u32(attrs[TIPC_NLA_MON_REF]));

	return MNL_CB_OK;
}

static void cmd_link_mon_list_help(struct cmdl *cmdl)
{
	fprintf(stderr, "Usage: %s monitor list [ media MEDIA ARGS...]\n\n",
		cmdl->argv[0]);
	print_bearer_media();
}

static void cmd_link_mon_list_l2_help(struct cmdl *cmdl, char *media)
{
	fprintf(stderr,
		"Usage: %s monitor list media %s device DEVICE [OPTIONS]\n",
		cmdl->argv[0], media);
}

static void cmd_link_mon_list_udp_help(struct cmdl *cmdl, char *media)
{
	fprintf(stderr,
		"Usage: %s monitor list media udp name NAME\n\n",
		cmdl->argv[0]);
}

static int cmd_link_mon_list(struct nlmsghdr *nlh, const struct cmd *cmd,
			     struct cmdl *cmdl, void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	char bname[TIPC_MAX_BEARER_NAME] = {0};
	struct opt opts[] = {
		{ "media",	OPT_KEYVAL,	NULL },
		{ "device",	OPT_KEYVAL,	NULL },
		{ "name",	OPT_KEYVAL,	NULL },
		{ NULL }
	};
	struct tipc_sup_media sup_media[] = {
		{ "udp",        "name",         cmd_link_mon_list_udp_help},
		{ "eth",        "device",       cmd_link_mon_list_l2_help },
		{ "ib",         "device",       cmd_link_mon_list_l2_help },
		{ NULL, },
	};

	int err;

	if (parse_opts(opts, cmdl) < 0)
		return -EINVAL;

	if (get_opt(opts, "media")) {
		err = cmd_get_unique_bearer_name(cmd, cmdl, opts, bname,
						 sup_media);
		if (err)
			return err;
	}

	if (help_flag) {
		cmd->help(cmdl);
		return -EINVAL;
	}

	nlh = msg_init(buf, TIPC_NL_MON_GET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}

	return msg_dumpit(nlh, link_mon_list_cb, bname);
}

static void cmd_link_mon_set_help(struct cmdl *cmdl)
{
	fprintf(stderr, "Usage: %s monitor set PPROPERTY\n\n"
		"PROPERTIES\n"
		" threshold SIZE	- Set monitor activation threshold\n",
		cmdl->argv[0]);
}

static int cmd_link_mon_set(struct nlmsghdr *nlh, const struct cmd *cmd,
			    struct cmdl *cmdl, void *data)
{
	const struct cmd cmds[] = {
		{ "threshold",	cmd_link_mon_set_prop,	NULL },
		{ NULL }
	};

	return run_cmd(nlh, cmd, cmds, cmdl, NULL);
}

static void cmd_link_mon_get_help(struct cmdl *cmdl)
{
	fprintf(stderr, "Usage: %s monitor get PPROPERTY\n\n"
		"PROPERTIES\n"
		" threshold	- Get monitor activation threshold\n",
		cmdl->argv[0]);
}

static int link_mon_get_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *info[TIPC_NLA_MAX + 1] = {};
	struct nlattr *attrs[TIPC_NLA_MON_MAX + 1] = {};

	mnl_attr_parse(nlh, sizeof(*genl), parse_attrs, info);
	if (!info[TIPC_NLA_MON])
		return MNL_CB_ERROR;

	mnl_attr_parse_nested(info[TIPC_NLA_MON], parse_attrs, attrs);
	if (!attrs[TIPC_NLA_MON_ACTIVATION_THRESHOLD])
		return MNL_CB_ERROR;

	printf("%u\n",
	       mnl_attr_get_u32(attrs[TIPC_NLA_MON_ACTIVATION_THRESHOLD]));

	return MNL_CB_OK;
}

static int cmd_link_mon_get_prop(struct nlmsghdr *nlh, const struct cmd *cmd,
				 struct cmdl *cmdl, void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];

	nlh = msg_init(buf, TIPC_NL_MON_GET);
	if (!nlh) {
		fprintf(stderr, "error, message initialisation failed\n");
		return -1;
	}

	return msg_doit(nlh,	link_mon_get_cb,	NULL);
}

static int cmd_link_mon_get(struct nlmsghdr *nlh, const struct cmd *cmd,
			    struct cmdl *cmdl, void *data)
{
	const struct cmd cmds[] = {
		{ "threshold",	cmd_link_mon_get_prop,	NULL},
		{ NULL }
	};

	return run_cmd(nlh, cmd, cmds, cmdl, NULL);
}

static void cmd_link_mon_help(struct cmdl *cmdl)
{
	fprintf(stderr,
		"Usage: %s montior COMMAND [ARGS] ...\n\n"
		"COMMANDS\n"
		" set			- Set monitor properties\n"
		" get			- Get monitor properties\n"
		" list			- List all cluster members\n"
		" summary		- Show local node monitor summary\n",
		cmdl->argv[0]);
}

static int cmd_link_mon(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl,
			void *data)
{
	const struct cmd cmds[] = {
		{ "set",	cmd_link_mon_set,	cmd_link_mon_set_help },
		{ "get",	cmd_link_mon_get,	cmd_link_mon_get_help },
		{ "list",	cmd_link_mon_list,	cmd_link_mon_list_help },
		{ "summary",	cmd_link_mon_summary,	NULL },
		{ NULL }
	};

	return run_cmd(nlh, cmd, cmds, cmdl, NULL);
}

void cmd_link_help(struct cmdl *cmdl)
{
	fprintf(stderr,
		"Usage: %s link COMMAND [ARGS] ...\n"
		"\n"
		"COMMANDS\n"
		" list                  - List links\n"
		" get                   - Get various link properties\n"
		" set                   - Set various link properties\n"
		" statistics            - Show or reset statistics\n"
		" monitor               - Show or set link supervision\n",
		cmdl->argv[0]);
}

int cmd_link(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl,
	     void *data)
{
	const struct cmd cmds[] = {
		{ "get",	cmd_link_get,	cmd_link_get_help },
		{ "list",	cmd_link_list,	NULL },
		{ "set",	cmd_link_set,	cmd_link_set_help },
		{ "statistics", cmd_link_stat,	cmd_link_stat_help },
		{ "monitor",	cmd_link_mon,	cmd_link_mon_help },
		{ NULL }
	};

	return run_cmd(nlh, cmd, cmds, cmdl, NULL);
}
