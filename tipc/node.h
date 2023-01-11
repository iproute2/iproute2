/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * node.h	TIPC node functionality.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_NODE_H
#define _TIPC_NODE_H

extern int help_flag;

int cmd_node(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl,
	     void *data);
void cmd_node_help(struct cmdl *cmdl);

#endif
