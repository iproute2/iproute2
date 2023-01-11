/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * link.c	TIPC link functionality.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_LINK_H
#define _TIPC_LINK_H

extern int help_flag;

int cmd_link(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl,
	     void *data);
void cmd_link_help(struct cmdl *cmdl);

#endif
