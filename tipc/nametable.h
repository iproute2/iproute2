/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * nametable.h	TIPC nametable functionality.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_NAMETABLE_H
#define _TIPC_NAMETABLE_H

extern int help_flag;

void cmd_nametable_help(struct cmdl *cmdl);
int cmd_nametable(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl,
		  void *data);

#endif
