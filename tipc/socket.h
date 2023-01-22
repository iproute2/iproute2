/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * socket.h	TIPC socket functionality.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_SOCKET_H
#define _TIPC_SOCKET_H

extern int help_flag;

void cmd_socket_help(struct cmdl *cmdl);
int cmd_socket(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl,
		  void *data);

#endif
