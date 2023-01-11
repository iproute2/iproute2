/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * peer.h	TIPC peer functionality.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_PEER_H
#define _TIPC_PEER_H

extern int help_flag;

int cmd_peer(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl,
	     void *data);
void cmd_peer_help(struct cmdl *cmdl);

#endif
