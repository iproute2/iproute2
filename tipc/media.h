/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * media.h	TIPC link functionality.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_MEDIA_H
#define _TIPC_MEDIA_H

extern int help_flag;

int cmd_media(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl,
	     void *data);
void cmd_media_help(struct cmdl *cmdl);

#endif
