/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bearer.h	TIPC bearer functionality.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_BEARER_H
#define _TIPC_BEARER_H

#include "cmdl.h"

extern int help_flag;

int cmd_bearer(struct nlmsghdr *nlh, const struct cmd *cmd, struct cmdl *cmdl, void *data);
void cmd_bearer_help(struct cmdl *cmdl);

void print_bearer_media(void);
int cmd_get_unique_bearer_name(const struct cmd *cmd, struct cmdl *cmdl,
			       struct opt *opts, char *bname,
			       const struct tipc_sup_media *sup_media);
#endif
