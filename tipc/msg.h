/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * msg.h	Messaging (netlink) helper functions.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_MSG_H
#define _TIPC_MSG_H

struct nlmsghdr *msg_init(int cmd);
int msg_doit(struct nlmsghdr *nlh, mnl_cb_t callback, void *data);
int msg_dumpit(struct nlmsghdr *nlh, mnl_cb_t callback, void *data);
int parse_attrs(const struct nlattr *attr, void *data);

#endif
