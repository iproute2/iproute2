/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * msg.c	Messaging (netlink) helper functions.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include <libmnl/libmnl.h>

#include "mnl_utils.h"
#include "msg.h"

extern struct mnlu_gen_socket tipc_nlg;

int parse_attrs(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	tb[type] = attr;

	return MNL_CB_OK;
}

int msg_doit(struct nlmsghdr *nlh, mnl_cb_t callback, void *data)
{
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	return mnlu_gen_socket_sndrcv(&tipc_nlg, nlh, callback, data);
}

int msg_dumpit(struct nlmsghdr *nlh, mnl_cb_t callback, void *data)
{
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	return mnlu_gen_socket_sndrcv(&tipc_nlg, nlh, callback, data);
}

struct nlmsghdr *msg_init(int cmd)
{
	struct nlmsghdr *nlh;

	nlh = mnlu_gen_socket_cmd_prepare(&tipc_nlg, cmd, 0);

	return nlh;
}
