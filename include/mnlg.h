/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   mnlg.h	Generic Netlink helpers for libmnl
 *
 * Authors:     Jiri Pirko <jiri@mellanox.com>
 */

#ifndef _MNLG_H_
#define _MNLG_H_

#include <libmnl/libmnl.h>

struct mnlu_gen_socket;

int mnlg_socket_send(struct mnlu_gen_socket *nlg, const struct nlmsghdr *nlh);
int mnlg_socket_group_add(struct mnlu_gen_socket *nlg, const char *group_name);
int mnlg_socket_get_fd(struct mnlu_gen_socket *nlg);

#endif /* _MNLG_H_ */
