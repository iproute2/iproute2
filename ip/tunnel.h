/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C)2006 USAGI/WIDE Project
 *
 * Author:
 *	Masahide NAKAMURA @USAGI
 */
#ifndef __TUNNEL_H__
#define __TUNNEL_H__ 1

#include <stdbool.h>
#include <linux/types.h>

struct rtattr;
struct ifinfomsg;

extern struct rtnl_handle rth;

struct tnl_print_nlmsg_info {
	const struct ifinfomsg *ifi;
	const void *p1;
	void *p2;

	void (*init)(const struct tnl_print_nlmsg_info *info);
	bool (*match)(const struct tnl_print_nlmsg_info *info);
	void (*print)(const void *t);
};

int do_tunnels_list(struct tnl_print_nlmsg_info *info);

const char *tnl_strproto(__u8 proto);

int tnl_get_ioctl(const char *basedev, void *p);
int tnl_add_ioctl(int cmd, const char *basedev, const char *name, void *p);
int tnl_del_ioctl(const char *basedev, const char *name, void *p);
int tnl_prl_ioctl(int cmd, const char *name, void *p);
int tnl_6rd_ioctl(int cmd, const char *name, void *p);
int tnl_ioctl_get_6rd(const char *name, void *p);
__be32 tnl_parse_key(const char *name, const char *key);
void tnl_print_encap(struct rtattr *tb[],
		     int encap_type, int encap_flags,
		     int encap_sport, int encap_dport);
void tnl_print_endpoint(const char *name,
			const struct rtattr *rta, int family);
void tnl_print_gre_flags(__u8 proto,
			 __be16 i_flags, __be16 o_flags,
			 __be32 i_key, __be32 o_key);

#endif
