/* $USAGI: $ */

/*
 * Copyright (C)2004 USAGI/WIDE Project
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * Authors:
 *	Masahide NAKAMURA @USAGI
 */

#ifndef __XFRM_H__
#define __XFRM_H__ 1

#include <stdio.h>
#include <sys/socket.h>
#include <linux/xfrm.h>
#include "utils.h"

#define XFRM_MAX_DEPTH 6

#define XFRMS_RTA(x)  ((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_usersa_info))))
#define XFRMS_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct xfrm_usersa_info))

#define XFRMP_RTA(x)  ((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_userpolicy_info))))
#define XFRMP_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct xfrm_userpoilcy_info))

struct xfrm_buffer {
	char *buf;
	int size;
	int offset;

	int nlmsg_count;
	struct rtnl_handle *rth;
};

struct xfrm_filter {
	int use;

	struct xfrm_usersa_info xsinfo;
	__u32 id_src_mask;
	__u32 id_dst_mask;
	__u32 id_proto_mask;
	__u32 id_spi_mask;
	__u32 mode_mask;
	__u32 reqid_mask;
	__u32 state_flags_mask;

	struct xfrm_userpolicy_info xpinfo;
	__u32 dir_mask;
	__u32 sel_src_mask;
	__u32 sel_dst_mask;
	__u32 sel_dev_mask;
	__u32 upspec_proto_mask;
	__u32 upspec_sport_mask;
	__u32 upspec_dport_mask;
	__u32 upspec_type_mask;
	__u32 upspec_code_mask;
	__u32 index_mask;
	__u32 action_mask;
	__u32 priority_mask;
};
#define XFRM_FILTER_MASK_FULL (~(__u32)0)

extern struct xfrm_filter filter;

int do_xfrm_state(int argc, char **argv);
int do_xfrm_policy(int argc, char **argv);

const char *strxf_flags(__u8 flags);
const char *strxf_share(__u8 share);
void xfrm_id_info_print(xfrm_address_t *saddr, struct xfrm_id *id,
			__u8 mode, __u32 reqid, __u16 family, FILE *fp,
			const char *prefix);
void xfrm_stats_print(struct xfrm_stats *s, FILE *fp, const char *prefix);
void xfrm_lifetime_print(struct xfrm_lifetime_cfg *cfg,
			 struct xfrm_lifetime_cur *cur,
			 FILE *fp, const char *prefix);
void xfrm_selector_print(struct xfrm_selector *sel, __u16 family,
			 FILE *fp, const char *prefix);
void xfrm_xfrma_print(struct rtattr *tb[], int ntb, __u16 family,
		      FILE *fp, const char *prefix);
int xfrm_id_parse(xfrm_address_t *saddr, struct xfrm_id *id, __u16 *family,
		    int *argcp, char ***argvp);
int xfrm_mode_parse(__u8 *mode, int *argcp, char ***argvp);
int xfrm_reqid_parse(__u32 *reqid, int *argcp, char ***argvp);
int xfrm_selector_parse(struct xfrm_selector *sel, int *argcp, char ***argvp);
int xfrm_lifetime_cfg_parse(struct xfrm_lifetime_cfg *lft,
			    int *argcp, char ***argvp);

#endif
