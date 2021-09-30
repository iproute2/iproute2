/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NH_COMMON_H__
#define __NH_COMMON_H__ 1

struct nha_res_grp {
	__u16			buckets;
	__u32			idle_timer;
	__u32			unbalanced_timer;
	__u64			unbalanced_time;
};

#endif /* __NH_COMMON_H__ */
