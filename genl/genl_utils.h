#ifndef _TC_UTIL_H_
#define _TC_UTIL_H_ 1

#include "linux/genetlink.h"

struct genl_util
{
	struct  genl_util *next;
	char	name[16];
	int	(*parse_genlopt)(struct genl_util *fu, int argc, char **argv);
	int	(*print_genlopt)(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);
};

extern int genl_ctrl_resolve_family(const char *family);

/* seems to have dissapeared from netlink.h */
static inline __u32 nl_mgrp(__u32 group)
{
	return group ? 1 << group : 0;
}

#endif
