/*
 * tc_bpf.h	BPF common code
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Daniel Borkmann <dborkman@redhat.com>
 *		Jiri Pirko <jiri@resnulli.us>
 */

#ifndef _TC_BPF_H_
#define _TC_BPF_H_ 1

#include <stdio.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int bpf_parse_string(char *arg, bool from_file, __u16 *bpf_len,
		     char **bpf_string, bool *need_release,
		     const char separator);
int bpf_parse_ops(int argc, char **argv, struct sock_filter *bpf_ops,
		  bool from_file);
void bpf_print_ops(FILE *f, struct rtattr *bpf_ops, __u16 len);

#endif
