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

#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>

#include "utils.h"

/* Note:
 *
 * Below ELF section names and bpf_elf_map structure definition
 * are not (!) kernel ABI. It's rather a "contract" between the
 * application and the BPF loader in tc. For compatibility, the
 * section names should stay as-is. Introduction of aliases, if
 * needed, are a possibility, though.
 */

/* ELF section names, etc */
#define ELF_SECTION_LICENSE	"license"
#define ELF_SECTION_MAPS	"maps"
#define ELF_SECTION_CLASSIFIER	"classifier"
#define ELF_SECTION_ACTION	"action"

#define ELF_MAX_MAPS		64
#define ELF_MAX_LICENSE_LEN	128

/* ELF map definition */
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
};

int bpf_parse_string(char *arg, bool from_file, __u16 *bpf_len,
		     char **bpf_string, bool *need_release,
		     const char separator);
int bpf_parse_ops(int argc, char **argv, struct sock_filter *bpf_ops,
		  bool from_file);
void bpf_print_ops(FILE *f, struct rtattr *bpf_ops, __u16 len);

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

#ifdef HAVE_ELF
int bpf_open_object(const char *path, enum bpf_prog_type type);

static inline int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifdef __NR_bpf
	return syscall(__NR_bpf, cmd, attr, size);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#else
static inline int bpf_open_object(const char *path, enum bpf_prog_type type)
{
	errno = ENOSYS;
	return -1;
}
#endif /* HAVE_ELF */
#endif /* _TC_BPF_H_ */
