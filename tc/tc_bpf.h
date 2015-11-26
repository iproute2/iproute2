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

#include <linux/netlink.h>
#include <linux/bpf.h>
#include <linux/magic.h>

#include "utils.h"
#include "bpf_scm.h"

enum {
	BPF_NLA_OPS_LEN = 0,
	BPF_NLA_OPS,
	BPF_NLA_FD,
	BPF_NLA_NAME,
	__BPF_NLA_MAX,
};

#define BPF_NLA_MAX	__BPF_NLA_MAX

#define BPF_ENV_UDS	"TC_BPF_UDS"
#define BPF_ENV_MNT	"TC_BPF_MNT"
#define BPF_ENV_NOLOG	"TC_BPF_NOLOG"

#ifndef BPF_FS_MAGIC
# define BPF_FS_MAGIC	0xcafe4a11
#endif

#define BPF_DIR_MNT	"/sys/fs/bpf"

#define BPF_DIR_TC	"tc"
#define BPF_DIR_GLOBALS	"globals"

#ifndef TRACEFS_MAGIC
# define TRACEFS_MAGIC	0x74726163
#endif

#define TRACE_DIR_MNT	"/sys/kernel/tracing"

int bpf_trace_pipe(void);
const char *bpf_default_section(const enum bpf_prog_type type);

int bpf_parse_common(int *ptr_argc, char ***ptr_argv, const int *nla_tbl,
		     enum bpf_prog_type type, const char **ptr_object,
		     const char **ptr_uds_name, struct nlmsghdr *n);
int bpf_graft_map(const char *map_path, uint32_t *key, int argc, char **argv);

void bpf_print_ops(FILE *f, struct rtattr *bpf_ops, __u16 len);

#ifdef HAVE_ELF
int bpf_send_map_fds(const char *path, const char *obj);
int bpf_recv_map_fds(const char *path, int *fds, struct bpf_map_aux *aux,
		     unsigned int entries);
#else
static inline int bpf_send_map_fds(const char *path, const char *obj)
{
	return 0;
}

static inline int bpf_recv_map_fds(const char *path, int *fds,
				   struct bpf_map_aux *aux,
				   unsigned int entries)
{
	return -1;
}
#endif /* HAVE_ELF */
#endif /* _TC_BPF_H_ */
