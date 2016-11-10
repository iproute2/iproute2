/*
 * bpf_util.h	BPF common code
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Daniel Borkmann <daniel@iogearbox.net>
 *		Jiri Pirko <jiri@resnulli.us>
 */

#ifndef __BPF_UTIL__
#define __BPF_UTIL__

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/elf-em.h>
#include <linux/if_alg.h>

#include "utils.h"
#include "bpf_scm.h"

#define BPF_ENV_UDS	"TC_BPF_UDS"
#define BPF_ENV_MNT	"TC_BPF_MNT"

#ifndef BPF_MAX_LOG
# define BPF_MAX_LOG	4096
#endif

#define BPF_DIR_GLOBALS	"globals"

#ifndef BPF_FS_MAGIC
# define BPF_FS_MAGIC	0xcafe4a11
#endif

#define BPF_DIR_MNT	"/sys/fs/bpf"

#ifndef TRACEFS_MAGIC
# define TRACEFS_MAGIC	0x74726163
#endif

#define TRACE_DIR_MNT	"/sys/kernel/tracing"

#ifndef AF_ALG
# define AF_ALG		38
#endif

#ifndef EM_BPF
# define EM_BPF		247
#endif

struct bpf_cfg_ops {
	void (*cbpf_cb)(void *nl, const struct sock_filter *ops, int ops_len);
	void (*ebpf_cb)(void *nl, int fd, const char *annotation);
};

struct bpf_cfg_in {
	const char *object;
	const char *section;
	const char *uds;
	int argc;
	char **argv;
	struct sock_filter *ops;
};

int bpf_parse_common(enum bpf_prog_type type, struct bpf_cfg_in *cfg,
		     const struct bpf_cfg_ops *ops, void *nl);

const char *bpf_prog_to_default_section(enum bpf_prog_type type);

int bpf_graft_map(const char *map_path, uint32_t *key, int argc, char **argv);
int bpf_trace_pipe(void);

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
#endif /* __BPF_UTIL__ */
