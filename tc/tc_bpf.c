/*
 * tc_bpf.c	BPF common code
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Daniel Borkmann <dborkman@redhat.com>
 *		Jiri Pirko <jiri@resnulli.us>
 *		Alexei Starovoitov <ast@plumgrid.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#ifdef HAVE_ELF
#include <libelf.h>
#include <gelf.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/resource.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_alg.h>

#include <arpa/inet.h>

#include "utils.h"

#include "bpf_elf.h"
#include "bpf_scm.h"

#include "tc_util.h"
#include "tc_bpf.h"

#ifdef HAVE_ELF
static int bpf_obj_open(const char *path, enum bpf_prog_type type,
			const char *sec, bool verbose);
#else
static int bpf_obj_open(const char *path, enum bpf_prog_type type,
			const char *sec, bool verbose)
{
	fprintf(stderr, "No ELF library support compiled in.\n");
	errno = ENOSYS;
	return -1;
}
#endif

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifdef __NR_bpf
	return syscall(__NR_bpf, cmd, attr, size);
#else
	fprintf(stderr, "No bpf syscall, kernel headers too old?\n");
	errno = ENOSYS;
	return -1;
#endif
}

static int bpf_map_update(int fd, const void *key, const void *value,
			  uint64_t flags)
{
	union bpf_attr attr = {
		.map_fd		= fd,
		.key		= bpf_ptr_to_u64(key),
		.value		= bpf_ptr_to_u64(value),
		.flags		= flags,
	};

	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_parse_string(char *arg, bool from_file, __u16 *bpf_len,
			    char **bpf_string, bool *need_release,
			    const char separator)
{
	char sp;

	if (from_file) {
		size_t tmp_len, op_len = sizeof("65535 255 255 4294967295,");
		char *tmp_string;
		FILE *fp;

		tmp_len = sizeof("4096,") + BPF_MAXINSNS * op_len;
		tmp_string = malloc(tmp_len);
		if (tmp_string == NULL)
			return -ENOMEM;

		memset(tmp_string, 0, tmp_len);

		fp = fopen(arg, "r");
		if (fp == NULL) {
			perror("Cannot fopen");
			free(tmp_string);
			return -ENOENT;
		}

		if (!fgets(tmp_string, tmp_len, fp)) {
			free(tmp_string);
			fclose(fp);
			return -EIO;
		}

		fclose(fp);

		*need_release = true;
		*bpf_string = tmp_string;
	} else {
		*need_release = false;
		*bpf_string = arg;
	}

	if (sscanf(*bpf_string, "%hu%c", bpf_len, &sp) != 2 ||
	    sp != separator) {
		if (*need_release)
			free(*bpf_string);
		return -EINVAL;
	}

	return 0;
}

static int bpf_ops_parse(int argc, char **argv, struct sock_filter *bpf_ops,
			 bool from_file)
{
	char *bpf_string, *token, separator = ',';
	int ret = 0, i = 0;
	bool need_release;
	__u16 bpf_len = 0;

	if (argc < 1)
		return -EINVAL;
	if (bpf_parse_string(argv[0], from_file, &bpf_len, &bpf_string,
			     &need_release, separator))
		return -EINVAL;
	if (bpf_len == 0 || bpf_len > BPF_MAXINSNS) {
		ret = -EINVAL;
		goto out;
	}

	token = bpf_string;
	while ((token = strchr(token, separator)) && (++token)[0]) {
		if (i >= bpf_len) {
			fprintf(stderr, "Real program length exceeds encoded "
				"length parameter!\n");
			ret = -EINVAL;
			goto out;
		}

		if (sscanf(token, "%hu %hhu %hhu %u,",
			   &bpf_ops[i].code, &bpf_ops[i].jt,
			   &bpf_ops[i].jf, &bpf_ops[i].k) != 4) {
			fprintf(stderr, "Error at instruction %d!\n", i);
			ret = -EINVAL;
			goto out;
		}

		i++;
	}

	if (i != bpf_len) {
		fprintf(stderr, "Parsed program length is less than encoded"
			"length parameter!\n");
		ret = -EINVAL;
		goto out;
	}
	ret = bpf_len;
out:
	if (need_release)
		free(bpf_string);

	return ret;
}

void bpf_print_ops(FILE *f, struct rtattr *bpf_ops, __u16 len)
{
	struct sock_filter *ops = (struct sock_filter *) RTA_DATA(bpf_ops);
	int i;

	if (len == 0)
		return;

	fprintf(f, "bytecode \'%u,", len);

	for (i = 0; i < len - 1; i++)
		fprintf(f, "%hu %hhu %hhu %u,", ops[i].code, ops[i].jt,
			ops[i].jf, ops[i].k);

	fprintf(f, "%hu %hhu %hhu %u\'", ops[i].code, ops[i].jt,
		ops[i].jf, ops[i].k);
}

static int bpf_map_selfcheck_pinned(int fd, const struct bpf_elf_map *map,
				    int length)
{
	char file[PATH_MAX], buff[4096];
	struct bpf_elf_map tmp, zero;
	unsigned int val;
	FILE *fp;

	snprintf(file, sizeof(file), "/proc/%d/fdinfo/%d", getpid(), fd);

	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "No procfs support?!\n");
		return -EIO;
	}

	memset(&tmp, 0, sizeof(tmp));
	while (fgets(buff, sizeof(buff), fp)) {
		if (sscanf(buff, "map_type:\t%u", &val) == 1)
			tmp.type = val;
		else if (sscanf(buff, "key_size:\t%u", &val) == 1)
			tmp.size_key = val;
		else if (sscanf(buff, "value_size:\t%u", &val) == 1)
			tmp.size_value = val;
		else if (sscanf(buff, "max_entries:\t%u", &val) == 1)
			tmp.max_elem = val;
	}

	fclose(fp);

	if (!memcmp(&tmp, map, length)) {
		return 0;
	} else {
		memset(&zero, 0, sizeof(zero));
		/* If kernel doesn't have eBPF-related fdinfo, we cannot do much,
		 * so just accept it. We know we do have an eBPF fd and in this
		 * case, everything is 0. It is guaranteed that no such map exists
		 * since map type of 0 is unloadable BPF_MAP_TYPE_UNSPEC.
		 */
		if (!memcmp(&tmp, &zero, length))
			return 0;

		fprintf(stderr, "Map specs from pinned file differ!\n");
		return -EINVAL;
	}
}

static int bpf_mnt_fs(const char *target)
{
	bool bind_done = false;

	while (mount("", target, "none", MS_PRIVATE | MS_REC, NULL)) {
		if (errno != EINVAL || bind_done) {
			fprintf(stderr, "mount --make-private %s failed: %s\n",
				target,	strerror(errno));
			return -1;
		}

		if (mount(target, target, "none", MS_BIND, NULL)) {
			fprintf(stderr, "mount --bind %s %s failed: %s\n",
				target,	target, strerror(errno));
			return -1;
		}

		bind_done = true;
	}

	if (mount("bpf", target, "bpf", 0, NULL)) {
		fprintf(stderr, "mount -t bpf bpf %s failed: %s\n",
			target,	strerror(errno));
		return -1;
	}

	return 0;
}

static int bpf_valid_mntpt(const char *mnt, unsigned long magic)
{
	struct statfs st_fs;

	if (statfs(mnt, &st_fs) < 0)
		return -ENOENT;
	if ((unsigned long)st_fs.f_type != magic)
		return -ENOENT;

	return 0;
}

static const char *bpf_find_mntpt(const char *fstype, unsigned long magic,
				  char *mnt, int len,
				  const char * const *known_mnts)
{
	const char * const *ptr;
	char type[100];
	FILE *fp;

	if (known_mnts) {
		ptr = known_mnts;
		while (*ptr) {
			if (bpf_valid_mntpt(*ptr, magic) == 0) {
				strncpy(mnt, *ptr, len - 1);
				mnt[len - 1] = 0;
				return mnt;
			}
			ptr++;
		}
	}

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL || len != PATH_MAX)
		return NULL;

	while (fscanf(fp, "%*s %" textify(PATH_MAX) "s %99s %*s %*d %*d\n",
		      mnt, type) == 2) {
		if (strcmp(type, fstype) == 0)
			break;
	}

	fclose(fp);
	if (strcmp(type, fstype) != 0)
		return NULL;

	return mnt;
}

int bpf_trace_pipe(void)
{
	char tracefs_mnt[PATH_MAX] = TRACE_DIR_MNT;
	static const char * const tracefs_known_mnts[] = {
		TRACE_DIR_MNT,
		"/sys/kernel/debug/tracing",
		"/tracing",
		"/trace",
		0,
	};
	char tpipe[PATH_MAX];
	const char *mnt;
	int fd;

	mnt = bpf_find_mntpt("tracefs", TRACEFS_MAGIC, tracefs_mnt,
			     sizeof(tracefs_mnt), tracefs_known_mnts);
	if (!mnt) {
		fprintf(stderr, "tracefs not mounted?\n");
		return -1;
	}

	snprintf(tpipe, sizeof(tpipe), "%s/trace_pipe", mnt);

	fd = open(tpipe, O_RDONLY);
	if (fd < 0)
		return -1;

	fprintf(stderr, "Running! Hang up with ^C!\n\n");
	while (1) {
		static char buff[4096];
		ssize_t ret;

		ret = read(fd, buff, sizeof(buff) - 1);
		if (ret > 0) {
			write(2, buff, ret);
			fflush(stderr);
		}
	}

	return 0;
}

static const char *bpf_get_tc_dir(void)
{
	static bool bpf_mnt_cached = false;
	static char bpf_tc_dir[PATH_MAX];
	static const char *mnt;
	static const char * const bpf_known_mnts[] = {
		BPF_DIR_MNT,
		0,
	};
	char bpf_mnt[PATH_MAX] = BPF_DIR_MNT;
	char bpf_glo_dir[PATH_MAX];
	int ret;

	if (bpf_mnt_cached)
		goto done;

	mnt = bpf_find_mntpt("bpf", BPF_FS_MAGIC, bpf_mnt, sizeof(bpf_mnt),
			     bpf_known_mnts);
	if (!mnt) {
		mnt = getenv(BPF_ENV_MNT);
		if (!mnt)
			mnt = BPF_DIR_MNT;
		ret = bpf_mnt_fs(mnt);
		if (ret) {
			mnt = NULL;
			goto out;
		}
	}

	snprintf(bpf_tc_dir, sizeof(bpf_tc_dir), "%s/%s", mnt, BPF_DIR_TC);
	ret = mkdir(bpf_tc_dir, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", bpf_tc_dir,
			strerror(errno));
		mnt = NULL;
		goto out;
	}

	snprintf(bpf_glo_dir, sizeof(bpf_glo_dir), "%s/%s",
		 bpf_tc_dir, BPF_DIR_GLOBALS);
	ret = mkdir(bpf_glo_dir, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", bpf_glo_dir,
			strerror(errno));
		mnt = NULL;
		goto out;
	}

	mnt = bpf_tc_dir;
out:
	bpf_mnt_cached = true;
done:
	return mnt;
}

static int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr;
	char tmp[PATH_MAX];

	if (strlen(pathname) > 2 && pathname[0] == 'm' &&
	    pathname[1] == ':' && bpf_get_tc_dir()) {
		snprintf(tmp, sizeof(tmp), "%s/%s",
			 bpf_get_tc_dir(), pathname + 2);
		pathname = tmp;
	}

	memset(&attr, 0, sizeof(attr));
	attr.pathname = bpf_ptr_to_u64(pathname);

	return bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

const char *bpf_default_section(const enum bpf_prog_type type)
{
	switch (type) {
	case BPF_PROG_TYPE_SCHED_CLS:
		return ELF_SECTION_CLASSIFIER;
	case BPF_PROG_TYPE_SCHED_ACT:
		return ELF_SECTION_ACTION;
	default:
		return NULL;
	}
}

enum bpf_mode {
	CBPF_BYTECODE = 0,
	CBPF_FILE,
	EBPF_OBJECT,
	EBPF_PINNED,
	__BPF_MODE_MAX,
#define BPF_MODE_MAX	__BPF_MODE_MAX
};

static int bpf_parse(int *ptr_argc, char ***ptr_argv, const bool *opt_tbl,
		     enum bpf_prog_type *type, enum bpf_mode *mode,
		     const char **ptr_object, const char **ptr_section,
		     const char **ptr_uds_name, struct sock_filter *opcodes)
{
	const char *file, *section, *uds_name;
	bool verbose = false;
	int ret, argc;
	char **argv;

	argv = *ptr_argv;
	argc = *ptr_argc;

	if (opt_tbl[CBPF_BYTECODE] &&
	    (matches(*argv, "bytecode") == 0 ||
	     strcmp(*argv, "bc") == 0)) {
		*mode = CBPF_BYTECODE;
	} else if (opt_tbl[CBPF_FILE] &&
		   (matches(*argv, "bytecode-file") == 0 ||
		    strcmp(*argv, "bcf") == 0)) {
		*mode = CBPF_FILE;
	} else if (opt_tbl[EBPF_OBJECT] &&
		   (matches(*argv, "object-file") == 0 ||
		    strcmp(*argv, "obj") == 0)) {
		*mode = EBPF_OBJECT;
	} else if (opt_tbl[EBPF_PINNED] &&
		   (matches(*argv, "object-pinned") == 0 ||
		    matches(*argv, "pinned") == 0 ||
		    matches(*argv, "fd") == 0)) {
		*mode = EBPF_PINNED;
	} else {
		fprintf(stderr, "What mode is \"%s\"?\n", *argv);
		return -1;
	}

	NEXT_ARG();
	file = section = uds_name = NULL;
	if (*mode == EBPF_OBJECT || *mode == EBPF_PINNED) {
		file = *argv;
		NEXT_ARG_FWD();

		if (*type == BPF_PROG_TYPE_UNSPEC) {
			if (argc > 0 && matches(*argv, "type") == 0) {
				NEXT_ARG();
				if (matches(*argv, "cls") == 0) {
					*type = BPF_PROG_TYPE_SCHED_CLS;
				} else if (matches(*argv, "act") == 0) {
					*type = BPF_PROG_TYPE_SCHED_ACT;
				} else {
					fprintf(stderr, "What type is \"%s\"?\n",
						*argv);
					return -1;
				}
				NEXT_ARG_FWD();
			} else {
				*type = BPF_PROG_TYPE_SCHED_CLS;
			}
		}

		section = bpf_default_section(*type);
		if (argc > 0 && matches(*argv, "section") == 0) {
			NEXT_ARG();
			section = *argv;
			NEXT_ARG_FWD();
		}

		uds_name = getenv(BPF_ENV_UDS);
		if (argc > 0 && !uds_name &&
		    matches(*argv, "export") == 0) {
			NEXT_ARG();
			uds_name = *argv;
			NEXT_ARG_FWD();
		}

		if (argc > 0 && matches(*argv, "verbose") == 0) {
			verbose = true;
			NEXT_ARG_FWD();
		}

		PREV_ARG();
	}

	if (*mode == CBPF_BYTECODE || *mode == CBPF_FILE)
		ret = bpf_ops_parse(argc, argv, opcodes, *mode == CBPF_FILE);
	else if (*mode == EBPF_OBJECT)
		ret = bpf_obj_open(file, *type, section, verbose);
	else if (*mode == EBPF_PINNED)
		ret = bpf_obj_get(file);
	else
		return -1;

	if (ptr_object)
		*ptr_object = file;
	if (ptr_section)
		*ptr_section = section;
	if (ptr_uds_name)
		*ptr_uds_name = uds_name;

	*ptr_argc = argc;
	*ptr_argv = argv;

	return ret;
}

int bpf_parse_common(int *ptr_argc, char ***ptr_argv, const int *nla_tbl,
		     enum bpf_prog_type type, const char **ptr_object,
		     const char **ptr_uds_name, struct nlmsghdr *n)
{
	struct sock_filter opcodes[BPF_MAXINSNS];
	const bool opt_tbl[BPF_MODE_MAX] = {
		[CBPF_BYTECODE]	= true,
		[CBPF_FILE]	= true,
		[EBPF_OBJECT]	= true,
		[EBPF_PINNED]	= true,
	};
	char annotation[256];
	const char *section;
	enum bpf_mode mode;
	int ret;

	ret = bpf_parse(ptr_argc, ptr_argv, opt_tbl, &type, &mode,
			ptr_object, &section, ptr_uds_name, opcodes);
	if (ret < 0)
		return ret;

	if (mode == CBPF_BYTECODE || mode == CBPF_FILE) {
		addattr16(n, MAX_MSG, nla_tbl[BPF_NLA_OPS_LEN], ret);
		addattr_l(n, MAX_MSG, nla_tbl[BPF_NLA_OPS], opcodes,
			  ret * sizeof(struct sock_filter));
	}

	if (mode == EBPF_OBJECT || mode == EBPF_PINNED) {
		snprintf(annotation, sizeof(annotation), "%s:[%s]",
			 basename(*ptr_object), mode == EBPF_PINNED ?
			 "*fsobj" : section);

		addattr32(n, MAX_MSG, nla_tbl[BPF_NLA_FD], ret);
		addattrstrz(n, MAX_MSG, nla_tbl[BPF_NLA_NAME], annotation);
	}

	return 0;
}

int bpf_graft_map(const char *map_path, uint32_t *key, int argc, char **argv)
{
	enum bpf_prog_type type = BPF_PROG_TYPE_UNSPEC;
	const bool opt_tbl[BPF_MODE_MAX] = {
		[CBPF_BYTECODE]	= false,
		[CBPF_FILE]	= false,
		[EBPF_OBJECT]	= true,
		[EBPF_PINNED]	= true,
	};
	const struct bpf_elf_map test = {
		.type		= BPF_MAP_TYPE_PROG_ARRAY,
		.size_key	= sizeof(int),
		.size_value	= sizeof(int),
	};
	int ret, prog_fd, map_fd;
	const char *section;
	enum bpf_mode mode;
	uint32_t map_key;

	prog_fd = bpf_parse(&argc, &argv, opt_tbl, &type, &mode,
			    NULL, &section, NULL, NULL);
	if (prog_fd < 0)
		return prog_fd;
	if (key) {
		map_key = *key;
	} else {
		ret = sscanf(section, "%*i/%i", &map_key);
		if (ret != 1) {
			fprintf(stderr, "Couldn\'t infer map key from section "
				"name! Please provide \'key\' argument!\n");
			ret = -EINVAL;
			goto out_prog;
		}
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "Couldn\'t retrieve pinned map \'%s\': %s\n",
			map_path, strerror(errno));
		ret = map_fd;
		goto out_prog;
	}

	ret = bpf_map_selfcheck_pinned(map_fd, &test,
				       offsetof(struct bpf_elf_map, max_elem));
	if (ret < 0) {
		fprintf(stderr, "Map \'%s\' self-check failed!\n", map_path);
		goto out_map;
	}

	ret = bpf_map_update(map_fd, &map_key, &prog_fd, BPF_ANY);
	if (ret < 0)
		fprintf(stderr, "Map update failed: %s\n", strerror(errno));
out_map:
	close(map_fd);
out_prog:
	close(prog_fd);
	return ret;
}

#ifdef HAVE_ELF
struct bpf_elf_prog {
	enum bpf_prog_type	type;
	const struct bpf_insn	*insns;
	size_t			size;
	const char		*license;
};

struct bpf_hash_entry {
	unsigned int		pinning;
	const char		*subpath;
	struct bpf_hash_entry	*next;
};

struct bpf_elf_ctx {
	Elf			*elf_fd;
	GElf_Ehdr		elf_hdr;
	Elf_Data		*sym_tab;
	Elf_Data		*str_tab;
	int			obj_fd;
	int			map_fds[ELF_MAX_MAPS];
	struct bpf_elf_map	maps[ELF_MAX_MAPS];
	int			sym_num;
	int			map_num;
	bool			*sec_done;
	int			sec_maps;
	char			license[ELF_MAX_LICENSE_LEN];
	enum bpf_prog_type	type;
	bool			verbose;
	struct bpf_elf_st	stat;
	struct bpf_hash_entry	*ht[256];
};

struct bpf_elf_sec_data {
	GElf_Shdr		sec_hdr;
	Elf_Data		*sec_data;
	const char		*sec_name;
};

struct bpf_map_data {
	int			*fds;
	const char		*obj;
	struct bpf_elf_st	*st;
	struct bpf_elf_map	*ent;
};

/* If we provide a small buffer with log level enabled, the kernel
 * could fail program load as no buffer space is available for the
 * log and thus verifier fails. In case something doesn't pass the
 * verifier we still want to hand something descriptive to the user.
 */
static char bpf_log_buf[65536];

static __check_format_string(1, 2) void bpf_dump_error(const char *format, ...)
{
	va_list vl;

	va_start(vl, format);
	vfprintf(stderr, format, vl);
	va_end(vl);

	if (bpf_log_buf[0]) {
		fprintf(stderr, "%s\n", bpf_log_buf);
		memset(bpf_log_buf, 0, sizeof(bpf_log_buf));
	}
}

static int bpf_map_create(enum bpf_map_type type, unsigned int size_key,
			  unsigned int size_value, unsigned int max_elem)
{
	union bpf_attr attr = {
		.map_type	= type,
		.key_size	= size_key,
		.value_size	= size_value,
		.max_entries	= max_elem,
	};

	return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns,
			 size_t size, const char *license)
{
	union bpf_attr attr = {
		.prog_type	= type,
		.insns		= bpf_ptr_to_u64(insns),
		.insn_cnt	= size / sizeof(struct bpf_insn),
		.license	= bpf_ptr_to_u64(license),
		.log_buf	= bpf_ptr_to_u64(bpf_log_buf),
		.log_size	= sizeof(bpf_log_buf),
		.log_level	= 1,
	};

	if (getenv(BPF_ENV_NOLOG)) {
		attr.log_buf	= 0;
		attr.log_size	= 0;
		attr.log_level	= 0;
	}

	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_obj_pin(int fd, const char *pathname)
{
	union bpf_attr attr = {
		.pathname	= bpf_ptr_to_u64(pathname),
		.bpf_fd		= fd,
	};

	return bpf(BPF_OBJ_PIN, &attr, sizeof(attr));
}

static int bpf_obj_hash(const char *object, uint8_t *out, size_t len)
{
	struct sockaddr_alg alg = {
		.salg_family	= AF_ALG,
		.salg_type	= "hash",
		.salg_name	= "sha1",
	};
	int ret, cfd, ofd, ffd;
	struct stat stbuff;
	ssize_t size;

	if (!object || len != 20)
		return -EINVAL;

	cfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (cfd < 0) {
		fprintf(stderr, "Cannot get AF_ALG socket: %s\n",
			strerror(errno));
		return cfd;
	}

	ret = bind(cfd, (struct sockaddr *)&alg, sizeof(alg));
	if (ret < 0) {
		fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
		goto out_cfd;
	}

	ofd = accept(cfd, NULL, 0);
	if (ofd < 0) {
		fprintf(stderr, "Error accepting socket: %s\n",
			strerror(errno));
		ret = ofd;
		goto out_cfd;
	}

	ffd = open(object, O_RDONLY);
	if (ffd < 0) {
		fprintf(stderr, "Error opening object %s: %s\n",
			object, strerror(errno));
		ret = ffd;
		goto out_ofd;
	}

        ret = fstat(ffd, &stbuff);
	if (ret < 0) {
		fprintf(stderr, "Error doing fstat: %s\n",
			strerror(errno));
		goto out_ffd;
	}

	size = sendfile(ofd, ffd, NULL, stbuff.st_size);
	if (size != stbuff.st_size) {
		fprintf(stderr, "Error from sendfile (%zd vs %zu bytes): %s\n",
			size, stbuff.st_size, strerror(errno));
		ret = -1;
		goto out_ffd;
	}

	size = read(ofd, out, len);
	if (size != len) {
		fprintf(stderr, "Error from read (%zd vs %zu bytes): %s\n",
			size, len, strerror(errno));
		ret = -1;
	} else {
		ret = 0;
	}
out_ffd:
	close(ffd);
out_ofd:
	close(ofd);
out_cfd:
	close(cfd);
	return ret;
}

static const char *bpf_get_obj_uid(const char *pathname)
{
	static bool bpf_uid_cached = false;
	static char bpf_uid[64];
	uint8_t tmp[20];
	int ret;

	if (bpf_uid_cached)
		goto done;

	ret = bpf_obj_hash(pathname, tmp, sizeof(tmp));
	if (ret) {
		fprintf(stderr, "Object hashing failed!\n");
		return NULL;
	}

	hexstring_n2a(tmp, sizeof(tmp), bpf_uid, sizeof(bpf_uid));
	bpf_uid_cached = true;
done:
	return bpf_uid;
}

static int bpf_init_env(const char *pathname)
{
	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	/* Don't bother in case we fail! */
	setrlimit(RLIMIT_MEMLOCK, &limit);

	if (!bpf_get_tc_dir()) {
		fprintf(stderr, "Continuing without mounted eBPF fs. "
			"Too old kernel?\n");
		return 0;
	}

	if (!bpf_get_obj_uid(pathname))
		return -1;

	return 0;
}

static const char *bpf_custom_pinning(const struct bpf_elf_ctx *ctx,
				      uint32_t pinning)
{
	struct bpf_hash_entry *entry;

	entry = ctx->ht[pinning & (ARRAY_SIZE(ctx->ht) - 1)];
	while (entry && entry->pinning != pinning)
		entry = entry->next;

	return entry ? entry->subpath : NULL;
}

static bool bpf_no_pinning(const struct bpf_elf_ctx *ctx,
			   uint32_t pinning)
{
	switch (pinning) {
	case PIN_OBJECT_NS:
	case PIN_GLOBAL_NS:
		return false;
	case PIN_NONE:
		return true;
	default:
		return !bpf_custom_pinning(ctx, pinning);
	}
}

static void bpf_make_pathname(char *pathname, size_t len, const char *name,
			      const struct bpf_elf_ctx *ctx, uint32_t pinning)
{
	switch (pinning) {
	case PIN_OBJECT_NS:
		snprintf(pathname, len, "%s/%s/%s", bpf_get_tc_dir(),
			 bpf_get_obj_uid(NULL), name);
		break;
	case PIN_GLOBAL_NS:
		snprintf(pathname, len, "%s/%s/%s", bpf_get_tc_dir(),
			 BPF_DIR_GLOBALS, name);
		break;
	default:
		snprintf(pathname, len, "%s/../%s/%s", bpf_get_tc_dir(),
			 bpf_custom_pinning(ctx, pinning), name);
		break;
	}
}

static int bpf_probe_pinned(const char *name, const struct bpf_elf_ctx *ctx,
			    uint32_t pinning)
{
	char pathname[PATH_MAX];

	if (bpf_no_pinning(ctx, pinning) || !bpf_get_tc_dir())
		return 0;

	bpf_make_pathname(pathname, sizeof(pathname), name, ctx, pinning);
	return bpf_obj_get(pathname);
}

static int bpf_make_obj_path(void)
{
	char tmp[PATH_MAX];
	int ret;

	snprintf(tmp, sizeof(tmp), "%s/%s", bpf_get_tc_dir(),
		 bpf_get_obj_uid(NULL));

	ret = mkdir(tmp, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", tmp, strerror(errno));
		return ret;
	}

	return 0;
}

static int bpf_make_custom_path(const char *todo)
{
	char tmp[PATH_MAX], rem[PATH_MAX], *sub;
	int ret;

	snprintf(tmp, sizeof(tmp), "%s/../", bpf_get_tc_dir());
	snprintf(rem, sizeof(rem), "%s/", todo);
	sub = strtok(rem, "/");

	while (sub) {
		if (strlen(tmp) + strlen(sub) + 2 > PATH_MAX)
			return -EINVAL;

		strcat(tmp, sub);
		strcat(tmp, "/");

		ret = mkdir(tmp, S_IRWXU);
		if (ret && errno != EEXIST) {
			fprintf(stderr, "mkdir %s failed: %s\n", tmp,
				strerror(errno));
			return ret;
		}

		sub = strtok(NULL, "/");
	}

	return 0;
}

static int bpf_place_pinned(int fd, const char *name,
			    const struct bpf_elf_ctx *ctx, uint32_t pinning)
{
	char pathname[PATH_MAX];
	const char *tmp;
	int ret = 0;

	if (bpf_no_pinning(ctx, pinning) || !bpf_get_tc_dir())
		return 0;

	if (pinning == PIN_OBJECT_NS)
		ret = bpf_make_obj_path();
	else if ((tmp = bpf_custom_pinning(ctx, pinning)))
		ret = bpf_make_custom_path(tmp);
	if (ret < 0)
		return ret;

	bpf_make_pathname(pathname, sizeof(pathname), name, ctx, pinning);
	return bpf_obj_pin(fd, pathname);
}

static int bpf_prog_attach(const char *section,
			   const struct bpf_elf_prog *prog, bool verbose)
{
	int fd;

	/* We can add pinning here later as well, same as bpf_map_attach(). */
	errno = 0;
	fd = bpf_prog_load(prog->type, prog->insns, prog->size,
			   prog->license);
	if (fd < 0 || verbose) {
		bpf_dump_error("Prog section \'%s\' (type:%u insns:%zu "
			       "license:\'%s\') %s%s (%d)!\n\n",
			       section, prog->type,
			       prog->size / sizeof(struct bpf_insn),
			       prog->license, fd < 0 ? "rejected: " :
			       "loaded", fd < 0 ? strerror(errno) : "",
			       fd < 0 ? errno : fd);
	}

	return fd;
}

static int bpf_map_attach(const char *name, const struct bpf_elf_map *map,
			  const struct bpf_elf_ctx *ctx, bool verbose)
{
	int fd, ret;

	fd = bpf_probe_pinned(name, ctx, map->pinning);
	if (fd > 0) {
		ret = bpf_map_selfcheck_pinned(fd, map,
					       offsetof(struct bpf_elf_map,
							id));
		if (ret < 0) {
			close(fd);
			fprintf(stderr, "Map \'%s\' self-check failed!\n",
				name);
			return ret;
		}
		if (verbose)
			fprintf(stderr, "Map \'%s\' loaded as pinned!\n",
				name);
		return fd;
	}

	errno = 0;
	fd = bpf_map_create(map->type, map->size_key, map->size_value,
			    map->max_elem);
	if (fd < 0 || verbose) {
		bpf_dump_error("Map \'%s\' (type:%u id:%u pinning:%u "
			       "ksize:%u vsize:%u max-elems:%u) %s%s (%d)!\n",
			       name, map->type, map->id, map->pinning,
			       map->size_key, map->size_value, map->max_elem,
			       fd < 0 ? "rejected: " : "loaded", fd < 0 ?
			       strerror(errno) : "", fd < 0 ? errno : fd);
		if (fd < 0)
			return fd;
	}

	ret = bpf_place_pinned(fd, name, ctx, map->pinning);
	if (ret < 0 && errno != EEXIST) {
		fprintf(stderr, "Could not pin %s map: %s\n", name,
			strerror(errno));
		close(fd);
		return ret;
	}

	return fd;
}

#define __ELF_ST_BIND(x)	((x) >> 4)
#define __ELF_ST_TYPE(x)	(((unsigned int) x) & 0xf)

static const char *bpf_str_tab_name(const struct bpf_elf_ctx *ctx,
				    const GElf_Sym *sym)
{
	return ctx->str_tab->d_buf + sym->st_name;
}

static const char *bpf_map_fetch_name(struct bpf_elf_ctx *ctx, int which)
{
	GElf_Sym sym;
	int i;

	for (i = 0; i < ctx->sym_num; i++) {
		if (gelf_getsym(ctx->sym_tab, i, &sym) != &sym)
			continue;

		if (__ELF_ST_BIND(sym.st_info) != STB_GLOBAL ||
		    __ELF_ST_TYPE(sym.st_info) != STT_NOTYPE ||
		    sym.st_shndx != ctx->sec_maps ||
		    sym.st_value / sizeof(struct bpf_elf_map) != which)
			continue;

		return bpf_str_tab_name(ctx, &sym);
	}

	return NULL;
}

static int bpf_maps_attach_all(struct bpf_elf_ctx *ctx)
{
	const char *map_name;
	int i, fd;

	for (i = 0; i < ctx->map_num; i++) {
		map_name = bpf_map_fetch_name(ctx, i);
		if (!map_name)
			return -EIO;

		fd = bpf_map_attach(map_name, &ctx->maps[i], ctx,
				    ctx->verbose);
		if (fd < 0)
			return fd;

		ctx->map_fds[i] = fd;
	}

	return 0;
}

static int bpf_fill_section_data(struct bpf_elf_ctx *ctx, int section,
				 struct bpf_elf_sec_data *data)
{
	Elf_Data *sec_edata;
	GElf_Shdr sec_hdr;
	Elf_Scn *sec_fd;
	char *sec_name;

	memset(data, 0, sizeof(*data));

	sec_fd = elf_getscn(ctx->elf_fd, section);
	if (!sec_fd)
		return -EINVAL;
	if (gelf_getshdr(sec_fd, &sec_hdr) != &sec_hdr)
		return -EIO;

	sec_name = elf_strptr(ctx->elf_fd, ctx->elf_hdr.e_shstrndx,
			      sec_hdr.sh_name);
	if (!sec_name || !sec_hdr.sh_size)
		return -ENOENT;

	sec_edata = elf_getdata(sec_fd, NULL);
	if (!sec_edata || elf_getdata(sec_fd, sec_edata))
		return -EIO;

	memcpy(&data->sec_hdr, &sec_hdr, sizeof(sec_hdr));

	data->sec_name = sec_name;
	data->sec_data = sec_edata;
	return 0;
}

static int bpf_fetch_maps(struct bpf_elf_ctx *ctx, int section,
			  struct bpf_elf_sec_data *data)
{
	if (data->sec_data->d_size % sizeof(struct bpf_elf_map) != 0)
		return -EINVAL;

	ctx->map_num = data->sec_data->d_size / sizeof(struct bpf_elf_map);
	ctx->sec_maps = section;
	ctx->sec_done[section] = true;

	if (ctx->map_num > ARRAY_SIZE(ctx->map_fds)) {
		fprintf(stderr, "Too many BPF maps in ELF section!\n");
		return -ENOMEM;
	}

	memcpy(ctx->maps, data->sec_data->d_buf, data->sec_data->d_size);
	return 0;
}

static int bpf_fetch_license(struct bpf_elf_ctx *ctx, int section,
			     struct bpf_elf_sec_data *data)
{
	if (data->sec_data->d_size > sizeof(ctx->license))
		return -ENOMEM;

	memcpy(ctx->license, data->sec_data->d_buf, data->sec_data->d_size);
	ctx->sec_done[section] = true;
	return 0;
}

static int bpf_fetch_symtab(struct bpf_elf_ctx *ctx, int section,
			    struct bpf_elf_sec_data *data)
{
	ctx->sym_tab = data->sec_data;
	ctx->sym_num = data->sec_hdr.sh_size / data->sec_hdr.sh_entsize;
	ctx->sec_done[section] = true;
	return 0;
}

static int bpf_fetch_strtab(struct bpf_elf_ctx *ctx, int section,
			    struct bpf_elf_sec_data *data)
{
	ctx->str_tab = data->sec_data;
	ctx->sec_done[section] = true;
	return 0;
}

static int bpf_fetch_ancillary(struct bpf_elf_ctx *ctx)
{
	struct bpf_elf_sec_data data;
	int i, ret = -1;

	for (i = 1; i < ctx->elf_hdr.e_shnum; i++) {
		ret = bpf_fill_section_data(ctx, i, &data);
		if (ret < 0)
			continue;

		if (data.sec_hdr.sh_type == SHT_PROGBITS &&
		    !strcmp(data.sec_name, ELF_SECTION_MAPS))
			ret = bpf_fetch_maps(ctx, i, &data);
		else if (data.sec_hdr.sh_type == SHT_PROGBITS &&
			 !strcmp(data.sec_name, ELF_SECTION_LICENSE))
			ret = bpf_fetch_license(ctx, i, &data);
		else if (data.sec_hdr.sh_type == SHT_SYMTAB &&
			 !strcmp(data.sec_name, ".symtab"))
			ret = bpf_fetch_symtab(ctx, i, &data);
		else if (data.sec_hdr.sh_type == SHT_STRTAB &&
			 !strcmp(data.sec_name, ".strtab"))
			ret = bpf_fetch_strtab(ctx, i, &data);
		if (ret < 0) {
			fprintf(stderr, "Error parsing section %d! Perhaps"
				"check with readelf -a?\n", i);
			break;
		}
	}

	if (ctx->sym_tab && ctx->str_tab && ctx->sec_maps) {
		ret = bpf_maps_attach_all(ctx);
		if (ret < 0) {
			fprintf(stderr, "Error loading maps into kernel!\n");
			return ret;
		}
	}

	return ret;
}

static int bpf_fetch_prog(struct bpf_elf_ctx *ctx, const char *section)
{
	struct bpf_elf_sec_data data;
	struct bpf_elf_prog prog;
	int ret, i, fd = -1;

	for (i = 1; i < ctx->elf_hdr.e_shnum; i++) {
		if (ctx->sec_done[i])
			continue;

		ret = bpf_fill_section_data(ctx, i, &data);
		if (ret < 0 ||
		    !(data.sec_hdr.sh_type == SHT_PROGBITS &&
		      data.sec_hdr.sh_flags & SHF_EXECINSTR &&
		      !strcmp(data.sec_name, section)))
			continue;

		memset(&prog, 0, sizeof(prog));
		prog.type    = ctx->type;
		prog.insns   = data.sec_data->d_buf;
		prog.size    = data.sec_data->d_size;
		prog.license = ctx->license;

		fd = bpf_prog_attach(section, &prog, ctx->verbose);
		if (fd < 0)
			continue;

		ctx->sec_done[i] = true;
		break;
	}

	return fd;
}

static int bpf_apply_relo_data(struct bpf_elf_ctx *ctx,
			       struct bpf_elf_sec_data *data_relo,
			       struct bpf_elf_sec_data *data_insn)
{
	Elf_Data *idata = data_insn->sec_data;
	GElf_Shdr *rhdr = &data_relo->sec_hdr;
	int relo_ent, relo_num = rhdr->sh_size / rhdr->sh_entsize;
	struct bpf_insn *insns = idata->d_buf;
	unsigned int num_insns = idata->d_size / sizeof(*insns);

	for (relo_ent = 0; relo_ent < relo_num; relo_ent++) {
		unsigned int ioff, rmap;
		GElf_Rel relo;
		GElf_Sym sym;

		if (gelf_getrel(data_relo->sec_data, relo_ent, &relo) != &relo)
			return -EIO;

		ioff = relo.r_offset / sizeof(struct bpf_insn);
		if (ioff >= num_insns ||
		    insns[ioff].code != (BPF_LD | BPF_IMM | BPF_DW))
			return -EINVAL;

		if (gelf_getsym(ctx->sym_tab, GELF_R_SYM(relo.r_info), &sym) != &sym)
			return -EIO;

		rmap = sym.st_value / sizeof(struct bpf_elf_map);
		if (rmap >= ARRAY_SIZE(ctx->map_fds))
			return -EINVAL;
		if (!ctx->map_fds[rmap])
			return -EINVAL;

		if (ctx->verbose)
			fprintf(stderr, "Map \'%s\' (%d) injected into prog "
				"section \'%s\' at offset %u!\n",
				bpf_str_tab_name(ctx, &sym), ctx->map_fds[rmap],
				data_insn->sec_name, ioff);

		insns[ioff].src_reg = BPF_PSEUDO_MAP_FD;
		insns[ioff].imm     = ctx->map_fds[rmap];
	}

	return 0;
}

static int bpf_fetch_prog_relo(struct bpf_elf_ctx *ctx, const char *section)
{
	struct bpf_elf_sec_data data_relo, data_insn;
	struct bpf_elf_prog prog;
	int ret, idx, i, fd = -1;

	for (i = 1; i < ctx->elf_hdr.e_shnum; i++) {
		ret = bpf_fill_section_data(ctx, i, &data_relo);
		if (ret < 0 || data_relo.sec_hdr.sh_type != SHT_REL)
			continue;

		idx = data_relo.sec_hdr.sh_info;
		ret = bpf_fill_section_data(ctx, idx, &data_insn);
		if (ret < 0 ||
		    !(data_insn.sec_hdr.sh_type == SHT_PROGBITS &&
		      data_insn.sec_hdr.sh_flags & SHF_EXECINSTR &&
		      !strcmp(data_insn.sec_name, section)))
			continue;

		ret = bpf_apply_relo_data(ctx, &data_relo, &data_insn);
		if (ret < 0)
			continue;

		memset(&prog, 0, sizeof(prog));
		prog.type    = ctx->type;
		prog.insns   = data_insn.sec_data->d_buf;
		prog.size    = data_insn.sec_data->d_size;
		prog.license = ctx->license;

		fd = bpf_prog_attach(section, &prog, ctx->verbose);
		if (fd < 0)
			continue;

		ctx->sec_done[i]   = true;
		ctx->sec_done[idx] = true;
		break;
	}

	return fd;
}

static int bpf_fetch_prog_sec(struct bpf_elf_ctx *ctx, const char *section)
{
	int ret = -1;

	if (ctx->sym_tab)
		ret = bpf_fetch_prog_relo(ctx, section);
	if (ret < 0)
		ret = bpf_fetch_prog(ctx, section);

	return ret;
}

static int bpf_find_map_by_id(struct bpf_elf_ctx *ctx, uint32_t id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ctx->map_fds); i++)
		if (ctx->map_fds[i] && ctx->maps[i].id == id &&
		    ctx->maps[i].type == BPF_MAP_TYPE_PROG_ARRAY)
			return i;
	return -1;
}

static int bpf_fill_prog_arrays(struct bpf_elf_ctx *ctx)
{
	struct bpf_elf_sec_data data;
	uint32_t map_id, key_id;
	int fd, i, ret, idx;

	for (i = 1; i < ctx->elf_hdr.e_shnum; i++) {
		if (ctx->sec_done[i])
			continue;

		ret = bpf_fill_section_data(ctx, i, &data);
		if (ret < 0)
			continue;

		ret = sscanf(data.sec_name, "%i/%i", &map_id, &key_id);
		if (ret != 2)
			continue;

		idx = bpf_find_map_by_id(ctx, map_id);
		if (idx < 0)
			continue;

		fd = bpf_fetch_prog_sec(ctx, data.sec_name);
		if (fd < 0)
			return -EIO;

		ret = bpf_map_update(ctx->map_fds[idx], &key_id,
				     &fd, BPF_ANY);
		if (ret < 0)
			return -ENOENT;

		ctx->sec_done[i] = true;
	}

	return 0;
}

static void bpf_save_finfo(struct bpf_elf_ctx *ctx)
{
	struct stat st;
	int ret;

	memset(&ctx->stat, 0, sizeof(ctx->stat));

	ret = fstat(ctx->obj_fd, &st);
	if (ret < 0) {
		fprintf(stderr, "Stat of elf file failed: %s\n",
			strerror(errno));
		return;
	}

	ctx->stat.st_dev = st.st_dev;
	ctx->stat.st_ino = st.st_ino;
}

static int bpf_read_pin_mapping(FILE *fp, uint32_t *id, char *path)
{
	char buff[PATH_MAX];

	while (fgets(buff, sizeof(buff), fp)) {
		char *ptr = buff;

		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		if (*ptr == '#' || *ptr == '\n' || *ptr == 0)
			continue;

		if (sscanf(ptr, "%i %s\n", id, path) != 2 &&
		    sscanf(ptr, "%i %s #", id, path) != 2) {
			strcpy(path, ptr);
			return -1;
		}

		return 1;
	}

	return 0;
}

static bool bpf_pinning_reserved(uint32_t pinning)
{
	switch (pinning) {
	case PIN_NONE:
	case PIN_OBJECT_NS:
	case PIN_GLOBAL_NS:
		return true;
	default:
		return false;
	}
}

static void bpf_hash_init(struct bpf_elf_ctx *ctx, const char *db_file)
{
	struct bpf_hash_entry *entry;
	char subpath[PATH_MAX];
	uint32_t pinning;
	FILE *fp;
	int ret;

	fp = fopen(db_file, "r");
	if (!fp)
		return;

	memset(subpath, 0, sizeof(subpath));
	while ((ret = bpf_read_pin_mapping(fp, &pinning, subpath))) {
		if (ret == -1) {
			fprintf(stderr, "Database %s is corrupted at: %s\n",
				db_file, subpath);
			fclose(fp);
			return;
		}

		if (bpf_pinning_reserved(pinning)) {
			fprintf(stderr, "Database %s, id %u is reserved - "
				"ignoring!\n", db_file, pinning);
			continue;
		}

		entry = malloc(sizeof(*entry));
		if (!entry) {
			fprintf(stderr, "No memory left for db entry!\n");
			continue;
		}

		entry->pinning = pinning;
		entry->subpath = strdup(subpath);
		if (!entry->subpath) {
			fprintf(stderr, "No memory left for db entry!\n");
			free(entry);
			continue;
		}

		entry->next = ctx->ht[pinning & (ARRAY_SIZE(ctx->ht) - 1)];
		ctx->ht[pinning & (ARRAY_SIZE(ctx->ht) - 1)] = entry;
	}

	fclose(fp);
}

static void bpf_hash_destroy(struct bpf_elf_ctx *ctx)
{
	struct bpf_hash_entry *entry;
	int i;

	for (i = 0; i < ARRAY_SIZE(ctx->ht); i++) {
		while ((entry = ctx->ht[i]) != NULL) {
			ctx->ht[i] = entry->next;
			free((char *)entry->subpath);
			free(entry);
		}
	}
}

static int bpf_elf_check_ehdr(const struct bpf_elf_ctx *ctx)
{
	if (ctx->elf_hdr.e_type != ET_REL ||
	    ctx->elf_hdr.e_machine != 0 ||
	    ctx->elf_hdr.e_version != EV_CURRENT) {
		fprintf(stderr, "ELF format error, ELF file not for eBPF?\n");
		return -EINVAL;
	}

	switch (ctx->elf_hdr.e_ident[EI_DATA]) {
	default:
		fprintf(stderr, "ELF format error, wrong endianness info?\n");
		return -EINVAL;
	case ELFDATA2LSB:
		if (htons(1) == 1) {
			fprintf(stderr,
				"We are big endian, eBPF object is little endian!\n");
			return -EIO;
		}
		break;
	case ELFDATA2MSB:
		if (htons(1) != 1) {
			fprintf(stderr,
				"We are little endian, eBPF object is big endian!\n");
			return -EIO;
		}
		break;
	}

	return 0;
}

static int bpf_elf_ctx_init(struct bpf_elf_ctx *ctx, const char *pathname,
			    enum bpf_prog_type type, bool verbose)
{
	int ret = -EINVAL;

	if (elf_version(EV_CURRENT) == EV_NONE ||
	    bpf_init_env(pathname))
		return ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->verbose = verbose;
	ctx->type    = type;

	ctx->obj_fd = open(pathname, O_RDONLY);
	if (ctx->obj_fd < 0)
		return ctx->obj_fd;

	ctx->elf_fd = elf_begin(ctx->obj_fd, ELF_C_READ, NULL);
	if (!ctx->elf_fd) {
		ret = -EINVAL;
		goto out_fd;
	}

	if (elf_kind(ctx->elf_fd) != ELF_K_ELF) {
		ret = -EINVAL;
		goto out_fd;
	}

	if (gelf_getehdr(ctx->elf_fd, &ctx->elf_hdr) !=
	    &ctx->elf_hdr) {
		ret = -EIO;
		goto out_elf;
	}

	ret = bpf_elf_check_ehdr(ctx);
	if (ret < 0)
		goto out_elf;

	ctx->sec_done = calloc(ctx->elf_hdr.e_shnum,
			       sizeof(*(ctx->sec_done)));
	if (!ctx->sec_done) {
		ret = -ENOMEM;
		goto out_elf;
	}

	bpf_save_finfo(ctx);
	bpf_hash_init(ctx, CONFDIR "/bpf_pinning");

	return 0;
out_elf:
	elf_end(ctx->elf_fd);
out_fd:
	close(ctx->obj_fd);
	return ret;
}

static int bpf_maps_count(struct bpf_elf_ctx *ctx)
{
	int i, count = 0;

	for (i = 0; i < ARRAY_SIZE(ctx->map_fds); i++) {
		if (!ctx->map_fds[i])
			break;
		count++;
	}

	return count;
}

static void bpf_maps_teardown(struct bpf_elf_ctx *ctx)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ctx->map_fds); i++) {
		if (ctx->map_fds[i])
			close(ctx->map_fds[i]);
	}
}

static void bpf_elf_ctx_destroy(struct bpf_elf_ctx *ctx, bool failure)
{
	if (failure)
		bpf_maps_teardown(ctx);

	bpf_hash_destroy(ctx);
	free(ctx->sec_done);
	elf_end(ctx->elf_fd);
	close(ctx->obj_fd);
}

static struct bpf_elf_ctx __ctx;

static int bpf_obj_open(const char *pathname, enum bpf_prog_type type,
			const char *section, bool verbose)
{
	struct bpf_elf_ctx *ctx = &__ctx;
	int fd = 0, ret;

	ret = bpf_elf_ctx_init(ctx, pathname, type, verbose);
	if (ret < 0) {
		fprintf(stderr, "Cannot initialize ELF context!\n");
		return ret;
	}

	ret = bpf_fetch_ancillary(ctx);
	if (ret < 0) {
		fprintf(stderr, "Error fetching ELF ancillary data!\n");
		goto out;
	}

	fd = bpf_fetch_prog_sec(ctx, section);
	if (fd < 0) {
		fprintf(stderr, "Error fetching program/map!\n");
		ret = fd;
		goto out;
	}

	ret = bpf_fill_prog_arrays(ctx);
	if (ret < 0)
		fprintf(stderr, "Error filling program arrays!\n");
out:
	bpf_elf_ctx_destroy(ctx, ret < 0);
	if (ret < 0) {
		if (fd)
			close(fd);
		return ret;
	}

	return fd;
}

static int
bpf_map_set_send(int fd, struct sockaddr_un *addr, unsigned int addr_len,
		 const struct bpf_map_data *aux, unsigned int entries)
{
	struct bpf_map_set_msg msg;
	int *cmsg_buf, min_fd;
	char *amsg_buf;
	int i;

	memset(&msg, 0, sizeof(msg));

	msg.aux.uds_ver = BPF_SCM_AUX_VER;
	msg.aux.num_ent = entries;

	strncpy(msg.aux.obj_name, aux->obj, sizeof(msg.aux.obj_name));
	memcpy(&msg.aux.obj_st, aux->st, sizeof(msg.aux.obj_st));

	cmsg_buf = bpf_map_set_init(&msg, addr, addr_len);
	amsg_buf = (char *)msg.aux.ent;

	for (i = 0; i < entries; i += min_fd) {
		int ret;

		min_fd = min(BPF_SCM_MAX_FDS * 1U, entries - i);
		bpf_map_set_init_single(&msg, min_fd);

		memcpy(cmsg_buf, &aux->fds[i], sizeof(aux->fds[0]) * min_fd);
		memcpy(amsg_buf, &aux->ent[i], sizeof(aux->ent[0]) * min_fd);

		ret = sendmsg(fd, &msg.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;
	}

	return 0;
}

static int
bpf_map_set_recv(int fd, int *fds,  struct bpf_map_aux *aux,
		 unsigned int entries)
{
	struct bpf_map_set_msg msg;
	int *cmsg_buf, min_fd;
	char *amsg_buf, *mmsg_buf;
	unsigned int needed = 1;
	int i;

	cmsg_buf = bpf_map_set_init(&msg, NULL, 0);
	amsg_buf = (char *)msg.aux.ent;
	mmsg_buf = (char *)&msg.aux;

	for (i = 0; i < min(entries, needed); i += min_fd) {
		struct cmsghdr *cmsg;
		int ret;

		min_fd = min(entries, entries - i);
		bpf_map_set_init_single(&msg, min_fd);

		ret = recvmsg(fd, &msg.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;

		cmsg = CMSG_FIRSTHDR(&msg.hdr);
		if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS)
			return -EINVAL;
		if (msg.hdr.msg_flags & MSG_CTRUNC)
			return -EIO;
		if (msg.aux.uds_ver != BPF_SCM_AUX_VER)
			return -ENOSYS;

		min_fd = (cmsg->cmsg_len - sizeof(*cmsg)) / sizeof(fd);
		if (min_fd > entries || min_fd <= 0)
			return -EINVAL;

		memcpy(&fds[i], cmsg_buf, sizeof(fds[0]) * min_fd);
		memcpy(&aux->ent[i], amsg_buf, sizeof(aux->ent[0]) * min_fd);
		memcpy(aux, mmsg_buf, offsetof(struct bpf_map_aux, ent));

		needed = aux->num_ent;
	}

	return 0;
}

int bpf_send_map_fds(const char *path, const char *obj)
{
	struct bpf_elf_ctx *ctx = &__ctx;
	struct sockaddr_un addr;
	struct bpf_map_data bpf_aux;
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open socket: %s\n",
			strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "Cannot connect to %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	memset(&bpf_aux, 0, sizeof(bpf_aux));

	bpf_aux.fds = ctx->map_fds;
	bpf_aux.ent = ctx->maps;
	bpf_aux.st  = &ctx->stat;
	bpf_aux.obj = obj;

	ret = bpf_map_set_send(fd, &addr, sizeof(addr), &bpf_aux,
			       bpf_maps_count(ctx));
	if (ret < 0)
		fprintf(stderr, "Cannot send fds to %s: %s\n",
			path, strerror(errno));

	bpf_maps_teardown(ctx);
	close(fd);
	return ret;
}

int bpf_recv_map_fds(const char *path, int *fds, struct bpf_map_aux *aux,
		     unsigned int entries)
{
	struct sockaddr_un addr;
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open socket: %s\n",
			strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "Cannot bind to socket: %s\n",
			strerror(errno));
		return -1;
	}

	ret = bpf_map_set_recv(fd, fds, aux, entries);
	if (ret < 0)
		fprintf(stderr, "Cannot recv fds from %s: %s\n",
			path, strerror(errno));

	unlink(addr.sun_path);
	close(fd);
	return ret;
}
#endif /* HAVE_ELF */
