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
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifdef HAVE_ELF
#include <libelf.h>
#include <gelf.h>
#endif

#include "utils.h"
#include "tc_util.h"
#include "tc_bpf.h"

int bpf_parse_string(char *arg, bool from_file, __u16 *bpf_len,
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

int bpf_parse_ops(int argc, char **argv, struct sock_filter *bpf_ops,
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

	fprintf(f, "%hu %hhu %hhu %u\'\n", ops[i].code, ops[i].jt,
		ops[i].jf, ops[i].k);
}

#ifdef HAVE_ELF
struct bpf_elf_sec_data {
	GElf_Shdr	sec_hdr;
	char		*sec_name;
	Elf_Data	*sec_data;
};

static char bpf_log_buf[8192];

static const char *prog_type_section(enum bpf_prog_type type)
{
	switch (type) {
	case BPF_PROG_TYPE_SCHED_CLS:
		return ELF_SECTION_CLASSIFIER;
	/* case BPF_PROG_TYPE_SCHED_ACT:   */
	/*	return ELF_SECTION_ACTION; */
	default:
		return NULL;
	}
}

static void bpf_dump_error(const char *format, ...)  __check_format_string(1, 2);
static void bpf_dump_error(const char *format, ...)
{
	va_list vl;

	va_start(vl, format);
	vfprintf(stderr, format, vl);
	va_end(vl);

	fprintf(stderr, "%s", bpf_log_buf);
	memset(bpf_log_buf, 0, sizeof(bpf_log_buf));
}

static int bpf_create_map(enum bpf_map_type type, unsigned int size_key,
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
			 unsigned int len, const char *license)
{
	union bpf_attr attr = {
		.prog_type	= type,
		.insns		= bpf_ptr_to_u64(insns),
		.insn_cnt	= len / sizeof(struct bpf_insn),
		.license	= bpf_ptr_to_u64(license),
		.log_buf	= bpf_ptr_to_u64(bpf_log_buf),
		.log_size	= sizeof(bpf_log_buf),
		.log_level	= 1,
	};

	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_prog_attach(enum bpf_prog_type type, const struct bpf_insn *insns,
			   unsigned int size, const char *license)
{
	int prog_fd = bpf_prog_load(type, insns, size, license);

	if (prog_fd < 0)
		bpf_dump_error("BPF program rejected: %s\n", strerror(errno));

	return prog_fd;
}

static int bpf_map_attach(enum bpf_map_type type, unsigned int size_key,
			  unsigned int size_value, unsigned int max_elem)
{
	int map_fd = bpf_create_map(type, size_key, size_value, max_elem);

	if (map_fd < 0)
		bpf_dump_error("BPF map rejected: %s\n", strerror(errno));

	return map_fd;
}

static void bpf_maps_init(int *map_fds, unsigned int max_fds)
{
	int i;

	for (i = 0; i < max_fds; i++)
		map_fds[i] = -1;
}

static void bpf_maps_destroy(const int *map_fds, unsigned int max_fds)
{
	int i;

	for (i = 0; i < max_fds; i++) {
		if (map_fds[i] >= 0)
			close(map_fds[i]);
	}
}

static int bpf_maps_attach(struct bpf_elf_map *maps, unsigned int num_maps,
			   int *map_fds, unsigned int max_fds)
{
	int i, ret;

	for (i = 0; i < num_maps && num_maps <= max_fds; i++) {
		struct bpf_elf_map *map = &maps[i];

		ret = bpf_map_attach(map->type, map->size_key,
				     map->size_value, map->max_elem);
		if (ret < 0)
			goto err_unwind;

		map_fds[i] = ret;
	}

	return 0;

err_unwind:
	bpf_maps_destroy(map_fds, i);
	return ret;
}

static int bpf_fill_section_data(Elf *elf_fd, GElf_Ehdr *elf_hdr, int sec_index,
				 struct bpf_elf_sec_data *sec_data)
{
	GElf_Shdr sec_hdr;
	Elf_Scn *sec_fd;
	Elf_Data *sec_edata;
	char *sec_name;

	memset(sec_data, 0, sizeof(*sec_data));

	sec_fd = elf_getscn(elf_fd, sec_index);
	if (!sec_fd)
		return -EINVAL;

	if (gelf_getshdr(sec_fd, &sec_hdr) != &sec_hdr)
		return -EIO;

	sec_name = elf_strptr(elf_fd, elf_hdr->e_shstrndx,
			      sec_hdr.sh_name);
	if (!sec_name || !sec_hdr.sh_size)
		return -ENOENT;

	sec_edata = elf_getdata(sec_fd, NULL);
	if (!sec_edata || elf_getdata(sec_fd, sec_edata))
		return -EIO;

	memcpy(&sec_data->sec_hdr, &sec_hdr, sizeof(sec_hdr));
	sec_data->sec_name = sec_name;
	sec_data->sec_data = sec_edata;

	return 0;
}

static int bpf_apply_relo_data(struct bpf_elf_sec_data *data_relo,
			       struct bpf_elf_sec_data *data_insn,
			       Elf_Data *sym_tab, int *map_fds, int max_fds)
{
	Elf_Data *idata = data_insn->sec_data;
	GElf_Shdr *rhdr = &data_relo->sec_hdr;
	int relo_ent, relo_num = rhdr->sh_size / rhdr->sh_entsize;
	struct bpf_insn *insns = idata->d_buf;
	unsigned int num_insns = idata->d_size / sizeof(*insns);

	for (relo_ent = 0; relo_ent < relo_num; relo_ent++) {
		unsigned int ioff, fnum;
		GElf_Rel relo;
		GElf_Sym sym;

		if (gelf_getrel(data_relo->sec_data, relo_ent, &relo) != &relo)
			return -EIO;

		ioff = relo.r_offset / sizeof(struct bpf_insn);
		if (ioff >= num_insns)
			return -EINVAL;
		if (insns[ioff].code != (BPF_LD | BPF_IMM | BPF_DW))
			return -EINVAL;

		if (gelf_getsym(sym_tab, GELF_R_SYM(relo.r_info), &sym) != &sym)
			return -EIO;

		fnum = sym.st_value / sizeof(struct bpf_elf_map);
		if (fnum >= max_fds)
			return -EINVAL;

		insns[ioff].src_reg = BPF_PSEUDO_MAP_FD;
		insns[ioff].imm = map_fds[fnum];
	}

	return 0;
}

static int bpf_fetch_ancillary(Elf *elf_fd, GElf_Ehdr *elf_hdr, bool *sec_seen,
			       int *map_fds, unsigned int max_fds,
			       char *license, unsigned int lic_len,
			       Elf_Data **sym_tab)
{
	int sec_index, ret = -1;

	for (sec_index = 1; sec_index < elf_hdr->e_shnum; sec_index++) {
		struct bpf_elf_sec_data data_anc;

		ret = bpf_fill_section_data(elf_fd, elf_hdr, sec_index,
					    &data_anc);
		if (ret < 0)
			continue;

		/* Extract and load eBPF map fds. */
		if (!strcmp(data_anc.sec_name, ELF_SECTION_MAPS)) {
			struct bpf_elf_map *maps = data_anc.sec_data->d_buf;
			unsigned int maps_num = data_anc.sec_data->d_size /
						sizeof(*maps);

			sec_seen[sec_index] = true;
			ret = bpf_maps_attach(maps, maps_num, map_fds,
					      max_fds);
			if (ret < 0)
				return ret;
		}
		/* Extract eBPF license. */
		else if (!strcmp(data_anc.sec_name, ELF_SECTION_LICENSE)) {
			if (data_anc.sec_data->d_size > lic_len)
				return -ENOMEM;

			sec_seen[sec_index] = true;
			memcpy(license, data_anc.sec_data->d_buf,
			       data_anc.sec_data->d_size);
		}
		/* Extract symbol table for relocations (map fd fixups). */
		else if (data_anc.sec_hdr.sh_type == SHT_SYMTAB) {
			sec_seen[sec_index] = true;
			*sym_tab = data_anc.sec_data;
		}
	}

	return ret;
}

static int bpf_fetch_prog_relo(Elf *elf_fd, GElf_Ehdr *elf_hdr, bool *sec_seen,
			       enum bpf_prog_type type, char *license,
			       Elf_Data *sym_tab, int *map_fds, unsigned int max_fds)
{
	int sec_index, prog_fd = -1;

	for (sec_index = 1; sec_index < elf_hdr->e_shnum; sec_index++) {
		struct bpf_elf_sec_data data_relo, data_insn;
		int ins_index, ret;

		/* Attach eBPF programs with relocation data (maps). */
		ret = bpf_fill_section_data(elf_fd, elf_hdr, sec_index,
					    &data_relo);
		if (ret < 0 || data_relo.sec_hdr.sh_type != SHT_REL)
			continue;

		ins_index = data_relo.sec_hdr.sh_info;

		ret = bpf_fill_section_data(elf_fd, elf_hdr, ins_index,
					    &data_insn);
		if (ret < 0)
			continue;
		if (strcmp(data_insn.sec_name, prog_type_section(type)))
			continue;

		sec_seen[sec_index] = true;
		sec_seen[ins_index] = true;

		ret = bpf_apply_relo_data(&data_relo, &data_insn, sym_tab,
					  map_fds, max_fds);
		if (ret < 0)
			continue;

		prog_fd = bpf_prog_attach(type, data_insn.sec_data->d_buf,
					  data_insn.sec_data->d_size, license);
		if (prog_fd < 0)
			continue;

		break;
	}

	return prog_fd;
}

static int bpf_fetch_prog(Elf *elf_fd, GElf_Ehdr *elf_hdr, bool *sec_seen,
			  enum bpf_prog_type type, char *license)
{
	int sec_index, prog_fd = -1;

	for (sec_index = 1; sec_index < elf_hdr->e_shnum; sec_index++) {
		struct bpf_elf_sec_data data_insn;
		int ret;

		/* Attach eBPF programs without relocation data. */
		if (sec_seen[sec_index])
			continue;

		ret = bpf_fill_section_data(elf_fd, elf_hdr, sec_index,
					    &data_insn);
		if (ret < 0)
			continue;
		if (strcmp(data_insn.sec_name, prog_type_section(type)))
			continue;

		prog_fd = bpf_prog_attach(type, data_insn.sec_data->d_buf,
					  data_insn.sec_data->d_size, license);
		if (prog_fd < 0)
			continue;

		break;
	}

	return prog_fd;
}

int bpf_open_object(const char *path, enum bpf_prog_type type)
{
	int map_fds[ELF_MAX_MAPS], max_fds = ARRAY_SIZE(map_fds);
	char license[ELF_MAX_LICENSE_LEN];
	int file_fd, prog_fd = -1, ret;
	Elf_Data *sym_tab = NULL;
	GElf_Ehdr elf_hdr;
	bool *sec_seen;
	Elf *elf_fd;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return -EINVAL;

	file_fd = open(path, O_RDONLY, 0);
	if (file_fd < 0)
		return -errno;

	elf_fd = elf_begin(file_fd, ELF_C_READ, NULL);
	if (!elf_fd) {
		ret = -EINVAL;
		goto out;
	}

	if (gelf_getehdr(elf_fd, &elf_hdr) != &elf_hdr) {
		ret = -EIO;
		goto out_elf;
	}

	sec_seen = calloc(elf_hdr.e_shnum, sizeof(*sec_seen));
	if (!sec_seen) {
		ret = -ENOMEM;
		goto out_elf;
	}

	memset(license, 0, sizeof(license));
	bpf_maps_init(map_fds, max_fds);

	ret = bpf_fetch_ancillary(elf_fd, &elf_hdr, sec_seen, map_fds, max_fds,
				  license, sizeof(license), &sym_tab);
	if (ret < 0)
		goto out_maps;
	if (sym_tab)
		prog_fd = bpf_fetch_prog_relo(elf_fd, &elf_hdr, sec_seen, type,
					      license, sym_tab, map_fds, max_fds);
	if (prog_fd < 0)
		prog_fd = bpf_fetch_prog(elf_fd, &elf_hdr, sec_seen, type,
					 license);
	if (prog_fd < 0)
		goto out_maps;
out_sec:
	free(sec_seen);
out_elf:
	elf_end(elf_fd);
out:
	close(file_fd);
	return prog_fd;

out_maps:
	bpf_maps_destroy(map_fds, max_fds);
	goto out_sec;
}

#endif /* HAVE_ELF */
