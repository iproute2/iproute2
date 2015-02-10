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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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
