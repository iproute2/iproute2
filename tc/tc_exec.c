/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * tc_exec.c	"tc exec".
 *
 * Authors:	Daniel Borkmann <daniel@iogearbox.net>
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "utils.h"

#include "tc_util.h"
#include "tc_common.h"

static struct exec_util *exec_list;
static void *BODY;

static void usage(void)
{
	fprintf(stderr,
		"Usage: tc exec [ EXEC_TYPE ] [ help | OPTIONS ]\n"
		"Where:\n"
		"EXEC_TYPE := { bpf | etc. }\n"
		"OPTIONS := ... try tc exec <desired EXEC_KIND> help\n");
}

static int parse_noeopt(const struct exec_util *eu, int argc, char **argv)
{
	if (argc) {
		fprintf(stderr, "Unknown exec \"%s\", hence option \"%s\" is unparsable\n",
			eu->id, *argv);
		return -1;
	}

	return 0;
}

static struct exec_util *get_exec_kind(const char *name)
{
	struct exec_util *eu;
	char buf[256];
	void *dlh;

	for (eu = exec_list; eu; eu = eu->next)
		if (strcmp(eu->id, name) == 0)
			return eu;

	snprintf(buf, sizeof(buf), "%s/e_%s.so", get_tc_lib(), name);
	dlh = dlopen(buf, RTLD_LAZY);
	if (dlh == NULL) {
		dlh = BODY;
		if (dlh == NULL) {
			dlh = BODY = dlopen(NULL, RTLD_LAZY);
			if (dlh == NULL)
				goto noexist;
		}
	}

	snprintf(buf, sizeof(buf), "%s_exec_util", name);
	eu = dlsym(dlh, buf);
	if (eu == NULL)
		goto noexist;
reg:
	eu->next = exec_list;
	exec_list = eu;

	return eu;
noexist:
	eu = calloc(1, sizeof(*eu));
	if (eu) {
		strncpy(eu->id, name, sizeof(eu->id) - 1);
		eu->parse_eopt = parse_noeopt;
		goto reg;
	}

	return eu;
}

int do_exec(int argc, char **argv)
{
	struct exec_util *eu;
	char kind[FILTER_NAMESZ] = {};

	if (argc < 1) {
		fprintf(stderr, "No command given, try \"tc exec help\".\n");
		return -1;
	}

	if (matches(*argv, "help") == 0) {
		usage();
		return 0;
	}

	strncpy(kind, *argv, sizeof(kind) - 1);

	eu = get_exec_kind(kind);
	if (eu == NULL) {
		fprintf(stderr, "Allocation failed finding exec\n");
		return -1;
	}

	argc--;
	argv++;

	return eu->parse_eopt(eu, argc, argv);
}
