/*
 * rdma.c	RDMA tool
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Leon Romanovsky <leonro@mellanox.com>
 */

#include "rdma.h"
#include "SNAPSHOT.h"

static void help(char *name)
{
	pr_out("Usage: %s [ OPTIONS ] OBJECT { COMMAND | help }\n"
	       "       %s [ -f[orce] ] -b[atch] filename\n"
	       "where  OBJECT := { dev | link | resource | help }\n"
	       "       OPTIONS := { -V[ersion] | -d[etails] | -j[son] | -p[retty]}\n", name, name);
}

static int cmd_help(struct rd *rd)
{
	help(rd->filename);
	return 0;
}

static int rd_cmd(struct rd *rd, int argc, char **argv)
{
	const struct rd_cmd cmds[] = {
		{ NULL,		cmd_help },
		{ "help",	cmd_help },
		{ "dev",	cmd_dev },
		{ "link",	cmd_link },
		{ "resource",	cmd_res },
		{ 0 }
	};

	rd->argc = argc;
	rd->argv = argv;

	return rd_exec_cmd(rd, cmds, "object");
}

static int rd_batch(struct rd *rd, const char *name, bool force)
{
	char *line = NULL;
	size_t len = 0;
	int ret = 0;

	if (name && strcmp(name, "-") != 0) {
		if (!freopen(name, "r", stdin)) {
			pr_err("Cannot open file \"%s\" for reading: %s\n",
			       name, strerror(errno));
			return errno;
		}
	}

	cmdlineno = 0;
	while (getcmdline(&line, &len, stdin) != -1) {
		char *largv[512];
		int largc;

		largc = makeargs(line, largv, ARRAY_SIZE(largv));
		if (!largc)
			continue;	/* blank line */

		ret = rd_cmd(rd, largc, largv);
		if (ret) {
			pr_err("Command failed %s:%d\n", name, cmdlineno);
			if (!force)
				break;
		}
	}

	free(line);

	return ret;
}

static int rd_init(struct rd *rd, char *filename)
{
	uint32_t seq;
	int ret;

	rd->filename = filename;
	INIT_LIST_HEAD(&rd->dev_map_list);
	INIT_LIST_HEAD(&rd->filter_list);

	if (rd->json_output) {
		rd->jw = jsonw_new(stdout);
		if (!rd->jw) {
			pr_err("Failed to create JSON writer\n");
			return -ENOMEM;
		}
		jsonw_pretty(rd->jw, rd->pretty_output);
	}

	rd->buff = malloc(MNL_SOCKET_BUFFER_SIZE);
	if (!rd->buff)
		return -ENOMEM;

	rd_prepare_msg(rd, RDMA_NLDEV_CMD_GET,
		       &seq, (NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP));
	ret = rd_send_msg(rd);
	if (ret)
		return ret;

	return rd_recv_msg(rd, rd_dev_init_cb, rd, seq);
}

static void rd_cleanup(struct rd *rd)
{
	if (rd->json_output)
		jsonw_destroy(&rd->jw);
	rd_free(rd);
}

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "version",		no_argument,		NULL, 'V' },
		{ "help",		no_argument,		NULL, 'h' },
		{ "json",		no_argument,		NULL, 'j' },
		{ "pretty",		no_argument,		NULL, 'p' },
		{ "details",		no_argument,		NULL, 'd' },
		{ "force",		no_argument,		NULL, 'f' },
		{ "batch",		required_argument,	NULL, 'b' },
		{ NULL, 0, NULL, 0 }
	};
	bool show_driver_details = false;
	const char *batch_file = NULL;
	bool pretty_output = false;
	bool show_details = false;
	bool json_output = false;
	bool force = false;
	struct rd rd = {};
	char *filename;
	int opt;
	int err;

	filename = basename(argv[0]);

	while ((opt = getopt_long(argc, argv, ":Vhdpjfb:",
				  long_options, NULL)) >= 0) {
		switch (opt) {
		case 'V':
			printf("%s utility, iproute2-ss%s\n",
			       filename, SNAPSHOT);
			return EXIT_SUCCESS;
		case 'p':
			pretty_output = true;
			break;
		case 'd':
			if (show_details)
				show_driver_details = true;
			else
				show_details = true;
			break;
		case 'j':
			json_output = true;
			break;
		case 'f':
			force = true;
			break;
		case 'b':
			batch_file = optarg;
			break;
		case 'h':
			help(filename);
			return EXIT_SUCCESS;
		case ':':
			pr_err("-%c option requires an argument\n", optopt);
			return EXIT_FAILURE;
		default:
			pr_err("Unknown option.\n");
			help(filename);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	rd.show_details = show_details;
	rd.show_driver_details = show_driver_details;
	rd.json_output = json_output;
	rd.pretty_output = pretty_output;

	err = rd_init(&rd, filename);
	if (err)
		goto out;

	if (batch_file)
		err = rd_batch(&rd, batch_file, force);
	else
		err = rd_cmd(&rd, argc, argv);
out:
	/* Always cleanup */
	rd_cleanup(&rd);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
