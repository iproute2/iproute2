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
#ifndef _RDMA_TOOL_H_
#define _RDMA_TOOL_H_

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <libmnl/libmnl.h>
#include <rdma/rdma_netlink.h>
#include <time.h>

#include "list.h"
#include "utils.h"
#include "json_writer.h"

#define pr_err(args...) fprintf(stderr, ##args)
#define pr_out(args...) fprintf(stdout, ##args)

#define RDMA_BITMAP_ENUM(name, bit_no) RDMA_BITMAP_##name = BIT(bit_no),
#define RDMA_BITMAP_NAMES(name, bit_no) [bit_no] = #name,

struct dev_map {
	struct list_head list;
	char *dev_name;
	uint32_t num_ports;
	uint32_t idx;
};

struct rd {
	int argc;
	char **argv;
	char *filename;
	bool show_details;
	struct list_head dev_map_list;
	uint32_t dev_idx;
	uint32_t port_idx;
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	char *buff;
	json_writer_t *jw;
	bool json_output;
	bool pretty_output;
};

struct rd_cmd {
	const char *cmd;
	int (*func)(struct rd *rd);
};

/*
 * Parser interface
 */
bool rd_no_arg(struct rd *rd);
void rd_arg_inc(struct rd *rd);

char *rd_argv(struct rd *rd);
uint32_t get_port_from_argv(struct rd *rd);

/*
 * Commands interface
 */
int cmd_dev(struct rd *rd);
int cmd_link(struct rd *rd);
int rd_exec_cmd(struct rd *rd, const struct rd_cmd *c, const char *str);

/*
 * Device manipulation
 */
void rd_free_devmap(struct rd *rd);
struct dev_map *dev_map_lookup(struct rd *rd, bool allow_port_index);
struct dev_map *_dev_map_lookup(struct rd *rd, const char *dev_name);

/*
 * Netlink
 */
int rd_send_msg(struct rd *rd);
int rd_recv_msg(struct rd *rd, mnl_cb_t callback, void *data, uint32_t seq);
void rd_prepare_msg(struct rd *rd, uint32_t cmd, uint32_t *seq, uint16_t flags);
int rd_dev_init_cb(const struct nlmsghdr *nlh, void *data);
int rd_attr_cb(const struct nlattr *attr, void *data);
#endif /* _RDMA_TOOL_H_ */
