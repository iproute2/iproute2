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
#include <netinet/in.h>
#include <libmnl/libmnl.h>
#include <rdma/rdma_netlink.h>
#include <rdma/rdma_user_cm.h>
#include <time.h>
#include <net/if_arp.h>

#include "list.h"
#include "utils.h"
#include "json_writer.h"

#define pr_err(args...) fprintf(stderr, ##args)
#define pr_out(args...) fprintf(stdout, ##args)

#define RDMA_BITMAP_ENUM(name, bit_no) RDMA_BITMAP_##name = BIT(bit_no),
#define RDMA_BITMAP_NAMES(name, bit_no) [bit_no] = #name,

#define MAX_NUMBER_OF_FILTERS 64
struct filters {
	const char *name;
	bool is_number;
};

struct filter_entry {
	struct list_head list;
	char *key;
	char *value;
};

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
	bool show_driver_details;
	struct list_head dev_map_list;
	uint32_t dev_idx;
	uint32_t port_idx;
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	char *buff;
	json_writer_t *jw;
	bool json_output;
	bool pretty_output;
	struct list_head filter_list;
};

struct rd_cmd {
	const char *cmd;
	int (*func)(struct rd *rd);
};


/*
 * Commands interface
 */
int cmd_dev(struct rd *rd);
int cmd_link(struct rd *rd);
int cmd_res(struct rd *rd);
int rd_exec_cmd(struct rd *rd, const struct rd_cmd *c, const char *str);
int rd_exec_dev(struct rd *rd, int (*cb)(struct rd *rd));
int rd_exec_link(struct rd *rd, int (*cb)(struct rd *rd), bool strict_port);
void rd_free(struct rd *rd);
int rd_set_arg_to_devname(struct rd *rd);
int rd_argc(struct rd *rd);

/*
 * Device manipulation
 */
struct dev_map *dev_map_lookup(struct rd *rd, bool allow_port_index);

/*
 * Filter manipulation
 */
int rd_build_filter(struct rd *rd, const struct filters valid_filters[]);
bool rd_check_is_filtered(struct rd *rd, const char *key, uint32_t val);
bool rd_check_is_string_filtered(struct rd *rd, const char *key, const char *val);
bool rd_check_is_key_exist(struct rd *rd, const char *key);
/*
 * Netlink
 */
int rd_send_msg(struct rd *rd);
int rd_recv_msg(struct rd *rd, mnl_cb_t callback, void *data, uint32_t seq);
void rd_prepare_msg(struct rd *rd, uint32_t cmd, uint32_t *seq, uint16_t flags);
int rd_dev_init_cb(const struct nlmsghdr *nlh, void *data);
int rd_attr_cb(const struct nlattr *attr, void *data);

/*
 * Print helpers
 */
void print_driver_table(struct rd *rd, struct nlattr *tb);
void newline(struct rd *rd);
#define MAX_LINE_LENGTH 80

#endif /* _RDMA_TOOL_H_ */
