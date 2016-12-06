/*
 * iplink_xdp.c XDP program loader
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Daniel Borkmann <daniel@iogearbox.net>
 */

#include <stdio.h>
#include <stdlib.h>

#include <linux/bpf.h>

#include "xdp.h"
#include "bpf_util.h"

extern int force;

static void xdp_ebpf_cb(void *raw, int fd, const char *annotation)
{
	__u32 flags = !force ? XDP_FLAGS_UPDATE_IF_NOEXIST : 0;
	struct iplink_req *req = raw;
	struct rtattr *xdp;

	xdp = addattr_nest(&req->n, sizeof(*req), IFLA_XDP);
	addattr32(&req->n, sizeof(*req), IFLA_XDP_FD, fd);
	addattr32(&req->n, sizeof(*req), IFLA_XDP_FLAGS, flags);
	addattr_nest_end(&req->n, xdp);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.ebpf_cb = xdp_ebpf_cb,
};

static int xdp_delete(struct iplink_req *req)
{
	xdp_ebpf_cb(req, -1, NULL);
	return 0;
}

int xdp_parse(int *argc, char ***argv, struct iplink_req *req)
{
	struct bpf_cfg_in cfg = {
		.argc = *argc,
		.argv = *argv,
	};

	if (*argc == 1) {
		if (strcmp(**argv, "none") == 0 ||
		    strcmp(**argv, "off") == 0)
			return xdp_delete(req);
	}
	if (bpf_parse_common(BPF_PROG_TYPE_XDP, &cfg, &bpf_cb_ops, req))
		return -1;

	*argc = cfg.argc;
	*argv = cfg.argv;
	return 0;
}

void xdp_dump(FILE *fp, struct rtattr *xdp)
{
	struct rtattr *tb[IFLA_XDP_MAX + 1];

	parse_rtattr_nested(tb, IFLA_XDP_MAX, xdp);
	if (!tb[IFLA_XDP_ATTACHED] ||
	    !rta_getattr_u8(tb[IFLA_XDP_ATTACHED]))
		return;

	fprintf(fp, "xdp ");
	/* More to come here in future for 'ip -d link' (digest, etc) ... */
}
