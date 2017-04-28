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

struct xdp_req {
	struct iplink_req *req;
	__u32 flags;
};

static void xdp_ebpf_cb(void *raw, int fd, const char *annotation)
{
	struct xdp_req *xdp = raw;
	struct iplink_req *req = xdp->req;
	struct rtattr *xdp_attr;

	xdp_attr = addattr_nest(&req->n, sizeof(*req), IFLA_XDP);
	addattr32(&req->n, sizeof(*req), IFLA_XDP_FD, fd);
	if (xdp->flags)
		addattr32(&req->n, sizeof(*req), IFLA_XDP_FLAGS, xdp->flags);
	addattr_nest_end(&req->n, xdp_attr);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.ebpf_cb = xdp_ebpf_cb,
};

static int xdp_delete(struct xdp_req *xdp)
{
	xdp_ebpf_cb(xdp, -1, NULL);
	return 0;
}

int xdp_parse(int *argc, char ***argv, struct iplink_req *req, bool generic)
{
	struct bpf_cfg_in cfg = {
		.argc = *argc,
		.argv = *argv,
	};
	struct xdp_req xdp = {
		.req = req,
	};

	if (!force)
		xdp.flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
	if (generic)
		xdp.flags |= XDP_FLAGS_SKB_MODE;

	if (*argc == 1) {
		if (strcmp(**argv, "none") == 0 ||
		    strcmp(**argv, "off") == 0)
			return xdp_delete(&xdp);
	}

	if (bpf_parse_common(BPF_PROG_TYPE_XDP, &cfg, &bpf_cb_ops, &xdp))
		return -1;

	*argc = cfg.argc;
	*argv = cfg.argv;
	return 0;
}

void xdp_dump(FILE *fp, struct rtattr *xdp)
{
	struct rtattr *tb[IFLA_XDP_MAX + 1];
	__u32 flags = 0;

	parse_rtattr_nested(tb, IFLA_XDP_MAX, xdp);

	if (!tb[IFLA_XDP_ATTACHED] ||
	    !rta_getattr_u8(tb[IFLA_XDP_ATTACHED]))
		return;

	if (tb[IFLA_XDP_FLAGS])
		flags = rta_getattr_u32(tb[IFLA_XDP_FLAGS]);

	fprintf(fp, "xdp%s ",
		flags & XDP_FLAGS_SKB_MODE ? "generic" : "");
}
