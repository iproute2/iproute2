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

#include "json_print.h"
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

int xdp_parse(int *argc, char ***argv, struct iplink_req *req, bool generic,
	      bool drv, bool offload)
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
	if (drv)
		xdp.flags |= XDP_FLAGS_DRV_MODE;
	if (offload)
		xdp.flags |= XDP_FLAGS_HW_MODE;

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

static void xdp_dump_json(struct rtattr *tb[IFLA_XDP_MAX + 1])
{
	__u32 prog_id = 0;
	__u8 mode;

	mode = rta_getattr_u8(tb[IFLA_XDP_ATTACHED]);
	if (tb[IFLA_XDP_PROG_ID])
		prog_id = rta_getattr_u32(tb[IFLA_XDP_PROG_ID]);

	open_json_object("xdp");
	print_uint(PRINT_JSON, "mode", NULL, mode);
	if (prog_id)
		bpf_dump_prog_info(NULL, prog_id);
	close_json_object();
}

void xdp_dump(FILE *fp, struct rtattr *xdp, bool link, bool details)
{
	struct rtattr *tb[IFLA_XDP_MAX + 1];
	__u32 prog_id = 0;
	__u8 mode;

	parse_rtattr_nested(tb, IFLA_XDP_MAX, xdp);

	if (!tb[IFLA_XDP_ATTACHED])
		return;

	mode = rta_getattr_u8(tb[IFLA_XDP_ATTACHED]);
	if (mode == XDP_ATTACHED_NONE)
		return;
	else if (is_json_context())
		return details ? (void)0 : xdp_dump_json(tb);
	else if (details && link)
		fprintf(fp, "%s    prog/xdp", _SL_);
	else if (mode == XDP_ATTACHED_DRV)
		fprintf(fp, "xdp");
	else if (mode == XDP_ATTACHED_SKB)
		fprintf(fp, "xdpgeneric");
	else if (mode == XDP_ATTACHED_HW)
		fprintf(fp, "xdpoffload");
	else
		fprintf(fp, "xdp[%u]", mode);

	if (tb[IFLA_XDP_PROG_ID])
		prog_id = rta_getattr_u32(tb[IFLA_XDP_PROG_ID]);
	if (!details) {
		if (prog_id && !link)
			fprintf(fp, "/id:%u", prog_id);
		fprintf(fp, " ");
		return;
	}

	if (prog_id) {
		fprintf(fp, " ");
		bpf_dump_prog_info(fp, prog_id);
	}
}
