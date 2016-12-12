/*
 * iproute_lwtunnel.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Roopa Prabhu, <roopa@cumulusnetworks.com>
 *		Thomas Graf <tgraf@suug.ch>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/ila.h>
#include <linux/lwtunnel.h>
#include <linux/mpls_iptunnel.h>
#include <errno.h>

#include "rt_names.h"
#include "utils.h"
#include "iproute_lwtunnel.h"
#include "bpf_util.h"

static const char *format_encap_type(int type)
{
	switch (type) {
	case LWTUNNEL_ENCAP_MPLS:
		return "mpls";
	case LWTUNNEL_ENCAP_IP:
		return "ip";
	case LWTUNNEL_ENCAP_IP6:
		return "ip6";
	case LWTUNNEL_ENCAP_ILA:
		return "ila";
	case LWTUNNEL_ENCAP_BPF:
		return "bpf";
	default:
		return "unknown";
	}
}

static void encap_type_usage(void)
{
	int i;

	fprintf(stderr, "Usage: ip route ... encap TYPE [ OPTIONS ] [...]\n");

	for (i = 1; i <= LWTUNNEL_ENCAP_MAX; i++)
		fprintf(stderr, "%s %s\n", format_encap_type(i),
			i == 1 ? "TYPE := " : "      ");

	exit(-1);
}

static int read_encap_type(const char *name)
{
	if (strcmp(name, "mpls") == 0)
		return LWTUNNEL_ENCAP_MPLS;
	else if (strcmp(name, "ip") == 0)
		return LWTUNNEL_ENCAP_IP;
	else if (strcmp(name, "ip6") == 0)
		return LWTUNNEL_ENCAP_IP6;
	else if (strcmp(name, "ila") == 0)
		return LWTUNNEL_ENCAP_ILA;
	else if (strcmp(name, "bpf") == 0)
		return LWTUNNEL_ENCAP_BPF;
	else if (strcmp(name, "help") == 0)
		encap_type_usage();

	return LWTUNNEL_ENCAP_NONE;
}

static void print_encap_mpls(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[MPLS_IPTUNNEL_MAX+1];

	parse_rtattr_nested(tb, MPLS_IPTUNNEL_MAX, encap);

	if (tb[MPLS_IPTUNNEL_DST])
		fprintf(fp, " %s ",
		        format_host_rta(AF_MPLS, tb[MPLS_IPTUNNEL_DST]));
}

static void print_encap_ip(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[LWTUNNEL_IP_MAX+1];

	parse_rtattr_nested(tb, LWTUNNEL_IP_MAX, encap);

	if (tb[LWTUNNEL_IP_ID])
		fprintf(fp, "id %llu ", ntohll(rta_getattr_u64(tb[LWTUNNEL_IP_ID])));

	if (tb[LWTUNNEL_IP_SRC])
		fprintf(fp, "src %s ",
			rt_addr_n2a_rta(AF_INET, tb[LWTUNNEL_IP_SRC]));

	if (tb[LWTUNNEL_IP_DST])
		fprintf(fp, "dst %s ",
			rt_addr_n2a_rta(AF_INET, tb[LWTUNNEL_IP_DST]));

	if (tb[LWTUNNEL_IP_TTL])
		fprintf(fp, "ttl %d ", rta_getattr_u8(tb[LWTUNNEL_IP_TTL]));

	if (tb[LWTUNNEL_IP_TOS])
		fprintf(fp, "tos %d ", rta_getattr_u8(tb[LWTUNNEL_IP_TOS]));
}

static char *ila_csum_mode2name(__u8 csum_mode)
{
	switch (csum_mode) {
	case ILA_CSUM_ADJUST_TRANSPORT:
		return "adj-transport";
	case ILA_CSUM_NEUTRAL_MAP:
		return "neutral-map";
	case ILA_CSUM_NO_ACTION:
		return "no-action";
	default:
		return "unknown";
	}
}

static __u8 ila_csum_name2mode(char *name)
{
	if (strcmp(name, "adj-transport") == 0)
		return ILA_CSUM_ADJUST_TRANSPORT;
	else if (strcmp(name, "neutral-map") == 0)
		return ILA_CSUM_NEUTRAL_MAP;
	else if (strcmp(name, "no-action") == 0)
		return ILA_CSUM_NO_ACTION;
	else
		return -1;
}

static void print_encap_ila(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[ILA_ATTR_MAX+1];

	parse_rtattr_nested(tb, ILA_ATTR_MAX, encap);

	if (tb[ILA_ATTR_LOCATOR]) {
		char abuf[ADDR64_BUF_SIZE];

		addr64_n2a(*(__u64 *)RTA_DATA(tb[ILA_ATTR_LOCATOR]),
			   abuf, sizeof(abuf));
		fprintf(fp, " %s ", abuf);
	}

	if (tb[ILA_ATTR_CSUM_MODE])
		fprintf(fp, " csum-mode %s ",
			ila_csum_mode2name(rta_getattr_u8(tb[ILA_ATTR_CSUM_MODE])));
}

static void print_encap_ip6(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[LWTUNNEL_IP6_MAX+1];

	parse_rtattr_nested(tb, LWTUNNEL_IP6_MAX, encap);

	if (tb[LWTUNNEL_IP6_ID])
		fprintf(fp, "id %llu ", ntohll(rta_getattr_u64(tb[LWTUNNEL_IP6_ID])));

	if (tb[LWTUNNEL_IP6_SRC])
		fprintf(fp, "src %s ",
			rt_addr_n2a_rta(AF_INET6, tb[LWTUNNEL_IP6_SRC]));

	if (tb[LWTUNNEL_IP6_DST])
		fprintf(fp, "dst %s ",
			rt_addr_n2a_rta(AF_INET6, tb[LWTUNNEL_IP6_DST]));

	if (tb[LWTUNNEL_IP6_HOPLIMIT])
		fprintf(fp, "hoplimit %d ", rta_getattr_u8(tb[LWTUNNEL_IP6_HOPLIMIT]));

	if (tb[LWTUNNEL_IP6_TC])
		fprintf(fp, "tc %d ", rta_getattr_u8(tb[LWTUNNEL_IP6_TC]));
}

static void print_encap_bpf_prog(FILE *fp, struct rtattr *encap,
				 const char *str)
{
	struct rtattr *tb[LWT_BPF_PROG_MAX+1];

	parse_rtattr_nested(tb, LWT_BPF_PROG_MAX, encap);
	fprintf(fp, "%s ", str);

	if (tb[LWT_BPF_PROG_NAME])
		fprintf(fp, "%s ", rta_getattr_str(tb[LWT_BPF_PROG_NAME]));
}

static void print_encap_bpf(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[LWT_BPF_MAX+1];

	parse_rtattr_nested(tb, LWT_BPF_MAX, encap);

	if (tb[LWT_BPF_IN])
		print_encap_bpf_prog(fp, tb[LWT_BPF_IN], "in");
	if (tb[LWT_BPF_OUT])
		print_encap_bpf_prog(fp, tb[LWT_BPF_OUT], "out");
	if (tb[LWT_BPF_XMIT])
		print_encap_bpf_prog(fp, tb[LWT_BPF_XMIT], "xmit");
	if (tb[LWT_BPF_XMIT_HEADROOM])
		fprintf(fp, "%d ", rta_getattr_u32(tb[LWT_BPF_XMIT_HEADROOM]));
}

void lwt_print_encap(FILE *fp, struct rtattr *encap_type,
			  struct rtattr *encap)
{
	int et;

	if (!encap_type)
		return;

	et = rta_getattr_u16(encap_type);

	fprintf(fp, " encap %s ", format_encap_type(et));

	switch (et) {
	case LWTUNNEL_ENCAP_MPLS:
		print_encap_mpls(fp, encap);
		break;
	case LWTUNNEL_ENCAP_IP:
		print_encap_ip(fp, encap);
		break;
	case LWTUNNEL_ENCAP_ILA:
		print_encap_ila(fp, encap);
		break;
	case LWTUNNEL_ENCAP_IP6:
		print_encap_ip6(fp, encap);
		break;
	case LWTUNNEL_ENCAP_BPF:
		print_encap_bpf(fp, encap);
		break;
	}
}

static int parse_encap_mpls(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
	inet_prefix addr;
	int argc = *argcp;
	char **argv = *argvp;

	if (get_addr(&addr, *argv, AF_MPLS)) {
		fprintf(stderr, "Error: an inet address is expected rather than \"%s\".\n", *argv);
		exit(1);
	}

	rta_addattr_l(rta, len, MPLS_IPTUNNEL_DST, &addr.data,
		      addr.bytelen);

	*argcp = argc;
	*argvp = argv;

	return 0;
}

static int parse_encap_ip(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
	int id_ok = 0, dst_ok = 0, tos_ok = 0, ttl_ok = 0;
	char **argv = *argvp;
	int argc = *argcp;

	while (argc > 0) {
		if (strcmp(*argv, "id") == 0) {
			__u64 id;

			NEXT_ARG();
			if (id_ok++)
				duparg2("id", *argv);
			if (get_be64(&id, *argv, 0))
				invarg("\"id\" value is invalid\n", *argv);
			rta_addattr64(rta, len, LWTUNNEL_IP_ID, id);
		} else if (strcmp(*argv, "dst") == 0) {
			inet_prefix addr;

			NEXT_ARG();
			if (dst_ok++)
				duparg2("dst", *argv);
			get_addr(&addr, *argv, AF_INET);
			rta_addattr_l(rta, len, LWTUNNEL_IP_DST, &addr.data, addr.bytelen);
		} else if (strcmp(*argv, "tos") == 0) {
			__u32 tos;

			NEXT_ARG();
			if (tos_ok++)
				duparg2("tos", *argv);
			if (rtnl_dsfield_a2n(&tos, *argv))
				invarg("\"tos\" value is invalid\n", *argv);
			rta_addattr8(rta, len, LWTUNNEL_IP_TOS, tos);
		} else if (strcmp(*argv, "ttl") == 0) {
			__u8 ttl;

			NEXT_ARG();
			if (ttl_ok++)
				duparg2("ttl", *argv);
			if (get_u8(&ttl, *argv, 0))
				invarg("\"ttl\" value is invalid\n", *argv);
			rta_addattr8(rta, len, LWTUNNEL_IP_TTL, ttl);
		} else {
			break;
		}
		argc--; argv++;
	}

	/* argv is currently the first unparsed argument,
	 * but the lwt_parse_encap() caller will move to the next,
	 * so step back */
	*argcp = argc + 1;
	*argvp = argv - 1;

	return 0;
}

static int parse_encap_ila(struct rtattr *rta, size_t len,
			   int *argcp, char ***argvp)
{
	__u64 locator;
	int argc = *argcp;
	char **argv = *argvp;

	if (get_addr64(&locator, *argv) < 0) {
		fprintf(stderr, "Bad locator: %s\n", *argv);
		exit(1);
	}

	argc--; argv++;

	rta_addattr64(rta, 1024, ILA_ATTR_LOCATOR, locator);

	while (argc > 0) {
		if (strcmp(*argv, "csum-mode") == 0) {
			__u8 csum_mode;

			NEXT_ARG();

			csum_mode = ila_csum_name2mode(*argv);
			if (csum_mode < 0)
				invarg("\"csum-mode\" value is invalid\n", *argv);

			rta_addattr8(rta, 1024, ILA_ATTR_CSUM_MODE, csum_mode);

			argc--; argv++;
		} else {
			break;
		}
	}

	/* argv is currently the first unparsed argument,
	 * but the lwt_parse_encap() caller will move to the next,
	 * so step back
	 */
	*argcp = argc + 1;
	*argvp = argv - 1;

	return 0;
}

static int parse_encap_ip6(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
	int id_ok = 0, dst_ok = 0, tos_ok = 0, ttl_ok = 0;
	char **argv = *argvp;
	int argc = *argcp;

	while (argc > 0) {
		if (strcmp(*argv, "id") == 0) {
			__u64 id;

			NEXT_ARG();
			if (id_ok++)
				duparg2("id", *argv);
			if (get_be64(&id, *argv, 0))
				invarg("\"id\" value is invalid\n", *argv);
			rta_addattr64(rta, len, LWTUNNEL_IP6_ID, id);
		} else if (strcmp(*argv, "dst") == 0) {
			inet_prefix addr;

			NEXT_ARG();
			if (dst_ok++)
				duparg2("dst", *argv);
			get_addr(&addr, *argv, AF_INET6);
			rta_addattr_l(rta, len, LWTUNNEL_IP6_DST, &addr.data, addr.bytelen);
		} else if (strcmp(*argv, "tc") == 0) {
			__u32 tc;

			NEXT_ARG();
			if (tos_ok++)
				duparg2("tc", *argv);
			if (rtnl_dsfield_a2n(&tc, *argv))
				invarg("\"tc\" value is invalid\n", *argv);
			rta_addattr8(rta, len, LWTUNNEL_IP6_TC, tc);
		} else if (strcmp(*argv, "hoplimit") == 0) {
			__u8 hoplimit;

			NEXT_ARG();
			if (ttl_ok++)
				duparg2("hoplimit", *argv);
			if (get_u8(&hoplimit, *argv, 0))
				invarg("\"hoplimit\" value is invalid\n", *argv);
			rta_addattr8(rta, len, LWTUNNEL_IP6_HOPLIMIT, hoplimit);
		} else {
			break;
		}
		argc--; argv++;
	}

	/* argv is currently the first unparsed argument,
	 * but the lwt_parse_encap() caller will move to the next,
	 * so step back */
	*argcp = argc + 1;
	*argvp = argv - 1;

	return 0;
}

struct lwt_x {
	struct rtattr *rta;
	size_t len;
};

static void bpf_lwt_cb(void *lwt_ptr, int fd, const char *annotation)
{
	struct lwt_x *x = lwt_ptr;

	rta_addattr32(x->rta, x->len, LWT_BPF_PROG_FD, fd);
	rta_addattr_l(x->rta, x->len, LWT_BPF_PROG_NAME, annotation,
		      strlen(annotation) + 1);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.ebpf_cb = bpf_lwt_cb,
};

static int lwt_parse_bpf(struct rtattr *rta, size_t len, int *argcp, char ***argvp,
			 int attr, const enum bpf_prog_type bpf_type)
{
	struct bpf_cfg_in cfg = {
		.argc = *argcp,
		.argv = *argvp,
	};
	struct lwt_x x = {
		.rta = rta,
		.len = len,
	};
	struct rtattr *nest;
	int err;

	nest = rta_nest(rta, len, attr);
	err = bpf_parse_common(bpf_type, &cfg, &bpf_cb_ops, &x);
	if (err < 0) {
		fprintf(stderr, "Failed to parse eBPF program: %s\n", strerror(err));
		return -1;
	}
	rta_nest_end(rta, nest);

	*argcp = cfg.argc;
	*argvp = cfg.argv;

	return 0;
}

static void lwt_bpf_usage(void)
{
	fprintf(stderr, "Usage: ip route ... encap bpf [ in BPF ] [ out BPF ] [ xmit BPF ] [...]\n");
	fprintf(stderr, "BPF := obj FILE [ section NAME ] [ verbose ]\n");
	exit(-1);
}

static int parse_encap_bpf(struct rtattr *rta, size_t len, int *argcp,
			   char ***argvp)
{
	char **argv = *argvp;
	int argc = *argcp;
	int headroom_set = 0;

	while (argc > 0) {
		if (strcmp(*argv, "in") == 0) {
			NEXT_ARG();
			if (lwt_parse_bpf(rta, len, &argc, &argv, LWT_BPF_IN,
					  BPF_PROG_TYPE_LWT_IN) < 0)
				return -1;
		} else if (strcmp(*argv, "out") == 0) {
			NEXT_ARG();
			if (lwt_parse_bpf(rta, len, &argc, &argv, LWT_BPF_OUT,
					  BPF_PROG_TYPE_LWT_OUT) < 0)
				return -1;
		} else if (strcmp(*argv, "xmit") == 0) {
			NEXT_ARG();
			if (lwt_parse_bpf(rta, len, &argc, &argv, LWT_BPF_XMIT,
					  BPF_PROG_TYPE_LWT_XMIT) < 0)
				return -1;
		} else if (strcmp(*argv, "headroom") == 0) {
			unsigned int headroom;

			NEXT_ARG();
			if (get_unsigned(&headroom, *argv, 0) || headroom == 0)
				invarg("headroom is invalid\n", *argv);
			if (!headroom_set)
				rta_addattr32(rta, 1024, LWT_BPF_XMIT_HEADROOM,
					      headroom);
			headroom_set = 1;
		} else if (strcmp(*argv, "help") == 0) {
			lwt_bpf_usage();
		} else {
			break;
		}
		NEXT_ARG_FWD();
	}

	/* argv is currently the first unparsed argument,
	 * but the lwt_parse_encap() caller will move to the next,
	 * so step back */
	*argcp = argc + 1;
	*argvp = argv - 1;

	return 0;
}

int lwt_parse_encap(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
	struct rtattr *nest;
	int argc = *argcp;
	char **argv = *argvp;
	__u16 type;

	NEXT_ARG();
	type = read_encap_type(*argv);
	if (!type)
		invarg("\"encap type\" value is invalid\n", *argv);

	NEXT_ARG();
	if (argc <= 1) {
		fprintf(stderr, "Error: unexpected end of line after \"encap\"\n");
		exit(-1);
	}

	nest = rta_nest(rta, 1024, RTA_ENCAP);
	switch (type) {
	case LWTUNNEL_ENCAP_MPLS:
		parse_encap_mpls(rta, len, &argc, &argv);
		break;
	case LWTUNNEL_ENCAP_IP:
		parse_encap_ip(rta, len, &argc, &argv);
		break;
	case LWTUNNEL_ENCAP_ILA:
		parse_encap_ila(rta, len, &argc, &argv);
		break;
	case LWTUNNEL_ENCAP_IP6:
		parse_encap_ip6(rta, len, &argc, &argv);
		break;
	case LWTUNNEL_ENCAP_BPF:
		if (parse_encap_bpf(rta, len, &argc, &argv) < 0)
			exit(-1);
		break;
	default:
		fprintf(stderr, "Error: unsupported encap type\n");
		break;
	}
	rta_nest_end(rta, nest);

	rta_addattr16(rta, 1024, RTA_ENCAP_TYPE, type);

	*argcp = argc;
	*argvp = argv;

	return 0;
}
