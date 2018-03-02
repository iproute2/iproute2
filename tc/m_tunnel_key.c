/*
 * m_tunnel_key.c	ip tunnel manipulation module
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Amir Vadai <amir@vadai.me>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_ether.h>
#include "utils.h"
#include "rt_names.h"
#include "tc_util.h"
#include <linux/tc_act/tc_tunnel_key.h>

static void explain(void)
{
	fprintf(stderr, "Usage: tunnel_key unset\n");
	fprintf(stderr, "       tunnel_key set <TUNNEL_KEY>\n");
	fprintf(stderr,
		"Where TUNNEL_KEY is a combination of:\n"
		"id <TUNNELID> (mandatory)\n"
		"src_ip <IP> (mandatory)\n"
		"dst_ip <IP> (mandatory)\n"
		"dst_port <UDP_PORT>\n"
		"csum | nocsum (default is \"csum\")\n");
}

static void usage(void)
{
	explain();
	exit(-1);
}

static int tunnel_key_parse_ip_addr(const char *str, int addr4_type,
				    int addr6_type, struct nlmsghdr *n)
{
	inet_prefix addr;
	int ret;

	ret = get_addr(&addr, str, AF_UNSPEC);
	if (ret)
		return ret;

	addattr_l(n, MAX_MSG, addr.family == AF_INET ? addr4_type : addr6_type,
		  addr.data, addr.bytelen);

	return 0;
}

static int tunnel_key_parse_key_id(const char *str, int type,
				   struct nlmsghdr *n)
{
	__be32 key_id;
	int ret;

	ret = get_be32(&key_id, str, 10);
	if (!ret)
		addattr32(n, MAX_MSG, type, key_id);

	return ret;
}

static int tunnel_key_parse_dst_port(char *str, int type, struct nlmsghdr *n)
{
	int ret;
	__be16 dst_port;

	ret = get_be16(&dst_port, str, 10);
	if (ret)
		return -1;

	addattr16(n, MAX_MSG, type, dst_port);

	return 0;
}

static int parse_tunnel_key(struct action_util *a, int *argc_p, char ***argv_p,
			    int tca_id, struct nlmsghdr *n)
{
	struct tc_tunnel_key parm = {};
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail;
	int action = 0;
	int ret;
	int has_src_ip = 0;
	int has_dst_ip = 0;
	int has_key_id = 0;
	int csum = 1;

	if (matches(*argv, "tunnel_key") != 0)
		return -1;

	tail = NLMSG_TAIL(n);
	addattr_l(n, MAX_MSG, tca_id, NULL, 0);

	NEXT_ARG();

	while (argc > 0) {
		if (matches(*argv, "unset") == 0) {
			if (action) {
				fprintf(stderr, "unexpected \"%s\" - action already specified\n",
					*argv);
				explain();
				return -1;
			}
			action = TCA_TUNNEL_KEY_ACT_RELEASE;
		} else if (matches(*argv, "set") == 0) {
			if (action) {
				fprintf(stderr, "unexpected \"%s\" - action already specified\n",
					*argv);
				explain();
				return -1;
			}
			action = TCA_TUNNEL_KEY_ACT_SET;
		} else if (matches(*argv, "src_ip") == 0) {
			NEXT_ARG();
			ret = tunnel_key_parse_ip_addr(*argv,
						       TCA_TUNNEL_KEY_ENC_IPV4_SRC,
						       TCA_TUNNEL_KEY_ENC_IPV6_SRC,
						       n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"src_ip\"\n");
				return -1;
			}
			has_src_ip = 1;
		} else if (matches(*argv, "dst_ip") == 0) {
			NEXT_ARG();
			ret = tunnel_key_parse_ip_addr(*argv,
						       TCA_TUNNEL_KEY_ENC_IPV4_DST,
						       TCA_TUNNEL_KEY_ENC_IPV6_DST,
						       n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"dst_ip\"\n");
				return -1;
			}
			has_dst_ip = 1;
		} else if (matches(*argv, "id") == 0) {
			NEXT_ARG();
			ret = tunnel_key_parse_key_id(*argv, TCA_TUNNEL_KEY_ENC_KEY_ID, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"id\"\n");
				return -1;
			}
			has_key_id = 1;
		} else if (matches(*argv, "dst_port") == 0) {
			NEXT_ARG();
			ret = tunnel_key_parse_dst_port(*argv,
							TCA_TUNNEL_KEY_ENC_DST_PORT, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"dst port\"\n");
				return -1;
			}
		} else if (matches(*argv, "csum") == 0) {
			csum = 1;
		} else if (matches(*argv, "nocsum") == 0) {
			csum = 0;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}
		NEXT_ARG_FWD();
	}

	addattr8(n, MAX_MSG, TCA_TUNNEL_KEY_NO_CSUM, !csum);

	parse_action_control_dflt(&argc, &argv, &parm.action,
				  false, TC_ACT_PIPE);

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&parm.index, *argv, 10)) {
				fprintf(stderr, "tunnel_key: Illegal \"index\"\n");
				return -1;
			}

			NEXT_ARG_FWD();
		}
	}

	if (action == TCA_TUNNEL_KEY_ACT_SET &&
	    (!has_src_ip || !has_dst_ip || !has_key_id)) {
		fprintf(stderr, "set needs tunnel_key parameters\n");
		explain();
		return -1;
	}

	parm.t_action = action;
	addattr_l(n, MAX_MSG, TCA_TUNNEL_KEY_PARMS, &parm, sizeof(parm));
	tail->rta_len = (char *)NLMSG_TAIL(n) - (char *)tail;

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static void tunnel_key_print_ip_addr(FILE *f, const char *name,
				     struct rtattr *attr)
{
	int family;
	size_t len;

	if (!attr)
		return;

	len = RTA_PAYLOAD(attr);

	if (len == 4)
		family = AF_INET;
	else if (len == 16)
		family = AF_INET6;
	else
		return;

	fprintf(f, "\n\t%s %s", name, rt_addr_n2a_rta(family, attr));
}

static void tunnel_key_print_key_id(FILE *f, const char *name,
				    struct rtattr *attr)
{
	if (!attr)
		return;
	fprintf(f, "\n\t%s %d", name, rta_getattr_be32(attr));
}

static void tunnel_key_print_dst_port(FILE *f, char *name,
				      struct rtattr *attr)
{
	if (!attr)
		return;
	fprintf(f, "\n\t%s %d", name, rta_getattr_be16(attr));
}

static void tunnel_key_print_flag(FILE *f, const char *name_on,
				  const char *name_off,
				  struct rtattr *attr)
{
	if (!attr)
		return;
	fprintf(f, "\n\t%s", rta_getattr_u8(attr) ? name_on : name_off);
}

static int print_tunnel_key(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_TUNNEL_KEY_MAX + 1];
	struct tc_tunnel_key *parm;

	if (!arg)
		return -1;

	parse_rtattr_nested(tb, TCA_TUNNEL_KEY_MAX, arg);

	if (!tb[TCA_TUNNEL_KEY_PARMS]) {
		fprintf(f, "[NULL tunnel_key parameters]");
		return -1;
	}
	parm = RTA_DATA(tb[TCA_TUNNEL_KEY_PARMS]);

	fprintf(f, "tunnel_key");

	switch (parm->t_action) {
	case TCA_TUNNEL_KEY_ACT_RELEASE:
		fprintf(f, " unset");
		break;
	case TCA_TUNNEL_KEY_ACT_SET:
		fprintf(f, " set");
		tunnel_key_print_ip_addr(f, "src_ip",
					 tb[TCA_TUNNEL_KEY_ENC_IPV4_SRC]);
		tunnel_key_print_ip_addr(f, "dst_ip",
					 tb[TCA_TUNNEL_KEY_ENC_IPV4_DST]);
		tunnel_key_print_ip_addr(f, "src_ip",
					 tb[TCA_TUNNEL_KEY_ENC_IPV6_SRC]);
		tunnel_key_print_ip_addr(f, "dst_ip",
					 tb[TCA_TUNNEL_KEY_ENC_IPV6_DST]);
		tunnel_key_print_key_id(f, "key_id",
					tb[TCA_TUNNEL_KEY_ENC_KEY_ID]);
		tunnel_key_print_dst_port(f, "dst_port",
					  tb[TCA_TUNNEL_KEY_ENC_DST_PORT]);
		tunnel_key_print_flag(f, "nocsum", "csum",
				      tb[TCA_TUNNEL_KEY_NO_CSUM]);
		break;
	}
	print_action_control(f, " ", parm->action, "");

	fprintf(f, "\n\tindex %d ref %d bind %d", parm->index, parm->refcnt,
		parm->bindcnt);

	if (show_stats) {
		if (tb[TCA_TUNNEL_KEY_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_TUNNEL_KEY_TM]);

			print_tm(f, tm);
		}
	}

	fprintf(f, "\n ");

	return 0;
}

struct action_util tunnel_key_action_util = {
	.id = "tunnel_key",
	.parse_aopt = parse_tunnel_key,
	.print_aopt = print_tunnel_key,
};
