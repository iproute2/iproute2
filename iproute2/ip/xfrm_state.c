/* $USAGI: $ */

/*
 * Copyright (C)2004 USAGI/WIDE Project
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * based on iproute.c
 */
/*
 * Authors:
 *	Masahide NAKAMURA @USAGI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <linux/xfrm.h>
#include "utils.h"
#include "xfrm.h"
#include "ip_common.h"

//#define NLMSG_FLUSH_BUF_SIZE (4096-512)
#define NLMSG_FLUSH_BUF_SIZE 8192

/*
 * Receiving buffer defines:
 * nlmsg
 *   data = struct xfrm_usersa_info
 *   rtattr
 *   rtattr
 *   ... (max count of rtattr is XFRM_MAX_DEPTH)
 *
 *  each rtattr data = struct xfrm_algo(dynamic size) or xfrm_address_t
 */
#define NLMSG_BUF_SIZE 4096
#define RTA_BUF_SIZE 2048
#define XFRM_ALGO_KEY_BUF_SIZE 512

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
#ifdef USE_MIP6
	fprintf(stderr, "Usage: ip xfrm state { add | update } ID [ XFRM_OPT ] [ mode MODE ]\n");
#else
	fprintf(stderr, "Usage: ip xfrm state { add | update } ID [ ALGO-LIST ] [ mode MODE ]\n");
#endif
	fprintf(stderr, "        [ reqid REQID ] [ FLAG-LIST ] [ sel SELECTOR ] [ LIMIT-LIST ]\n");

	fprintf(stderr, "Usage: ip xfrm state { delete | get } ID\n");
	fprintf(stderr, "Usage: ip xfrm state { flush | list } [ ID ] [ mode MODE ] [ reqid REQID ]\n");
	fprintf(stderr, "        [ FLAG_LIST ]\n");

	fprintf(stderr, "ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM_PROTO ] [ spi SPI ]\n");
#ifdef USE_MIP6
	fprintf(stderr, "XFRM_PROTO := [ esp | ah | ipcomp | route2 | hao ]\n");
#else
	fprintf(stderr, "XFRM_PROTO := [ esp | ah | ipcomp ]\n");
#endif
	//fprintf(stderr, "SPI - security parameter index(default=0)(PROTO=esp,ah,ipcomp)\n");

#ifdef USE_MIP6
	fprintf(stderr, "XFRM_OPT := [ ALGO-LIST ] | [ coa ADDR ]\n");
#endif

 	fprintf(stderr, "MODE := [ transport | tunnel ](default=transport)\n");
 	//fprintf(stderr, "REQID - number(default=0)\n");

	fprintf(stderr, "FLAG-LIST := [ FLAG-LIST ] [ flag FLAG ]\n");
	fprintf(stderr, "FLAG := [ noecn | wildrecv ]\n");

	fprintf(stderr, "ALGO-LIST := [ ALGO-LIST ] | [ algo ALGO ]\n");
	fprintf(stderr, "ALGO := ALGO_TYPE ALGO_NAME ALGO_KEY\n");
	fprintf(stderr, "ALGO_TYPE := [ E | A | C ]\n");
	//fprintf(stderr, "ALGO_NAME - algorithm name\n");
	//fprintf(stderr, "ALGO_KEY - algorithm key\n");

	fprintf(stderr, "SELECTOR := src ADDR[/PLEN] dst ADDR[/PLEN] [ upspec UPSPEC ] [ dev DEV ]\n");

	fprintf(stderr, "UPSPEC := proto PROTO [ UPSPEC_OPT ]\n");
	fprintf(stderr, "UPSPEC_OPT := [ [ sport PORT ] [ dport PORT ] ] |\n");
#ifdef USE_MIP6
	fprintf(stderr, "              [ type TYPE [ code CODE ] ](for PROTO=ipv6-icmp) |\n");
	fprintf(stderr, "              [ type TYPE ](for PROTO=ipv6-mh)\n");
#else
	fprintf(stderr, "              [ type TYPE [ code CODE ] ](for PROTO=ipv6-icmp)\n");
#endif

	//fprintf(stderr, "DEV - device name(default=none)\n");
	fprintf(stderr, "LIMIT-LIST := [ LIMIT-LIST ] | [ limit LIMIT ]\n");
	fprintf(stderr, "LIMIT := [ [time-soft|time-hard|time-use-soft|time-use-hard] SECONDS ] |\n");
	fprintf(stderr, "         [ [byte-soft|byte-hard] SIZE ] | [ [packet-soft|packet-hard] COUNT ]\n");
	exit(-1);
}

static int xfrm_algo_parse(struct xfrm_algo *alg, enum xfrm_attr_type_t type,
			   char *name, char *key, int max)
{
	int len;

#if 1
	/* XXX: verifying both name and key is required! */
	fprintf(stderr, "warning: ALGONAME/ALGOKEY will send to kernel promiscuously!(verifying them isn't implemented yet)\n");
#endif

	strncpy(alg->alg_name, name, sizeof(alg->alg_name));

	if (strncmp(key, "0x", 2) == 0) {
		/*
		 * XXX: fix me!!
		 */
		__u64 val = 0;
		char *p = (char *)&val;

		if (get_u64(&val, key, 16))
			invarg("\"ALGOKEY\" is invalid", key);

		len = (strlen(key) - 2) / 2;
		if (len > sizeof(val))
			invarg("\"ALGOKEY\" is invalid: too large", key);

		if (len > 0) {
			int index = sizeof(val) - len;
			if (len > max)
				invarg("\"ALGOKEY\" makes buffer overflow\n", key);

			memcpy(alg->alg_key, &p[index], len);
		}

	} else {
		len = strlen(key);
		if (len > 0) {
			if (len > max)
				invarg("\"ALGOKEY\" makes buffer overflow\n", key);

			strncpy(alg->alg_key, key, len);
		}
	}

	alg->alg_key_len = len * 8;

	return 0;
}

static int xfrm_state_flag_parse(__u8 *flags, int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;

	if (strcmp(*argv, "noecn") == 0)
		*flags |= XFRM_STATE_NOECN;
#ifdef USE_MIP6
	else if (strcmp(*argv, "wildrecv") == 0)
		*flags |= XFRM_STATE_WILDRECV;
#endif
	else
		invarg("\"FLAG\" is invalid", *argv);

	filter.state_flags_mask = XFRM_FILTER_MASK_FULL;

	*argcp = argc;
	*argvp = argv;

	return 0;
}

static int xfrm_state_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr 	n;
		struct xfrm_usersa_info xsinfo;
		char   			buf[RTA_BUF_SIZE];
	} req;
	char *idp = NULL;
	char *ealgop = NULL;
	char *aalgop = NULL;
	char *calgop = NULL;
#ifdef USE_MIP6
	char *coap = NULL;
#endif

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsinfo));
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = cmd;
	req.xsinfo.family = preferred_family;

	req.xsinfo.lft.soft_byte_limit = XFRM_INF;
	req.xsinfo.lft.hard_byte_limit = XFRM_INF;
	req.xsinfo.lft.soft_packet_limit = XFRM_INF;
	req.xsinfo.lft.hard_packet_limit = XFRM_INF;

	while (argc > 0) {
		if (strcmp(*argv, "algo") == 0) {
			struct {
				struct xfrm_algo alg;
				char buf[XFRM_ALGO_KEY_BUF_SIZE];
			} alg;
			int len;
			enum xfrm_attr_type_t type;
			char *name;
			char *key;

			NEXT_ARG();

			if (strcmp(*argv, "E") == 0) {
				if (ealgop)
					duparg("ALGOTYPE", *argv);
				ealgop = *argv;
				type = XFRMA_ALG_CRYPT;
			} else if (strcmp(*argv, "A") == 0) {
				if (aalgop)
					duparg("ALGOTYPE", *argv);
				aalgop = *argv;
				type = XFRMA_ALG_AUTH;

			} else if (strcmp(*argv, "C") == 0) {
				if (calgop)
					duparg("ALGOTYPE", *argv);
				calgop = *argv;
				type = XFRMA_ALG_COMP;
			} else
				invarg("\"ALGOTYPE\" is invalid\n", *argv);

			if (!NEXT_ARG_OK())
				missarg("ALGONAME");
			NEXT_ARG();
			name = *argv;

			if (!NEXT_ARG_OK())
				missarg("ALGOKEY");
			NEXT_ARG();
			key = *argv;

			memset(&alg, 0, sizeof(alg));

			xfrm_algo_parse((void *)&alg, type, name, key, sizeof(alg.buf));
			len = sizeof(struct xfrm_algo) + alg.alg.alg_key_len;

			addattr_l(&req.n, sizeof(req.buf), type,
				  (void *)&alg, len);

#ifdef USE_MIP6
		} else if (strcmp(*argv, "coa") == 0) {
			inet_prefix coa;

			if (coap)
				duparg("coa", *argv);
			coap = *argv;

			NEXT_ARG();

			get_prefix(&coa, *argv, req.xsinfo.family);
			if (req.xsinfo.family == AF_UNSPEC)
				req.xsinfo.family = coa.family;
			if (coa.bytelen)
				addattr_l(&req.n, sizeof(req.buf), XFRMA_ADDR,
					  &coa.data, coa.bytelen);

#endif
		} else if (strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
			xfrm_mode_parse(&req.xsinfo.mode, &argc, &argv);
		} else if (strcmp(*argv, "reqid") == 0) {
			NEXT_ARG();
			xfrm_reqid_parse(&req.xsinfo.reqid, &argc, &argv);
		} else if (strcmp(*argv, "flag") == 0) {
			NEXT_ARG();
			xfrm_state_flag_parse(&req.xsinfo.flags, &argc, &argv);
		} else if (strcmp(*argv, "sel") == 0) {
			NEXT_ARG();
			xfrm_selector_parse(&req.xsinfo.sel, &argc, &argv);

		} else if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			xfrm_lifetime_cfg_parse(&req.xsinfo.lft, &argc, &argv);
		} else {
			if (idp)
				invarg("unknown", *argv);
			idp = *argv;

			/* ID */
			xfrm_id_parse(&req.xsinfo.saddr, &req.xsinfo.id,
				      &req.xsinfo.family, &argc, &argv);
			if (preferred_family == AF_UNSPEC)
				preferred_family = req.xsinfo.family;
		}
		argc--; argv++;
	}

	if (!idp) {
		fprintf(stderr, "Not enough information: \"ID\" is required\n");
		exit(1);
	}

	if (ealgop || aalgop || calgop) {
		if (req.xsinfo.id.proto != IPPROTO_ESP &&
		    req.xsinfo.id.proto != IPPROTO_AH &&
		    req.xsinfo.id.proto != IPPROTO_COMP) {
			fprintf(stderr, "\"ALGO\" is invalid with proto=%d\n", req.xsinfo.id.proto);
			exit(1);
		}
	} else {
		if (req.xsinfo.id.proto == IPPROTO_ESP ||
		    req.xsinfo.id.proto == IPPROTO_AH ||
		    req.xsinfo.id.proto == IPPROTO_COMP) {
			fprintf(stderr, "\"ALGO\" is required with proto=%d\n", req.xsinfo.id.proto);
			exit (1);
		}
	}

#ifdef USE_MIP6
	if (coap) {
		if (req.xsinfo.id.proto != IPPROTO_ROUTING &&
		    req.xsinfo.id.proto != IPPROTO_DSTOPTS) {
			fprintf(stderr, "\"COA\" is invalid with proto=%d\n", req.xsinfo.id.proto);
			exit(1);
		}
	} else {
		if (req.xsinfo.id.proto == IPPROTO_ROUTING ||
		    req.xsinfo.id.proto == IPPROTO_DSTOPTS) {
			fprintf(stderr, "\"COA\" is required with proto=%d\n", req.xsinfo.id.proto);
			exit(1);
		}
	}
#endif

	if (req.xsinfo.id.spi) {
		if (req.xsinfo.id.proto == IPPROTO_ROUTING ||
		    req.xsinfo.id.proto == IPPROTO_DSTOPTS) {
			fprintf(stderr, "Invalid spi: %u (zero is requried) with proto=%d\n", ntohl(req.xsinfo.id.spi), req.xsinfo.id.proto);
			exit(1);
		}
	}

	if (req.xsinfo.mode) {
		if (req.xsinfo.id.proto == IPPROTO_ROUTING ||
		    req.xsinfo.id.proto == IPPROTO_DSTOPTS) {
			fprintf(stderr, "Invalid mode: (transport is requried) with proto=%d\n", req.xsinfo.id.proto);
			exit(1);
		}
	}

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (req.xsinfo.family == AF_UNSPEC)
		req.xsinfo.family = AF_INET;

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);

	rtnl_close(&rth);

	return 0;
}

static int xfrm_state_filter_match(struct xfrm_usersa_info *xsinfo)
{
	if (!filter.use)
		return 1;

	if (filter.id_src_mask)
		if (memcmp(&xsinfo->saddr, &filter.xsinfo.saddr,
			   filter.id_src_mask) != 0)
			return 0;
	if (filter.id_dst_mask)
		if (memcmp(&xsinfo->id.daddr, &filter.xsinfo.id.daddr,
			   filter.id_dst_mask) != 0)
			return 0;
	if ((xsinfo->id.proto^filter.xsinfo.id.proto)&filter.id_proto_mask)
		return 0;
	if ((xsinfo->id.spi^filter.xsinfo.id.spi)&filter.id_spi_mask)
		return 0;
	if ((xsinfo->mode^filter.xsinfo.mode)&filter.mode_mask)
		return 0;
	if ((xsinfo->reqid^filter.xsinfo.reqid)&filter.reqid_mask)
		return 0;
	if (filter.state_flags_mask)
		if ((xsinfo->flags & filter.xsinfo.flags) == 0)
			return 0;

	return 1;
}

int xfrm_state_print(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE*)arg;
	struct xfrm_usersa_info *xsinfo = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[XFRMA_MAX+1];
	int ntb;

	if (n->nlmsg_type != XFRM_MSG_NEWSA &&
	    n->nlmsg_type != XFRM_MSG_DELSA) {
		fprintf(stderr, "Not a state: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*xsinfo));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (!xfrm_state_filter_match(xsinfo))
		return 0;

	memset(tb, 0, sizeof(tb));
	ntb = parse_rtattr_byindex(tb, XFRM_MAX_DEPTH, XFRMS_RTA(xsinfo), len);

	if (n->nlmsg_type == XFRM_MSG_DELSA)
		fprintf(fp, "Deleted ");

	xfrm_id_info_print(&xsinfo->saddr, &xsinfo->id, xsinfo->mode,
			   xsinfo->reqid, xsinfo->family, fp, NULL);

	if (show_stats > 0) {
		fprintf(fp, "\t");
		fprintf(fp, "seq 0x%08u ", xsinfo->seq);
		fprintf(fp, "replay-window %d ", xsinfo->replay_window);
		fprintf(fp, "flags ");
		if (xsinfo->flags & XFRM_STATE_NOECN)
			fprintf(fp, "noecn ");
#ifdef USE_MIP6
		if (xsinfo->flags & XFRM_STATE_WILDRECV)
			fprintf(fp, "wildrecv ");
#endif
		fprintf(fp, "(0x%s)", strxf_flags(xsinfo->flags));

		fprintf(fp, "\n");
	}

	xfrm_xfrma_print(tb, ntb, xsinfo->family, fp, "\t");

	if (show_stats > 0) {
		fprintf(fp, "\tsel:\n");
		xfrm_selector_print(&xsinfo->sel, xsinfo->family, fp, "\t  ");
	}

	if (show_stats > 0) {
		xfrm_lifetime_print(&xsinfo->lft, &xsinfo->curlft, fp, "\t");
		xfrm_stats_print(&xsinfo->stats, fp, "\t");
	}

	return 0;
}

static int xfrm_state_get_or_delete(int argc, char **argv, int delete)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr 	n;
		struct xfrm_usersa_id	xsid;
	} req;
	struct xfrm_id id;
	char *idp = NULL;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsid));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = delete ? XFRM_MSG_DELSA : XFRM_MSG_GETSA;
	req.xsid.family = preferred_family;

	while (argc > 0) {
#ifndef USE_MIP6
		/*
		 * XXX: Source address is not used and ignore it to follow
		 * XXX: a manner of setkey e.g. in the case of deleting/getting
		 * XXX: message of IPsec SA.
		 */
		xfrm_address_t ignore_saddr;
#endif
		if (idp)
			invarg("unknown", *argv);
		idp = *argv;

		/* ID */
		memset(&id, 0, sizeof(id));
#ifdef USE_MIP6
		xfrm_id_parse(&req.xsid.saddr, &id, &req.xsid.family,
			      &argc, &argv);
#else
		xfrm_id_parse(&ignore_saddr, &id, &req.xsid.family,
			      &argc, &argv);
#endif
		memcpy(&req.xsid.daddr, &id.daddr, sizeof(req.xsid.daddr));
		req.xsid.spi = id.spi;
		req.xsid.proto = id.proto;

		argc--; argv++;
	}

	switch (req.xsid.proto) {
#ifdef USE_MIP6
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
		if (req.xsid.spi) {
			fprintf(stderr, "Invalid spi: %u (zero is requried) with proto=%d\n", req.xsid.spi, req.xsid.proto);
			exit(1);
		}
		break;
#endif
	default:
		break;
	}

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (req.xsid.family == AF_UNSPEC)
		req.xsid.family = AF_INET;

	if (delete) {
		if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
			exit(2);
	} else {
		char buf[NLMSG_BUF_SIZE];
		struct nlmsghdr *res_n = (struct nlmsghdr *)buf;

		memset(buf, 0, sizeof(buf));

		if (rtnl_talk(&rth, &req.n, 0, 0, res_n, NULL, NULL) < 0)
			exit(2);

		if (xfrm_state_print(NULL, res_n, (void*)stdout) < 0) {
			fprintf(stderr, "An error :-)\n");
			exit(1);
		}
	}

	rtnl_close(&rth);

	return 0;
}

/*
 * With an existing state of nlmsg, make new nlmsg for deleting the state
 * and store it to buffer.
 */
int xfrm_state_keep(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct xfrm_buffer *xb = (struct xfrm_buffer *)arg;
	struct rtnl_handle *rth = xb->rth;
	struct xfrm_usersa_info *xsinfo = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct nlmsghdr *new_n;
	struct xfrm_usersa_id *xsid;

	if (n->nlmsg_type != XFRM_MSG_NEWSA) {
		fprintf(stderr, "Not a state: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*xsinfo));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (!xfrm_state_filter_match(xsinfo))
		return 0;

	if (xb->offset > xb->size) {
		fprintf(stderr, "Flush buffer overflow\n");
		return -1;
	}

	new_n = (struct nlmsghdr *)(xb->buf + xb->offset);
	new_n->nlmsg_len = NLMSG_LENGTH(sizeof(*xsid));
	new_n->nlmsg_flags = NLM_F_REQUEST;
	new_n->nlmsg_type = XFRM_MSG_DELSA;
	new_n->nlmsg_seq = ++rth->seq;

	xsid = NLMSG_DATA(new_n);
	xsid->family = xsinfo->family;
	memcpy(&xsid->daddr, &xsinfo->id.daddr, sizeof(xsid->daddr));
#ifdef USE_MIP6
	memcpy(&xsid->saddr, &xsinfo->saddr, sizeof(xsid->saddr));
#endif
	xsid->spi = xsinfo->id.spi;
	xsid->proto = xsinfo->id.proto;

	xb->offset += new_n->nlmsg_len;
	xb->nlmsg_count ++;

	return 0;
}

static int xfrm_state_list_or_flush(int argc, char **argv, int flush)
{
	char *idp = NULL;
	struct rtnl_handle rth;

	filter.use = 1;
	filter.xsinfo.family = preferred_family;

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
			xfrm_mode_parse(&filter.xsinfo.mode, &argc, &argv);

			filter.mode_mask = XFRM_FILTER_MASK_FULL;

		} else if (strcmp(*argv, "reqid") == 0) {
			NEXT_ARG();
			xfrm_reqid_parse(&filter.xsinfo.reqid, &argc, &argv);

			filter.reqid_mask = XFRM_FILTER_MASK_FULL;

		} else if (strcmp(*argv, "flag") == 0) {
			NEXT_ARG();
			xfrm_state_flag_parse(&filter.xsinfo.flags, &argc, &argv);

			filter.state_flags_mask = XFRM_FILTER_MASK_FULL;

		} else {
			if (idp)
				invarg("unknown", *argv);
			idp = *argv;

			/* ID */
			xfrm_id_parse(&filter.xsinfo.saddr,
				      &filter.xsinfo.id,
					&filter.xsinfo.family, &argc, &argv);
			if (preferred_family == AF_UNSPEC)
				preferred_family = filter.xsinfo.family;
		}
		argc--; argv++;
	}

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (flush) {
		struct xfrm_buffer xb;
		char buf[NLMSG_FLUSH_BUF_SIZE];
		int i;

		xb.buf = buf;
		xb.size = sizeof(buf);
		xb.rth = &rth;

		for (i = 0; ; i++) {
			xb.offset = 0;
			xb.nlmsg_count = 0;

			if (show_stats > 1)
				fprintf(stderr, "Flush round = %d\n", i);

			if (rtnl_wilddump_request(&rth, preferred_family, XFRM_MSG_GETSA) < 0) {
				perror("Cannot send dump request");
				exit(1);
			}

			if (rtnl_dump_filter(&rth, xfrm_state_keep, &xb, NULL, NULL) < 0) {
				fprintf(stderr, "Flush terminated\n");
				exit(1);
			}
			if (xb.nlmsg_count == 0) {
				if (show_stats > 1)
					fprintf(stderr, "Flush completed\n");
				break;
			}

			if (rtnl_send(&rth, xb.buf, xb.offset) < 0) {
				perror("Failed to send flush request\n");
				exit(1);
			}
			if (show_stats > 1)
				fprintf(stderr, "Flushed nlmsg count = %d\n", xb.nlmsg_count);

			xb.offset = 0;
			xb.nlmsg_count = 0;
		}

	} else {
		if (rtnl_wilddump_request(&rth, preferred_family, XFRM_MSG_GETSA) < 0) {
			perror("Cannot send dump request");
			exit(1);
		}

		if (rtnl_dump_filter(&rth, xfrm_state_print, stdout, NULL, NULL) < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}
	}

	rtnl_close(&rth);

	exit(0);
}

int do_xfrm_state(int argc, char **argv)
{
	if (argc < 1)
		return xfrm_state_list_or_flush(0, NULL, 0);

#if 0
	/*
	 * NLM_F_X is not supported for xfrm in the kernel.
	 */
	if (matches(*argv, "add") == 0)
		return xfrm_state_modify(XFRM_MSG_NEWSA, NLM_F_CREATE|NLM_F_EXCL,
					 argc-1, argv+1);
	if (matches(*argv, "change") == 0 || strcmp(*argv, "chg") == 0)
		return xfrm_state_modify(XFRM_MSG_NEWSA, NLM_F_REPLACE,
					 argc-1, argv+1);
	if (matches(*argv, "replace") == 0)
		return xfrm_state_modify(XFRM_MSG_NEWSA, NLM_F_CREATE|NLM_F_REPLACE,
					 argc-1, argv+1);
	if (matches(*argv, "prepend") == 0)
		return xfrm_state_modify(XFRM_MSG_NEWSA, NLM_F_CREATE,
					 argc-1, argv+1);
	if (matches(*argv, "append") == 0)
		return xfrm_state_modify(XFRM_MSG_NEWSA, NLM_F_CREATE|NLM_F_APPEND,
					 argc-1, argv+1);
	if (matches(*argv, "test") == 0)
		return xfrm_state_modify(XFRM_MSG_NEWSA, NLM_F_EXCL,
					 argc-1, argv+1);
#else
	if (matches(*argv, "add") == 0)
		return xfrm_state_modify(XFRM_MSG_NEWSA, 0,
					 argc-1, argv+1);
#endif
	if (matches(*argv, "update") == 0)
		return xfrm_state_modify(XFRM_MSG_UPDSA, 0,
					 argc-1, argv+1);
	if (matches(*argv, "delete") == 0 || matches(*argv, "del") == 0)
		return xfrm_state_get_or_delete(argc-1, argv+1, 1);
	if (matches(*argv, "list") == 0 || matches(*argv, "show") == 0
	    || matches(*argv, "lst") == 0)
		return xfrm_state_list_or_flush(argc-1, argv+1, 0);
	if (matches(*argv, "get") == 0)
		return xfrm_state_get_or_delete(argc-1, argv+1, 0);
	if (matches(*argv, "flush") == 0)
		return xfrm_state_list_or_flush(argc-1, argv+1, 1);
	if (matches(*argv, "help") == 0)
		usage();
	fprintf(stderr, "Command \"%s\" is unknown, try \"ip xfrm state help\".\n", *argv);
	exit(-1);
}
