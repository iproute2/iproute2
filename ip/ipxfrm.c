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
 * based on ip.c, iproute.c
 */
/*
 * Authors:
 *	Masahide NAKAMURA @USAGI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#include "utils.h"
#include "xfrm.h"

struct xfrm_filter filter;

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr, 
		"Usage: ip xfrm XFRM_OBJECT { COMMAND | help }\n"
		"where  XFRM_OBJECT := { state | policy }\n");
	exit(-1);
}

struct typeent {
	const char *t_name;
	int t_type;
};

static const struct typeent algo_types[]= {
	{ "enc", XFRMA_ALG_CRYPT }, { "auth", XFRMA_ALG_AUTH },
	{ "comp", XFRMA_ALG_COMP }, { NULL, -1 }
};

int xfrm_algotype_getbyname(char *name)
{
	int i;

	for (i = 0; ; i++) {
		const struct typeent *t = &algo_types[i];
		if (!t->t_name || t->t_type == -1)
			break;

		if (strcmp(t->t_name, name) == 0)
			return t->t_type;
	}

	return -1;
}

const char *strxf_algotype(int type)
{
	int i;

	for (i = 0; ; i++) {
		const struct typeent *t = &algo_types[i];
		if (!t->t_name || t->t_type == -1)
			break;

		if (t->t_type == type)
			return t->t_name;
	}

	return NULL;
}

const char *strxf_flags(__u8 flags)
{
	static char str[16];
	const int sn = sizeof(flags) * 8 - 1;
	__u8 b;
	int i = 0;

	for (b = (1 << sn); b > 0; b >>= 1)
		str[i++] = ((b & flags) ? '1' : '0');
	str[i] = '\0';

	return str;
}

const char *strxf_share(__u8 share)
{
	static char str[32];

	switch (share) {
	case XFRM_SHARE_ANY:
		strcpy(str, "any");
		break;
	case XFRM_SHARE_SESSION:
		strcpy(str, "session");
		break;
	case XFRM_SHARE_USER:
		strcpy(str, "user");
		break;
	case XFRM_SHARE_UNIQUE:
		strcpy(str, "unique");
		break;
	default:
		sprintf(str, "%d", share);
		break;
	}

	return str;
}

const char *strxf_proto(__u8 proto)
{
	static char buf[32];
	struct protoent *pp;
	const char *p;

	pp = getprotobynumber(proto);
	if (pp)
		p = pp->p_name;
	else {
		sprintf(buf, "%d", proto);
		p = buf;
	}

	return p;
}

void xfrm_id_info_print(xfrm_address_t *saddr, struct xfrm_id *id,
			__u8 mode, __u32 reqid, __u16 family, FILE *fp,
			const char *prefix)
{
	char abuf[256];
	__u32 spi;

	if (prefix)
		fprintf(fp, prefix);

	memset(abuf, '\0', sizeof(abuf));
	fprintf(fp, "src %s ", rt_addr_n2a(family, sizeof(*saddr),
					   saddr, abuf, sizeof(abuf)));
	memset(abuf, '\0', sizeof(abuf));
	fprintf(fp, "dst %s", rt_addr_n2a(family, sizeof(id->daddr),
					  &id->daddr, abuf, sizeof(abuf)));
	fprintf(fp, "%s", _SL_);

	if (prefix)
		fprintf(fp, prefix);
	fprintf(fp, "\t");

	fprintf(fp, "proto %s ", strxf_proto(id->proto));

	spi = ntohl(id->spi);
	fprintf(fp, "spi 0x%08x", spi);
	if (show_stats > 0)
		fprintf(fp, "(%u)", spi);
	fprintf(fp, " ");

	fprintf(fp, "reqid %u", reqid);
	if (show_stats > 0)
		fprintf(fp, "(0x%08x)", reqid);
	fprintf(fp, " ");

	fprintf(fp, "mode ");
	switch (mode) {
	case 0:
		fprintf(fp, "transport");
		break;
	case 1:
		fprintf(fp, "tunnel");
		break;
	default:
		fprintf(fp, "%u", mode);
		break;
	}
	fprintf(fp, "%s", _SL_);
}

static const char *strxf_limit(__u64 limit)
{
	static char str[32];
	if (limit == XFRM_INF)
		strcpy(str, "(INF)");
	else
		sprintf(str, "%llu", limit);

	return str;
}

void xfrm_stats_print(struct xfrm_stats *s, FILE *fp, const char *prefix)
{
	if (prefix)
		fprintf(fp, prefix);
	fprintf(fp, "stats:");
	fprintf(fp, "%s", _SL_);

	if (prefix)
		fprintf(fp, prefix);
	fprintf(fp, "  ");
	fprintf(fp, "replay-window %d ", s->replay_window);
	fprintf(fp, "replay %d ", s->replay);
	fprintf(fp, "failed %d", s->integrity_failed);
	fprintf(fp, "%s", _SL_);
}

static const char *strxf_time(__u64 time)
{
	static char str[32];

	if (time == 0)
		strcpy(str, "-");
	else {
		time_t t;
		struct tm *tp;

		/* XXX: treat time in the same manner of kernel's 
		 * net/xfrm/xfrm_{user,state}.c
		 */
		t = (long)time;
		tp = localtime(&t);

		strftime(str, sizeof(str), "%F %T", tp);
	}

	return str;
}

void xfrm_lifetime_print(struct xfrm_lifetime_cfg *cfg,
			 struct xfrm_lifetime_cur *cur,
			 FILE *fp, const char *prefix)
{
	if (cfg) {
		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "lifetime config:");
		fprintf(fp, "%s", _SL_);

		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "  ");
		fprintf(fp, "limit: ");
		fprintf(fp, "soft ");
		fprintf(fp, strxf_limit(cfg->soft_byte_limit));
		fprintf(fp, "(bytes), hard ");
		fprintf(fp, strxf_limit(cfg->hard_byte_limit));
		fprintf(fp, "(bytes)");
		fprintf(fp, "%s", _SL_);

		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "  ");
		fprintf(fp, "limit: ");
		fprintf(fp, "soft ");
		fprintf(fp, strxf_limit(cfg->soft_packet_limit));
		fprintf(fp, "(packets), hard ");
		fprintf(fp, strxf_limit(cfg->hard_packet_limit));
		fprintf(fp, "(packets)");
		fprintf(fp, "%s", _SL_);

		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "  ");
		fprintf(fp, "expire add: ");
		fprintf(fp, "soft ");
		fprintf(fp, "%llu", cfg->soft_add_expires_seconds);
		fprintf(fp, "(sec), hard ");
		fprintf(fp, "%llu", cfg->hard_add_expires_seconds);
		fprintf(fp, "(sec)");
		fprintf(fp, "%s", _SL_);

		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "  ");
		fprintf(fp, "expire use: ");
		fprintf(fp, "soft ");
		fprintf(fp, "%llu", cfg->soft_use_expires_seconds);
		fprintf(fp, "(sec), hard ");
		fprintf(fp, "%llu", cfg->hard_use_expires_seconds);
		fprintf(fp, "(sec)");
		fprintf(fp, "%s", _SL_);
	}
	if (cur) {
		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "lifetime current:");
		fprintf(fp, "%s", _SL_);

		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "  ");
		fprintf(fp, "%llu(bytes), ", cur->bytes);
		fprintf(fp, "%llu(packets)", cur->packets);
		fprintf(fp, "%s", _SL_);

		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "  ");
		fprintf(fp, "add %s ", strxf_time(cur->add_time));
		fprintf(fp, "use %s", strxf_time(cur->use_time));
		fprintf(fp, "%s", _SL_);
	}
}

void xfrm_selector_print(struct xfrm_selector *sel, __u16 family,
			 FILE *fp, const char *prefix)
{
	char abuf[256];
	__u16 f;

	f = sel->family;
	if (f == AF_UNSPEC)
		f = family;
	if (f == AF_UNSPEC)
		f = preferred_family;

	if (prefix)
		fprintf(fp, prefix);

	memset(abuf, '\0', sizeof(abuf));
	fprintf(fp, "src %s/%d ", rt_addr_n2a(f, sizeof(sel->saddr),
					      &sel->saddr, abuf, sizeof(abuf)),
		sel->prefixlen_s);

	memset(abuf, '\0', sizeof(abuf));
	fprintf(fp, "dst %s/%d ", rt_addr_n2a(f, sizeof(sel->daddr),
					      &sel->daddr, abuf, sizeof(abuf)),
		sel->prefixlen_d);

	if (sel->proto)
		fprintf(fp, "proto %s ", strxf_proto(sel->proto));
	if (sel->sport)
		fprintf(fp, "sport %u ", ntohs(sel->sport));
	if (sel->dport)
		fprintf(fp, "dport %u ", ntohs(sel->dport));

	if (sel->ifindex > 0) {
		char buf[IF_NAMESIZE];

		memset(buf, '\0', sizeof(buf));
		if_indextoname(sel->ifindex, buf);
		fprintf(fp, "dev %s ", buf);
	}

	if (show_stats > 0)
		fprintf(fp, "uid %u", sel->user);

	fprintf(fp, "%s", _SL_);
}

static void xfrm_algo_print(struct xfrm_algo *algo, int type, FILE *fp,
			    const char *prefix)
{
	int len;
	int i;

	if (prefix)
		fprintf(fp, prefix);

	fprintf(fp, "%s ", strxf_algotype(type));
	fprintf(fp, "%s ", algo->alg_name);

	fprintf(fp, "0x");
	len = algo->alg_key_len / 8;
	for (i = 0; i < len; i ++)
		fprintf(fp, "%.2x", (unsigned char)algo->alg_key[i]);

	if (show_stats > 0)
		fprintf(fp, " (%d bits)", algo->alg_key_len);

	fprintf(fp, "%s", _SL_);
}

static const char *strxf_mask(__u32 mask)
{
	static char str[128];
	const int sn = 	sizeof(mask) * 8 - 1;
	__u32 b;
	int finish = 0;
	int broken = 0;
	int i = 0;

	for (b = (1 << sn); b > 0; b >>= 1) {
		if ((b & mask) == 0) {
			if (!finish)
				finish = 1;
		} else {
			if (!finish)
				i ++;
			else {
				broken = 1;
				break;
			}
		}
	}

	if (!broken)
		sprintf(str, "%u", i);
	else
		sprintf(str, "broken(%u)", mask);

	return str;
}

static void xfrm_tmpl_print(struct xfrm_user_tmpl *tmpls, int ntmpls,
			    __u16 family, FILE *fp, const char *prefix)
{
	int i;

	for (i = 0; i < ntmpls; i++) {
		struct xfrm_user_tmpl *tmpl = &tmpls[i];

		if (prefix)
			fprintf(fp, prefix);

		fprintf(fp, "tmpl");
		xfrm_id_info_print(&tmpl->saddr, &tmpl->id, tmpl->mode,
				   tmpl->reqid, family, fp, prefix);

		if (prefix)
			fprintf(fp, prefix);
		fprintf(fp, "\t");
		switch (tmpl->optional) {
		case 0:
			if (show_stats > 0)
				fprintf(fp, "level required ");
			break;
		case 1:
			fprintf(fp, "level use ");
			break;
		default:
			fprintf(fp, "level %d ", tmpl->optional);
			break;
		}

		if (show_stats > 0) {
			fprintf(fp, "share %s ", strxf_share(tmpl->share));
			fprintf(fp, "algo-mask:");
			fprintf(fp, "%s=%s, ",
				strxf_algotype(XFRMA_ALG_CRYPT),
				strxf_mask(tmpl->ealgos));
			fprintf(fp, "%s=%s, ",
				strxf_algotype(XFRMA_ALG_AUTH),
				strxf_mask(tmpl->aalgos));
			fprintf(fp, "%s=%s",
				strxf_algotype(XFRMA_ALG_COMP),
				strxf_mask(tmpl->calgos));
		}
		fprintf(fp, "%s", _SL_);
	}
}

void xfrm_xfrma_print(struct rtattr *tb[], int ntb, __u16 family,
		      FILE *fp, const char *prefix)
{
	int i;

	for (i = 0; i < ntb; i++) {
		__u16 type = tb[i]->rta_type;
		void *data = RTA_DATA(tb[i]);

		switch (type) {
		case XFRMA_ALG_CRYPT:
		case XFRMA_ALG_AUTH:
		case XFRMA_ALG_COMP:
			xfrm_algo_print((struct xfrm_algo *)data, type, fp,
					prefix);
			break;
		case XFRMA_ENCAP:
			if (prefix)
				fprintf(fp, prefix);
			/* XXX */
			fprintf(fp, "encap (not implemented yet!)");
			fprintf(fp, "%s", _SL_);
			break;
		case XFRMA_TMPL:
		{
			int len = tb[i]->rta_len;
			int ntmpls = len / sizeof(struct xfrm_user_tmpl);

			xfrm_tmpl_print((struct xfrm_user_tmpl *)data,
					ntmpls, family, fp, prefix);
			break;
		}
		default:
			if (prefix)
				fprintf(fp, prefix);
			fprintf(fp, "%u (unknown rta_type)", type);
			fprintf(fp, "%s", _SL_);
			break;
		}
	}
}

int xfrm_id_parse(xfrm_address_t *saddr, struct xfrm_id *id, __u16 *family,
		  int loose, int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;
	inet_prefix dst;
	inet_prefix src;
	__u8 proto = 0;

	memset(&dst, 0, sizeof(dst));
	memset(&src, 0, sizeof(src));

	while (1) {
		if (strcmp(*argv, "src") == 0) {
			NEXT_ARG();

			get_prefix(&src, *argv, preferred_family);
			if (src.family == AF_UNSPEC)
				invarg("\"SADDR\" address family is AF_UNSPEC", *argv);
			if (family)
				*family = src.family;

			memcpy(saddr, &src.data, sizeof(*saddr));

			filter.id_src_mask = src.bitlen;

		} else if (strcmp(*argv, "dst") == 0) {
			NEXT_ARG();

			get_prefix(&dst, *argv, preferred_family);
			if (dst.family == AF_UNSPEC)
				invarg("\"DADDR\" address family is AF_UNSPEC", *argv);
			if (family)
				*family = dst.family;

			memcpy(&id->daddr, &dst.data, sizeof(id->daddr));

			filter.id_dst_mask = dst.bitlen;

		} else if (strcmp(*argv, "proto") == 0) {
			struct protoent *pp;

			NEXT_ARG();

			pp = getprotobyname(*argv);
			if (pp)
				proto = pp->p_proto;
			else {
				if (get_u8(&proto, *argv, 0))
					invarg("\"XFRM_PROTO\" is invalid", *argv);
			}

			switch (proto) {
			case IPPROTO_ESP:
			case IPPROTO_AH:
			case IPPROTO_COMP:
				id->proto = proto;
				break;
			default:
				invarg("\"XFRM_PROTO\" is unsuppored proto", *argv);
			}

			filter.id_proto_mask = XFRM_FILTER_MASK_FULL;

		} else if (strcmp(*argv, "spi") == 0) {
			__u32 spi;

			NEXT_ARG();
			if (get_u32(&spi, *argv, 0))
				invarg("\"SPI\" is invalid", *argv);

			spi = htonl(spi);
			id->spi = spi;

			filter.id_spi_mask = XFRM_FILTER_MASK_FULL;

		} else {
			PREV_ARG(); /* back track */
			break;
		}

		if (!NEXT_ARG_OK())
			break;
		NEXT_ARG();
	}

	if (src.family && dst.family && (src.family != dst.family))
		invarg("the same address family is required between \"SADDR\" and \"DADDR\"", *argv);

	if (loose == 0 && proto == 0)
		missarg("PROTO");
	if (argc == *argcp)
		missarg("ID");

	*argcp = argc;
	*argvp = argv;

	return 0;
}

int xfrm_mode_parse(__u8 *mode, int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;

	if (matches(*argv, "transport") == 0)
		*mode = 0;
	else if (matches(*argv, "tunnel") == 0)
		*mode = 1;
	else
		invarg("\"MODE\" is invalid", *argv);

	*argcp = argc;
	*argvp = argv;

	return 0;
}

/* NOTE: reqid is used by host-byte order */
int xfrm_reqid_parse(__u32 *reqid, int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;

	if (get_u32(reqid, *argv, 0))
		invarg("\"REQID\" is invalid", *argv);

	*argcp = argc;
	*argvp = argv;

	return 0;
}

static int xfrm_selector_upspec_parse(struct xfrm_selector *sel,
				      int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;

	while (1) {
		if (strcmp(*argv, "proto") == 0) {
			__u8 upspec;

			NEXT_ARG();

			if (strcmp(*argv, "any") == 0)
				upspec = 0;
			else {
				struct protoent *pp;
				pp = getprotobyname(*argv);
				if (pp)
					upspec = pp->p_proto;
				else {
					if (get_u8(&upspec, *argv, 0))
						invarg("\"PROTO\" is invalid", *argv);
				}
			}
			sel->proto = upspec;

			filter.upspec_proto_mask = XFRM_FILTER_MASK_FULL;

		} else if (strcmp(*argv, "sport") == 0) {
			NEXT_ARG();

			if (get_u16(&sel->sport, *argv, 0))
				invarg("\"PORT\" is invalid", *argv);
			sel->sport = htons(sel->sport);
			if (sel->sport)
				sel->sport_mask = ~((__u16)0);

			filter.upspec_sport_mask = XFRM_FILTER_MASK_FULL;

		} else if (strcmp(*argv, "dport") == 0) {
			NEXT_ARG();

			if (get_u16(&sel->dport, *argv, 0))
				invarg("\"PORT\" is invalid", *argv);
			sel->dport = htons(sel->dport);
			if (sel->dport)
				sel->dport_mask = ~((__u16)0);

			filter.upspec_dport_mask = XFRM_FILTER_MASK_FULL;

		} else {
			PREV_ARG(); /* back track */
			break;
		}

		if (!NEXT_ARG_OK())
			break;
		NEXT_ARG();
	}
	if (argc == *argcp)
		missarg("UPSPEC");

	*argcp = argc;
	*argvp = argv;

	return 0;
}

int xfrm_selector_parse(struct xfrm_selector *sel, int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;
	inet_prefix dst;
	inet_prefix src;
	char *upspecp = NULL;

	memset(&dst, 0, sizeof(dst));
	memset(&src, 0, sizeof(src));

	while (1) {
		if (strcmp(*argv, "src") == 0) {
			NEXT_ARG();

			get_prefix(&src, *argv, preferred_family);
			if (src.family == AF_UNSPEC)
				invarg("\"SADDR\" address family is AF_UNSPEC", *argv);
			sel->family = src.family;

			memcpy(&sel->saddr, &src.data, sizeof(sel->saddr));
			sel->prefixlen_s = src.bitlen;

			filter.sel_src_mask = src.bitlen;

		} else if (strcmp(*argv, "dst") == 0) {
			NEXT_ARG();

			get_prefix(&dst, *argv, preferred_family);
			if (dst.family == AF_UNSPEC)
				invarg("\"DADDR\" address family is AF_UNSPEC", *argv);
			sel->family = dst.family;

			memcpy(&sel->daddr, &dst.data, sizeof(sel->daddr));
			sel->prefixlen_d = dst.bitlen;

			filter.sel_dst_mask = dst.bitlen;

		} else if (strcmp(*argv, "dev") == 0) {
			int ifindex;

			NEXT_ARG();

			if (strcmp(*argv, "none") == 0)
				ifindex = 0;
			else {
				ifindex = if_nametoindex(*argv);
				if (ifindex <= 0)
					invarg("\"DEV\" is invalid", *argv);
			}
			sel->ifindex = ifindex;

			filter.sel_dev_mask = XFRM_FILTER_MASK_FULL;

		} else {
			if (upspecp) {
				PREV_ARG(); /* back track */
				break;
			} else {
				upspecp = *argv;
				xfrm_selector_upspec_parse(sel, &argc, &argv);
			}
		}

		if (!NEXT_ARG_OK())
			break;

		NEXT_ARG();
	}

	if (src.family && dst.family && (src.family != dst.family))
		invarg("the same address family is required between \"SADDR\" and \"DADDR\"", *argv);

	if (argc == *argcp)
		missarg("SELECTOR");

	*argcp = argc;
	*argvp = argv;

	return 0;
}

int xfrm_lifetime_cfg_parse(struct xfrm_lifetime_cfg *lft,
			    int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;
	int ret;

	if (strcmp(*argv, "time-soft") == 0) {
		NEXT_ARG();
		ret = get_u64(&lft->soft_add_expires_seconds, *argv, 0);
		if (ret)
			invarg("\"time-soft\" value is invalid", *argv);
	} else if (strcmp(*argv, "time-hard") == 0) {
		NEXT_ARG();
		ret = get_u64(&lft->hard_add_expires_seconds, *argv, 0);
		if (ret)
			invarg("\"time-hard\" value is invalid", *argv);
	} else if (strcmp(*argv, "time-use-soft") == 0) {
		NEXT_ARG();
		ret = get_u64(&lft->soft_use_expires_seconds, *argv, 0);
		if (ret)
			invarg("\"time-use-soft\" value is invalid", *argv);
	} else if (strcmp(*argv, "time-use-hard") == 0) {
		NEXT_ARG();
		ret = get_u64(&lft->hard_use_expires_seconds, *argv, 0);
		if (ret)
			invarg("\"time-use-hard\" value is invalid", *argv);
	} else if (strcmp(*argv, "byte-soft") == 0) {
		NEXT_ARG();
		ret = get_u64(&lft->soft_byte_limit, *argv, 0);
		if (ret)
			invarg("\"byte-soft\" value is invalid", *argv);
	} else if (strcmp(*argv, "byte-hard") == 0) {
		NEXT_ARG();
		ret = get_u64(&lft->hard_byte_limit, *argv, 0);
		if (ret)
			invarg("\"byte-hard\" value is invalid", *argv);
	} else if (strcmp(*argv, "packet-soft") == 0) {
		NEXT_ARG();
		ret = get_u64(&lft->soft_packet_limit, *argv, 0);
		if (ret)
			invarg("\"packet-soft\" value is invalid", *argv);
	} else if (strcmp(*argv, "packet-hard") == 0) {
		NEXT_ARG();
		ret = get_u64(&lft->hard_packet_limit, *argv, 0);
		if (ret)
			invarg("\"packet-hard\" value is invalid", *argv);
	} else
		invarg("\"LIMIT\" is invalid", *argv);

	*argcp = argc;
	*argvp = argv;

	return 0;
}

int do_xfrm(int argc, char **argv)
{
	memset(&filter, 0, sizeof(filter));

	if (argc < 1)
		usage();

	if (matches(*argv, "state") == 0 ||
	    matches(*argv, "sa") == 0) {
		return do_xfrm_state(argc-1, argv+1);
	} else if (matches(*argv, "policy") == 0)
		return do_xfrm_policy(argc-1, argv+1);
	else if (matches(*argv, "help") == 0) {
		usage();
		fprintf(stderr, "xfrm Object \"%s\" is unknown.\n", *argv);
		exit(-1);
	}
	usage();
}
