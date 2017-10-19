/*
 * iprule.c		"ip rule".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if.h>
#include <linux/fib_rules.h>
#include <errno.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

enum list_action {
	IPRULE_LIST,
	IPRULE_FLUSH,
	IPRULE_SAVE,
};

extern struct rtnl_handle rth;

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr,
		"Usage: ip rule { add | del } SELECTOR ACTION\n"
		"       ip rule { flush | save | restore }\n"
		"       ip rule [ list [ SELECTOR ]]\n"
		"SELECTOR := [ not ] [ from PREFIX ] [ to PREFIX ] [ tos TOS ] [ fwmark FWMARK[/MASK] ]\n"
		"            [ iif STRING ] [ oif STRING ] [ pref NUMBER ] [ l3mdev ]\n"
		"            [ uidrange NUMBER-NUMBER ]\n"
		"ACTION := [ table TABLE_ID ]\n"
		"          [ nat ADDRESS ]\n"
		"          [ realms [SRCREALM/]DSTREALM ]\n"
		"          [ goto NUMBER ]\n"
		"          SUPPRESSOR\n"
		"SUPPRESSOR := [ suppress_prefixlength NUMBER ]\n"
		"              [ suppress_ifgroup DEVGROUP ]\n"
		"TABLE_ID := [ local | main | default | NUMBER ]\n");
	exit(-1);
}

static struct
{
	int not;
	int l3mdev;
	int iifmask, oifmask, uidrange;
	unsigned int tb;
	unsigned int tos, tosmask;
	unsigned int pref, prefmask;
	unsigned int fwmark, fwmask;
	char iif[IFNAMSIZ];
	char oif[IFNAMSIZ];
	struct fib_rule_uid_range range;
	inet_prefix src;
	inet_prefix dst;
} filter;

static bool filter_nlmsg(struct nlmsghdr *n, struct rtattr **tb, int host_len)
{
	struct rtmsg *r = NLMSG_DATA(n);
	inet_prefix src = { .family = r->rtm_family };
	inet_prefix dst = { .family = r->rtm_family };
	__u32 table;

	if (preferred_family != AF_UNSPEC && r->rtm_family != preferred_family)
		return false;

	if (filter.prefmask &&
	    filter.pref ^ (tb[FRA_PRIORITY] ? rta_getattr_u32(tb[FRA_PRIORITY]) : 0))
		return false;
	if (filter.not && !(r->rtm_flags & FIB_RULE_INVERT))
		return false;

	if (filter.src.family) {
		if (tb[FRA_SRC]) {
			memcpy(&src.data, RTA_DATA(tb[FRA_SRC]),
			       (r->rtm_src_len + 7) / 8);
		}
		if (filter.src.family != r->rtm_family ||
		    filter.src.bitlen > r->rtm_src_len ||
		    inet_addr_match(&src, &filter.src, filter.src.bitlen))
			return false;
	}

	if (filter.dst.family) {
		if (tb[FRA_DST]) {
			memcpy(&dst.data, RTA_DATA(tb[FRA_DST]),
			       (r->rtm_dst_len + 7) / 8);
		}
		if (filter.dst.family != r->rtm_family ||
		    filter.dst.bitlen > r->rtm_dst_len ||
		    inet_addr_match(&dst, &filter.dst, filter.dst.bitlen))
			return false;
	}

	if (filter.tosmask && filter.tos ^ r->rtm_tos)
		return false;

	if (filter.fwmark) {
		__u32 mark = 0;

		if (tb[FRA_FWMARK])
			mark = rta_getattr_u32(tb[FRA_FWMARK]);
		if (filter.fwmark ^ mark)
			return false;
	}
	if (filter.fwmask) {
		__u32 mask = 0;

		if (tb[FRA_FWMASK])
			mask = rta_getattr_u32(tb[FRA_FWMASK]);
		if (filter.fwmask ^ mask)
			return false;
	}

	if (filter.iifmask) {
		if (tb[FRA_IFNAME]) {
			if (strcmp(filter.iif, rta_getattr_str(tb[FRA_IFNAME])) != 0)
				return false;
		} else {
			return false;
		}
	}

	if (filter.oifmask) {
		if (tb[FRA_OIFNAME]) {
			if (strcmp(filter.oif, rta_getattr_str(tb[FRA_OIFNAME])) != 0)
				return false;
		} else {
			return false;
		}
	}

	if (filter.l3mdev && !(tb[FRA_L3MDEV] && rta_getattr_u8(tb[FRA_L3MDEV])))
		return false;

	if (filter.uidrange) {
		struct fib_rule_uid_range *r = RTA_DATA(tb[FRA_UID_RANGE]);

		if (!tb[FRA_UID_RANGE] ||
		    r->start != filter.range.start ||
		    r->end != filter.range.end)
			return false;
	}

	table = rtm_get_table(r, tb);
	if (filter.tb > 0 && filter.tb ^ table)
		return false;

	return true;
}

int print_rule(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	int host_len = -1;
	__u32 table;
	struct rtattr *tb[FRA_MAX+1];

	SPRINT_BUF(b1);

	if (n->nlmsg_type != RTM_NEWRULE && n->nlmsg_type != RTM_DELRULE)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0)
		return -1;

	parse_rtattr(tb, FRA_MAX, RTM_RTA(r), len);

	host_len = af_bit_len(r->rtm_family);

	if (!filter_nlmsg(n, tb, host_len))
		return 0;

	if (n->nlmsg_type == RTM_DELRULE)
		fprintf(fp, "Deleted ");

	if (tb[FRA_PRIORITY])
		fprintf(fp, "%u:\t",
			rta_getattr_u32(tb[FRA_PRIORITY]));
	else
		fprintf(fp, "0:\t");

	if (r->rtm_flags & FIB_RULE_INVERT)
		fprintf(fp, "not ");

	if (tb[FRA_SRC]) {
		if (r->rtm_src_len != host_len) {
			fprintf(fp, "from %s/%u ",
				rt_addr_n2a_rta(r->rtm_family, tb[FRA_SRC]),
				r->rtm_src_len);
		} else {
			fprintf(fp, "from %s ",
				format_host_rta(r->rtm_family, tb[FRA_SRC]));
		}
	} else if (r->rtm_src_len) {
		fprintf(fp, "from 0/%d ", r->rtm_src_len);
	} else {
		fprintf(fp, "from all ");
	}

	if (tb[FRA_DST]) {
		if (r->rtm_dst_len != host_len) {
			fprintf(fp, "to %s/%u ",
				rt_addr_n2a_rta(r->rtm_family, tb[FRA_DST]),
				r->rtm_dst_len);
		} else {
			fprintf(fp, "to %s ",
				format_host_rta(r->rtm_family, tb[FRA_DST]));
		}
	} else if (r->rtm_dst_len) {
		fprintf(fp, "to 0/%d ", r->rtm_dst_len);
	}

	if (r->rtm_tos) {
		SPRINT_BUF(b1);
		fprintf(fp, "tos %s ",
			rtnl_dsfield_n2a(r->rtm_tos, b1, sizeof(b1)));
	}

	if (tb[FRA_FWMARK] || tb[FRA_FWMASK]) {
		__u32 mark = 0, mask = 0;

		if (tb[FRA_FWMARK])
			mark = rta_getattr_u32(tb[FRA_FWMARK]);

		if (tb[FRA_FWMASK] &&
		    (mask = rta_getattr_u32(tb[FRA_FWMASK])) != 0xFFFFFFFF)
			fprintf(fp, "fwmark 0x%x/0x%x ", mark, mask);
		else
			fprintf(fp, "fwmark 0x%x ", mark);
	}

	if (tb[FRA_IFNAME]) {
		fprintf(fp, "iif %s ", rta_getattr_str(tb[FRA_IFNAME]));
		if (r->rtm_flags & FIB_RULE_IIF_DETACHED)
			fprintf(fp, "[detached] ");
	}

	if (tb[FRA_OIFNAME]) {
		fprintf(fp, "oif %s ", rta_getattr_str(tb[FRA_OIFNAME]));
		if (r->rtm_flags & FIB_RULE_OIF_DETACHED)
			fprintf(fp, "[detached] ");
	}

	if (tb[FRA_L3MDEV]) {
		if (rta_getattr_u8(tb[FRA_L3MDEV]))
			fprintf(fp, "lookup [l3mdev-table] ");
	}

	if (tb[FRA_UID_RANGE]) {
		struct fib_rule_uid_range *r = RTA_DATA(tb[FRA_UID_RANGE]);

		fprintf(fp, "uidrange %u-%u ", r->start, r->end);
	}

	table = rtm_get_table(r, tb);
	if (table) {
		fprintf(fp, "lookup %s ",
			rtnl_rttable_n2a(table, b1, sizeof(b1)));

		if (tb[FRA_SUPPRESS_PREFIXLEN]) {
			int pl = rta_getattr_u32(tb[FRA_SUPPRESS_PREFIXLEN]);

			if (pl != -1)
				fprintf(fp, "suppress_prefixlength %d ", pl);
		}
		if (tb[FRA_SUPPRESS_IFGROUP]) {
			int group = rta_getattr_u32(tb[FRA_SUPPRESS_IFGROUP]);

			if (group != -1) {
				SPRINT_BUF(b1);
				fprintf(fp, "suppress_ifgroup %s ",
					rtnl_group_n2a(group, b1, sizeof(b1)));
			}
		}
	}

	if (tb[FRA_FLOW]) {
		__u32 to = rta_getattr_u32(tb[FRA_FLOW]);
		__u32 from = to>>16;

		to &= 0xFFFF;
		if (from) {
			fprintf(fp, "realms %s/",
				rtnl_rtrealm_n2a(from, b1, sizeof(b1)));
		}
		fprintf(fp, "%s ",
			rtnl_rtrealm_n2a(to, b1, sizeof(b1)));
	}

	if (r->rtm_type == RTN_NAT) {
		if (tb[RTA_GATEWAY]) {
			fprintf(fp, "map-to %s ",
				format_host_rta(r->rtm_family,
						tb[RTA_GATEWAY]));
		} else
			fprintf(fp, "masquerade");
	} else if (r->rtm_type == FR_ACT_GOTO) {
		fprintf(fp, "goto ");
		if (tb[FRA_GOTO])
			fprintf(fp, "%u", rta_getattr_u32(tb[FRA_GOTO]));
		else
			fprintf(fp, "none");
		if (r->rtm_flags & FIB_RULE_UNRESOLVED)
			fprintf(fp, " [unresolved]");
	} else if (r->rtm_type == FR_ACT_NOP)
		fprintf(fp, "nop");
	else if (r->rtm_type != RTN_UNICAST)
		fprintf(fp, "%s",
			rtnl_rtntype_n2a(r->rtm_type,
					 b1, sizeof(b1)));

	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

static __u32 rule_dump_magic = 0x71706986;

static int save_rule_prep(void)
{
	int ret;

	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Not sending a binary stream to stdout\n");
		return -1;
	}

	ret = write(STDOUT_FILENO, &rule_dump_magic, sizeof(rule_dump_magic));
	if (ret != sizeof(rule_dump_magic)) {
		fprintf(stderr, "Can't write magic to dump file\n");
		return -1;
	}

	return 0;
}

static int save_rule(const struct sockaddr_nl *who,
		     struct nlmsghdr *n, void *arg)
{
	int ret;

	ret = write(STDOUT_FILENO, n, n->nlmsg_len);
	if ((ret > 0) && (ret != n->nlmsg_len)) {
		fprintf(stderr, "Short write while saving nlmsg\n");
		ret = -EIO;
	}

	return ret == n->nlmsg_len ? 0 : ret;
}

static int flush_rule(const struct sockaddr_nl *who, struct nlmsghdr *n,
		      void *arg)
{
	struct rtnl_handle rth2;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[FRA_MAX+1];

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0)
		return -1;

	parse_rtattr(tb, FRA_MAX, RTM_RTA(r), len);

	if (tb[FRA_PRIORITY]) {
		n->nlmsg_type = RTM_DELRULE;
		n->nlmsg_flags = NLM_F_REQUEST;

		if (rtnl_open(&rth2, 0) < 0)
			return -1;

		if (rtnl_talk(&rth2, n, NULL, 0) < 0)
			return -2;

		rtnl_close(&rth2);
	}

	return 0;
}

static int iprule_list_flush_or_save(int argc, char **argv, int action)
{
	rtnl_filter_t filter_fn;
	int af = preferred_family;

	if (af == AF_UNSPEC)
		af = AF_INET;

	if (action != IPRULE_LIST && argc > 0) {
		fprintf(stderr, "\"ip rule %s\" does not take any arguments.\n",
				action == IPRULE_SAVE ? "save" : "flush");
		return -1;
	}

	switch (action) {
	case IPRULE_SAVE:
		if (save_rule_prep())
			return -1;
		filter_fn = save_rule;
		break;
	case IPRULE_FLUSH:
		filter_fn = flush_rule;
		break;
	default:
		filter_fn = print_rule;
	}

	memset(&filter, 0, sizeof(filter));

	while (argc > 0) {
		if (matches(*argv, "preference") == 0 ||
		    matches(*argv, "order") == 0 ||
		    matches(*argv, "priority") == 0) {
			__u32 pref;

			NEXT_ARG();
			if (get_u32(&pref, *argv, 0))
				invarg("preference value is invalid\n", *argv);
			filter.pref = pref;
			filter.prefmask = 1;
		} else if (strcmp(*argv, "not") == 0) {
			filter.not = 1;
		} else if (strcmp(*argv, "tos") == 0) {
			__u32 tos;

			NEXT_ARG();
			if (rtnl_dsfield_a2n(&tos, *argv))
				invarg("TOS value is invalid\n", *argv);
			filter.tos = tos;
			filter.tosmask = 1;
		} else if (strcmp(*argv, "fwmark") == 0) {
			char *slash;
			__u32 fwmark, fwmask;

			NEXT_ARG();
			slash = strchr(*argv, '/');
			if (slash != NULL)
				*slash = '\0';
			if (get_u32(&fwmark, *argv, 0))
				invarg("fwmark value is invalid\n", *argv);
			filter.fwmark = fwmark;
			if (slash) {
				if (get_u32(&fwmask, slash+1, 0))
					invarg("fwmask value is invalid\n",
					       slash+1);
				filter.fwmask = fwmask;
			}
		} else if (strcmp(*argv, "dev") == 0 ||
			   strcmp(*argv, "iif") == 0) {
			NEXT_ARG();
			if (get_ifname(filter.iif, *argv))
				invarg("\"iif\"/\"dev\" not a valid ifname", *argv);
			filter.iifmask = 1;
		} else if (strcmp(*argv, "oif") == 0) {
			NEXT_ARG();
			if (get_ifname(filter.oif, *argv))
				invarg("\"oif\" not a valid ifname", *argv);
			filter.oifmask = 1;
		} else if (strcmp(*argv, "l3mdev") == 0) {
			filter.l3mdev = 1;
		} else if (strcmp(*argv, "uidrange") == 0) {
			NEXT_ARG();
			filter.uidrange = 1;
			if (sscanf(*argv, "%u-%u",
				   &filter.range.start,
				   &filter.range.end) != 2)
				invarg("invalid UID range\n", *argv);

		} else if (matches(*argv, "lookup") == 0 ||
			   matches(*argv, "table") == 0) {
			__u32 tid;

			NEXT_ARG();
			if (rtnl_rttable_a2n(&tid, *argv))
				invarg("table id value is invalid\n", *argv);
			filter.tb = tid;
		} else if (matches(*argv, "from") == 0 ||
			   matches(*argv, "src") == 0) {
			NEXT_ARG();
			get_prefix(&filter.src, *argv, af);
		} else {
			if (matches(*argv, "dst") == 0 ||
			    matches(*argv, "to") == 0) {
				NEXT_ARG();
			}
			get_prefix(&filter.dst, *argv, af);
		}
		argc--; argv++;
	}

	if (rtnl_wilddump_request(&rth, af, RTM_GETRULE) < 0) {
		perror("Cannot send dump request");
		return 1;
	}

	if (rtnl_dump_filter(&rth, filter_fn, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return 1;
	}

	return 0;
}

static int rule_dump_check_magic(void)
{
	int ret;
	__u32 magic = 0;

	if (isatty(STDIN_FILENO)) {
		fprintf(stderr, "Can't restore rule dump from a terminal\n");
		return -1;
	}

	ret = fread(&magic, sizeof(magic), 1, stdin);
	if (magic != rule_dump_magic) {
		fprintf(stderr, "Magic mismatch (%d elems, %x magic)\n",
			ret, magic);
		return -1;
	}

	return 0;
}

static int restore_handler(const struct sockaddr_nl *nl,
			   struct rtnl_ctrl_data *ctrl,
			   struct nlmsghdr *n, void *arg)
{
	int ret;

	n->nlmsg_flags |= NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;

	ll_init_map(&rth);

	ret = rtnl_talk(&rth, n, n, sizeof(*n));
	if ((ret < 0) && (errno == EEXIST))
		ret = 0;

	return ret;
}


static int iprule_restore(void)
{
	if (rule_dump_check_magic())
		exit(-1);

	exit(rtnl_from_file(stdin, &restore_handler, NULL));
}

static int iprule_modify(int cmd, int argc, char **argv)
{
	int l3mdev_rule = 0;
	int table_ok = 0;
	__u32 tid = 0;
	struct {
		struct nlmsghdr	n;
		struct rtmsg		r;
		char			buf[1024];
	} req = {
		.n.nlmsg_type = cmd,
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.r.rtm_family = preferred_family,
		.r.rtm_protocol = RTPROT_BOOT,
		.r.rtm_scope = RT_SCOPE_UNIVERSE,
		.r.rtm_type = RTN_UNSPEC,
	};

	if (cmd == RTM_NEWRULE) {
		req.n.nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
		req.r.rtm_type = RTN_UNICAST;
	}

	if (cmd == RTM_DELRULE && argc == 0) {
		fprintf(stderr, "\"ip rule del\" requires arguments.\n");
		return -1;
	}

	while (argc > 0) {
		if (strcmp(*argv, "not") == 0) {
			req.r.rtm_flags |= FIB_RULE_INVERT;
		} else if (strcmp(*argv, "from") == 0) {
			inet_prefix dst;

			NEXT_ARG();
			get_prefix(&dst, *argv, req.r.rtm_family);
			req.r.rtm_src_len = dst.bitlen;
			addattr_l(&req.n, sizeof(req), FRA_SRC,
				  &dst.data, dst.bytelen);
		} else if (strcmp(*argv, "to") == 0) {
			inet_prefix dst;

			NEXT_ARG();
			get_prefix(&dst, *argv, req.r.rtm_family);
			req.r.rtm_dst_len = dst.bitlen;
			addattr_l(&req.n, sizeof(req), FRA_DST,
				  &dst.data, dst.bytelen);
		} else if (matches(*argv, "preference") == 0 ||
			   matches(*argv, "order") == 0 ||
			   matches(*argv, "priority") == 0) {
			__u32 pref;

			NEXT_ARG();
			if (get_u32(&pref, *argv, 0))
				invarg("preference value is invalid\n", *argv);
			addattr32(&req.n, sizeof(req), FRA_PRIORITY, pref);
		} else if (strcmp(*argv, "tos") == 0 ||
			   matches(*argv, "dsfield") == 0) {
			__u32 tos;

			NEXT_ARG();
			if (rtnl_dsfield_a2n(&tos, *argv))
				invarg("TOS value is invalid\n", *argv);
			req.r.rtm_tos = tos;
		} else if (strcmp(*argv, "fwmark") == 0) {
			char *slash;
			__u32 fwmark, fwmask;

			NEXT_ARG();

			slash = strchr(*argv, '/');
			if (slash != NULL)
				*slash = '\0';
			if (get_u32(&fwmark, *argv, 0))
				invarg("fwmark value is invalid\n", *argv);
			addattr32(&req.n, sizeof(req), FRA_FWMARK, fwmark);
			if (slash) {
				if (get_u32(&fwmask, slash+1, 0))
					invarg("fwmask value is invalid\n",
					       slash+1);
				addattr32(&req.n, sizeof(req),
					  FRA_FWMASK, fwmask);
			}
		} else if (matches(*argv, "realms") == 0) {
			__u32 realm;

			NEXT_ARG();
			if (get_rt_realms_or_raw(&realm, *argv))
				invarg("invalid realms\n", *argv);
			addattr32(&req.n, sizeof(req), FRA_FLOW, realm);
		} else if (matches(*argv, "table") == 0 ||
			   strcmp(*argv, "lookup") == 0) {
			NEXT_ARG();
			if (rtnl_rttable_a2n(&tid, *argv))
				invarg("invalid table ID\n", *argv);
			if (tid < 256)
				req.r.rtm_table = tid;
			else {
				req.r.rtm_table = RT_TABLE_UNSPEC;
				addattr32(&req.n, sizeof(req), FRA_TABLE, tid);
			}
			table_ok = 1;
		} else if (matches(*argv, "suppress_prefixlength") == 0 ||
			   strcmp(*argv, "sup_pl") == 0) {
			int pl;

			NEXT_ARG();
			if (get_s32(&pl, *argv, 0) || pl < 0)
				invarg("suppress_prefixlength value is invalid\n",
				       *argv);
			addattr32(&req.n, sizeof(req),
				  FRA_SUPPRESS_PREFIXLEN, pl);
		} else if (matches(*argv, "suppress_ifgroup") == 0 ||
			   strcmp(*argv, "sup_group") == 0) {
			NEXT_ARG();
			int group;

			if (rtnl_group_a2n(&group, *argv))
				invarg("Invalid \"suppress_ifgroup\" value\n",
				       *argv);
			addattr32(&req.n, sizeof(req),
				  FRA_SUPPRESS_IFGROUP, group);
		} else if (strcmp(*argv, "dev") == 0 ||
			   strcmp(*argv, "iif") == 0) {
			NEXT_ARG();
			if (check_ifname(*argv))
				invarg("\"iif\"/\"dev\" not a valid ifname", *argv);
			addattr_l(&req.n, sizeof(req), FRA_IFNAME,
				  *argv, strlen(*argv)+1);
		} else if (strcmp(*argv, "oif") == 0) {
			NEXT_ARG();
			if (check_ifname(*argv))
				invarg("\"oif\" not a valid ifname", *argv);
			addattr_l(&req.n, sizeof(req), FRA_OIFNAME,
				  *argv, strlen(*argv)+1);
		} else if (strcmp(*argv, "l3mdev") == 0) {
			addattr8(&req.n, sizeof(req), FRA_L3MDEV, 1);
			table_ok = 1;
			l3mdev_rule = 1;
		} else if (strcmp(*argv, "uidrange") == 0) {
			struct fib_rule_uid_range r;

			NEXT_ARG();
			if (sscanf(*argv, "%u-%u", &r.start, &r.end) != 2)
				invarg("invalid UID range\n", *argv);
			addattr_l(&req.n, sizeof(req), FRA_UID_RANGE, &r,
				  sizeof(r));
		} else if (strcmp(*argv, "nat") == 0 ||
			   matches(*argv, "map-to") == 0) {
			NEXT_ARG();
			fprintf(stderr, "Warning: route NAT is deprecated\n");
			addattr32(&req.n, sizeof(req), RTA_GATEWAY,
				  get_addr32(*argv));
			req.r.rtm_type = RTN_NAT;
		} else {
			int type;

			if (strcmp(*argv, "type") == 0)
				NEXT_ARG();

			if (matches(*argv, "help") == 0)
				usage();
			else if (matches(*argv, "goto") == 0) {
				__u32 target;

				type = FR_ACT_GOTO;
				NEXT_ARG();
				if (get_u32(&target, *argv, 0))
					invarg("invalid target\n", *argv);
				addattr32(&req.n, sizeof(req),
					  FRA_GOTO, target);
			} else if (matches(*argv, "nop") == 0)
				type = FR_ACT_NOP;
			else if (rtnl_rtntype_a2n(&type, *argv))
				invarg("Failed to parse rule type", *argv);
			req.r.rtm_type = type;
			table_ok = 1;
		}
		argc--;
		argv++;
	}

	if (l3mdev_rule && tid != 0) {
		fprintf(stderr,
			"table can not be specified for l3mdev rules\n");
		return -EINVAL;
	}

	if (req.r.rtm_family == AF_UNSPEC)
		req.r.rtm_family = AF_INET;

	if (!table_ok && cmd == RTM_NEWRULE)
		req.r.rtm_table = RT_TABLE_MAIN;

	if (rtnl_talk(&rth, &req.n, NULL, 0) < 0)
		return -2;

	return 0;
}

int do_iprule(int argc, char **argv)
{
	if (argc < 1) {
		return iprule_list_flush_or_save(0, NULL, IPRULE_LIST);
	} else if (matches(argv[0], "list") == 0 ||
		   matches(argv[0], "lst") == 0 ||
		   matches(argv[0], "show") == 0) {
		return iprule_list_flush_or_save(argc-1, argv+1, IPRULE_LIST);
	} else if (matches(argv[0], "save") == 0) {
		return iprule_list_flush_or_save(argc-1, argv+1, IPRULE_SAVE);
	} else if (matches(argv[0], "restore") == 0) {
		return iprule_restore();
	} else if (matches(argv[0], "add") == 0) {
		return iprule_modify(RTM_NEWRULE, argc-1, argv+1);
	} else if (matches(argv[0], "delete") == 0) {
		return iprule_modify(RTM_DELRULE, argc-1, argv+1);
	} else if (matches(argv[0], "flush") == 0) {
		return iprule_list_flush_or_save(argc-1, argv+1, IPRULE_FLUSH);
	} else if (matches(argv[0], "help") == 0)
		usage();

	fprintf(stderr,
		"Command \"%s\" is unknown, try \"ip rule help\".\n", *argv);
	exit(-1);
}

int do_multirule(int argc, char **argv)
{
	switch (preferred_family) {
	case AF_UNSPEC:
	case AF_INET:
		preferred_family = RTNL_FAMILY_IPMR;
		break;
	case AF_INET6:
		preferred_family = RTNL_FAMILY_IP6MR;
		break;
	case RTNL_FAMILY_IPMR:
	case RTNL_FAMILY_IP6MR:
		break;
	default:
		fprintf(stderr,
			"Multicast rules are only supported for IPv4/IPv6, was: %i\n",
			preferred_family);
		exit(-1);
	}

	return do_iprule(argc, argv);
}
