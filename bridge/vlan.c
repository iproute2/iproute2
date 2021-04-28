/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <string.h>

#include "json_print.h"
#include "libnetlink.h"
#include "br_common.h"
#include "utils.h"

static unsigned int filter_index, filter_vlan;
static int vlan_rtm_cur_ifidx = -1;

enum vlan_show_subject {
	VLAN_SHOW_VLAN,
	VLAN_SHOW_TUNNELINFO,
};

#define VLAN_ID_LEN 9

#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)

static void usage(void)
{
	fprintf(stderr,
		"Usage: bridge vlan { add | del } vid VLAN_ID dev DEV [ tunnel_info id TUNNEL_ID ]\n"
		"                                                     [ pvid ] [ untagged ]\n"
		"                                                     [ self ] [ master ]\n"
		"       bridge vlan { set } vid VLAN_ID dev DEV [ state STP_STATE ]\n"
		"       bridge vlan { show } [ dev DEV ] [ vid VLAN_ID ]\n"
		"       bridge vlan { tunnelshow } [ dev DEV ] [ vid VLAN_ID ]\n");
	exit(-1);
}

static int parse_tunnel_info(int *argcp, char ***argvp, __u32 *tun_id_start,
			     __u32 *tun_id_end)
{
	char **argv = *argvp;
	int argc = *argcp;
	char *t;

	NEXT_ARG();
	if (!matches(*argv, "id")) {
		NEXT_ARG();
		t = strchr(*argv, '-');
		if (t) {
			*t = '\0';
			if (get_u32(tun_id_start, *argv, 0) ||
				    *tun_id_start >= 1u << 24)
				invarg("invalid tun id", *argv);
			if (get_u32(tun_id_end, t + 1, 0) ||
				    *tun_id_end >= 1u << 24)
				invarg("invalid tun id", *argv);

		} else {
			if (get_u32(tun_id_start, *argv, 0) ||
				    *tun_id_start >= 1u << 24)
				invarg("invalid tun id", *argv);
		}
	} else {
		invarg("tunnel id expected", *argv);
	}

	*argcp = argc;
	*argvp = argv;

	return 0;
}

static int add_tunnel_info(struct nlmsghdr *n, int reqsize,
			   __u16 vid, __u32 tun_id, __u16 flags)
{
	struct rtattr *tinfo;

	tinfo = addattr_nest(n, reqsize, IFLA_BRIDGE_VLAN_TUNNEL_INFO);
	addattr32(n, reqsize, IFLA_BRIDGE_VLAN_TUNNEL_ID, tun_id);
	addattr16(n, reqsize, IFLA_BRIDGE_VLAN_TUNNEL_VID, vid);
	addattr16(n, reqsize, IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, flags);

	addattr_nest_end(n, tinfo);

	return 0;
}

static int add_tunnel_info_range(struct nlmsghdr *n, int reqsize,
				 __u16 vid_start, int16_t vid_end,
				 __u32 tun_id_start, __u32 tun_id_end)
{
	if (vid_end != -1 && (vid_end - vid_start) > 0) {
		add_tunnel_info(n, reqsize, vid_start, tun_id_start,
				BRIDGE_VLAN_INFO_RANGE_BEGIN);

		add_tunnel_info(n, reqsize, vid_end, tun_id_end,
				BRIDGE_VLAN_INFO_RANGE_END);
	} else {
		add_tunnel_info(n, reqsize, vid_start, tun_id_start, 0);
	}

	return 0;
}

static int add_vlan_info_range(struct nlmsghdr *n, int reqsize, __u16 vid_start,
			       int16_t vid_end, __u16 flags)
{
	struct bridge_vlan_info vinfo = {};

	vinfo.flags = flags;
	vinfo.vid = vid_start;
	if (vid_end != -1) {
		/* send vlan range start */
		addattr_l(n, reqsize, IFLA_BRIDGE_VLAN_INFO, &vinfo,
			  sizeof(vinfo));
		vinfo.flags &= ~BRIDGE_VLAN_INFO_RANGE_BEGIN;

		/* Now send the vlan range end */
		vinfo.flags |= BRIDGE_VLAN_INFO_RANGE_END;
		vinfo.vid = vid_end;
		addattr_l(n, reqsize, IFLA_BRIDGE_VLAN_INFO, &vinfo,
			  sizeof(vinfo));
	} else {
		addattr_l(n, reqsize, IFLA_BRIDGE_VLAN_INFO, &vinfo,
			  sizeof(vinfo));
	}

	return 0;
}

static int vlan_modify(int cmd, int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct ifinfomsg	ifm;
		char			buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = cmd,
		.ifm.ifi_family = PF_BRIDGE,
	};
	char *d = NULL;
	short vid = -1;
	short vid_end = -1;
	struct rtattr *afspec;
	struct bridge_vlan_info vinfo = {};
	bool tunnel_info_set = false;
	unsigned short flags = 0;
	__u32 tun_id_start = 0;
	__u32 tun_id_end = 0;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "vid") == 0) {
			char *p;

			NEXT_ARG();
			p = strchr(*argv, '-');
			if (p) {
				*p = '\0';
				p++;
				vid = atoi(*argv);
				vid_end = atoi(p);
				vinfo.flags |= BRIDGE_VLAN_INFO_RANGE_BEGIN;
			} else {
				vid = atoi(*argv);
			}
		} else if (strcmp(*argv, "self") == 0) {
			flags |= BRIDGE_FLAGS_SELF;
		} else if (strcmp(*argv, "master") == 0) {
			flags |= BRIDGE_FLAGS_MASTER;
		} else if (strcmp(*argv, "pvid") == 0) {
			vinfo.flags |= BRIDGE_VLAN_INFO_PVID;
		} else if (strcmp(*argv, "untagged") == 0) {
			vinfo.flags |= BRIDGE_VLAN_INFO_UNTAGGED;
		} else if (strcmp(*argv, "tunnel_info") == 0) {
				if (parse_tunnel_info(&argc, &argv,
						      &tun_id_start,
						      &tun_id_end))
					return -1;
				tunnel_info_set = true;
		} else {
			if (matches(*argv, "help") == 0)
				NEXT_ARG();
		}
		argc--; argv++;
	}

	if (d == NULL || vid == -1) {
		fprintf(stderr, "Device and VLAN ID are required arguments.\n");
		return -1;
	}

	req.ifm.ifi_index = ll_name_to_index(d);
	if (req.ifm.ifi_index == 0) {
		fprintf(stderr, "Cannot find bridge device \"%s\"\n", d);
		return -1;
	}

	if (vid >= 4096) {
		fprintf(stderr, "Invalid VLAN ID \"%hu\"\n", vid);
		return -1;
	}

	if (vinfo.flags & BRIDGE_VLAN_INFO_RANGE_BEGIN) {
		if (vid_end == -1 || vid_end >= 4096 || vid >= vid_end) {
			fprintf(stderr, "Invalid VLAN range \"%hu-%hu\"\n",
				vid, vid_end);
			return -1;
		}
		if (vinfo.flags & BRIDGE_VLAN_INFO_PVID) {
			fprintf(stderr,
				"pvid cannot be configured for a vlan range\n");
			return -1;
		}
	}

	afspec = addattr_nest(&req.n, sizeof(req), IFLA_AF_SPEC);

	if (flags)
		addattr16(&req.n, sizeof(req), IFLA_BRIDGE_FLAGS, flags);

	if (tunnel_info_set)
		add_tunnel_info_range(&req.n, sizeof(req), vid, vid_end,
				      tun_id_start, tun_id_end);
	else
		add_vlan_info_range(&req.n, sizeof(req), vid, vid_end,
				    vinfo.flags);

	addattr_nest_end(&req.n, afspec);

	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -1;

	return 0;
}

static int vlan_option_set(int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct br_vlan_msg	bvm;
		char			buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_vlan_msg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_NEWVLAN,
		.bvm.family = PF_BRIDGE,
	};
	struct bridge_vlan_info vinfo = {};
	struct rtattr *afspec;
	short vid_end = -1;
	char *d = NULL;
	short vid = -1;
	int state = -1;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "vid") == 0) {
			char *p;

			NEXT_ARG();
			p = strchr(*argv, '-');
			if (p) {
				*p = '\0';
				p++;
				vid = atoi(*argv);
				vid_end = atoi(p);
				if (vid >= vid_end || vid_end >= 4096) {
					fprintf(stderr, "Invalid VLAN range \"%hu-%hu\"\n",
						vid, vid_end);
					return -1;
				}
			} else {
				vid = atoi(*argv);
			}
		} else if (strcmp(*argv, "state") == 0) {
			char *endptr;

			NEXT_ARG();
			state = strtol(*argv, &endptr, 10);
			if (!(**argv != '\0' && *endptr == '\0'))
				state = parse_stp_state(*argv);
			if (state == -1) {
				fprintf(stderr, "Error: invalid STP state\n");
				return -1;
			}
		} else {
			if (matches(*argv, "help") == 0)
				NEXT_ARG();
		}
		argc--; argv++;
	}

	if (d == NULL || vid == -1) {
		fprintf(stderr, "Device and VLAN ID are required arguments.\n");
		return -1;
	}

	req.bvm.ifindex = ll_name_to_index(d);
	if (req.bvm.ifindex == 0) {
		fprintf(stderr, "Cannot find network device \"%s\"\n", d);
		return -1;
	}

	if (vid >= 4096) {
		fprintf(stderr, "Invalid VLAN ID \"%hu\"\n", vid);
		return -1;
	}
	afspec = addattr_nest(&req.n, sizeof(req), BRIDGE_VLANDB_ENTRY);
	afspec->rta_type |= NLA_F_NESTED;

	vinfo.flags = BRIDGE_VLAN_INFO_ONLY_OPTS;
	vinfo.vid = vid;
	addattr_l(&req.n, sizeof(req), BRIDGE_VLANDB_ENTRY_INFO, &vinfo,
		  sizeof(vinfo));
	if (vid_end != -1)
		addattr16(&req.n, sizeof(req), BRIDGE_VLANDB_ENTRY_RANGE,
			  vid_end);
	if (state >= 0)
		addattr8(&req.n, sizeof(req), BRIDGE_VLANDB_ENTRY_STATE, state);
	addattr_nest_end(&req.n, afspec);

	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -1;

	return 0;
}

/* In order to use this function for both filtering and non-filtering cases
 * we need to make it a tristate:
 * return -1 - if filtering we've gone over so don't continue
 * return  0 - skip entry and continue (applies to range start or to entries
 *             which are less than filter_vlan)
 * return  1 - print the entry and continue
 */
static int filter_vlan_check(__u16 vid, __u16 flags)
{
	/* if we're filtering we should stop on the first greater entry */
	if (filter_vlan && vid > filter_vlan &&
	    !(flags & BRIDGE_VLAN_INFO_RANGE_END))
		return -1;
	if ((flags & BRIDGE_VLAN_INFO_RANGE_BEGIN) ||
	    vid < filter_vlan)
		return 0;

	return 1;
}

static void open_vlan_port(int ifi_index, enum vlan_show_subject subject)
{
	open_json_object(NULL);
	print_color_string(PRINT_ANY, COLOR_IFNAME, "ifname",
			   "%-" __stringify(IFNAMSIZ) "s  ",
			   ll_index_to_name(ifi_index));
	open_json_array(PRINT_JSON,
			subject == VLAN_SHOW_VLAN ? "vlans": "tunnels");
}

static void close_vlan_port(void)
{
	close_json_array(PRINT_JSON, NULL);
	close_json_object();
}

static unsigned int print_range(const char *name, __u32 start, __u32 id)
{
	char end[64];
	int width;

	snprintf(end, sizeof(end), "%sEnd", name);

	width = print_uint(PRINT_ANY, name, "%u", start);
	if (start != id)
		width += print_uint(PRINT_ANY, end, "-%u", id);

	return width;
}

static void print_vlan_tunnel_info(struct rtattr *tb, int ifindex)
{
	struct rtattr *i, *list = tb;
	int rem = RTA_PAYLOAD(list);
	__u16 last_vid_start = 0;
	__u32 last_tunid_start = 0;
	bool opened = false;

	for (i = RTA_DATA(list); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
		struct rtattr *ttb[IFLA_BRIDGE_VLAN_TUNNEL_MAX+1];
		__u32 tunnel_id = 0;
		__u16 tunnel_vid = 0;
		__u16 tunnel_flags = 0;
		unsigned int width;
		int vcheck_ret;

		if (i->rta_type != IFLA_BRIDGE_VLAN_TUNNEL_INFO)
			continue;

		parse_rtattr(ttb, IFLA_BRIDGE_VLAN_TUNNEL_MAX,
			     RTA_DATA(i), RTA_PAYLOAD(i));

		if (ttb[IFLA_BRIDGE_VLAN_TUNNEL_VID])
			tunnel_vid =
				rta_getattr_u16(ttb[IFLA_BRIDGE_VLAN_TUNNEL_VID]);
		else
			continue;

		if (ttb[IFLA_BRIDGE_VLAN_TUNNEL_ID])
			tunnel_id =
				rta_getattr_u32(ttb[IFLA_BRIDGE_VLAN_TUNNEL_ID]);

		if (ttb[IFLA_BRIDGE_VLAN_TUNNEL_FLAGS])
			tunnel_flags =
				rta_getattr_u16(ttb[IFLA_BRIDGE_VLAN_TUNNEL_FLAGS]);

		if (!(tunnel_flags & BRIDGE_VLAN_INFO_RANGE_END)) {
			last_vid_start = tunnel_vid;
			last_tunid_start = tunnel_id;
		}

		vcheck_ret = filter_vlan_check(tunnel_vid, tunnel_flags);
		if (vcheck_ret == -1)
			break;
		else if (vcheck_ret == 0)
			continue;

		if (!opened) {
			open_vlan_port(ifindex, VLAN_SHOW_TUNNELINFO);
			opened = true;
		} else {
			print_string(PRINT_FP, NULL,
				     "%-" __stringify(IFNAMSIZ) "s  ", "");
		}

		open_json_object(NULL);
		width = print_range("vlan", last_vid_start, tunnel_vid);
		if (width <= VLAN_ID_LEN) {
			char buf[VLAN_ID_LEN + 1];

			snprintf(buf, sizeof(buf), "%-*s",
				 VLAN_ID_LEN - width, "");
			print_string(PRINT_FP, NULL, "%s  ", buf);
		} else {
			fprintf(stderr, "BUG: vlan range too wide, %u\n",
				width);
		}
		print_range("tunid", last_tunid_start, tunnel_id);
		close_json_object();
		print_nl();
	}

	if (opened)
		close_vlan_port();
}

static int print_vlan(struct nlmsghdr *n, void *arg)
{
	enum vlan_show_subject *subject = arg;
	struct ifinfomsg *ifm = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[IFLA_MAX+1];

	if (n->nlmsg_type != RTM_NEWLINK) {
		fprintf(stderr, "Not RTM_NEWLINK: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*ifm));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (ifm->ifi_family != AF_BRIDGE)
		return 0;

	if (filter_index && filter_index != ifm->ifi_index)
		return 0;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifm), len);
	if (!tb[IFLA_AF_SPEC])
		return 0;

	switch (*subject) {
	case VLAN_SHOW_VLAN:
		print_vlan_info(tb[IFLA_AF_SPEC], ifm->ifi_index);
		break;
	case VLAN_SHOW_TUNNELINFO:
		print_vlan_tunnel_info(tb[IFLA_AF_SPEC], ifm->ifi_index);
		break;
	}

	return 0;
}

static void print_vlan_flags(__u16 flags)
{
	if (flags == 0)
		return;

	open_json_array(PRINT_JSON, "flags");
	if (flags & BRIDGE_VLAN_INFO_PVID)
		print_string(PRINT_ANY, NULL, " %s", "PVID");

	if (flags & BRIDGE_VLAN_INFO_UNTAGGED)
		print_string(PRINT_ANY, NULL, " %s", "Egress Untagged");
	close_json_array(PRINT_JSON, NULL);
}

static void __print_one_vlan_stats(const struct bridge_vlan_xstats *vstats)
{
	print_string(PRINT_FP, NULL, "%-" __stringify(IFNAMSIZ) "s    ", "");
	print_lluint(PRINT_ANY, "rx_bytes", "RX: %llu bytes",
		     vstats->rx_bytes);
	print_lluint(PRINT_ANY, "rx_packets", " %llu packets\n",
		     vstats->rx_packets);

	print_string(PRINT_FP, NULL, "%-" __stringify(IFNAMSIZ) "s    ", "");
	print_lluint(PRINT_ANY, "tx_bytes", "TX: %llu bytes",
		     vstats->tx_bytes);
	print_lluint(PRINT_ANY, "tx_packets", " %llu packets\n",
		     vstats->tx_packets);
}

static void print_one_vlan_stats(const struct bridge_vlan_xstats *vstats)
{
	open_json_object(NULL);

	print_hu(PRINT_ANY, "vid", "%hu", vstats->vid);
	print_vlan_flags(vstats->flags);
	print_nl();
	__print_one_vlan_stats(vstats);

	close_json_object();
}

static void print_vlan_stats_attr(struct rtattr *attr, int ifindex)
{
	struct rtattr *brtb[LINK_XSTATS_TYPE_MAX+1];
	struct rtattr *i, *list;
	bool found_vlan = false;
	int rem;

	parse_rtattr(brtb, LINK_XSTATS_TYPE_MAX, RTA_DATA(attr),
		     RTA_PAYLOAD(attr));
	if (!brtb[LINK_XSTATS_TYPE_BRIDGE])
		return;

	list = brtb[LINK_XSTATS_TYPE_BRIDGE];
	rem = RTA_PAYLOAD(list);

	for (i = RTA_DATA(list); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
		const struct bridge_vlan_xstats *vstats = RTA_DATA(i);

		if (i->rta_type != BRIDGE_XSTATS_VLAN)
			continue;

		if (filter_vlan && filter_vlan != vstats->vid)
			continue;

		/* skip pure port entries, they'll be dumped via the slave stats call */
		if ((vstats->flags & BRIDGE_VLAN_INFO_MASTER) &&
		    !(vstats->flags & BRIDGE_VLAN_INFO_BRENTRY))
			continue;

		/* found vlan stats, first time print the interface name */
		if (!found_vlan) {
			open_vlan_port(ifindex, VLAN_SHOW_VLAN);
			found_vlan = true;
		} else {
			print_string(PRINT_FP, NULL,
				     "%-" __stringify(IFNAMSIZ) "s  ", "");
		}
		print_one_vlan_stats(vstats);
	}

	/* vlan_port is opened only if there are any vlan stats */
	if (found_vlan)
		close_vlan_port();
}

static int print_vlan_stats(struct nlmsghdr *n, void *arg)
{
	struct if_stats_msg *ifsm = NLMSG_DATA(n);
	struct rtattr *tb[IFLA_STATS_MAX+1];
	int len = n->nlmsg_len;
	FILE *fp = arg;

	len -= NLMSG_LENGTH(sizeof(*ifsm));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (filter_index && filter_index != ifsm->ifindex)
		return 0;

	parse_rtattr(tb, IFLA_STATS_MAX, IFLA_STATS_RTA(ifsm), len);

	/* We have to check if any of the two attrs are usable */
	if (tb[IFLA_STATS_LINK_XSTATS])
		print_vlan_stats_attr(tb[IFLA_STATS_LINK_XSTATS],
				      ifsm->ifindex);

	if (tb[IFLA_STATS_LINK_XSTATS_SLAVE])
		print_vlan_stats_attr(tb[IFLA_STATS_LINK_XSTATS_SLAVE],
				      ifsm->ifindex);

	fflush(fp);
	return 0;
}

int print_vlan_rtm(struct nlmsghdr *n, void *arg, bool monitor)
{
	struct rtattr *vtb[BRIDGE_VLANDB_ENTRY_MAX + 1], *a;
	struct br_vlan_msg *bvm = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	int rem;

	if (n->nlmsg_type != RTM_NEWVLAN && n->nlmsg_type != RTM_DELVLAN &&
	    n->nlmsg_type != RTM_GETVLAN) {
		fprintf(stderr, "Unknown vlan rtm message: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*bvm));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (bvm->family != AF_BRIDGE)
		return 0;

	if (filter_index && filter_index != bvm->ifindex)
		return 0;

	if (n->nlmsg_type == RTM_DELVLAN)
		print_bool(PRINT_ANY, "deleted", "Deleted ", true);

	if (monitor)
		vlan_rtm_cur_ifidx = -1;

	if (vlan_rtm_cur_ifidx != -1 && vlan_rtm_cur_ifidx != bvm->ifindex) {
		close_vlan_port();
		vlan_rtm_cur_ifidx = -1;
	}

	rem = len;
	for (a = BRVLAN_RTA(bvm); RTA_OK(a, rem); a = RTA_NEXT(a, rem)) {
		struct bridge_vlan_xstats vstats;
		struct bridge_vlan_info *vinfo;
		__u32 vrange = 0;
		__u8 state = 0;

		parse_rtattr_flags(vtb, BRIDGE_VLANDB_ENTRY_MAX, RTA_DATA(a),
				   RTA_PAYLOAD(a), NLA_F_NESTED);
		vinfo = RTA_DATA(vtb[BRIDGE_VLANDB_ENTRY_INFO]);

		memset(&vstats, 0, sizeof(vstats));
		if (vtb[BRIDGE_VLANDB_ENTRY_RANGE])
			vrange = rta_getattr_u16(vtb[BRIDGE_VLANDB_ENTRY_RANGE]);
		else
			vrange = vinfo->vid;

		if (vtb[BRIDGE_VLANDB_ENTRY_STATE])
			state = rta_getattr_u8(vtb[BRIDGE_VLANDB_ENTRY_STATE]);

		if (vtb[BRIDGE_VLANDB_ENTRY_STATS]) {
			struct rtattr *stb[BRIDGE_VLANDB_STATS_MAX+1];
			struct rtattr *attr;

			attr = vtb[BRIDGE_VLANDB_ENTRY_STATS];
			parse_rtattr(stb, BRIDGE_VLANDB_STATS_MAX, RTA_DATA(attr),
				     RTA_PAYLOAD(attr));

			if (stb[BRIDGE_VLANDB_STATS_RX_BYTES]) {
				attr = stb[BRIDGE_VLANDB_STATS_RX_BYTES];
				vstats.rx_bytes = rta_getattr_u64(attr);
			}
			if (stb[BRIDGE_VLANDB_STATS_RX_PACKETS]) {
				attr = stb[BRIDGE_VLANDB_STATS_RX_PACKETS];
				vstats.rx_packets = rta_getattr_u64(attr);
			}
			if (stb[BRIDGE_VLANDB_STATS_TX_PACKETS]) {
				attr = stb[BRIDGE_VLANDB_STATS_TX_PACKETS];
				vstats.tx_packets = rta_getattr_u64(attr);
			}
			if (stb[BRIDGE_VLANDB_STATS_TX_BYTES]) {
				attr = stb[BRIDGE_VLANDB_STATS_TX_BYTES];
				vstats.tx_bytes = rta_getattr_u64(attr);
			}
		}
		if (vlan_rtm_cur_ifidx != bvm->ifindex) {
			open_vlan_port(bvm->ifindex, VLAN_SHOW_VLAN);
			open_json_object(NULL);
			vlan_rtm_cur_ifidx = bvm->ifindex;
		} else {
			open_json_object(NULL);
			print_string(PRINT_FP, NULL, "%-" __stringify(IFNAMSIZ) "s  ", "");
		}
		print_range("vlan", vinfo->vid, vrange);
		print_vlan_flags(vinfo->flags);
		print_nl();
		print_string(PRINT_FP, NULL, "%-" __stringify(IFNAMSIZ) "s    ", "");
		print_stp_state(state);
		print_nl();
		if (show_stats)
			__print_one_vlan_stats(&vstats);
		close_json_object();
	}

	return 0;
}

static int print_vlan_rtm_filter(struct nlmsghdr *n, void *arg)
{
	return print_vlan_rtm(n, arg, false);
}

static int vlan_show(int argc, char **argv, int subject)
{
	char *filter_dev = NULL;
	int ret = 0;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (filter_dev)
				duparg("dev", *argv);
			filter_dev = *argv;
		} else if (strcmp(*argv, "vid") == 0) {
			NEXT_ARG();
			if (filter_vlan)
				duparg("vid", *argv);
			filter_vlan = atoi(*argv);
		}
		argc--; argv++;
	}

	if (filter_dev) {
		filter_index = ll_name_to_index(filter_dev);
		if (!filter_index)
			return nodev(filter_dev);
	}

	new_json_obj(json);

	/* if show_details is true then use the new bridge vlan dump format */
	if (show_details && subject == VLAN_SHOW_VLAN) {
		__u32 dump_flags = show_stats ? BRIDGE_VLANDB_DUMPF_STATS : 0;

		if (rtnl_brvlandump_req(&rth, PF_BRIDGE, dump_flags) < 0) {
			perror("Cannot send dump request");
			exit(1);
		}

		if (!is_json_context()) {
			printf("%-" __stringify(IFNAMSIZ) "s  %-"
			       __stringify(VLAN_ID_LEN) "s", "port",
			       "vlan-id");
			printf("\n");
		}

		ret = rtnl_dump_filter(&rth, print_vlan_rtm_filter, &subject);
		if (ret < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}

		if (vlan_rtm_cur_ifidx != -1)
			close_vlan_port();

		goto out;
	}

	if (!show_stats) {
		if (rtnl_linkdump_req_filter(&rth, PF_BRIDGE,
					     (compress_vlans ?
					      RTEXT_FILTER_BRVLAN_COMPRESSED :
					      RTEXT_FILTER_BRVLAN)) < 0) {
			perror("Cannot send dump request");
			exit(1);
		}

		if (!is_json_context()) {
			printf("%-" __stringify(IFNAMSIZ) "s  %-"
			       __stringify(VLAN_ID_LEN) "s", "port",
			       "vlan-id");
			if (subject == VLAN_SHOW_TUNNELINFO)
				printf("  tunnel-id");
			printf("\n");
		}

		ret = rtnl_dump_filter(&rth, print_vlan, &subject);
		if (ret < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}
	} else {
		__u32 filt_mask;

		filt_mask = IFLA_STATS_FILTER_BIT(IFLA_STATS_LINK_XSTATS);
		if (rtnl_statsdump_req_filter(&rth, AF_UNSPEC, filt_mask) < 0) {
			perror("Cannot send dump request");
			exit(1);
		}

		if (!is_json_context())
			printf("%-" __stringify(IFNAMSIZ) "s  vlan-id\n",
			       "port");

		if (rtnl_dump_filter(&rth, print_vlan_stats, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}

		filt_mask = IFLA_STATS_FILTER_BIT(IFLA_STATS_LINK_XSTATS_SLAVE);
		if (rtnl_statsdump_req_filter(&rth, AF_UNSPEC, filt_mask) < 0) {
			perror("Cannot send slave dump request");
			exit(1);
		}

		if (rtnl_dump_filter(&rth, print_vlan_stats, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}
	}

out:
	delete_json_obj();
	fflush(stdout);
	return 0;
}

void print_vlan_info(struct rtattr *tb, int ifindex)
{
	struct rtattr *i, *list = tb;
	int rem = RTA_PAYLOAD(list);
	__u16 last_vid_start = 0;
	bool opened = false;

	for (i = RTA_DATA(list); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
		struct bridge_vlan_info *vinfo;
		int vcheck_ret;

		if (i->rta_type != IFLA_BRIDGE_VLAN_INFO)
			continue;

		vinfo = RTA_DATA(i);

		if (!(vinfo->flags & BRIDGE_VLAN_INFO_RANGE_END))
			last_vid_start = vinfo->vid;
		vcheck_ret = filter_vlan_check(vinfo->vid, vinfo->flags);
		if (vcheck_ret == -1)
			break;
		else if (vcheck_ret == 0)
			continue;

		if (!opened) {
			open_vlan_port(ifindex, VLAN_SHOW_VLAN);
			opened = true;
		} else {
			print_string(PRINT_FP, NULL, "%-"
				     __stringify(IFNAMSIZ) "s  ", "");
		}

		open_json_object(NULL);
		print_range("vlan", last_vid_start, vinfo->vid);

		print_vlan_flags(vinfo->flags);
		close_json_object();
		print_nl();
	}

	if (opened)
		close_vlan_port();
}

int do_vlan(int argc, char **argv)
{
	ll_init_map(&rth);

	if (argc > 0) {
		if (matches(*argv, "add") == 0)
			return vlan_modify(RTM_SETLINK, argc-1, argv+1);
		if (matches(*argv, "delete") == 0)
			return vlan_modify(RTM_DELLINK, argc-1, argv+1);
		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return vlan_show(argc-1, argv+1, VLAN_SHOW_VLAN);
		if (matches(*argv, "tunnelshow") == 0) {
			return vlan_show(argc-1, argv+1, VLAN_SHOW_TUNNELINFO);
		}
		if (matches(*argv, "set") == 0)
			return vlan_option_set(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else {
		return vlan_show(0, NULL, VLAN_SHOW_VLAN);
	}

	fprintf(stderr, "Command \"%s\" is unknown, try \"bridge vlan help\".\n", *argv);
	exit(-1);
}
