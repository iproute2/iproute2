// SPDX-License-Identifier: GPL-2.0+
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

#include "list.h"
#include "utils.h"
#include "ip_common.h"

struct ipstats_stat_dump_filters {
	/* mask[0] filters outer attributes. Then individual nests have their
	 * filtering mask at the index of the nested attribute.
	 */
	__u32 mask[IFLA_STATS_MAX + 1];
};

static void
ipstats_stat_desc_enable_bit(struct ipstats_stat_dump_filters *filters,
			     unsigned int group, unsigned int subgroup)
{
	filters->mask[0] |= IFLA_STATS_FILTER_BIT(group);
	if (subgroup)
		filters->mask[group] |= IFLA_STATS_FILTER_BIT(subgroup);
}

struct ipstats_stat_show_attrs {
	struct if_stats_msg *ifsm;
	int len;

	/* tbs[0] contains top-level attribute table. Then individual nests have
	 * their attribute tables at the index of the nested attribute.
	 */
	struct rtattr **tbs[IFLA_STATS_MAX + 1];
};

static const char *const ipstats_levels[] = {
	"group",
	"subgroup",
	"suite",
};

enum {
	IPSTATS_LEVELS_COUNT = ARRAY_SIZE(ipstats_levels),
};

struct ipstats_sel {
	const char *sel[IPSTATS_LEVELS_COUNT];
};

struct ipstats_stat_enabled_one {
	const struct ipstats_stat_desc *desc;
	struct ipstats_sel sel;
};

struct ipstats_stat_enabled {
	struct ipstats_stat_enabled_one *enabled;
	size_t nenabled;
};

static const unsigned int ipstats_stat_ifla_max[] = {
	[0] = IFLA_STATS_MAX,
	[IFLA_STATS_LINK_XSTATS] = LINK_XSTATS_TYPE_MAX,
	[IFLA_STATS_LINK_XSTATS_SLAVE] = LINK_XSTATS_TYPE_MAX,
	[IFLA_STATS_LINK_OFFLOAD_XSTATS] = IFLA_OFFLOAD_XSTATS_MAX,
	[IFLA_STATS_AF_SPEC] = AF_MAX - 1,
};

static_assert(ARRAY_SIZE(ipstats_stat_ifla_max) == IFLA_STATS_MAX + 1,
	      "An IFLA_STATS attribute is missing from the ifla_max table");

static int
ipstats_stat_show_attrs_alloc_tb(struct ipstats_stat_show_attrs *attrs,
				 unsigned int group)
{
	unsigned int ifla_max;
	int err;

	assert(group < ARRAY_SIZE(ipstats_stat_ifla_max));
	assert(group < ARRAY_SIZE(attrs->tbs));
	ifla_max = ipstats_stat_ifla_max[group];
	assert(ifla_max != 0);

	if (attrs->tbs[group])
		return 0;

	attrs->tbs[group] = calloc(ifla_max + 1, sizeof(*attrs->tbs[group]));
	if (attrs->tbs[group] == NULL) {
		fprintf(stderr, "Error parsing netlink answer: %s\n",
			strerror(errno));
		return -errno;
	}

	if (group == 0)
		err = parse_rtattr(attrs->tbs[group], ifla_max,
				   IFLA_STATS_RTA(attrs->ifsm), attrs->len);
	else
		err = parse_rtattr_nested(attrs->tbs[group], ifla_max,
					  attrs->tbs[0][group]);

	if (err != 0) {
		free(attrs->tbs[group]);
		attrs->tbs[group] = NULL;
	}
	return err;
}

static const struct rtattr *
ipstats_stat_show_get_attr(struct ipstats_stat_show_attrs *attrs,
			   int group, int subgroup, int *err)
{
	int tmp_err;

	if (err == NULL)
		err = &tmp_err;

	*err = 0;
	if (subgroup == 0)
		return attrs->tbs[0][group];

	if (attrs->tbs[0][group] == NULL)
		return NULL;

	*err = ipstats_stat_show_attrs_alloc_tb(attrs, group);
	if (*err != 0)
		return NULL;

	return attrs->tbs[group][subgroup];
}

static void
ipstats_stat_show_attrs_free(struct ipstats_stat_show_attrs *attrs)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(attrs->tbs); i++)
		free(attrs->tbs[i]);
}

#define IPSTATS_RTA_PAYLOAD(VAR, AT)					\
	do {								\
		const struct rtattr *__at = (AT);			\
		size_t __at_sz = __at->rta_len - RTA_LENGTH(0);		\
		size_t __var_sz = sizeof(VAR);				\
		typeof(VAR) *__dest = &VAR;				\
									\
		memset(__dest, 0, __var_sz);				\
		memcpy(__dest, RTA_DATA(__at), MIN(__at_sz, __var_sz));	\
	} while (0)

static int ipstats_show_64(struct ipstats_stat_show_attrs *attrs,
			   unsigned int group, unsigned int subgroup)
{
	struct rtnl_link_stats64 stats;
	const struct rtattr *at;
	int err;

	at = ipstats_stat_show_get_attr(attrs, group, subgroup, &err);
	if (at == NULL)
		return err;

	IPSTATS_RTA_PAYLOAD(stats, at);

	open_json_object("stats64");
	print_stats64(stdout, &stats, NULL, NULL);
	close_json_object();
	return 0;
}

static void print_hw_stats64(FILE *fp, struct rtnl_hw_stats64 *s)
{
	unsigned int cols[] = {
		strlen("*X: bytes"),
		strlen("packets"),
		strlen("errors"),
		strlen("dropped"),
		strlen("overrun"),
	};

	if (is_json_context()) {
		/* RX stats */
		open_json_object("rx");
		print_u64(PRINT_JSON, "bytes", NULL, s->rx_bytes);
		print_u64(PRINT_JSON, "packets", NULL, s->rx_packets);
		print_u64(PRINT_JSON, "errors", NULL, s->rx_errors);
		print_u64(PRINT_JSON, "dropped", NULL, s->rx_dropped);
		print_u64(PRINT_JSON, "multicast", NULL, s->multicast);
		close_json_object();

		/* TX stats */
		open_json_object("tx");
		print_u64(PRINT_JSON, "bytes", NULL, s->tx_bytes);
		print_u64(PRINT_JSON, "packets", NULL, s->tx_packets);
		print_u64(PRINT_JSON, "errors", NULL, s->tx_errors);
		print_u64(PRINT_JSON, "dropped", NULL, s->tx_dropped);
		close_json_object();
	} else {
		size_columns(cols, ARRAY_SIZE(cols),
			     s->rx_bytes, s->rx_packets, s->rx_errors,
			     s->rx_dropped, s->multicast);
		size_columns(cols, ARRAY_SIZE(cols),
			     s->tx_bytes, s->tx_packets, s->tx_errors,
			     s->tx_dropped, 0);

		/* RX stats */
		fprintf(fp, "    RX: %*s %*s %*s %*s %*s%s",
			cols[0] - 4, "bytes", cols[1], "packets",
			cols[2], "errors", cols[3], "dropped",
			cols[4], "mcast", _SL_);

		fprintf(fp, "    ");
		print_num(fp, cols[0], s->rx_bytes);
		print_num(fp, cols[1], s->rx_packets);
		print_num(fp, cols[2], s->rx_errors);
		print_num(fp, cols[3], s->rx_dropped);
		print_num(fp, cols[4], s->multicast);
		fprintf(fp, "%s", _SL_);

		/* TX stats */
		fprintf(fp, "    TX: %*s %*s %*s %*s%s",
			cols[0] - 4, "bytes", cols[1], "packets",
			cols[2], "errors", cols[3], "dropped", _SL_);

		fprintf(fp, "    ");
		print_num(fp, cols[0], s->tx_bytes);
		print_num(fp, cols[1], s->tx_packets);
		print_num(fp, cols[2], s->tx_errors);
		print_num(fp, cols[3], s->tx_dropped);
	}
}

static int ipstats_show_hw64(const struct rtattr *at)
{
	struct rtnl_hw_stats64 stats;

	IPSTATS_RTA_PAYLOAD(stats, at);
	print_hw_stats64(stdout, &stats);
	return 0;
}

enum ipstats_maybe_on_off {
	IPSTATS_MOO_OFF = -1,
	IPSTATS_MOO_INVALID,
	IPSTATS_MOO_ON,
};

static bool ipstats_moo_to_bool(enum ipstats_maybe_on_off moo)
{
	assert(moo != IPSTATS_MOO_INVALID);
	return moo + 1;
}

static int ipstats_print_moo(enum output_type t, const char *key,
			     const char *fmt, enum ipstats_maybe_on_off moo)
{
	if (!moo)
		return 0;
	return print_on_off(t, key, fmt, ipstats_moo_to_bool(moo));
}

struct ipstats_hw_s_info_one {
	enum ipstats_maybe_on_off request;
	enum ipstats_maybe_on_off used;
};

enum ipstats_hw_s_info_idx {
	IPSTATS_HW_S_INFO_IDX_L3_STATS,
	IPSTATS_HW_S_INFO_IDX_COUNT
};

static const char *const ipstats_hw_s_info_name[] = {
	"l3_stats",
};

static_assert(ARRAY_SIZE(ipstats_hw_s_info_name) ==
	      IPSTATS_HW_S_INFO_IDX_COUNT,
	      "mismatch: enum ipstats_hw_s_info_idx x ipstats_hw_s_info_name");

struct ipstats_hw_s_info {
	/* Indexed by enum ipstats_hw_s_info_idx. */
	struct ipstats_hw_s_info_one *infos[IPSTATS_HW_S_INFO_IDX_COUNT];
};

static enum ipstats_maybe_on_off ipstats_dissect_01(int value, const char *what)
{
	switch (value) {
	case 0:
		return IPSTATS_MOO_OFF;
	case 1:
		return IPSTATS_MOO_ON;
	default:
		fprintf(stderr, "Invalid value for %s: expected 0 or 1, got %d.\n",
			what, value);
		return IPSTATS_MOO_INVALID;
	}
}

static int ipstats_dissect_hw_s_info_one(const struct rtattr *at,
					 struct ipstats_hw_s_info_one *p_hwsio,
					 const char *what)
{
	int attr_id_request = IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST;
	struct rtattr *tb[IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX + 1];
	int attr_id_used = IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED;
	struct ipstats_hw_s_info_one hwsio = {};
	int err;
	int v;

	err = parse_rtattr_nested(tb, IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX, at);
	if (err)
		return err;

	if (tb[attr_id_request]) {
		v = rta_getattr_u8(tb[attr_id_request]);
		hwsio.request = ipstats_dissect_01(v, "request");

		/* This has to be present & valid. */
		if (!hwsio.request)
			return -EINVAL;
	}

	if (tb[attr_id_used]) {
		v = rta_getattr_u8(tb[attr_id_used]);
		hwsio.used = ipstats_dissect_01(v, "used");
	}

	*p_hwsio = hwsio;
	return 0;
}

static int ipstats_dissect_hw_s_info(const struct rtattr *at,
				     struct ipstats_hw_s_info *hwsi)
{
	struct rtattr *tb[IFLA_OFFLOAD_XSTATS_MAX + 1];
	int attr_id_l3 = IFLA_OFFLOAD_XSTATS_L3_STATS;
	struct ipstats_hw_s_info_one *hwsio = NULL;
	int err;

	err = parse_rtattr_nested(tb, IFLA_OFFLOAD_XSTATS_MAX, at);
	if (err)
		return err;

	*hwsi = (struct ipstats_hw_s_info){};

	if (tb[attr_id_l3]) {
		hwsio = malloc(sizeof(*hwsio));
		if (!hwsio) {
			err = -ENOMEM;
			goto out;
		}

		err = ipstats_dissect_hw_s_info_one(tb[attr_id_l3], hwsio, "l3");
		if (err)
			goto out;

		hwsi->infos[IPSTATS_HW_S_INFO_IDX_L3_STATS] = hwsio;
		hwsio = NULL;
	}

	return 0;

out:
	free(hwsio);
	return err;
}

static void ipstats_fini_hw_s_info(struct ipstats_hw_s_info *hwsi)
{
	int i;

	for (i = 0; i < IPSTATS_HW_S_INFO_IDX_COUNT; i++)
		free(hwsi->infos[i]);
}

static void
__ipstats_show_hw_s_info_one(const struct ipstats_hw_s_info_one *hwsio)
{
	if (hwsio == NULL)
		return;

	ipstats_print_moo(PRINT_ANY, "request", " %s", hwsio->request);
	ipstats_print_moo(PRINT_ANY, "used", " used %s", hwsio->used);
}

static void
ipstats_show_hw_s_info_one(const struct ipstats_hw_s_info *hwsi,
			   enum ipstats_hw_s_info_idx idx)
{
	const struct ipstats_hw_s_info_one *hwsio = hwsi->infos[idx];
	const char *name = ipstats_hw_s_info_name[idx];

	if (hwsio == NULL)
		return;

	print_string(PRINT_FP, NULL, "    %s", name);
	open_json_object(name);
	__ipstats_show_hw_s_info_one(hwsio);
	close_json_object();
}

static int __ipstats_show_hw_s_info(const struct rtattr *at)
{
	struct ipstats_hw_s_info hwsi = {};
	int err;

	err = ipstats_dissect_hw_s_info(at, &hwsi);
	if (err)
		return err;

	open_json_object("info");
	ipstats_show_hw_s_info_one(&hwsi, IPSTATS_HW_S_INFO_IDX_L3_STATS);
	close_json_object();

	ipstats_fini_hw_s_info(&hwsi);
	return 0;
}

static int ipstats_show_hw_s_info(struct ipstats_stat_show_attrs *attrs,
				  unsigned int group, unsigned int subgroup)
{
	const struct rtattr *at;
	int err;

	at = ipstats_stat_show_get_attr(attrs, group, subgroup, &err);
	if (at == NULL)
		return err;

	print_nl();
	return __ipstats_show_hw_s_info(at);
}

static int __ipstats_show_hw_stats(const struct rtattr *at_hwsi,
				   const struct rtattr *at_stats,
				   enum ipstats_hw_s_info_idx idx)
{
	int err = 0;

	if (at_hwsi != NULL) {
		struct ipstats_hw_s_info hwsi = {};

		err = ipstats_dissect_hw_s_info(at_hwsi, &hwsi);
		if (err)
			return err;

		open_json_object("info");
		__ipstats_show_hw_s_info_one(hwsi.infos[idx]);
		close_json_object();

		ipstats_fini_hw_s_info(&hwsi);
	}

	if (at_stats != NULL) {
		print_nl();
		open_json_object("stats64");
		err = ipstats_show_hw64(at_stats);
		close_json_object();
	}

	return err;
}

static int ipstats_show_hw_stats(struct ipstats_stat_show_attrs *attrs,
				 unsigned int group,
				 unsigned int hw_s_info,
				 unsigned int hw_stats,
				 enum ipstats_hw_s_info_idx idx)
{
	const struct rtattr *at_stats;
	const struct rtattr *at_hwsi;
	int err = 0;

	at_hwsi = ipstats_stat_show_get_attr(attrs, group, hw_s_info, &err);
	if (at_hwsi == NULL)
		return err;

	at_stats = ipstats_stat_show_get_attr(attrs, group, hw_stats, &err);
	if (at_stats == NULL && err != 0)
		return err;

	return __ipstats_show_hw_stats(at_hwsi, at_stats, idx);
}

static void
ipstats_stat_desc_pack_cpu_hit(struct ipstats_stat_dump_filters *filters,
			       const struct ipstats_stat_desc *desc)
{
	ipstats_stat_desc_enable_bit(filters,
				     IFLA_STATS_LINK_OFFLOAD_XSTATS,
				     IFLA_OFFLOAD_XSTATS_CPU_HIT);
}

static int ipstats_stat_desc_show_cpu_hit(struct ipstats_stat_show_attrs *attrs,
					  const struct ipstats_stat_desc *desc)
{
	print_nl();
	return ipstats_show_64(attrs,
			       IFLA_STATS_LINK_OFFLOAD_XSTATS,
			       IFLA_OFFLOAD_XSTATS_CPU_HIT);
}

static const struct ipstats_stat_desc ipstats_stat_desc_offload_cpu_hit = {
	.name = "cpu_hit",
	.kind = IPSTATS_STAT_DESC_KIND_LEAF,
	.pack = &ipstats_stat_desc_pack_cpu_hit,
	.show = &ipstats_stat_desc_show_cpu_hit,
};

static void
ipstats_stat_desc_pack_hw_stats_info(struct ipstats_stat_dump_filters *filters,
				     const struct ipstats_stat_desc *desc)
{
	ipstats_stat_desc_enable_bit(filters,
				     IFLA_STATS_LINK_OFFLOAD_XSTATS,
				     IFLA_OFFLOAD_XSTATS_HW_S_INFO);
}

static int
ipstats_stat_desc_show_hw_stats_info(struct ipstats_stat_show_attrs *attrs,
				     const struct ipstats_stat_desc *desc)
{
	return ipstats_show_hw_s_info(attrs,
				      IFLA_STATS_LINK_OFFLOAD_XSTATS,
				      IFLA_OFFLOAD_XSTATS_HW_S_INFO);
}

static const struct ipstats_stat_desc ipstats_stat_desc_offload_hw_s_info = {
	.name = "hw_stats_info",
	.kind = IPSTATS_STAT_DESC_KIND_LEAF,
	.pack = &ipstats_stat_desc_pack_hw_stats_info,
	.show = &ipstats_stat_desc_show_hw_stats_info,
};

static void
ipstats_stat_desc_pack_l3_stats(struct ipstats_stat_dump_filters *filters,
				const struct ipstats_stat_desc *desc)
{
	ipstats_stat_desc_enable_bit(filters,
				     IFLA_STATS_LINK_OFFLOAD_XSTATS,
				     IFLA_OFFLOAD_XSTATS_L3_STATS);
	ipstats_stat_desc_enable_bit(filters,
				     IFLA_STATS_LINK_OFFLOAD_XSTATS,
				     IFLA_OFFLOAD_XSTATS_HW_S_INFO);
}

static int
ipstats_stat_desc_show_l3_stats(struct ipstats_stat_show_attrs *attrs,
				const struct ipstats_stat_desc *desc)
{
	return ipstats_show_hw_stats(attrs,
				     IFLA_STATS_LINK_OFFLOAD_XSTATS,
				     IFLA_OFFLOAD_XSTATS_HW_S_INFO,
				     IFLA_OFFLOAD_XSTATS_L3_STATS,
				     IPSTATS_HW_S_INFO_IDX_L3_STATS);
}

static const struct ipstats_stat_desc ipstats_stat_desc_offload_l3_stats = {
	.name = "l3_stats",
	.kind = IPSTATS_STAT_DESC_KIND_LEAF,
	.pack = &ipstats_stat_desc_pack_l3_stats,
	.show = &ipstats_stat_desc_show_l3_stats,
};

static const struct ipstats_stat_desc *ipstats_stat_desc_offload_subs[] = {
	&ipstats_stat_desc_offload_cpu_hit,
	&ipstats_stat_desc_offload_hw_s_info,
	&ipstats_stat_desc_offload_l3_stats,
};

static const struct ipstats_stat_desc ipstats_stat_desc_offload_group = {
	.name = "offload",
	.kind = IPSTATS_STAT_DESC_KIND_GROUP,
	.subs = ipstats_stat_desc_offload_subs,
	.nsubs = ARRAY_SIZE(ipstats_stat_desc_offload_subs),
};

void ipstats_stat_desc_pack_xstats(struct ipstats_stat_dump_filters *filters,
				   const struct ipstats_stat_desc *desc)
{
	struct ipstats_stat_desc_xstats *xdesc;

	xdesc = container_of(desc, struct ipstats_stat_desc_xstats, desc);
	ipstats_stat_desc_enable_bit(filters, xdesc->xstats_at, 0);
}

int ipstats_stat_desc_show_xstats(struct ipstats_stat_show_attrs *attrs,
				  const struct ipstats_stat_desc *desc)
{
	struct ipstats_stat_desc_xstats *xdesc;
	const struct rtattr *at;
	const struct rtattr *i;
	int err;

	xdesc = container_of(desc, struct ipstats_stat_desc_xstats, desc);
	at = ipstats_stat_show_get_attr(attrs,
					xdesc->xstats_at,
					xdesc->link_type_at, &err);
	if (at == NULL)
		return err;

	rtattr_for_each_nested(i, at) {
		if (i->rta_type == xdesc->inner_at) {
			print_nl();
			xdesc->show_cb(i);
		}
	}

	return 0;
}

static const struct ipstats_stat_desc *ipstats_stat_desc_xstats_subs[] = {
	&ipstats_stat_desc_xstats_bridge_group,
	&ipstats_stat_desc_xstats_bond_group,
};

static const struct ipstats_stat_desc ipstats_stat_desc_xstats_group = {
	.name = "xstats",
	.kind = IPSTATS_STAT_DESC_KIND_GROUP,
	.subs = ipstats_stat_desc_xstats_subs,
	.nsubs = ARRAY_SIZE(ipstats_stat_desc_xstats_subs),
};

static const struct ipstats_stat_desc *ipstats_stat_desc_xstats_slave_subs[] = {
	&ipstats_stat_desc_xstats_slave_bridge_group,
	&ipstats_stat_desc_xstats_slave_bond_group,
};

static const struct ipstats_stat_desc ipstats_stat_desc_xstats_slave_group = {
	.name = "xstats_slave",
	.kind = IPSTATS_STAT_DESC_KIND_GROUP,
	.subs = ipstats_stat_desc_xstats_slave_subs,
	.nsubs = ARRAY_SIZE(ipstats_stat_desc_xstats_slave_subs),
};

static void
ipstats_stat_desc_pack_link(struct ipstats_stat_dump_filters *filters,
			    const struct ipstats_stat_desc *desc)
{
	ipstats_stat_desc_enable_bit(filters,
				     IFLA_STATS_LINK_64, 0);
}

static int
ipstats_stat_desc_show_link(struct ipstats_stat_show_attrs *attrs,
			    const struct ipstats_stat_desc *desc)
{
	print_nl();
	return ipstats_show_64(attrs, IFLA_STATS_LINK_64, 0);
}

static const struct ipstats_stat_desc ipstats_stat_desc_toplev_link = {
	.name = "link",
	.kind = IPSTATS_STAT_DESC_KIND_LEAF,
	.pack = &ipstats_stat_desc_pack_link,
	.show = &ipstats_stat_desc_show_link,
};

static const struct ipstats_stat_desc ipstats_stat_desc_afstats_group;

static void
ipstats_stat_desc_pack_afstats(struct ipstats_stat_dump_filters *filters,
			       const struct ipstats_stat_desc *desc)
{
	ipstats_stat_desc_enable_bit(filters, IFLA_STATS_AF_SPEC, 0);
}

static int
ipstats_stat_desc_show_afstats_mpls(struct ipstats_stat_show_attrs *attrs,
				    const struct ipstats_stat_desc *desc)
{
	struct rtattr *mrtb[MPLS_STATS_MAX+1];
	struct mpls_link_stats stats;
	const struct rtattr *at;
	int err;

	at = ipstats_stat_show_get_attr(attrs, IFLA_STATS_AF_SPEC,
					AF_MPLS, &err);
	if (at == NULL)
		return err;

	parse_rtattr_nested(mrtb, MPLS_STATS_MAX, at);
	if (mrtb[MPLS_STATS_LINK] == NULL)
		return -ENOENT;

	IPSTATS_RTA_PAYLOAD(stats, mrtb[MPLS_STATS_LINK]);

	print_nl();
	open_json_object("mpls_stats");
	print_mpls_link_stats(stdout, &stats, "    ");
	close_json_object();
	return 0;
}

static const struct ipstats_stat_desc ipstats_stat_desc_afstats_mpls = {
	.name = "mpls",
	.kind = IPSTATS_STAT_DESC_KIND_LEAF,
	.pack = &ipstats_stat_desc_pack_afstats,
	.show = &ipstats_stat_desc_show_afstats_mpls,
};

static const struct ipstats_stat_desc *ipstats_stat_desc_afstats_subs[] = {
	&ipstats_stat_desc_afstats_mpls,
};

static const struct ipstats_stat_desc ipstats_stat_desc_afstats_group = {
	.name = "afstats",
	.kind = IPSTATS_STAT_DESC_KIND_GROUP,
	.subs = ipstats_stat_desc_afstats_subs,
	.nsubs = ARRAY_SIZE(ipstats_stat_desc_afstats_subs),
};
static const struct ipstats_stat_desc *ipstats_stat_desc_toplev_subs[] = {
	&ipstats_stat_desc_toplev_link,
	&ipstats_stat_desc_xstats_group,
	&ipstats_stat_desc_xstats_slave_group,
	&ipstats_stat_desc_offload_group,
	&ipstats_stat_desc_afstats_group,
};

static const struct ipstats_stat_desc ipstats_stat_desc_toplev_group = {
	.name = "top-level",
	.kind = IPSTATS_STAT_DESC_KIND_GROUP,
	.subs = ipstats_stat_desc_toplev_subs,
	.nsubs = ARRAY_SIZE(ipstats_stat_desc_toplev_subs),
};

static void ipstats_show_group(const struct ipstats_sel *sel)
{
	int i;

	for (i = 0; i < IPSTATS_LEVELS_COUNT; i++) {
		if (sel->sel[i] == NULL)
			break;
		print_string(PRINT_JSON, ipstats_levels[i], NULL, sel->sel[i]);
		print_string(PRINT_FP, NULL, " %s ", ipstats_levels[i]);
		print_string(PRINT_FP, NULL, "%s", sel->sel[i]);
	}
}

static int
ipstats_process_ifsm(FILE *fp, struct nlmsghdr *answer,
		     struct ipstats_stat_enabled *enabled)
{
	struct ipstats_stat_show_attrs show_attrs = {};
	const char *dev;
	int err = 0;
	int i;

	show_attrs.ifsm = NLMSG_DATA(answer);
	show_attrs.len = (answer->nlmsg_len -
			  NLMSG_LENGTH(sizeof(*show_attrs.ifsm)));
	if (show_attrs.len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", show_attrs.len);
		return -EINVAL;
	}

	err = ipstats_stat_show_attrs_alloc_tb(&show_attrs, 0);
	if (err)
		return err;

	dev = ll_index_to_name(show_attrs.ifsm->ifindex);

	print_headers(fp, "[STATS]");

	for (i = 0; i < enabled->nenabled; i++) {
		const struct ipstats_stat_desc *desc = enabled->enabled[i].desc;

		open_json_object(NULL);
		print_int(PRINT_ANY, "ifindex", "%d:",
			  show_attrs.ifsm->ifindex);
		print_color_string(PRINT_ANY, COLOR_IFNAME,
				   "ifname", " %s:", dev);
		ipstats_show_group(&enabled->enabled[i].sel);
		err = desc->show(&show_attrs, desc);
		if (err != 0)
			goto out;
		close_json_object();
		print_nl();
	}

out:
	ipstats_stat_show_attrs_free(&show_attrs);
	return err;
}

static bool
ipstats_req_should_filter_at(struct ipstats_stat_dump_filters *filters, int at)
{
	return filters->mask[at] != 0 &&
	       filters->mask[at] != (1 << ipstats_stat_ifla_max[at]) - 1;
}

static int
ipstats_req_add_filters(struct ipstats_req *req, void *data)
{
	struct ipstats_stat_dump_filters dump_filters = {};
	struct ipstats_stat_enabled *enabled = data;
	bool get_filters = false;
	int i;

	for (i = 0; i < enabled->nenabled; i++)
		enabled->enabled[i].desc->pack(&dump_filters,
					       enabled->enabled[i].desc);

	for (i = 1; i < ARRAY_SIZE(dump_filters.mask); i++) {
		if (ipstats_req_should_filter_at(&dump_filters, i)) {
			get_filters = true;
			break;
		}
	}

	req->ifsm.filter_mask = dump_filters.mask[0];
	if (get_filters) {
		struct rtattr *nest;

		nest = addattr_nest(&req->nlh, sizeof(*req),
				    IFLA_STATS_GET_FILTERS | NLA_F_NESTED);

		for (i = 1; i < ARRAY_SIZE(dump_filters.mask); i++) {
			if (ipstats_req_should_filter_at(&dump_filters, i))
				addattr32(&req->nlh, sizeof(*req), i,
					  dump_filters.mask[i]);
		}

		addattr_nest_end(&req->nlh, nest);
	}

	return 0;
}

static int
ipstats_show_one(int ifindex, struct ipstats_stat_enabled *enabled)
{
	struct ipstats_req req = {
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct if_stats_msg)),
		.nlh.nlmsg_type = RTM_GETSTATS,
		.ifsm.family = PF_UNSPEC,
		.ifsm.ifindex = ifindex,
	};
	struct nlmsghdr *answer;
	int err = 0;

	ipstats_req_add_filters(&req, enabled);
	if (rtnl_talk(&rth, &req.nlh, &answer) < 0)
		return -2;
	err = ipstats_process_ifsm(stdout, answer, enabled);
	free(answer);

	return err;
}

static int ipstats_dump_one(struct nlmsghdr *n, void *arg)
{
	struct ipstats_stat_enabled *enabled = arg;
	int rc;

	rc = ipstats_process_ifsm(stdout, n, enabled);
	if (rc)
		return rc;

	print_nl();
	return 0;
}

static int ipstats_dump(struct ipstats_stat_enabled *enabled)
{
	int rc = 0;

	if (rtnl_statsdump_req_filter(&rth, PF_UNSPEC, 0,
				      ipstats_req_add_filters,
				      enabled) < 0) {
		perror("Cannot send dump request");
		return -2;
	}

	if (rtnl_dump_filter(&rth, ipstats_dump_one, enabled) < 0) {
		fprintf(stderr, "Dump terminated\n");
		rc = -2;
	}

	fflush(stdout);
	return rc;
}

static int
ipstats_show_do(int ifindex, struct ipstats_stat_enabled *enabled)
{
	int rc;

	new_json_obj(json);
	if (ifindex)
		rc = ipstats_show_one(ifindex, enabled);
	else
		rc = ipstats_dump(enabled);
	delete_json_obj();

	return rc;
}

static int ipstats_add_enabled(struct ipstats_stat_enabled_one ens[],
			       size_t nens,
			       struct ipstats_stat_enabled *enabled)
{
	struct ipstats_stat_enabled_one *new_en;

	new_en = realloc(enabled->enabled,
			 sizeof(*new_en) * (enabled->nenabled + nens));
	if (new_en == NULL)
		return -ENOMEM;

	enabled->enabled = new_en;
	while (nens-- > 0)
		enabled->enabled[enabled->nenabled++] = *ens++;
	return 0;
}

static void ipstats_select_push(struct ipstats_sel *sel, const char *name)
{
	int i;

	for (i = 0; i < IPSTATS_LEVELS_COUNT; i++)
		if (sel->sel[i] == NULL) {
			sel->sel[i] = name;
			return;
		}

	assert(false);
}

static int
ipstats_enable_recursively(const struct ipstats_stat_desc *desc,
			   struct ipstats_stat_enabled *enabled,
			   const struct ipstats_sel *sel)
{
	bool found = false;
	size_t i;
	int err;

	if (desc->kind == IPSTATS_STAT_DESC_KIND_LEAF) {
		struct ipstats_stat_enabled_one en[] = {{
			.desc = desc,
			.sel = *sel,
		}};

		return ipstats_add_enabled(en, ARRAY_SIZE(en), enabled);
	}

	for (i = 0; i < desc->nsubs; i++) {
		struct ipstats_sel subsel = *sel;

		ipstats_select_push(&subsel, desc->subs[i]->name);
		err = ipstats_enable_recursively(desc->subs[i], enabled,
						 &subsel);
		if (err == -ENOENT)
			continue;
		if (err != 0)
			return err;
		found = true;
	}

	return found ? 0 : -ENOENT;
}

static int ipstats_comp_enabled(const void *a, const void *b)
{
	const struct ipstats_stat_enabled_one *en_a = a;
	const struct ipstats_stat_enabled_one *en_b = b;

	if (en_a->desc < en_b->desc)
		return -1;
	if (en_a->desc > en_b->desc)
		return 1;

	return 0;
}

static void ipstats_enabled_free(struct ipstats_stat_enabled *enabled)
{
	free(enabled->enabled);
}

static const struct ipstats_stat_desc *
ipstats_stat_desc_find(const struct ipstats_stat_desc *desc,
		       const char *name)
{
	size_t i;

	assert(desc->kind == IPSTATS_STAT_DESC_KIND_GROUP);
	for (i = 0; i < desc->nsubs; i++) {
		const struct ipstats_stat_desc *sub = desc->subs[i];

		if (strcmp(sub->name, name) == 0)
			return sub;
	}

	return NULL;
}

static const struct ipstats_stat_desc *
ipstats_enable_find_stat_desc(struct ipstats_sel *sel)
{
	const struct ipstats_stat_desc *toplev = &ipstats_stat_desc_toplev_group;
	const struct ipstats_stat_desc *desc = toplev;
	int i;

	for (i = 0; i < IPSTATS_LEVELS_COUNT; i++) {
		const struct ipstats_stat_desc *next_desc;

		if (sel->sel[i] == NULL)
			break;
		if (desc->kind == IPSTATS_STAT_DESC_KIND_LEAF) {
			fprintf(stderr, "Error: %s %s requested inside leaf %s %s\n",
				ipstats_levels[i], sel->sel[i],
				ipstats_levels[i - 1], desc->name);
			return NULL;
		}

		next_desc = ipstats_stat_desc_find(desc, sel->sel[i]);
		if (next_desc == NULL) {
			fprintf(stderr, "Error: no %s named %s found inside %s\n",
				ipstats_levels[i], sel->sel[i], desc->name);
			return NULL;
		}

		desc = next_desc;
	}

	return desc;
}

static int ipstats_enable(struct ipstats_sel *sel,
			  struct ipstats_stat_enabled *enabled)
{
	struct ipstats_stat_enabled new_enabled = {};
	const struct ipstats_stat_desc *desc;
	size_t i, j;
	int err = 0;

	desc = ipstats_enable_find_stat_desc(sel);
	if (desc == NULL)
		return -EINVAL;

	err = ipstats_enable_recursively(desc, &new_enabled, sel);
	if (err != 0)
		return err;

	err = ipstats_add_enabled(new_enabled.enabled, new_enabled.nenabled,
				  enabled);
	if (err != 0)
		goto out;

	qsort(enabled->enabled, enabled->nenabled, sizeof(*enabled->enabled),
	      ipstats_comp_enabled);

	for (i = 1, j = 1; i < enabled->nenabled; i++) {
		if (enabled->enabled[i].desc != enabled->enabled[j - 1].desc)
			enabled->enabled[j++] = enabled->enabled[i];
	}
	enabled->nenabled = j;

out:
	ipstats_enabled_free(&new_enabled);
	return err;
}

static int ipstats_enable_check(struct ipstats_sel *sel,
				struct ipstats_stat_enabled *enabled)
{
	int err;
	int i;

	err = ipstats_enable(sel, enabled);
	if (err == -ENOENT) {
		fprintf(stderr, "The request for");
		for (i = 0; i < IPSTATS_LEVELS_COUNT; i++)
			if (sel->sel[i] != NULL)
				fprintf(stderr, " %s %s",
					ipstats_levels[i], sel->sel[i]);
			else
				break;
		fprintf(stderr, " did not match any known stats.\n");
	}

	return err;
}

static int do_help(void)
{
	const struct ipstats_stat_desc *toplev = &ipstats_stat_desc_toplev_group;
	int i;

	fprintf(stderr,
		"Usage: ip stats help\n"
		"       ip stats show [ dev DEV ] [ group GROUP [ subgroup SUBGROUP [ suite SUITE ] ... ] ... ] ...\n"
		"       ip stats set dev DEV l3_stats { on | off }\n"
		);

	for (i = 0; i < toplev->nsubs; i++) {
		const struct ipstats_stat_desc *desc = toplev->subs[i];

		if (i == 0)
			fprintf(stderr, "GROUP := { %s", desc->name);
		else
			fprintf(stderr, " | %s", desc->name);
	}
	if (i > 0)
		fprintf(stderr, " }\n");

	for (i = 0; i < toplev->nsubs; i++) {
		const struct ipstats_stat_desc *desc = toplev->subs[i];
		bool opened = false;
		size_t j;

		if (desc->kind != IPSTATS_STAT_DESC_KIND_GROUP)
			continue;

		for (j = 0; j < desc->nsubs; j++) {
			size_t k;

			if (j == 0)
				fprintf(stderr, "%s SUBGROUP := {", desc->name);
			else
				fprintf(stderr, " |");
			fprintf(stderr, " %s", desc->subs[j]->name);
			opened = true;

			if (desc->subs[j]->kind != IPSTATS_STAT_DESC_KIND_GROUP)
				continue;

			for (k = 0; k < desc->subs[j]->nsubs; k++)
				fprintf(stderr, " [ suite %s ]",
					desc->subs[j]->subs[k]->name);
		}
		if (opened)
			fprintf(stderr, " }\n");
	}

	return 0;
}

static int ipstats_select(struct ipstats_sel *old_sel,
			  const char *new_sel, int level,
			  struct ipstats_stat_enabled *enabled)
{
	int err;
	int i;

	for (i = 0; i < level; i++) {
		if (old_sel->sel[i] == NULL) {
			fprintf(stderr, "Error: %s %s requested without selecting a %s first\n",
				ipstats_levels[level], new_sel,
				ipstats_levels[i]);
			return -EINVAL;
		}
	}

	for (i = level; i < IPSTATS_LEVELS_COUNT; i++) {
		if (old_sel->sel[i] != NULL) {
			err = ipstats_enable_check(old_sel, enabled);
			if (err)
				return err;
			break;
		}
	}

	old_sel->sel[level] = new_sel;
	for (i = level + 1; i < IPSTATS_LEVELS_COUNT; i++)
		old_sel->sel[i] = NULL;

	return 0;
}

static int ipstats_show(int argc, char **argv)
{
	struct ipstats_stat_enabled enabled = {};
	struct ipstats_sel sel = {};
	const char *dev = NULL;
	int ifindex;
	int err;
	int i;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (dev != NULL)
				duparg2("dev", *argv);
			if (check_ifname(*argv))
				invarg("\"dev\" not a valid ifname", *argv);
			dev = *argv;
		} else if (strcmp(*argv, "help") == 0) {
			do_help();
			return 0;
		} else {
			bool found_level = false;

			for (i = 0; i < ARRAY_SIZE(ipstats_levels); i++) {
				if (strcmp(*argv, ipstats_levels[i]) == 0) {
					NEXT_ARG();
					err = ipstats_select(&sel, *argv, i,
							     &enabled);
					if (err)
						goto err;

					found_level = true;
				}
			}

			if (!found_level) {
				fprintf(stderr, "What is \"%s\"?\n", *argv);
				do_help();
				err = -EINVAL;
				goto err;
			}
		}

		NEXT_ARG_FWD();
	}

	/* Push whatever was given. */
	err = ipstats_enable_check(&sel, &enabled);
	if (err)
		goto err;

	if (dev) {
		ifindex = ll_name_to_index(dev);
		if (!ifindex) {
			err = nodev(dev);
			goto err;
		}
	} else {
		ifindex = 0;
	}


	err = ipstats_show_do(ifindex, &enabled);

err:
	ipstats_enabled_free(&enabled);
	return err;
}

static int ipstats_set_do(int ifindex, int at, bool enable)
{
	struct ipstats_req req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct if_stats_msg)),
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_type = RTM_SETSTATS,
		.ifsm.family = PF_UNSPEC,
		.ifsm.ifindex = ifindex,
	};

	addattr8(&req.nlh, sizeof(req), at, enable);

	if (rtnl_talk(&rth, &req.nlh, NULL) < 0)
		return -2;
	return 0;
}

static int ipstats_set(int argc, char **argv)
{
	const char *dev = NULL;
	bool enable = false;
	int ifindex;
	int at = 0;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (dev)
				duparg2("dev", *argv);
			if (check_ifname(*argv))
				invarg("\"dev\" not a valid ifname", *argv);
			dev = *argv;
		} else if (strcmp(*argv, "l3_stats") == 0) {
			int err;

			NEXT_ARG();
			if (at) {
				fprintf(stderr, "A statistics suite to toggle was already given.\n");
				return -EINVAL;
			}
			at = IFLA_STATS_SET_OFFLOAD_XSTATS_L3_STATS;
			enable = parse_on_off("l3_stats", *argv, &err);
			if (err)
				return err;
		} else if (strcmp(*argv, "help") == 0) {
			do_help();
			return 0;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			do_help();
			return -EINVAL;
		}

		NEXT_ARG_FWD();
	}

	if (!dev) {
		fprintf(stderr, "Not enough information: \"dev\" argument is required.\n");
		exit(-1);
	}

	if (!at) {
		fprintf(stderr, "Not enough information: stat type to toggle is required.\n");
		exit(-1);
	}

	ifindex = ll_name_to_index(dev);
	if (!ifindex)
		return nodev(dev);

	return ipstats_set_do(ifindex, at, enable);
}

int do_ipstats(int argc, char **argv)
{
	int rc;

	if (argc == 0) {
		rc = ipstats_show(0, NULL);
	} else if (strcmp(*argv, "help") == 0) {
		do_help();
		rc = 0;
	} else if (strcmp(*argv, "show") == 0) {
		/* Invoking "stats show" implies one -s. Passing -d adds one
		 * more -s.
		 */
		show_stats += show_details + 1;
		rc = ipstats_show(argc-1, argv+1);
	} else if (strcmp(*argv, "set") == 0) {
		rc = ipstats_set(argc-1, argv+1);
	} else {
		fprintf(stderr, "Command \"%s\" is unknown, try \"ip stats help\".\n",
			*argv);
		rc = -1;
	}

	return rc;
}

int ipstats_print(struct nlmsghdr *n, void *arg)
{
	struct ipstats_stat_enabled_one one = {
		.desc = &ipstats_stat_desc_offload_hw_s_info,
	};
	struct ipstats_stat_enabled enabled = {
		.enabled = &one,
		.nenabled = 1,
	};
	FILE *fp = arg;
	int rc;

	rc = ipstats_process_ifsm(fp, n, &enabled);
	if (rc)
		return rc;

	fflush(fp);
	return 0;
}
