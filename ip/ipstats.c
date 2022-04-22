// SPDX-License-Identifier: GPL-2.0+
#include <assert.h>
#include <errno.h>

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
	if (attrs->tbs[group] == NULL)
		return -ENOMEM;

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

#define IPSTATS_RTA_PAYLOAD(TYPE, AT)					\
	({								\
		const struct rtattr *__at = (AT);			\
		TYPE *__ret = NULL;					\
									\
		if (__at != NULL &&					\
		    __at->rta_len - RTA_LENGTH(0) >= sizeof(TYPE))	\
			__ret = RTA_DATA(__at);				\
		__ret;							\
	})

static int ipstats_show_64(struct ipstats_stat_show_attrs *attrs,
			   unsigned int group, unsigned int subgroup)
{
	struct rtnl_link_stats64 *stats;
	const struct rtattr *at;
	int err;

	at = ipstats_stat_show_get_attr(attrs, group, subgroup, &err);
	if (at == NULL)
		return err;

	stats = IPSTATS_RTA_PAYLOAD(struct rtnl_link_stats64, at);
	if (stats == NULL) {
		fprintf(stderr, "Error: attribute payload too short");
		return -EINVAL;
	}

	open_json_object("stats64");
	print_stats64(stdout, stats, NULL, NULL);
	close_json_object();
	return 0;
}

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

static const struct ipstats_stat_desc *ipstats_stat_desc_toplev_subs[] = {
	&ipstats_stat_desc_toplev_link,
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
ipstats_process_ifsm(struct nlmsghdr *answer,
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
	if (err != 0) {
		fprintf(stderr, "Error parsing netlink answer: %s\n",
			strerror(err));
		return err;
	}

	dev = ll_index_to_name(show_attrs.ifsm->ifindex);

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
	err = ipstats_process_ifsm(answer, enabled);
	free(answer);

	return err;
}

static int ipstats_dump_one(struct nlmsghdr *n, void *arg)
{
	struct ipstats_stat_enabled *enabled = arg;
	int rc;

	rc = ipstats_process_ifsm(n, enabled);
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
		"       ip stats show [ dev DEV ] [ group GROUP [ subgroup SUBGROUP ] ... ] ...\n"
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
			if (j == 0)
				fprintf(stderr, "%s SUBGROUP := {", desc->name);
			else
				fprintf(stderr, " |");
			fprintf(stderr, " %s", desc->subs[j]->name);
			opened = true;

			if (desc->subs[j]->kind != IPSTATS_STAT_DESC_KIND_GROUP)
				continue;
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
