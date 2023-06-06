// SPDX-License-Identifier: GPL-2.0+

#include <errno.h>
#include <linux/dcbnl.h>
#include <stdio.h>

#include "dcb.h"
#include "utils.h"

static void dcb_rewr_help_add(void)
{
	fprintf(stderr,
		"Usage: dcb rewr { add | del | replace } dev STRING\n"
		"           [ prio-pcp PRIO:PCP ]\n"
		"           [ prio-dscp PRIO:DSCP ]\n"
		"\n"
		" where PRIO := { 0 .. 7 }\n"
		"       PCP  := { 0(nd/de) .. 7(nd/de) }\n"
		"       DSCP := { 0 .. 63 }\n"
		"\n"
	);
}

static void dcb_rewr_help_show_flush(void)
{
	fprintf(stderr,
		"Usage: dcb rewr { show | flush } dev STRING\n"
		"           [ prio-pcp ]\n"
		"           [ prio-dscp ]\n"
		"\n"
	);
}

static void dcb_rewr_help(void)
{
	fprintf(stderr,
		"Usage: dcb rewr help\n"
		"\n"
	);
	dcb_rewr_help_show_flush();
	dcb_rewr_help_add();
}

static void dcb_rewr_parse_mapping_cb(__u32 key, __u64 value, void *data)
{
	struct dcb_app_parse_mapping *pm = data;
	struct dcb_app app = {
		.selector = pm->selector,
		.priority = key,
		.protocol = value,
	};

	if (pm->err)
		return;

	pm->err = dcb_app_table_push(pm->tab, &app);
}

static int dcb_rewr_parse_mapping_prio_pcp(__u32 key, char *value, void *data)
{
	__u32 pcp;

	if (dcb_app_parse_pcp(&pcp, value))
		return -EINVAL;

	return dcb_parse_mapping("PRIO", key, IEEE_8021QAZ_MAX_TCS - 1,
				 "PCP", pcp, DCB_APP_PCP_MAX,
				 dcb_rewr_parse_mapping_cb, data);
}

static int dcb_rewr_parse_mapping_prio_dscp(__u32 key, char *value, void *data)
{
	__u32 dscp;

	if (dcb_app_parse_dscp(&dscp, value))
		return -EINVAL;

	return dcb_parse_mapping("PRIO", key, IEEE_8021QAZ_MAX_TCS - 1,
				 "DSCP", dscp, DCB_APP_DSCP_MAX,
				 dcb_rewr_parse_mapping_cb, data);
}

static void dcb_rewr_print_prio_pid(int (*print_pid)(__u16 protocol),
				    const struct dcb_app *app)
{
	print_uint(PRINT_ANY, NULL, "%u:", app->priority);
	print_pid(app->protocol);
}

static void dcb_rewr_print_prio_pcp(const struct dcb *dcb,
				    const struct dcb_app_table *tab)
{
	dcb_app_print_filtered(tab, dcb_app_is_pcp,
			       dcb_rewr_print_prio_pid,
			       dcb->numeric ? dcb_app_print_pid_dec :
					      dcb_app_print_pid_pcp,
			       "prio_pcp", "prio-pcp");
}

static void dcb_rewr_print_prio_dscp(const struct dcb *dcb,
				     const struct dcb_app_table *tab)
{
	dcb_app_print_filtered(tab, dcb_app_is_dscp,
			       dcb_rewr_print_prio_pid,
			       dcb->numeric ? dcb_app_print_pid_dec :
					      dcb_app_print_pid_dscp,
			       "prio_dscp", "prio-dscp");
}

static void dcb_rewr_print(const struct dcb *dcb,
			   const struct dcb_app_table *tab)
{
	dcb_rewr_print_prio_pcp(dcb, tab);
	dcb_rewr_print_prio_dscp(dcb, tab);
}

static bool dcb_rewr_prio_eq(const struct dcb_app *aa, const struct dcb_app *ab)
{
	return aa->selector == ab->selector &&
	       aa->priority == ab->priority;
}

static int dcb_cmd_rewr_parse_add_del(struct dcb *dcb, const char *dev,
				      int argc, char **argv,
				      struct dcb_app_table *tab)
{
	struct dcb_app_parse_mapping pm = {
		.tab = tab,
	};
	int ret;

	if (!argc) {
		dcb_rewr_help_add();
		return 0;
	}

	do {
		if (strcmp(*argv, "help") == 0) {
			dcb_rewr_help_add();
			return 0;
		} else if (strcmp(*argv, "prio-pcp") == 0) {
			NEXT_ARG();
			pm.selector = DCB_APP_SEL_PCP;
			ret = parse_mapping(&argc, &argv, false,
					    &dcb_rewr_parse_mapping_prio_pcp,
					    &pm);
		} else if (strcmp(*argv, "prio-dscp") == 0) {
			NEXT_ARG();
			pm.selector = IEEE_8021QAZ_APP_SEL_DSCP;
			ret = parse_mapping(&argc, &argv, false,
					    &dcb_rewr_parse_mapping_prio_dscp,
					    &pm);
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			dcb_rewr_help_add();
			return -EINVAL;
		}

		if (ret != 0) {
			fprintf(stderr, "Invalid mapping %s\n", *argv);
			return ret;
		}
		if (pm.err)
			return pm.err;
	} while (argc > 0);

	return 0;
}

static int dcb_cmd_rewr_add(struct dcb *dcb, const char *dev, int argc,
			    char **argv)
{
	struct dcb_app_table tab = { .attr = DCB_ATTR_DCB_REWR_TABLE };
	int ret;

	ret = dcb_cmd_rewr_parse_add_del(dcb, dev, argc, argv, &tab);
	if (ret != 0)
		return ret;

	ret = dcb_app_add_del(dcb, dev, DCB_CMD_IEEE_SET, &tab, NULL);
	dcb_app_table_fini(&tab);
	return ret;
}

static int dcb_cmd_rewr_del(struct dcb *dcb, const char *dev, int argc,
			    char **argv)
{
	struct dcb_app_table tab = { .attr = DCB_ATTR_DCB_REWR_TABLE };
	int ret;

	ret = dcb_cmd_rewr_parse_add_del(dcb, dev, argc, argv, &tab);
	if (ret != 0)
		return ret;

	ret = dcb_app_add_del(dcb, dev, DCB_CMD_IEEE_DEL, &tab, NULL);
	dcb_app_table_fini(&tab);
	return ret;
}

static int dcb_cmd_rewr_replace(struct dcb *dcb, const char *dev, int argc,
				char **argv)
{
	struct dcb_app_table orig = { .attr = DCB_ATTR_DCB_REWR_TABLE };
	struct dcb_app_table tab = { .attr = DCB_ATTR_DCB_REWR_TABLE };
	struct dcb_app_table new = { .attr = DCB_ATTR_DCB_REWR_TABLE };
	int ret;

	ret = dcb_app_get(dcb, dev, &orig);
	if (ret != 0)
		return ret;

	ret = dcb_cmd_rewr_parse_add_del(dcb, dev, argc, argv, &tab);
	if (ret != 0)
		goto out;

	/* Attempts to add an existing entry would be rejected, so drop
	 * these entries from tab.
	 */
	ret = dcb_app_table_copy(&new, &tab);
	if (ret != 0)
		goto out;
	dcb_app_table_remove_existing(&new, &orig);

	ret = dcb_app_add_del(dcb, dev, DCB_CMD_IEEE_SET, &new, NULL);
	if (ret != 0) {
		fprintf(stderr, "Could not add new rewrite entries\n");
		goto out;
	}

	/* Remove the obsolete entries. */
	dcb_app_table_remove_replaced(&orig, &tab, dcb_rewr_prio_eq);
	ret = dcb_app_add_del(dcb, dev, DCB_CMD_IEEE_DEL, &orig, NULL);
	if (ret != 0) {
		fprintf(stderr, "Could not remove replaced rewrite entries\n");
		goto out;
	}

out:
	dcb_app_table_fini(&new);
	dcb_app_table_fini(&tab);
	dcb_app_table_fini(&orig);
	return 0;
}

static int dcb_cmd_rewr_show(struct dcb *dcb, const char *dev, int argc,
			     char **argv)
{
	struct dcb_app_table tab = { .attr = DCB_ATTR_DCB_REWR_TABLE };
	int ret;

	ret = dcb_app_get(dcb, dev, &tab);
	if (ret != 0)
		return ret;

	dcb_app_table_sort(&tab);

	open_json_object(NULL);

	if (!argc) {
		dcb_rewr_print(dcb, &tab);
		goto out;
	}

	do {
		if (strcmp(*argv, "help") == 0) {
			dcb_rewr_help_show_flush();
			goto out;
		} else if (strcmp(*argv, "prio-pcp") == 0) {
			dcb_rewr_print_prio_pcp(dcb, &tab);
		} else if (strcmp(*argv, "prio-dscp") == 0) {
			dcb_rewr_print_prio_dscp(dcb, &tab);
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			dcb_rewr_help_show_flush();
			ret = -EINVAL;
			goto out;
		}

		NEXT_ARG_FWD();
	} while (argc > 0);

out:
	close_json_object();
	dcb_app_table_fini(&tab);
	return ret;
}

static int dcb_cmd_rewr_flush(struct dcb *dcb, const char *dev, int argc,
			      char **argv)
{
	struct dcb_app_table tab = { .attr = DCB_ATTR_DCB_REWR_TABLE };
	int ret;

	ret = dcb_app_get(dcb, dev, &tab);
	if (ret != 0)
		return ret;

	if (!argc) {
		ret = dcb_app_add_del(dcb, dev, DCB_CMD_IEEE_DEL, &tab,
				      NULL);
		goto out;
	}

	do {
		if (strcmp(*argv, "help") == 0) {
			dcb_rewr_help_show_flush();
			goto out;
		} else if (strcmp(*argv, "prio-pcp") == 0) {
			ret = dcb_app_add_del(dcb, dev, DCB_CMD_IEEE_DEL, &tab,
					      &dcb_app_is_pcp);
			if (ret != 0)
				goto out;
		} else if (strcmp(*argv, "prio-dscp") == 0) {
			ret = dcb_app_add_del(dcb, dev, DCB_CMD_IEEE_DEL, &tab,
					      &dcb_app_is_dscp);
			if (ret != 0)
				goto out;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			dcb_rewr_help_show_flush();
			ret = -EINVAL;
			goto out;
		}

		NEXT_ARG_FWD();
	} while (argc > 0);

out:
	dcb_app_table_fini(&tab);
	return ret;
}

int dcb_cmd_rewr(struct dcb *dcb, int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		dcb_rewr_help();
		return 0;
	} else if (strcmp(*argv, "show") == 0) {
		NEXT_ARG_FWD();
		return dcb_cmd_parse_dev(dcb, argc, argv, dcb_cmd_rewr_show,
					 dcb_rewr_help_show_flush);
	} else if (strcmp(*argv, "flush") == 0) {
		NEXT_ARG_FWD();
		return dcb_cmd_parse_dev(dcb, argc, argv, dcb_cmd_rewr_flush,
					 dcb_rewr_help_show_flush);
	} else if (strcmp(*argv, "add") == 0) {
		NEXT_ARG_FWD();
		return dcb_cmd_parse_dev(dcb, argc, argv, dcb_cmd_rewr_add,
					 dcb_rewr_help_add);
	} else if (strcmp(*argv, "del") == 0) {
		NEXT_ARG_FWD();
		return dcb_cmd_parse_dev(dcb, argc, argv, dcb_cmd_rewr_del,
					 dcb_rewr_help_add);
	} else if (strcmp(*argv, "replace") == 0) {
		NEXT_ARG_FWD();
		return dcb_cmd_parse_dev(dcb, argc, argv, dcb_cmd_rewr_replace,
					 dcb_rewr_help_add);
	} else {
		fprintf(stderr, "What is \"%s\"?\n", *argv);
		dcb_rewr_help();
		return -EINVAL;
	}
}
