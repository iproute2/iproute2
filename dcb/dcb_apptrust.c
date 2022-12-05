// SPDX-License-Identifier: GPL-2.0+

#include <errno.h>
#include <linux/dcbnl.h>

#include "dcb.h"
#include "utils.h"

static void dcb_apptrust_help_set(void)
{
	fprintf(stderr,
		"Usage: dcb apptrust set dev STRING\n"
		"       [ order [ ethtype | stream-port | dgram-port | port | dscp | pcp ] ]\n"
		"\n");
}

static void dcb_apptrust_help_show(void)
{
	fprintf(stderr, "Usage: dcb apptrust show dev STRING\n"
			"       [ order ]\n"
			"\n");
}

static void dcb_apptrust_help(void)
{
	fprintf(stderr, "Usage: dcb apptrust help\n"
			"\n");
	dcb_apptrust_help_show();
	dcb_apptrust_help_set();
}

static const char *const selector_names[] = {
	[IEEE_8021QAZ_APP_SEL_ETHERTYPE] = "ethtype",
	[IEEE_8021QAZ_APP_SEL_STREAM]    = "stream-port",
	[IEEE_8021QAZ_APP_SEL_DGRAM]     = "dgram-port",
	[IEEE_8021QAZ_APP_SEL_ANY]       = "port",
	[IEEE_8021QAZ_APP_SEL_DSCP]      = "dscp",
	[DCB_APP_SEL_PCP]                = "pcp",
};

struct dcb_apptrust_table {
	__u8 selectors[IEEE_8021QAZ_APP_SEL_MAX + 1];
	int nselectors;
};

static bool dcb_apptrust_contains(const struct dcb_apptrust_table *table,
				  __u8 selector)
{
	int i;

	for (i = 0; i < table->nselectors; i++)
		if (table->selectors[i] == selector)
			return true;

	return false;
}

static void dcb_apptrust_print_order(const struct dcb_apptrust_table *table)
{
	const char *str;
	__u8 selector;
	int i;

	open_json_array(PRINT_JSON, "order");
	print_string(PRINT_FP, NULL, "order: ", NULL);

	for (i = 0; i < table->nselectors; i++) {
		selector = table->selectors[i];
		str = selector_names[selector];
		print_string(PRINT_ANY, NULL, "%s ", str);
	}
	print_nl();

	close_json_array(PRINT_JSON, "order");
}

static void dcb_apptrust_print(const struct dcb_apptrust_table *table)
{
	dcb_apptrust_print_order(table);
	print_nl();
}

static int dcb_apptrust_get_cb(const struct nlattr *attr, void *data)
{
	struct dcb_apptrust_table *table = data;
	uint16_t type;
	__u8 selector;

	type = mnl_attr_get_type(attr);

	if (!dcb_app_attr_type_validate(type)) {
		fprintf(stderr,
			"Unknown attribute in DCB_ATTR_IEEE_APP_TRUST_TABLE: %d\n",
			type);
		return MNL_CB_OK;
	}

	if (mnl_attr_get_payload_len(attr) < 1) {
		fprintf(stderr,
			"DCB_ATTR_IEEE_APP_TRUST payload expected to have size %zd, not %d\n",
			sizeof(struct dcb_app), mnl_attr_get_payload_len(attr));
		return MNL_CB_OK;
	}

	selector = mnl_attr_get_u8(attr);

	/* Check that selector is encapsulated in the right attribute */
	if (!dcb_app_selector_validate(type, selector)) {
		fprintf(stderr, "Wrong type for selector: %s\n",
			selector_names[selector]);
		return MNL_CB_OK;
	}

	table->selectors[table->nselectors++] = selector;

	return MNL_CB_OK;
}

static int dcb_apptrust_get(struct dcb *dcb, const char *dev,
			    struct dcb_apptrust_table *table)
{
	uint16_t payload_len;
	void *payload;
	int ret;

	ret = dcb_get_attribute_va(dcb, dev, DCB_ATTR_DCB_APP_TRUST_TABLE,
				   &payload, &payload_len);
	if (ret != 0)
		return ret;

	ret = mnl_attr_parse_payload(payload, payload_len, dcb_apptrust_get_cb,
				     table);
	if (ret != MNL_CB_OK)
		return -EINVAL;

	return 0;
}

static int dcb_apptrust_set_cb(struct dcb *dcb, struct nlmsghdr *nlh,
			       void *data)
{
	const struct dcb_apptrust_table *table = data;
	enum ieee_attrs_app type;
	struct nlattr *nest;
	int i;

	nest = mnl_attr_nest_start(nlh, DCB_ATTR_DCB_APP_TRUST_TABLE);

	for (i = 0; i < table->nselectors; i++) {
		type = dcb_app_attr_type_get(table->selectors[i]);
		mnl_attr_put_u8(nlh, type, table->selectors[i]);
	}

	mnl_attr_nest_end(nlh, nest);

	return 0;
}

static int dcb_apptrust_set(struct dcb *dcb, const char *dev,
			    const struct dcb_apptrust_table *table)
{
	return dcb_set_attribute_va(dcb, DCB_CMD_IEEE_SET, dev,
				    &dcb_apptrust_set_cb, (void *)table);
}

static __u8 dcb_apptrust_parse_selector(const char *selector, int *err)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(selector_names); i++) {
		if (selector_names[i] &&
		    strcmp(selector, selector_names[i]) == 0) {
			    *err = 0;
			    return i;
		    }
	}

	*err = -EINVAL;
	return 0;
}

static int dcb_apptrust_parse_selector_list(int *argcp, char ***argvp,
					    struct dcb_apptrust_table *table)
{
	int argc = *argcp, err;
	char **argv = *argvp;
	__u8 selector;

	/* No trusted selectors ? */
	if (argc == 0)
		goto out;

	while (argc > 0) {
		selector = dcb_apptrust_parse_selector(*argv, &err);
		if (err < 0)
			goto out;

		if (table->nselectors > IEEE_8021QAZ_APP_SEL_MAX)
			return -ERANGE;

		if (dcb_apptrust_contains(table, selector)) {
			fprintf(stderr, "Duplicate selector: %s\n",
				selector_names[selector]);
			return -EINVAL;
		}

		table->selectors[table->nselectors++] = selector;

		NEXT_ARG_FWD();
	}

out:
	*argcp = argc;
	*argvp = argv;

	return 0;
}

static int dcb_cmd_apptrust_set(struct dcb *dcb, const char *dev, int argc,
				char **argv)
{
	struct dcb_apptrust_table table = { 0 };
	int ret;

	if (!argc) {
		dcb_apptrust_help_set();
		return 0;
	}

	do {
		if (strcmp(*argv, "help") == 0) {
			dcb_apptrust_help_set();
			return 0;
		} else if (strcmp(*argv, "order") == 0) {
			NEXT_ARG_FWD();
			ret = dcb_apptrust_parse_selector_list(&argc, &argv,
							       &table);
			if (ret < 0) {
				fprintf(stderr, "Invalid list of selectors\n");
				return -EINVAL;
			}
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			dcb_apptrust_help_set();
			return -EINVAL;
		}
	} while (argc > 0);

	return dcb_apptrust_set(dcb, dev, &table);
}

static int dcb_cmd_apptrust_show(struct dcb *dcb, const char *dev, int argc,
				 char **argv)
{
	struct dcb_apptrust_table table = { 0 };
	int ret;

	ret = dcb_apptrust_get(dcb, dev, &table);
	if (ret)
		return ret;

	open_json_object(NULL);

	if (!argc) {
		dcb_apptrust_print(&table);
		goto out;
	}

	do {
		if (strcmp(*argv, "help") == 0) {
			dcb_apptrust_help_show();
			return 0;
		} else if (strcmp(*argv, "order") == 0) {
			dcb_apptrust_print_order(&table);
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			dcb_apptrust_help_show();
			return -EINVAL;
		}

		NEXT_ARG_FWD();
	} while (argc > 0);

out:
	close_json_object();
	return 0;
}

int dcb_cmd_apptrust(struct dcb *dcb, int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		dcb_apptrust_help();
		return 0;
	} else if (strcmp(*argv, "show") == 0) {
		NEXT_ARG_FWD();
		return dcb_cmd_parse_dev(dcb, argc, argv, dcb_cmd_apptrust_show,
					 dcb_apptrust_help_show);
	} else if (strcmp(*argv, "set") == 0) {
		NEXT_ARG_FWD();
		return dcb_cmd_parse_dev(dcb, argc, argv, dcb_cmd_apptrust_set,
					 dcb_apptrust_help_set);
	} else {
		fprintf(stderr, "What is \"%s\"?\n", *argv);
		dcb_apptrust_help();
		return -EINVAL;
	}
}
