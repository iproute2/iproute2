/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * dpll.c	DPLL tool
 *
 * Authors:	Petr Oros <poros@redhat.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <linux/dpll.h>
#include <linux/genetlink.h>
#include <libmnl/libmnl.h>

#include <mnlg.h>
#include "mnl_utils.h"
#include "version.h"
#include "utils.h"
#include "json_print.h"

#define pr_err(args...) fprintf(stderr, ##args)

int json;

struct dpll {
	struct mnlu_gen_socket nlg;
	int argc;
	char **argv;
};

static const char *str_enable_disable(bool v)
{
	return v ? "enable" : "disable";
}

static struct str_num_map pin_state_map[] = {
	{ .str = "connected", .num = DPLL_PIN_STATE_CONNECTED },
	{ .str = "disconnected", .num = DPLL_PIN_STATE_DISCONNECTED },
	{ .str = "selectable", .num = DPLL_PIN_STATE_SELECTABLE },
	{
		.str = NULL,
	},
};

static struct str_num_map pin_type_map[] = {
	{ .str = "mux", .num = DPLL_PIN_TYPE_MUX },
	{ .str = "ext", .num = DPLL_PIN_TYPE_EXT },
	{ .str = "synce-eth-port", .num = DPLL_PIN_TYPE_SYNCE_ETH_PORT },
	{ .str = "int-oscillator", .num = DPLL_PIN_TYPE_INT_OSCILLATOR },
	{ .str = "gnss", .num = DPLL_PIN_TYPE_GNSS },
	{
		.str = NULL,
	},
};

static struct str_num_map pin_direction_map[] = {
	{ .str = "input", .num = DPLL_PIN_DIRECTION_INPUT },
	{ .str = "output", .num = DPLL_PIN_DIRECTION_OUTPUT },
	{
		.str = NULL,
	},
};

static int dpll_argc(struct dpll *dpll)
{
	return dpll->argc;
}

static const char *dpll_argv(struct dpll *dpll)
{
	if (dpll_argc(dpll) == 0)
		return NULL;
	return *dpll->argv;
}

static void dpll_arg_inc(struct dpll *dpll)
{
	if (dpll_argc(dpll) == 0)
		return;
	dpll->argc--;
	dpll->argv++;
}

static const char *dpll_argv_next(struct dpll *dpll)
{
	const char *ret;

	dpll_arg_inc(dpll);
	if (dpll_argc(dpll) == 0)
		return NULL;

	ret = *dpll->argv;
	dpll_arg_inc(dpll);
	return ret;
}

static bool dpll_argv_match(struct dpll *dpll, const char *pattern)
{
	if (dpll_argc(dpll) == 0)
		return false;
	return strcmp(dpll_argv(dpll), pattern) == 0;
}

static int dpll_arg_required(struct dpll *dpll, const char *arg_name)
{
	if (dpll_argc(dpll) == 0) {
		pr_err("%s requires an argument\n", arg_name);
		return -EINVAL;
	}
	return 0;
}

static bool dpll_argv_match_inc(struct dpll *dpll, const char *pattern)
{
	if (!dpll_argv_match(dpll, pattern))
		return false;
	dpll_arg_inc(dpll);
	return true;
}

static bool dpll_no_arg(struct dpll *dpll)
{
	return dpll_argc(dpll) == 0;
}

static int str_to_dpll_pin_state(const char *state_str, __u32 *state)
{
	int num;

	num = str_map_lookup_str(pin_state_map, state_str);
	if (num < 0)
		return num;
	*state = num;
	return 0;
}

static int str_to_dpll_pin_type(const char *type_str, __u32 *type)
{
	int num;

	num = str_map_lookup_str(pin_type_map, type_str);
	if (num < 0)
		return num;
	*type = num;
	return 0;
}

static int dpll_parse_state(struct dpll *dpll, __u32 *state)
{
	const char *str = dpll_argv(dpll);

	if (str_to_dpll_pin_state(str, state)) {
		pr_err("invalid state: %s (use connected/disconnected/selectable)\n",
		       str);
		return -EINVAL;
	}
	dpll_arg_inc(dpll);
	return 0;
}

static int dpll_parse_direction(struct dpll *dpll, __u32 *direction)
{
	const char *str = dpll_argv(dpll);
	int num;

	num = str_map_lookup_str(pin_direction_map, str);
	if (num < 0) {
		pr_err("invalid direction: %s (use input/output)\n", str);
		return num;
	}
	*direction = num;
	dpll_arg_inc(dpll);
	return 0;
}

static int dpll_parse_pin_type(struct dpll *dpll, __u32 *type)
{
	const char *str = dpll_argv(dpll);

	if (str_to_dpll_pin_type(str, type)) {
		pr_err("invalid type: %s (use mux/ext/synce-eth-port/int-oscillator/gnss)\n",
		       str);
		return -EINVAL;
	}
	dpll_arg_inc(dpll);
	return 0;
}

static int dpll_parse_u32(struct dpll *dpll, const char *arg_name,
			  __u32 *val_ptr)
{
	const char *__str = dpll_argv_next(dpll);

	if (!__str) {
		pr_err("%s requires an argument\n", arg_name);
		return -EINVAL;
	}
	if (get_u32(val_ptr, __str, 0)) {
		pr_err("invalid %s: %s\n", arg_name, __str);
		return -EINVAL;
	}
	return 0;
}

static int dpll_parse_attr_u32(struct dpll *dpll, struct nlmsghdr *nlh,
			       const char *arg_name, int attr_id)
{
	__u32 val;

	if (dpll_parse_u32(dpll, arg_name, &val))
		return -EINVAL;
	mnl_attr_put_u32(nlh, attr_id, val);
	return 0;
}

static int dpll_parse_attr_s32(struct dpll *dpll, struct nlmsghdr *nlh,
			       const char *arg_name, int attr_id)
{
	const char *str = dpll_argv_next(dpll);
	__s32 val;

	if (!str) {
		pr_err("%s requires an argument\n", arg_name);
		return -EINVAL;
	}
	if (get_s32(&val, str, 0)) {
		pr_err("invalid %s: %s\n", arg_name, str);
		return -EINVAL;
	}
	mnl_attr_put(nlh, attr_id, sizeof(val), &val);
	return 0;
}

static int dpll_parse_attr_u64(struct dpll *dpll, struct nlmsghdr *nlh,
			       const char *arg_name, int attr_id)
{
	const char *str = dpll_argv_next(dpll);
	__u64 val;

	if (!str) {
		pr_err("%s requires an argument\n", arg_name);
		return -EINVAL;
	}
	if (get_u64(&val, str, 0)) {
		pr_err("invalid %s: %s\n", arg_name, str);
		return -EINVAL;
	}
	mnl_attr_put_u64(nlh, attr_id, val);
	return 0;
}

static int dpll_parse_attr_str(struct dpll *dpll, struct nlmsghdr *nlh,
			       const char *arg_name, int attr_id)
{
	const char *str = dpll_argv_next(dpll);

	if (!str) {
		pr_err("%s requires an argument\n", arg_name);
		return -EINVAL;
	}
	mnl_attr_put_strz(nlh, attr_id, str);
	return 0;
}

static int dpll_parse_attr_enum(struct dpll *dpll, struct nlmsghdr *nlh,
				const char *arg_name, int attr_id,
				int (*parse_func)(struct dpll *, __u32 *))
{
	__u32 val;

	if (dpll_arg_required(dpll, arg_name))
		return -EINVAL;
	if (parse_func(dpll, &val))
		return -EINVAL;
	mnl_attr_put_u32(nlh, attr_id, val);
	return 0;
}

/* Macros for printing netlink attributes
 * These macros combine the common pattern of:
 *
 * if (tb[ATTR])
 *	print_xxx(PRINT_ANY, "name", "format", mnl_attr_get_xxx(tb[ATTR]));
 *
 * Generic versions with custom format string (_FMT suffix)
 * Simple versions auto-generate format string: "  name: %d\n"
 */

#define DPLL_PR_INT_FMT(tb, attr_id, name, format_str)                         \
	do {                                                                   \
		if (tb[attr_id])                                               \
			print_int(                                             \
				PRINT_ANY, name, format_str,                   \
				*(__s32 *)mnl_attr_get_payload(tb[attr_id]));  \
	} while (0)

#define DPLL_PR_UINT_FMT(tb, attr_id, name, format_str)                        \
	do {                                                                   \
		if (tb[attr_id])                                               \
			print_uint(PRINT_ANY, name, format_str,                \
				   mnl_attr_get_u32(tb[attr_id]));             \
	} while (0)

#define DPLL_PR_U64_FMT(tb, attr_id, name, format_str)                         \
	do {                                                                   \
		if (tb[attr_id])                                               \
			print_lluint(PRINT_ANY, name, format_str,              \
				     mnl_attr_get_u64(tb[attr_id]));           \
	} while (0)

#define DPLL_PR_STR_FMT(tb, attr_id, name, format_str)                         \
	do {                                                                   \
		if (tb[attr_id])                                               \
			print_string(PRINT_ANY, name, format_str,              \
				     mnl_attr_get_str(tb[attr_id]));           \
	} while (0)

/* Simple versions with auto-generated format */
#define DPLL_PR_INT(tb, attr_id, name)                                         \
	DPLL_PR_INT_FMT(tb, attr_id, name, "  " name ": %d\n")

#define DPLL_PR_UINT(tb, attr_id, name)                                        \
	DPLL_PR_UINT_FMT(tb, attr_id, name, "  " name ": %u\n")

#define DPLL_PR_U64(tb, attr_id, name)                                         \
	DPLL_PR_U64_FMT(tb, attr_id, name, "  " name ": %" PRIu64 "\n")

/* Helper to read signed int (can be s32 or s64 depending on value) */
static __s64 mnl_attr_get_sint(const struct nlattr *attr)
{
	if (mnl_attr_get_payload_len(attr) == sizeof(__s32))
		return *(__s32 *)mnl_attr_get_payload(attr);
	else
		return *(__s64 *)mnl_attr_get_payload(attr);
}

#define DPLL_PR_SINT_FMT(tb, attr_id, name, format_str)                        \
	do {                                                                   \
		if (tb[attr_id])                                               \
			print_s64(PRINT_ANY, name, format_str,                 \
				  mnl_attr_get_sint(tb[attr_id]));             \
	} while (0)

#define DPLL_PR_SINT(tb, attr_id, name)                                        \
	DPLL_PR_SINT_FMT(tb, attr_id, name, "  " name ": %" PRId64 "\n")

#define DPLL_PR_STR(tb, attr_id, name)                                         \
	DPLL_PR_STR_FMT(tb, attr_id, name, "  " name ": %s\n")

/* Temperature macro - JSON prints raw millidegrees, human prints formatted */
#define DPLL_PR_TEMP(tb, attr_id)                                              \
	do {                                                                   \
		if (tb[attr_id]) {                                             \
			__s32 temp = mnl_attr_get_u32(tb[attr_id]);            \
			div_t d = div(temp, 1000);                             \
			print_int(PRINT_JSON, "temp", NULL, temp);             \
			print_int(PRINT_FP, NULL, "  temp: %d.", d.quot);      \
			print_int(PRINT_FP, NULL, "%03d C\n", d.rem);          \
		}                                                              \
	} while (0)

/* Generic version with custom format */
#define DPLL_PR_ENUM_STR_FMT(tb, attr_id, name, format_str, name_func)         \
	do {                                                                   \
		if (tb[attr_id])                                               \
			print_string(                                          \
				PRINT_ANY, name, format_str,                   \
				name_func(mnl_attr_get_u32(tb[attr_id])));     \
	} while (0)

/* Simple version with auto-generated format */
#define DPLL_PR_ENUM_STR(tb, attr_id, name, name_func)                         \
	DPLL_PR_ENUM_STR_FMT(tb, attr_id, name, "  " name ": %s\n", name_func)

/* Multi-attr enum printer - handles multiple occurrences of same attribute */
static void dpll_pr_multi_enum_str(const struct nlmsghdr *nlh, int attr_id,
				   const char *name,
				   const char *(*name_func)(__u32))
{
	struct nlattr *attr;
	bool first = true;

	if (!nlh)
		return;

	mnl_attr_for_each(attr, nlh, sizeof(struct genlmsghdr))
	{
		if (mnl_attr_get_type(attr) == attr_id) {
			__u32 val = mnl_attr_get_u32(attr);

			if (first) {
				open_json_array(PRINT_JSON, name);
				print_string(PRINT_FP, NULL, "  %s:", name);
				first = false;
			}
			print_string(PRINT_ANY, NULL, " %s", name_func(val));
		}
	}

	if (first)
		return;

	close_json_array(PRINT_JSON, NULL);
	print_nl();
}

/* Print frequency range (or single value if min==max) */
static void dpll_pr_freq_range(__u64 freq_min, __u64 freq_max)
{
	open_json_object(NULL);

	/* JSON: always print both min and max */
	print_lluint(PRINT_JSON, "frequency-min", NULL, freq_min);
	print_lluint(PRINT_JSON, "frequency-max", NULL, freq_max);

	/* FP: print range or single value */
	print_string(PRINT_FP, NULL, "    ", NULL);
	if (freq_min == freq_max) {
		print_lluint(PRINT_FP, NULL, "%" PRIu64 " Hz\n", freq_min);
	} else {
		print_lluint(PRINT_FP, NULL, "%" PRIu64, freq_min);
		print_string(PRINT_FP, NULL, "-", NULL);
		print_lluint(PRINT_FP, NULL, "%" PRIu64 " Hz\n", freq_max);
	}

	close_json_object();
}

static void help(void)
{
	pr_err("Usage: dpll [ OPTIONS ] OBJECT { COMMAND | help }\n"
	       "       dpll [ -j[son] ] [ -p[retty] ]\n"
	       "where  OBJECT := { device | pin | monitor }\n"
	       "       OPTIONS := { -V[ersion] | -j[son] | -p[retty] }\n");
}

static int cmd_device(struct dpll *dpll);
static int cmd_pin(struct dpll *dpll);
static int cmd_monitor(struct dpll *dpll);

static int dpll_cmd(struct dpll *dpll, int argc, char **argv)
{
	dpll->argc = argc;
	dpll->argv = argv;

	if (dpll_argv_match(dpll, "help") || dpll_no_arg(dpll)) {
		help();
		return 0;
	} else if (dpll_argv_match_inc(dpll, "device")) {
		return cmd_device(dpll);
	} else if (dpll_argv_match_inc(dpll, "pin")) {
		return cmd_pin(dpll);
	} else if (dpll_argv_match_inc(dpll, "monitor")) {
		return cmd_monitor(dpll);
	}
	pr_err("Object \"%s\" not found\n", dpll_argv(dpll));
	return -ENOENT;
}

static int dpll_init(struct dpll *dpll)
{
	int err;

	err = mnlu_gen_socket_open(&dpll->nlg, "dpll", DPLL_FAMILY_VERSION);
	if (err) {
		pr_err("Failed to connect to DPLL Netlink (DPLL subsystem not available in kernel?)\n");
		return -1;
	}
	return 0;
}

static void dpll_fini(struct dpll *dpll)
{
	mnlu_gen_socket_close(&dpll->nlg);
}

static struct dpll *dpll_alloc(void)
{
	struct dpll *dpll;

	dpll = calloc(1, sizeof(*dpll));
	if (!dpll)
		return NULL;
	return dpll;
}

static void dpll_free(struct dpll *dpll)
{
	free(dpll);
}

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "Version", no_argument, NULL, 'V' },
		{ "json", no_argument, NULL, 'j' },
		{ "pretty", no_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 }
	};
	const char *opt_short = "Vjp";
	struct dpll *dpll;
	int err, opt, ret;

	dpll = dpll_alloc();
	if (!dpll) {
		pr_err("Failed to allocate memory\n");
		return EXIT_FAILURE;
	}

	while ((opt = getopt_long(argc, argv, opt_short, long_options, NULL)) >=
	       0) {
		switch (opt) {
		case 'V':
			printf("dpll utility, iproute2-%s\n", version);
			ret = EXIT_SUCCESS;
			goto dpll_free;
		case 'j':
			json = 1;
			break;
		case 'p':
			pretty = true;
			break;
		default:
			pr_err("Unknown option.\n");
			help();
			ret = EXIT_FAILURE;
			goto dpll_free;
		}
	}

	argc -= optind;
	argv += optind;

	new_json_obj_plain(json);
	open_json_object(NULL);

	/* Skip netlink init for help commands */
	bool need_nl = true;

	if (argc > 0 && strcmp(argv[0], "help") == 0)
		need_nl = false;
	if (argc > 1 && strcmp(argv[1], "help") == 0)
		need_nl = false;

	if (need_nl) {
		err = dpll_init(dpll);
		if (err) {
			ret = EXIT_FAILURE;
			goto json_cleanup;
		}
	}

	err = dpll_cmd(dpll, argc, argv);
	if (err) {
		ret = EXIT_FAILURE;
		goto dpll_fini;
	}

	ret = EXIT_SUCCESS;

dpll_fini:
	if (need_nl)
		dpll_fini(dpll);
json_cleanup:
	close_json_object();
	delete_json_obj_plain();
dpll_free:
	dpll_free(dpll);
	return ret;
}

/*
 * Device commands
 */

static void cmd_device_help(void)
{
	pr_err("Usage: dpll device show [ id DEVICE_ID ]\n");
	pr_err("       dpll device set id DEVICE_ID [ phase-offset-monitor { enable | disable } ]\n");
	pr_err("                                      [ phase-offset-avg-factor NUM ]\n");
	pr_err("       dpll device id-get [ module-name NAME ] [ clock-id ID ] [ type TYPE ]\n");
}

static const char *dpll_mode_name(__u32 mode)
{
	switch (mode) {
	case DPLL_MODE_MANUAL:
		return "manual";
	case DPLL_MODE_AUTOMATIC:
		return "automatic";
	default:
		return "unknown";
	}
}

static const char *dpll_lock_status_name(__u32 status)
{
	switch (status) {
	case DPLL_LOCK_STATUS_UNLOCKED:
		return "unlocked";
	case DPLL_LOCK_STATUS_LOCKED:
		return "locked";
	case DPLL_LOCK_STATUS_LOCKED_HO_ACQ:
		return "locked-ho-acq";
	case DPLL_LOCK_STATUS_HOLDOVER:
		return "holdover";
	default:
		return "unknown";
	}
}

static const char *dpll_type_name(__u32 type)
{
	switch (type) {
	case DPLL_TYPE_PPS:
		return "pps";
	case DPLL_TYPE_EEC:
		return "eec";
	default:
		return "unknown";
	}
}

static int str_to_dpll_type(const char *s, __u32 *type)
{
	if (!strcmp(s, "pps"))
		*type = DPLL_TYPE_PPS;
	else if (!strcmp(s, "eec"))
		*type = DPLL_TYPE_EEC;
	else
		return -EINVAL;
	return 0;
}

static const char *dpll_lock_status_error_name(__u32 error)
{
	switch (error) {
	case DPLL_LOCK_STATUS_ERROR_NONE:
		return "none";
	case DPLL_LOCK_STATUS_ERROR_UNDEFINED:
		return "undefined";
	case DPLL_LOCK_STATUS_ERROR_MEDIA_DOWN:
		return "media-down";
	case DPLL_LOCK_STATUS_ERROR_FRACTIONAL_FREQUENCY_OFFSET_TOO_HIGH:
		return "fractional-frequency-offset-too-high";
	default:
		return "unknown";
	}
}

static const char *dpll_clock_quality_level_name(__u32 level)
{
	switch (level) {
	case DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRC:
		return "itu-opt1-prc";
	case DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_A:
		return "itu-opt1-ssu-a";
	case DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_B:
		return "itu-opt1-ssu-b";
	case DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEC1:
		return "itu-opt1-eec1";
	case DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRTC:
		return "itu-opt1-prtc";
	case DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRTC:
		return "itu-opt1-eprtc";
	case DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEEC:
		return "itu-opt1-eeec";
	case DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRC:
		return "itu-opt1-eprc";
	default:
		return "unknown";
	}
}

/* Netlink attribute parsing - device attributes */
static int attr_cb(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	const struct nlattr **tb = data;

	if (mnl_attr_type_valid(attr, DPLL_A_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

/* Netlink attribute parsing - pin attributes */
static int attr_pin_cb(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	const struct nlattr **tb = data;

	if (mnl_attr_type_valid(attr, DPLL_A_PIN_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

/* Print device attributes */
static void dpll_device_print_attrs(const struct nlmsghdr *nlh,
				    struct nlattr **tb)
{
	DPLL_PR_UINT_FMT(tb, DPLL_A_ID, "id", "device id %u:\n");
	DPLL_PR_STR(tb, DPLL_A_MODULE_NAME, "module-name");
	DPLL_PR_ENUM_STR(tb, DPLL_A_MODE, "mode", dpll_mode_name);
	DPLL_PR_U64(tb, DPLL_A_CLOCK_ID, "clock-id");
	DPLL_PR_ENUM_STR(tb, DPLL_A_TYPE, "type", dpll_type_name);
	DPLL_PR_ENUM_STR(tb, DPLL_A_LOCK_STATUS, "lock-status",
			 dpll_lock_status_name);
	DPLL_PR_ENUM_STR(tb, DPLL_A_LOCK_STATUS_ERROR, "lock-status-error",
			 dpll_lock_status_error_name);
	dpll_pr_multi_enum_str(nlh, DPLL_A_CLOCK_QUALITY_LEVEL,
			       "clock-quality-level",
			       dpll_clock_quality_level_name);
	DPLL_PR_TEMP(tb, DPLL_A_TEMP);
	dpll_pr_multi_enum_str(nlh, DPLL_A_MODE_SUPPORTED, "mode-supported",
			       dpll_mode_name);
	DPLL_PR_ENUM_STR_FMT(tb, DPLL_A_PHASE_OFFSET_MONITOR,
			     "phase-offset-monitor",
			     "  phase-offset-monitor: %s\n",
			     str_enable_disable);
	DPLL_PR_UINT(tb, DPLL_A_PHASE_OFFSET_AVG_FACTOR,
		     "phase-offset-avg-factor");
}

/* Netlink callback - device get (single device) */
static int cmd_device_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DPLL_A_MAX + 1] = {};

	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), attr_cb, tb);
	dpll_device_print_attrs(nlh, tb);

	return MNL_CB_OK;
}

/* Netlink callback - device dump (multiple devices) */
static int cmd_device_show_dump_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DPLL_A_MAX + 1] = {};

	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), attr_cb, tb);

	open_json_object(NULL);
	dpll_device_print_attrs(nlh, tb);
	close_json_object();

	return MNL_CB_OK;
}

static int cmd_device_show_id(struct dpll *dpll, __u32 id)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlu_gen_socket_cmd_prepare(&dpll->nlg, DPLL_CMD_DEVICE_GET,
					  NLM_F_REQUEST | NLM_F_ACK);
	mnl_attr_put_u32(nlh, DPLL_A_ID, id);

	err = mnlu_gen_socket_sndrcv(&dpll->nlg, nlh, cmd_device_show_cb, NULL);
	if (err < 0) {
		pr_err("Failed to get device %u\n", id);
		return -1;
	}

	return 0;
}

static int cmd_device_show_dump(struct dpll *dpll)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlu_gen_socket_cmd_prepare(&dpll->nlg, DPLL_CMD_DEVICE_GET,
					  NLM_F_REQUEST | NLM_F_ACK |
						  NLM_F_DUMP);

	open_json_array(PRINT_JSON, "device");

	err = mnlu_gen_socket_sndrcv(&dpll->nlg, nlh, cmd_device_show_dump_cb,
				     NULL);
	if (err < 0) {
		pr_err("Failed to dump devices\n");
		close_json_array(PRINT_JSON, NULL);
		return -1;
	}

	close_json_array(PRINT_JSON, NULL);

	return 0;
}

static int cmd_device_show(struct dpll *dpll)
{
	bool has_id = false;
	__u32 id = 0;

	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match(dpll, "id")) {
			if (dpll_parse_u32(dpll, "id", &id))
				return -EINVAL;
			has_id = true;
		} else {
			pr_err("unknown option: %s\n", dpll_argv(dpll));
			return -EINVAL;
		}
	}

	if (has_id)
		return cmd_device_show_id(dpll, id);

	return cmd_device_show_dump(dpll);
}

static int cmd_device_set(struct dpll *dpll)
{
	struct nlmsghdr *nlh;
	bool has_id = false;
	__u32 id = 0;
	int err;

	nlh = mnlu_gen_socket_cmd_prepare(&dpll->nlg, DPLL_CMD_DEVICE_SET,
					  NLM_F_REQUEST | NLM_F_ACK);

	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match(dpll, "id")) {
			if (dpll_parse_u32(dpll, "id", &id))
				return -EINVAL;
			mnl_attr_put_u32(nlh, DPLL_A_ID, id);
			has_id = true;
		} else if (dpll_argv_match(dpll, "phase-offset-monitor")) {
			const char *str = dpll_argv_next(dpll);
			bool val;

			if (!str) {
				pr_err("phase-offset-monitor requires an argument\n");
				return -EINVAL;
			}
			if (str_to_bool(str, &val)) {
				pr_err("invalid phase-offset-monitor value: %s (use enable/disable)\n",
				       str);
				return -EINVAL;
			}
			mnl_attr_put_u32(nlh, DPLL_A_PHASE_OFFSET_MONITOR,
					 val ? 1 : 0);
		} else if (dpll_argv_match(dpll, "phase-offset-avg-factor")) {
			if (dpll_parse_attr_u32(dpll, nlh,
						"phase-offset-avg-factor",
						DPLL_A_PHASE_OFFSET_AVG_FACTOR))
				return -EINVAL;
		} else {
			pr_err("unknown option: %s\n", dpll_argv(dpll));
			return -EINVAL;
		}
	}

	if (!has_id) {
		pr_err("device id is required\n");
		return -EINVAL;
	}

	err = mnlu_gen_socket_sndrcv(&dpll->nlg, nlh, NULL, NULL);
	if (err < 0) {
		pr_err("Failed to set device\n");
		return -1;
	}

	return 0;
}

/* Netlink callback - print device ID found by query */
static int cmd_device_id_get_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DPLL_A_MAX + 1] = {};
	int *found = data;

	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), attr_cb, tb);

	if (tb[DPLL_A_ID]) {
		__u32 id = mnl_attr_get_u32(tb[DPLL_A_ID]);

		print_uint(PRINT_ANY, "id", "%u\n", id);
		if (found)
			*found = 1;
	}

	return MNL_CB_OK;
}

static int cmd_device_id_get(struct dpll *dpll)
{
	struct nlmsghdr *nlh;
	int found = 0;
	int err;

	nlh = mnlu_gen_socket_cmd_prepare(&dpll->nlg, DPLL_CMD_DEVICE_ID_GET,
					  NLM_F_REQUEST | NLM_F_ACK);

	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match(dpll, "module-name")) {
			if (dpll_parse_attr_str(dpll, nlh, "module-name",
						DPLL_A_MODULE_NAME))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "clock-id")) {
			if (dpll_parse_attr_u64(dpll, nlh, "clock-id",
						DPLL_A_CLOCK_ID))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "type")) {
			const char *str = dpll_argv_next(dpll);
			__u32 val;

			if (!str) {
				pr_err("type requires an argument\n");
				return -EINVAL;
			}
			if (str_to_dpll_type(str, &val)) {
				pr_err("invalid type: %s (use pps/eec)\n", str);
				return -EINVAL;
			}
			mnl_attr_put_u32(nlh, DPLL_A_TYPE, val);
		} else {
			pr_err("unknown option: %s\n", dpll_argv(dpll));
			return -EINVAL;
		}
	}

	err = mnlu_gen_socket_sndrcv(&dpll->nlg, nlh, cmd_device_id_get_cb,
				     &found);
	if (err < 0) {
		pr_err("Failed to get device id\n");
		return -1;
	}

	if (!found) {
		pr_err("No device found matching the criteria\n");
		return -1;
	}

	return 0;
}

static int cmd_device(struct dpll *dpll)
{
	if (dpll_argv_match(dpll, "help") || dpll_no_arg(dpll)) {
		cmd_device_help();
		return 0;
	} else if (dpll_argv_match_inc(dpll, "show")) {
		return cmd_device_show(dpll);
	} else if (dpll_argv_match_inc(dpll, "set")) {
		return cmd_device_set(dpll);
	} else if (dpll_argv_match_inc(dpll, "id-get")) {
		return cmd_device_id_get(dpll);
	}

	pr_err("Command \"%s\" not found\n",
	       dpll_argv(dpll) ? dpll_argv(dpll) : "");
	return -ENOENT;
}

/*
 * Pin commands
 */

static void cmd_pin_help(void)
{
	pr_err("Usage: dpll pin show [ id PIN_ID ] [ device DEVICE_ID ]\n");
	pr_err("       dpll pin set id PIN_ID [ frequency FREQ ]\n");
	pr_err("                              [ phase-adjust ADJUST ]\n");
	pr_err("                              [ esync-frequency FREQ ]\n");
	pr_err("                              [ parent-device DEVICE_ID [ direction DIR ]\n");
	pr_err("                                                        [ prio PRIO ]\n");
	pr_err("                                                        [ state STATE ] ]\n");
	pr_err("                              [ parent-pin PIN_ID [ state STATE ] ]\n");
	pr_err("                              [ reference-sync PIN_ID [ state STATE ] ]\n");
	pr_err("       dpll pin id-get [ module-name NAME ] [ clock-id ID ]\n");
	pr_err("                       [ board-label LABEL ] [ panel-label LABEL ]\n");
	pr_err("                       [ package-label LABEL ] [ type TYPE ]\n");
}

static const char *dpll_pin_type_name(__u32 type)
{
	const char *str;

	str = str_map_lookup_uint(pin_type_map, type);
	return str ? str : "unknown";
}

static const char *dpll_pin_state_name(__u32 state)
{
	const char *str;

	str = str_map_lookup_uint(pin_state_map, state);
	return str ? str : "unknown";
}

static const char *dpll_pin_direction_name(__u32 direction)
{
	const char *str;

	str = str_map_lookup_uint(pin_direction_map, direction);
	return str ? str : "unknown";
}

static void dpll_pin_capabilities_name(__u32 capabilities)
{
	if (capabilities & DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE)
		print_string(PRINT_FP, NULL, " state-can-change", NULL);
	if (capabilities & DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE)
		print_string(PRINT_FP, NULL, " priority-can-change", NULL);
	if (capabilities & DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE)
		print_string(PRINT_FP, NULL, " direction-can-change", NULL);
}

/* Multi-attribute collection context */
struct multi_attr_ctx {
	int count;
	struct nlattr **entries;
};

static void dpll_pin_print_freq_supported(struct nlattr *attr)
{
	struct multi_attr_ctx *ctx = (struct multi_attr_ctx *)attr;
	int i;

	if (!attr)
		return;

	open_json_array(PRINT_JSON, "frequency-supported");
	print_string(PRINT_FP, NULL, "  frequency-supported:\n", NULL);

	/* Iterate through all collected frequency-supported entries */
	for (i = 0; i < ctx->count; i++) {
		struct nlattr *tb_freq[DPLL_A_PIN_MAX + 1] = {};
		__u64 freq_min = 0, freq_max = 0;

		mnl_attr_parse_nested(ctx->entries[i], attr_pin_cb, tb_freq);

		if (tb_freq[DPLL_A_PIN_FREQUENCY_MIN])
			freq_min = mnl_attr_get_u64(
				tb_freq[DPLL_A_PIN_FREQUENCY_MIN]);
		if (tb_freq[DPLL_A_PIN_FREQUENCY_MAX])
			freq_max = mnl_attr_get_u64(
				tb_freq[DPLL_A_PIN_FREQUENCY_MAX]);

		dpll_pr_freq_range(freq_min, freq_max);
	}
	close_json_array(PRINT_JSON, NULL);
}

static void dpll_pin_print_capabilities(struct nlattr *attr)
{
	__u32 caps;

	if (!attr)
		return;

	caps = mnl_attr_get_u32(attr);
	open_json_array(PRINT_JSON, "capabilities");
	if (caps & DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE)
		print_string(PRINT_JSON, NULL, NULL, "state-can-change");
	if (caps & DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE)
		print_string(PRINT_JSON, NULL, NULL, "priority-can-change");
	if (caps & DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE)
		print_string(PRINT_JSON, NULL, NULL, "direction-can-change");
	close_json_array(PRINT_JSON, NULL);

	print_hex(PRINT_FP, NULL, "  capabilities: 0x%x", caps);
	dpll_pin_capabilities_name(caps);
	print_nl();
}

static void dpll_pin_print_esync_freq_supported(struct nlattr *attr)
{
	struct multi_attr_ctx *ctx = (struct multi_attr_ctx *)attr;
	int i;

	if (!attr)
		return;

	open_json_array(PRINT_JSON, "esync-frequency-supported");
	print_string(PRINT_FP, NULL, "  esync-frequency-supported:\n", NULL);

	/* Iterate through all collected esync-frequency-supported entries */
	for (i = 0; i < ctx->count; i++) {
		struct nlattr *tb_freq[DPLL_A_PIN_MAX + 1] = {};
		__u64 freq_min = 0, freq_max = 0;

		mnl_attr_parse_nested(ctx->entries[i], attr_pin_cb, tb_freq);

		if (tb_freq[DPLL_A_PIN_FREQUENCY_MIN])
			freq_min = mnl_attr_get_u64(
				tb_freq[DPLL_A_PIN_FREQUENCY_MIN]);
		if (tb_freq[DPLL_A_PIN_FREQUENCY_MAX])
			freq_max = mnl_attr_get_u64(
				tb_freq[DPLL_A_PIN_FREQUENCY_MAX]);

		dpll_pr_freq_range(freq_min, freq_max);
	}
	close_json_array(PRINT_JSON, NULL);
}

static void dpll_pin_print_parent_devices(struct nlattr *attr)
{
	struct multi_attr_ctx *ctx = (struct multi_attr_ctx *)attr;
	int i;

	if (!attr)
		return;

	open_json_array(PRINT_JSON, "parent-device");
	print_string(PRINT_FP, NULL, "  parent-device:\n", NULL);

	/* Iterate through all collected parent-device entries */
	for (i = 0; i < ctx->count; i++) {
		struct nlattr *tb_parent[DPLL_A_PIN_MAX + 1] = {};

		mnl_attr_parse_nested(ctx->entries[i], attr_pin_cb, tb_parent);

		open_json_object(NULL);
		print_string(PRINT_FP, NULL, "    ", NULL);

		DPLL_PR_UINT_FMT(tb_parent, DPLL_A_PIN_PARENT_ID, "parent-id",
				 "id %u");
		DPLL_PR_ENUM_STR_FMT(tb_parent, DPLL_A_PIN_DIRECTION,
				     "direction", " direction %s",
				     dpll_pin_direction_name);
		DPLL_PR_UINT_FMT(tb_parent, DPLL_A_PIN_PRIO, "prio",
				 " prio %u");
		DPLL_PR_ENUM_STR_FMT(tb_parent, DPLL_A_PIN_STATE, "state",
				     " state %s", dpll_pin_state_name);
		DPLL_PR_SINT_FMT(tb_parent, DPLL_A_PIN_PHASE_OFFSET,
				 "phase-offset", " phase-offset %" PRId64);

		print_nl();
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);
}

static void dpll_pin_print_parent_pins(struct nlattr *attr)
{
	struct multi_attr_ctx *ctx = (struct multi_attr_ctx *)attr;
	int i;

	if (!attr)
		return;

	open_json_array(PRINT_JSON, "parent-pin");
	print_string(PRINT_FP, NULL, "  parent-pin:\n", NULL);

	for (i = 0; i < ctx->count; i++) {
		struct nlattr *tb_parent[DPLL_A_PIN_MAX + 1] = {};

		mnl_attr_parse_nested(ctx->entries[i], attr_pin_cb, tb_parent);

		open_json_object(NULL);
		print_string(PRINT_FP, NULL, "    ", NULL);

		DPLL_PR_UINT_FMT(tb_parent, DPLL_A_PIN_PARENT_ID, "parent-id",
				 "id %u");
		DPLL_PR_ENUM_STR_FMT(tb_parent, DPLL_A_PIN_STATE, "state",
				     " state %s", dpll_pin_state_name);

		print_nl();
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);
}

static void dpll_pin_print_refsync_pins(struct nlattr *attr)
{
	struct multi_attr_ctx *ctx = (struct multi_attr_ctx *)attr;
	int i;

	if (!attr)
		return;

	open_json_array(PRINT_JSON, "reference-sync");
	print_string(PRINT_FP, NULL, "  reference-sync:\n", NULL);

	for (i = 0; i < ctx->count; i++) {
		struct nlattr *tb_ref[DPLL_A_PIN_MAX + 1] = {};

		mnl_attr_parse_nested(ctx->entries[i], attr_pin_cb, tb_ref);

		open_json_object(NULL);
		print_string(PRINT_FP, NULL, "    ", NULL);

		DPLL_PR_UINT_FMT(tb_ref, DPLL_A_PIN_ID, "id", "pin %u");
		DPLL_PR_ENUM_STR_FMT(tb_ref, DPLL_A_PIN_STATE, "state",
				     " state %s", dpll_pin_state_name);

		print_nl();
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);
}

/* Print pin attributes */
static void dpll_pin_print_attrs(struct nlattr **tb)
{
	DPLL_PR_UINT_FMT(tb, DPLL_A_PIN_ID, "id", "pin id %u:\n");
	DPLL_PR_STR(tb, DPLL_A_PIN_MODULE_NAME, "module-name");
	DPLL_PR_U64(tb, DPLL_A_PIN_CLOCK_ID, "clock-id");
	DPLL_PR_STR(tb, DPLL_A_PIN_BOARD_LABEL, "board-label");
	DPLL_PR_STR(tb, DPLL_A_PIN_PANEL_LABEL, "panel-label");
	DPLL_PR_STR(tb, DPLL_A_PIN_PACKAGE_LABEL, "package-label");
	DPLL_PR_ENUM_STR(tb, DPLL_A_PIN_TYPE, "type", dpll_pin_type_name);
	DPLL_PR_U64_FMT(tb, DPLL_A_PIN_FREQUENCY, "frequency",
			"  frequency: %" PRIu64 " Hz\n");

	dpll_pin_print_freq_supported(tb[DPLL_A_PIN_FREQUENCY_SUPPORTED]);

	dpll_pin_print_capabilities(tb[DPLL_A_PIN_CAPABILITIES]);

	DPLL_PR_INT(tb, DPLL_A_PIN_PHASE_ADJUST_MIN, "phase-adjust-min");
	DPLL_PR_INT(tb, DPLL_A_PIN_PHASE_ADJUST_MAX, "phase-adjust-max");
	DPLL_PR_UINT(tb, DPLL_A_PIN_PHASE_ADJUST_GRAN, "phase-adjust-gran");
	DPLL_PR_INT(tb, DPLL_A_PIN_PHASE_ADJUST, "phase-adjust");

	DPLL_PR_SINT(tb, DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET,
		     "fractional-frequency-offset");

	DPLL_PR_U64_FMT(tb, DPLL_A_PIN_ESYNC_FREQUENCY, "esync-frequency",
			"  esync-frequency: %" PRIu64 " Hz\n");

	dpll_pin_print_esync_freq_supported(
		tb[DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED]);

	DPLL_PR_UINT_FMT(tb, DPLL_A_PIN_ESYNC_PULSE, "esync-pulse",
			 "  esync-pulse: %u\n");

	dpll_pin_print_parent_devices(tb[DPLL_A_PIN_PARENT_DEVICE]);

	dpll_pin_print_parent_pins(tb[DPLL_A_PIN_PARENT_PIN]);

	dpll_pin_print_refsync_pins(tb[DPLL_A_PIN_REFERENCE_SYNC]);
}

struct multi_attr_counter {
	int attr_type;
	int count;
};

/* Count how many times a specific attribute type appears */
static int count_multi_attr_cb(const struct nlattr *attr, void *data)
{
	struct multi_attr_counter *counter = data;
	int type = mnl_attr_get_type(attr);

	if (type == counter->attr_type)
		counter->count++;
	return MNL_CB_OK;
}

/* Helper to count specific multi-attr type occurrences */
static unsigned int multi_attr_count_get(const struct nlmsghdr *nlh,
					 struct genlmsghdr *genl, int attr_type)
{
	struct multi_attr_counter counter;

	counter.attr_type = attr_type;
	counter.count = 0;
	mnl_attr_parse(nlh, sizeof(*genl), count_multi_attr_cb, &counter);
	return counter.count;
}

/* Initialize multi-attr context with proper allocation */
static int multi_attr_ctx_init(struct multi_attr_ctx *ctx, unsigned int count)
{
	if (count == 0) {
		ctx->count = 0;
		ctx->entries = NULL;
		return 0;
	}

	ctx->entries = calloc(count, sizeof(struct nlattr *));
	if (!ctx->entries)
		return -ENOMEM;
	ctx->count = 0;
	return 0;
}

/* Free multi-attr context */
static void multi_attr_ctx_free(struct multi_attr_ctx *ctx)
{
	free(ctx->entries);
	ctx->entries = NULL;
	ctx->count = 0;
}

/* Generic helper to collect specific multi-attr type */
struct multi_attr_collector {
	int attr_type;
	struct multi_attr_ctx *ctx;
};

static int collect_multi_attr_cb(const struct nlattr *attr, void *data)
{
	struct multi_attr_collector *collector = data;
	int type = mnl_attr_get_type(attr);

	if (type == collector->attr_type) {
		collector->ctx->entries[collector->ctx->count++] =
			(struct nlattr *)attr;
	}
	return MNL_CB_OK;
}

static void dpll_multi_attr_parse(const struct nlmsghdr *nlh, int attr_type,
				  struct multi_attr_ctx *ctx)
{
	struct multi_attr_collector collector;

	collector.attr_type = attr_type;
	collector.ctx = ctx;
	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), collect_multi_attr_cb,
		       &collector);
}

/* Callback for pin get (single) */
static int cmd_pin_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct multi_attr_ctx parent_dev_ctx = { 0 }, parent_pin_ctx = { 0 },
			      ref_sync_ctx = { 0 };
	struct multi_attr_ctx freq_supp_ctx = { 0 },
			      esync_freq_supp_ctx = { 0 };
	struct nlattr *tb[DPLL_A_PIN_MAX + 1] = {};
	unsigned int count;
	int ret;

	/* First parse to get main attributes */
	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), attr_pin_cb, tb);

	/* Pass 1: Count multi-attr occurrences and allocate */
	count = multi_attr_count_get(nlh, genl, DPLL_A_PIN_PARENT_DEVICE);
	if (count > 0 && multi_attr_ctx_init(&parent_dev_ctx, count) < 0)
		goto err_alloc;

	count = multi_attr_count_get(nlh, genl, DPLL_A_PIN_PARENT_PIN);
	if (count > 0 && multi_attr_ctx_init(&parent_pin_ctx, count) < 0)
		goto err_alloc;

	count = multi_attr_count_get(nlh, genl, DPLL_A_PIN_REFERENCE_SYNC);
	if (count > 0 && multi_attr_ctx_init(&ref_sync_ctx, count) < 0)
		goto err_alloc;

	count = multi_attr_count_get(nlh, genl, DPLL_A_PIN_FREQUENCY_SUPPORTED);
	if (count > 0 && multi_attr_ctx_init(&freq_supp_ctx, count) < 0)
		goto err_alloc;

	count = multi_attr_count_get(nlh, genl,
				     DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED);
	if (count > 0 && multi_attr_ctx_init(&esync_freq_supp_ctx, count) < 0)
		goto err_alloc;

	/* Pass 2: Collect multi-attr entries */
	if (parent_dev_ctx.entries)
		dpll_multi_attr_parse(nlh, DPLL_A_PIN_PARENT_DEVICE,
				      &parent_dev_ctx);
	if (parent_pin_ctx.entries)
		dpll_multi_attr_parse(nlh, DPLL_A_PIN_PARENT_PIN,
				      &parent_pin_ctx);
	if (ref_sync_ctx.entries)
		dpll_multi_attr_parse(nlh, DPLL_A_PIN_REFERENCE_SYNC,
				      &ref_sync_ctx);
	if (freq_supp_ctx.entries)
		dpll_multi_attr_parse(nlh, DPLL_A_PIN_FREQUENCY_SUPPORTED,
				      &freq_supp_ctx);
	if (esync_freq_supp_ctx.entries)
		dpll_multi_attr_parse(nlh, DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED,
				      &esync_freq_supp_ctx);

	/* Replace tb entries with contexts */
	if (parent_dev_ctx.count > 0)
		tb[DPLL_A_PIN_PARENT_DEVICE] = (struct nlattr *)&parent_dev_ctx;
	if (parent_pin_ctx.count > 0)
		tb[DPLL_A_PIN_PARENT_PIN] = (struct nlattr *)&parent_pin_ctx;
	if (ref_sync_ctx.count > 0)
		tb[DPLL_A_PIN_REFERENCE_SYNC] = (struct nlattr *)&ref_sync_ctx;
	if (freq_supp_ctx.count > 0)
		tb[DPLL_A_PIN_FREQUENCY_SUPPORTED] =
			(struct nlattr *)&freq_supp_ctx;
	if (esync_freq_supp_ctx.count > 0)
		tb[DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED] =
			(struct nlattr *)&esync_freq_supp_ctx;

	dpll_pin_print_attrs(tb);

	ret = MNL_CB_OK;
	goto cleanup;

err_alloc:
	fprintf(stderr,
		"Failed to allocate memory for multi-attr collection\n");
	ret = MNL_CB_ERROR;

cleanup:
	/* Free allocated memory */
	multi_attr_ctx_free(&parent_dev_ctx);
	multi_attr_ctx_free(&parent_pin_ctx);
	multi_attr_ctx_free(&ref_sync_ctx);
	multi_attr_ctx_free(&freq_supp_ctx);
	multi_attr_ctx_free(&esync_freq_supp_ctx);

	return ret;
}

/* Callback for pin dump (multiple) - wraps each pin in object */
static int cmd_pin_show_dump_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;

	open_json_object(NULL);
	ret = cmd_pin_show_cb(nlh, data);
	close_json_object();

	return ret;
}

static int cmd_pin_show_id(struct dpll *dpll, __u32 id)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlu_gen_socket_cmd_prepare(&dpll->nlg, DPLL_CMD_PIN_GET,
					  NLM_F_REQUEST | NLM_F_ACK);
	mnl_attr_put_u32(nlh, DPLL_A_PIN_ID, id);

	err = mnlu_gen_socket_sndrcv(&dpll->nlg, nlh, cmd_pin_show_cb, NULL);
	if (err < 0) {
		pr_err("Failed to get pin %u\n", id);
		return -1;
	}

	return 0;
}

static int cmd_pin_show_dump(struct dpll *dpll, bool has_device_id,
			     __u32 device_id)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlu_gen_socket_cmd_prepare(&dpll->nlg, DPLL_CMD_PIN_GET,
					  NLM_F_REQUEST | NLM_F_ACK |
						  NLM_F_DUMP);

	/* If device_id specified, filter pins by device */
	if (has_device_id)
		mnl_attr_put_u32(nlh, DPLL_A_ID, device_id);

	/* Open JSON array for multiple pins */
	open_json_array(PRINT_JSON, "pin");

	err = mnlu_gen_socket_sndrcv(&dpll->nlg, nlh, cmd_pin_show_dump_cb,
				     NULL);
	if (err < 0) {
		pr_err("Failed to dump pins\n");
		close_json_array(PRINT_JSON, NULL);
		return -1;
	}

	/* Close JSON array */
	close_json_array(PRINT_JSON, NULL);

	return 0;
}

static int cmd_pin_show(struct dpll *dpll)
{
	bool has_pin_id = false, has_device_id = false;
	__u32 pin_id = 0, device_id = 0;

	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match(dpll, "id")) {
			if (dpll_parse_u32(dpll, "id", &pin_id))
				return -EINVAL;
			has_pin_id = true;
		} else if (dpll_argv_match(dpll, "device")) {
			if (dpll_parse_u32(dpll, "device", &device_id))
				return -EINVAL;
			has_device_id = true;
		} else {
			pr_err("unknown option: %s\n", dpll_argv(dpll));
			return -EINVAL;
		}
	}

	if (has_pin_id)
		return cmd_pin_show_id(dpll, pin_id);
	else
		return cmd_pin_show_dump(dpll, has_device_id, device_id);
}

static int cmd_pin_parse_parent_device(struct dpll *dpll, struct nlmsghdr *nlh)
{
	struct nlattr *nest;
	__u32 parent_id;

	dpll_arg_inc(dpll);
	if (dpll_arg_required(dpll, "parent-device"))
		return -EINVAL;

	if (get_u32(&parent_id, dpll_argv(dpll), 0)) {
		pr_err("invalid parent-device id: %s\n", dpll_argv(dpll));
		return -EINVAL;
	}
	dpll_arg_inc(dpll);

	nest = mnl_attr_nest_start(nlh, DPLL_A_PIN_PARENT_DEVICE);
	mnl_attr_put_u32(nlh, DPLL_A_PIN_PARENT_ID, parent_id);

	/* Parse optional parent-device attributes */
	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match_inc(dpll, "direction")) {
			if (dpll_parse_attr_enum(dpll, nlh, "direction",
						 DPLL_A_PIN_DIRECTION,
						 dpll_parse_direction))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "prio")) {
			if (dpll_parse_attr_u32(dpll, nlh, "prio",
						DPLL_A_PIN_PRIO))
				return -EINVAL;
		} else if (dpll_argv_match_inc(dpll, "state")) {
			if (dpll_parse_attr_enum(dpll, nlh, "state",
						 DPLL_A_PIN_STATE,
						 dpll_parse_state))
				return -EINVAL;
		} else {
			/* Not a parent-device attribute, break to parse
			 * next option.
			 */
			break;
		}
	}

	mnl_attr_nest_end(nlh, nest);

	return 0;
}

static int cmd_pin_parse_parent_pin(struct dpll *dpll, struct nlmsghdr *nlh)
{
	struct nlattr *nest;
	__u32 parent_id;

	dpll_arg_inc(dpll);
	if (dpll_arg_required(dpll, "parent-pin"))
		return -EINVAL;

	if (get_u32(&parent_id, dpll_argv(dpll), 0)) {
		pr_err("invalid parent-pin id: %s\n", dpll_argv(dpll));
		return -EINVAL;
	}
	dpll_arg_inc(dpll);

	nest = mnl_attr_nest_start(nlh, DPLL_A_PIN_PARENT_PIN);
	mnl_attr_put_u32(nlh, DPLL_A_PIN_PARENT_ID, parent_id);

	/* Parse optional parent-pin attributes */
	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match_inc(dpll, "state")) {
			if (dpll_parse_attr_enum(dpll, nlh, "state",
						 DPLL_A_PIN_STATE,
						 dpll_parse_state))
				return -EINVAL;
		} else {
			/* Not a parent-pin attribute, break to parse next
			 * option.
			 */
			break;
		}
	}

	mnl_attr_nest_end(nlh, nest);

	return 0;
}

static int cmd_pin_parse_reference_sync(struct dpll *dpll, struct nlmsghdr *nlh)
{
	struct nlattr *nest;
	__u32 ref_pin_id;

	dpll_arg_inc(dpll);
	if (dpll_arg_required(dpll, "reference-sync"))
		return -EINVAL;

	if (get_u32(&ref_pin_id, dpll_argv(dpll), 0)) {
		pr_err("invalid reference-sync pin id: %s\n", dpll_argv(dpll));
		return -EINVAL;
	}
	dpll_arg_inc(dpll);

	nest = mnl_attr_nest_start(nlh, DPLL_A_PIN_REFERENCE_SYNC);
	mnl_attr_put_u32(nlh, DPLL_A_PIN_ID, ref_pin_id);

	/* Parse optional reference-sync attributes */
	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match_inc(dpll, "state")) {
			if (dpll_parse_attr_enum(dpll, nlh, "state",
						 DPLL_A_PIN_STATE,
						 dpll_parse_state))
				return -EINVAL;
		} else {
			/* Not a reference-sync attribute, break to parse
			 * next option.
			 */
			break;
		}
	}

	mnl_attr_nest_end(nlh, nest);

	return 0;
}

static int cmd_pin_set(struct dpll *dpll)
{
	struct nlmsghdr *nlh;
	bool has_id = false;
	__u32 id = 0;
	int err;

	nlh = mnlu_gen_socket_cmd_prepare(&dpll->nlg, DPLL_CMD_PIN_SET,
					  NLM_F_REQUEST | NLM_F_ACK);

	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match(dpll, "id")) {
			if (dpll_parse_u32(dpll, "id", &id))
				return -EINVAL;
			mnl_attr_put_u32(nlh, DPLL_A_PIN_ID, id);
			has_id = true;
		} else if (dpll_argv_match(dpll, "frequency")) {
			if (dpll_parse_attr_u64(dpll, nlh, "frequency",
						DPLL_A_PIN_FREQUENCY))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "phase-adjust")) {
			if (dpll_parse_attr_s32(dpll, nlh, "phase-adjust",
						DPLL_A_PIN_PHASE_ADJUST))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "esync-frequency")) {
			if (dpll_parse_attr_u64(dpll, nlh, "esync-frequency",
						DPLL_A_PIN_ESYNC_FREQUENCY))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "parent-device")) {
			if (cmd_pin_parse_parent_device(dpll, nlh))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "parent-pin")) {
			if (cmd_pin_parse_parent_pin(dpll, nlh))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "reference-sync")) {
			if (cmd_pin_parse_reference_sync(dpll, nlh))
				return -EINVAL;
		} else {
			pr_err("unknown option: %s\n", dpll_argv(dpll));
			return -EINVAL;
		}
	}

	if (!has_id) {
		pr_err("pin id is required\n");
		return -EINVAL;
	}

	err = mnlu_gen_socket_sndrcv(&dpll->nlg, nlh, NULL, NULL);
	if (err < 0) {
		pr_err("Failed to set pin\n");
		return -1;
	}

	return 0;
}

static int cmd_pin_id_get_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DPLL_A_PIN_MAX + 1] = {};
	int *found = data;

	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), attr_pin_cb, tb);

	if (tb[DPLL_A_PIN_ID]) {
		__u32 id = mnl_attr_get_u32(tb[DPLL_A_PIN_ID]);

		print_uint(PRINT_ANY, "id", "%u\n", id);
		if (found)
			*found = 1;
	}

	return MNL_CB_OK;
}

static int cmd_pin_id_get(struct dpll *dpll)
{
	struct nlmsghdr *nlh;
	int found = 0;
	int err;

	nlh = mnlu_gen_socket_cmd_prepare(&dpll->nlg, DPLL_CMD_PIN_ID_GET,
					  NLM_F_REQUEST | NLM_F_ACK);

	while (dpll_argc(dpll) > 0) {
		if (dpll_argv_match(dpll, "module-name")) {
			if (dpll_parse_attr_str(dpll, nlh, "module-name",
						DPLL_A_PIN_MODULE_NAME))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "clock-id")) {
			if (dpll_parse_attr_u64(dpll, nlh, "clock-id",
						DPLL_A_PIN_CLOCK_ID))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "board-label")) {
			if (dpll_parse_attr_str(dpll, nlh, "board-label",
						DPLL_A_PIN_BOARD_LABEL))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "panel-label")) {
			if (dpll_parse_attr_str(dpll, nlh, "panel-label",
						DPLL_A_PIN_PANEL_LABEL))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "package-label")) {
			if (dpll_parse_attr_str(dpll, nlh, "package-label",
						DPLL_A_PIN_PACKAGE_LABEL))
				return -EINVAL;
		} else if (dpll_argv_match(dpll, "type")) {
			if (dpll_parse_attr_enum(dpll, nlh, "type",
						 DPLL_A_PIN_TYPE,
						 dpll_parse_pin_type))
				return -EINVAL;
		} else {
			pr_err("unknown option: %s\n", dpll_argv(dpll));
			return -EINVAL;
		}
	}

	err = mnlu_gen_socket_sndrcv(&dpll->nlg, nlh, cmd_pin_id_get_cb,
				     &found);
	if (err < 0) {
		pr_err("Failed to get pin id\n");
		return -1;
	}

	if (!found) {
		pr_err("No pin found matching the criteria\n");
		return -1;
	}

	return 0;
}

static int cmd_pin(struct dpll *dpll)
{
	if (dpll_argv_match(dpll, "help") || dpll_no_arg(dpll)) {
		cmd_pin_help();
		return 0;
	} else if (dpll_argv_match_inc(dpll, "show")) {
		return cmd_pin_show(dpll);
	} else if (dpll_argv_match_inc(dpll, "set")) {
		return cmd_pin_set(dpll);
	} else if (dpll_argv_match_inc(dpll, "id-get")) {
		return cmd_pin_id_get(dpll);
	}

	pr_err("Command \"%s\" not found\n",
	       dpll_argv(dpll) ? dpll_argv(dpll) : "");
	return -ENOENT;
}

/* Monitor command - notification handling */
static int cmd_monitor_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	const char *cmd_name = "UNKNOWN";
	const char *json_name = "unknown";
	int ret = MNL_CB_OK;

	switch (genl->cmd) {
	case DPLL_CMD_DEVICE_CREATE_NTF:
		cmd_name = "DEVICE_CREATE";
		json_name = "device-create-ntf";
		/* fallthrough */
	case DPLL_CMD_DEVICE_CHANGE_NTF:
		if (genl->cmd == DPLL_CMD_DEVICE_CHANGE_NTF) {
			cmd_name = "DEVICE_CHANGE";
			json_name = "device-change-ntf";
		}
		/* fallthrough */
	case DPLL_CMD_DEVICE_DELETE_NTF: {
		if (genl->cmd == DPLL_CMD_DEVICE_DELETE_NTF) {
			cmd_name = "DEVICE_DELETE";
			json_name = "device-delete-ntf";
		}
		struct nlattr *tb[DPLL_A_MAX + 1] = {};

		mnl_attr_parse(nlh, sizeof(struct genlmsghdr), attr_cb, tb);

		open_json_object(NULL);
		print_string(PRINT_JSON, "name", NULL, json_name);
		open_json_object("msg");
		print_string(PRINT_FP, NULL, "[%s] ", cmd_name);

		dpll_device_print_attrs(nlh, tb);

		close_json_object();
		close_json_object();
		break;
	}
	case DPLL_CMD_PIN_CREATE_NTF:
		cmd_name = "PIN_CREATE";
		json_name = "pin-create-ntf";
		/* fallthrough */
	case DPLL_CMD_PIN_CHANGE_NTF:
		if (genl->cmd == DPLL_CMD_PIN_CHANGE_NTF) {
			cmd_name = "PIN_CHANGE";
			json_name = "pin-change-ntf";
		}
		/* fallthrough */
	case DPLL_CMD_PIN_DELETE_NTF: {
		if (genl->cmd == DPLL_CMD_PIN_DELETE_NTF) {
			cmd_name = "PIN_DELETE";
			json_name = "pin-delete-ntf";
		}

		open_json_object(NULL);
		print_string(PRINT_JSON, "name", NULL, json_name);
		open_json_object("msg");
		print_string(PRINT_FP, NULL, "[%s] ", cmd_name);

		ret = cmd_pin_show_cb(nlh, NULL);

		close_json_object();
		close_json_object();
		break;
	}
	default:
		pr_err("Unknown notification command: %d\n", genl->cmd);
		break;
	}

	return ret;
}

static int cmd_monitor(struct dpll *dpll)
{
	int netlink_fd, signal_fd = -1;
	struct pollfd pfds[2];
	sigset_t mask;
	int ret = 0;

	ret = mnlg_socket_group_add(&dpll->nlg, "monitor");
	if (ret) {
		pr_err("Failed to subscribe to monitor group: %s\n",
		       strerror(errno));
		return ret;
	}

	print_string(PRINT_FP, NULL,
		     "Monitoring DPLL events (Press Ctrl+C to stop)...\n",
		     NULL);

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		pr_err("Failed to block signals: %s\n", strerror(errno));
		return -errno;
	}

	signal_fd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (signal_fd < 0) {
		pr_err("Failed to create signalfd: %s\n", strerror(errno));
		ret = -errno;
		goto err_sigmask;
	}

	netlink_fd = mnlg_socket_get_fd(&dpll->nlg);
	if (netlink_fd < 0) {
		pr_err("Failed to get netlink socket fd\n");
		ret = -1;
		goto err_signalfd;
	}

	ret = fcntl(netlink_fd, F_GETFL);
	if (ret < 0) {
		pr_err("Failed to get netlink socket flags: %s\n",
		       strerror(errno));
		ret = -errno;
		goto err_signalfd;
	}
	if (fcntl(netlink_fd, F_SETFL, ret | O_NONBLOCK) < 0) {
		pr_err("Failed to set netlink socket to non-blocking: %s\n",
		       strerror(errno));
		ret = -errno;
		goto err_signalfd;
	}

	open_json_array(PRINT_JSON, "monitor");

	pfds[0].fd = signal_fd;
	pfds[0].events = POLLIN;
	pfds[1].fd = netlink_fd;
	pfds[1].events = POLLIN;

	while (1) {
		ret = poll(pfds, ARRAY_SIZE(pfds), -1);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			pr_err("poll() failed: %s\n", strerror(errno));
			ret = -errno;
			break;
		}

		if (pfds[0].revents & POLLIN) {
			ret = 0;
			break;
		}

		if (pfds[1].revents & POLLIN) {
			ret = mnlu_gen_socket_recv_run(&dpll->nlg,
						       cmd_monitor_cb, NULL);
			if (ret < 0 && errno != EAGAIN &&
			    errno != EWOULDBLOCK) {
				pr_err("Failed to receive notifications: %s\n",
				       strerror(errno));
				break;
			}
		}
	}

	close_json_array(PRINT_JSON, NULL);

err_signalfd:
	if (signal_fd >= 0)
		close(signal_fd);
err_sigmask:
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	return ret < 0 ? ret : 0;
}
