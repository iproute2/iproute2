/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __DCB_H__
#define __DCB_H__ 1

#include <libmnl/libmnl.h>
#include <stdbool.h>
#include <stddef.h>

/* dcb.c */

struct dcb {
	char *buf;
	struct mnl_socket *nl;
	bool json_output;
	bool stats;
	bool use_iec;
	bool numeric;
};

int dcb_parse_mapping(const char *what_key, __u32 key, __u32 max_key,
		      const char *what_value, __u64 value, __u64 max_value,
		      void (*set_array)(__u32 index, __u64 value, void *data),
		      void *set_array_data);
int dcb_cmd_parse_dev(struct dcb *dcb, int argc, char **argv,
		      int (*and_then)(struct dcb *dcb, const char *dev,
				      int argc, char **argv),
		      void (*help)(void));

void dcb_set_u8(__u32 key, __u64 value, void *data);
void dcb_set_u32(__u32 key, __u64 value, void *data);
void dcb_set_u64(__u32 key, __u64 value, void *data);

int dcb_get_attribute(struct dcb *dcb, const char *dev, int attr,
		      void *data, size_t data_len);
int dcb_set_attribute(struct dcb *dcb, const char *dev, int attr,
		      const void *data, size_t data_len);
int dcb_get_attribute_va(struct dcb *dcb, const char *dev, int attr,
			 void **payload_p, __u16 *payload_len_p);
int dcb_set_attribute_va(struct dcb *dcb, int command, const char *dev,
			 int (*cb)(struct dcb *dcb, struct nlmsghdr *nlh, void *data),
			 void *data);
int dcb_get_attribute_bare(struct dcb *dcb, int cmd, const char *dev, int attr,
			   void **payload_p, __u16 *payload_len_p);
int dcb_set_attribute_bare(struct dcb *dcb, int command, const char *dev,
			   int attr, const void *data, size_t data_len,
			   int response_attr);

void dcb_print_named_array(const char *json_name, const char *fp_name,
			   const __u8 *array, size_t size,
			   void (*print_array)(const __u8 *, size_t));
void dcb_print_array_u8(const __u8 *array, size_t size);
void dcb_print_array_u64(const __u64 *array, size_t size);
void dcb_print_array_on_off(const __u8 *array, size_t size);
void dcb_print_array_kw(const __u8 *array, size_t array_size,
			const char *const kw[], size_t kw_size);

/* dcp_rewr.c */

int dcb_cmd_rewr(struct dcb *dcb, int argc, char **argv);

/* dcb_app.c */

struct dcb_app_table {
	struct dcb_app *apps;
	size_t n_apps;
	int attr;
};

struct dcb_app_parse_mapping {
	__u8 selector;
	struct dcb_app_table *tab;
	int err;
};

#define DCB_APP_PCP_MAX 15
#define DCB_APP_DSCP_MAX 63

int dcb_cmd_app(struct dcb *dcb, int argc, char **argv);

int dcb_app_get(struct dcb *dcb, const char *dev, struct dcb_app_table *tab);
int dcb_app_add_del(struct dcb *dcb, const char *dev, int command,
		    const struct dcb_app_table *tab,
		    bool (*filter)(const struct dcb_app *));

bool dcb_app_is_dscp(const struct dcb_app *app);
bool dcb_app_is_pcp(const struct dcb_app *app);

int dcb_app_print_pid_dscp(__u16 protocol);
int dcb_app_print_pid_pcp(__u16 protocol);
int dcb_app_print_pid_dec(__u16 protocol);
void dcb_app_print_filtered(const struct dcb_app_table *tab,
			    bool (*filter)(const struct dcb_app *),
			    void (*print_pid_prio)(int (*print_pid)(__u16),
						   const struct dcb_app *),
			    int (*print_pid)(__u16 protocol),
			    const char *json_name,
			    const char *fp_name);

enum ieee_attrs_app dcb_app_attr_type_get(__u8 selector);
bool dcb_app_attr_type_validate(enum ieee_attrs_app type);
bool dcb_app_selector_validate(enum ieee_attrs_app type, __u8 selector);

int dcb_app_table_push(struct dcb_app_table *tab, struct dcb_app *app);
int dcb_app_table_copy(struct dcb_app_table *a,
		       const struct dcb_app_table *b);
void dcb_app_table_sort(struct dcb_app_table *tab);
void dcb_app_table_fini(struct dcb_app_table *tab);
void dcb_app_table_remove_existing(struct dcb_app_table *a,
				   const struct dcb_app_table *b);
void dcb_app_table_remove_replaced(struct dcb_app_table *a,
				   const struct dcb_app_table *b,
				   bool (*key_eq)(const struct dcb_app *aa,
						  const struct dcb_app *ab));

int dcb_app_parse_pcp(__u32 *key, const char *arg);
int dcb_app_parse_dscp(__u32 *key, const char *arg);

/* dcb_apptrust.c */

int dcb_cmd_apptrust(struct dcb *dcb, int argc, char **argv);

/* dcb_buffer.c */

int dcb_cmd_buffer(struct dcb *dcb, int argc, char **argv);

/* dcb_dcbx.c */

int dcb_cmd_dcbx(struct dcb *dcb, int argc, char **argv);

/* dcb_ets.c */

int dcb_cmd_ets(struct dcb *dcb, int argc, char **argv);

/* dcb_maxrate.c */

int dcb_cmd_maxrate(struct dcb *dcb, int argc, char **argv);

/* dcb_pfc.c */

int dcb_cmd_pfc(struct dcb *dcb, int argc, char **argv);

#endif /* __DCB_H__ */
