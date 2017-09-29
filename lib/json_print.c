/*
 * json_print.c		"print regular or json output, based on json_writer".
 *
 *             This program is free software; you can redistribute it and/or
 *             modify it under the terms of the GNU General Public License
 *             as published by the Free Software Foundation; either version
 *             2 of the License, or (at your option) any later version.
 *
 * Authors:    Julien Fortin, <julien@cumulusnetworks.com>
 */

#include <stdarg.h>
#include <stdio.h>

#include "utils.h"
#include "json_print.h"

static json_writer_t *_jw;

#define _IS_JSON_CONTEXT(type) ((type & PRINT_JSON || type & PRINT_ANY) && _jw)
#define _IS_FP_CONTEXT(type) (!_jw && (type & PRINT_FP || type & PRINT_ANY))

void new_json_obj(int json)
{
	if (json) {
		_jw = jsonw_new(stdout);
		if (!_jw) {
			perror("json object");
			exit(1);
		}
		jsonw_pretty(_jw, true);
		jsonw_start_array(_jw);
	}
}

void delete_json_obj(void)
{
	if (_jw) {
		jsonw_end_array(_jw);
		jsonw_destroy(&_jw);
	}
}

bool is_json_context(void)
{
	return _jw != NULL;
}

json_writer_t *get_json_writer(void)
{
	return _jw;
}

void open_json_object(const char *str)
{
	if (_IS_JSON_CONTEXT(PRINT_JSON)) {
		if (str)
			jsonw_name(_jw, str);
		jsonw_start_object(_jw);
	}
}

void close_json_object(void)
{
	if (_IS_JSON_CONTEXT(PRINT_JSON))
		jsonw_end_object(_jw);
}

/*
 * Start json array or string array using
 * the provided string as json key (if not null)
 * or as array delimiter in non-json context.
 */
void open_json_array(enum output_type type, const char *str)
{
	if (_IS_JSON_CONTEXT(type)) {
		if (str)
			jsonw_name(_jw, str);
		jsonw_start_array(_jw);
	} else if (_IS_FP_CONTEXT(type)) {
		printf("%s", str);
	}
}

/*
 * End json array or string array
 */
void close_json_array(enum output_type type, const char *str)
{
	if (_IS_JSON_CONTEXT(type)) {
		jsonw_pretty(_jw, false);
		jsonw_end_array(_jw);
		jsonw_pretty(_jw, true);
	} else if (_IS_FP_CONTEXT(type)) {
		printf("%s", str);
	}
}

/*
 * pre-processor directive to generate similar
 * functions handling different types
 */
#define _PRINT_FUNC(type_name, type)					\
	void print_color_##type_name(enum output_type t,		\
				     enum color_attr color,		\
				     const char *key,			\
				     const char *fmt,			\
				     type value)			\
	{								\
		if (_IS_JSON_CONTEXT(t)) {				\
			if (!key)					\
				jsonw_##type_name(_jw, value);		\
			else						\
				jsonw_##type_name##_field(_jw, key, value); \
		} else if (_IS_FP_CONTEXT(t)) {				\
			color_fprintf(stdout, color, fmt, value);          \
		}							\
	}
_PRINT_FUNC(int, int);
_PRINT_FUNC(hu, unsigned short);
_PRINT_FUNC(uint, uint64_t);
_PRINT_FUNC(lluint, unsigned long long int);
#undef _PRINT_FUNC

void print_color_string(enum output_type type,
			enum color_attr color,
			const char *key,
			const char *fmt,
			const char *value)
{
	if (_IS_JSON_CONTEXT(type)) {
		if (key && !value)
			jsonw_name(_jw, key);
		else if (!key && value)
			jsonw_string(_jw, value);
		else
			jsonw_string_field(_jw, key, value);
	} else if (_IS_FP_CONTEXT(type)) {
		color_fprintf(stdout, color, fmt, value);
	}
}

/*
 * value's type is bool. When using this function in FP context you can't pass
 * a value to it, you will need to use "is_json_context()" to have different
 * branch for json and regular output. grep -r "print_bool" for example
 */
void print_color_bool(enum output_type type,
		      enum color_attr color,
		      const char *key,
		      const char *fmt,
		      bool value)
{
	if (_IS_JSON_CONTEXT(type)) {
		if (key)
			jsonw_bool_field(_jw, key, value);
		else
			jsonw_bool(_jw, value);
	} else if (_IS_FP_CONTEXT(type)) {
		color_fprintf(stdout, color, fmt, value ? "true" : "false");
	}
}

/*
 * In JSON context uses hardcode %#x format: 42 -> 0x2a
 */
void print_color_0xhex(enum output_type type,
		       enum color_attr color,
		       const char *key,
		       const char *fmt,
		       unsigned int hex)
{
	if (_IS_JSON_CONTEXT(type)) {
		SPRINT_BUF(b1);

		snprintf(b1, sizeof(b1), "%#x", hex);
		print_string(PRINT_JSON, key, NULL, b1);
	} else if (_IS_FP_CONTEXT(type)) {
		color_fprintf(stdout, color, fmt, hex);
	}
}

void print_color_hex(enum output_type type,
		     enum color_attr color,
		     const char *key,
		     const char *fmt,
		     unsigned int hex)
{
	if (_IS_JSON_CONTEXT(type)) {
		SPRINT_BUF(b1);

		snprintf(b1, sizeof(b1), "%x", hex);
		if (key)
			jsonw_string_field(_jw, key, b1);
		else
			jsonw_string(_jw, b1);
	} else if (_IS_FP_CONTEXT(type)) {
		color_fprintf(stdout, color, fmt, hex);
	}
}

/*
 * In JSON context we don't use the argument "value" we simply call jsonw_null
 * whereas FP context can use "value" to output anything
 */
void print_color_null(enum output_type type,
		      enum color_attr color,
		      const char *key,
		      const char *fmt,
		      const char *value)
{
	if (_IS_JSON_CONTEXT(type)) {
		if (key)
			jsonw_null_field(_jw, key);
		else
			jsonw_null(_jw);
	} else if (_IS_FP_CONTEXT(type)) {
		color_fprintf(stdout, color, fmt, value);
	}
}
