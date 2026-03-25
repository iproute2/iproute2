/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Escape character print handling derived from procps
 * Copyright 1998-2002 by Albert Cahalan
 * Copyright 2020-2022 Jim Warner <james.warner@comcast.net>
 *
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <langinfo.h>

#include "utils.h"

static const char UTF_tab[] = {
	1,  1,	1,  1,	1,  1,	1,  1,
	1,  1,	1,  1,	1,  1,	1,  1, // 0x00 - 0x0F
	1,  1,	1,  1,	1,  1,	1,  1,
	1,  1,	1,  1,	1,  1,	1,  1, // 0x10 - 0x1F
	1,  1,	1,  1,	1,  1,	1,  1,
	1,  1,	1,  1,	1,  1,	1,  1, // 0x20 - 0x2F
	1,  1,	1,  1,	1,  1,	1,  1,
	1,  1,	1,  1,	1,  1,	1,  1, // 0x30 - 0x3F
	1,  1,	1,  1,	1,  1,	1,  1,
	1,  1,	1,  1,	1,  1,	1,  1, // 0x40 - 0x4F
	1,  1,	1,  1,	1,  1,	1,  1,
	1,  1,	1,  1,	1,  1,	1,  1, // 0x50 - 0x5F
	1,  1,	1,  1,	1,  1,	1,  1,
	1,  1,	1,  1,	1,  1,	1,  1, // 0x60 - 0x6F
	1,  1,	1,  1,	1,  1,	1,  1,
	1,  1,	1,  1,	1,  1,	1,  1, // 0x70 - 0x7F
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, // 0x80 - 0x8F
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, // 0x90 - 0x9F
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, // 0xA0 - 0xAF
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, // 0xB0 - 0xBF
	-1, -1, 2,  2,	2,  2,	2,  2,
	2,  2,	2,  2,	2,  2,	2,  2, // 0xC0 - 0xCF
	2,  2,	2,  2,	2,  2,	2,  2,
	2,  2,	2,  2,	2,  2,	2,  2, // 0xD0 - 0xDF
	3,  3,	3,  3,	3,  3,	3,  3,
	3,  3,	3,  3,	3,  3,	3,  3, // 0xE0 - 0xEF
	4,  4,	4,  4,	4,  -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, // 0xF0 - 0xFF
};

static const unsigned char ESC_tab[] = {
	"@..............................." // 0x00 - 0x1F
	"||||||||||||||||||||||||||||||||" // 0x20 - 0x3F
	"||||||||||||||||||||||||||||||||" // 0x40 - 0x5f
	"|||||||||||||||||||||||||||||||." // 0x60 - 0x7F
	"????????????????????????????????" // 0x80 - 0x9F
	"????????????????????????????????" // 0xA0 - 0xBF
	"????????????????????????????????" // 0xC0 - 0xDF
	"????????????????????????????????" // 0xE0 - 0xFF
};

static void esc_all(unsigned char *str)
{
	// if bad locale/corrupt str, replace non-printing stuff
	while (*str) {
		unsigned char c = ESC_tab[*str];

		if (c != '|')
			*str = c;
		++str;
	}
}

static void esc_ctl(unsigned char *str, int len)
{
	int i;

	for (i = 0; i < len;) {
		// even with a proper locale, strings might be corrupt
		int n = UTF_tab[*str];

		if (n < 0 || i + n > len) {
			esc_all(str);
			return;
		}
		// and eliminate those non-printing control characters
		if (*str < 0x20 || *str == 0x7f)
			*str = '?';
		str += n;
		i += n;
	}
}

int escape_str(char *dst, const char *src, int bufsize)
{
	static int utf_sw;

	if (utf_sw == 0) {
		char *enc = nl_langinfo(CODESET);

		utf_sw = enc && strcasecmp(enc, "UTF-8") == 0 ? 1 : -1;
	}

	int n = strlcpy(dst, src, bufsize);

	if (utf_sw < 0)
		esc_all((unsigned char *)dst);
	else
		esc_ctl((unsigned char *)dst, n);
	return n;
}
