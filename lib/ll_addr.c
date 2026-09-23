/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ll_addr.c
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>

#include "rt_names.h"
#include "utils.h"

const char *ll_addr_n2a(const unsigned char *addr, int alen, int type,
			char *buf, int blen)
{
	int i;
	int l;

	if (alen == 4 &&
	    (type == ARPHRD_TUNNEL || type == ARPHRD_SIT
	     || type == ARPHRD_IPGRE))
		return inet_ntop(AF_INET, addr, buf, blen);

	if (alen == 16 && (type == ARPHRD_TUNNEL6 || type == ARPHRD_IP6GRE))
		return inet_ntop(AF_INET6, addr, buf, blen);

	snprintf(buf, blen, "%02x", addr[0]);
	for (i = 1, l = 2; i < alen && l < blen; i++, l += 3)
		snprintf(buf + l, blen - l, ":%02x", addr[i]);
	return buf;
}

/*NB: lladdr is char * (rather than u8 *) because sa_data is char * (1003.1g) */
int ll_addr_a2n(char *lladdr, int len, const char *arg)
{
	const char *cp;
	int i;

	if (strchr(arg, '.')) {
		inet_prefix pfx;

		if (get_addr_1(&pfx, arg, AF_INET)) {
			fprintf(stderr, "\"%s\" is invalid lladdr.\n", arg);
			return -1;
		}
		if (len < 4)
			return -1;
		memcpy(lladdr, pfx.data, 4);
		return 4;
	}

	for (i = 0, cp = arg; i < len; i++) {
		unsigned long val;
		char *endp;

		if (!isxdigit(*cp))
			goto invalid;

		val = strtoul(cp, &endp, 16);
		if (val > 255)
			goto invalid;

		lladdr[i] = val;

		if (*endp == '\0')
			return i + 1;
		if (*endp != ':')
			goto invalid;
		cp = endp + 1;
	}
invalid:
	fprintf(stderr, "\"%s\" is invalid lladdr.\n", arg);
	return -1;
}
