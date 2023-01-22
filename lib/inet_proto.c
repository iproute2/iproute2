/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * inet_proto.c
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#include "rt_names.h"
#include "utils.h"

const char *inet_proto_n2a(int proto, char *buf, int len)
{
	static char *ncache;
	static int icache = -1;
	struct protoent *pe;

	if (proto == icache)
		return ncache;

	pe = getprotobynumber(proto);
	if (pe && !numeric) {
		if (icache != -1)
			free(ncache);
		icache = proto;
		ncache = strdup(pe->p_name);
		strlcpy(buf, pe->p_name, len);
		return buf;
	}
	snprintf(buf, len, "ipproto-%d", proto);
	return buf;
}

int inet_proto_a2n(const char *buf)
{
	static char *ncache;
	static int icache = -1;
	struct protoent *pe;
	__u8 ret;

	if (icache != -1 && strcmp(ncache, buf) == 0)
		return icache;

	if (!get_u8(&ret, buf, 10))
		return ret;

	pe = getprotobyname(buf);
	if (pe) {
		if (icache != -1)
			free(ncache);
		icache = pe->p_proto;
		ncache = strdup(pe->p_name);
		return pe->p_proto;
	}
	return -1;
}
