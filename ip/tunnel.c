/*
 * Copyright (C)2006 USAGI/WIDE Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
/*
 * split from ip_tunnel.c
 */
/*
 * Author:
 *	Masahide NAKAMURA @USAGI
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>

#include "utils.h"
#include "tunnel.h"
#include "json_print.h"

const char *tnl_strproto(__u8 proto)
{
	switch (proto) {
	case IPPROTO_IPIP:
		return "ip";
	case IPPROTO_GRE:
		return "gre";
	case IPPROTO_IPV6:
		return "ipv6";
	case IPPROTO_ESP:
		return "esp";
	case IPPROTO_MPLS:
		return "mpls";
	case 0:
		return "any";
	default:
		return "unknown";
	}
}

int tnl_get_ioctl(const char *basedev, void *p)
{
	struct ifreq ifr;
	int fd;
	int err;

	strncpy(ifr.ifr_name, basedev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void *)p;

	fd = socket(preferred_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "create socket failed: %s\n", strerror(errno));
		return -1;
	}

	err = ioctl(fd, SIOCGETTUNNEL, &ifr);
	if (err)
		fprintf(stderr, "get tunnel \"%s\" failed: %s\n", basedev,
			strerror(errno));

	close(fd);
	return err;
}

int tnl_add_ioctl(int cmd, const char *basedev, const char *name, void *p)
{
	struct ifreq ifr;
	int fd;
	int err;

	if (cmd == SIOCCHGTUNNEL && name[0])
		strncpy(ifr.ifr_name, name, IFNAMSIZ);
	else
		strncpy(ifr.ifr_name, basedev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = p;

	fd = socket(preferred_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "create socket failed: %s\n", strerror(errno));
		return -1;
	}

	err = ioctl(fd, cmd, &ifr);
	if (err)
		fprintf(stderr, "add tunnel \"%s\" failed: %s\n", ifr.ifr_name,
			strerror(errno));
	close(fd);
	return err;
}

int tnl_del_ioctl(const char *basedev, const char *name, void *p)
{
	struct ifreq ifr;
	int fd;
	int err;

	if (name[0])
		strncpy(ifr.ifr_name, name, IFNAMSIZ);
	else
		strncpy(ifr.ifr_name, basedev, IFNAMSIZ);

	ifr.ifr_ifru.ifru_data = p;

	fd = socket(preferred_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "create socket failed: %s\n", strerror(errno));
		return -1;
	}

	err = ioctl(fd, SIOCDELTUNNEL, &ifr);
	if (err)
		fprintf(stderr, "delete tunnel \"%s\" failed: %s\n",
			ifr.ifr_name, strerror(errno));
	close(fd);
	return err;
}

static int tnl_gen_ioctl(int cmd, const char *name,
			 void *p, int skiperr)
{
	struct ifreq ifr;
	int fd;
	int err;

	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = p;

	fd = socket(preferred_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "create socket failed: %s\n", strerror(errno));
		return -1;
	}

	err = ioctl(fd, cmd, &ifr);
	if (err && errno != skiperr)
		fprintf(stderr, "%s: ioctl %x failed: %s\n", name,
			cmd, strerror(errno));
	close(fd);
	return err;
}

int tnl_prl_ioctl(int cmd, const char *name, void *p)
{
	return tnl_gen_ioctl(cmd, name, p, -1);
}

int tnl_6rd_ioctl(int cmd, const char *name, void *p)
{
	return tnl_gen_ioctl(cmd, name, p, -1);
}

int tnl_ioctl_get_6rd(const char *name, void *p)
{
	return tnl_gen_ioctl(SIOCGET6RD, name, p, EINVAL);
}

__be32 tnl_parse_key(const char *name, const char *key)
{
	unsigned int uval;

	if (strchr(key, '.'))
		return get_addr32(key);

	if (get_unsigned(&uval, key, 0) < 0) {
		fprintf(stderr,
			"invalid value for \"%s\": \"%s\"; it should be an unsigned integer\n",
			name, key);
		exit(-1);
	}
	return htonl(uval);
}

static const char *tnl_encap_str(const char *name, int enabled, int port)
{
	static const char ne[][sizeof("no")] = {
		[0] = "no",
		[1] = "",
	};
	static char buf[32];
	char b1[16];
	const char *val;

	if (!port) {
		val = "auto ";
	} else if (port < 0) {
		val = "";
	} else {
		snprintf(b1, sizeof(b1), "%u ", port - 1);
		val = b1;
	}

	snprintf(buf, sizeof(buf), "%sencap-%s %s", ne[!!enabled], name, val);
	return buf;
}

void tnl_print_encap(struct rtattr *tb[],
		     int encap_type, int encap_flags,
		     int encap_sport, int encap_dport)
{
	__u16 type, flags, sport, dport;

	if (!tb[encap_type])
		return;

	type = rta_getattr_u16(tb[encap_type]);
	if (type == TUNNEL_ENCAP_NONE)
		return;

	flags = rta_getattr_u16(tb[encap_flags]);
	sport = rta_getattr_u16(tb[encap_sport]);
	dport = rta_getattr_u16(tb[encap_dport]);

	open_json_object("encap");
	print_string(PRINT_FP, NULL, "encap ", NULL);

	switch (type) {
	case TUNNEL_ENCAP_FOU:
		print_string(PRINT_ANY, "type", "%s ", "fou");
		break;
	case TUNNEL_ENCAP_GUE:
		print_string(PRINT_ANY, "type", "%s ", "gue");
		break;
	default:
		print_null(PRINT_ANY, "type", "%s ", "unknown");
		break;
	}

	if (is_json_context()) {
		print_uint(PRINT_JSON, "sport", NULL, ntohs(sport));
		print_uint(PRINT_JSON, "dport", NULL, ntohs(dport));
		print_bool(PRINT_JSON, "csum", NULL,
			   flags & TUNNEL_ENCAP_FLAG_CSUM);
		print_bool(PRINT_JSON, "csum6", NULL,
			   flags & TUNNEL_ENCAP_FLAG_CSUM6);
		print_bool(PRINT_JSON, "remcsum", NULL,
			   flags & TUNNEL_ENCAP_FLAG_REMCSUM);
		close_json_object();
	} else {
		int t;

		t = sport ? ntohs(sport) + 1 : 0;
		print_string(PRINT_FP, NULL, "%s",
			     tnl_encap_str("sport", 1, t));

		t = ntohs(dport) + 1;
		print_string(PRINT_FP, NULL, "%s",
			     tnl_encap_str("dport", 1, t));

		t = flags & TUNNEL_ENCAP_FLAG_CSUM;
		print_string(PRINT_FP, NULL, "%s",
			     tnl_encap_str("csum", t, -1));

		t = flags & TUNNEL_ENCAP_FLAG_CSUM6;
		print_string(PRINT_FP, NULL, "%s",
			     tnl_encap_str("csum6", t, -1));

		t = flags & TUNNEL_ENCAP_FLAG_REMCSUM;
		print_string(PRINT_FP, NULL, "%s",
			     tnl_encap_str("remcsum", t, -1));
	}
}

/* tnl_print_stats - print tunnel statistics
 *
 * @buf - tunnel interface's line in /proc/net/dev,
 *        starting past the interface name and following colon
 */
void tnl_print_stats(const char *buf)
{
	unsigned long rx_bytes, rx_packets, rx_errs, rx_drops,
		      rx_fifo, rx_frame,
		      tx_bytes, tx_packets, tx_errs, tx_drops,
		      tx_fifo, tx_colls, tx_carrier, rx_multi;

	if (sscanf(buf, "%lu%lu%lu%lu%lu%lu%lu%*d%lu%lu%lu%lu%lu%lu%lu",
		   &rx_bytes, &rx_packets, &rx_errs, &rx_drops,
		   &rx_fifo, &rx_frame, &rx_multi,
		   &tx_bytes, &tx_packets, &tx_errs, &tx_drops,
		   &tx_fifo, &tx_colls, &tx_carrier) != 14)
		return;

	printf("%s", _SL_);
	printf("RX: Packets    Bytes        Errors CsumErrs OutOfSeq Mcasts%s", _SL_);
	printf("    %-10ld %-12ld %-6ld %-8ld %-8ld %-8ld%s",
	       rx_packets, rx_bytes, rx_errs, rx_frame, rx_fifo, rx_multi, _SL_);
	printf("TX: Packets    Bytes        Errors DeadLoop NoRoute  NoBufs%s", _SL_);
	printf("    %-10ld %-12ld %-6ld %-8ld %-8ld %-6ld",
	       tx_packets, tx_bytes, tx_errs, tx_colls, tx_carrier, tx_drops);
}
