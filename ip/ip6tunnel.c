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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * based on:
 * $Id: s.ipv6tunnel.c 1.7 02/12/11 11:21:51+02:00 antti@traci.mipl.mediapoli.com $
 *
 */
/*
 * Author:
 *	Masahide NAKAMURA @USAGI
 */
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <asm/types.h>
#include <linux/sockios.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>

#include "ipv6_tunnel.h"


int tunnel_local_packets = 0;

static void usage(void)
{
	fprintf(stderr, "Usage: ipv6tunnel { add | change | del | show } [ NAME ]\n");
	fprintf(stderr, "          [ --allow-local-packets ]\n");
	fprintf(stderr, "          [ --use-original-traffic-class ]\n");
	fprintf(stderr, "          [ remote ADDR local ADDR ]\n");
	fprintf(stderr, "          [ dev PHYS_DEV ]\n");
	fprintf(stderr, "          [ encaplimit TEL ]\n");
	fprintf(stderr, "          [ hoplimit HOPLIMIT ]\n"); 
	fprintf(stderr, "          [ flowlabel FL ]\n");
	fprintf(stderr, "Where: NAME := STRING\n");
	fprintf(stderr, "       ADDR := IPV6_ADDRESS\n");
	fprintf(stderr, "       HOPLIMIT := 0..255\n");
	fprintf(stderr, "       TEL := { none | 0..255 }\n");
	fprintf(stderr, "       FL := 0x0..0xfffff\n");
	fprintf(stderr, "       PHYS_DEV := STRING\n");
	exit(-1);
}

static int do_ioctl_get_ifindex(char *dev)
{
	struct ifreq ifr;
	int fd;
	int err;

//	fprintf(stderr, "do_ioctl_get_ifindex\n");

	strcpy(ifr.ifr_name, dev);
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (err) {
		perror("ioctl");
		return 0;
	}
	close(fd);
	return ifr.ifr_ifindex;
}

static char *do_ioctl_get_ifname(int idx)
{
	static struct ifreq ifr;
	int fd;
	int err;

//	fprintf(stderr, "do_ioctl_get_ifname\n");

	ifr.ifr_ifindex = idx;
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCGIFNAME, &ifr);
	if (err) {
		perror("ioctl");
		return NULL;
	}
	close(fd);
	return ifr.ifr_name;
}

static int do_get_ioctl(char *basedev, struct ipv6_tnl_parm *p)
{
	struct ifreq ifr;
	int fd;
	int err;

//	fprintf(stderr, "do_get_ioctl\n");

	strcpy(ifr.ifr_name, basedev);
	ifr.ifr_ifru.ifru_data = (void *)p;
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCGETTUNNEL, &ifr);
	if (err)
		perror("ioctl");
	close(fd);
	return err;
}

static int do_add_ioctl(int cmd, char *basedev, struct ipv6_tnl_parm *p)
{
	struct ifreq ifr;
	int fd;
	int err;

//	fprintf(stderr, "do_add_ioctl\n");

	strcpy(ifr.ifr_name, basedev);
	ifr.ifr_ifru.ifru_data = (void *)p;
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	err = ioctl(fd, cmd, &ifr);
	if (err)
		perror("ioctl");
	close(fd);
	return err;
}


static int do_del_ioctl(char *basedev, struct ipv6_tnl_parm *p)
{
	struct ifreq ifr;
	int fd;
	int err;

//	fprintf(stderr, "do_del_ioctl\n");

	strcpy(ifr.ifr_name, basedev);
	ifr.ifr_ifru.ifru_data = (void *)p;
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCDELTUNNEL, &ifr);
	if (err)
		perror("ioctl");
	close(fd);
	return err;
}

void print_tunnel(struct ipv6_tnl_parm *p)
{
	char remote[64];
	char local[64];
	
	inet_ntop(AF_INET6, &p->raddr, remote, sizeof(remote));
	inet_ntop(AF_INET6, &p->laddr, local, sizeof(local));

	printf("%s: %s/IPv6 remote %s local %s",
	       p->name,
	       (p->proto == IPPROTO_IPV6 ? "IPv6" : "unknown"),
	       remote, local);
	if (p->link) {
		char *n = do_ioctl_get_ifname(p->link);
		if (n)
			printf(" dev %s", n);
	}
	if (p->encap_limit)
		printf(" encaplimit %d", p->encap_limit);

	printf(" hoplimit %d", p->hop_limit);

	if (p->flow_lbl)
		printf(" flowlabel 0x%x", p->flow_lbl);

	if (p->flags) {
		char flags[33];
		char *fp = flags;
		memset(flags, 0, 33);
		if (p->flags & IPV6_TNL_F_IGN_ENCAP_LIMIT) {
			*fp = 'E';
			fp++;
		}
		if (p->flags & IPV6_TNL_F_USE_ORIG_TCLASS) {
			*fp = 'T';
			fp++;
		}
		if (p->flags & IPV6_TNL_F_ALLOW_LOCAL) {
			*fp = 'L';
			fp++;
		}
		if (p->flags & IPV6_TNL_F_KERNEL_DEV) {
			*fp = 'K';
			fp++;
		}
		if (p->flags & IPV6_TNL_F_MIPV6_DEV) {
			*fp = 'M';
			fp++;
		}
		if (p->flags & IPV6_TNL_F_RCV_ONLY) {
			*fp = 'R';
			fp++;
		}
		printf(" flags %s", flags);
	}
	printf("\n");
}

void resolve_name(char *name, struct in6_addr *ip6)
{ 
	struct addrinfo ai, *res; 
	int err; 
	memset(&ai, 0, sizeof(struct addrinfo)); 
	ai.ai_family = AF_INET6; 
	ai.ai_protocol = IPPROTO_IPV6; 
	ai.ai_flags = AI_NUMERICHOST;
	err = getaddrinfo(name, NULL, &ai, &res);
	if (err)
		exit(-1);

	*ip6 = ((struct sockaddr_in6 *) (res->ai_addr))->sin6_addr;
	freeaddrinfo(res); 
} 

int get_u8(__u8 *val, char *arg)
{
	unsigned long res = 0;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, 0);
	if (!ptr || ptr == arg || *ptr || res > 0xFF)
		return -1;
	*val = (__u8) res;
	return 0;
}

int get_u20(__u32 *val, char *arg)
{
	unsigned long res = 0;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, 0);
	if (!ptr || ptr == arg || *ptr || res > 0xFFFFF)
		return -1;
	*val = res;
	return 0;
}

static int parse_args(int argc, char **argv, struct ipv6_tnl_parm *p)
{
	char medium[IFNAMSIZ];

//	fprintf(stderr, "parse_args\n");

	memset(p, 0, sizeof(*p));
	p->hop_limit = -1;
	p->encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
	p->proto = IPPROTO_IPV6;
	memset(&medium, 0, sizeof(medium));

	while (argc > 0) {
		if (!strcmp(*argv, "--help") || !strcmp(*argv, "-h")) {
			usage();
		} else if (!strcmp(*argv, "--allow-local-packets")) {
			p->flags |= IPV6_TNL_F_ALLOW_LOCAL;
		} else if (!strcmp(*argv, "--use-original-traffic-class")) {
			p->flags |= IPV6_TNL_F_USE_ORIG_TCLASS;
		} else if (!strcmp(*argv, "remote")) {
			argv++; 
			if (--argc <= 0) 
				usage();
			resolve_name(*argv, &p->raddr);
		} else if (!strcmp(*argv, "local")) {
			argv++; 
			if (--argc <= 0) 
				usage();
			resolve_name(*argv, &p->laddr);
		} else if (!strcmp(*argv, "dev")) {
			argv++; 
			if (--argc <= 0) 
				usage();
			strncpy(medium, *argv, IFNAMSIZ - 1);
		} else if (!strcmp(*argv, "hoplimit")) {
			__u8 uval;
			argv++; 
			if (--argc <= 0) 
				usage();
			if (get_u8(&uval, *argv) < -1)
				usage();
			p->hop_limit = uval;
		} else if (!strcmp(*argv, "flowlabel")) {
			__u32 uval;
			argv++; 
			if (--argc <= 0) 
				usage();
			if (get_u20(&uval, *argv) < -1)
				usage();
			p->flow_lbl = uval;
		} else if (!strcmp(*argv, "encaplimit")) {
			argv++; 
			if (--argc <= 0) 
				usage();
			if (!strcmp(*argv, "none")) {
				p->flags |= IPV6_TNL_F_IGN_ENCAP_LIMIT;
			} else {
				__u8 uval;
				if (get_u8(&uval, *argv) < -1)
					usage();
				p->encap_limit = uval;
			}
		} else {
			if (p->name[0])
				usage();
			strncpy(p->name, *argv, IFNAMSIZ - 1);
		}
		argc--; argv++;
	}
	if (medium[0]) {
		p->link = do_ioctl_get_ifindex(medium);
		if (p->link == 0)
			return -1;
	}
	return 0;
}

static int do_show(int argc, char **argv)
{
        struct ipv6_tnl_parm p;

        if (parse_args(argc, argv, &p) < 0)
                return -1;

	if (do_get_ioctl(p.name[0] ? p.name : "ip6tnl0", &p))
                return -1;

        print_tunnel(&p);
        return 0;
}




static int do_add(int cmd, int argc, char **argv)
{
	struct ipv6_tnl_parm p;

	if (parse_args(argc, argv, &p) < 0)
		return -1;
	
	return do_add_ioctl(cmd, 
			    cmd == SIOCCHGTUNNEL && p.name[0] ?
			    p.name : "ip6tnl0", &p);
}

int do_del(int argc, char **argv)
{
	struct ipv6_tnl_parm p;

	if (parse_args(argc, argv, &p) < 0)
		return -1;

	return do_del_ioctl(p.name[0] ? p.name : "ip6tnl0", &p);
}


int main(int argc, char **argv) 
{ 
	argc--;
	argv++;
	if (argc > 0) {
		if (strcmp(*argv, "add") == 0)
			return do_add(SIOCADDTUNNEL, argc - 1, argv + 1);
		else if (strcmp(*argv, "change") == 0)
			return do_add(SIOCCHGTUNNEL, argc - 1, argv + 1);
		else if (strcmp(*argv, "del") == 0)
			return do_del(argc - 1, argv + 1);
		else if (strcmp(*argv, "show") == 0)
			return do_show(argc - 1, argv + 1);
		else
			usage();

	} else
		return do_show(0, NULL);

	return 0;
}
