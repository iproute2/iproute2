/*
 * ip.c		"ip" utility frontend.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *
 * Changes:
 *
 * Rani Assaf <rani@magic.metawire.com> 980929:	resolve addresses
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "SNAPSHOT.h"
#include "utils.h"
#include "ip_common.h"

int preferred_family = AF_UNSPEC;
int show_stats = 0;
int resolve_hosts = 0;
int oneline = 0;
char * _SL_ = NULL;

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr,
"Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
"where  OBJECT := { link | addr | route | rule | neigh | tunnel |\n"
"                   maddr | mroute | monitor }\n"
"       OPTIONS := { -V[ersion] | -s[tatistics] | -r[esolve] |\n"
"                    -f[amily] { inet | inet6 | ipx | dnet | link } | -o[neline] }\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	char *basename;

	basename = strrchr(argv[0], '/');
	if (basename == NULL)
		basename = argv[0];
	else
		basename++;
	
	while (argc > 1) {
		char *opt = argv[1];
		if (strcmp(opt,"--") == 0) {
			argc--; argv++;
			break;
		}
		if (opt[0] != '-')
			break;
		if (opt[1] == '-')
			opt++;
		if (matches(opt, "-family") == 0) {
			argc--;
			argv++;
			if (argc <= 1)
				usage();
			if (strcmp(argv[1], "inet") == 0)
				preferred_family = AF_INET;
			else if (strcmp(argv[1], "inet6") == 0)
				preferred_family = AF_INET6;
			else if (strcmp(argv[1], "dnet") == 0)
				preferred_family = AF_DECnet;
			else if (strcmp(argv[1], "link") == 0)
				preferred_family = AF_PACKET;
			else if (strcmp(argv[1], "ipx") == 0)
				preferred_family = AF_IPX;
			else if (strcmp(argv[1], "help") == 0)
				usage();
			else
				invarg(argv[1], "invalid protocol family");
		} else if (strcmp(opt, "-4") == 0) {
			preferred_family = AF_INET;
		} else if (strcmp(opt, "-6") == 0) {
			preferred_family = AF_INET6;
		} else if (strcmp(opt, "-0") == 0) {
			preferred_family = AF_PACKET;
		} else if (strcmp(opt, "-I") == 0) {
			preferred_family = AF_IPX;
		} else if (strcmp(opt, "-D") == 0) {
			preferred_family = AF_DECnet;
		} else if (matches(opt, "-stats") == 0 ||
			   matches(opt, "-statistics") == 0) {
			++show_stats;
		} else if (matches(opt, "-resolve") == 0) {
			++resolve_hosts;
		} else if (matches(opt, "-oneline") == 0) {
			++oneline;
#if 0
		} else if (matches(opt, "-numeric") == 0) {
			rtnl_names_numeric++;
#endif
		} else if (matches(opt, "-Version") == 0) {
			printf("ip utility, iproute2-ss%s\n", SNAPSHOT);
			exit(0);
		} else if (matches(opt, "-help") == 0) {
			usage();
		} else {
			fprintf(stderr, "Option \"%s\" is unknown, try \"ip -help\".\n", opt);
			exit(-1);
		}
		argc--;	argv++;
	}

	_SL_ = oneline ? "\\" : "\n" ;

	if (strcmp(basename, "ipaddr") == 0)
		return do_ipaddr(argc-1, argv+1);
	if (strcmp(basename, "ipmaddr") == 0)
		return do_multiaddr(argc-1, argv+1);
	if (strcmp(basename, "iproute") == 0)
		return do_iproute(argc-1, argv+1);
	if (strcmp(basename, "iprule") == 0)
		return do_iprule(argc-1, argv+1);
	if (strcmp(basename, "ipneigh") == 0)
		return do_ipneigh(argc-1, argv+1);
	if (strcmp(basename, "iplink") == 0)
		return do_iplink(argc-1, argv+1);
	if (strcmp(basename, "iptunnel") == 0)
		return do_iptunnel(argc-1, argv+1);
	if (strcmp(basename, "ipmonitor") == 0)
		return do_ipmonitor(argc-1, argv+1);

	if (argc > 1) {
		if (matches(argv[1], "address") == 0)
			return do_ipaddr(argc-2, argv+2);
		if (matches(argv[1], "maddress") == 0)
			return do_multiaddr(argc-2, argv+2);
		if (matches(argv[1], "route") == 0)
			return do_iproute(argc-2, argv+2);
		if (matches(argv[1], "rule") == 0)
			return do_iprule(argc-2, argv+2);
		if (matches(argv[1], "mroute") == 0)
			return do_multiroute(argc-2, argv+2);
		if (matches(argv[1], "neighbor") == 0 ||
		    matches(argv[1], "neighbour") == 0)
			return do_ipneigh(argc-2, argv+2);
		if (matches(argv[1], "link") == 0)
			return do_iplink(argc-2, argv+2);
		if (matches(argv[1], "tunnel") == 0 ||
		    strcmp(argv[1], "tunl") == 0)
			return do_iptunnel(argc-2, argv+2);
		if (matches(argv[1], "monitor") == 0)
			return do_ipmonitor(argc-2, argv+2);
		if (matches(argv[1], "help") == 0)
			usage();
		fprintf(stderr, "Object \"%s\" is unknown, try \"ip help\".\n", argv[1]);
		exit(-1);
	}
	usage();
}
