/* rtstat.c:  A program for route cache monitoring
 *
 * Copyright 2001 by Robert Olsson <robert.olsson@its.uu.se>
 *                                 Uppsala University, Sweden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Additional credits:
 * Martin Josefsson <gandalf@wlug.westbo.se> 010828 bug fix
 *					     030420 cleanup
 * 
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#define VERSION "0.42 030623"


#define FMT_LEN1 11 
#define FMT_LEN2 15
#define FMT_LEN3 17

extern char *optarg;
extern int optind, opterr, optopt;

FILE *fp;
unsigned rt_size, in_hit[2], in_slow_tot[2], in_slow_mc[2], 
  in_no_rt[2], in_brd[2], in_martian_dst[2], in_martian_src[2],
  out_hit[2], out_slow_tot[2], out_slow_mc[2], gc_total[2], 
  gc_ignored[2], gc_goal_miss[2], gc_dst_overflow[2],
  in_hlist_search[2], out_hlist_search[2];

int llen;


/* Read (and summarize for SMP) the different stats vars. */

void scan_line(int i)
{
	char buf[1024];
	unsigned temp[16];
	
	i %= 2;

	in_hit[i] = 0;
	in_slow_tot[i] = 0;
	in_slow_mc[i] = 0;
	in_no_rt[i] = 0;
	in_brd[i] = 0;
	in_martian_dst[i] = 0;
	in_martian_src[i] = 0;
	out_hit[i] = 0;
	out_slow_tot[i] = 0;
	out_slow_mc[i] = 0;
	gc_total[i] = 0;
	gc_ignored[i] = 0;
	gc_goal_miss[i] = 0;
	gc_dst_overflow[i] = 0;
	in_hlist_search[i] = 0;
	out_hlist_search[i] = 0;

	for(;;) {
		fgets(buf, 1023, fp);
		if( feof(fp) ) break;

		llen = sscanf(buf, "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n", 

		       &rt_size,
		       &temp[0],     /* in_hit */
		       &temp[1],     /* in_slow_tot */
		       &temp[2],     /* in_slow_mc */
		       &temp[3],     /* in_no_rt */
		       &temp[4],     /* in_brd */
		       &temp[5],     /* in_martian_dst */
		       &temp[6],     /* in_martian_src */
		       &temp[7],     /* out_hit */
		       &temp[8],     /* out_slow_tot */
		       &temp[9],      /* out_slow_mc */
		       &temp[10],     /* gc_total */
		       &temp[11],     /* gc_ignored */
		       &temp[12],     /* gc_goal_miss */
		       &temp[13],     /* gc_dst_overflow */
		       &temp[14],     /* in_hlist_search */
		       &temp[15]      /* out_hlist_search */
		       );

		in_hit[i] += temp[0];
		in_slow_tot[i] += temp[1];
		in_slow_mc[i] += temp[2];
		in_no_rt[i] += temp[3];
		in_brd[i] += temp[4];
		in_martian_dst[i] += temp[5];
		in_martian_src[i] += temp[6];
		out_hit[i] += temp[7];
		out_slow_tot[i] += temp[8];
		out_slow_mc[i] += temp[9];
		if(llen > FMT_LEN1 ) {
			gc_total[i] += temp[10];
			gc_ignored[i] += temp[11];
			gc_goal_miss[i] += temp[12];
			gc_dst_overflow[i] += temp[13];
		}
		if(llen > FMT_LEN2 ) {
			in_hlist_search[i] += temp[14];
			out_hlist_search[i] += temp[15];
		}
	}
}
void print_hdr_line(void)
{		
	printf(" size   IN: hit     tot    mc no_rt bcast madst masrc  OUT: hit     tot     mc");

	if( llen > FMT_LEN1 )
		printf(" GC: tot ignored goal_miss ovrf");

	if( llen > FMT_LEN2 )
		printf(" HASH: in_search out_search");

	printf("\n");
}

int usage(int exit_code)
{
	fprintf(stderr, "rtstat        Version %s\n", VERSION);
	fprintf(stderr, "              -help\n");
	fprintf(stderr, "              -i interval\n");
	fprintf(stderr, "              -s subject [0-2]\n");	
	fprintf(stderr, "\n");	
	print_hdr_line();
	fprintf(stderr, "\n");	
	fprintf(stderr, "size   == route cache size\n");	
	fprintf(stderr, "hit    == IN: total number of cache hits per sec\n");	
	fprintf(stderr, "tot    == IN: total number of cache misses per sec\n");
	fprintf(stderr, "mc     == IN: mulicast cache misses per sec\n");
	fprintf(stderr, "no_rt  == IN: route table misses per sec\n");
	fprintf(stderr, "bcast  == IN: broadcast cache misses per sec\n");
	fprintf(stderr, "madst  == IN: dst martians per sec\n");
	fprintf(stderr, "masrc  == IN: src martians per sec\n");
	fprintf(stderr, "hit    == OUT: total number of cache hits per sec\n");	
	fprintf(stderr, "tot    == OUT: total number of cache misses per sec\n");
	fprintf(stderr, "mc     == OUT: mulicast cache misses per sec\n");
	fprintf(stderr, "tot     == GC: total calls per sec\n");
	fprintf(stderr, "ignored == GC: calls ignored per sec\n");
	fprintf(stderr, "goal_miss  == GC: goal miss per sec\n");
	fprintf(stderr, "ovrflw  == GC: dst_overflow per sec\n");
	fprintf(stderr, "in_search  == HASH: input hash list search per sec\n");
	fprintf(stderr, "out_search  == HASH: output hash list search per sec\n");

	exit(exit_code);
}

void print(int i, int interval)
{		  
	int new = i % 2;
	int old = !new;

	printf("%5u %9u %7u %5u %5u %5u %5u %5u %9u %7u %6u",
	       rt_size,
	       (in_hit[new] - in_hit[old])/interval,
	       (in_slow_tot[new] - in_slow_tot[old])/interval,
	       (in_slow_mc[new] - in_slow_mc[old])/interval,
	       (in_no_rt[new] - in_no_rt[old])/interval,
	       (in_brd[new] - in_brd[old])/interval,
	       (in_martian_dst[new] - in_martian_dst[old])/interval,
	       (in_martian_src[new] - in_martian_src[old])/interval,

	       (out_hit[new] - out_hit[old])/interval,
	       (out_slow_tot[new] - out_slow_tot[old])/interval,
	       (out_slow_mc[new] - out_slow_mc[old])/interval);

	       if(llen > FMT_LEN1 )
		       printf(" %7u %7u %9u %4u",

	       (gc_total[new] - gc_total[old])/interval,
	       (gc_ignored[new] - gc_ignored[old])/interval,
	       (gc_goal_miss[new] - gc_goal_miss[old])/interval,
	       (gc_dst_overflow[new] - gc_dst_overflow[old])/interval);

	       if(llen > FMT_LEN2 )
		       printf(" %15u %10u",
			      (in_hlist_search[new] - in_hlist_search[old])/interval,
			      (out_hlist_search[new] - out_hlist_search[old])/interval);
	       printf("\n");
}

int main(int argc, char **argv)
{
	int c, i, interval = 2, hdr = 2;
  
	while ((c=getopt(argc, argv,"h?s:i:")) != EOF) {
		switch (c)
		{
			case '?':
			case 'h':
				usage(0);
				break;
				
			case 'i':
				sscanf(optarg, "%u", &interval);
				break;
	
			case 's':
				sscanf(optarg, "%u", &hdr);
				break;
	
			default:
				usage(1);
		}
	}

	if (interval < 1)
		interval = 1;

	fp = fopen("/proc/net/rt_cache_stat", "r");
	if (!fp) {
		perror("fopen");
		exit(-1);
	}

	/* Read llen */
	scan_line(0);
	rewind(fp);

	if (hdr > 0)
		print_hdr_line();

	for(i = 0;;i++) {
		if(hdr > 1 && i != 0 && (i % 20) == 0)
			print_hdr_line();

		scan_line(i);
		rewind(fp);
		if (i != 0)
			print(i, interval);
		sleep(interval);
	}
	return 1;
}
