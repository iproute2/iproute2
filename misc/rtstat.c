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
 * 
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#define VERSION "0.33 010829"

extern char *optarg;
extern int optind, opterr, optopt;

FILE *fp;
unsigned rt_size, in_hit[2], in_slow_tot[2], in_slow_mc[2], 
  in_no_rt[2], in_brd[2], in_martian_dst[2], in_martian_src[2],
  out_hit[2], out_slow_tot[2], out_slow_mc[2];


/* Read (and summarize for SMP) the different stats vars. */

void scan_line(int i)
{
	unsigned temp[10];

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

	while(!feof(fp)) {
		fscanf(fp, "%x %x %x %x %x %x %x %x %x %x %x\n", 
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
		       &temp[9]      /* out_slow_mc */
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
	}
	return;
}

void print_hdr_line(void)
{		
	printf(" size   IN: hit     tot    mc no_rt bcast madst masrc  OUT: hit     tot     mc\n");
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

	exit(exit_code);
}

int main(int argc, char **argv)
{
	int c, i=1, interval=2, hdr=2;
  
	while ((c=getopt(argc, argv,"h?s:i:")) != EOF)
		switch (c)
		{

		case '?':
		case 'h':       usage(0);
	
		case 'i':      sscanf(optarg, "%u", &interval);
			break;
	
		case 's':      sscanf(optarg, "%u", &hdr);
			break;
	
		default:        usage(1);
		}

	if(interval < 1 ) interval=1;

	if ((fp = fopen("/proc/net/rt_cache_stat", "r")));
	else 
	{
		perror("fopen");
		exit(-1);
	}

	if(hdr > 0) print_hdr_line();

	for(;1;i++) {

		if(hdr > 1 && (!  (i % 20)))  print_hdr_line();
		
		scan_line(0);
		sleep(interval);
		rewind(fp);
		scan_line(1);
		rewind(fp);			
		  
		printf("%5u %9u %7u %5u %5u %5u %5u %5u %9u %7u %6u\n",
		       rt_size,
		       (in_hit[1] - in_hit[0])/interval,
		       (in_slow_tot[1] - in_slow_tot[0])/interval,
		       (in_slow_mc[1] - in_slow_mc[0])/interval,
		       (in_no_rt[1] - in_no_rt[0])/interval,
		       (in_brd[1] - in_brd[0])/interval,
		       (in_martian_dst[1] - in_martian_dst[0])/interval,
		       (in_martian_src[1] - in_martian_src[0])/interval,

		       (out_hit[1] - out_hit[0])/interval,
		       (out_slow_tot[1] - out_slow_tot[0])/interval,
		       (out_slow_mc[1] - out_slow_mc[0])/interval
			);
	}
	return 1;
}

/*
 * Compile: 
  gcc -g -O2 -Wall -o rtstat  rtstat.c
*/



