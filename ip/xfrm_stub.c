/*
 * Minimal stub used to build against older kernels with xfrm
 */
#include <stdio.h>
#include <stdlib.h>

int do_xfrm(int arg, char **argv)
{
	fprintf(stderr, "This version of built without xfrm support\n");
	exit(1);
}
