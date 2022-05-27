/* SPDX-License-Identifier: GPL-2.0
 *
 * iplink_virt_wifi.c  A fake implementation of cfg80211_ops that can be tacked
 *                     on to an ethernet net_device to make it appear as a
 *                     wireless connection.
 *
 * Authors:            Baligh Gasmi <gasmibal@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "ip_common.h"

static void virt_wifi_print_help(struct link_util *lu,
		int argc, char **argv, FILE *f)
{
	fprintf(f, "Usage: ... virt_wifi \n");
}

struct link_util virt_wifi_link_util = {
	.id		= "virt_wifi",
	.print_help	= virt_wifi_print_help,
};
