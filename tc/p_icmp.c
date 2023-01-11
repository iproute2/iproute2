/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * m_pedit_icmp.c	packet editor: ICMP header
 *
 * Authors:  J Hadi Salim (hadi@cyberus.ca)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "utils.h"
#include "tc_util.h"
#include "m_pedit.h"


static int
parse_icmp(int *argc_p, char ***argv_p,
	   struct m_pedit_sel *sel, struct m_pedit_key *tkey)
{
	return -1;
}

struct m_pedit_util p_pedit_icmp = {
	.id = "icmp",
	.parse_peopt = parse_icmp,
};
