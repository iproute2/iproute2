/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Utilities for translating PPP protocols from strings
 * and vice versa.
 *
 * Authors:     Wojciech Drewek <wojciech.drewek@intel.com>
 */

#include <linux/ppp_defs.h>
#include <linux/if_ether.h>
#include "utils.h"
#include "rt_names.h"

static const struct proto ppp_proto_names[] = {
	{PPP_IP, "ip"},
	{PPP_AT, "at"},
	{PPP_IPX, "ipx"},
	{PPP_VJC_COMP, "vjc_comp"},
	{PPP_VJC_UNCOMP, "vjc_uncomp"},
	{PPP_MP, "mp"},
	{PPP_IPV6, "ipv6"},
	{PPP_COMPFRAG, "compfrag"},
	{PPP_COMP, "comp"},
	{PPP_MPLS_UC, "mpls_uc"},
	{PPP_MPLS_MC, "mpls_mc"},
	{PPP_IPCP, "ipcp"},
	{PPP_ATCP, "atcp"},
	{PPP_IPXCP, "ipxcp"},
	{PPP_IPV6CP, "ipv6cp"},
	{PPP_CCPFRAG, "ccpfrag"},
	{PPP_CCP, "ccp"},
	{PPP_MPLSCP, "mplscp"},
	{PPP_LCP, "lcp"},
	{PPP_PAP, "pap"},
	{PPP_LQR, "lqr"},
	{PPP_CHAP, "chap"},
	{PPP_CBCP, "cbcp"},
};

const char *ppp_proto_n2a(unsigned short id, char *buf, int len)
{
	size_t len_tb = ARRAY_SIZE(ppp_proto_names);

	return proto_n2a(id, buf, len, ppp_proto_names, len_tb);
}

int ppp_proto_a2n(unsigned short *id, const char *buf)
{
	size_t len_tb = ARRAY_SIZE(ppp_proto_names);

	return proto_a2n(id, buf, ppp_proto_names, len_tb);
}
