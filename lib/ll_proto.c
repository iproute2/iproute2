/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ll_proto.c
 *
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>

#include "utils.h"
#include "rt_names.h"


#define __PF(f,n) { ETH_P_##f, #n },

static const struct proto llproto_names[] = {
__PF(LOOP,loop)
__PF(PUP,pup)
__PF(PUPAT,pupat)
__PF(IP,ip)
__PF(X25,x25)
__PF(ARP,arp)
__PF(BPQ,bpq)
__PF(IEEEPUP,ieeepup)
__PF(IEEEPUPAT,ieeepupat)
__PF(DEC,dec)
__PF(DNA_DL,dna_dl)
__PF(DNA_RC,dna_rc)
__PF(DNA_RT,dna_rt)
__PF(LAT,lat)
__PF(DIAG,diag)
__PF(CUST,cust)
__PF(SCA,sca)
__PF(RARP,rarp)
__PF(ATALK,atalk)
__PF(AARP,aarp)
__PF(IPX,ipx)
__PF(IPV6,ipv6)
__PF(PPP_DISC,ppp_disc)
__PF(PPP_SES,ppp_ses)
__PF(ATMMPOA,atmmpoa)
__PF(ATMFATE,atmfate)
__PF(802_3,802_3)
__PF(AX25,ax25)
__PF(ALL,all)
__PF(802_2,802_2)
__PF(SNAP,snap)
__PF(DDCMP,ddcmp)
__PF(WAN_PPP,wan_ppp)
__PF(PPP_MP,ppp_mp)
__PF(LOCALTALK,localtalk)
__PF(CAN,can)
__PF(PPPTALK,ppptalk)
__PF(TR_802_2,tr_802_2)
__PF(MOBITEX,mobitex)
__PF(CONTROL,control)
__PF(IRDA,irda)
__PF(ECONET,econet)
__PF(TIPC,tipc)
__PF(PROFINET,profinet)
__PF(AOE,aoe)
__PF(ETHERCAT,ethercat)
__PF(8021Q,802.1Q)
__PF(8021AD,802.1ad)
__PF(MPLS_UC,mpls_uc)
__PF(MPLS_MC,mpls_mc)
__PF(TEB,teb)
__PF(CFM,cfm)

{ 0x8100, "802.1Q" },
{ 0x88cc, "LLDP" },
{ ETH_P_IP, "ipv4" },
};
#undef __PF

const char *ll_proto_n2a(unsigned short id, char *buf, int len)
{
	size_t len_tb = ARRAY_SIZE(llproto_names);

	return proto_n2a(id, buf, len, llproto_names, len_tb);
}

int ll_proto_a2n(unsigned short *id, const char *buf)
{
	size_t len_tb = ARRAY_SIZE(llproto_names);

	return proto_a2n(id, buf, llproto_names, len_tb);
}
