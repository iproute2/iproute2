/*
 * f_flower.c		Flower Classifier
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:     Jiri Pirko <jiri@resnulli.us>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tc_act/tc_vlan.h>

#include "utils.h"
#include "tc_util.h"
#include "rt_names.h"

enum flower_matching_flags {
	FLOWER_IP_FLAGS,
};

enum flower_endpoint {
	FLOWER_ENDPOINT_SRC,
	FLOWER_ENDPOINT_DST
};

enum flower_icmp_field {
	FLOWER_ICMP_FIELD_TYPE,
	FLOWER_ICMP_FIELD_CODE
};

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... flower [ MATCH-LIST ]\n"
		"                  [ skip_sw | skip_hw ]\n"
		"                  [ action ACTION-SPEC ] [ classid CLASSID ]\n"
		"\n"
		"Where: MATCH-LIST := [ MATCH-LIST ] MATCH\n"
		"       MATCH      := { indev DEV-NAME |\n"
		"                       vlan_id VID |\n"
		"                       vlan_prio PRIORITY |\n"
		"                       vlan_ethtype [ ipv4 | ipv6 | ETH-TYPE ] |\n"
		"                       dst_mac MASKED-LLADDR |\n"
		"                       src_mac MASKED-LLADDR |\n"
		"                       ip_proto [tcp | udp | sctp | icmp | icmpv6 | IP-PROTO ] |\n"
		"                       ip_tos MASKED-IP_TOS |\n"
		"                       ip_ttl MASKED-IP_TTL |\n"
		"                       dst_ip PREFIX |\n"
		"                       src_ip PREFIX |\n"
		"                       dst_port PORT-NUMBER |\n"
		"                       src_port PORT-NUMBER |\n"
		"                       tcp_flags MASKED-TCP_FLAGS |\n"
		"                       type MASKED-ICMP-TYPE |\n"
		"                       code MASKED-ICMP-CODE |\n"
		"                       arp_tip IPV4-PREFIX |\n"
		"                       arp_sip IPV4-PREFIX |\n"
		"                       arp_op [ request | reply | OP ] |\n"
		"                       arp_tha MASKED-LLADDR |\n"
		"                       arp_sha MASKED-LLADDR |\n"
		"                       enc_dst_ip [ IPV4-ADDR | IPV6-ADDR ] |\n"
		"                       enc_src_ip [ IPV4-ADDR | IPV6-ADDR ] |\n"
		"                       enc_key_id [ KEY-ID ] |\n"
		"                       ip_flags IP-FLAGS | \n"
		"                       enc_dst_port [ port_number ] }\n"
		"       FILTERID := X:Y:Z\n"
		"       MASKED_LLADDR := { LLADDR | LLADDR/MASK | LLADDR/BITS }\n"
		"       ACTION-SPEC := ... look at individual actions\n"
		"\n"
		"NOTE: CLASSID, IP-PROTO are parsed as hexadecimal input.\n"
		"NOTE: There can be only used one mask per one prio. If user needs\n"
		"      to specify different mask, he has to use different prio.\n");
}

static int flower_parse_eth_addr(char *str, int addr_type, int mask_type,
				 struct nlmsghdr *n)
{
	int ret, err = -1;
	char addr[ETH_ALEN], *slash;

	slash = strchr(str, '/');
	if (slash)
		*slash = '\0';

	ret = ll_addr_a2n(addr, sizeof(addr), str);
	if (ret < 0)
		goto err;
	addattr_l(n, MAX_MSG, addr_type, addr, sizeof(addr));

	if (slash) {
		unsigned bits;

		if (!get_unsigned(&bits, slash + 1, 10)) {
			uint64_t mask;

			/* Extra 16 bit shift to push mac address into
			 * high bits of uint64_t
			 */
			mask = htonll(0xffffffffffffULL << (16 + 48 - bits));
			memcpy(addr, &mask, ETH_ALEN);
		} else {
			ret = ll_addr_a2n(addr, sizeof(addr), slash + 1);
			if (ret < 0)
				goto err;
		}
	} else {
		memset(addr, 0xff, ETH_ALEN);
	}
	addattr_l(n, MAX_MSG, mask_type, addr, sizeof(addr));

	err = 0;
err:
	if (slash)
		*slash = '/';
	return err;
}

static int flower_parse_vlan_eth_type(char *str, __be16 eth_type, int type,
				      __be16 *p_vlan_eth_type,
				      struct nlmsghdr *n)
{
	__be16 vlan_eth_type;

	if (eth_type != htons(ETH_P_8021Q)) {
		fprintf(stderr,
			"Can't set \"vlan_ethtype\" if ethertype isn't 802.1Q\n");
		return -1;
	}

	if (ll_proto_a2n(&vlan_eth_type, str))
		invarg("invalid vlan_ethtype", str);
	addattr16(n, MAX_MSG, type, vlan_eth_type);
	*p_vlan_eth_type = vlan_eth_type;
	return 0;
}

struct flag_to_string {
	int flag;
	enum flower_matching_flags type;
	char *string;
};

static struct flag_to_string flags_str[] = {
	{ TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT, FLOWER_IP_FLAGS, "frag" },
};

static int flower_parse_matching_flags(char *str,
				       enum flower_matching_flags type,
				       __u32 *mtf, __u32 *mtf_mask)
{
	char *token;
	bool no;
	bool found;
	int i;

	token = strtok(str, "/");

	while (token) {
		if (!strncmp(token, "no", 2)) {
			no = true;
			token += 2;
		} else
			no = false;

		found = false;
		for (i = 0; i < ARRAY_SIZE(flags_str); i++) {
			if (type != flags_str[i].type)
				continue;

			if (!strcmp(token, flags_str[i].string)) {
				if (no)
					*mtf &= ~flags_str[i].flag;
				else
					*mtf |= flags_str[i].flag;

				*mtf_mask |= flags_str[i].flag;
				found = true;
				break;
			}
		}
		if (!found)
			return -1;

		token = strtok(NULL, "/");
	}

	return 0;
}

static int flower_parse_ip_proto(char *str, __be16 eth_type, int type,
				 __u8 *p_ip_proto, struct nlmsghdr *n)
{
	int ret;
	__u8 ip_proto;

	if (eth_type != htons(ETH_P_IP) && eth_type != htons(ETH_P_IPV6))
		goto err;

	if (matches(str, "tcp") == 0) {
		ip_proto = IPPROTO_TCP;
	} else if (matches(str, "udp") == 0) {
		ip_proto = IPPROTO_UDP;
	} else if (matches(str, "sctp") == 0) {
		ip_proto = IPPROTO_SCTP;
	} else if (matches(str, "icmp") == 0) {
		if (eth_type != htons(ETH_P_IP))
			goto err;
		ip_proto = IPPROTO_ICMP;
	} else if (matches(str, "icmpv6") == 0) {
		if (eth_type != htons(ETH_P_IPV6))
			goto err;
		ip_proto = IPPROTO_ICMPV6;
	} else {
		ret = get_u8(&ip_proto, str, 16);
		if (ret)
			return -1;
	}
	addattr8(n, MAX_MSG, type, ip_proto);
	*p_ip_proto = ip_proto;
	return 0;

err:
	fprintf(stderr, "Illegal \"eth_type\" for ip proto\n");
	return -1;
}

static int __flower_parse_ip_addr(char *str, int family,
				  int addr4_type, int mask4_type,
				  int addr6_type, int mask6_type,
				  struct nlmsghdr *n)
{
	int ret;
	inet_prefix addr;
	int bits;
	int i;

	ret = get_prefix(&addr, str, family);
	if (ret)
		return -1;

	if (family && (addr.family != family)) {
		fprintf(stderr, "Illegal \"eth_type\" for ip address\n");
		return -1;
	}

	addattr_l(n, MAX_MSG, addr.family == AF_INET ? addr4_type : addr6_type,
		  addr.data, addr.bytelen);

	memset(addr.data, 0xff, addr.bytelen);
	bits = addr.bitlen;
	for (i = 0; i < addr.bytelen / 4; i++) {
		if (!bits) {
			addr.data[i] = 0;
		} else if (bits / 32 >= 1) {
			bits -= 32;
		} else {
			addr.data[i] <<= 32 - bits;
			addr.data[i] = htonl(addr.data[i]);
			bits = 0;
		}
	}

	addattr_l(n, MAX_MSG, addr.family == AF_INET ? mask4_type : mask6_type,
		  addr.data, addr.bytelen);

	return 0;
}

static int flower_parse_ip_addr(char *str, __be16 eth_type,
				int addr4_type, int mask4_type,
				int addr6_type, int mask6_type,
				struct nlmsghdr *n)
{
	int family;

	if (eth_type == htons(ETH_P_IP)) {
		family = AF_INET;
	} else if (eth_type == htons(ETH_P_IPV6)) {
		family = AF_INET6;
	} else if (!eth_type) {
		family = AF_UNSPEC;
	} else {
		return -1;
	}

	return __flower_parse_ip_addr(str, family, addr4_type, mask4_type,
				      addr6_type, mask6_type, n);
}

static bool flower_eth_type_arp(__be16 eth_type)
{
	return eth_type == htons(ETH_P_ARP) || eth_type == htons(ETH_P_RARP);
}

static int flower_parse_arp_ip_addr(char *str, __be16 eth_type,
				    int addr_type, int mask_type,
				    struct nlmsghdr *n)
{
	if (!flower_eth_type_arp(eth_type))
		return -1;

	return __flower_parse_ip_addr(str, AF_INET, addr_type, mask_type,
				      TCA_FLOWER_UNSPEC, TCA_FLOWER_UNSPEC, n);
}

static int flower_parse_u8(char *str, int value_type, int mask_type,
			   int (*value_from_name)(const char *str,
						 __u8 *value),
			   bool (*value_validate)(__u8 value),
			   struct nlmsghdr *n)
{
	char *slash;
	int ret, err = -1;
	__u8 value, mask;

	slash = strchr(str, '/');
	if (slash)
		*slash = '\0';

	ret = value_from_name ? value_from_name(str, &value) : -1;
	if (ret < 0) {
		ret = get_u8(&value, str, 10);
		if (ret)
			goto err;
	}

	if (value_validate && !value_validate(value))
		goto err;

	if (slash) {
		ret = get_u8(&mask, slash + 1, 10);
		if (ret)
			goto err;
	}
	else {
		mask = UINT8_MAX;
	}

	addattr8(n, MAX_MSG, value_type, value);
	addattr8(n, MAX_MSG, mask_type, mask);

	err = 0;
err:
	if (slash)
		*slash = '/';
	return err;
}

static const char *flower_print_arp_op_to_name(__u8 op)
{
	switch (op) {
	case ARPOP_REQUEST:
		return "request";
	case ARPOP_REPLY:
		return "reply";
	default:
		return NULL;
	}
}

static int flower_arp_op_from_name(const char *name, __u8 *op)
{
	if (!strcmp(name, "request"))
		*op = ARPOP_REQUEST;
	else if (!strcmp(name, "reply"))
		*op = ARPOP_REPLY;
	else
		return -1;

	return 0;
}

static bool flow_arp_op_validate(__u8 op)
{
	return !op || op == ARPOP_REQUEST || op == ARPOP_REPLY;
}

static int flower_parse_arp_op(char *str, __be16 eth_type,
			       int op_type, int mask_type,
			       struct nlmsghdr *n)
{
	if (!flower_eth_type_arp(eth_type))
		return -1;

	return flower_parse_u8(str, op_type, mask_type, flower_arp_op_from_name,
			       flow_arp_op_validate, n);
}

static int flower_icmp_attr_type(__be16 eth_type, __u8 ip_proto,
				 enum flower_icmp_field field)
{
	if (eth_type == htons(ETH_P_IP) && ip_proto == IPPROTO_ICMP)
		return field == FLOWER_ICMP_FIELD_CODE ?
			TCA_FLOWER_KEY_ICMPV4_CODE :
			TCA_FLOWER_KEY_ICMPV4_TYPE;
	else if (eth_type == htons(ETH_P_IPV6) && ip_proto == IPPROTO_ICMPV6)
		return field == FLOWER_ICMP_FIELD_CODE ?
			TCA_FLOWER_KEY_ICMPV6_CODE :
			TCA_FLOWER_KEY_ICMPV6_TYPE;

	return -1;
}

static int flower_icmp_attr_mask_type(__be16 eth_type, __u8 ip_proto,
				      enum flower_icmp_field field)
{
	if (eth_type == htons(ETH_P_IP) && ip_proto == IPPROTO_ICMP)
		return field == FLOWER_ICMP_FIELD_CODE ?
			TCA_FLOWER_KEY_ICMPV4_CODE_MASK :
			TCA_FLOWER_KEY_ICMPV4_TYPE_MASK;
	else if (eth_type == htons(ETH_P_IPV6) && ip_proto == IPPROTO_ICMPV6)
		return field == FLOWER_ICMP_FIELD_CODE ?
			TCA_FLOWER_KEY_ICMPV6_CODE_MASK :
			TCA_FLOWER_KEY_ICMPV6_TYPE_MASK;

	return -1;
}

static int flower_parse_icmp(char *str, __u16 eth_type, __u8 ip_proto,
			     enum flower_icmp_field field, struct nlmsghdr *n)
{
	int value_type, mask_type;

	value_type = flower_icmp_attr_type(eth_type, ip_proto, field);
	mask_type = flower_icmp_attr_mask_type(eth_type, ip_proto, field);
	if (value_type < 0 || mask_type < 0)
		return -1;

	return flower_parse_u8(str, value_type, mask_type, NULL, NULL, n);
}

static int flower_port_attr_type(__u8 ip_proto, enum flower_endpoint endpoint)
{
	if (ip_proto == IPPROTO_TCP)
		return endpoint == FLOWER_ENDPOINT_SRC ?
			TCA_FLOWER_KEY_TCP_SRC :
			TCA_FLOWER_KEY_TCP_DST;
	else if (ip_proto == IPPROTO_UDP)
		return endpoint == FLOWER_ENDPOINT_SRC ?
			TCA_FLOWER_KEY_UDP_SRC :
			TCA_FLOWER_KEY_UDP_DST;
	else if (ip_proto == IPPROTO_SCTP)
		return endpoint == FLOWER_ENDPOINT_SRC ?
			TCA_FLOWER_KEY_SCTP_SRC :
			TCA_FLOWER_KEY_SCTP_DST;
	else
		return -1;
}

static int flower_parse_port(char *str, __u8 ip_proto,
			     enum flower_endpoint endpoint,
			     struct nlmsghdr *n)
{
	int ret;
	int type;
	__be16 port;

	type = flower_port_attr_type(ip_proto, endpoint);
	if (type < 0)
		return -1;

	ret = get_be16(&port, str, 10);
	if (ret)
		return -1;

	addattr16(n, MAX_MSG, type, port);

	return 0;
}

#define TCP_FLAGS_MAX_MASK 0xfff

static int flower_parse_tcp_flags(char *str, int flags_type, int mask_type,
				  struct nlmsghdr *n)
{
	char *slash;
	int ret, err = -1;
	__u16 flags;

	slash = strchr(str, '/');
	if (slash)
		*slash = '\0';

	ret = get_u16(&flags, str, 16);
	if (ret < 0 || flags & ~TCP_FLAGS_MAX_MASK)
		goto err;

	addattr16(n, MAX_MSG, flags_type, htons(flags));

	if (slash) {
		ret = get_u16(&flags, slash + 1, 16);
		if (ret < 0 || flags & ~TCP_FLAGS_MAX_MASK)
			goto err;
	} else {
		flags = TCP_FLAGS_MAX_MASK;
	}
	addattr16(n, MAX_MSG, mask_type, htons(flags));

	err = 0;
err:
	if (slash)
		*slash = '/';
	return err;
}

static int flower_parse_ip_tos_ttl(char *str, int key_type, int mask_type,
				   struct nlmsghdr *n)
{
	char *slash;
	int ret, err = -1;
	__u8 tos_ttl;

	slash = strchr(str, '/');
	if (slash)
		*slash = '\0';

	ret = get_u8(&tos_ttl, str, 10);
	if (ret < 0)
		ret = get_u8(&tos_ttl, str, 16);
	if (ret < 0)
		goto err;

	addattr8(n, MAX_MSG, key_type, tos_ttl);

	if (slash) {
		ret = get_u8(&tos_ttl, slash + 1, 16);
		if (ret < 0)
			goto err;
	} else {
		tos_ttl = 0xff;
	}
	addattr8(n, MAX_MSG, mask_type, tos_ttl);

	err = 0;
err:
	if (slash)
		*slash = '/';
	return err;
}

static int flower_parse_key_id(const char *str, int type, struct nlmsghdr *n)
{
	int ret;
	__be32 key_id;

	ret = get_be32(&key_id, str, 10);
	if (!ret)
		addattr32(n, MAX_MSG, type, key_id);

	return ret;
}

static int flower_parse_enc_port(char *str, int type, struct nlmsghdr *n)
{
	int ret;
	__be16 port;

	ret = get_be16(&port, str, 10);
	if (ret)
		return -1;

	addattr16(n, MAX_MSG, type, port);

	return 0;
}

static int flower_parse_opt(struct filter_util *qu, char *handle,
			    int argc, char **argv, struct nlmsghdr *n)
{
	int ret;
	struct tcmsg *t = NLMSG_DATA(n);
	struct rtattr *tail;
	__be16 eth_type = TC_H_MIN(t->tcm_info);
	__be16 vlan_ethtype = 0;
	__u8 ip_proto = 0xff;
	__u32 flags = 0;
	__u32 mtf = 0;
	__u32 mtf_mask = 0;

	if (handle) {
		ret = get_u32(&t->tcm_handle, handle, 0);
		if (ret) {
			fprintf(stderr, "Illegal \"handle\"\n");
			return -1;
		}
	}

	tail = (struct rtattr *) (((void *) n) + NLMSG_ALIGN(n->nlmsg_len));
	addattr_l(n, MAX_MSG, TCA_OPTIONS, NULL, 0);

	if (argc == 0) {
		/*at minimal we will match all ethertype packets */
		goto parse_done;
	}

	while (argc > 0) {
		if (matches(*argv, "classid") == 0 ||
		    matches(*argv, "flowid") == 0) {
			unsigned int handle;

			NEXT_ARG();
			ret = get_tc_classid(&handle, *argv);
			if (ret) {
				fprintf(stderr, "Illegal \"classid\"\n");
				return -1;
			}
			addattr_l(n, MAX_MSG, TCA_FLOWER_CLASSID, &handle, 4);
		} else if (matches(*argv, "ip_flags") == 0) {
			NEXT_ARG();
			ret = flower_parse_matching_flags(*argv,
							  FLOWER_IP_FLAGS,
							  &mtf,
							  &mtf_mask);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"ip_flags\"\n");
				return -1;
			}
		} else if (matches(*argv, "skip_hw") == 0) {
			flags |= TCA_CLS_FLAGS_SKIP_HW;
		} else if (matches(*argv, "skip_sw") == 0) {
			flags |= TCA_CLS_FLAGS_SKIP_SW;
		} else if (matches(*argv, "indev") == 0) {
			NEXT_ARG();
			if (check_ifname(*argv))
				invarg("\"indev\" not a valid ifname", *argv);
			addattrstrz(n, MAX_MSG, TCA_FLOWER_INDEV, *argv);
		} else if (matches(*argv, "vlan_id") == 0) {
			__u16 vid;

			NEXT_ARG();
			if (eth_type != htons(ETH_P_8021Q)) {
				fprintf(stderr,
					"Can't set \"vlan_id\" if ethertype isn't 802.1Q\n");
				return -1;
			}
			ret = get_u16(&vid, *argv, 10);
			if (ret < 0 || vid & ~0xfff) {
				fprintf(stderr, "Illegal \"vlan_id\"\n");
				return -1;
			}
			addattr16(n, MAX_MSG, TCA_FLOWER_KEY_VLAN_ID, vid);
		} else if (matches(*argv, "vlan_prio") == 0) {
			__u8 vlan_prio;

			NEXT_ARG();
			if (eth_type != htons(ETH_P_8021Q)) {
				fprintf(stderr,
					"Can't set \"vlan_prio\" if ethertype isn't 802.1Q\n");
				return -1;
			}
			ret = get_u8(&vlan_prio, *argv, 10);
			if (ret < 0 || vlan_prio & ~0x7) {
				fprintf(stderr, "Illegal \"vlan_prio\"\n");
				return -1;
			}
			addattr8(n, MAX_MSG,
				 TCA_FLOWER_KEY_VLAN_PRIO, vlan_prio);
		} else if (matches(*argv, "vlan_ethtype") == 0) {
			NEXT_ARG();
			ret = flower_parse_vlan_eth_type(*argv, eth_type,
						 TCA_FLOWER_KEY_VLAN_ETH_TYPE,
						 &vlan_ethtype, n);
			if (ret < 0)
				return -1;
		} else if (matches(*argv, "dst_mac") == 0) {
			NEXT_ARG();
			ret = flower_parse_eth_addr(*argv,
						    TCA_FLOWER_KEY_ETH_DST,
						    TCA_FLOWER_KEY_ETH_DST_MASK,
						    n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"dst_mac\"\n");
				return -1;
			}
		} else if (matches(*argv, "src_mac") == 0) {
			NEXT_ARG();
			ret = flower_parse_eth_addr(*argv,
						    TCA_FLOWER_KEY_ETH_SRC,
						    TCA_FLOWER_KEY_ETH_SRC_MASK,
						    n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"src_mac\"\n");
				return -1;
			}
		} else if (matches(*argv, "ip_proto") == 0) {
			NEXT_ARG();
			ret = flower_parse_ip_proto(*argv, vlan_ethtype ?
						    vlan_ethtype : eth_type,
						    TCA_FLOWER_KEY_IP_PROTO,
						    &ip_proto, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"ip_proto\"\n");
				return -1;
			}
		} else if (matches(*argv, "ip_tos") == 0) {
			NEXT_ARG();
			ret = flower_parse_ip_tos_ttl(*argv,
						      TCA_FLOWER_KEY_IP_TOS,
						      TCA_FLOWER_KEY_IP_TOS_MASK,
						      n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"ip_tos\"\n");
				return -1;
			}
		} else if (matches(*argv, "ip_ttl") == 0) {
			NEXT_ARG();
			ret = flower_parse_ip_tos_ttl(*argv,
						      TCA_FLOWER_KEY_IP_TTL,
						      TCA_FLOWER_KEY_IP_TTL_MASK,
						      n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"ip_ttl\"\n");
				return -1;
			}
		} else if (matches(*argv, "dst_ip") == 0) {
			NEXT_ARG();
			ret = flower_parse_ip_addr(*argv, vlan_ethtype ?
						   vlan_ethtype : eth_type,
						   TCA_FLOWER_KEY_IPV4_DST,
						   TCA_FLOWER_KEY_IPV4_DST_MASK,
						   TCA_FLOWER_KEY_IPV6_DST,
						   TCA_FLOWER_KEY_IPV6_DST_MASK,
						   n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"dst_ip\"\n");
				return -1;
			}
		} else if (matches(*argv, "src_ip") == 0) {
			NEXT_ARG();
			ret = flower_parse_ip_addr(*argv, vlan_ethtype ?
						   vlan_ethtype : eth_type,
						   TCA_FLOWER_KEY_IPV4_SRC,
						   TCA_FLOWER_KEY_IPV4_SRC_MASK,
						   TCA_FLOWER_KEY_IPV6_SRC,
						   TCA_FLOWER_KEY_IPV6_SRC_MASK,
						   n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"src_ip\"\n");
				return -1;
			}
		} else if (matches(*argv, "dst_port") == 0) {
			NEXT_ARG();
			ret = flower_parse_port(*argv, ip_proto,
						FLOWER_ENDPOINT_DST, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"dst_port\"\n");
				return -1;
			}
		} else if (matches(*argv, "src_port") == 0) {
			NEXT_ARG();
			ret = flower_parse_port(*argv, ip_proto,
						FLOWER_ENDPOINT_SRC, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"src_port\"\n");
				return -1;
			}
		} else if (matches(*argv, "tcp_flags") == 0) {
			NEXT_ARG();
			ret = flower_parse_tcp_flags(*argv,
						     TCA_FLOWER_KEY_TCP_FLAGS,
						     TCA_FLOWER_KEY_TCP_FLAGS_MASK,
						     n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"tcp_flags\"\n");
				return -1;
			}
		} else if (matches(*argv, "type") == 0) {
			NEXT_ARG();
			ret = flower_parse_icmp(*argv, eth_type, ip_proto,
						FLOWER_ICMP_FIELD_TYPE, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"icmp type\"\n");
				return -1;
			}
		} else if (matches(*argv, "code") == 0) {
			NEXT_ARG();
			ret = flower_parse_icmp(*argv, eth_type, ip_proto,
						FLOWER_ICMP_FIELD_CODE, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"icmp code\"\n");
				return -1;
			}
		} else if (matches(*argv, "arp_tip") == 0) {
			NEXT_ARG();
			ret = flower_parse_arp_ip_addr(*argv, vlan_ethtype ?
						       vlan_ethtype : eth_type,
						       TCA_FLOWER_KEY_ARP_TIP,
						       TCA_FLOWER_KEY_ARP_TIP_MASK,
						       n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"arp_tip\"\n");
				return -1;
			}
		} else if (matches(*argv, "arp_sip") == 0) {
			NEXT_ARG();
			ret = flower_parse_arp_ip_addr(*argv, vlan_ethtype ?
						       vlan_ethtype : eth_type,
						       TCA_FLOWER_KEY_ARP_SIP,
						       TCA_FLOWER_KEY_ARP_SIP_MASK,
						       n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"arp_sip\"\n");
				return -1;
			}
		} else if (matches(*argv, "arp_op") == 0) {
			NEXT_ARG();
			ret = flower_parse_arp_op(*argv, vlan_ethtype ?
						  vlan_ethtype : eth_type,
						  TCA_FLOWER_KEY_ARP_OP,
						  TCA_FLOWER_KEY_ARP_OP_MASK,
						  n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"arp_op\"\n");
				return -1;
			}
		} else if (matches(*argv, "arp_tha") == 0) {
			NEXT_ARG();
			ret = flower_parse_eth_addr(*argv,
						    TCA_FLOWER_KEY_ARP_THA,
						    TCA_FLOWER_KEY_ARP_THA_MASK,
						    n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"arp_tha\"\n");
				return -1;
			}
		} else if (matches(*argv, "arp_sha") == 0) {
			NEXT_ARG();
			ret = flower_parse_eth_addr(*argv,
						    TCA_FLOWER_KEY_ARP_SHA,
						    TCA_FLOWER_KEY_ARP_SHA_MASK,
						    n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"arp_sha\"\n");
				return -1;
			}
		} else if (matches(*argv, "enc_dst_ip") == 0) {
			NEXT_ARG();
			ret = flower_parse_ip_addr(*argv, 0,
						   TCA_FLOWER_KEY_ENC_IPV4_DST,
						   TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,
						   TCA_FLOWER_KEY_ENC_IPV6_DST,
						   TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,
						   n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"enc_dst_ip\"\n");
				return -1;
			}
		} else if (matches(*argv, "enc_src_ip") == 0) {
			NEXT_ARG();
			ret = flower_parse_ip_addr(*argv, 0,
						   TCA_FLOWER_KEY_ENC_IPV4_SRC,
						   TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,
						   TCA_FLOWER_KEY_ENC_IPV6_SRC,
						   TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,
						   n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"enc_src_ip\"\n");
				return -1;
			}
		} else if (matches(*argv, "enc_key_id") == 0) {
			NEXT_ARG();
			ret = flower_parse_key_id(*argv,
						  TCA_FLOWER_KEY_ENC_KEY_ID, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"enc_key_id\"\n");
				return -1;
			}
		} else if (matches(*argv, "enc_dst_port") == 0) {
			NEXT_ARG();
			ret = flower_parse_enc_port(*argv,
						    TCA_FLOWER_KEY_ENC_UDP_DST_PORT, n);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"enc_dst_port\"\n");
				return -1;
			}
		} else if (matches(*argv, "action") == 0) {
			NEXT_ARG();
			ret = parse_action(&argc, &argv, TCA_FLOWER_ACT, n);
			if (ret) {
				fprintf(stderr, "Illegal \"action\"\n");
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

parse_done:
	ret = addattr32(n, MAX_MSG, TCA_FLOWER_FLAGS, flags);
	if (ret)
		return ret;

	if (mtf_mask) {
		ret = addattr32(n, MAX_MSG, TCA_FLOWER_KEY_FLAGS, htonl(mtf));
		if (ret)
			return ret;

		ret = addattr32(n, MAX_MSG, TCA_FLOWER_KEY_FLAGS_MASK, htonl(mtf_mask));
		if (ret)
			return ret;
	}

	if (eth_type != htons(ETH_P_ALL)) {
		ret = addattr16(n, MAX_MSG, TCA_FLOWER_KEY_ETH_TYPE, eth_type);
		if (ret)
			return ret;
	}

	tail->rta_len = (((void *)n)+n->nlmsg_len) - (void *)tail;

	return 0;
}

static int __mask_bits(char *addr, size_t len)
{
	int bits = 0;
	bool hole = false;
	int i;
	int j;

	for (i = 0; i < len; i++, addr++) {
		for (j = 7; j >= 0; j--) {
			if (((*addr) >> j) & 0x1) {
				if (hole)
					return -1;
				bits++;
			} else if (bits) {
				hole = true;
			} else{
				return -1;
			}
		}
	}
	return bits;
}

static void flower_print_eth_addr(FILE *f, char *name,
				  struct rtattr *addr_attr,
				  struct rtattr *mask_attr)
{
	SPRINT_BUF(b1);
	int bits;

	if (!addr_attr || RTA_PAYLOAD(addr_attr) != ETH_ALEN)
		return;
	fprintf(f, "\n  %s %s", name, ll_addr_n2a(RTA_DATA(addr_attr), ETH_ALEN,
						  0, b1, sizeof(b1)));
	if (!mask_attr || RTA_PAYLOAD(mask_attr) != ETH_ALEN)
		return;
	bits = __mask_bits(RTA_DATA(mask_attr), ETH_ALEN);
	if (bits < 0)
		fprintf(f, "/%s", ll_addr_n2a(RTA_DATA(mask_attr), ETH_ALEN,
					      0, b1, sizeof(b1)));
	else if (bits < ETH_ALEN * 8)
		fprintf(f, "/%d", bits);
}

static void flower_print_eth_type(FILE *f, __be16 *p_eth_type,
				  struct rtattr *eth_type_attr)
{
	__be16 eth_type;

	if (!eth_type_attr)
		return;

	eth_type = rta_getattr_u16(eth_type_attr);
	fprintf(f, "\n  eth_type ");
	if (eth_type == htons(ETH_P_IP))
		fprintf(f, "ipv4");
	else if (eth_type == htons(ETH_P_IPV6))
		fprintf(f, "ipv6");
	else if (eth_type == htons(ETH_P_ARP))
		fprintf(f, "arp");
	else if (eth_type == htons(ETH_P_RARP))
		fprintf(f, "rarp");
	else
		fprintf(f, "%04x", ntohs(eth_type));
	*p_eth_type = eth_type;
}

static void flower_print_ip_proto(FILE *f, __u8 *p_ip_proto,
				  struct rtattr *ip_proto_attr)
{
	__u8 ip_proto;

	if (!ip_proto_attr)
		return;

	ip_proto = rta_getattr_u8(ip_proto_attr);
	fprintf(f, "\n  ip_proto ");
	if (ip_proto == IPPROTO_TCP)
		fprintf(f, "tcp");
	else if (ip_proto == IPPROTO_UDP)
		fprintf(f, "udp");
	else if (ip_proto == IPPROTO_SCTP)
		fprintf(f, "sctp");
	else if (ip_proto == IPPROTO_ICMP)
		fprintf(f, "icmp");
	else if (ip_proto == IPPROTO_ICMPV6)
		fprintf(f, "icmpv6");
	else
		fprintf(f, "%02x", ip_proto);
	*p_ip_proto = ip_proto;
}

static void flower_print_ip_attr(FILE *f, char *name,
				 struct rtattr *key_attr,
				 struct rtattr *mask_attr)
{
	if (!key_attr)
		return;

	fprintf(f, "\n  %s %x", name, rta_getattr_u8(key_attr));
	if (!mask_attr)
		return;
	fprintf(f, "/%x", rta_getattr_u8(mask_attr));
}

static void flower_print_matching_flags(FILE *f, char *name,
					enum flower_matching_flags type,
					struct rtattr *attr,
					struct rtattr *mask_attr)
{
	int i;
	int count = 0;
	__u32 mtf;
	__u32 mtf_mask;

	if (!mask_attr || RTA_PAYLOAD(mask_attr) != 4)
		return;

	mtf = ntohl(rta_getattr_u32(attr));
	mtf_mask = ntohl(rta_getattr_u32(mask_attr));

	for (i = 0; i < ARRAY_SIZE(flags_str); i++) {
		if (type != flags_str[i].type)
			continue;
		if (mtf_mask & flags_str[i].flag) {
			if (++count == 1)
				fprintf(f, "\n  %s ", name);
			else
				fprintf(f, "/");

			if (mtf & flags_str[i].flag)
				fprintf(f, "%s", flags_str[i].string);
			else
				fprintf(f, "no%s", flags_str[i].string);
		}
	}
}

static void flower_print_ip_addr(FILE *f, char *name, __be16 eth_type,
				 struct rtattr *addr4_attr,
				 struct rtattr *mask4_attr,
				 struct rtattr *addr6_attr,
				 struct rtattr *mask6_attr)
{
	struct rtattr *addr_attr;
	struct rtattr *mask_attr;
	int family;
	size_t len;
	int bits;

	if (eth_type == htons(ETH_P_IP)) {
		family = AF_INET;
		addr_attr = addr4_attr;
		mask_attr = mask4_attr;
		len = 4;
	} else if (eth_type == htons(ETH_P_IPV6)) {
		family = AF_INET6;
		addr_attr = addr6_attr;
		mask_attr = mask6_attr;
		len = 16;
	} else {
		return;
	}
	if (!addr_attr || RTA_PAYLOAD(addr_attr) != len)
		return;
	fprintf(f, "\n  %s %s", name, rt_addr_n2a_rta(family, addr_attr));
	if (!mask_attr || RTA_PAYLOAD(mask_attr) != len)
		return;
	bits = __mask_bits(RTA_DATA(mask_attr), len);
	if (bits < 0)
		fprintf(f, "/%s", rt_addr_n2a_rta(family, mask_attr));
	else if (bits < len * 8)
		fprintf(f, "/%d", bits);
}
static void flower_print_ip4_addr(FILE *f, char *name,
				  struct rtattr *addr_attr,
				  struct rtattr *mask_attr)
{
	return flower_print_ip_addr(f, name, htons(ETH_P_IP),
				    addr_attr, mask_attr, 0, 0);
}

static void flower_print_port(FILE *f, char *name, struct rtattr *attr)
{
	if (attr)
		fprintf(f, "\n  %s %d", name, rta_getattr_be16(attr));
}

static void flower_print_tcp_flags(FILE *f, char *name,
				  struct rtattr *flags_attr,
				  struct rtattr *mask_attr)
{
	if (!flags_attr)
		return;
	fprintf(f, "\n  %s %x", name, rta_getattr_be16(flags_attr));
	if (!mask_attr)
		return;
	fprintf(f, "/%x", rta_getattr_be16(mask_attr));
}


static void flower_print_key_id(FILE *f, const char *name,
				struct rtattr *attr)
{
	if (attr)
		fprintf(f, "\n  %s %d", name, rta_getattr_be32(attr));
}

static void flower_print_masked_u8(FILE *f, const char *name,
				   struct rtattr *attr,
				   struct rtattr *mask_attr,
				   const char *(*value_to_str)(__u8 value))
{
	const char *value_str = NULL;
	__u8 value, mask;

	if (!attr)
		return;

	value = rta_getattr_u8(attr);
	mask = mask_attr ? rta_getattr_u8(mask_attr) : UINT8_MAX;
	if (mask == UINT8_MAX && value_to_str)
		value_str = value_to_str(value);

	fprintf(f, "\n  %s ", name);

	if (value_str)
		fputs(value_str, f);
	else
		fprintf(f, "%d", value);

	if (mask != UINT8_MAX)
		fprintf(f, "/%d", mask);
}

static void flower_print_arp_op(FILE *f, const char *name,
				struct rtattr *op_attr,
				struct rtattr *mask_attr)
{
	flower_print_masked_u8(f, name, op_attr, mask_attr,
			       flower_print_arp_op_to_name);
}

static int flower_print_opt(struct filter_util *qu, FILE *f,
			    struct rtattr *opt, __u32 handle)
{
	struct rtattr *tb[TCA_FLOWER_MAX + 1];
	int nl_type, nl_mask_type;
	__be16 eth_type = 0;
	__u8 ip_proto = 0xff;

	if (!opt)
		return 0;

	parse_rtattr_nested(tb, TCA_FLOWER_MAX, opt);

	if (handle)
		fprintf(f, "handle 0x%x ", handle);

	if (tb[TCA_FLOWER_CLASSID]) {
		SPRINT_BUF(b1);
		fprintf(f, "classid %s ",
			sprint_tc_classid(rta_getattr_u32(tb[TCA_FLOWER_CLASSID]),
					  b1));
	}

	if (tb[TCA_FLOWER_INDEV]) {
		struct rtattr *attr = tb[TCA_FLOWER_INDEV];

		fprintf(f, "\n  indev %s", rta_getattr_str(attr));
	}

	if (tb[TCA_FLOWER_KEY_VLAN_ID]) {
		struct rtattr *attr = tb[TCA_FLOWER_KEY_VLAN_ID];

		fprintf(f, "\n  vlan_id %d", rta_getattr_u16(attr));
	}

	if (tb[TCA_FLOWER_KEY_VLAN_PRIO]) {
		struct rtattr *attr = tb[TCA_FLOWER_KEY_VLAN_PRIO];

		fprintf(f, "\n  vlan_prio %d", rta_getattr_u8(attr));
	}

	flower_print_eth_addr(f, "dst_mac", tb[TCA_FLOWER_KEY_ETH_DST],
			      tb[TCA_FLOWER_KEY_ETH_DST_MASK]);
	flower_print_eth_addr(f, "src_mac", tb[TCA_FLOWER_KEY_ETH_SRC],
			      tb[TCA_FLOWER_KEY_ETH_SRC_MASK]);

	flower_print_eth_type(f, &eth_type, tb[TCA_FLOWER_KEY_ETH_TYPE]);
	flower_print_ip_proto(f, &ip_proto, tb[TCA_FLOWER_KEY_IP_PROTO]);

	flower_print_ip_attr(f, "ip_tos", tb[TCA_FLOWER_KEY_IP_TOS],
			    tb[TCA_FLOWER_KEY_IP_TOS_MASK]);
	flower_print_ip_attr(f, "ip_ttl", tb[TCA_FLOWER_KEY_IP_TTL],
			    tb[TCA_FLOWER_KEY_IP_TTL_MASK]);

	flower_print_ip_addr(f, "dst_ip", eth_type,
			     tb[TCA_FLOWER_KEY_IPV4_DST],
			     tb[TCA_FLOWER_KEY_IPV4_DST_MASK],
			     tb[TCA_FLOWER_KEY_IPV6_DST],
			     tb[TCA_FLOWER_KEY_IPV6_DST_MASK]);

	flower_print_ip_addr(f, "src_ip", eth_type,
			     tb[TCA_FLOWER_KEY_IPV4_SRC],
			     tb[TCA_FLOWER_KEY_IPV4_SRC_MASK],
			     tb[TCA_FLOWER_KEY_IPV6_SRC],
			     tb[TCA_FLOWER_KEY_IPV6_SRC_MASK]);

	nl_type = flower_port_attr_type(ip_proto, FLOWER_ENDPOINT_DST);
	if (nl_type >= 0)
		flower_print_port(f, "dst_port", tb[nl_type]);
	nl_type = flower_port_attr_type(ip_proto, FLOWER_ENDPOINT_SRC);
	if (nl_type >= 0)
		flower_print_port(f, "src_port", tb[nl_type]);

	flower_print_tcp_flags(f, "tcp_flags", tb[TCA_FLOWER_KEY_TCP_FLAGS],
			       tb[TCA_FLOWER_KEY_TCP_FLAGS_MASK]);

	nl_type = flower_icmp_attr_type(eth_type, ip_proto,
					FLOWER_ICMP_FIELD_TYPE);
	nl_mask_type = flower_icmp_attr_mask_type(eth_type, ip_proto,
						  FLOWER_ICMP_FIELD_TYPE);
	if (nl_type >= 0 && nl_mask_type >= 0)
		flower_print_masked_u8(f, "icmp_type", tb[nl_type],
				       tb[nl_mask_type], NULL);

	nl_type = flower_icmp_attr_type(eth_type, ip_proto,
					FLOWER_ICMP_FIELD_CODE);
	nl_mask_type = flower_icmp_attr_mask_type(eth_type, ip_proto,
						  FLOWER_ICMP_FIELD_CODE);
	if (nl_type >= 0 && nl_mask_type >= 0)
		flower_print_masked_u8(f, "icmp_code", tb[nl_type],
				       tb[nl_mask_type], NULL);

	flower_print_ip4_addr(f, "arp_sip", tb[TCA_FLOWER_KEY_ARP_SIP],
			     tb[TCA_FLOWER_KEY_ARP_SIP_MASK]);
	flower_print_ip4_addr(f, "arp_tip", tb[TCA_FLOWER_KEY_ARP_TIP],
			     tb[TCA_FLOWER_KEY_ARP_TIP_MASK]);
	flower_print_arp_op(f, "arp_op", tb[TCA_FLOWER_KEY_ARP_OP],
			    tb[TCA_FLOWER_KEY_ARP_OP_MASK]);
	flower_print_eth_addr(f, "arp_sha", tb[TCA_FLOWER_KEY_ARP_SHA],
			      tb[TCA_FLOWER_KEY_ARP_SHA_MASK]);
	flower_print_eth_addr(f, "arp_tha", tb[TCA_FLOWER_KEY_ARP_THA],
			      tb[TCA_FLOWER_KEY_ARP_THA_MASK]);

	flower_print_ip_addr(f, "enc_dst_ip",
			     tb[TCA_FLOWER_KEY_ENC_IPV4_DST_MASK] ?
			     htons(ETH_P_IP) : htons(ETH_P_IPV6),
			     tb[TCA_FLOWER_KEY_ENC_IPV4_DST],
			     tb[TCA_FLOWER_KEY_ENC_IPV4_DST_MASK],
			     tb[TCA_FLOWER_KEY_ENC_IPV6_DST],
			     tb[TCA_FLOWER_KEY_ENC_IPV6_DST_MASK]);

	flower_print_ip_addr(f, "enc_src_ip",
			     tb[TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK] ?
			     htons(ETH_P_IP) : htons(ETH_P_IPV6),
			     tb[TCA_FLOWER_KEY_ENC_IPV4_SRC],
			     tb[TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK],
			     tb[TCA_FLOWER_KEY_ENC_IPV6_SRC],
			     tb[TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK]);

	flower_print_key_id(f, "enc_key_id",
			    tb[TCA_FLOWER_KEY_ENC_KEY_ID]);

	flower_print_port(f, "enc_dst_port",
			  tb[TCA_FLOWER_KEY_ENC_UDP_DST_PORT]);

	flower_print_matching_flags(f, "ip_flags",
				    FLOWER_IP_FLAGS,
				    tb[TCA_FLOWER_KEY_FLAGS],
				    tb[TCA_FLOWER_KEY_FLAGS_MASK]);

	if (tb[TCA_FLOWER_FLAGS]) {
		__u32 flags = rta_getattr_u32(tb[TCA_FLOWER_FLAGS]);

		if (flags & TCA_CLS_FLAGS_SKIP_HW)
			fprintf(f, "\n  skip_hw");
		if (flags & TCA_CLS_FLAGS_SKIP_SW)
			fprintf(f, "\n  skip_sw");

		if (flags & TCA_CLS_FLAGS_IN_HW)
			fprintf(f, "\n  in_hw");
		else if (flags & TCA_CLS_FLAGS_NOT_IN_HW)
			fprintf(f, "\n  not_in_hw");
	}

	if (tb[TCA_FLOWER_ACT])
		tc_print_action(f, tb[TCA_FLOWER_ACT], 0);

	return 0;
}

struct filter_util flower_filter_util = {
	.id = "flower",
	.parse_fopt = flower_parse_opt,
	.print_fopt = flower_print_opt,
};
