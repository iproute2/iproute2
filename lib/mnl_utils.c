// SPDX-License-Identifier: GPL-2.0+
/*
 * mnl_utils.c	Helpers for working with libmnl.
 */

#include <string.h>
#include <time.h>
#include <libmnl/libmnl.h>

#include "mnl_utils.h"

struct mnl_socket *mnlu_socket_open(int bus)
{
	struct mnl_socket *nl;
	int one = 1;

	nl = mnl_socket_open(bus);
	if (nl == NULL)
		return NULL;

	mnl_socket_setsockopt(nl, NETLINK_CAP_ACK, &one, sizeof(one));
	mnl_socket_setsockopt(nl, NETLINK_EXT_ACK, &one, sizeof(one));

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		goto err_bind;

	return nl;

err_bind:
	mnl_socket_close(nl);
	return NULL;
}

struct nlmsghdr *mnlu_msg_prepare(void *buf, uint32_t nlmsg_type, uint16_t flags,
				  void *extra_header, size_t extra_header_size)
{
	struct nlmsghdr *nlh;
	void *eh;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = time(NULL);

	eh = mnl_nlmsg_put_extra_header(nlh, extra_header_size);
	memcpy(eh, extra_header, extra_header_size);

	return nlh;
}
