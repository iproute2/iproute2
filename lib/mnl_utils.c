// SPDX-License-Identifier: GPL-2.0+
/*
 * mnl_utils.c	Helpers for working with libmnl.
 */

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
