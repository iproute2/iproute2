// SPDX-License-Identifier: GPL-2.0+
/*
 * mnl_utils.c	Helpers for working with libmnl.
 */

#include <errno.h>
#include <string.h>
#include <time.h>
#include <libmnl/libmnl.h>

#include "libnetlink.h"
#include "mnl_utils.h"
#include "utils.h"

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

static int mnlu_cb_noop(const struct nlmsghdr *nlh, void *data)
{
	return MNL_CB_OK;
}

static int mnlu_cb_error(const struct nlmsghdr *nlh, void *data)
{
	const struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);

	/* Netlink subsystems returns the errno value with different signess */
	if (err->error < 0)
		errno = -err->error;
	else
		errno = err->error;

	if (nl_dump_ext_ack(nlh, NULL))
		return MNL_CB_ERROR;

	return err->error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
}

static int mnlu_cb_stop(const struct nlmsghdr *nlh, void *data)
{
	int len = *(int *)NLMSG_DATA(nlh);

	if (len < 0) {
		errno = -len;
		nl_dump_ext_ack_done(nlh, len);
		return MNL_CB_ERROR;
	}
	return MNL_CB_STOP;
}

static mnl_cb_t mnlu_cb_array[NLMSG_MIN_TYPE] = {
	[NLMSG_NOOP]	= mnlu_cb_noop,
	[NLMSG_ERROR]	= mnlu_cb_error,
	[NLMSG_DONE]	= mnlu_cb_stop,
	[NLMSG_OVERRUN]	= mnlu_cb_noop,
};

int mnlu_socket_recv_run(struct mnl_socket *nl, unsigned int seq, void *buf, size_t buf_size,
			 mnl_cb_t cb, void *data)
{
	unsigned int portid = mnl_socket_get_portid(nl);
	int err;

	do {
		err = mnl_socket_recvfrom(nl, buf, buf_size);
		if (err <= 0)
			break;
		err = mnl_cb_run2(buf, err, seq, portid,
				  cb, data, mnlu_cb_array,
				  ARRAY_SIZE(mnlu_cb_array));
	} while (err > 0);

	return err;
}
