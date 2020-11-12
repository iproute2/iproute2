/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MNL_UTILS_H__
#define __MNL_UTILS_H__ 1

struct mnl_socket *mnlu_socket_open(int bus);
struct nlmsghdr *mnlu_msg_prepare(void *buf, uint32_t nlmsg_type, uint16_t flags,
				  void *extra_header, size_t extra_header_size);
int mnlu_socket_recv_run(struct mnl_socket *nl, unsigned int seq, void *buf, size_t buf_size,
			 mnl_cb_t cb, void *data);

#endif /* __MNL_UTILS_H__ */
