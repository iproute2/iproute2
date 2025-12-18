/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SHA-1 message digest algorithm
 *
 * Copyright 2025 Google LLC
 */
#ifndef __SHA1_H__
#define __SHA1_H__

#include <linux/types.h>
#include <stddef.h>

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE 64

void sha1(const __u8 *data, size_t len, __u8 out[SHA1_DIGEST_SIZE]);

#endif /* __SHA1_H__ */
