/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * misc.h	Miscellaneous TIPC helper functions.
 *
 * Authors:	Richard Alpe <richard.alpe@ericsson.com>
 */

#ifndef _TIPC_MISC_H
#define _TIPC_MISC_H

#include <stdint.h>

uint32_t str2addr(char *str);
int str2nodeid(char *str, uint8_t *id);
void nodeid2str(uint8_t *id, char *str);
void hash2nodestr(uint32_t hash, char *str);
int str2key(char *str, struct tipc_aead_key *key);

#endif
