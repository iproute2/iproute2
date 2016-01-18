#ifndef __BPF_API__
#define __BPF_API__

/* Note:
 *
 * This file can be included into eBPF kernel programs. It contains
 * a couple of useful helper functions, map/section ABI (bpf_elf.h),
 * misc macros and some eBPF specific LLVM built-ins.
 */

#include <stdint.h>

#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include <asm/byteorder.h>

#include "bpf_elf.h"

/** Misc macros. */

#ifndef __stringify
# define __stringify(X)		#X
#endif

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef offsetof
# define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)
#endif

#ifndef likely
# define likely(X)		__builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
# define unlikely(X)		__builtin_expect(!!(X), 0)
#endif

#ifndef htons
# define htons(X)		__constant_htons((X))
#endif

#ifndef ntohs
# define ntohs(X)		__constant_ntohs((X))
#endif

#ifndef htonl
# define htonl(X)		__constant_htonl((X))
#endif

#ifndef ntohl
# define ntohl(X)		__constant_ntohl((X))
#endif

/** Section helper macros. */

#ifndef __section
# define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)					\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __section_cls_entry
# define __section_cls_entry						\
	__section(ELF_SECTION_CLASSIFIER)
#endif

#ifndef __section_act_entry
# define __section_act_entry						\
	__section(ELF_SECTION_ACTION)
#endif

#ifndef __section_license
# define __section_license						\
	__section(ELF_SECTION_LICENSE)
#endif

#ifndef __section_maps
# define __section_maps							\
	__section(ELF_SECTION_MAPS)
#endif

/** Declaration helper macros. */

#ifndef BPF_LICENSE
# define BPF_LICENSE(NAME)						\
	char ____license[] __section_license = NAME
#endif

#ifndef __BPF_MAP
# define __BPF_MAP(NAME, TYPE, ID, SIZE_KEY, SIZE_VALUE, PIN, MAX_ELEM)	\
	struct bpf_elf_map __section_maps NAME = {			\
		.type		= (TYPE),				\
		.id		= (ID),					\
		.size_key	= (SIZE_KEY),				\
		.size_value	= (SIZE_VALUE),				\
		.pinning	= (PIN),				\
		.max_elem	= (MAX_ELEM),				\
	}
#endif

#ifndef BPF_HASH
# define BPF_HASH(NAME, ID, SIZE_KEY, SIZE_VALUE, PIN, MAX_ELEM)	\
	__BPF_MAP(NAME, BPF_MAP_TYPE_HASH, ID, SIZE_KEY, SIZE_VALUE,	\
		  PIN, MAX_ELEM)
#endif

#ifndef BPF_ARRAY
# define BPF_ARRAY(NAME, ID, SIZE_VALUE, PIN, MAX_ELEM)			\
	__BPF_MAP(NAME, BPF_MAP_TYPE_ARRAY, ID, sizeof(uint32_t), 	\
		  SIZE_VALUE, PIN, MAX_ELEM)
#endif

#ifndef BPF_ARRAY2
# define BPF_ARRAY2(NAME, ID, PIN, MAX_ELEM)				\
	BPF_ARRAY(NAME, ID, sizeof(uint16_t), PIN, MAX_ELEM)
#endif

#ifndef BPF_ARRAY4
# define BPF_ARRAY4(NAME, ID, PIN, MAX_ELEM)				\
	BPF_ARRAY(NAME, ID, sizeof(uint32_t), PIN, MAX_ELEM)
#endif

#ifndef BPF_ARRAY8
# define BPF_ARRAY8(NAME, ID, PIN, MAX_ELEM)				\
	BPF_ARRAY(NAME, ID, sizeof(uint64_t), PIN, MAX_ELEM)
#endif

#ifndef BPF_PROG_ARRAY
# define BPF_PROG_ARRAY(NAME, ID, PIN, MAX_ELEM)			\
	__BPF_MAP(NAME, BPF_MAP_TYPE_PROG_ARRAY, ID, sizeof(uint32_t),	\
		  sizeof(uint32_t), PIN, MAX_ELEM)
#endif

/** Classifier helper */

#ifndef BPF_H_DEFAULT
# define BPF_H_DEFAULT	-1
#endif

/** BPF helper functions for tc. */

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) __maybe_unused = (void *) BPF_FUNC_##NAME
#endif

/* Map access/manipulation */
static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
static int BPF_FUNC(map_update_elem, void *map, const void *key,
		    const void *value, uint32_t flags);
static int BPF_FUNC(map_delete_elem, void *map, const void *key);

/* Time access */
static uint64_t BPF_FUNC(ktime_get_ns);

/* Debugging */
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

/* Random numbers */
static uint32_t BPF_FUNC(get_prandom_u32);

/* Tail calls */
static void BPF_FUNC(tail_call, struct __sk_buff *skb, void *map,
		     uint32_t index);

/* System helpers */
static uint32_t BPF_FUNC(get_smp_processor_id);

/* Packet misc meta data */
static uint32_t BPF_FUNC(get_cgroup_classid, struct __sk_buff *skb);
static uint32_t BPF_FUNC(get_route_realm, struct __sk_buff *skb);

/* Packet redirection */
static int BPF_FUNC(redirect, int ifindex, uint32_t flags);
static int BPF_FUNC(clone_redirect, struct __sk_buff *skb, int ifindex,
		    uint32_t flags);

/* Packet manipulation */
#define BPF_PSEUDO_HDR			0x10
#define BPF_HAS_PSEUDO_HDR(flags)	((flags) & BPF_PSEUDO_HDR)
#define BPF_HDR_FIELD_SIZE(flags)	((flags) & 0x0f)

static int BPF_FUNC(skb_store_bytes, struct __sk_buff *skb, uint32_t off,
		    void *from, uint32_t len, uint32_t flags);
static int BPF_FUNC(l3_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);
static int BPF_FUNC(l4_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);

/* Packet vlan encap/decap */
static int BPF_FUNC(skb_vlan_push, struct __sk_buff *skb, uint16_t proto,
		    uint16_t vlan_tci);
static int BPF_FUNC(skb_vlan_pop, struct __sk_buff *skb);

/* Packet tunnel encap/decap */
static int BPF_FUNC(skb_get_tunnel_key, struct __sk_buff *skb,
		    struct bpf_tunnel_key *to, uint32_t size, uint32_t flags);
static int BPF_FUNC(skb_set_tunnel_key, struct __sk_buff *skb,
		    struct bpf_tunnel_key *from, uint32_t size, uint32_t flags);

/** LLVM built-ins */

#ifndef lock_xadd
# define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

unsigned long long load_byte(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.byte");

unsigned long long load_half(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.half");

unsigned long long load_word(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.word");

#endif /* __BPF_API__ */
