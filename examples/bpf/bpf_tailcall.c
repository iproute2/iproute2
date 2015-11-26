#include <linux/bpf.h>

#include "bpf_funcs.h"

#define ENTRY_INIT	3
#define ENTRY_0		0
#define ENTRY_1		1
#define MAX_JMP_SIZE	2

#define FOO		42
#define BAR		43

/* This example doesn't really do anything useful, but it's purpose is to
 * demonstrate eBPF tail calls on a very simple example.
 *
 * cls_entry() is our classifier entry point, from there we jump based on
 * skb->hash into cls_case1() or cls_case2(). They are both part of the
 * program array jmp_tc. Indicated via __section_tail(), the tc loader
 * populates the program arrays with the loaded file descriptors already.
 *
 * To demonstrate nested jumps, cls_case2() jumps within the same jmp_tc
 * array to cls_case1(). And whenever we arrive at cls_case1(), we jump
 * into cls_exit(), part of the jump array jmp_ex.
 *
 * Also, to show it's possible, all programs share map_sh and dump the value
 * that the entry point incremented. The sections that are loaded into a
 * program array can be atomically replaced during run-time, e.g. to change
 * classifier behaviour.
 */
struct bpf_elf_map __section("maps") map_sh = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_OBJECT_NS,
	.max_elem	= 1,
};

struct bpf_elf_map __section("maps") jmp_tc = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= FOO,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_OBJECT_NS,
	.max_elem	= MAX_JMP_SIZE,
};

struct bpf_elf_map __section("maps") jmp_ex = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= BAR,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_OBJECT_NS,
	.max_elem	= 1,
};

__section_tail(FOO, ENTRY_0) int cls_case1(struct __sk_buff *skb)
{
	char fmt[] = "case1: map-val: %d from:%u\n";
	int key = 0, *val;

	val = bpf_map_lookup_elem(&map_sh, &key);
	if (val)
		bpf_printk(fmt, sizeof(fmt), *val, skb->cb[0]);

	skb->cb[0] = ENTRY_0;
	bpf_tail_call(skb, &jmp_ex, ENTRY_0);
	return 0;
}

__section_tail(FOO, ENTRY_1) int cls_case2(struct __sk_buff *skb)
{
	char fmt[] = "case2: map-val: %d from:%u\n";
	int key = 0, *val;

	val = bpf_map_lookup_elem(&map_sh, &key);
	if (val)
		bpf_printk(fmt, sizeof(fmt), *val, skb->cb[0]);

	skb->cb[0] = ENTRY_1;
	bpf_tail_call(skb, &jmp_tc, ENTRY_0);
	return 0;
}

__section_tail(BAR, ENTRY_0) int cls_exit(struct __sk_buff *skb)
{
	char fmt[] = "exit: map-val: %d from:%u\n";
	int key = 0, *val;

	val = bpf_map_lookup_elem(&map_sh, &key);
	if (val)
		bpf_printk(fmt, sizeof(fmt), *val, skb->cb[0]);

	/* Termination point. */
	return -1;
}

__section("classifier") int cls_entry(struct __sk_buff *skb)
{
	char fmt[] = "fallthrough\n";
	int key = 0, *val;

	/* For transferring state, we can use skb->cb[0] ... skb->cb[4]. */
	val = bpf_map_lookup_elem(&map_sh, &key);
	if (val) {
		__sync_fetch_and_add(val, 1);

		skb->cb[0] = ENTRY_INIT;
		bpf_tail_call(skb, &jmp_tc, skb->hash & (MAX_JMP_SIZE - 1));
	}

	bpf_printk(fmt, sizeof(fmt));
	return 0;
}

char __license[] __section("license") = "GPL";
