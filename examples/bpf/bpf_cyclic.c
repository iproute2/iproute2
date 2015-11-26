#include <linux/bpf.h>

#include "bpf_funcs.h"

/* Cyclic dependency example to test the kernel's runtime upper
 * bound on loops.
 */
struct bpf_elf_map __section("maps") jmp_tc = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= 0xabccba,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_OBJECT_NS,
	.max_elem	= 1,
};

__section_tail(0xabccba, 0) int cls_loop(struct __sk_buff *skb)
{
	char fmt[] = "cb: %u\n";

	bpf_printk(fmt, sizeof(fmt), skb->cb[0]++);
	bpf_tail_call(skb, &jmp_tc, 0);
	return -1;
}

__section("classifier") int cls_entry(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &jmp_tc, 0);
	return -1;
}

char __license[] __section("license") = "GPL";
