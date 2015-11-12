#include <linux/bpf.h>

#include "bpf_funcs.h"

/* Minimal, stand-alone toy map pinning example:
 *
 * clang -target bpf -O2 [...] -o bpf_shared.o -c bpf_shared.c
 * tc filter add dev foo parent 1: bpf obj bpf_shared.o sec egress
 * tc filter add dev foo parent ffff: bpf obj bpf_shared.o sec ingress
 *
 * Both classifier will share the very same map instance in this example,
 * so map content can be accessed from ingress *and* egress side!
 *
 * This example has a pinning of PIN_OBJECT_NS, so it's private and
 * thus shared among various program sections within the object.
 *
 * A setting of PIN_GLOBAL_NS would place it into a global namespace,
 * so that it can be shared among different object files. A setting
 * of PIN_NONE (= 0) means no sharing, so each tc invocation a new map
 * instance is being created.
 */

struct bpf_elf_map __section("maps") map_sh = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_OBJECT_NS, /* or PIN_GLOBAL_NS, or PIN_NONE */
	.max_elem	= 1,
};

__section("egress") int emain(struct __sk_buff *skb)
{
	int key = 0, *val;

	val = bpf_map_lookup_elem(&map_sh, &key);
	if (val)
		__sync_fetch_and_add(val, 1);

	return -1;
}

__section("ingress") int imain(struct __sk_buff *skb)
{
	char fmt[] = "map val: %d\n";
	int key = 0, *val;

	val = bpf_map_lookup_elem(&map_sh, &key);
	if (val)
		bpf_printk(fmt, sizeof(fmt), *val);

	return -1;
}

char __license[] __section("license") = "GPL";
