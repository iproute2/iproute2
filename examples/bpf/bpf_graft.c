#include "../../include/bpf_api.h"

/* This example demonstrates how classifier run-time behaviour
 * can be altered with tail calls. We start out with an empty
 * jmp_tc array, then add section aaa to the array slot 0, and
 * later on atomically replace it with section bbb. Note that
 * as shown in other examples, the tc loader can prepopulate
 * tail called sections, here we start out with an empty one
 * on purpose to show it can also be done this way.
 *
 * tc filter add dev foo parent ffff: bpf obj graft.o
 * tc exec bpf dbg
 *   [...]
 *   Socket Thread-20229 [001] ..s. 138993.003923: : fallthrough
 *   <idle>-0            [001] ..s. 138993.202265: : fallthrough
 *   Socket Thread-20229 [001] ..s. 138994.004149: : fallthrough
 *   [...]
 *
 * tc exec bpf graft m:globals/jmp_tc key 0 obj graft.o sec aaa
 * tc exec bpf dbg
 *   [...]
 *   Socket Thread-19818 [002] ..s. 139012.053587: : aaa
 *   <idle>-0            [002] ..s. 139012.172359: : aaa
 *   Socket Thread-19818 [001] ..s. 139012.173556: : aaa
 *   [...]
 *
 * tc exec bpf graft m:globals/jmp_tc key 0 obj graft.o sec bbb
 * tc exec bpf dbg
 *   [...]
 *   Socket Thread-19818 [002] ..s. 139022.102967: : bbb
 *   <idle>-0            [002] ..s. 139022.155640: : bbb
 *   Socket Thread-19818 [001] ..s. 139022.156730: : bbb
 *   [...]
 */

BPF_PROG_ARRAY(jmp_tc, 0, PIN_GLOBAL_NS, 1);

__section("aaa")
int cls_aaa(struct __sk_buff *skb)
{
	char fmt[] = "aaa\n";

	trace_printk(fmt, sizeof(fmt));
	return TC_H_MAKE(1, 42);
}

__section("bbb")
int cls_bbb(struct __sk_buff *skb)
{
	char fmt[] = "bbb\n";

	trace_printk(fmt, sizeof(fmt));
	return TC_H_MAKE(1, 43);
}

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	char fmt[] = "fallthrough\n";

	tail_call(skb, &jmp_tc, 0);
	trace_printk(fmt, sizeof(fmt));

	return BPF_H_DEFAULT;
}

BPF_LICENSE("GPL");
