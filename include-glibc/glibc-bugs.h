#ifndef __GLIBC_BUGS_H__
#define __GLIBC_BUGS_H__ 1

#include <features.h>
#include <sys/types.h>

#if defined(__GLIBC__) && __GLIBC__ >= 2

#ifndef __KERNEL_STRICT_NAMES
#define __KERNEL_STRICT_NAMES 1
#endif

#include <linux/types.h>

typedef __u16 in_port_t;
typedef __u32 in_addr_t;

#endif

#endif
