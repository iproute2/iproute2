/* ila.h - ILA Interface */

#ifndef _LINUX_ILA_H
#define _LINUX_ILA_H

enum {
	ILA_ATTR_UNSPEC,
	ILA_ATTR_LOCATOR,			/* u64 */

	__ILA_ATTR_MAX,
};

#define ILA_ATTR_MAX		(__ILA_ATTR_MAX - 1)

#endif /* _LINUX_ILA_H */
