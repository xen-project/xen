#ifndef _I386_BUG_H
#define _I386_BUG_H

#include <linux/config.h>

#define BUG() do { \
	printk("kernel BUG at %s:%d (%s)!\n", \
	       __FILE__, __LINE__, __FUNCTION__); \
	dump_stack(); \
	panic("BUG!"); \
} while (0)
#define HAVE_ARCH_BUG

#include <asm-generic/bug.h>

#endif
