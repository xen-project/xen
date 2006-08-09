/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __XEN_CONFIG_H__
#define __XEN_CONFIG_H__

#include <asm/config.h>

#define EXPORT_SYMBOL(var)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Linux syslog levels. */
#define KERN_NOTICE  ""
#define KERN_WARNING ""
#define KERN_DEBUG   ""
#define KERN_INFO    ""
#define KERN_ERR     ""
#define KERN_CRIT    ""
#define KERN_EMERG   ""
#define KERN_ALERT   ""

/* Linux 'checker' project. */
#define __iomem
#define __user

#ifdef VERBOSE
#define DPRINTK(_f, _a...) printk("(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

#ifndef __ASSEMBLY__
#include <xen/compiler.h>
#endif

#define __STR(...) #__VA_ARGS__
#define STR(...) __STR(__VA_ARGS__)

#ifndef __ASSEMBLY__
/* Turn a plain number into a C unsigned long constant. */
#define __mk_unsigned_long(x) x ## UL
#define mk_unsigned_long(x) __mk_unsigned_long(x)
#else /* __ASSEMBLY__ */
/* In assembly code we cannot use C numeric constant suffixes. */
#define mk_unsigned_long(x) x
#endif /* !__ASSEMBLY__ */

#define fastcall

#endif /* __XEN_CONFIG_H__ */
