/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __XEN_CONFIG_H__
#define __XEN_CONFIG_H__

#include <asm/config.h>

#define EXPORT_SYMBOL(var)
#define offsetof(_p,_f) ((unsigned long)&(((_p *)0)->_f))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define always_inline __inline__ __attribute__ ((always_inline))

/* syslog levels ==> nothing! */
#define KERN_NOTICE  ""
#define KERN_WARNING ""
#define KERN_DEBUG   ""
#define KERN_INFO    ""
#define KERN_ERR     ""
#define KERN_CRIT    ""
#define KERN_EMERG   ""
#define KERN_ALERT   ""

#ifdef VERBOSE
#define DPRINTK(_f, _a...) printk("(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

#ifndef __ASSEMBLY__
#include <xen/compiler.h>
#endif

#endif /* __XEN_CONFIG_H__ */
