/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __XEN_CONFIG_H__
#define __XEN_CONFIG_H__

#include <asm/config.h>

/* syslog levels ==> nothing! */
#define KERN_NOTICE  ""
#define KERN_WARNING ""
#define KERN_DEBUG   ""
#define KERN_INFO    ""
#define KERN_ERR     ""
#define KERN_CRIT    ""
#define KERN_EMERG   ""
#define KERN_ALERT   ""

#define offsetof(_p,_f) ((unsigned long)&(((_p *)0)->_f))
#define struct_cpy(_x,_y) (memcpy((_x),(_y),sizeof(*(_x))))

#define dev_probe_lock() ((void)0)
#define dev_probe_unlock() ((void)0)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define capable(_c) 0

#ifndef NDEBUG
#define DPRINTK(_f, _a...) printk("(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

#ifndef __ASSEMBLY__
#include <xen/compiler.h>
extern unsigned int opt_ser_baud;
#define SERIAL_ENABLED (opt_ser_baud != 0)
#endif

#endif /* __XEN_CONFIG_H__ */
