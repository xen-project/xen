/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __XEN_CONFIG_H__
#define __XEN_CONFIG_H__

#ifndef __ASSEMBLY__
#include <xen/compiler.h>
#endif
#include <asm/config.h>

#define EXPORT_SYMBOL(var)
#define EXPORT_SYMBOL_GPL(var)

/*
 * The following log levels are as follows:
 *
 *   XENLOG_ERR: Fatal errors, either Xen, Guest or Dom0
 *               is about to crash.
 *
 *   XENLOG_WARNING: Something bad happened, but we can recover.
 *
 *   XENLOG_INFO: Interesting stuff, but not too noisy.
 *
 *   XENLOG_DEBUG: Use where ever you like. Lots of noise.
 *
 *
 * Since we don't trust the guest operating system, we don't want
 * it to allow for DoS by causing the HV to print out a lot of
 * info, so where ever the guest has control of what is printed
 * we use the XENLOG_GUEST to distinguish that the output is
 * controlled by the guest.
 *
 * To make it easier on the typing, the above log levels all
 * have a corresponding _G_ equivalent that appends the
 * XENLOG_GUEST. (see the defines below).
 *
 */
#define XENLOG_ERR     "<0>"
#define XENLOG_WARNING "<1>"
#define XENLOG_INFO    "<2>"
#define XENLOG_DEBUG   "<3>"

#define XENLOG_GUEST   "<G>"

#define XENLOG_G_ERR     XENLOG_GUEST XENLOG_ERR
#define XENLOG_G_WARNING XENLOG_GUEST XENLOG_WARNING
#define XENLOG_G_INFO    XENLOG_GUEST XENLOG_INFO
#define XENLOG_G_DEBUG   XENLOG_GUEST XENLOG_DEBUG

/*
 * Some code is copied directly from Linux.
 * Match some of the Linux log levels to Xen.
 */
#define KERN_ERR       XENLOG_ERR
#define KERN_CRIT      XENLOG_ERR
#define KERN_EMERG     XENLOG_ERR
#define KERN_WARNING   XENLOG_WARNING
#define KERN_NOTICE    XENLOG_INFO
#define KERN_INFO      XENLOG_INFO
#define KERN_DEBUG     XENLOG_DEBUG

/* Linux 'checker' project. */
#define __iomem
#define __user
#define __force
#define __bitwise

#define MB(_mb)     (_AC(_mb, UL) << 20)
#define GB(_gb)     (_AC(_gb, UL) << 30)

#ifndef __ASSEMBLY__

#define dprintk(_l, _f, _a...)                              \
    printk(_l "%s:%d: " _f, __FILE__ , __LINE__ , ## _a )
#define gdprintk(_l, _f, _a...)                             \
    printk(XENLOG_GUEST _l "%s:%d:%pv " _f, __FILE__,       \
           __LINE__, current, ## _a )

#endif /* !__ASSEMBLY__ */

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
#define __cpuinitdata
#define __cpuinit

#ifdef FLASK_ENABLE
#define XSM_MAGIC 0xf97cff8c
/* Enable permissive mode (xl setenforce or flask_enforcing parameter) */
#define FLASK_DEVELOP 1
/* Allow runtime disabling of FLASK via the flask_enable parameter */
#define FLASK_BOOTPARAM 1
/* Maintain statistics on the access vector cache */
#define FLASK_AVC_STATS 1
#endif

#endif /* __XEN_CONFIG_H__ */
