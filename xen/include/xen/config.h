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
 * controled by the Guest.
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

#define XENLOG_MAX 3

/*
 * To control the amount of printing, thresholds are added.
 * These thresholds correspond to the above log levels.
 * There's an upper and lower threshold for non-guests
 * and Guest.  This works as follows:
 *
 * If printk log level > upper threshold
 *   don't print anything
 *
 * If printk log level >= lower threshold
 *   rate limit the print (keep the amount down)
 *
 * Otherwise, just print.
 *
 * Note, in the above algorithm, to never rate limit
 * simply make the lower threshold greater than the upper.
 * This way the output will never be rate limited.
 *
 * For example:
 *   lower = 2; upper = 1;
 *  This will always print ERR and WARNING messages
 *  but will not print anything else.  Nothing is
 *  rate limited.
 */
/*
 * Defaults:
 *   For the HV, always print ERR and WARNING
 *   but nothing for INFO and DEBUG.
 *
 *   For Guests, always rate limit ERR and WARNING
 *   but never print for INFO and DEBUG.
 */
#ifndef XENLOG_UPPER_THRESHOLD
#define XENLOG_UPPER_THRESHOLD 1
#endif
#ifndef XENLOG_LOWER_THRESHOLD
#define XENLOG_LOWER_THRESHOLD 2
#endif
#ifndef XENLOG_GUEST_UPPER_THRESHOLD
#define XENLOG_GUEST_UPPER_THRESHOLD 1
#endif
#ifndef XENLOG_GUEST_LOWER_THRESHOLD
#define XENLOG_GUEST_LOWER_THRESHOLD 0
#endif

/*
 * The XENLOG_DEFAULT is the default given to printks that
 * do not have any print level associated to it.
 */
#ifndef XENLOG_DEFAULT
#define XENLOG_DEFAULT 1 /* Warning */
#endif
#ifndef XENLOG_GUEST_DEFAULT
#define XENLOG_GUEST_DEFAULT 1 /* Warning */
#endif

/*
 * Some code is copied directly from Linux.
 * Match some of the Linux log levels to Xen.
 *  (Should these be Guest logs?? - SDR)
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

#define DPRINTK(_f, _a...) printk("(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )

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
#define __cpuinitdata
#define __cpuinit

#endif /* __XEN_CONFIG_H__ */
