/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __XEN_CONFIG_H__
#define __XEN_CONFIG_H__

#include <xen/kconfig.h>

#ifndef __ASSEMBLY__
#include <xen/compiler.h>
#endif
#include <asm/config.h>

#define EXPORT_SYMBOL(var)

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

#define KB(_kb)     (_AC(_kb, ULL) << 10)
#define MB(_mb)     (_AC(_mb, ULL) << 20)
#define GB(_gb)     (_AC(_gb, ULL) << 30)

#define IS_ALIGNED(val, align) (((val) & ((align) - 1)) == 0)

#define __STR(...) #__VA_ARGS__
#define STR(...) __STR(__VA_ARGS__)

/* allow existing code to work with Kconfig variable */
#define NR_CPUS CONFIG_NR_CPUS

#ifndef CONFIG_DEBUG
#define NDEBUG
#endif

#ifndef ZERO_BLOCK_PTR
/* Return value for zero-size allocation, distinguished from NULL. */
#define ZERO_BLOCK_PTR ((void *)-1L)
#endif

#endif /* __XEN_CONFIG_H__ */
