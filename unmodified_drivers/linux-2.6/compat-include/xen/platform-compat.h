#ifndef COMPAT_INCLUDE_XEN_PLATFORM_COMPAT_H
#define COMPAT_INCLUDE_XEN_PLATFORM_COMPAT_H

#include <linux/version.h>

#include <linux/spinlock.h>

#if defined(__LINUX_COMPILER_H) && !defined(__always_inline)
#define __always_inline inline
#endif

#if defined(__LINUX_SPINLOCK_H) && !defined(DEFINE_SPINLOCK)
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#if defined(_LINUX_INIT_H) && !defined(__init)
#define __init
#endif

#if defined(__LINUX_CACHE_H) && !defined(__read_mostly)
#define __read_mostly
#endif

#if defined(_LINUX_SKBUFF_H) && !defined(NET_IP_ALIGN)
#define NET_IP_ALIGN 0
#endif

#if defined(_LINUX_ERR_H) && !defined(IS_ERR_VALUE)
#define IS_ERR_VALUE(x) unlikely((x) > (unsigned long)-1000L)
#endif

#if defined(_ASM_IA64_PGTABLE_H) && !defined(_PGTABLE_NOPUD_H)
#include <asm-generic/pgtable-nopud.h>
#endif

/* Some kernels have this typedef backported so we cannot reliably
 * detect based on version number, hence we forcibly #define it.
 */
#if defined(__LINUX_TYPES_H) || defined(__LINUX_GFP_H)
#define gfp_t unsigned
#endif

#if defined(_LINUX_FS_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
#define nonseekable_open(inode, filp) /* Nothing to do */
#endif

#if defined(_LINUX_MM_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
unsigned long vmalloc_to_pfn(void *addr);
#endif

#if defined(__LINUX_COMPLETION_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
unsigned long wait_for_completion_timeout(struct completion *x, unsigned long timeout);
#endif

#if defined(_LINUX_SCHED_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
signed long schedule_timeout_interruptible(signed long timeout);
#endif

#if defined(_LINUX_SLAB_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
void *kzalloc(size_t size, int flags);
#endif

#if defined(_LINUX_BLKDEV_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#define end_that_request_last(req, uptodate) end_that_request_last(req)
#endif

#if defined(_LINUX_KERNEL_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
extern char *kasprintf(gfp_t gfp, const char *fmt, ...)
       __attribute__ ((format (printf, 2, 3)));
#endif

#endif
