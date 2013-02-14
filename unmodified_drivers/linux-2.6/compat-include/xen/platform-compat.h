#ifndef COMPAT_INCLUDE_XEN_PLATFORM_COMPAT_H
#define COMPAT_INCLUDE_XEN_PLATFORM_COMPAT_H

#include <linux/version.h>
#include <linux/spinlock.h>
#include <asm/maddr.h>

#if defined(__LINUX_COMPILER_H) && !defined(__always_inline)
#define __always_inline inline
#endif

#if defined(__LINUX_SPINLOCK_H) && !defined(DEFINE_SPINLOCK)
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#ifdef _LINUX_INIT_H

#ifndef __init
#define __init
#endif

#ifndef __devinit
#define __devinit
#define __devinitdata
#endif

#endif /* _LINUX_INIT_H */

#if defined(__LINUX_CACHE_H) && !defined(__read_mostly)
#define __read_mostly
#endif

#if defined(_LINUX_SKBUFF_H) && !defined(NET_IP_ALIGN)
#define NET_IP_ALIGN 0
#endif

#if defined(_LINUX_SKBUFF_H) && !defined(CHECKSUM_HW)
#define CHECKSUM_HW CHECKSUM_PARTIAL
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
#if defined(__LINUX_TYPES_H) || defined(__LINUX_GFP_H) || defined(_LINUX_KERNEL_H)
#define gfp_t unsigned
#endif

#if defined(_LINUX_NOTIFIER_H) && !defined(ATOMIC_NOTIFIER_HEAD)
#define ATOMIC_NOTIFIER_HEAD(name) struct notifier_block *name
#define atomic_notifier_chain_register(chain,nb) notifier_chain_register(chain,nb)
#define atomic_notifier_chain_unregister(chain,nb) notifier_chain_unregister(chain,nb)
#define atomic_notifier_call_chain(chain,val,v) notifier_call_chain(chain,val,v)
#endif

#if defined(_LINUX_NOTIFIER_H) && !defined(BLOCKING_NOTIFIER_HEAD)
#define BLOCKING_NOTIFIER_HEAD(name) struct notifier_block *name
#define blocking_notifier_chain_register(chain,nb) notifier_chain_register(chain,nb)
#define blocking_notifier_chain_unregister(chain,nb) notifier_chain_unregister(chain,nb)
#define blocking_notifier_call_chain(chain,val,v) notifier_call_chain(chain,val,v)
#endif

#if defined(_LINUX_MM_H) && defined set_page_count
#define init_page_count(page) set_page_count(page, 1)
#endif

#if defined(__LINUX_GFP_H) && !defined __GFP_NOMEMALLOC
#define __GFP_NOMEMALLOC 0
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

#if defined(_LINUX_CAPABILITY_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#define capable(cap) (1)
#endif

#if defined(_LINUX_KERNEL_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
extern char *kasprintf(gfp_t gfp, const char *fmt, ...)
       __attribute__ ((format (printf, 2, 3)));
#endif

#if defined(_LINUX_SYSRQ_H) && LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#define handle_sysrq(x,y,z) handle_sysrq(x,y)
#endif

#if defined(_PAGE_PRESENT) && !defined(_PAGE_NX)
#define _PAGE_NX 0
/*
 * This variable at present is referenced by netfront, but only in code that
 * is dead when running in hvm guests. To detect potential active uses of it
 * in the future, don't try to supply a 'valid' value here, so that any
 * mappings created with it will fault when accessed.
 */
#define __supported_pte_mask ((maddr_t)0)
#endif

/* This code duplication is not ideal, but || does not seem to properly 
 *  short circuit in a #if condition.
 **/
#if defined(_LINUX_NETDEVICE_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#if !defined(SLE_VERSION) 
#define netif_tx_lock_bh(dev) spin_lock_bh(&(dev)->xmit_lock)
#define netif_tx_unlock_bh(dev) spin_unlock_bh(&(dev)->xmit_lock)
#elif SLE_VERSION_CODE < SLE_VERSION(10,1,0)
#define netif_tx_lock_bh(dev) spin_lock_bh(&(dev)->xmit_lock)
#define netif_tx_unlock_bh(dev) spin_unlock_bh(&(dev)->xmit_lock)
#endif
#endif

#if defined(__LINUX_SEQLOCK_H) && !defined(DEFINE_SEQLOCK)
#define DEFINE_SEQLOCK(x) seqlock_t x = SEQLOCK_UNLOCKED
#endif

/* Bug in RHEL4-U3: rw_lock_t is mistakenly defined in DEFINE_RWLOCK() macro */
#if defined(__LINUX_SPINLOCK_H) && defined(DEFINE_RWLOCK)
#define rw_lock_t rwlock_t
#endif

#if defined(__LINUX_SPINLOCK_H) && !defined(DEFINE_RWLOCK)
#define DEFINE_RWLOCK(x) rwlock_t x = RW_LOCK_UNLOCKED
#endif

#if defined(_LINUX_INTERRUPT_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/**
 *   RHEL4-U5 pulled back this feature into the older kernel 
 *   Since it is a typedef, and not a macro - detect this kernel via
 *   RHEL_VERSION
 */
#if !defined(RHEL_VERSION) || (RHEL_VERSION == 4 && RHEL_UPDATE < 5)
#if !defined(RHEL_MAJOR) || (RHEL_MAJOR == 4 && RHEL_MINOR < 5)
typedef irqreturn_t (*irq_handler_t)(int, void *, struct pt_regs *);
#endif
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
#define setup_xen_features xen_setup_features
#endif

#ifndef atomic_cmpxchg
#define atomic_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), (old), (new)))
#endif

#ifdef sync_test_bit
#define synch_change_bit		sync_change_bit
#define synch_clear_bit			sync_clear_bit
#define synch_set_bit			sync_set_bit
#define synch_test_and_change_bit	sync_test_and_change_bit
#define synch_test_and_clear_bit	sync_test_and_clear_bit
#define synch_test_and_set_bit		sync_test_and_set_bit
#define synch_test_bit			sync_test_bit
#endif

#endif
