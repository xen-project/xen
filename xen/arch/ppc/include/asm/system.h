/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) IBM Corp. 2005
 * Copyright (C) Raptor Engineering LLC
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Shawn Anastasio <sanastasio@raptorengineering.com>
 */

#ifndef _ASM_SYSTEM_H_
#define _ASM_SYSTEM_H_

#include <xen/lib.h>
#include <asm/memory.h>
#include <asm/time.h>
#include <asm/processor.h>
#include <asm/msr.h>

#define xchg(ptr,x)                                                            \
({                                                                             \
    __typeof__(*(ptr)) _x_ = (x);                                              \
    (__typeof__(*(ptr))) __xchg((ptr), (unsigned long)_x_, sizeof(*(ptr)));    \
})

#define build_xchg(fn, type, ldinsn, stinsn) \
static inline unsigned long fn(volatile type *m, unsigned long val)            \
{                                                                              \
    unsigned long dummy;                                                       \
    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER                                    \
                   "1: " ldinsn " %0,0,%3\n"                                   \
                   stinsn " %2,0,%3\n"                                         \
                   "2:  bne- 1b\n"                                             \
                   PPC_ATOMIC_EXIT_BARRIER                                     \
                   : "=&r" (dummy), "=m" (*m)                                  \
                   : "r" (val), "r" (m)                                        \
                   : "cc", "memory" );                                         \
    return dummy;                                                              \
}

build_xchg(__xchg_u8, uint8_t, "lbarx", "stbcx.")
build_xchg(__xchg_u16, uint16_t, "lharx", "sthcx.")
build_xchg(__xchg_u32, uint32_t, "lwarx", "stwcx.")
build_xchg(__xchg_u64, uint64_t, "ldarx", "stdcx.")

#undef build_xchg

/*
 * This function doesn't exist, so you'll get a linker error
 * if something tries to do an invalid xchg().
 */
extern void __xchg_called_with_bad_pointer(void);

static inline unsigned long __xchg(volatile void *ptr, unsigned long x,
                                   int size)
{
    switch ( size )
    {
    case 1:
        return __xchg_u8(ptr, x);
    case 2:
        return __xchg_u16(ptr, x);
    case 4:
        return __xchg_u32(ptr, x);
    case 8:
        return __xchg_u64(ptr, x);
    }
    __xchg_called_with_bad_pointer();
    return x;
}


static inline unsigned long __cmpxchg_u32(volatile int *p, int old, int new)
{
    unsigned int prev;

    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER
                   "1: lwarx   %0,0,%2\n"
                   "cmpw    0,%0,%3\n"
                   "bne-    2f\n "
                   "stwcx.  %4,0,%2\n"
                   "bne-    1b\n"
                   PPC_ATOMIC_EXIT_BARRIER "\n"
                   "2:"
                   : "=&r" (prev), "=m" (*p)
                   : "r" (p), "r" (old), "r" (new), "m" (*p)
                   : "cc", "memory" );

    return prev;
}

static inline unsigned long __cmpxchg_u64(volatile long *p, unsigned long old,
                                          unsigned long new)
{
    unsigned long prev;

    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER
                   "1: ldarx   %0,0,%2\n"
                   "cmpd    0,%0,%3\n"
                   "bne-    2f\n"
                   "stdcx.  %4,0,%2\n"
                   "bne-    1b\n"
                   PPC_ATOMIC_EXIT_BARRIER "\n"
                   "2:"
                   : "=&r" (prev), "=m" (*p)
                   : "r" (p), "r" (old), "r" (new), "m" (*p)
                   : "cc", "memory" );

    return prev;
}

/* This function doesn't exist, so you'll get a linker error
   if something tries to do an invalid cmpxchg().  */
extern void __cmpxchg_called_with_bad_pointer(void);

static always_inline unsigned long __cmpxchg(
    volatile void *ptr,
    unsigned long old,
    unsigned long new,
    int size)
{
    switch ( size )
    {
    case 2:
        BUG_ON("unimplemented"); return 0; /* XXX implement __cmpxchg_u16 ? */
    case 4:
        return __cmpxchg_u32(ptr, old, new);
    case 8:
        return __cmpxchg_u64(ptr, old, new);
    }
    __cmpxchg_called_with_bad_pointer();
    return old;
}

#define cmpxchg_user(ptr,o,n) cmpxchg(ptr,o,n)

#define cmpxchg(ptr,o,n)                                                       \
  ({                                                                           \
     __typeof__(*(ptr)) _o_ = (o);                                             \
     __typeof__(*(ptr)) _n_ = (n);                                             \
     (__typeof__(*(ptr)))__cmpxchg((ptr), (unsigned long)_o_,                  \
                                   (unsigned long)_n_, sizeof(*(ptr)));        \
  })


/*
 * Memory barrier.
 * The sync instruction guarantees that all memory accesses initiated
 * by this processor have been performed (with respect to all other
 * mechanisms that access memory).  The eieio instruction is a barrier
 * providing an ordering (separately) for (a) cacheable stores and (b)
 * loads and stores to non-cacheable memory (e.g. I/O devices).
 *
 * mb() prevents loads and stores being reordered across this point.
 * rmb() prevents loads being reordered across this point.
 * wmb() prevents stores being reordered across this point.
 * read_barrier_depends() prevents data-dependent loads being reordered
 *  across this point (nop on PPC).
 *
 * We have to use the sync instructions for mb(), since lwsync doesn't
 * order loads with respect to previous stores.  Lwsync is fine for
 * rmb(), though.
 * For wmb(), we use sync since wmb is used in drivers to order
 * stores to system memory with respect to writes to the device.
 * However, smp_wmb() can be a lighter-weight eieio barrier on
 * SMP since it is only used to order updates to system memory.
 */
#define mb()   __asm__ __volatile__ ( "sync" : : : "memory" )
#define rmb()  __asm__ __volatile__ ( "lwsync" : : : "memory" )
#define wmb()  __asm__ __volatile__ ( "sync" : : : "memory" )
#define read_barrier_depends()  do { } while(0)

#define set_mb(var, value)  do { var = value; smp_mb(); } while (0)
#define set_wmb(var, value) do { var = value; smp_wmb(); } while (0)

#define smp_mb__before_atomic()    smp_mb()
#define smp_mb__after_atomic()     smp_mb()

#define smp_mb()    mb()
#define smp_rmb()   rmb()
#define smp_wmb()   __asm__ __volatile__ ("lwsync" : : : "memory")
#define smp_read_barrier_depends()  read_barrier_depends()

#define local_save_flags(flags) ((flags) = mfmsr())
#define local_irq_restore(flags) do { \
        __asm__ __volatile__("": : :"memory"); \
        mtmsrd((flags)); \
} while(0)

static inline void local_irq_disable(void)
{
    unsigned long msr;
    msr = mfmsr();
    mtmsrd(msr & ~MSR_EE);
    barrier();
}

static inline void local_irq_enable(void)
{
    unsigned long msr;
    barrier();
    msr = mfmsr();
    mtmsrd(msr | MSR_EE);
}

static inline void __do_save_and_cli(unsigned long *flags)
{
    unsigned long msr;
    msr = mfmsr();
    *flags = msr;
    mtmsrd(msr & ~MSR_EE);
    barrier();
}

#define local_irq_save(flags) __do_save_and_cli(&flags)

static inline int local_irq_is_enabled(void)
{
    return !!(mfmsr() & MSR_EE);
}

#define arch_fetch_and_add(x, v) __sync_fetch_and_add(x, v)

#endif /* _ASM_SYSTEM_H */
