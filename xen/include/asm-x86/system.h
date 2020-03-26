#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <xen/lib.h>
#include <xen/bitops.h>
#include <asm/processor.h>

#define read_sreg(name)                                         \
({  unsigned int __sel;                                         \
    asm volatile ( "mov %%" STR(name) ",%0" : "=r" (__sel) );   \
    __sel;                                                      \
})

static inline void wbinvd(void)
{
    asm volatile ( "wbinvd" ::: "memory" );
}

static inline void wbnoinvd(void)
{
    asm volatile ( "repe; wbinvd" : : : "memory" );
}

static inline void clflush(const void *p)
{
    asm volatile ( "clflush %0" :: "m" (*(const char *)p) );
}

static inline void clflushopt(const void *p)
{
    asm volatile ( "data16 clflush %0" :: "m" (*(const char *)p) );
}

static inline void clwb(const void *p)
{
#if defined(HAVE_AS_CLWB)
    asm volatile ( "clwb %0" :: "m" (*(const char *)p) );
#elif defined(HAVE_AS_XSAVEOPT)
    asm volatile ( "data16 xsaveopt %0" :: "m" (*(const char *)p) );
#else
    asm volatile ( ".byte 0x66, 0x0f, 0xae, 0x32"
                   :: "d" (p), "m" (*(const char *)p) );
#endif
}

#define xchg(ptr,v) \
    ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))

#include <asm/x86_64/system.h>

/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *   but generally the primitive is invalid, *ptr is output argument. --ANK
 */
static always_inline unsigned long __xchg(
    unsigned long x, volatile void *ptr, int size)
{
    switch ( size )
    {
    case 1:
        asm volatile ( "xchg %b[x], %[ptr]"
                       : [x] "+q" (x), [ptr] "+m" (*(volatile uint8_t *)ptr)
                       :: "memory" );
        break;
    case 2:
        asm volatile ( "xchg %w[x], %[ptr]"
                       : [x] "+r" (x), [ptr] "+m" (*(volatile uint16_t *)ptr)
                       :: "memory" );
        break;
    case 4:
        asm volatile ( "xchg %k[x], %[ptr]"
                       : [x] "+r" (x), [ptr] "+m" (*(volatile uint32_t *)ptr)
                       :: "memory" );
        break;
    case 8:
        asm volatile ( "xchg %q[x], %[ptr]"
                       : [x] "+r" (x), [ptr] "+m" (*(volatile uint64_t *)ptr)
                       :: "memory" );
        break;
    }
    return x;
}

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */

static always_inline unsigned long __cmpxchg(
    volatile void *ptr, unsigned long old, unsigned long new, int size)
{
    unsigned long prev;
    switch ( size )
    {
    case 1:
        asm volatile ( "lock cmpxchg %b[new], %[ptr]"
                       : "=a" (prev), [ptr] "+m" (*(volatile uint8_t *)ptr)
                       : [new] "q" (new), "a" (old)
                       : "memory" );
        return prev;
    case 2:
        asm volatile ( "lock cmpxchg %w[new], %[ptr]"
                       : "=a" (prev), [ptr] "+m" (*(volatile uint16_t *)ptr)
                       : [new] "r" (new), "a" (old)
                       : "memory" );
        return prev;
    case 4:
        asm volatile ( "lock cmpxchg %k[new], %[ptr]"
                       : "=a" (prev), [ptr] "+m" (*(volatile uint32_t *)ptr)
                       : [new] "r" (new), "a" (old)
                       : "memory" );
        return prev;
    case 8:
        asm volatile ( "lock cmpxchg %q[new], %[ptr]"
                       : "=a" (prev), [ptr] "+m" (*(volatile uint64_t *)ptr)
                       : [new] "r" (new), "a" (old)
                       : "memory" );
        return prev;
    }
    return old;
}

static always_inline unsigned long cmpxchg_local_(
    void *ptr, unsigned long old, unsigned long new, unsigned int size)
{
    unsigned long prev = ~old;

    switch ( size )
    {
    case 1:
        asm volatile ( "cmpxchg %b[new], %[ptr]"
                       : "=a" (prev), [ptr] "+m" (*(uint8_t *)ptr)
                       : [new] "q" (new), "a" (old) );
        break;
    case 2:
        asm volatile ( "cmpxchg %w[new], %[ptr]"
                       : "=a" (prev), [ptr] "+m" (*(uint16_t *)ptr)
                       : [new] "r" (new), "a" (old) );
        break;
    case 4:
        asm volatile ( "cmpxchg %k[new], %[ptr]"
                       : "=a" (prev), [ptr] "+m" (*(uint32_t *)ptr)
                       : [new] "r" (new), "a" (old) );
        break;
    case 8:
        asm volatile ( "cmpxchg %q[new], %[ptr]"
                       : "=a" (prev), [ptr] "+m" (*(uint64_t *)ptr)
                       : [new] "r" (new), "a" (old) );
        break;
    }

    return prev;
}

#define cmpxchgptr(ptr,o,n) ({                                          \
    const __typeof__(**(ptr)) *__o = (o);                               \
    __typeof__(**(ptr)) *__n = (n);                                     \
    ((__typeof__(*(ptr)))__cmpxchg((ptr),(unsigned long)__o,            \
                                   (unsigned long)__n,sizeof(*(ptr)))); \
})

/*
 * Undefined symbol to cause link failure if a wrong size is used with
 * arch_fetch_and_add().
 */
extern unsigned long __bad_fetch_and_add_size(void);

static always_inline unsigned long __xadd(
    volatile void *ptr, unsigned long v, int size)
{
    switch ( size )
    {
    case 1:
        asm volatile ( "lock xadd %b[v], %[ptr]"
                       : [v] "+q" (v), [ptr] "+m" (*(volatile uint8_t *)ptr)
                       :: "memory");
        return v;
    case 2:
        asm volatile ( "lock xadd %w[v], %[ptr]"
                       : [v] "+r" (v), [ptr] "+m" (*(volatile uint16_t *)ptr)
                       :: "memory");
        return v;
    case 4:
        asm volatile ( "lock xadd %k[v], %[ptr]"
                       : [v] "+r" (v), [ptr] "+m" (*(volatile uint32_t *)ptr)
                       :: "memory");
        return v;
    case 8:
        asm volatile ( "lock xadd %q[v], %[ptr]"
                       : [v] "+r" (v), [ptr] "+m" (*(volatile uint64_t *)ptr)
                       :: "memory");

        return v;
    default:
        return __bad_fetch_and_add_size();
    }
}

/*
 * Atomically add @v to the 1, 2, 4, or 8 byte value at @ptr.  Returns
 * the previous value.
 *
 * This is a full memory barrier.
 */
#define arch_fetch_and_add(ptr, v) \
    ((typeof(*(ptr)))__xadd(ptr, (typeof(*(ptr)))(v), sizeof(*(ptr))))

/*
 * Mandatory barriers, for enforced ordering of reads and writes, e.g. for use
 * with MMIO devices mapped with reduced cacheability.
 */
#define mb()            asm volatile ( "mfence" ::: "memory" )
#define rmb()           asm volatile ( "lfence" ::: "memory" )
#define wmb()           asm volatile ( "sfence" ::: "memory" )

/*
 * SMP barriers, for ordering of reads and writes between CPUs, most commonly
 * used with shared memory.
 *
 * Both Intel and AMD agree that, from a programmer's viewpoint:
 *  Loads cannot be reordered relative to other loads.
 *  Stores cannot be reordered relative to other stores.
 *  Loads may be reordered ahead of a unaliasing stores.
 *
 * Refer to the vendor system programming manuals for further details.
 */
#define smp_mb()        mb()
#define smp_rmb()       barrier()
#define smp_wmb()       barrier()

#define set_mb(var, value) do { xchg(&var, value); } while (0)
#define set_wmb(var, value) do { var = value; smp_wmb(); } while (0)

#define smp_mb__before_atomic()    do { } while (0)
#define smp_mb__after_atomic()     do { } while (0)

/**
 * array_index_mask_nospec() - generate a mask that is ~0UL when the
 *      bounds check succeeds and 0 otherwise
 * @index: array element index
 * @size: number of elements in array
 *
 * Returns:
 *     0 - (index < size)
 */
static inline unsigned long array_index_mask_nospec(unsigned long index,
                                                    unsigned long size)
{
    unsigned long mask;

    asm volatile ( "cmp %[size], %[index]; sbb %[mask], %[mask];"
                   : [mask] "=r" (mask)
                   : [size] "g" (size), [index] "r" (index) );

    return mask;
}

/* Override default implementation in nospec.h. */
#define array_index_mask_nospec array_index_mask_nospec

#define local_irq_disable()     asm volatile ( "cli" : : : "memory" )
#define local_irq_enable()      asm volatile ( "sti" : : : "memory" )

/* used in the idle loop; sti takes one instruction cycle to complete */
#define safe_halt()     asm volatile ( "sti; hlt" : : : "memory" )
/* used when interrupts are already enabled or to shutdown the processor */
#define halt()          asm volatile ( "hlt" : : : "memory" )

#define local_save_flags(x)                                      \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    asm volatile ( "pushf" __OS " ; pop" __OS " %0" : "=g" (x)); \
})
#define local_irq_save(x)                                        \
({                                                               \
    local_save_flags(x);                                         \
    local_irq_disable();                                         \
})
#define local_irq_restore(x)                                     \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    asm volatile ( "pushfq\n\t"                                  \
                   "andq %0, (%%rsp)\n\t"                        \
                   "orq  %1, (%%rsp)\n\t"                        \
                   "popfq"                                       \
                   : : "i?r" ( ~X86_EFLAGS_IF ),                 \
                       "ri" ( (x) & X86_EFLAGS_IF ) );           \
})

static inline int local_irq_is_enabled(void)
{
    unsigned long flags;
    local_save_flags(flags);
    return !!(flags & X86_EFLAGS_IF);
}

#define BROKEN_ACPI_Sx          0x0001
#define BROKEN_INIT_AFTER_S1    0x0002

void trap_init(void);
void init_idt_traps(void);
void load_system_tables(void);
void percpu_traps_init(void);
void subarch_percpu_traps_init(void);

#endif
