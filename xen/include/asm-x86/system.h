#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <xen/config.h>
#include <xen/types.h>
#include <asm/bitops.h>

#define read_segment_register(name)                                     \
({  u16 __sel;                                                          \
    __asm__ __volatile__ ( "movw %%" STR(name) ",%0" : "=r" (__sel) );  \
    __sel;                                                              \
})

#define wbinvd() \
	__asm__ __volatile__ ("wbinvd": : :"memory");

#define nop() __asm__ __volatile__ ("nop")

#define xchg(ptr,v) ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))

struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((struct __xchg_dummy *)(x))


/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *   but generally the primitive is invalid, *ptr is output argument. --ANK
 */
static always_inline unsigned long __xchg(unsigned long x, volatile void * ptr, int size)
{
	switch (size) {
		case 1:
			__asm__ __volatile__("xchgb %b0,%1"
				:"=q" (x)
				:"m" (*__xg((volatile void *)ptr)), "0" (x)
				:"memory");
			break;
		case 2:
			__asm__ __volatile__("xchgw %w0,%1"
				:"=r" (x)
				:"m" (*__xg((volatile void *)ptr)), "0" (x)
				:"memory");
			break;
#if defined(__i386__)
		case 4:
			__asm__ __volatile__("xchgl %0,%1"
				:"=r" (x)
				:"m" (*__xg((volatile void *)ptr)), "0" (x)
				:"memory");
			break;
#elif defined(__x86_64__)
		case 4:
			__asm__ __volatile__("xchgl %k0,%1"
				:"=r" (x)
				:"m" (*__xg((volatile void *)ptr)), "0" (x)
				:"memory");
			break;
		case 8:
			__asm__ __volatile__("xchgq %0,%1"
				:"=r" (x)
				:"m" (*__xg((volatile void *)ptr)), "0" (x)
				:"memory");
			break;
#endif
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
	switch (size) {
	case 1:
		__asm__ __volatile__(LOCK_PREFIX "cmpxchgb %b1,%2"
				     : "=a"(prev)
				     : "q"(new), "m"(*__xg((volatile void *)ptr)), "0"(old)
				     : "memory");
		return prev;
	case 2:
		__asm__ __volatile__(LOCK_PREFIX "cmpxchgw %w1,%2"
				     : "=a"(prev)
				     : "r"(new), "m"(*__xg((volatile void *)ptr)), "0"(old)
				     : "memory");
		return prev;
#if defined(__i386__)
	case 4:
		__asm__ __volatile__(LOCK_PREFIX "cmpxchgl %1,%2"
				     : "=a"(prev)
				     : "r"(new), "m"(*__xg((volatile void *)ptr)), "0"(old)
				     : "memory");
		return prev;
#elif defined(__x86_64__)
	case 4:
		__asm__ __volatile__(LOCK_PREFIX "cmpxchgl %k1,%2"
				     : "=a"(prev)
				     : "r"(new), "m"(*__xg((volatile void *)ptr)), "0"(old)
				     : "memory");
		return prev;
	case 8:
		__asm__ __volatile__(LOCK_PREFIX "cmpxchgq %1,%2"
				     : "=a"(prev)
				     : "r"(new), "m"(*__xg((volatile void *)ptr)), "0"(old)
				     : "memory");
		return prev;
#endif
	}
	return old;
}

#define __HAVE_ARCH_CMPXCHG

#if BITS_PER_LONG == 64

#define cmpxchg(ptr,o,n)                                                \
    ((__typeof__(*(ptr)))__cmpxchg((ptr),(unsigned long)(o),            \
                                   (unsigned long)(n),sizeof(*(ptr))))
#else

static always_inline unsigned long long __cmpxchg8b(
    volatile void *ptr, unsigned long long old, unsigned long long new)
{
    unsigned long long prev;
    __asm__ __volatile__ (
        LOCK_PREFIX "cmpxchg8b %3"
        : "=A" (prev)
        : "c" ((u32)(new>>32)), "b" ((u32)new),
          "m" (*__xg((volatile void *)ptr)), "0" (old)
        : "memory" );
    return prev;
}

#define cmpxchg(ptr,o,n)                                \
({                                                      \
    __typeof__(*(ptr)) __prev;                          \
    switch ( sizeof(*(ptr)) ) {                         \
    case 8:                                             \
        __prev = ((__typeof__(*(ptr)))__cmpxchg8b(      \
            (ptr),                                      \
            (unsigned long long)(o),                    \
            (unsigned long long)(n)));                  \
        break;                                          \
    default:                                            \
        __prev = ((__typeof__(*(ptr)))__cmpxchg(        \
            (ptr),                                      \
            (unsigned long)(o),                         \
            (unsigned long)(n),                         \
            sizeof(*(ptr))));                           \
        break;                                          \
    }                                                   \
    __prev;                                             \
})

#endif


/*
 * This function causes value _o to be changed to _n at location _p.
 * If this access causes a fault then we return 1, otherwise we return 0.
 * If no fault occurs then _o is updated to the value we saw at _p. If this
 * is the same as the initial value of _o then _n is written to location _p.
 */
#ifdef __i386__
#define __cmpxchg_user(_p,_o,_n,_isuff,_oppre,_regtype)                 \
    __asm__ __volatile__ (                                              \
        "1: " LOCK_PREFIX "cmpxchg"_isuff" %"_oppre"2,%3\n"             \
        "2:\n"                                                          \
        ".section .fixup,\"ax\"\n"                                      \
        "3:     movl $1,%1\n"                                           \
        "       jmp 2b\n"                                               \
        ".previous\n"                                                   \
        ".section __ex_table,\"a\"\n"                                   \
        "       .align 4\n"                                             \
        "       .long 1b,3b\n"                                          \
        ".previous"                                                     \
        : "=a" (_o), "=r" (_rc)                                         \
        : _regtype (_n), "m" (*__xg((volatile void *)_p)), "0" (_o), "1" (0) \
        : "memory");
#define cmpxchg_user(_p,_o,_n)                                          \
({                                                                      \
    int _rc;                                                            \
    switch ( sizeof(*(_p)) ) {                                          \
    case 1:                                                             \
        __cmpxchg_user(_p,_o,_n,"b","b","q");                           \
        break;                                                          \
    case 2:                                                             \
        __cmpxchg_user(_p,_o,_n,"w","w","r");                           \
        break;                                                          \
    case 4:                                                             \
        __cmpxchg_user(_p,_o,_n,"l","","r");                            \
        break;                                                          \
    case 8:                                                             \
        __asm__ __volatile__ (                                          \
            "1: " LOCK_PREFIX "cmpxchg8b %4\n"                          \
            "2:\n"                                                      \
            ".section .fixup,\"ax\"\n"                                  \
            "3:     movl $1,%1\n"                                       \
            "       jmp 2b\n"                                           \
            ".previous\n"                                               \
            ".section __ex_table,\"a\"\n"                               \
            "       .align 4\n"                                         \
            "       .long 1b,3b\n"                                      \
            ".previous"                                                 \
            : "=A" (_o), "=r" (_rc)                                     \
            : "c" ((u32)((u64)(_n)>>32)), "b" ((u32)(_n)),              \
              "m" (*__xg((volatile void *)(_p))), "0" (_o), "1" (0)     \
            : "memory");                                                \
        break;                                                          \
    }                                                                   \
    _rc;                                                                \
})
#else
#define __cmpxchg_user(_p,_o,_n,_isuff,_oppre,_regtype)                 \
    __asm__ __volatile__ (                                              \
        "1: " LOCK_PREFIX "cmpxchg"_isuff" %"_oppre"2,%3\n"             \
        "2:\n"                                                          \
        ".section .fixup,\"ax\"\n"                                      \
        "3:     movl $1,%1\n"                                           \
        "       jmp 2b\n"                                               \
        ".previous\n"                                                   \
        ".section __ex_table,\"a\"\n"                                   \
        "       .align 8\n"                                             \
        "       .quad 1b,3b\n"                                          \
        ".previous"                                                     \
        : "=a" (_o), "=r" (_rc)                                         \
        : _regtype (_n), "m" (*__xg((volatile void *)_p)), "0" (_o), "1" (0) \
        : "memory");
#define cmpxchg_user(_p,_o,_n)                                          \
({                                                                      \
    int _rc;                                                            \
    switch ( sizeof(*(_p)) ) {                                          \
    case 1:                                                             \
        __cmpxchg_user(_p,_o,_n,"b","b","q");                           \
        break;                                                          \
    case 2:                                                             \
        __cmpxchg_user(_p,_o,_n,"w","w","r");                           \
        break;                                                          \
    case 4:                                                             \
        __cmpxchg_user(_p,_o,_n,"l","k","r");                           \
        break;                                                          \
    case 8:                                                             \
        __cmpxchg_user(_p,_o,_n,"q","","r");                            \
        break;                                                          \
    }                                                                   \
    _rc;                                                                \
})
#endif

/*
 * Force strict CPU ordering.
 * And yes, this is required on UP too when we're talking
 * to devices.
 *
 * For now, "wmb()" doesn't actually do anything, as all
 * Intel CPU's follow what Intel calls a *Processor Order*,
 * in which all writes are seen in the program order even
 * outside the CPU.
 *
 * I expect future Intel CPU's to have a weaker ordering,
 * but I'd also expect them to finally get their act together
 * and add some real memory barriers if so.
 *
 * Some non intel clones support out of order store. wmb() ceases to be a
 * nop for these.
 */
#if defined(__i386__)
#define mb() 	__asm__ __volatile__ ("lock; addl $0,0(%%esp)": : :"memory")
#define rmb()	__asm__ __volatile__ ("lock; addl $0,0(%%esp)": : :"memory")
#ifdef CONFIG_X86_OOSTORE
#define wmb() 	__asm__ __volatile__ ("lock; addl $0,0(%%esp)": : :"memory")
#endif
#elif defined(__x86_64__)
#define mb()    __asm__ __volatile__ ("mfence":::"memory")
#define rmb()   __asm__ __volatile__ ("lfence":::"memory")
#ifdef CONFIG_X86_OOSTORE
#define wmb()   __asm__ __volatile__ ("sfence":::"memory")
#endif
#endif

#ifndef CONFIG_X86_OOSTORE
#define wmb()	__asm__ __volatile__ ("": : :"memory")
#endif

#ifdef CONFIG_SMP
#define smp_mb()	mb()
#define smp_rmb()	rmb()
#define smp_wmb()	wmb()
#else
#define smp_mb()	barrier()
#define smp_rmb()	barrier()
#define smp_wmb()	barrier()
#endif

#define set_mb(var, value) do { xchg(&var, value); } while (0)
#define set_wmb(var, value) do { var = value; wmb(); } while (0)

/* interrupt control.. */
#if defined(__i386__)
#define __save_flags(x)		__asm__ __volatile__("pushfl ; popl %0":"=g" (x): /* no input */)
#define __restore_flags(x) 	__asm__ __volatile__("pushl %0 ; popfl": /* no output */ :"g" (x):"memory", "cc")
#elif defined(__x86_64__)
#define __save_flags(x)		do { __asm__ __volatile__("# save_flags \n\t pushfq ; popq %q0":"=g" (x): /* no input */ :"memory"); } while (0)
#define __restore_flags(x) 	__asm__ __volatile__("# restore_flags \n\t pushq %0 ; popfq": /* no output */ :"g" (x):"memory", "cc")
#endif
#define __cli() 		__asm__ __volatile__("cli": : :"memory")
#define __sti()			__asm__ __volatile__("sti": : :"memory")
/* used in the idle loop; sti takes one instruction cycle to complete */
#define safe_halt()		__asm__ __volatile__("sti; hlt": : :"memory")

/* For spinlocks etc */
#if defined(__i386__)
#define local_irq_save(x)	__asm__ __volatile__("pushfl ; popl %0 ; cli":"=g" (x): /* no input */ :"memory")
#define local_irq_restore(x)	__restore_flags(x)
#elif defined(__x86_64__)
#define local_irq_save(x) 	do { __asm__ __volatile__("# local_irq_save \n\t pushfq ; popq %0 ; cli":"=g" (x): /* no input */ :"memory"); } while (0)
#define local_irq_restore(x)	__asm__ __volatile__("# local_irq_restore \n\t pushq %0 ; popfq": /* no output */ :"g" (x):"memory")
#endif
#define local_irq_disable()	__cli()
#define local_irq_enable()	__sti()

static inline int local_irq_is_enabled(void)
{
    unsigned long flags;
    __save_flags(flags);
    return !!(flags & (1<<9)); /* EFLAGS_IF */
}

#define BROKEN_ACPI_Sx		0x0001
#define BROKEN_INIT_AFTER_S1	0x0002

extern int es7000_plat;

#endif
