/******************************************************************************
 * os.h
 * 
 * random collection of macros and definition
 */

#ifndef _OS_H_
#define _OS_H_

#ifndef NULL
#define NULL (void *)0
#endif

/* Somewhere in the middle of the GCC 2.96 development cycle, we implemented
   a mechanism by which the user can annotate likely branch directions and
   expect the blocks to be reordered appropriately.  Define __builtin_expect
   to nothing for earlier compilers.  */

#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif



/*
 * These are the segment descriptors provided for us by the hypervisor.
 * For now, these are hardwired -- guest OSes cannot update the GDT
 * or LDT.
 * 
 * It shouldn't be hard to support descriptor-table frobbing -- let me 
 * know if the BSD or XP ports require flexibility here.
 */


/*
 * these are also defined in hypervisor-if.h but can't be pulled in as
 * they are used in start of day assembly. Need to clean up the .h files
 * a bit more...
 */

#ifndef FLAT_RING1_CS
#define FLAT_RING1_CS		0x0819
#define FLAT_RING1_DS		0x0821
#define FLAT_RING3_CS		0x082b
#define FLAT_RING3_DS		0x0833
#endif

#define __KERNEL_CS        FLAT_RING1_CS
#define __KERNEL_DS        FLAT_RING1_DS

/* Everything below this point is not included by assembler (.S) files. */
#ifndef __ASSEMBLY__
#include <sys/types.h>

#include <machine/hypervisor-ifs.h>
void printk(const char *fmt, ...);

/* some function prototypes */
void trap_init(void);


/*
 * STI/CLI equivalents. These basically set and clear the virtual
 * event_enable flag in teh shared_info structure. Note that when
 * the enable bit is set, there may be pending events to be handled.
 * We may therefore call into do_hypervisor_callback() directly.
 */
#define likely(x)  __builtin_expect((x),1)
#define unlikely(x)  __builtin_expect((x),0)

#define __cli()                                                               \
do {                                                                          \
    HYPERVISOR_shared_info->vcpu_data[0].evtchn_upcall_mask = 1;              \
    barrier();                                                                \
} while (0)

#define __sti()                                                               \
do {                                                                          \
    shared_info_t *_shared = HYPERVISOR_shared_info;                          \
    barrier();                                                                \
    _shared->vcpu_data[0].evtchn_upcall_mask = 0;                             \
    barrier(); /* unmask then check (avoid races) */                          \
    if ( unlikely(_shared->vcpu_data[0].evtchn_upcall_pending) )              \
        force_evtchn_callback();                                              \
} while (0)

#define __save_flags(x)                                                       \
do {                                                                          \
    (x) = HYPERVISOR_shared_info->vcpu_data[0].evtchn_upcall_mask;            \
} while (0)

#define __restore_flags(x)                                                    \
do {                                                                          \
    shared_info_t *_shared = HYPERVISOR_shared_info;                          \
    barrier();                                                                \
    if ( (_shared->vcpu_data[0].evtchn_upcall_mask = (x)) == 0 ) {            \
        barrier(); /* unmask then check (avoid races) */                      \
        if ( unlikely(_shared->vcpu_data[0].evtchn_upcall_pending) )          \
            force_evtchn_callback();                                          \
    }                                                                         \
} while (0)

#define __save_and_cli(x)                                                     \
do {                                                                          \
    (x) = HYPERVISOR_shared_info->vcpu_data[0].evtchn_upcall_mask;            \
    HYPERVISOR_shared_info->vcpu_data[0].evtchn_upcall_mask = 1;              \
    barrier();                                                                \
} while (0)

#define __save_and_sti(x)                                                     \
do {                                                                          \
    shared_info_t *_shared = HYPERVISOR_shared_info;                          \
    barrier();                                                                \
    (x) = _shared->vcpu_data[0].evtchn_upcall_mask;                           \
    _shared->vcpu_data[0].evtchn_upcall_mask = 0;                             \
    barrier(); /* unmask then check (avoid races) */                          \
    if ( unlikely(_shared->vcpu_data[0].evtchn_upcall_pending) )              \
        force_evtchn_callback();                                              \
} while (0)

#ifdef SMP
/* extra macros need for the SMP case */
#error "global_irq_* not defined"
#endif

#define cli() __cli()
#define sti() __sti()
#define save_flags(x) __save_flags(x)
#define restore_flags(x) __restore_flags(x)
#define save_and_cli(x) __save_and_cli(x)
#define save_and_sti(x) __save_and_sti(x)

#define local_irq_save(x)       __save_and_cli(x)
#define local_irq_set(x)        __save_and_sti(x)
#define local_irq_restore(x)    __restore_flags(x)
#define local_irq_disable()     __cli()
#define local_irq_enable()      __sti()

#define mtx_lock_irqsave(lock, x) {local_irq_save((x)); mtx_lock_spin((lock));}
#define mtx_unlock_irqrestore(lock, x) {mtx_unlock_spin((lock)); local_irq_restore((x)); }

#define mb()
#define rmb()
#define smp_mb() 
#define wmb()



/* This is a barrier for the compiler only, NOT the processor! */
#define barrier() __asm__ __volatile__("": : :"memory")

#define LOCK_PREFIX ""
#define LOCK ""
#define ADDR (*(volatile long *) addr)
/*
 * Make sure gcc doesn't try to be clever and move things around
 * on us. We need to use _exactly_ the address the user gave us,
 * not some alias that contains the same information.
 */
typedef struct { volatile int counter; } atomic_t;



#define xen_xchg(ptr,v) \
        ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))
struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((volatile struct __xchg_dummy *)(x))
static __inline unsigned long __xchg(unsigned long x, volatile void * ptr,
                                   int size)
{
    switch (size) {
    case 1:
        __asm__ __volatile__("xchgb %b0,%1"
                             :"=q" (x)
                             :"m" (*__xg(ptr)), "0" (x)
                             :"memory");
        break;
    case 2:
        __asm__ __volatile__("xchgw %w0,%1"
                             :"=r" (x)
                             :"m" (*__xg(ptr)), "0" (x)
                             :"memory");
        break;
    case 4:
        __asm__ __volatile__("xchgl %0,%1"
                             :"=r" (x)
                             :"m" (*__xg(ptr)), "0" (x)
                             :"memory");
        break;
    }
    return x;
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It also implies a memory barrier.
 */
static __inline__ int test_and_clear_bit(int nr, volatile void * addr)
{
        int oldbit;

        __asm__ __volatile__( LOCK_PREFIX
                "btrl %2,%1\n\tsbbl %0,%0"
                :"=r" (oldbit),"=m" (ADDR)
                :"Ir" (nr) : "memory");
        return oldbit;
}

static __inline__ int constant_test_bit(int nr, const volatile void * addr)
{
    return ((1UL << (nr & 31)) & (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
}

static __inline__ int variable_test_bit(int nr, volatile void * addr)
{
    int oldbit;
    
    __asm__ __volatile__(
        "btl %2,%1\n\tsbbl %0,%0"
        :"=r" (oldbit)
        :"m" (ADDR),"Ir" (nr));
    return oldbit;
}

#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))


/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit()
 * if you do not require the atomic guarantees.
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static __inline__ void set_bit(int nr, volatile void * addr)
{
        __asm__ __volatile__( LOCK_PREFIX
                "btsl %1,%0"
                :"=m" (ADDR)
                :"Ir" (nr));
}

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does
 * not contain a memory barrier, so if it is used for locking purposes,
 * you should call smp_mb__before_clear_bit() and/or smp_mb__after_clear_bit()
 * in order to ensure changes are visible on other processors.
 */
static __inline__ void clear_bit(int nr, volatile void * addr)
{
        __asm__ __volatile__( LOCK_PREFIX
                "btrl %1,%0"
                :"=m" (ADDR)
                :"Ir" (nr));
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */ 
static __inline__ void atomic_inc(atomic_t *v)
{
        __asm__ __volatile__(
                LOCK "incl %0"
                :"=m" (v->counter)
                :"m" (v->counter));
}


#define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))


#endif /* !__ASSEMBLY__ */

#endif /* _OS_H_ */
