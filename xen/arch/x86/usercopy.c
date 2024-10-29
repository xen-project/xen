/* 
 * User address space access functions.
 *
 * Copyright 1997 Andi Kleen <ak@muc.de>
 * Copyright 1997 Linus Torvalds
 * Copyright 2002 Andi Kleen <ak@suse.de>
 */

#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/uaccess.h>

#ifndef GUARD
# define GUARD UA_KEEP
#endif

unsigned int copy_to_guest_ll(void __user *to, const void *from, unsigned int n)
{
    GUARD(unsigned dummy);

    stac();
    asm volatile (
        GUARD(
        "    guest_access_mask_ptr %[to], %q[scratch1], %q[scratch2]\n"
        )
        "1:  rep movsb\n"
        "2:\n"
        _ASM_EXTABLE(1b, 2b)
        : [cnt] "+c" (n), [to] "+D" (to), [from] "+S" (from)
          GUARD(, [scratch1] "=&r" (dummy), [scratch2] "=&r" (dummy))
        :: "memory" );
    clac();

    return n;
}

unsigned int copy_from_guest_ll(void *to, const void __user *from, unsigned int n)
{
    unsigned dummy;

    stac();
    asm volatile (
        GUARD(
        "    guest_access_mask_ptr %[from], %q[scratch1], %q[scratch2]\n"
        )
        "1:  rep movsb\n"
        "2:\n"
        ".section .fixup,\"ax\"\n"
        "6:  mov  %[cnt], %k[from]\n"
        "    xchg %%eax, %[aux]\n"
        "    xor  %%eax, %%eax\n"
        "    rep stosb\n"
        "    xchg %[aux], %%eax\n"
        "    mov  %k[from], %[cnt]\n"
        "    jmp 2b\n"
        ".previous\n"
        _ASM_EXTABLE(1b, 6b)
        : [cnt] "+c" (n), [to] "+D" (to), [from] "+S" (from),
          [aux] "=&r" (dummy)
          GUARD(, [scratch1] "=&r" (dummy), [scratch2] "=&r" (dummy))
        :: "memory" );
    clac();

    return n;
}

#if GUARD(1) + 0

/**
 * copy_to_guest_pv: - Copy a block of data into PV guest space.
 * @to:   Destination address, in PV guest space.
 * @from: Source address, in hypervisor space.
 * @n:    Number of bytes to copy.
 *
 * Copy data from hypervisor space to PV guest space.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 */
unsigned int copy_to_guest_pv(void __user *to, const void *from, unsigned int n)
{
    if ( access_ok(to, n) )
        n = __copy_to_guest_pv(to, from, n);
    return n;
}

/**
 * clear_guest_pv: - Zero a block of memory in PV guest space.
 * @to:   Destination address, in PV guest space.
 * @n:    Number of bytes to zero.
 *
 * Zero a block of memory in PV guest space.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
unsigned int clear_guest_pv(void __user *to, unsigned int n)
{
    if ( access_ok(to, n) )
    {
        long dummy;

        stac();
        asm volatile (
            "    guest_access_mask_ptr %[to], %[scratch1], %[scratch2]\n"
            "1:  rep stosb\n"
            "2:\n"
            _ASM_EXTABLE(1b,2b)
            : [cnt] "+c" (n), [to] "+D" (to), [scratch1] "=&r" (dummy),
              [scratch2] "=&r" (dummy)
            : "a" (0) );
        clac();
    }

    return n;
}

/**
 * copy_from_guest_pv: - Copy a block of data from PV guest space.
 * @to:   Destination address, in hypervisor space.
 * @from: Source address, in PV guest space.
 * @n:    Number of bytes to copy.
 *
 * Copy data from PV guest space to hypervisor space.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 *
 * If some data could not be copied, this function will pad the copied
 * data to the requested size using zero bytes.
 */
unsigned int copy_from_guest_pv(void *to, const void __user *from,
                                unsigned int n)
{
    if ( access_ok(from, n) )
        n = __copy_from_guest_pv(to, from, n);
    else
        memset(to, 0, n);
    return n;
}

# undef GUARD
# define GUARD UA_DROP
# define copy_to_guest_ll copy_to_unsafe_ll
# define copy_from_guest_ll copy_from_unsafe_ll
# undef __user
# define __user
# include __FILE__

#endif /* GUARD(1) */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
