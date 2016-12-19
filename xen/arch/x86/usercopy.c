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

unsigned __copy_to_user_ll(void __user *to, const void *from, unsigned n)
{
    unsigned dummy;

    stac();
    asm volatile (
        "    cmp  $"STR(2*BYTES_PER_LONG-1)", %[cnt]\n"
        "    jbe  1f\n"
        "    mov  %k[to], %[cnt]\n"
        "    neg  %[cnt]\n"
        "    and  $"STR(BYTES_PER_LONG-1)", %[cnt]\n"
        "    sub  %[cnt], %[aux]\n"
        "4:  rep movsb\n" /* make 'to' address aligned */
        "    mov  %[aux], %[cnt]\n"
        "    shr  $"STR(LONG_BYTEORDER)", %[cnt]\n"
        "    and  $"STR(BYTES_PER_LONG-1)", %[aux]\n"
        "    .align 2,0x90\n"
        "0:  rep movs"__OS"\n" /* as many words as possible... */
        "    mov  %[aux],%[cnt]\n"
        "1:  rep movsb\n" /* ...remainder copied as bytes */
        "2:\n"
        ".section .fixup,\"ax\"\n"
        "5:  add %[aux], %[cnt]\n"
        "    jmp 2b\n"
        "3:  lea (%q[aux], %q[cnt], "STR(BYTES_PER_LONG)"), %[cnt]\n"
        "    jmp 2b\n"
        ".previous\n"
        _ASM_EXTABLE(4b, 5b)
        _ASM_EXTABLE(0b, 3b)
        _ASM_EXTABLE(1b, 2b)
        : [cnt] "+c" (n), [to] "+D" (to), [from] "+S" (from),
          [aux] "=&r" (dummy)
        : "[aux]" (n)
        : "memory" );
    clac();

    return n;
}

unsigned __copy_from_user_ll(void *to, const void __user *from, unsigned n)
{
    unsigned dummy;

    stac();
    asm volatile (
        "    cmp  $"STR(2*BYTES_PER_LONG-1)", %[cnt]\n"
        "    jbe  1f\n"
        "    mov  %k[to], %[cnt]\n"
        "    neg  %[cnt]\n"
        "    and  $"STR(BYTES_PER_LONG-1)", %[cnt]\n"
        "    sub  %[cnt], %[aux]\n"
        "4:  rep movsb\n" /* make 'to' address aligned */
        "    mov  %[aux],%[cnt]\n"
        "    shr  $"STR(LONG_BYTEORDER)", %[cnt]\n"
        "    and  $"STR(BYTES_PER_LONG-1)", %[aux]\n"
        "    .align 2,0x90\n"
        "0:  rep movs"__OS"\n" /* as many words as possible... */
        "    mov  %[aux], %[cnt]\n"
        "1:  rep movsb\n" /* ...remainder copied as bytes */
        "2:\n"
        ".section .fixup,\"ax\"\n"
        "5:  add  %[aux], %[cnt]\n"
        "    jmp 6f\n"
        "3:  lea  (%q[aux], %q[cnt], "STR(BYTES_PER_LONG)"), %[cnt]\n"
        "6:  mov  %[cnt], %k[from]\n"
        "    xchg %%eax, %[aux]\n"
        "    xor  %%eax, %%eax\n"
        "    rep stosb\n"
        "    xchg %[aux], %%eax\n"
        "    mov  %k[from], %[cnt]\n"
        "    jmp 2b\n"
        ".previous\n"
        _ASM_EXTABLE(4b, 5b)
        _ASM_EXTABLE(0b, 3b)
        _ASM_EXTABLE(1b, 6b)
        : [cnt] "+c" (n), [to] "+D" (to), [from] "+S" (from),
          [aux] "=&r" (dummy)
        : "[aux]" (n)
        : "memory" );
    clac();

    return n;
}

/**
 * copy_to_user: - Copy a block of data into user space.
 * @to:   Destination address, in user space.
 * @from: Source address, in kernel space.
 * @n:    Number of bytes to copy.
 *
 * Context: User context only.  This function may sleep.
 *
 * Copy data from kernel space to user space.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 */
unsigned copy_to_user(void __user *to, const void *from, unsigned n)
{
    if ( access_ok(to, n) )
        n = __copy_to_user(to, from, n);
    return n;
}

/**
 * clear_user: - Zero a block of memory in user space.
 * @to:   Destination address, in user space.
 * @n:    Number of bytes to zero.
 *
 * Zero a block of memory in user space.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
unsigned clear_user(void __user *to, unsigned n)
{
    if ( access_ok(to, n) )
    {
        stac();
        asm volatile (
            "0:  rep stos"__OS"\n"
            "    mov  %[bytes], %[cnt]\n"
            "1:  rep stosb\n"
            "2:\n"
            ".section .fixup,\"ax\"\n"
            "3:  lea  (%q[bytes], %q[longs], "STR(BYTES_PER_LONG)"), %[cnt]\n"
            "    jmp  2b\n"
            ".previous\n"
            _ASM_EXTABLE(0b,3b)
            _ASM_EXTABLE(1b,2b)
            : [cnt] "=&c" (n), [to] "+D" (to)
            : [bytes] "r" (n & (BYTES_PER_LONG - 1)),
              [longs] "0" (n / BYTES_PER_LONG), "a" (0) );
        clac();
    }

    return n;
}

/**
 * copy_from_user: - Copy a block of data from user space.
 * @to:   Destination address, in kernel space.
 * @from: Source address, in user space.
 * @n:    Number of bytes to copy.
 *
 * Context: User context only.  This function may sleep.
 *
 * Copy data from user space to kernel space.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 *
 * If some data could not be copied, this function will pad the copied
 * data to the requested size using zero bytes.
 */
unsigned copy_from_user(void *to, const void __user *from, unsigned n)
{
    if ( access_ok(from, n) )
        n = __copy_from_user(to, from, n);
    else
        memset(to, 0, n);
    return n;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
