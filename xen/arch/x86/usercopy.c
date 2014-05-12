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

unsigned long __copy_to_user_ll(void __user *to, const void *from, unsigned n)
{
    unsigned long __d0, __d1, __d2, __n = n;

    stac();
    asm volatile (
        "    cmp  $"STR(2*BYTES_PER_LONG-1)",%0\n"
        "    jbe  1f\n"
        "    mov  %1,%0\n"
        "    neg  %0\n"
        "    and  $"STR(BYTES_PER_LONG-1)",%0\n"
        "    sub  %0,%3\n"
        "4:  rep movsb\n" /* make 'to' address aligned */
        "    mov  %3,%0\n"
        "    shr  $"STR(LONG_BYTEORDER)",%0\n"
        "    and  $"STR(BYTES_PER_LONG-1)",%3\n"
        "    .align 2,0x90\n"
        "0:  rep movs"__OS"\n" /* as many words as possible... */
        "    mov  %3,%0\n"
        "1:  rep movsb\n" /* ...remainder copied as bytes */
        "2:\n"
        ".section .fixup,\"ax\"\n"
        "5:  add %3,%0\n"
        "    jmp 2b\n"
        "3:  lea 0(%3,%0,"STR(BYTES_PER_LONG)"),%0\n"
        "    jmp 2b\n"
        ".previous\n"
        _ASM_EXTABLE(4b, 5b)
        _ASM_EXTABLE(0b, 3b)
        _ASM_EXTABLE(1b, 2b)
        : "=&c" (__n), "=&D" (__d0), "=&S" (__d1), "=&r" (__d2)
        : "0" (__n), "1" (to), "2" (from), "3" (__n)
        : "memory" );
    clac();

    return __n;
}

unsigned long
__copy_from_user_ll(void *to, const void __user *from, unsigned n)
{
    unsigned long __d0, __d1, __d2, __n = n;

    stac();
    asm volatile (
        "    cmp  $"STR(2*BYTES_PER_LONG-1)",%0\n"
        "    jbe  1f\n"
        "    mov  %1,%0\n"
        "    neg  %0\n"
        "    and  $"STR(BYTES_PER_LONG-1)",%0\n"
        "    sub  %0,%3\n"
        "4:  rep; movsb\n" /* make 'to' address aligned */
        "    mov  %3,%0\n"
        "    shr  $"STR(LONG_BYTEORDER)",%0\n"
        "    and  $"STR(BYTES_PER_LONG-1)",%3\n"
        "    .align 2,0x90\n"
        "0:  rep; movs"__OS"\n" /* as many words as possible... */
        "    mov  %3,%0\n"
        "1:  rep; movsb\n" /* ...remainder copied as bytes */
        "2:\n"
        ".section .fixup,\"ax\"\n"
        "5:  add %3,%0\n"
        "    jmp 6f\n"
        "3:  lea 0(%3,%0,"STR(BYTES_PER_LONG)"),%0\n"
        "6:  push %0\n"
        "    push %%"__OP"ax\n"
        "    xor  %%eax,%%eax\n"
        "    rep; stosb\n"
        "    pop  %%"__OP"ax\n"
        "    pop  %0\n"
        "    jmp 2b\n"
        ".previous\n"
        _ASM_EXTABLE(4b, 5b)
        _ASM_EXTABLE(0b, 3b)
        _ASM_EXTABLE(1b, 6b)
        : "=&c" (__n), "=&D" (__d0), "=&S" (__d1), "=&r" (__d2)
        : "0" (__n), "1" (to), "2" (from), "3" (__n)
        : "memory" );
    clac();

    return __n;
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
unsigned long
copy_to_user(void __user *to, const void *from, unsigned n)
{
    if ( access_ok(to, n) )
        n = __copy_to_user(to, from, n);
    return n;
}

#define __do_clear_user(addr,size)					\
do {									\
	long __d0;							\
	stac();								\
	__asm__ __volatile__(						\
		"0:	rep; stosl\n"					\
		"	movl %2,%0\n"					\
		"1:	rep; stosb\n"					\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"3:	lea 0(%2,%0,4),%0\n"				\
		"	jmp 2b\n"					\
		".previous\n"						\
		_ASM_EXTABLE(0b,3b)					\
		_ASM_EXTABLE(1b,2b)					\
		: "=&c"(size), "=&D" (__d0)				\
		: "r"(size & 3), "0"(size / 4), "1"((long)addr), "a"(0));	\
	clac();								\
} while (0)

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
unsigned long
clear_user(void __user *to, unsigned n)
{
	if ( access_ok(to, n) )
		__do_clear_user(to, n);
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
unsigned long
copy_from_user(void *to, const void __user *from, unsigned n)
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
