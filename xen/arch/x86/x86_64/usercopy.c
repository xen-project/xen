/* 
 * User address space access functions.
 *
 * Copyright 1997 Andi Kleen <ak@muc.de>
 * Copyright 1997 Linus Torvalds
 * Copyright 2002 Andi Kleen <ak@suse.de>
 */
#include <asm/uaccess.h>

/*
 * Zero Userspace
 */

unsigned long __clear_user(void *addr, unsigned long size)
{
	long __d0;
	/* no memory constraint because it doesn't change any memory gcc knows
	   about */
	asm volatile(
		"	testq  %[size8],%[size8]\n"
		"	jz     4f\n"
		"0:	movq %[zero],(%[dst])\n"
		"	addq   %[eight],%[dst]\n"
		"	decl %%ecx ; jnz   0b\n"
		"4:	movq  %[size1],%%rcx\n"
		"	testl %%ecx,%%ecx\n"
		"	jz     2f\n"
		"1:	movb   %b[zero],(%[dst])\n"
		"	incq   %[dst]\n"
		"	decl %%ecx ; jnz  1b\n"
		"2:\n"
		".section .fixup,\"ax\"\n"
		"3:	lea 0(%[size1],%[size8],8),%[size8]\n"
		"	jmp 2b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"       .align 8\n"
		"	.quad 0b,3b\n"
		"	.quad 1b,2b\n"
		".previous"
		: [size8] "=c"(size), [dst] "=&D" (__d0)
		: [size1] "r"(size & 7), "[size8]" (size / 8), "[dst]"(addr),
		  [zero] "r" (0UL), [eight] "r" (8UL));
	return size;
}

unsigned long __copy_to_user_ll(void __user *to, const void *from, unsigned n)
{
	unsigned long __d0, __d1, __d2, __n = n;
	__asm__ __volatile__(
		"	cmpq  $15,%0\n"
		"	jbe  1f\n"
		"	mov  %1,%0\n"
		"	neg  %0\n"
		"	and  $7,%0\n"
		"	sub  %0,%3\n"
		"4:	rep; movsb\n" /* make 'to' address aligned */
		"	mov  %3,%0\n"
		"	shr  $3,%0\n"
		"	and  $7,%3\n"
		"	.align 2,0x90\n"
		"0:	rep; movsq\n" /* as many quadwords as possible... */
		"	mov  %3,%0\n"
		"1:	rep; movsb\n" /* ...remainder copied as bytes */
		"2:\n"
		".section .fixup,\"ax\"\n"
		"5:	add %3,%0\n"
		"	jmp 2b\n"
		"3:	lea 0(%3,%0,8),%0\n"
		"	jmp 2b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 8\n"
		"	.quad 4b,5b\n"
		"	.quad 0b,3b\n"
		"	.quad 1b,2b\n"
		".previous"
		: "=&c"(__n), "=&D" (__d0), "=&S" (__d1), "=r"(__d2)
		: "3"(__n), "0"(__n), "1"(to), "2"(from)
		: "memory");
	return (unsigned)__n;
}

unsigned long
__copy_from_user_ll(void *to, const void __user *from, unsigned n)
{
	unsigned long __d0, __d1, __d2, __n = n;
	__asm__ __volatile__(
		"	cmp  $15,%0\n"
		"	jbe  1f\n"
		"	mov  %1,%0\n"
		"	neg  %0\n"
		"	and  $7,%0\n"
		"	sub  %0,%3\n"
		"4:	rep; movsb\n" /* make 'to' address aligned */
		"	mov  %3,%0\n"
		"	shr  $3,%0\n"
		"	and  $7,%3\n"
		"	.align 2,0x90\n"
		"0:	rep; movsq\n" /* as many quadwords as possible... */
		"	mov  %3,%0\n"
		"1:	rep; movsb\n" /* ...remainder copied as bytes */
		"2:\n"
		".section .fixup,\"ax\"\n"
		"5:	add %3,%0\n"
		"	jmp 6f\n"
		"3:	lea 0(%3,%0,8),%0\n"
		"6:	push %0\n"
		"	push %%rax\n"
		"	xor  %%rax,%%rax\n"
		"	rep; stosb\n"
		"	pop  %%rax\n"
		"	pop  %0\n"
		"	jmp 2b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 8\n"
		"	.quad 4b,5b\n"
		"	.quad 0b,3b\n"
		"	.quad 1b,6b\n"
		".previous"
		: "=&c"(__n), "=&D" (__d0), "=&S" (__d1), "=r"(__d2)
		: "3"(__n), "0"(__n), "1"(to), "2"(from)
		: "memory");
	return (unsigned)__n;
}

unsigned long clear_user(void *to, unsigned long n)
{
	if (access_ok(VERIFY_WRITE, to, n))
		return __clear_user(to, n);
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
unsigned long
copy_to_user(void __user *to, const void *from, unsigned n)
{
	if (access_ok(VERIFY_WRITE, to, n))
		n = __copy_to_user(to, from, n);
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
	if (access_ok(VERIFY_READ, from, n))
		n = __copy_from_user(to, from, n);
	else
		memset(to, 0, n);
	return n;
}
