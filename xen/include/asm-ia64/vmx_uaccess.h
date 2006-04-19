/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_uaccess.h: Defines vmx specific macros to transfer memory areas
 * across the domain/hypervisor boundary.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Note:  For vmx enabled environment, poor man's policy is actually
 * useless since HV resides in completely different address space as
 * domain. So the only way to do the access is search vTLB first, and
 * access identity mapped address if hit.
 *
 * Copyright (c) 2004, Intel Corporation.
 * 	Kun Tian (Kevin Tian) (kevin.tian@intel.com)
 */

#ifndef __ASM_IA64_VMX_UACCESS_H__
#define __ASM_IA64_VMX_UACCESS_H__

#include <xen/compiler.h>
#include <xen/errno.h>
#include <xen/sched.h>

#include <asm/intrinsics.h>
#include <asm/vmmu.h>

/* Since HV never accesses domain space directly, most security check can
 * be dummy now
 */
asm (".section \"__ex_table\", \"a\"\n\t.previous");

/* For back compatibility */
#define __access_ok(addr, size, segment)	1
#define access_ok(addr, size, segment)	__access_ok((addr), (size), (segment))

/*
 * These are the main single-value transfer routines.  They automatically
 * use the right size if we just have the right pointer type.
 *
 * Careful to not
 * (a) re-use the arguments for side effects (sizeof/typeof is ok)
 * (b) require any knowledge of processes at this stage
 */
#define put_user(x, ptr)	__put_user((x), (ptr))
#define get_user(x, ptr)	__get_user((x), (ptr))

#define __put_user(x, ptr)	__do_put_user((__typeof__(*(ptr))) (x), (ptr), sizeof(*(ptr)))
#define __get_user(x, ptr)	__do_get_user((x), (ptr), sizeof(*(ptr)))

/* TODO: add specific unaligned access later. If assuming aligned at
 * 1,2,4,8 bytes by far, it's impossible for operand spaning two
 * vTLB entry
 */
extern long
__domain_va_to_ma(unsigned long va, unsigned long* ma, unsigned long *len);

#define __do_put_user(x, ptr, size)					\
({									\
    __typeof__ (x) __pu_x = (x);					\
    __typeof__ (*(ptr)) __user *__pu_ptr = (ptr);			\
    __typeof__ (size) __pu_size = (size);				\
    unsigned long __pu_ma;						\
    long __pu_err;							\
									\
    __pu_err = __domain_va_to_ma((unsigned long)__pu_ptr,		\
				&__pu_ma, &__pu_size);			\
    __pu_err ? (__pu_err = -EFAULT) :					\
    	(*((__typeof__ (*(ptr)) *)__va(__pu_ma)) = x);			\
    __pu_err;								\
})

#define __do_get_user(x, ptr, size)					\
({									\
    __typeof__ (x) __gu_x = (x);					\
    __typeof__ (*(ptr)) __user *__gu_ptr = (ptr);			\
    __typeof__ (size) __gu_size = (size);				\
    unsigned long __gu_ma;						\
    long __gu_err;							\
									\
    __gu_err = __domain_va_to_ma((unsigned long)__gu_ptr,		\
				&__gu_ma, &__gu_size);			\
    __gu_err ? (__gu_err = -EFAULT) :					\
    	(x = *((__typeof__ (*(ptr)) *)__va(__gu_ma)));			\
    __gu_err;								\
})

/* More complex copy from domain */
#define copy_from_user(to, from, n)	__copy_from_user((to), (from), (n))
#define copy_to_user(to, from, n)	__copy_to_user((to), (from), (n))
#define clear_user(to, n)		__clear_user((t0), (n))

static inline unsigned long
__copy_from_user(void *to, void *from, unsigned long n)
{
    unsigned long ma, i;

    i = n;
    while(!__domain_va_to_ma((unsigned long)from, &ma, &i)) {
	    memcpy(to, (void *)__va(ma), i);
	    n -= i;
        if (!n)
            break;
	    from += i;
	    to += i;
	    i = n;
    }
    return n;
}

static inline unsigned long
__copy_to_user(void *to, void *from, unsigned long n)
{
    unsigned long ma, i;

    i = n;
    while(!__domain_va_to_ma((unsigned long)to, &ma, &i)) {
	    memcpy((void *)__va(ma), from, i);
	    n -= i;
        if (!n)
            break;
	    from += i;
	    to += i;
	    i = n;
    }
    return n;
}

static inline unsigned long
__clear_user(void *to, unsigned long n)
{
    unsigned long ma, i;

    i = n;
    while(!__domain_va_to_ma((unsigned long)to, &ma, &i)) {
	    memset((void *)__va(ma), 0, i);
	    n -= i;
        if (!n)
            break;
	    to += i;
	    i = n;
    }
    return n;
}

#endif // __ASM_IA64_VMX_UACCESS_H__
