#ifndef __X86_64_UACCESS_H
#define __X86_64_UACCESS_H

/*
 * User space memory access functions
 */
#include <xen/config.h>
#include <xen/compiler.h>
#include <xen/errno.h>
#include <xen/prefetch.h>
#include <asm/page.h>

#define __user

#define VERIFY_READ 0
#define VERIFY_WRITE 1

/*
 * Valid if in +ve half of 48-bit address space, or above Xen-reserved area.
 * This is also valid for range checks (addr, addr+size). As long as the
 * start address is outside the Xen-reserved area then we will access a
 * non-canonical address (and thus fault) before ever reaching VIRT_START.
 */
#define __addr_ok(addr) \
    (((unsigned long)(addr) < (1UL<<48)) || \
     ((unsigned long)(addr) >= HYPERVISOR_VIRT_END))

#define access_ok(type, addr, size) (__addr_ok(addr))

#define array_access_ok(type,addr,count,size) (__addr_ok(addr))

extern long __get_user_bad(void);
extern void __put_user_bad(void);

/**
 * get_user: - Get a simple variable from user space.
 * @x:   Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
#define get_user(x,ptr)	\
  __get_user_check((x),(ptr),sizeof(*(ptr)))

/**
 * put_user: - Write a simple value into user space.
 * @x:   Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define put_user(x,ptr)							\
  __put_user_check((__typeof__(*(ptr)))(x),(ptr),sizeof(*(ptr)))


/**
 * __get_user: - Get a simple variable from user space, with less checking.
 * @x:   Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
#define __get_user(x,ptr) \
  __get_user_nocheck((x),(ptr),sizeof(*(ptr)))


/**
 * __put_user: - Write a simple value into user space, with less checking.
 * @x:   Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define __put_user(x,ptr) \
  __put_user_nocheck((__typeof__(*(ptr)))(x),(ptr),sizeof(*(ptr)))

#define __put_user_nocheck(x,ptr,size)				\
({								\
	long __pu_err;						\
	__put_user_size((x),(ptr),(size),__pu_err,-EFAULT);	\
	__pu_err;						\
})

#define __put_user_check(x,ptr,size)					\
({									\
	long __pu_err = -EFAULT;					\
	__typeof__(*(ptr)) __user *__pu_addr = (ptr);			\
	if (__addr_ok(__pu_addr))					\
		__put_user_size((x),__pu_addr,(size),__pu_err,-EFAULT);	\
	__pu_err;							\
})							

#define __put_user_size(x,ptr,size,retval,errret)			\
do {									\
	retval = 0;							\
	switch (size) {							\
	case 1: __put_user_asm(x,ptr,retval,"b","b","iq",errret);break;	\
	case 2: __put_user_asm(x,ptr,retval,"w","w","ir",errret);break; \
	case 4: __put_user_asm(x,ptr,retval,"l","k","ir",errret);break;	\
	case 8: __put_user_asm(x,ptr,retval,"q","","ir",errret);break;	\
	default: __put_user_bad();					\
	}								\
} while (0)

struct __large_struct { unsigned long buf[100]; };
#define __m(x) (*(struct __large_struct *)(x))

/*
 * Tell gcc we read from memory instead of writing: this is because
 * we do not write to any memory gcc knows about, so there are no
 * aliasing issues.
 */
#define __put_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
	__asm__ __volatile__(						\
		"1:	mov"itype" %"rtype"1,%2\n"			\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"3:	mov %3,%0\n"					\
		"	jmp 2b\n"					\
		".previous\n"						\
		".section __ex_table,\"a\"\n"				\
		"	.align 8\n"					\
		"	.quad 1b,3b\n"					\
		".previous"						\
		: "=r"(err)						\
		: ltype (x), "m"(__m(addr)), "i"(errret), "0"(err))

#define __get_user_nocheck(x,ptr,size)				\
({								\
	long __gu_err, __gu_val;				\
	__get_user_size(__gu_val,(ptr),(size),__gu_err,-EFAULT);\
	(x) = (__typeof__(*(ptr)))__gu_val;			\
	__gu_err;						\
})

#define __get_user_check(x,ptr,size)					\
({									\
	long __gu_err, __gu_val;					\
	__typeof__(*(ptr)) __user *__gu_addr = (ptr);			\
	__get_user_size(__gu_val,__gu_addr,(size),__gu_err,-EFAULT);	\
	(x) = (__typeof__(*(ptr)))__gu_val;				\
	if (!__addr_ok(__gu_addr)) __gu_err = -EFAULT;			\
	__gu_err;							\
})							

#define __get_user_size(x,ptr,size,retval,errret)			\
do {									\
	retval = 0;							\
	switch (size) {							\
	case 1: __get_user_asm(x,ptr,retval,"b","b","=q",errret);break;	\
	case 2: __get_user_asm(x,ptr,retval,"w","w","=r",errret);break;	\
	case 4: __get_user_asm(x,ptr,retval,"l","k","=r",errret);break;	\
	case 8: __get_user_asm(x,ptr,retval,"q","","=r",errret); break;	\
	default: (x) = __get_user_bad();				\
	}								\
} while (0)

#define __get_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
	__asm__ __volatile__(						\
		"1:	mov"itype" %2,%"rtype"1\n"			\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"3:	mov %3,%0\n"					\
		"	xor"itype" %"rtype"1,%"rtype"1\n"		\
		"	jmp 2b\n"					\
		".previous\n"						\
		".section __ex_table,\"a\"\n"				\
		"	.align 8\n"					\
		"	.quad 1b,3b\n"					\
		".previous"						\
		: "=r"(err), ltype (x)					\
		: "m"(__m(addr)), "i"(errret), "0"(err))


/*
 * Copy To/From Userspace
 */

/* Handles exceptions in both to and from, but doesn't do access_ok */
unsigned long __copy_to_user_ll(void __user *to, const void *from, unsigned n);
unsigned long __copy_from_user_ll(void *to, const void __user *from, unsigned n);

unsigned long copy_to_user(void __user *to, const void *from, unsigned len); 
unsigned long copy_from_user(void *to, const void __user *from, unsigned len); 

static always_inline int __copy_from_user(void *dst, const void __user *src, unsigned size) 
{ 
    int ret = 0;
    if (!__builtin_constant_p(size))
        return __copy_from_user_ll(dst,(void *)src,size);
    switch (size) { 
    case 1:__get_user_asm(*(u8*)dst,(u8 __user *)src,ret,"b","b","=q",1); 
        return ret;
    case 2:__get_user_asm(*(u16*)dst,(u16 __user *)src,ret,"w","w","=r",2);
        return ret;
    case 4:__get_user_asm(*(u32*)dst,(u32 __user *)src,ret,"l","k","=r",4);
        return ret;
    case 8:__get_user_asm(*(u64*)dst,(u64 __user *)src,ret,"q","","=r",8);
        return ret; 
    case 10:
        __get_user_asm(*(u64*)dst,(u64 __user *)src,ret,"q","","=r",16);
        if (unlikely(ret)) return ret;
        __get_user_asm(*(u16*)(8+(char*)dst),(u16 __user *)(8+(char __user *)src),ret,"w","w","=r",2);
        return ret; 
    case 16:
        __get_user_asm(*(u64*)dst,(u64 __user *)src,ret,"q","","=r",16);
        if (unlikely(ret)) return ret;
        __get_user_asm(*(u64*)(8+(char*)dst),(u64 __user *)(8+(char __user *)src),ret,"q","","=r",8);
        return ret; 
    default:
        return __copy_from_user_ll(dst,(void *)src,size); 
    }
}	

static always_inline int __copy_to_user(void __user *dst, const void *src, unsigned size) 
{ 
    int ret = 0;
    if (!__builtin_constant_p(size))
        return __copy_to_user_ll((void *)dst,src,size);
    switch (size) { 
    case 1:__put_user_asm(*(u8*)src,(u8 __user *)dst,ret,"b","b","iq",1); 
        return ret;
    case 2:__put_user_asm(*(u16*)src,(u16 __user *)dst,ret,"w","w","ir",2);
        return ret;
    case 4:__put_user_asm(*(u32*)src,(u32 __user *)dst,ret,"l","k","ir",4);
        return ret;
    case 8:__put_user_asm(*(u64*)src,(u64 __user *)dst,ret,"q","","ir",8);
        return ret; 
    case 10:
        __put_user_asm(*(u64*)src,(u64 __user *)dst,ret,"q","","ir",10);
        if (unlikely(ret)) return ret;
        asm("":::"memory");
        __put_user_asm(4[(u16*)src],4+(u16 __user *)dst,ret,"w","w","ir",2);
        return ret; 
    case 16:
        __put_user_asm(*(u64*)src,(u64 __user *)dst,ret,"q","","ir",16);
        if (unlikely(ret)) return ret;
        asm("":::"memory");
        __put_user_asm(1[(u64*)src],1+(u64 __user *)dst,ret,"q","","ir",8);
        return ret; 
    default:
        return __copy_to_user_ll((void *)dst,src,size); 
    }
}	

unsigned long clear_user(void __user *mem, unsigned long len);
unsigned long __clear_user(void __user *mem, unsigned long len);

#endif /* __X86_64_UACCESS_H */
