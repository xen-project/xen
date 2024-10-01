
#ifndef __X86_UACCESS_H__
#define __X86_UACCESS_H__

#include <xen/compiler.h>
#include <xen/errno.h>
#include <xen/prefetch.h>
#include <asm/asm_defns.h>

#include <asm/x86_64/uaccess.h>

unsigned int copy_to_guest_pv(void __user *to, const void *from,
                              unsigned int n);
unsigned int clear_guest_pv(void __user *to, unsigned int n);
unsigned int copy_from_guest_pv(void *to, const void __user *from,
                                unsigned int n);

/* Handles exceptions in both to and from, but doesn't do access_ok */
unsigned int copy_to_guest_ll(void __user*to, const void *from, unsigned int n);
unsigned int copy_from_guest_ll(void *to, const void __user *from, unsigned int n);
unsigned int copy_to_unsafe_ll(void *to, const void *from, unsigned int n);
unsigned int copy_from_unsafe_ll(void *to, const void *from, unsigned int n);

void noreturn __get_user_bad(void);
void noreturn __put_user_bad(void);

#define UA_KEEP(args...) args
#define UA_DROP(args...)

/**
 * get_guest: - Get a simple variable from guest space.
 * @x:   Variable to store result.
 * @ptr: Source address, in guest space.
 *
 * This macro load a single simple variable from guest space.
 * It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
#define get_guest(x, ptr) get_guest_check(x, ptr, sizeof(*(ptr)))

/**
 * put_guest: - Write a simple value into guest space.
 * @x:   Value to store in guest space.
 * @ptr: Destination address, in guest space.
 *
 * This macro stores a single simple value from to guest space.
 * It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define put_guest(x, ptr) \
    put_guest_check((__typeof__(*(ptr)))(x), ptr, sizeof(*(ptr)))

/**
 * __get_guest: - Get a simple variable from guest space, with less checking.
 * @x:   Variable to store result.
 * @ptr: Source address, in guest space.
 *
 * This macro copies a single simple variable from guest space to hypervisor
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
#define __get_guest(x, ptr) get_guest_nocheck(x, ptr, sizeof(*(ptr)))

/**
 * __put_guest: - Write a simple value into guest space, with less checking.
 * @x:   Value to store in guest space.
 * @ptr: Destination address, in guest space.
 *
 * This macro copies a single simple value from hypervisor space to guest
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
#define __put_guest(x, ptr) \
    put_guest_nocheck((__typeof__(*(ptr)))(x), ptr, sizeof(*(ptr)))

#define put_unsafe(x, ptr)						\
({									\
	int err_; 							\
	put_unsafe_size(x, ptr, sizeof(*(ptr)), UA_DROP, err_, -EFAULT);\
	err_;								\
})

#define put_guest_nocheck(x, ptr, size)					\
({									\
	int err_; 							\
	put_guest_size(x, ptr, size, err_, -EFAULT);			\
	err_;								\
})

#define put_guest_check(x, ptr, size)					\
({									\
	__typeof__(*(ptr)) __user *ptr_ = (ptr);			\
	__typeof__(size) size_ = (size);				\
	access_ok(ptr_, size_) ? put_guest_nocheck(x, ptr_, size_)	\
			       : -EFAULT;				\
})

#define get_unsafe(x, ptr)						\
({									\
	int err_; 							\
	get_unsafe_size(x, ptr, sizeof(*(ptr)), UA_DROP, err_, -EFAULT);\
	err_;								\
})

#define get_guest_nocheck(x, ptr, size)					\
({									\
	int err_; 							\
	get_guest_size(x, ptr, size, err_, -EFAULT);			\
	err_;								\
})

#define get_guest_check(x, ptr, size)					\
({									\
	__typeof__(*(ptr)) __user *ptr_ = (ptr);			\
	__typeof__(size) size_ = (size);				\
	access_ok(ptr_, size_) ? get_guest_nocheck(x, ptr_, size_)	\
			       : -EFAULT;				\
})

struct __large_struct { unsigned long buf[100]; };
#define __m(x) (*(const struct __large_struct *)(x))

/*
 * Tell gcc we read from memory instead of writing: this is because
 * we do not write to any memory gcc knows about, so there are no
 * aliasing issues.
 */
#define put_unsafe_asm(x, addr, GUARD, err, itype, rtype, ltype, errret) \
	__asm__ __volatile__(						\
		GUARD(							\
		"	guest_access_mask_ptr %[ptr], %[scr1], %[scr2]\n" \
		)							\
		"1:	mov"itype" %"rtype"[val], (%[ptr])\n"		\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"3:	mov %[errno], %[ret]\n"				\
		"	jmp 2b\n"					\
		".previous\n"						\
		_ASM_EXTABLE(1b, 3b)					\
		: [ret] "+r" (err), [ptr] "=&r" (dummy_)		\
		  GUARD(, [scr1] "=&r" (dummy_), [scr2] "=&r" (dummy_))	\
		: [val] ltype (x), "m" (__m(addr)),			\
		  "[ptr]" (addr), [errno] "i" (errret))

#define get_unsafe_asm(x, addr, GUARD, err, rtype, ltype, errret)	\
	__asm__ __volatile__(						\
		GUARD(							\
		"	guest_access_mask_ptr %[ptr], %[scr1], %[scr2]\n" \
		)							\
		"1:	mov (%[ptr]), %"rtype"[val]\n"			\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"3:	mov %[errno], %[ret]\n"				\
		"	xor %k[val], %k[val]\n"				\
		"	jmp 2b\n"					\
		".previous\n"						\
		_ASM_EXTABLE(1b, 3b)					\
		: [ret] "+r" (err), [val] ltype (x),			\
		  [ptr] "=&r" (dummy_)					\
		  GUARD(, [scr1] "=&r" (dummy_), [scr2] "=&r" (dummy_))	\
		: "m" (__m(addr)), "[ptr]" (addr),			\
		  [errno] "i" (errret))

#define put_unsafe_size(x, ptr, size, grd, retval, errret)                 \
do {                                                                       \
    retval = 0;                                                            \
    stac();                                                                \
    switch ( size )                                                        \
    {                                                                      \
    long dummy_;                                                           \
    case 1:                                                                \
        put_unsafe_asm(x, ptr, grd, retval, "b", "b", "iq", errret);       \
        break;                                                             \
    case 2:                                                                \
        put_unsafe_asm(x, ptr, grd, retval, "w", "w", "ir", errret);       \
        break;                                                             \
    case 4:                                                                \
        put_unsafe_asm(x, ptr, grd, retval, "l", "k", "ir", errret);       \
        break;                                                             \
    case 8:                                                                \
        put_unsafe_asm(x, ptr, grd, retval, "q",  "", "ir", errret);       \
        break;                                                             \
    default: __put_user_bad();                                             \
    }                                                                      \
    clac();                                                                \
} while ( false )

#define put_guest_size(x, ptr, size, retval, errret) \
    put_unsafe_size(x, ptr, size, UA_KEEP, retval, errret)

#define get_unsafe_size(x, ptr, size, grd, retval, errret)                 \
do {                                                                       \
    retval = 0;                                                            \
    stac();                                                                \
    switch ( size )                                                        \
    {                                                                      \
    long dummy_;                                                           \
    case 1: get_unsafe_asm(x, ptr, grd, retval, "b", "=q", errret); break; \
    case 2: get_unsafe_asm(x, ptr, grd, retval, "w", "=r", errret); break; \
    case 4: get_unsafe_asm(x, ptr, grd, retval, "k", "=r", errret); break; \
    case 8: get_unsafe_asm(x, ptr, grd, retval,  "", "=r", errret); break; \
    default: __get_user_bad();                                             \
    }                                                                      \
    clac();                                                                \
} while ( false )

#define get_guest_size(x, ptr, size, retval, errret)                       \
    get_unsafe_size(x, ptr, size, UA_KEEP, retval, errret)

/**
 * __copy_to_guest_pv: - Copy a block of data into guest space, with less
 *                       checking
 * @to:   Destination address, in guest space.
 * @from: Source address, in hypervisor space.
 * @n:    Number of bytes to copy.
 *
 * Copy data from hypervisor space to guest space.  Caller must check
 * the specified block with access_ok() before calling this function.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 */
static always_inline unsigned long
__copy_to_guest_pv(void __user *to, const void *from, unsigned long n)
{
    if ( __builtin_constant_p(n) && !((unsigned long)to & (n - 1)) )
    {
        unsigned long ret;

        switch (n) {
        case 1:
            put_guest_size(*(const uint8_t *)from, to, 1, ret, 1);
            return ret;
        case 2:
            put_guest_size(*(const uint16_t *)from, to, 2, ret, 2);
            return ret;
        case 4:
            put_guest_size(*(const uint32_t *)from, to, 4, ret, 4);
            return ret;
        case 8:
            put_guest_size(*(const uint64_t *)from, to, 8, ret, 8);
            return ret;
        }
    }
    return copy_to_guest_ll(to, from, n);
}

/**
 * __copy_from_guest_pv: - Copy a block of data from guest space, with less
 *                         checking
 * @to:   Destination address, in hypervisor space.
 * @from: Source address, in guest space.
 * @n:    Number of bytes to copy.
 *
 * Copy data from guest space to hypervisor space.  Caller must check
 * the specified block with access_ok() before calling this function.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 *
 * If some data could not be copied, this function will pad the copied
 * data to the requested size using zero bytes.
 */
static always_inline unsigned long
__copy_from_guest_pv(void *to, const void __user *from, unsigned long n)
{
    if ( __builtin_constant_p(n) && !((unsigned long)from & (n - 1)) )
    {
        unsigned long ret;

        switch (n) {
        case 1:
            get_guest_size(*(uint8_t *)to, from, 1, ret, 1);
            return ret;
        case 2:
            get_guest_size(*(uint16_t *)to, from, 2, ret, 2);
            return ret;
        case 4:
            get_guest_size(*(uint32_t *)to, from, 4, ret, 4);
            return ret;
        case 8:
            get_guest_size(*(uint64_t *)to, from, 8, ret, 8);
            return ret;
        }
    }
    return copy_from_guest_ll(to, from, n);
}

/**
 * copy_to_unsafe: - Copy a block of data to unsafe space, with exception
 *                   checking
 * @to:   Unsafe destination address.
 * @from: Safe source address, in hypervisor space.
 * @n:    Number of bytes to copy.
 *
 * Copy data from hypervisor space to a potentially unmapped area.
 *
 * Returns zero on success and non-zero if some bytes could not be copied.
 */
static always_inline unsigned int
copy_to_unsafe(void __user *to, const void *from, unsigned int n)
{
    if (__builtin_constant_p(n)) {
        unsigned long ret;

        switch (n) {
        case 1:
            put_unsafe_size(*(const uint8_t *)from, to, 1, UA_DROP, ret, 1);
            return ret;
        case 2:
            put_unsafe_size(*(const uint16_t *)from, to, 2, UA_DROP, ret, 2);
            return ret;
        case 4:
            put_unsafe_size(*(const uint32_t *)from, to, 4, UA_DROP, ret, 4);
            return ret;
        case 8:
            put_unsafe_size(*(const uint64_t *)from, to, 8, UA_DROP, ret, 8);
            return ret;
        }
    }

    return copy_to_unsafe_ll(to, from, n);
}

/**
 * copy_from_unsafe: - Copy a block of data from unsafe space, with exception
 *                     checking
 * @to:   Safe destination address, in hypervisor space.
 * @from: Unsafe source address.
 * @n:    Number of bytes to copy.
 *
 * Copy data from a potentially unmapped area space to hypervisor space.
 *
 * Returns zero on success and non-zero if some bytes could not be copied.
 *
 * If some data could not be copied, this function will pad the copied
 * data to the requested size using zero bytes.
 */
static always_inline unsigned int
copy_from_unsafe(void *to, const void __user *from, unsigned int n)
{
    if ( __builtin_constant_p(n) )
    {
        unsigned long ret;

        switch ( n )
        {
        case 1:
            get_unsafe_size(*(uint8_t *)to, from, 1, UA_DROP, ret, 1);
            return ret;
        case 2:
            get_unsafe_size(*(uint16_t *)to, from, 2, UA_DROP, ret, 2);
            return ret;
        case 4:
            get_unsafe_size(*(uint32_t *)to, from, 4, UA_DROP, ret, 4);
            return ret;
        case 8:
            get_unsafe_size(*(uint64_t *)to, from, 8, UA_DROP, ret, 8);
            return ret;
        }
    }

    return copy_from_unsafe_ll(to, from, n);
}

/*
 * The exception table consists of pairs of addresses: the first is the
 * address of an instruction that is allowed to fault, and the second is
 * the address at which the program should continue.  No registers are
 * modified, so it is entirely up to the continuation code to figure out
 * what to do.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 */

struct exception_table_entry
{
	int32_t addr, cont;
};
extern struct exception_table_entry __start___ex_table[];
extern struct exception_table_entry __stop___ex_table[];
extern struct exception_table_entry __start___pre_ex_table[];
extern struct exception_table_entry __stop___pre_ex_table[];

union stub_exception_token {
    struct {
        uint16_t ec;
        uint8_t trapnr;
    } fields;
    unsigned long raw;
};

extern unsigned long search_exception_table(const struct cpu_user_regs *regs,
                                            unsigned long *stub_ra);
extern void sort_exception_tables(void);
extern void sort_exception_table(struct exception_table_entry *start,
                                 const struct exception_table_entry *stop);

#endif /* __X86_UACCESS_H__ */
