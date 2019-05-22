#ifndef __ASM_ARM32_CMPXCHG_H
#define __ASM_ARM32_CMPXCHG_H

#include <xen/prefetch.h>

extern void __bad_xchg(volatile void *, int);

static inline unsigned long __xchg(unsigned long x, volatile void *ptr, int size)
{
	unsigned long ret;
	unsigned int tmp;

	smp_mb();
	prefetchw((const void *)ptr);

	switch (size) {
	case 1:
		asm volatile("@	__xchg1\n"
		"1:	ldrexb	%0, [%3]\n"
		"	strexb	%1, %2, [%3]\n"
		"	teq	%1, #0\n"
		"	bne	1b"
			: "=&r" (ret), "=&r" (tmp)
			: "r" (x), "r" (ptr)
			: "memory", "cc");
		break;
	case 4:
		asm volatile("@	__xchg4\n"
		"1:	ldrex	%0, [%3]\n"
		"	strex	%1, %2, [%3]\n"
		"	teq	%1, #0\n"
		"	bne	1b"
			: "=&r" (ret), "=&r" (tmp)
			: "r" (x), "r" (ptr)
			: "memory", "cc");
		break;
	default:
		__bad_xchg(ptr, size), ret = 0;
		break;
	}
	smp_mb();

	return ret;
}

#define xchg(ptr,x) \
	((__typeof__(*(ptr)))__xchg((unsigned long)(x),(ptr),sizeof(*(ptr))))

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */

extern unsigned long __bad_cmpxchg(volatile void *ptr, int size);

#define __CMPXCHG_CASE(sz, name)					\
static inline bool __cmpxchg_case_##name(volatile void *ptr,		\
					 unsigned long *old,		\
					 unsigned long new,		\
					 bool timeout,			\
					 unsigned int max_try)		\
{									\
	unsigned long oldval;						\
	unsigned long res;						\
									\
	do {								\
		asm volatile("@ __cmpxchg_case_" #name "\n"		\
		"	ldrex" #sz "	%1, [%2]\n"			\
		"	mov	%0, #0\n"				\
		"	teq	%1, %3\n"				\
		"	strex" #sz "eq %0, %4, [%2]\n"			\
		: "=&r" (res), "=&r" (oldval)				\
		: "r" (ptr), "Ir" (*old), "r" (new)			\
		: "memory", "cc");					\
									\
		if (!res)						\
			break;						\
	} while (!timeout || ((--max_try) > 0));			\
									\
	*old = oldval;							\
									\
	return !res;							\
}

__CMPXCHG_CASE(b, 1)
__CMPXCHG_CASE(h, 2)
__CMPXCHG_CASE( , 4)

static always_inline bool __int_cmpxchg(volatile void *ptr, unsigned long *old,
					unsigned long new, int size,
					bool timeout, unsigned int max_try)
{
	prefetchw((const void *)ptr);

	switch (size) {
	case 1:
		return __cmpxchg_case_1(ptr, old, new, timeout, max_try);
	case 2:
		return __cmpxchg_case_2(ptr, old, new, timeout, max_try);
	case 4:
		return __cmpxchg_case_4(ptr, old, new, timeout, max_try);
	default:
		return __bad_cmpxchg(ptr, size);
	}

	ASSERT_UNREACHABLE();
}

static always_inline unsigned long __cmpxchg(volatile void *ptr,
					     unsigned long old,
					     unsigned long new,
					     int size)
{
	if (!__int_cmpxchg(ptr, &old, new, size, false, 0))
		ASSERT_UNREACHABLE();

	return old;
}

static always_inline unsigned long __cmpxchg_mb(volatile void *ptr,
                                                unsigned long old,
                                                unsigned long new, int size)
{
	unsigned long ret;

	smp_mb();
	ret = __cmpxchg(ptr, old, new, size);
	smp_mb();

	return ret;
}

/*
 * The helper may fail to update the memory if the action takes too long.
 *
 * @old: On call the value pointed contains the expected old value. It will be
 * updated to the actual old value.
 * @max_try: Maximum number of iterations
 *
 * The helper will return true when the update has succeeded (i.e no
 * timeout) and false if the update has failed.
 */
static always_inline bool __cmpxchg_mb_timeout(volatile void *ptr,
					       unsigned long *old,
					       unsigned long new,
					       int size,
					       unsigned int max_try)
{
	return __int_cmpxchg(ptr, old, new, size, true, max_try);
}

#define cmpxchg(ptr,o,n)						\
	((__typeof__(*(ptr)))__cmpxchg_mb((ptr),			\
					  (unsigned long)(o),		\
					  (unsigned long)(n),		\
					  sizeof(*(ptr))))

#define cmpxchg_local(ptr,o,n)						\
	((__typeof__(*(ptr)))__cmpxchg((ptr),				\
				       (unsigned long)(o),		\
				       (unsigned long)(n),		\
				       sizeof(*(ptr))))
#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
