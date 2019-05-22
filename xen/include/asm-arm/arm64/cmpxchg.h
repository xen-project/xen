#ifndef __ASM_ARM64_CMPXCHG_H
#define __ASM_ARM64_CMPXCHG_H

extern void __bad_xchg(volatile void *, int);

static inline unsigned long __xchg(unsigned long x, volatile void *ptr, int size)
{
	unsigned long ret, tmp;

	switch (size) {
	case 1:
		asm volatile("//	__xchg1\n"
		"1:	ldxrb	%w0, %2\n"
		"	stlxrb	%w1, %w3, %2\n"
		"	cbnz	%w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(u8 *)ptr)
			: "r" (x)
			: "memory");
		break;
	case 2:
		asm volatile("//	__xchg2\n"
		"1:	ldxrh	%w0, %2\n"
		"	stlxrh	%w1, %w3, %2\n"
		"	cbnz	%w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(u16 *)ptr)
			: "r" (x)
			: "memory");
		break;
	case 4:
		asm volatile("//	__xchg4\n"
		"1:	ldxr	%w0, %2\n"
		"	stlxr	%w1, %w3, %2\n"
		"	cbnz	%w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(u32 *)ptr)
			: "r" (x)
			: "memory");
		break;
	case 8:
		asm volatile("//	__xchg8\n"
		"1:	ldxr	%0, %2\n"
		"	stlxr	%w1, %3, %2\n"
		"	cbnz	%w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(u64 *)ptr)
			: "r" (x)
			: "memory");
		break;
	default:
		__bad_xchg(ptr, size), ret = 0;
		break;
	}

	smp_mb();
	return ret;
}

#define xchg(ptr,x) \
({ \
	__typeof__(*(ptr)) __ret; \
	__ret = (__typeof__(*(ptr))) \
		__xchg((unsigned long)(x), (ptr), sizeof(*(ptr))); \
	__ret; \
})

extern unsigned long __bad_cmpxchg(volatile void *ptr, int size);

#define __CMPXCHG_CASE(w, sz, name)					\
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
		asm volatile("// __cmpxchg_case_" #name "\n"		\
		"	ldxr" #sz "	%" #w "1, %2\n"			\
		"	mov	%w0, #0\n"				\
		"	cmp	%" #w "1, %" #w "3\n"			\
		"	b.ne	1f\n"					\
		"	stxr" #sz "	%w0, %" #w "4, %2\n"		\
		"1:\n"							\
		: "=&r" (res), "=&r" (oldval),				\
		  "+Q" (*(unsigned long *)ptr)				\
		: "Ir" (*old), "r" (new)				\
		: "cc");						\
									\
		if (!res)						\
			break;						\
	} while (!timeout || ((--max_try) > 0));			\
									\
	*old = oldval;							\
									\
	return !res;							\
}

__CMPXCHG_CASE(w, b, 1)
__CMPXCHG_CASE(w, h, 2)
__CMPXCHG_CASE(w,  , 4)
__CMPXCHG_CASE( ,  , 8)

static always_inline bool __int_cmpxchg(volatile void *ptr, unsigned long *old,
					unsigned long new, int size,
					bool timeout, unsigned int max_try)
{
	switch (size) {
	case 1:
		return __cmpxchg_case_1(ptr, old, new, timeout, max_try);
	case 2:
		return __cmpxchg_case_2(ptr, old, new, timeout, max_try);
	case 4:
		return __cmpxchg_case_4(ptr, old, new, timeout, max_try);
	case 8:
		return __cmpxchg_case_8(ptr, old, new, timeout, max_try);
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

#define cmpxchg(ptr, o, n) \
({ \
	__typeof__(*(ptr)) __ret; \
	__ret = (__typeof__(*(ptr))) \
		__cmpxchg_mb((ptr), (unsigned long)(o), (unsigned long)(n), \
			     sizeof(*(ptr))); \
	__ret; \
})

#define cmpxchg_local(ptr, o, n) \
({ \
	__typeof__(*(ptr)) __ret; \
	__ret = (__typeof__(*(ptr))) \
		__cmpxchg((ptr), (unsigned long)(o), \
			  (unsigned long)(n), sizeof(*(ptr))); \
	__ret; \
})

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
