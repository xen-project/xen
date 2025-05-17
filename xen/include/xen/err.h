#ifndef XEN_ERR_H
#define XEN_ERR_H

#ifndef __ASSEMBLY__

#include <xen/compiler.h>
#include <xen/errno.h>

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a dentry
 * pointer with the same return value.
 *
 * This could be a per-architecture thing, to allow different
 * error and pointer decisions.
 */
#define MAX_ERRNO	4095

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void *__must_check ERR_PTR(long error)
{
	return (void *)error;
}

static inline long __must_check PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline long __must_check IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long __must_check IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline int __must_check PTR_RET(const void *ptr)
{
	return IS_ERR(ptr) ? PTR_ERR(ptr) : 0;
}

#endif /* __ASSEMBLY__ */

#endif /* XEN_ERR_H */
