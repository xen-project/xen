/*
 * Written by Mark Hemment, 1996.
 * (markhe@nextd.demon.co.uk)
 */

#ifndef __SLAB_H__
#define __SLAB_H__

#include <xen/config.h>

#ifdef __ARCH_HAS_SLAB_ALLOCATOR

#include <asm/slab.h>

#else
#include <xen/mm.h>
#include <xen/cache.h>
#include <xen/types.h>

#define _xmalloc(size) __xmalloc(size, __FILE__, __LINE__)
#define xfree(ptr) __xfree(ptr, __FILE__, __LINE__)
extern void *__xmalloc(size_t size, const char *file, unsigned int line);
extern void __xfree(const void *p, const char *file, unsigned int line);

/* Nicely typesafe for you. */
#define xmalloc(type) ((type *)_xmalloc(sizeof(type)))
#define xmalloc_array(type, num) ((type *)_xmalloc_array(sizeof(type), (num)))

static inline void *_xmalloc_array(size_t size, size_t num)
{
	/* Check for overflow. */
	if (size && num > UINT_MAX / size)
		return NULL;
	return _xmalloc(size * num);
}
#endif /* __ARCH_HAS_SLAB_ALLOCATOR */

#endif /* __SLAB_H__ */
