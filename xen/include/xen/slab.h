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

typedef struct xmem_cache_s xmem_cache_t;

#include <xen/mm.h>
#include <xen/cache.h>

/* Flags to pass to xmem_cache_create(). */
/* NB. The first 3 are only valid when built with SLAB_DEBUG_SUPPORT. */
#define SLAB_DEBUG_INITIAL      0x00000200UL    /* Call constructor */
#define SLAB_RED_ZONE           0x00000400UL    /* Red zone objs in a cache */
#define SLAB_POISON             0x00000800UL    /* Poison objects */
#define SLAB_NO_REAP            0x00001000UL    /* never reap from the cache */
#define SLAB_HWCACHE_ALIGN      0x00002000UL    /* align obj on a cache line */

/* Flags passed to a constructor function. */
#define SLAB_CTOR_CONSTRUCTOR   0x001UL /* if not set, then deconstructor */
#define SLAB_CTOR_ATOMIC        0x002UL /* tell cons. it can't sleep */
#define SLAB_CTOR_VERIFY        0x004UL /* tell cons. it's a verify call */

extern void xmem_cache_init(void);
extern void xmem_cache_sizes_init(unsigned long);

extern xmem_cache_t *xmem_find_general_cachep(size_t);
extern xmem_cache_t *xmem_cache_create(
    const char *, size_t, size_t, unsigned long,
    void (*)(void *, xmem_cache_t *, unsigned long),
    void (*)(void *, xmem_cache_t *, unsigned long));
extern int xmem_cache_destroy(xmem_cache_t *);
extern int xmem_cache_shrink(xmem_cache_t *);
extern void *xmem_cache_alloc(xmem_cache_t *);
extern void xmem_cache_free(xmem_cache_t *, void *);

extern void *xmalloc(size_t);
extern void xfree(const void *);

extern int xmem_cache_reap(void);

extern void dump_slabinfo();

#endif /* __ARCH_HAS_SLAB_ALLOCATOR */

#endif /* __SLAB_H__ */
