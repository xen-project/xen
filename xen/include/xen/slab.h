/*
 * Written by Mark Hemment, 1996.
 * (markhe@nextd.demon.co.uk)
 */

#ifndef __SLAB_H__
#define __SLAB_H__

typedef struct kmem_cache_s kmem_cache_t;

#include <xen/mm.h>
#include <xen/cache.h>

/* Flags to pass to kmem_cache_create(). */
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

extern void kmem_cache_init(void);
extern void kmem_cache_sizes_init(unsigned long);

extern kmem_cache_t *kmem_find_general_cachep(size_t);
extern kmem_cache_t *kmem_cache_create(
    const char *, size_t, size_t, unsigned long,
    void (*)(void *, kmem_cache_t *, unsigned long),
    void (*)(void *, kmem_cache_t *, unsigned long));
extern int kmem_cache_destroy(kmem_cache_t *);
extern int kmem_cache_shrink(kmem_cache_t *);
extern void *kmem_cache_alloc(kmem_cache_t *);
extern void kmem_cache_free(kmem_cache_t *, void *);

extern void *kmalloc(size_t);
extern void kfree(const void *);

extern int kmem_cache_reap(void);

extern void dump_slabinfo();

#endif /* __SLAB_H__ */
