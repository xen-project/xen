/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain page frames into Xen space.
 */

#ifndef __ASM_DOMAIN_PAGE_H__
#define __ASM_DOMAIN_PAGE_H__

#include <xen/config.h>
#include <xen/sched.h>

extern l1_pgentry_t *mapcache;
#define MAPCACHE_ORDER    10
#define MAPCACHE_ENTRIES  (1 << MAPCACHE_ORDER)

/*
 * Maps a given physical address, returning corresponding virtual address.
 * The entire page containing that VA is now accessible until a 
 * corresponding call to unmap_domain_mem().
 */
extern void *map_domain_mem(unsigned long pa);

/*
 * Pass a VA within a page previously mapped with map_domain_mem().
 * That page will then be removed from the mapping lists.
 */
extern void unmap_domain_mem(void *va);

#define DMCACHE_ENTRY_VALID 1UL
#define DMCACHE_ENTRY_HELD  2UL

struct domain_mmap_cache {
    unsigned long pa;
    void *va;
};

static inline void
domain_mmap_cache_init(struct domain_mmap_cache *cache)
{
    ASSERT(cache != NULL);
    cache->pa = 0;
}

static inline void *
map_domain_mem_with_cache(unsigned long pa, struct domain_mmap_cache *cache)
{
    ASSERT(cache != NULL);
    BUG_ON(cache->pa & DMCACHE_ENTRY_HELD);

    if ( likely(cache->pa) )
    {
        cache->pa |= DMCACHE_ENTRY_HELD;
        if ( likely((pa & PAGE_MASK) == (cache->pa & PAGE_MASK)) )
            goto done;
        unmap_domain_mem(cache->va);
    }

    cache->pa = (pa & PAGE_MASK) | DMCACHE_ENTRY_HELD | DMCACHE_ENTRY_VALID;
    cache->va = map_domain_mem(cache->pa);

 done:
    return (void *)(((unsigned long)cache->va & PAGE_MASK) |
                    (pa & ~PAGE_MASK));
}

static inline void
unmap_domain_mem_with_cache(void *va, struct domain_mmap_cache *cache)
{
    ASSERT(cache != NULL);
    cache->pa &= ~DMCACHE_ENTRY_HELD;
}

static inline void
domain_mmap_cache_destroy(struct domain_mmap_cache *cache)
{
    ASSERT(cache != NULL);
    if ( likely(cache->pa) )
    {
        unmap_domain_mem(cache->va);
        cache->pa = 0;
    }
}

#endif /* __ASM_DOMAIN_PAGE_H__ */
