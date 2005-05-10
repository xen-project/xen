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
#define MAPCACHE_ENTRIES        1024

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

struct map_dom_mem_cache {
    unsigned long pa;
    void *va;
};

#define MAP_DOM_MEM_CACHE_INIT { .pa = 0 }

static inline void
init_map_domain_mem_cache(struct map_dom_mem_cache *cache)
{
    ASSERT(cache != NULL);
    *cache = MAP_DOM_MEM_CACHE_INIT;
}

static inline void *
map_domain_mem_with_cache(unsigned long pa, struct map_dom_mem_cache *cache)
{
    ASSERT(cache != NULL);

    if ( likely(cache->pa) )
    {
        if ( likely((pa & PAGE_MASK) == (cache->pa & PAGE_MASK)) )
            goto done;
        unmap_domain_mem(cache->va);
    }

    cache->pa = (pa & PAGE_MASK) | 1;
    cache->va = map_domain_mem(cache->pa);

 done:
    return (void *)(((unsigned long)cache->va & PAGE_MASK) |
                    (pa & ~PAGE_MASK));
}

static inline void
unmap_domain_mem_with_cache(void *va, struct map_dom_mem_cache *cache)
{
    ASSERT(cache != NULL);
    unmap_domain_mem(va);
}

static inline void
destroy_map_domain_mem_cache(struct map_dom_mem_cache *cache)
{
    ASSERT(cache != NULL);
    if ( likely(cache->pa) )
    {
        unmap_domain_mem(cache->va);
        cache->pa = 0;
    }
}

#endif /* __ASM_DOMAIN_PAGE_H__ */
