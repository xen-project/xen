/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain page frames into Xen space.
 */

#ifndef __ASM_DOMAIN_PAGE_H__
#define __ASM_DOMAIN_PAGE_H__

#include <xen/config.h>
#include <xen/sched.h>

extern unsigned long *mapcache;
#define MAPCACHE_ENTRIES        1024


//#define WATCH_MAP_DOMAIN_CALLERS 1
#ifdef WATCH_MAP_DOMAIN_CALLERS
extern int map_domain_mem_noisy;
#define map_domain_mem(__mdm_pa) (                                            \
{                                                                             \
    unsigned long _mdm_pa = (__mdm_pa);                                       \
    if ( map_domain_mem_noisy )                                               \
        printk("map_domain_mem(%p) @ %s:%d in %s\n",                          \
               _mdm_pa, __FILE__, __LINE__, __func__);                        \
    _map_domain_mem(_mdm_pa);                                                 \
})
#else
#define _map_domain_mem map_domain_mem
#endif

/*
 * Maps a given physical address, returning corresponding virtual address.
 * The entire page containing that VA is now accessible until a 
 * corresponding call to unmap_domain_mem().
 */
extern void *_map_domain_mem(unsigned long pa);

/*
 * Pass a VA within a page previously mapped with map_domain_mem().
 * That page will then be removed from the mapping lists.
 */
extern void unmap_domain_mem(void *va);

#endif /* __ASM_DOMAIN_PAGE_H__ */
