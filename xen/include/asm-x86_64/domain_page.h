/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain page frames into Xen space.
 */

#ifndef __ASM_DOMAIN_PAGE_H__
#define __ASM_DOMAIN_PAGE_H__

#include <xeno/config.h>
#include <xeno/sched.h>
#include <asm/page.h>

/*
 * Maps a given physical address, returning corresponding virtual address.
 * The entire page containing that VA is now accessible until a 
 * corresponding call to unmap_domain_mem().
 */
#define map_domain_mem(pa) __va(pa)

/*
 * Pass a VA within a page previously mapped with map_domain_mem().
 * That page will then be removed from the mapping lists.
 */
#define unmap_domain_mem(va) {}

#endif /* __ASM_DOMAIN_PAGE_H__ */
