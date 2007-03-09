/******************************************************************************
 * include/xen/mm.h
 * 
 * Definitions for memory pages, frame numbers, addresses, allocations, etc.
 * 
 * Note that Xen must handle several different physical 'address spaces' and
 * there is a consistent terminology for these:
 * 
 * 1. gpfn/gpaddr: A guest-specific pseudo-physical frame number or address.
 * 2. gmfn/gmaddr: A machine address from the p.o.v. of a particular guest.
 * 3. mfn/maddr:   A real machine frame number or address.
 * 4. pfn/paddr:   Used in 'polymorphic' functions that work across all
 *                 address spaces, depending on context. See the pagetable
 *                 conversion macros in asm-x86/page.h for examples.
 *                 Also 'paddr_t' is big enough to store any physical address.
 * 
 * This scheme provides consistent function and variable names even when
 * different guests are running in different memory-management modes.
 * 1. A guest running in auto-translated mode (e.g., shadow_mode_translate())
 *    will have gpfn == gmfn and gmfn != mfn.
 * 2. A paravirtualised x86 guest will have gpfn != gmfn and gmfn == mfn.
 * 3. A paravirtualised guest with no pseudophysical overlay will have
 *    gpfn == gpmfn == mfn.
 * 
 * Copyright (c) 2002-2006, K A Fraser <keir@xensource.com>
 */

#ifndef __XEN_MM_H__
#define __XEN_MM_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>

struct domain;
struct page_info;

/* Boot-time allocator. Turns into generic allocator after bootstrap. */
paddr_t init_boot_allocator(paddr_t bitmap_start);
void init_boot_pages(paddr_t ps, paddr_t pe);
unsigned long alloc_boot_pages(
    unsigned long nr_pfns, unsigned long pfn_align);
unsigned long alloc_boot_low_pages(
    unsigned long nr_pfns, unsigned long pfn_align);
int reserve_boot_pages(unsigned long first_pfn, unsigned long nr_pfns);
void end_boot_allocator(void);

/* Xen suballocator. These functions are interrupt-safe. */
void init_xenheap_pages(paddr_t ps, paddr_t pe);
void *alloc_xenheap_pages(unsigned int order);
void free_xenheap_pages(void *v, unsigned int order);
#define alloc_xenheap_page() (alloc_xenheap_pages(0))
#define free_xenheap_page(v) (free_xenheap_pages(v,0))

/* Domain suballocator. These functions are *not* interrupt-safe.*/
void init_domheap_pages(paddr_t ps, paddr_t pe);
struct page_info *alloc_domheap_pages(
    struct domain *d, unsigned int order, unsigned int memflags);
struct page_info *__alloc_domheap_pages(
    struct domain *d, unsigned int cpu, unsigned int order, 
    unsigned int memflags);
void free_domheap_pages(struct page_info *pg, unsigned int order);
unsigned long avail_domheap_pages(void);
#define alloc_domheap_page(d) (alloc_domheap_pages(d,0,0))
#define free_domheap_page(p)  (free_domheap_pages(p,0))

void scrub_heap_pages(void);

int assign_pages(
    struct domain *d,
    struct page_info *pg,
    unsigned int order,
    unsigned int memflags);

/* memflags: */
#define _MEMF_no_refcount 0
#define  MEMF_no_refcount (1U<<_MEMF_no_refcount)
#define _MEMF_bits        24
#define  MEMF_bits(n)     ((n)<<_MEMF_bits)

#ifdef CONFIG_PAGEALLOC_MAX_ORDER
#define MAX_ORDER CONFIG_PAGEALLOC_MAX_ORDER
#else
#define MAX_ORDER 20 /* 2^20 contiguous pages */
#endif

/* Automatic page scrubbing for dead domains. */
extern struct list_head page_scrub_list;
#define page_scrub_schedule_work()              \
    do {                                        \
        if ( !list_empty(&page_scrub_list) )    \
            raise_softirq(PAGE_SCRUB_SOFTIRQ);  \
    } while ( 0 )
#define page_scrub_kick()                                               \
    do {                                                                \
        if ( !list_empty(&page_scrub_list) )                            \
            cpumask_raise_softirq(cpu_online_map, PAGE_SCRUB_SOFTIRQ);  \
    } while ( 0 )
unsigned long avail_scrub_pages(void);

#include <asm/mm.h>

int guest_remove_page(struct domain *d, unsigned long gmfn);

/* Returns TRUE if the memory at address @p is ordinary RAM. */
int memory_is_conventional_ram(paddr_t p);

#endif /* __XEN_MM_H__ */
