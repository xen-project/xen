/******************************************************************************
 * dom_mem_ops.c
 *
 * Code to handle memory related requests from domains eg. balloon driver.
 *
 * Copyright (c) 2003-2004, B Dragovic & K A Fraser.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/domain_page.h>

static long alloc_dom_mem(struct domain *d, 
                          unsigned long *pages, 
                          unsigned long  nr_pages)
{
    struct pfn_info *page;
    unsigned long    i;

    for ( i = 0; i < nr_pages; i++ )
    {
        if ( unlikely((page = alloc_domheap_page(d)) == NULL) )
        {
            DPRINTK("Could not allocate a frame\n");
            break;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( unlikely(put_user(page_to_pfn(page), &pages[i]) != 0) )
            break;
    }

    return i;
}
    
static long free_dom_mem(struct domain *d, 
                         unsigned long *pages, 
                         unsigned long  nr_pages)
{
    struct pfn_info *page;
    unsigned long    i, mpfn;
    long             rc = 0;

    for ( i = 0; i < nr_pages; i++ )
    {
        if ( unlikely(get_user(mpfn, &pages[i]) != 0) )
            break;

        if ( unlikely(mpfn >= max_page) )
        {
            DPRINTK("Domain %u page number out of range (%08lx>=%08lx)\n", 
                    d->domain, mpfn, max_page);
            rc = -EINVAL;
            break;
        }

        page = &frame_table[mpfn];
        if ( unlikely(!get_page(page, d)) )
        {
            DPRINTK("Bad page free for domain %u\n", d->domain);
            rc = -EINVAL;
            break;
        }

        if ( test_and_clear_bit(_PGC_guest_pinned, &page->u.inuse.count_info) )
            put_page_and_type(page);

        if ( test_and_clear_bit(_PGC_allocated, &page->u.inuse.count_info) )
            put_page(page);

        put_page(page);
    }

    return rc ? rc : nr_pages;
}
    
long do_dom_mem_op(unsigned int op, void *pages, unsigned long nr_pages)
{
    if ( op == MEMOP_increase_reservation )
        return alloc_dom_mem(current, pages, nr_pages);

    if ( op == MEMOP_decrease_reservation )
        return free_dom_mem(current, pages, nr_pages);

    return -ENOSYS;
}
