/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
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

/*
 * To allow safe resume of do_dom_mem_op() after preemption, we need to know 
 * at what point in the page list to resume. For this purpose I steal the 
 * high-order bits of the @op parameter, which are otherwise unused and zero.
 */
#define START_EXTENT_SHIFT 4 /* op[:4] == start_extent */

#define PREEMPT_CHECK(_op)                          \
    if ( hypercall_preempt_check() )                \
        return hypercall_create_continuation(       \
            __HYPERVISOR_dom_mem_op, 5,             \
            (_op) | (i << START_EXTENT_SHIFT),      \
            extent_list, nr_extents, extent_order,  \
            (d == current->domain) ? DOMID_SELF : d->id);

static long
alloc_dom_mem(struct domain *d, 
              unsigned long *extent_list, 
              unsigned long  start_extent,
              unsigned long  nr_extents,
              unsigned int   extent_order)
{
    struct pfn_info *page;
    unsigned long    i;

    if ( unlikely(!array_access_ok(VERIFY_WRITE, extent_list, 
                                   nr_extents, sizeof(*extent_list))) )
        return start_extent;

    if ( (extent_order != 0) && !IS_CAPABLE_PHYSDEV(current->domain) )
    {
        DPRINTK("Only I/O-capable domains may allocate > order-0 memory.\n");
        return start_extent;
    }

    for ( i = start_extent; i < nr_extents; i++ )
    {
        PREEMPT_CHECK(MEMOP_increase_reservation);

        if ( unlikely((page = alloc_domheap_pages(d, extent_order)) == NULL) )
        {
            DPRINTK("Could not allocate a frame\n");
            return i;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( unlikely(__put_user(page_to_pfn(page), &extent_list[i]) != 0) )
            return i;
    }

    return i;
}
    
static long
free_dom_mem(struct domain *d,
             unsigned long *extent_list, 
             unsigned long  start_extent,
             unsigned long  nr_extents,
             unsigned int   extent_order)
{
    struct pfn_info *page;
    unsigned long    i, j, mpfn;

    if ( unlikely(!array_access_ok(VERIFY_READ, extent_list, 
                                   nr_extents, sizeof(*extent_list))) )
        return start_extent;

    for ( i = start_extent; i < nr_extents; i++ )
    {
        PREEMPT_CHECK(MEMOP_decrease_reservation);

        if ( unlikely(__get_user(mpfn, &extent_list[i]) != 0) )
            return i;

        for ( j = 0; j < (1 << extent_order); j++ )
        {
            if ( unlikely((mpfn + j) >= max_page) )
            {
                DPRINTK("Domain %u page number out of range (%08lx>=%08lx)\n", 
                        d->id, mpfn + j, max_page);
                return i;
            }
            
            page = &frame_table[mpfn + j];
            if ( unlikely(!get_page(page, d)) )
            {
                DPRINTK("Bad page free for domain %u\n", d->id);
                return i;
            }

            if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
                put_page_and_type(page);
            
            if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
                put_page(page);

            put_page(page);
        }
    }

    return i;
}

long
do_dom_mem_op(unsigned long  op, 
              unsigned long *extent_list, 
              unsigned long  nr_extents,
              unsigned int   extent_order,
              domid_t        domid)
{
    struct domain *d;
    unsigned long  rc, start_extent;

    /* Extract @start_extent from @op. */
    start_extent  = op >> START_EXTENT_SHIFT;
    op           &= (1 << START_EXTENT_SHIFT) - 1;

    if ( unlikely(start_extent > nr_extents) || 
         unlikely(nr_extents > (~0UL >> START_EXTENT_SHIFT)) )
        return -EINVAL;

    if ( likely(domid == DOMID_SELF) )
        d = current->domain;
    else if ( unlikely(!IS_PRIV(current->domain)) )
        return -EPERM;
    else if ( unlikely((d = find_domain_by_id(domid)) == NULL) )
        return -ESRCH;

    LOCK_BIGLOCK(d);

    switch ( op )
    {
    case MEMOP_increase_reservation:
        rc = alloc_dom_mem(
            d, extent_list, start_extent, nr_extents, extent_order);
        break;
    case MEMOP_decrease_reservation:
        rc = free_dom_mem(
            d, extent_list, start_extent, nr_extents, extent_order);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    if ( unlikely(domid != DOMID_SELF) )
        put_domain(d);

    UNLOCK_BIGLOCK(d);

    return rc;
}
