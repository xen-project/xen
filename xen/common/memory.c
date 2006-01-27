/******************************************************************************
 * memory.c
 *
 * Code to handle memory-related requests.
 *
 * Copyright (c) 2003-2004, B Dragovic
 * Copyright (c) 2003-2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/shadow.h>
#include <xen/iocap.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#include <public/memory.h>

static long
increase_reservation(
    struct domain *d, 
    unsigned long *extent_list, 
    unsigned int   nr_extents,
    unsigned int   extent_order,
    unsigned int   flags,
    int           *preempted)
{
    struct pfn_info *page;
    unsigned long    i;

    if ( (extent_list != NULL) &&
         !array_access_ok(extent_list, nr_extents, sizeof(*extent_list)) )
        return 0;

    if ( (extent_order != 0) &&
         !multipage_allocation_permitted(current->domain) )
        return 0;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            *preempted = 1;
            return i;
        }

        if ( unlikely((page = alloc_domheap_pages(
            d, extent_order, flags)) == NULL) )
        {
            DPRINTK("Could not allocate order=%d extent: "
                    "id=%d flags=%x (%ld of %d)\n",
                    extent_order, d->domain_id, flags, i, nr_extents);
            return i;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( (extent_list != NULL) &&
             (__put_user(page_to_pfn(page), &extent_list[i]) != 0) )
            return i;
    }

    return nr_extents;
}
    
static long
populate_physmap(
    struct domain *d, 
    unsigned long *extent_list, 
    unsigned int   nr_extents,
    unsigned int   extent_order,
    unsigned int   flags,
    int           *preempted)
{
    struct pfn_info *page;
    unsigned long    i, j, pfn, mfn;

    if ( !array_access_ok(extent_list, nr_extents, sizeof(*extent_list)) )
        return 0;

    if ( (extent_order != 0) &&
         !multipage_allocation_permitted(current->domain) )
        return 0;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            *preempted = 1;
            return i;
        }

        if ( unlikely((page = alloc_domheap_pages(
            d, extent_order, flags)) == NULL) )
        {
            DPRINTK("Could not allocate order=%d extent: "
                    "id=%d flags=%x (%ld of %d)\n",
                    extent_order, d->domain_id, flags, i, nr_extents);
            return i;
        }

        mfn = page_to_pfn(page);

        if ( unlikely(__get_user(pfn, &extent_list[i]) != 0) )
            return i;

        for ( j = 0; j < (1 << extent_order); j++ )
            set_pfn_from_mfn(mfn + j, pfn + j);

        /* Inform the domain of the new page's machine address. */ 
        if ( __put_user(mfn, &extent_list[i]) != 0 )
            return i;
    }

    return nr_extents;
}
    
static long
decrease_reservation(
    struct domain *d, 
    unsigned long *extent_list, 
    unsigned int   nr_extents,
    unsigned int   extent_order,
    unsigned int   flags,
    int           *preempted)
{
    struct pfn_info *page;
    unsigned long    i, j, mfn;

    if ( !array_access_ok(extent_list, nr_extents, sizeof(*extent_list)) )
        return 0;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            *preempted = 1;
            return i;
        }

        if ( unlikely(__get_user(mfn, &extent_list[i]) != 0) )
            return i;

        for ( j = 0; j < (1 << extent_order); j++ )
        {
            if ( unlikely((mfn + j) >= max_page) )
            {
                DPRINTK("Domain %u page number out of range (%lx >= %lx)\n", 
                        d->domain_id, mfn + j, max_page);
                return i;
            }
            
            page = pfn_to_page(mfn + j);
            if ( unlikely(!get_page(page, d)) )
            {
                DPRINTK("Bad page free for domain %u\n", d->domain_id);
                return i;
            }

            if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
                put_page_and_type(page);
            
            if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
                put_page(page);

            shadow_sync_and_drop_references(d, page);

            put_page(page);
        }
    }

    return nr_extents;
}

/*
 * To allow safe resume of do_memory_op() after preemption, we need to know 
 * at what point in the page list to resume. For this purpose I steal the 
 * high-order bits of the @cmd parameter, which are otherwise unused and zero.
 */
#define START_EXTENT_SHIFT 4 /* cmd[:4] == start_extent */

long do_memory_op(int cmd, void *arg)
{
    struct domain *d;
    int rc, start_extent, op, flags = 0, preempted = 0;
    struct xen_memory_reservation reservation;
    domid_t domid;

    op = cmd & ((1 << START_EXTENT_SHIFT) - 1);

    switch ( op )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        if ( copy_from_user(&reservation, arg, sizeof(reservation)) )
            return -EFAULT;

        start_extent = cmd >> START_EXTENT_SHIFT;
        if ( unlikely(start_extent > reservation.nr_extents) )
            return -EINVAL;
        
        if ( reservation.extent_start != NULL )
            reservation.extent_start += start_extent;
        reservation.nr_extents -= start_extent;

        if ( (reservation.address_bits != 0) &&
             (reservation.address_bits <
              (get_order_from_pages(max_page) + PAGE_SHIFT)) )
        {
            if ( reservation.address_bits < 31 )
                return -ENOMEM;
            flags = ALLOC_DOM_DMA;
        }

        if ( likely(reservation.domid == DOMID_SELF) )
            d = current->domain;
        else if ( !IS_PRIV(current->domain) )
            return -EPERM;
        else if ( (d = find_domain_by_id(reservation.domid)) == NULL )
            return -ESRCH;

        switch ( op )
        {
        case XENMEM_increase_reservation:
            rc = increase_reservation(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                flags,
                &preempted);
            break;
        case XENMEM_decrease_reservation:
            rc = decrease_reservation(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                flags,
                &preempted);
            break;
        case XENMEM_populate_physmap:
        default:
            rc = populate_physmap(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                flags,
                &preempted);
            break;
        }

        if ( unlikely(reservation.domid != DOMID_SELF) )
            put_domain(d);

        rc += start_extent;

        if ( preempted )
            return hypercall2_create_continuation(
                __HYPERVISOR_memory_op, op | (rc << START_EXTENT_SHIFT), arg);

        break;

    case XENMEM_maximum_ram_page:
        rc = max_page;
        break;

    case XENMEM_current_reservation:
    case XENMEM_maximum_reservation:
        if ( get_user(domid, (domid_t *)arg) )
            return -EFAULT;

        if ( likely((domid = (unsigned long)arg) == DOMID_SELF) )
            d = current->domain;
        else if ( !IS_PRIV(current->domain) )
            return -EPERM;
        else if ( (d = find_domain_by_id(domid)) == NULL )
            return -ESRCH;

        rc = (op == XENMEM_current_reservation) ? d->tot_pages : d->max_pages;

        if ( unlikely(domid != DOMID_SELF) )
            put_domain(d);

        break;

    default:
        rc = arch_memory_op(op, arg);
        break;
    }

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
