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
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#include <public/memory.h>

/*
 * To allow safe resume of do_memory_op() after preemption, we need to know 
 * at what point in the page list to resume. For this purpose I steal the 
 * high-order bits of the @cmd parameter, which are otherwise unused and zero.
 */
#define START_EXTENT_SHIFT 4 /* cmd[:4] == start_extent */

static long
increase_reservation(
    struct domain *d, 
    XEN_GUEST_HANDLE(xen_pfn_t) extent_list,
    unsigned int   nr_extents,
    unsigned int   extent_order,
    unsigned int   memflags,
    int           *preempted)
{
    struct page_info *page;
    unsigned long i;
    xen_pfn_t mfn;

    if ( !guest_handle_is_null(extent_list) &&
         !guest_handle_okay(extent_list, nr_extents) )
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
            d, extent_order, memflags)) == NULL) )
        {
            DPRINTK("Could not allocate order=%d extent: "
                    "id=%d memflags=%x (%ld of %d)\n",
                    extent_order, d->domain_id, memflags, i, nr_extents);
            return i;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( !guest_handle_is_null(extent_list) )
        {
            mfn = page_to_mfn(page);
            if ( unlikely(__copy_to_guest_offset(extent_list, i, &mfn, 1)) )
                return i;
        }
    }

    return nr_extents;
}

static long
populate_physmap(
    struct domain *d, 
    XEN_GUEST_HANDLE(xen_pfn_t) extent_list,
    unsigned int  nr_extents,
    unsigned int  extent_order,
    unsigned int  memflags,
    int          *preempted)
{
    struct page_info *page;
    unsigned long i, j;
    xen_pfn_t gpfn;
    xen_pfn_t mfn;

    if ( !guest_handle_okay(extent_list, nr_extents) )
        return 0;

    if ( (extent_order != 0) &&
         !multipage_allocation_permitted(current->domain) )
        return 0;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            *preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, extent_list, i, 1)) )
            goto out;

        if ( unlikely((page = alloc_domheap_pages(
            d, extent_order, memflags)) == NULL) )
        {
            DPRINTK("Could not allocate order=%d extent: "
                    "id=%d memflags=%x (%ld of %d)\n",
                    extent_order, d->domain_id, memflags, i, nr_extents);
            goto out;
        }

        mfn = page_to_mfn(page);

        if ( unlikely(shadow_mode_translate(d)) )
        {
            for ( j = 0; j < (1 << extent_order); j++ )
                guest_physmap_add_page(d, gpfn + j, mfn + j);
        }
        else
        {
            for ( j = 0; j < (1 << extent_order); j++ )
                set_gpfn_from_mfn(mfn + j, gpfn + j);

            /* Inform the domain of the new page's machine address. */ 
            if ( unlikely(__copy_to_guest_offset(extent_list, i, &mfn, 1)) )
                goto out;
        }
    }

 out:
    return i;
}

int
guest_remove_page(
    struct domain *d,
    unsigned long gmfn)
{
    struct page_info *page;
    unsigned long mfn;

    mfn = gmfn_to_mfn(d, gmfn);
    if ( unlikely(!mfn_valid(mfn)) )
    {
        DPRINTK("Domain %u page number %lx invalid\n",
                d->domain_id, mfn);
        return 0;
    }
            
    page = mfn_to_page(mfn);
    if ( unlikely(!get_page(page, d)) )
    {
        DPRINTK("Bad page free for domain %u\n", d->domain_id);
        return 0;
    }

    if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
        put_page_and_type(page);
            
    if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
        put_page(page);

    if ( unlikely(!page_is_removable(page)) )
    {
        /* We'll make this a guest-visible error in future, so take heed! */
        DPRINTK("Dom%d freeing in-use page %lx (pseudophys %lx):"
                " count=%lx type=%lx\n",
                d->domain_id, mfn, get_gpfn_from_mfn(mfn),
                (unsigned long)page->count_info, page->u.inuse.type_info);
    }

    guest_physmap_remove_page(d, gmfn, mfn);

    put_page(page);

    return 1;
}

static long
decrease_reservation(
    struct domain *d,
    XEN_GUEST_HANDLE(xen_pfn_t) extent_list,
    unsigned int   nr_extents,
    unsigned int   extent_order,
    int           *preempted)
{
    unsigned long i, j;
    xen_pfn_t gmfn;

    if ( !guest_handle_okay(extent_list, nr_extents) )
        return 0;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            *preempted = 1;
            return i;
        }

        if ( unlikely(__copy_from_guest_offset(&gmfn, extent_list, i, 1)) )
            return i;

        for ( j = 0; j < (1 << extent_order); j++ )
        {
            if ( !guest_remove_page(d, gmfn + j) )
                return i;
        }
    }

    return nr_extents;
}

static long
translate_gpfn_list(
    XEN_GUEST_HANDLE(xen_translate_gpfn_list_t) uop, unsigned long *progress)
{
    struct xen_translate_gpfn_list op;
    unsigned long i;
    xen_pfn_t gpfn;
    xen_pfn_t mfn;
    struct domain *d;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    /* Is size too large for us to encode a continuation? */
    if ( op.nr_gpfns > (ULONG_MAX >> START_EXTENT_SHIFT) )
        return -EINVAL;

    if ( !guest_handle_okay(op.gpfn_list, op.nr_gpfns) ||
         !guest_handle_okay(op.mfn_list,  op.nr_gpfns) )
        return -EFAULT;

    if ( op.domid == DOMID_SELF )
        op.domid = current->domain->domain_id;
    else if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (d = find_domain_by_id(op.domid)) == NULL )
        return -ESRCH;

    if ( !shadow_mode_translate(d) )
    {
        put_domain(d);
        return -EINVAL;
    }

    for ( i = *progress; i < op.nr_gpfns; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            put_domain(d);
            *progress = i;
            return -EAGAIN;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, op.gpfn_list, i, 1)) )
        {
            put_domain(d);
            return -EFAULT;
        }

        mfn = gmfn_to_mfn(d, gpfn);

        if ( unlikely(__copy_to_guest_offset(op.mfn_list, i, &mfn, 1)) )
        {
            put_domain(d);
            return -EFAULT;
        }
    }

    put_domain(d);
    return 0;
}

static long
memory_exchange(XEN_GUEST_HANDLE(xen_memory_exchange_t) arg)
{
    struct xen_memory_exchange exch;
    LIST_HEAD(in_chunk_list);
    LIST_HEAD(out_chunk_list);
    unsigned long in_chunk_order, out_chunk_order;
    xen_pfn_t     gpfn, gmfn, mfn;
    unsigned long i, j, k;
    unsigned int  memflags = 0;
    long          rc = 0;
    struct domain *d;
    struct page_info *page;

    if ( copy_from_guest(&exch, arg, 1) )
        return -EFAULT;

    /* Various sanity checks. */
    if ( (exch.nr_exchanged > exch.in.nr_extents) ||
         /* Input and output domain identifiers match? */
         (exch.in.domid != exch.out.domid) ||
         /* Sizes of input and output lists do not overflow a long? */
         ((~0UL >> exch.in.extent_order) < exch.in.nr_extents) ||
         ((~0UL >> exch.out.extent_order) < exch.out.nr_extents) ||
         /* Sizes of input and output lists match? */
         ((exch.in.nr_extents << exch.in.extent_order) !=
          (exch.out.nr_extents << exch.out.extent_order)) )
    {
        rc = -EINVAL;
        goto fail_early;
    }

    /* Only privileged guests can allocate multi-page contiguous extents. */
    if ( ((exch.in.extent_order != 0) || (exch.out.extent_order != 0)) &&
         !multipage_allocation_permitted(current->domain) )
    {
        rc = -EPERM;
        goto fail_early;
    }

    if ( (exch.out.address_bits != 0) &&
         (exch.out.address_bits <
          (get_order_from_pages(max_page) + PAGE_SHIFT)) )
    {
        if ( exch.out.address_bits < 31 )
        {
            rc = -ENOMEM;
            goto fail_early;
        }
        memflags = MEMF_dma;
    }

    guest_handle_add_offset(exch.in.extent_start, exch.nr_exchanged);
    exch.in.nr_extents -= exch.nr_exchanged;

    if ( exch.in.extent_order <= exch.out.extent_order )
    {
        in_chunk_order  = exch.out.extent_order - exch.in.extent_order;
        out_chunk_order = 0;
        guest_handle_add_offset(
            exch.out.extent_start, exch.nr_exchanged >> in_chunk_order);
        exch.out.nr_extents -= exch.nr_exchanged >> in_chunk_order;
    }
    else
    {
        in_chunk_order  = 0;
        out_chunk_order = exch.in.extent_order - exch.out.extent_order;
        guest_handle_add_offset(
            exch.out.extent_start, exch.nr_exchanged << out_chunk_order);
        exch.out.nr_extents -= exch.nr_exchanged << out_chunk_order;
    }

    /*
     * Only support exchange on calling domain right now. Otherwise there are
     * tricky corner cases to consider (e.g., DOMF_dying domain).
     */
    if ( unlikely(exch.in.domid != DOMID_SELF) )
    {
        rc = IS_PRIV(current->domain) ? -EINVAL : -EPERM;
        goto fail_early;
    }
    d = current->domain;

    for ( i = 0; i < (exch.in.nr_extents >> in_chunk_order); i++ )
    {
        if ( hypercall_preempt_check() )
        {
            exch.nr_exchanged += i << in_chunk_order;
            if ( copy_field_to_guest(arg, &exch, nr_exchanged) )
                return -EFAULT;
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh", XENMEM_exchange, arg);
        }

        /* Steal a chunk's worth of input pages from the domain. */
        for ( j = 0; j < (1UL << in_chunk_order); j++ )
        {
            if ( unlikely(__copy_from_guest_offset(
                &gmfn, exch.in.extent_start, (i<<in_chunk_order)+j, 1)) )
            {
                rc = -EFAULT;
                goto fail;
            }

            for ( k = 0; k < (1UL << exch.in.extent_order); k++ )
            {
                mfn = gmfn_to_mfn(d, gmfn + k);
                if ( unlikely(!mfn_valid(mfn)) )
                {
                    rc = -EINVAL;
                    goto fail;
                }

                page = mfn_to_page(mfn);

                if ( unlikely(steal_page(d, page, MEMF_no_refcount)) )
                {
                    rc = -EINVAL;
                    goto fail;
                }

                list_add(&page->list, &in_chunk_list);
            }
        }

        /* Allocate a chunk's worth of anonymous output pages. */
        for ( j = 0; j < (1UL << out_chunk_order); j++ )
        {
            page = alloc_domheap_pages(
                NULL, exch.out.extent_order, memflags);
            if ( unlikely(page == NULL) )
            {
                rc = -ENOMEM;
                goto fail;
            }

            list_add(&page->list, &out_chunk_list);
        }

        /*
         * Success! Beyond this point we cannot fail for this chunk.
         */

        /* Destroy final reference to each input page. */
        while ( !list_empty(&in_chunk_list) )
        {
            page = list_entry(in_chunk_list.next, struct page_info, list);
            list_del(&page->list);
            if ( !test_and_clear_bit(_PGC_allocated, &page->count_info) )
                BUG();
            mfn = page_to_mfn(page);
            guest_physmap_remove_page(d, mfn_to_gmfn(d, mfn), mfn);
            put_page(page);
        }

        /* Assign each output page to the domain. */
        j = 0;
        while ( !list_empty(&out_chunk_list) )
        {
            page = list_entry(out_chunk_list.next, struct page_info, list);
            list_del(&page->list);
            if ( assign_pages(d, page, exch.out.extent_order,
                              MEMF_no_refcount) )
                BUG();

            /* Note that we ignore errors accessing the output extent list. */
            (void)__copy_from_guest_offset(
                &gpfn, exch.out.extent_start, (i<<out_chunk_order)+j, 1);

            mfn = page_to_mfn(page);
            if ( unlikely(shadow_mode_translate(d)) )
            {
                for ( k = 0; k < (1UL << exch.out.extent_order); k++ )
                    guest_physmap_add_page(d, gpfn + k, mfn + k);
            }
            else
            {
                for ( k = 0; k < (1UL << exch.out.extent_order); k++ )
                    set_gpfn_from_mfn(mfn + k, gpfn + k);
                (void)__copy_to_guest_offset(
                    exch.out.extent_start, (i<<out_chunk_order)+j, &mfn, 1);
            }

            j++;
        }
        BUG_ON(j != (1UL << out_chunk_order));
    }

    exch.nr_exchanged += exch.in.nr_extents;
    if ( copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    return rc;

    /*
     * Failed a chunk! Free any partial chunk work. Tell caller how many
     * chunks succeeded.
     */
 fail:
    /* Reassign any input pages we managed to steal. */
    while ( !list_empty(&in_chunk_list) )
    {
        page = list_entry(in_chunk_list.next, struct page_info, list);
        list_del(&page->list);
        if ( assign_pages(d, page, 0, MEMF_no_refcount) )
            BUG();
    }

    /* Free any output pages we managed to allocate. */
    while ( !list_empty(&out_chunk_list) )
    {
        page = list_entry(out_chunk_list.next, struct page_info, list);
        list_del(&page->list);
        free_domheap_pages(page, exch.out.extent_order);
    }

    exch.nr_exchanged += i << in_chunk_order;

 fail_early:
    if ( copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    return rc;
}

long do_memory_op(unsigned long cmd, XEN_GUEST_HANDLE(void) arg)
{
    struct domain *d;
    int rc, op, preempted = 0;
    unsigned int memflags = 0;
    unsigned long start_extent, progress;
    struct xen_memory_reservation reservation;
    domid_t domid;

    op = cmd & ((1 << START_EXTENT_SHIFT) - 1);

    switch ( op )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        start_extent = cmd >> START_EXTENT_SHIFT;

        if ( copy_from_guest(&reservation, arg, 1) )
            return start_extent;

        /* Is size too large for us to encode a continuation? */
        if ( reservation.nr_extents > (ULONG_MAX >> START_EXTENT_SHIFT) )
            return start_extent;

        if ( unlikely(start_extent > reservation.nr_extents) )
            return start_extent;

        if ( !guest_handle_is_null(reservation.extent_start) )
            guest_handle_add_offset(reservation.extent_start, start_extent);
        reservation.nr_extents -= start_extent;

        if ( (reservation.address_bits != 0) &&
             (reservation.address_bits <
              (get_order_from_pages(max_page) + PAGE_SHIFT)) )
        {
            if ( reservation.address_bits < 31 )
                return start_extent;
            memflags = MEMF_dma;
        }

        if ( likely(reservation.domid == DOMID_SELF) )
            d = current->domain;
        else if ( !IS_PRIV(current->domain) ||
                  ((d = find_domain_by_id(reservation.domid)) == NULL) )
            return start_extent;

        switch ( op )
        {
        case XENMEM_increase_reservation:
            rc = increase_reservation(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                memflags,
                &preempted);
            break;
        case XENMEM_decrease_reservation:
            rc = decrease_reservation(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                &preempted);
            break;
        case XENMEM_populate_physmap:
        default:
            rc = populate_physmap(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                memflags,
                &preempted);
            break;
        }

        if ( unlikely(reservation.domid != DOMID_SELF) )
            put_domain(d);

        rc += start_extent;

        if ( preempted )
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh",
                op | (rc << START_EXTENT_SHIFT), arg);

        break;

    case XENMEM_exchange:
        rc = memory_exchange(guest_handle_cast(arg, xen_memory_exchange_t));
        break;

    case XENMEM_maximum_ram_page:
        rc = max_page;
        break;

    case XENMEM_current_reservation:
    case XENMEM_maximum_reservation:
        if ( copy_from_guest(&domid, arg, 1) )
            return -EFAULT;

        if ( likely(domid == DOMID_SELF) )
            d = current->domain;
        else if ( !IS_PRIV(current->domain) )
            return -EPERM;
        else if ( (d = find_domain_by_id(domid)) == NULL )
            return -ESRCH;

        rc = (op == XENMEM_current_reservation) ? d->tot_pages : d->max_pages;

        if ( unlikely(domid != DOMID_SELF) )
            put_domain(d);

        break;

    case XENMEM_translate_gpfn_list:
        progress = cmd >> START_EXTENT_SHIFT;
        rc = translate_gpfn_list(
            guest_handle_cast(arg, xen_translate_gpfn_list_t),
            &progress);
        if ( rc == -EAGAIN )
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh",
                op | (progress << START_EXTENT_SHIFT), arg);
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
