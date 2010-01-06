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
#include <xen/paging.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/errno.h>
#include <xen/tmem.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#ifdef CONFIG_X86
# include <asm/p2m.h>
#endif
#include <xen/numa.h>
#include <public/memory.h>
#include <xsm/xsm.h>

struct memop_args {
    /* INPUT */
    struct domain *domain;     /* Domain to be affected. */
    XEN_GUEST_HANDLE(xen_pfn_t) extent_list; /* List of extent base addrs. */
    unsigned int nr_extents;   /* Number of extents to allocate or free. */
    unsigned int extent_order; /* Size of each extent. */
    unsigned int memflags;     /* Allocation flags. */

    /* INPUT/OUTPUT */
    unsigned int nr_done;    /* Number of extents processed so far. */
    int          preempted;  /* Was the hypercall preempted? */
};

static void increase_reservation(struct memop_args *a)
{
    struct page_info *page;
    unsigned long i;
    xen_pfn_t mfn;
    struct domain *d = a->domain;

    if ( !guest_handle_is_null(a->extent_list) &&
         !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( !multipage_allocation_permitted(current->domain, a->extent_order) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        page = alloc_domheap_pages(d, a->extent_order, a->memflags);
        if ( unlikely(page == NULL) ) 
        {
            gdprintk(XENLOG_INFO, "Could not allocate order=%d extent: "
                    "id=%d memflags=%x (%ld of %d)\n",
                     a->extent_order, d->domain_id, a->memflags,
                     i, a->nr_extents);
            goto out;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( !guest_handle_is_null(a->extent_list) )
        {
            mfn = page_to_mfn(page);
            if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                goto out;
        }
    }

 out:
    a->nr_done = i;
}

static void populate_physmap(struct memop_args *a)
{
    struct page_info *page;
    unsigned long i, j;
    xen_pfn_t gpfn, mfn;
    struct domain *d = a->domain;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( !multipage_allocation_permitted(current->domain, a->extent_order) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, a->extent_list, i, 1)) )
            goto out;

        if ( a->memflags & MEMF_populate_on_demand )
        {
            if ( guest_physmap_mark_populate_on_demand(d, gpfn,
                                                       a->extent_order) < 0 )
                goto out;
        }
        else
        {
            page = alloc_domheap_pages(d, a->extent_order, a->memflags);
            if ( unlikely(page == NULL) ) 
            {
                if ( !opt_tmem || (a->extent_order != 0) )
                    gdprintk(XENLOG_INFO, "Could not allocate order=%d extent:"
                             " id=%d memflags=%x (%ld of %d)\n",
                             a->extent_order, d->domain_id, a->memflags,
                             i, a->nr_extents);
                goto out;
            }

            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, gpfn, mfn, a->extent_order);

            if ( !paging_mode_translate(d) )
            {
                for ( j = 0; j < (1 << a->extent_order); j++ )
                    set_gpfn_from_mfn(mfn + j, gpfn + j);

                /* Inform the domain of the new page's machine address. */ 
                if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                    goto out;
            }
        }
    }

out:
    a->nr_done = i;
}

int guest_remove_page(struct domain *d, unsigned long gmfn)
{
    struct page_info *page;
#ifdef CONFIG_X86
    p2m_type_t p2mt;
#endif
    unsigned long mfn;

#ifdef CONFIG_X86
    mfn = mfn_x(gfn_to_mfn(d, gmfn, &p2mt)); 
#else
    mfn = gmfn_to_mfn(d, gmfn);
#endif
    if ( unlikely(!mfn_valid(mfn)) )
    {
        gdprintk(XENLOG_INFO, "Domain %u page number %lx invalid\n",
                d->domain_id, gmfn);
        return 0;
    }
            
    page = mfn_to_page(mfn);
#ifdef CONFIG_X86
    /* If gmfn is shared, just drop the guest reference (which may or may not
     * free the page) */
    if(p2m_is_shared(p2mt))
    {
        put_page_and_type(page);
        guest_physmap_remove_page(d, gmfn, mfn, 0);
        return 1;
    }

#endif /* CONFIG_X86 */
    if ( unlikely(!get_page(page, d)) )
    {
        gdprintk(XENLOG_INFO, "Bad page free for domain %u\n", d->domain_id);
        return 0;
    }

    if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
        put_page_and_type(page);
            
    if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
        put_page(page);

    guest_physmap_remove_page(d, gmfn, mfn, 0);

    put_page(page);

    return 1;
}

static void decrease_reservation(struct memop_args *a)
{
    unsigned long i, j;
    xen_pfn_t gmfn;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gmfn, a->extent_list, i, 1)) )
            goto out;

        /* See if populate-on-demand wants to handle this */
        if ( is_hvm_domain(a->domain)
             && p2m_pod_decrease_reservation(a->domain, gmfn, a->extent_order) )
            continue;

        for ( j = 0; j < (1 << a->extent_order); j++ )
            if ( !guest_remove_page(a->domain, gmfn + j) )
                goto out;
    }

 out:
    a->nr_done = i;
}

static long memory_exchange(XEN_GUEST_HANDLE(xen_memory_exchange_t) arg)
{
    struct xen_memory_exchange exch;
    PAGE_LIST_HEAD(in_chunk_list);
    PAGE_LIST_HEAD(out_chunk_list);
    unsigned long in_chunk_order, out_chunk_order;
    xen_pfn_t     gpfn, gmfn, mfn;
    unsigned long i, j, k;
    unsigned int  node, memflags = 0;
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
    if ( !multipage_allocation_permitted(current->domain,
                                         exch.in.extent_order) ||
         !multipage_allocation_permitted(current->domain,
                                         exch.out.extent_order) )
    {
        rc = -EPERM;
        goto fail_early;
    }

    if ( exch.in.extent_order <= exch.out.extent_order )
    {
        in_chunk_order  = exch.out.extent_order - exch.in.extent_order;
        out_chunk_order = 0;
    }
    else
    {
        in_chunk_order  = 0;
        out_chunk_order = exch.in.extent_order - exch.out.extent_order;
    }

    if ( likely(exch.in.domid == DOMID_SELF) )
    {
        d = rcu_lock_current_domain();
    }
    else
    {
        if ( (d = rcu_lock_domain_by_id(exch.in.domid)) == NULL )
            goto fail_early;

        if ( !IS_PRIV_FOR(current->domain, d) )
        {
            rcu_unlock_domain(d);
            rc = -EPERM;
            goto fail_early;
        }
    }

    memflags |= MEMF_bits(domain_clamp_alloc_bitsize(
        d,
        XENMEMF_get_address_bits(exch.out.mem_flags) ? :
        (BITS_PER_LONG+PAGE_SHIFT)));
    node = XENMEMF_get_node(exch.out.mem_flags);
    if ( node == NUMA_NO_NODE )
        node = domain_to_node(d);
    memflags |= MEMF_node(node);

    for ( i = (exch.nr_exchanged >> in_chunk_order);
          i < (exch.in.nr_extents >> in_chunk_order);
          i++ )
    {
        if ( hypercall_preempt_check() )
        {
            exch.nr_exchanged = i << in_chunk_order;
            rcu_unlock_domain(d);
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
#ifdef CONFIG_X86
                p2m_type_t p2mt;

                /* Shared pages cannot be exchanged */
                mfn = mfn_x(gfn_to_mfn_unshare(d, gmfn + k, &p2mt, 0));
                if ( p2m_is_shared(p2mt) )
                {
                    rc = -ENOMEM;
                    goto fail; 
                }
#else /* !CONFIG_X86 */
                mfn = gmfn_to_mfn(d, gmfn + k);
#endif
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

                page_list_add(page, &in_chunk_list);
            }
        }

        /* Allocate a chunk's worth of anonymous output pages. */
        for ( j = 0; j < (1UL << out_chunk_order); j++ )
        {
            page = alloc_domheap_pages(NULL, exch.out.extent_order, memflags);
            if ( unlikely(page == NULL) )
            {
                rc = -ENOMEM;
                goto fail;
            }

            page_list_add(page, &out_chunk_list);
        }

        /*
         * Success! Beyond this point we cannot fail for this chunk.
         */

        /* Destroy final reference to each input page. */
        while ( (page = page_list_remove_head(&in_chunk_list)) )
        {
            unsigned long gfn;

            if ( !test_and_clear_bit(_PGC_allocated, &page->count_info) )
                BUG();
            mfn = page_to_mfn(page);
            gfn = mfn_to_gmfn(d, mfn);
            /* Pages were unshared above */
            BUG_ON(SHARED_M2P(gfn));
            guest_physmap_remove_page(d, gfn, mfn, 0);
            put_page(page);
        }

        /* Assign each output page to the domain. */
        j = 0;
        while ( (page = page_list_remove_head(&out_chunk_list)) )
        {
            if ( assign_pages(d, page, exch.out.extent_order,
                              MEMF_no_refcount) )
            {
                unsigned long dec_count;
                bool_t drop_dom_ref;

                /*
                 * Pages in in_chunk_list is stolen without
                 * decreasing the tot_pages. If the domain is dying when
                 * assign pages, we need decrease the count. For those pages
                 * that has been assigned, it should be covered by
                 * domain_relinquish_resources().
                 */
                dec_count = (((1UL << exch.in.extent_order) *
                              (1UL << in_chunk_order)) -
                             (j * (1UL << exch.out.extent_order)));

                spin_lock(&d->page_alloc_lock);
                d->tot_pages -= dec_count;
                drop_dom_ref = (dec_count && !d->tot_pages);
                spin_unlock(&d->page_alloc_lock);

                if ( drop_dom_ref )
                    put_domain(d);

                free_domheap_pages(page, exch.out.extent_order);
                goto dying;
            }

            /* Note that we ignore errors accessing the output extent list. */
            (void)__copy_from_guest_offset(
                &gpfn, exch.out.extent_start, (i<<out_chunk_order)+j, 1);

            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, gpfn, mfn, exch.out.extent_order);

            if ( !paging_mode_translate(d) )
            {
                for ( k = 0; k < (1UL << exch.out.extent_order); k++ )
                    set_gpfn_from_mfn(mfn + k, gpfn + k);
                (void)__copy_to_guest_offset(
                    exch.out.extent_start, (i<<out_chunk_order)+j, &mfn, 1);
            }
            j++;
        }
        BUG_ON( !(d->is_dying) && (j != (1UL << out_chunk_order)) );
    }

    exch.nr_exchanged = exch.in.nr_extents;
    if ( copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    rcu_unlock_domain(d);
    return rc;

    /*
     * Failed a chunk! Free any partial chunk work. Tell caller how many
     * chunks succeeded.
     */
 fail:
    /* Reassign any input pages we managed to steal. */
    while ( (page = page_list_remove_head(&in_chunk_list)) )
        if ( assign_pages(d, page, 0, MEMF_no_refcount) )
            BUG();
 dying:
    rcu_unlock_domain(d);
    /* Free any output pages we managed to allocate. */
    while ( (page = page_list_remove_head(&out_chunk_list)) )
        free_domheap_pages(page, exch.out.extent_order);

    exch.nr_exchanged = i << in_chunk_order;

 fail_early:
    if ( copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    return rc;
}

long do_memory_op(unsigned long cmd, XEN_GUEST_HANDLE(void) arg)
{
    struct domain *d;
    int rc, op;
    unsigned int address_bits;
    unsigned long start_extent;
    struct xen_memory_reservation reservation;
    struct memop_args args;
    domid_t domid;

    op = cmd & MEMOP_CMD_MASK;

    switch ( op )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        start_extent = cmd >> MEMOP_EXTENT_SHIFT;

        if ( copy_from_guest(&reservation, arg, 1) )
            return start_extent;

        /* Is size too large for us to encode a continuation? */
        if ( reservation.nr_extents > (ULONG_MAX >> MEMOP_EXTENT_SHIFT) )
            return start_extent;

        if ( unlikely(start_extent > reservation.nr_extents) )
            return start_extent;

        args.extent_list  = reservation.extent_start;
        args.nr_extents   = reservation.nr_extents;
        args.extent_order = reservation.extent_order;
        args.nr_done      = start_extent;
        args.preempted    = 0;
        args.memflags     = 0;

        address_bits = XENMEMF_get_address_bits(reservation.mem_flags);
        if ( (address_bits != 0) &&
             (address_bits < (get_order_from_pages(max_page) + PAGE_SHIFT)) )
        {
            if ( address_bits <= PAGE_SHIFT )
                return start_extent;
            args.memflags = MEMF_bits(address_bits);
        }

        args.memflags |= MEMF_node(XENMEMF_get_node(reservation.mem_flags));

        if ( op == XENMEM_populate_physmap
             && (reservation.mem_flags & XENMEMF_populate_on_demand) )
            args.memflags |= MEMF_populate_on_demand;

        if ( likely(reservation.domid == DOMID_SELF) )
        {
            d = rcu_lock_current_domain();
        }
        else
        {
            if ( (d = rcu_lock_domain_by_id(reservation.domid)) == NULL )
                return start_extent;
            if ( !IS_PRIV_FOR(current->domain, d) )
            {
                rcu_unlock_domain(d);
                return start_extent;
            }
        }
        args.domain = d;

        rc = xsm_memory_adjust_reservation(current->domain, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        switch ( op )
        {
        case XENMEM_increase_reservation:
            increase_reservation(&args);
            break;
        case XENMEM_decrease_reservation:
            decrease_reservation(&args);
            break;
        default: /* XENMEM_populate_physmap */
            populate_physmap(&args);
            break;
        }

        rcu_unlock_domain(d);

        rc = args.nr_done;

        if ( args.preempted )
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh",
                op | (rc << MEMOP_EXTENT_SHIFT), arg);

        break;

    case XENMEM_exchange:
        rc = memory_exchange(guest_handle_cast(arg, xen_memory_exchange_t));
        break;

    case XENMEM_maximum_ram_page:
        rc = max_page;
        break;

    case XENMEM_current_reservation:
    case XENMEM_maximum_reservation:
    case XENMEM_maximum_gpfn:
        if ( copy_from_guest(&domid, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(domid, &d);
        if ( rc )
            return rc;

        rc = xsm_memory_stat_reservation(current->domain, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        switch ( op )
        {
        case XENMEM_current_reservation:
            rc = d->tot_pages;
            break;
        case XENMEM_maximum_reservation:
            rc = d->max_pages;
            break;
        default:
            ASSERT(op == XENMEM_maximum_gpfn);
            rc = domain_get_maximum_gpfn(d);
            break;
        }

        rcu_unlock_domain(d);

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
