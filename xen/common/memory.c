/******************************************************************************
 * memory.c
 *
 * Code to handle memory-related requests.
 *
 * Copyright (c) 2003-2004, B Dragovic
 * Copyright (c) 2003-2005, K A Fraser
 */

#include <xen/domain_page.h>
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
#include <xen/numa.h>
#include <xen/mem_access.h>
#include <xen/trace.h>
#include <xen/grant_table.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#include <asm/p2m.h>
#include <public/memory.h>
#include <xsm/xsm.h>

#ifdef CONFIG_X86
#include <asm/guest.h>
#endif

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

#ifndef CONFIG_CTLDOM_MAX_ORDER
#define CONFIG_CTLDOM_MAX_ORDER CONFIG_PAGEALLOC_MAX_ORDER
#endif
#ifndef CONFIG_PTDOM_MAX_ORDER
#define CONFIG_PTDOM_MAX_ORDER CONFIG_HWDOM_MAX_ORDER
#endif

static unsigned int __read_mostly domu_max_order = CONFIG_DOMU_MAX_ORDER;
static unsigned int __read_mostly ctldom_max_order = CONFIG_CTLDOM_MAX_ORDER;
static unsigned int __read_mostly hwdom_max_order = CONFIG_HWDOM_MAX_ORDER;
#ifdef HAS_PASSTHROUGH
static unsigned int __read_mostly ptdom_max_order = CONFIG_PTDOM_MAX_ORDER;
#endif

static int __init parse_max_order(const char *s)
{
    if ( *s != ',' )
        domu_max_order = simple_strtoul(s, &s, 0);
    if ( *s == ',' && *++s != ',' )
        ctldom_max_order = simple_strtoul(s, &s, 0);
    if ( *s == ',' && *++s != ',' )
        hwdom_max_order = simple_strtoul(s, &s, 0);
#ifdef HAS_PASSTHROUGH
    if ( *s == ',' && *++s != ',' )
        ptdom_max_order = simple_strtoul(s, &s, 0);
#endif

    return *s ? -EINVAL : 0;
}
custom_param("memop-max-order", parse_max_order);

static unsigned int max_order(const struct domain *d)
{
    unsigned int order = domu_max_order;

#ifdef HAS_PASSTHROUGH
    if ( cache_flush_permitted(d) && order < ptdom_max_order )
        order = ptdom_max_order;
#endif

    if ( is_control_domain(d) && order < ctldom_max_order )
        order = ctldom_max_order;

    if ( is_hardware_domain(d) && order < hwdom_max_order )
        order = hwdom_max_order;

    return min(order, MAX_ORDER + 0U);
}

/* Helper to copy a typesafe MFN to guest */
static inline
unsigned long __copy_mfn_to_guest_offset(XEN_GUEST_HANDLE(xen_pfn_t) hnd,
                                         size_t off, mfn_t mfn)
 {
    xen_pfn_t mfn_ = mfn_x(mfn);

    return __copy_to_guest_offset(hnd, off, &mfn_, 1);
}

static void increase_reservation(struct memop_args *a)
{
    struct page_info *page;
    unsigned long i;
    struct domain *d = a->domain;

    if ( !guest_handle_is_null(a->extent_list) &&
         !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( a->extent_order > max_order(current->domain) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( i != a->nr_done && hypercall_preempt_check() )
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
        if ( !paging_mode_translate(d) &&
             !guest_handle_is_null(a->extent_list) )
        {
            mfn_t mfn = page_to_mfn(page);

            if ( unlikely(__copy_mfn_to_guest_offset(a->extent_list, i, mfn)) )
                goto out;
        }
    }

 out:
    a->nr_done = i;
}

static void populate_physmap(struct memop_args *a)
{
    struct page_info *page;
    unsigned int i, j;
    xen_pfn_t gpfn;
    struct domain *d = a->domain, *curr_d = current->domain;
    bool need_tlbflush = false;
    uint32_t tlbflush_timestamp = 0;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( a->extent_order > (a->memflags & MEMF_populate_on_demand ? MAX_ORDER :
                            max_order(curr_d)) )
        return;

    if ( unlikely(!d->creation_finished) )
    {
        /*
         * With MEMF_no_tlbflush set, alloc_heap_pages() will ignore
         * TLB-flushes. After VM creation, this is a security issue (it can
         * make pages accessible to guest B, when guest A may still have a
         * cached mapping to them). So we do this only during domain creation,
         * when the domain itself has not yet been unpaused for the first
         * time.
         */
        a->memflags |= MEMF_no_tlbflush;
        /*
         * With MEMF_no_icache_flush, alloc_heap_pages() will skip
         * performing icache flushes. We do it only before domain
         * creation as once the domain is running there is a danger of
         * executing instructions from stale caches if icache flush is
         * delayed.
         */
        a->memflags |= MEMF_no_icache_flush;
    }

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        mfn_t mfn;

        if ( i != a->nr_done && hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, a->extent_list, i, 1)) )
            goto out;

        if ( a->memflags & MEMF_populate_on_demand )
        {
            /* Disallow populating PoD pages on oneself. */
            if ( d == curr_d )
                goto out;

            if ( is_hvm_domain(d) &&
                 guest_physmap_mark_populate_on_demand(d, gpfn,
                                                       a->extent_order) < 0 )
                goto out;
        }
        else
        {
            if ( is_domain_direct_mapped(d) )
            {
                mfn = _mfn(gpfn);

                for ( j = 0; j < (1U << a->extent_order); j++,
                      mfn = mfn_add(mfn, 1) )
                {
                    if ( !mfn_valid(mfn) )
                    {
                        gdprintk(XENLOG_INFO, "Invalid mfn %#"PRI_mfn"\n",
                                 mfn_x(mfn));
                        goto out;
                    }

                    page = mfn_to_page(mfn);
                    if ( !get_page(page, d) )
                    {
                        gdprintk(XENLOG_INFO,
                                 "mfn %#"PRI_mfn" doesn't belong to d%d\n",
                                  mfn_x(mfn), d->domain_id);
                        goto out;
                    }
                    put_page(page);
                }

                mfn = _mfn(gpfn);
            }
            else
            {
                page = alloc_domheap_pages(d, a->extent_order, a->memflags);

                if ( unlikely(!page) )
                {
                    gdprintk(XENLOG_INFO,
                             "Could not allocate order=%u extent: id=%d memflags=%#x (%u of %u)\n",
                             a->extent_order, d->domain_id, a->memflags,
                             i, a->nr_extents);
                    goto out;
                }

                if ( unlikely(a->memflags & MEMF_no_tlbflush) )
                {
                    for ( j = 0; j < (1U << a->extent_order); j++ )
                        accumulate_tlbflush(&need_tlbflush, &page[j],
                                            &tlbflush_timestamp);
                }

                mfn = page_to_mfn(page);
            }

            guest_physmap_add_page(d, _gfn(gpfn), mfn, a->extent_order);

            if ( !paging_mode_translate(d) &&
                 /* Inform the domain of the new page's machine address. */
                 unlikely(__copy_mfn_to_guest_offset(a->extent_list, i, mfn)) )
                goto out;
        }
    }

out:
    if ( need_tlbflush )
        filtered_flush_tlb_mask(tlbflush_timestamp);

    if ( a->memflags & MEMF_no_icache_flush )
        invalidate_icache();

    a->nr_done = i;
}

int guest_remove_page(struct domain *d, unsigned long gmfn)
{
    struct page_info *page;
#ifdef CONFIG_X86
    p2m_type_t p2mt;
#endif
    mfn_t mfn;
    int rc;

#ifdef CONFIG_X86
    mfn = get_gfn_query(d, gmfn, &p2mt);
    if ( unlikely(p2mt == p2m_invalid) || unlikely(p2mt == p2m_mmio_dm) )
    {
        put_gfn(d, gmfn);

        return -ENOENT;
    }

    if ( unlikely(p2m_is_paging(p2mt)) )
    {
        /*
         * If the page hasn't yet been paged out, there is an
         * actual page that needs to be released.
         */
        if ( p2mt == p2m_ram_paging_out )
        {
            ASSERT(mfn_valid(mfn));
            goto obtain_page;
        }

        rc = guest_physmap_remove_page(d, _gfn(gmfn), mfn, 0);
        if ( rc )
            goto out_put_gfn;

        put_gfn(d, gmfn);

        p2m_mem_paging_drop_page(d, gmfn, p2mt);

        return 0;
    }
    if ( p2mt == p2m_mmio_direct )
    {
        rc = clear_mmio_p2m_entry(d, gmfn, mfn, PAGE_ORDER_4K);
        goto out_put_gfn;
    }
#else
    mfn = gfn_to_mfn(d, _gfn(gmfn));
#endif
    if ( unlikely(!mfn_valid(mfn)) )
    {
#ifdef CONFIG_X86
        put_gfn(d, gmfn);
#endif
        gdprintk(XENLOG_INFO, "Domain %u page number %lx invalid\n",
                d->domain_id, gmfn);

        return -EINVAL;
    }
            
#ifdef CONFIG_X86
    if ( p2m_is_shared(p2mt) )
    {
        /*
         * Unshare the page, bail out on error. We unshare because we
         * might be the only one using this shared page, and we need to
         * trigger proper cleanup. Once done, this is like any other page.
         */
        rc = mem_sharing_unshare_page(d, gmfn, 0);
        if ( rc )
        {
            mem_sharing_notify_enomem(d, gmfn, false);
            goto out_put_gfn;
        }
        /* Maybe the mfn changed */
        mfn = get_gfn_query_unlocked(d, gmfn, &p2mt);
        ASSERT(!p2m_is_shared(p2mt));
    }
#endif /* CONFIG_X86 */

 obtain_page: __maybe_unused;
    page = mfn_to_page(mfn);
    if ( unlikely(!get_page(page, d)) )
    {
#ifdef CONFIG_X86
        put_gfn(d, gmfn);
        if ( !p2m_is_paging(p2mt) )
#endif
            gdprintk(XENLOG_INFO, "Bad page free for Dom%u GFN %lx\n",
                     d->domain_id, gmfn);

        return -ENXIO;
    }

    rc = guest_physmap_remove_page(d, _gfn(gmfn), mfn, 0);

    /*
     * With the lack of an IOMMU on some platforms, domains with DMA-capable
     * device must retrieve the same pfn when the hypercall populate_physmap
     * is called.
     *
     * For this purpose (and to match populate_physmap() behavior), the page
     * is kept allocated.
     */
    if ( !rc && !is_domain_direct_mapped(d) )
        put_page_alloc_ref(page);

    put_page(page);

#ifdef CONFIG_X86
 out_put_gfn:
    put_gfn(d, gmfn);
#endif

    /*
     * Filter out -ENOENT return values that aren't a result of an empty p2m
     * entry.
     */
    return rc != -ENOENT ? rc : -EINVAL;
}

static void decrease_reservation(struct memop_args *a)
{
    unsigned long i, j;
    xen_pfn_t gmfn;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) ||
         a->extent_order > max_order(current->domain) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        unsigned long pod_done;

        if ( i != a->nr_done && hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gmfn, a->extent_list, i, 1)) )
            goto out;

        if ( tb_init_done )
        {
            struct {
                u64 gfn;
                int d:16,order:16;
            } t;

            t.gfn = gmfn;
            t.d = a->domain->domain_id;
            t.order = a->extent_order;
        
            __trace_var(TRC_MEM_DECREASE_RESERVATION, 0, sizeof(t), &t);
        }

        /* See if populate-on-demand wants to handle this */
        pod_done = is_hvm_domain(a->domain) ?
                   p2m_pod_decrease_reservation(a->domain, _gfn(gmfn),
                                                a->extent_order) : 0;

        /*
         * Look for pages not handled by p2m_pod_decrease_reservation().
         *
         * guest_remove_page() will return -ENOENT for pages which have already
         * been removed by p2m_pod_decrease_reservation(); so expect to see
         * exactly pod_done failures.  Any more means that there were invalid
         * entries before p2m_pod_decrease_reservation() was called.
         */
        for ( j = 0; j + pod_done < (1UL << a->extent_order); j++ )
        {
            switch ( guest_remove_page(a->domain, gmfn + j) )
            {
            case 0:
                break;
            case -ENOENT:
                if ( !pod_done )
                    goto out;
                --pod_done;
                break;
            default:
                goto out;
            }
        }
    }

 out:
    a->nr_done = i;
}

static bool propagate_node(unsigned int xmf, unsigned int *memflags)
{
    const struct domain *currd = current->domain;

    BUILD_BUG_ON(XENMEMF_get_node(0) != NUMA_NO_NODE);
    BUILD_BUG_ON(MEMF_get_node(0) != NUMA_NO_NODE);

    if ( XENMEMF_get_node(xmf) == NUMA_NO_NODE )
        return true;

    if ( is_hardware_domain(currd) || is_control_domain(currd) )
    {
        if ( XENMEMF_get_node(xmf) >= MAX_NUMNODES )
            return false;

        *memflags |= MEMF_node(XENMEMF_get_node(xmf));
        if ( xmf & XENMEMF_exact_node_request )
            *memflags |= MEMF_exact_node;
    }
    else if ( xmf & XENMEMF_exact_node_request )
        return false;

    return true;
}

static long memory_exchange(XEN_GUEST_HANDLE_PARAM(xen_memory_exchange_t) arg)
{
    struct xen_memory_exchange exch;
    PAGE_LIST_HEAD(in_chunk_list);
    PAGE_LIST_HEAD(out_chunk_list);
    unsigned long in_chunk_order, out_chunk_order;
    xen_pfn_t     gpfn, gmfn;
    mfn_t         mfn;
    unsigned long i, j, k;
    unsigned int  memflags = 0;
    long          rc = 0;
    struct domain *d;
    struct page_info *page;

    if ( copy_from_guest(&exch, arg, 1) )
        return -EFAULT;

    if ( max(exch.in.extent_order, exch.out.extent_order) >
         max_order(current->domain) )
    {
        rc = -EPERM;
        goto fail_early;
    }

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

    if ( exch.nr_exchanged == exch.in.nr_extents )
        return 0;

    if ( !guest_handle_subrange_okay(exch.in.extent_start, exch.nr_exchanged,
                                     exch.in.nr_extents - 1) )
    {
        rc = -EFAULT;
        goto fail_early;
    }

    if ( exch.in.extent_order <= exch.out.extent_order )
    {
        in_chunk_order  = exch.out.extent_order - exch.in.extent_order;
        out_chunk_order = 0;

        if ( !guest_handle_subrange_okay(exch.out.extent_start,
                                         exch.nr_exchanged >> in_chunk_order,
                                         exch.out.nr_extents - 1) )
        {
            rc = -EFAULT;
            goto fail_early;
        }
    }
    else
    {
        in_chunk_order  = 0;
        out_chunk_order = exch.in.extent_order - exch.out.extent_order;

        if ( !guest_handle_subrange_okay(exch.out.extent_start,
                                         exch.nr_exchanged << out_chunk_order,
                                         exch.out.nr_extents - 1) )
        {
            rc = -EFAULT;
            goto fail_early;
        }
    }

    if ( unlikely(!propagate_node(exch.out.mem_flags, &memflags)) )
    {
        rc = -EINVAL;
        goto fail_early;
    }

    d = rcu_lock_domain_by_any_id(exch.in.domid);
    if ( d == NULL )
    {
        rc = -ESRCH;
        goto fail_early;
    }

    rc = xsm_memory_exchange(XSM_TARGET, d);
    if ( rc )
    {
        rcu_unlock_domain(d);
        goto fail_early;
    }

    memflags |= MEMF_bits(domain_clamp_alloc_bitsize(
        d,
        XENMEMF_get_address_bits(exch.out.mem_flags) ? :
        (BITS_PER_LONG+PAGE_SHIFT)));

    for ( i = (exch.nr_exchanged >> in_chunk_order);
          i < (exch.in.nr_extents >> in_chunk_order);
          i++ )
    {
        if ( i != (exch.nr_exchanged >> in_chunk_order) &&
             hypercall_preempt_check() )
        {
            exch.nr_exchanged = i << in_chunk_order;
            rcu_unlock_domain(d);
            if ( __copy_field_to_guest(arg, &exch, nr_exchanged) )
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
                mfn = get_gfn_unshare(d, gmfn + k, &p2mt);
                if ( p2m_is_shared(p2mt) )
                {
                    put_gfn(d, gmfn + k);
                    rc = -ENOMEM;
                    goto fail; 
                }
#else /* !CONFIG_X86 */
                mfn = gfn_to_mfn(d, _gfn(gmfn + k));
#endif
                if ( unlikely(!mfn_valid(mfn)) )
                {
#ifdef CONFIG_X86
                    put_gfn(d, gmfn + k);
#endif
                    rc = -EINVAL;
                    goto fail;
                }

                page = mfn_to_page(mfn);

                rc = steal_page(d, page, MEMF_no_refcount);
                if ( unlikely(rc) )
                {
#ifdef CONFIG_X86
                    put_gfn(d, gmfn + k);
#endif
                    goto fail;
                }

                page_list_add(page, &in_chunk_list);
#ifdef CONFIG_X86
                put_gfn(d, gmfn + k);
#endif
            }
        }

        /* Allocate a chunk's worth of anonymous output pages. */
        for ( j = 0; j < (1UL << out_chunk_order); j++ )
        {
            page = alloc_domheap_pages(d, exch.out.extent_order,
                                       MEMF_no_owner | memflags);
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

        /*
         * These pages have already had owner and reference cleared.
         * Do the final two steps: Remove from the physmap, and free
         * them.
         */
        while ( (page = page_list_remove_head(&in_chunk_list)) )
        {
            unsigned long gfn;

            mfn = page_to_mfn(page);
            gfn = mfn_to_gmfn(d, mfn_x(mfn));
            /* Pages were unshared above */
            BUG_ON(SHARED_M2P(gfn));
            if ( guest_physmap_remove_page(d, _gfn(gfn), mfn, 0) )
                domain_crash(d);
            free_domheap_page(page);
        }

        /* Assign each output page to the domain. */
        for ( j = 0; (page = page_list_remove_head(&out_chunk_list)); ++j )
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
                drop_dom_ref = (dec_count &&
                                !domain_adjust_tot_pages(d, -dec_count));
                spin_unlock(&d->page_alloc_lock);

                if ( drop_dom_ref )
                    put_domain(d);

                free_domheap_pages(page, exch.out.extent_order);
                goto dying;
            }

            if ( __copy_from_guest_offset(&gpfn, exch.out.extent_start,
                                          (i << out_chunk_order) + j, 1) )
            {
                rc = -EFAULT;
                continue;
            }

            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, _gfn(gpfn), mfn,
                                   exch.out.extent_order);

            if ( !paging_mode_translate(d) &&
                 __copy_mfn_to_guest_offset(exch.out.extent_start,
                                            (i << out_chunk_order) + j,
                                            mfn) )
                rc = -EFAULT;
        }
        BUG_ON( !(d->is_dying) && (j != (1UL << out_chunk_order)) );

        if ( rc )
            goto fail;
    }

    exch.nr_exchanged = exch.in.nr_extents;
    if ( __copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    rcu_unlock_domain(d);
    return rc;

    /*
     * Failed a chunk! Free any partial chunk work. Tell caller how many
     * chunks succeeded.
     */
 fail:
    /*
     * Reassign any input pages we managed to steal.  NB that if the assign
     * fails again, we're on the hook for freeing the page, since we've already
     * cleared PGC_allocated.
     */
    while ( (page = page_list_remove_head(&in_chunk_list)) )
        if ( assign_pages(d, page, 0, MEMF_no_refcount) )
        {
            BUG_ON(!d->is_dying);
            free_domheap_page(page);
        }

 dying:
    rcu_unlock_domain(d);
    /* Free any output pages we managed to allocate. */
    while ( (page = page_list_remove_head(&out_chunk_list)) )
        free_domheap_pages(page, exch.out.extent_order);

    exch.nr_exchanged = i << in_chunk_order;

 fail_early:
    if ( __copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    return rc;
}

int xenmem_add_to_physmap(struct domain *d, struct xen_add_to_physmap *xatp,
                          unsigned int start)
{
    unsigned int done = 0;
    long rc = 0;
    union xen_add_to_physmap_batch_extra extra;

    ASSERT(paging_mode_translate(d));

    if ( xatp->space != XENMAPSPACE_gmfn_foreign )
        extra.res0 = 0;
    else
        extra.foreign_domid = DOMID_INVALID;

    if ( xatp->space != XENMAPSPACE_gmfn_range )
        return xenmem_add_to_physmap_one(d, xatp->space, extra,
                                         xatp->idx, _gfn(xatp->gpfn));

    if ( xatp->size < start )
        return -EILSEQ;

    xatp->idx += start;
    xatp->gpfn += start;
    xatp->size -= start;

    if ( has_iommu_pt(d) )
       this_cpu(iommu_dont_flush_iotlb) = 1;

    while ( xatp->size > done )
    {
        rc = xenmem_add_to_physmap_one(d, XENMAPSPACE_gmfn, extra,
                                       xatp->idx, _gfn(xatp->gpfn));
        if ( rc < 0 )
            break;

        xatp->idx++;
        xatp->gpfn++;

        /* Check for continuation if it's not the last iteration. */
        if ( xatp->size > ++done && hypercall_preempt_check() )
        {
            rc = start + done;
            break;
        }
    }

    if ( has_iommu_pt(d) )
    {
        int ret;

        this_cpu(iommu_dont_flush_iotlb) = 0;

        ret = iommu_iotlb_flush(d, _dfn(xatp->idx - done), done,
                                IOMMU_FLUSHF_added | IOMMU_FLUSHF_modified);
        if ( unlikely(ret) && rc >= 0 )
            rc = ret;

        ret = iommu_iotlb_flush(d, _dfn(xatp->gpfn - done), done,
                                IOMMU_FLUSHF_added | IOMMU_FLUSHF_modified);
        if ( unlikely(ret) && rc >= 0 )
            rc = ret;
    }

    return rc;
}

static int xenmem_add_to_physmap_batch(struct domain *d,
                                       struct xen_add_to_physmap_batch *xatpb,
                                       unsigned int extent)
{
    if ( unlikely(xatpb->size < extent) )
        return -EILSEQ;

    if ( unlikely(xatpb->size == extent) )
        return extent ? -EILSEQ : 0;

    if ( !guest_handle_subrange_okay(xatpb->idxs, extent, xatpb->size - 1) ||
         !guest_handle_subrange_okay(xatpb->gpfns, extent, xatpb->size - 1) ||
         !guest_handle_subrange_okay(xatpb->errs, extent, xatpb->size - 1) )
        return -EFAULT;

    while ( xatpb->size > extent )
    {
        xen_ulong_t idx;
        xen_pfn_t gpfn;
        int rc;

        if ( unlikely(__copy_from_guest_offset(&idx, xatpb->idxs,
                                               extent, 1)) ||
             unlikely(__copy_from_guest_offset(&gpfn, xatpb->gpfns,
                                               extent, 1)) )
            return -EFAULT;

        rc = xenmem_add_to_physmap_one(d, xatpb->space,
                                       xatpb->u,
                                       idx, _gfn(gpfn));

        if ( unlikely(__copy_to_guest_offset(xatpb->errs, extent, &rc, 1)) )
            return -EFAULT;

        /* Check for continuation if it's not the last iteration. */
        if ( xatpb->size > ++extent && hypercall_preempt_check() )
            return extent;
    }

    return 0;
}

static int construct_memop_from_reservation(
               const struct xen_memory_reservation *r,
               struct memop_args *a)
{
    unsigned int address_bits;

    a->extent_list  = r->extent_start;
    a->nr_extents   = r->nr_extents;
    a->extent_order = r->extent_order;
    a->memflags     = 0;

    address_bits = XENMEMF_get_address_bits(r->mem_flags);
    if ( (address_bits != 0) &&
         (address_bits < (get_order_from_pages(max_page) + PAGE_SHIFT)) )
    {
        if ( address_bits <= PAGE_SHIFT )
            return -EINVAL;
        a->memflags = MEMF_bits(address_bits);
    }

    if ( r->mem_flags & XENMEMF_vnode )
    {
        nodeid_t vnode, pnode;
        struct domain *d = a->domain;

        read_lock(&d->vnuma_rwlock);
        if ( d->vnuma )
        {
            vnode = XENMEMF_get_node(r->mem_flags);
            if ( vnode >= d->vnuma->nr_vnodes )
            {
                read_unlock(&d->vnuma_rwlock);
                return -EINVAL;
            }

            pnode = d->vnuma->vnode_to_pnode[vnode];
            if ( pnode != NUMA_NO_NODE )
            {
                a->memflags |= MEMF_node(pnode);
                if ( r->mem_flags & XENMEMF_exact_node_request )
                    a->memflags |= MEMF_exact_node;
            }
        }
        read_unlock(&d->vnuma_rwlock);
    }
    else if ( unlikely(!propagate_node(r->mem_flags, &a->memflags)) )
        return -EINVAL;

    return 0;
}

#ifdef CONFIG_HAS_PASSTHROUGH
struct get_reserved_device_memory {
    struct xen_reserved_device_memory_map map;
    unsigned int used_entries;
};

static int get_reserved_device_memory(xen_pfn_t start, xen_ulong_t nr,
                                      u32 id, void *ctxt)
{
    struct get_reserved_device_memory *grdm = ctxt;
    uint32_t sbdf = PCI_SBDF3(grdm->map.dev.pci.seg, grdm->map.dev.pci.bus,
                              grdm->map.dev.pci.devfn).sbdf;

    if ( !(grdm->map.flags & XENMEM_RDM_ALL) && (sbdf != id) )
        return 0;

    if ( grdm->used_entries < grdm->map.nr_entries )
    {
        struct xen_reserved_device_memory rdm = {
            .start_pfn = start, .nr_pages = nr
        };

        if ( __copy_to_guest_offset(grdm->map.buffer, grdm->used_entries,
                                    &rdm, 1) )
            return -EFAULT;
    }

    ++grdm->used_entries;

    return 1;
}
#endif

static long xatp_permission_check(struct domain *d, unsigned int space)
{
    if ( !paging_mode_translate(d) )
        return -EACCES;

    /*
     * XENMAPSPACE_dev_mmio mapping is only supported for hardware Domain
     * to map this kind of space to itself.
     */
    if ( (space == XENMAPSPACE_dev_mmio) &&
         (!is_hardware_domain(d) || (d != current->domain)) )
        return -EACCES;

    return xsm_add_to_physmap(XSM_TARGET, current->domain, d);
}

static int acquire_grant_table(struct domain *d, unsigned int id,
                               unsigned long frame,
                               unsigned int nr_frames,
                               xen_pfn_t mfn_list[])
{
    unsigned int i = nr_frames;

    /* Iterate backwards in case table needs to grow */
    while ( i-- != 0 )
    {
        mfn_t mfn = INVALID_MFN;
        int rc;

        switch ( id )
        {
        case XENMEM_resource_grant_table_id_shared:
            rc = gnttab_get_shared_frame(d, frame + i, &mfn);
            break;

        case XENMEM_resource_grant_table_id_status:
            rc = gnttab_get_status_frame(d, frame + i, &mfn);
            break;

        default:
            rc = -EINVAL;
            break;
        }

        if ( rc )
            return rc;

        ASSERT(!mfn_eq(mfn, INVALID_MFN));
        mfn_list[i] = mfn_x(mfn);
    }

    return 0;
}

static int acquire_resource(
    XEN_GUEST_HANDLE_PARAM(xen_mem_acquire_resource_t) arg)
{
    struct domain *d, *currd = current->domain;
    xen_mem_acquire_resource_t xmar;
    /*
     * The mfn_list and gfn_list (below) arrays are ok on stack for the
     * moment since they are small, but if they need to grow in future
     * use-cases then per-CPU arrays or heap allocations may be required.
     */
    xen_pfn_t mfn_list[32];
    int rc;

    if ( copy_from_guest(&xmar, arg, 1) )
        return -EFAULT;

    if ( xmar.flags != 0 )
        return -EINVAL;

    if ( guest_handle_is_null(xmar.frame_list) )
    {
        if ( xmar.nr_frames )
            return -EINVAL;

        xmar.nr_frames = ARRAY_SIZE(mfn_list);

        if ( __copy_field_to_guest(arg, &xmar, nr_frames) )
            return -EFAULT;

        return 0;
    }

    if ( xmar.nr_frames > ARRAY_SIZE(mfn_list) )
        return -E2BIG;

    rc = rcu_lock_remote_domain_by_id(xmar.domid, &d);
    if ( rc )
        return rc;

    rc = xsm_domain_resource_map(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    switch ( xmar.type )
    {
    case XENMEM_resource_grant_table:
        rc = acquire_grant_table(d, xmar.id, xmar.frame, xmar.nr_frames,
                                 mfn_list);
        break;

    default:
        rc = arch_acquire_resource(d, xmar.type, xmar.id, xmar.frame,
                                   xmar.nr_frames, mfn_list, &xmar.flags);
        break;
    }

    if ( rc )
        goto out;

    if ( !paging_mode_translate(currd) )
    {
        if ( copy_to_guest(xmar.frame_list, mfn_list, xmar.nr_frames) )
            rc = -EFAULT;
    }
    else
    {
        xen_pfn_t gfn_list[ARRAY_SIZE(mfn_list)];
        unsigned int i;

        /*
         * FIXME: Until foreign pages inserted into the P2M are properly
         *        reference counted, it is unsafe to allow mapping of
         *        non-caller-owned resource pages unless the caller is
         *        the hardware domain.
         */
        if ( !(xmar.flags & XENMEM_rsrc_acq_caller_owned) &&
             !is_hardware_domain(currd) )
            return -EACCES;

        if ( copy_from_guest(gfn_list, xmar.frame_list, xmar.nr_frames) )
            rc = -EFAULT;

        for ( i = 0; !rc && i < xmar.nr_frames; i++ )
        {
            rc = set_foreign_p2m_entry(currd, gfn_list[i],
                                       _mfn(mfn_list[i]));
            /* rc should be -EIO for any iteration other than the first */
            if ( rc && i )
                rc = -EIO;
        }
    }

    if ( xmar.flags != 0 &&
         __copy_field_to_guest(arg, &xmar, flags) )
        rc = -EFAULT;

 out:
    rcu_unlock_domain(d);

    return rc;
}

long do_memory_op(unsigned long cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct domain *d, *curr_d = current->domain;
    long rc;
    struct xen_memory_reservation reservation;
    struct memop_args args;
    domid_t domid;
    unsigned long start_extent = cmd >> MEMOP_EXTENT_SHIFT;
    int op = cmd & MEMOP_CMD_MASK;

    switch ( op )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        if ( copy_from_guest(&reservation, arg, 1) )
            return start_extent;

        /* Is size too large for us to encode a continuation? */
        if ( reservation.nr_extents > (UINT_MAX >> MEMOP_EXTENT_SHIFT) )
            return start_extent;

        if ( unlikely(start_extent >= reservation.nr_extents) )
            return start_extent;

        d = rcu_lock_domain_by_any_id(reservation.domid);
        if ( d == NULL )
            return start_extent;
        args.domain = d;

        if ( construct_memop_from_reservation(&reservation, &args) )
        {
            rcu_unlock_domain(d);
            return start_extent;
        }

        args.nr_done   = start_extent;
        args.preempted = 0;

        if ( op == XENMEM_populate_physmap
             && (reservation.mem_flags & XENMEMF_populate_on_demand) )
            args.memflags |= MEMF_populate_on_demand;

        if ( xsm_memory_adjust_reservation(XSM_TARGET, curr_d, d) )
        {
            rcu_unlock_domain(d);
            return start_extent;
        }

#ifdef CONFIG_X86
        if ( pv_shim && op != XENMEM_decrease_reservation && !args.preempted )
            /* Avoid calling pv_shim_online_memory when preempted. */
            pv_shim_online_memory(args.nr_extents, args.extent_order);
#endif

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

#ifdef CONFIG_X86
        if ( pv_shim && op == XENMEM_decrease_reservation )
            /*
             * Only call pv_shim_offline_memory when the hypercall has
             * finished. Note that nr_done is used to cope in case the
             * hypercall has failed and only part of the extents where
             * processed.
             */
            pv_shim_offline_memory(args.nr_extents, args.nr_done);
#endif

        break;

    case XENMEM_exchange:
        if ( unlikely(start_extent) )
            return -EINVAL;

        rc = memory_exchange(guest_handle_cast(arg, xen_memory_exchange_t));
        break;

    case XENMEM_maximum_ram_page:
        if ( unlikely(start_extent) )
            return -EINVAL;

        rc = max_page;
        break;

    case XENMEM_current_reservation:
    case XENMEM_maximum_reservation:
    case XENMEM_maximum_gpfn:
        if ( unlikely(start_extent) )
            return -EINVAL;

        if ( copy_from_guest(&domid, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_memory_stat_reservation(XSM_TARGET, curr_d, d);
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

    case XENMEM_add_to_physmap:
    {
        struct xen_add_to_physmap xatp;

        BUILD_BUG_ON((typeof(xatp.size))-1 > (UINT_MAX >> MEMOP_EXTENT_SHIFT));

        /* Check for malicious or buggy input. */
        if ( start_extent != (typeof(xatp.size))start_extent )
            return -EDOM;

        if ( copy_from_guest(&xatp, arg, 1) )
            return -EFAULT;

        /* Foreign mapping is only possible via add_to_physmap_batch. */
        if ( xatp.space == XENMAPSPACE_gmfn_foreign )
            return -ENOSYS;

        d = rcu_lock_domain_by_any_id(xatp.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xatp_permission_check(d, xatp.space);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        rc = xenmem_add_to_physmap(d, &xatp, start_extent);

        rcu_unlock_domain(d);

        if ( xatp.space == XENMAPSPACE_gmfn_range && rc > 0 )
            rc = hypercall_create_continuation(
                     __HYPERVISOR_memory_op, "lh",
                     op | (rc << MEMOP_EXTENT_SHIFT), arg);

        return rc;
    }

    case XENMEM_add_to_physmap_batch:
    {
        struct xen_add_to_physmap_batch xatpb;

        BUILD_BUG_ON((typeof(xatpb.size))-1 >
                     (UINT_MAX >> MEMOP_EXTENT_SHIFT));

        /* Check for malicious or buggy input. */
        if ( start_extent != (typeof(xatpb.size))start_extent )
            return -EDOM;

        if ( copy_from_guest(&xatpb, arg, 1) )
            return -EFAULT;

        /* This mapspace is unsupported for this hypercall. */
        if ( xatpb.space == XENMAPSPACE_gmfn_range )
            return -EOPNOTSUPP;

        d = rcu_lock_domain_by_any_id(xatpb.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xatp_permission_check(d, xatpb.space);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        rc = xenmem_add_to_physmap_batch(d, &xatpb, start_extent);

        rcu_unlock_domain(d);

        if ( rc > 0 )
            rc = hypercall_create_continuation(
                    __HYPERVISOR_memory_op, "lh",
                    op | (rc << MEMOP_EXTENT_SHIFT), arg);

        return rc;
    }

    case XENMEM_remove_from_physmap:
    {
        struct xen_remove_from_physmap xrfp;
        struct page_info *page;

        if ( unlikely(start_extent) )
            return -EINVAL;

        if ( copy_from_guest(&xrfp, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(xrfp.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = paging_mode_translate(d)
             ? xsm_remove_from_physmap(XSM_TARGET, curr_d, d)
             : -EACCES;
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        page = get_page_from_gfn(d, xrfp.gpfn, NULL, P2M_ALLOC);
        if ( page )
        {
            rc = guest_physmap_remove_page(d, _gfn(xrfp.gpfn),
                                           page_to_mfn(page), 0);
            put_page(page);
        }
        else
            rc = -ENOENT;

        rcu_unlock_domain(d);

        break;
    }

    case XENMEM_access_op:
        rc = mem_access_memop(cmd, guest_handle_cast(arg, xen_mem_access_op_t));
        break;

    case XENMEM_claim_pages:
        if ( unlikely(start_extent) )
            return -EINVAL;

        if ( copy_from_guest(&reservation, arg, 1) )
            return -EFAULT;

        if ( !guest_handle_is_null(reservation.extent_start) )
            return -EINVAL;

        if ( reservation.extent_order != 0 )
            return -EINVAL;

        if ( reservation.mem_flags != 0 )
            return -EINVAL;

        d = rcu_lock_domain_by_id(reservation.domid);
        if ( d == NULL )
            return -EINVAL;

        rc = xsm_claim_pages(XSM_PRIV, d);

        if ( !rc )
            rc = domain_set_outstanding_pages(d, reservation.nr_extents);

        rcu_unlock_domain(d);

        break;

    case XENMEM_get_vnumainfo:
    {
        struct xen_vnuma_topology_info topology;
        unsigned int dom_vnodes, dom_vranges, dom_vcpus;
        struct vnuma_info tmp;

        if ( unlikely(start_extent) )
            return -EINVAL;

        /*
         * Guest passes nr_vnodes, number of regions and nr_vcpus thus
         * we know how much memory guest has allocated.
         */
        if ( copy_from_guest(&topology, arg, 1 ))
            return -EFAULT;

        if ( topology.pad != 0 )
            return -EINVAL;

        if ( (d = rcu_lock_domain_by_any_id(topology.domid)) == NULL )
            return -ESRCH;

        rc = xsm_get_vnumainfo(XSM_TARGET, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        read_lock(&d->vnuma_rwlock);

        if ( d->vnuma == NULL )
        {
            read_unlock(&d->vnuma_rwlock);
            rcu_unlock_domain(d);
            return -EOPNOTSUPP;
        }

        dom_vnodes = d->vnuma->nr_vnodes;
        dom_vranges = d->vnuma->nr_vmemranges;
        dom_vcpus = d->max_vcpus;

        /*
         * Copied from guest values may differ from domain vnuma config.
         * Check here guest parameters make sure we dont overflow.
         * Additionaly check padding.
         */
        if ( topology.nr_vnodes < dom_vnodes      ||
             topology.nr_vcpus < dom_vcpus        ||
             topology.nr_vmemranges < dom_vranges )
        {
            read_unlock(&d->vnuma_rwlock);
            rcu_unlock_domain(d);

            topology.nr_vnodes = dom_vnodes;
            topology.nr_vcpus = dom_vcpus;
            topology.nr_vmemranges = dom_vranges;

            /* Copy back needed values. */
            return __copy_to_guest(arg, &topology, 1) ? -EFAULT : -ENOBUFS;
        }

        read_unlock(&d->vnuma_rwlock);

        tmp.vdistance = xmalloc_array(unsigned int, dom_vnodes * dom_vnodes);
        tmp.vmemrange = xmalloc_array(xen_vmemrange_t, dom_vranges);
        tmp.vcpu_to_vnode = xmalloc_array(unsigned int, dom_vcpus);

        if ( tmp.vdistance == NULL ||
             tmp.vmemrange == NULL ||
             tmp.vcpu_to_vnode == NULL )
        {
            rc = -ENOMEM;
            goto vnumainfo_out;
        }

        /*
         * Check if vnuma info has changed and if the allocated arrays
         * are not big enough.
         */
        read_lock(&d->vnuma_rwlock);

        if ( dom_vnodes < d->vnuma->nr_vnodes ||
             dom_vranges < d->vnuma->nr_vmemranges ||
             dom_vcpus < d->max_vcpus )
        {
            read_unlock(&d->vnuma_rwlock);
            rc = -EAGAIN;
            goto vnumainfo_out;
        }

        dom_vnodes = d->vnuma->nr_vnodes;
        dom_vranges = d->vnuma->nr_vmemranges;
        dom_vcpus = d->max_vcpus;

        memcpy(tmp.vmemrange, d->vnuma->vmemrange,
               sizeof(*d->vnuma->vmemrange) * dom_vranges);
        memcpy(tmp.vdistance, d->vnuma->vdistance,
               sizeof(*d->vnuma->vdistance) * dom_vnodes * dom_vnodes);
        memcpy(tmp.vcpu_to_vnode, d->vnuma->vcpu_to_vnode,
               sizeof(*d->vnuma->vcpu_to_vnode) * dom_vcpus);

        read_unlock(&d->vnuma_rwlock);

        rc = -EFAULT;

        if ( copy_to_guest(topology.vmemrange.h, tmp.vmemrange,
                           dom_vranges) != 0 )
            goto vnumainfo_out;

        if ( copy_to_guest(topology.vdistance.h, tmp.vdistance,
                           dom_vnodes * dom_vnodes) != 0 )
            goto vnumainfo_out;

        if ( copy_to_guest(topology.vcpu_to_vnode.h, tmp.vcpu_to_vnode,
                           dom_vcpus) != 0 )
            goto vnumainfo_out;

        topology.nr_vnodes = dom_vnodes;
        topology.nr_vcpus = dom_vcpus;
        topology.nr_vmemranges = dom_vranges;

        rc = __copy_to_guest(arg, &topology, 1) ? -EFAULT : 0;

 vnumainfo_out:
        rcu_unlock_domain(d);

        xfree(tmp.vdistance);
        xfree(tmp.vmemrange);
        xfree(tmp.vcpu_to_vnode);
        break;
    }

#ifdef CONFIG_HAS_PASSTHROUGH
    case XENMEM_reserved_device_memory_map:
    {
        struct get_reserved_device_memory grdm;

        if ( unlikely(start_extent) )
            return -EINVAL;

        if ( copy_from_guest(&grdm.map, arg, 1) ||
             !guest_handle_okay(grdm.map.buffer, grdm.map.nr_entries) )
            return -EFAULT;

        if ( grdm.map.flags & ~XENMEM_RDM_ALL )
            return -EINVAL;

        grdm.used_entries = 0;
        rc = iommu_get_reserved_device_memory(get_reserved_device_memory,
                                              &grdm);

        if ( !rc && grdm.map.nr_entries < grdm.used_entries )
            rc = -ENOBUFS;
        grdm.map.nr_entries = grdm.used_entries;
        if ( __copy_to_guest(arg, &grdm.map, 1) )
            rc = -EFAULT;

        break;
    }
#endif

    case XENMEM_acquire_resource:
        rc = acquire_resource(
            guest_handle_cast(arg, xen_mem_acquire_resource_t));
        break;

    default:
        rc = arch_memory_op(cmd, arg);
        break;
    }

    return rc;
}

void clear_domain_page(mfn_t mfn)
{
    void *ptr = map_domain_page(mfn);

    clear_page(ptr);
    unmap_domain_page(ptr);
}

void copy_domain_page(mfn_t dest, mfn_t source)
{
    const void *src = map_domain_page(source);
    void *dst = map_domain_page(dest);

    copy_page(dst, src);
    unmap_domain_page(dst);
    unmap_domain_page(src);
}

void destroy_ring_for_helper(
    void **_va, struct page_info *page)
{
    void *va = *_va;

    if ( va != NULL )
    {
        unmap_domain_page_global(va);
        put_page_and_type(page);
        *_va = NULL;
    }
}

/*
 * Acquire a pointer to struct page_info for a specified domain and GFN,
 * checking whether the page has been paged out, or needs unsharing.
 * If the function succeeds then zero is returned, page_p is written
 * with a pointer to the struct page_info with a reference taken, and
 * p2mt_p it is written with the P2M type of the page. The caller is
 * responsible for dropping the reference.
 * If the function fails then an appropriate errno is returned and the
 * values referenced by page_p and p2mt_p are undefined.
 */
int check_get_page_from_gfn(struct domain *d, gfn_t gfn, bool readonly,
                            p2m_type_t *p2mt_p, struct page_info **page_p)
{
    p2m_query_t q = readonly ? P2M_ALLOC : P2M_UNSHARE;
    p2m_type_t p2mt;
    struct page_info *page;

    page = get_page_from_gfn(d, gfn_x(gfn), &p2mt, q);

#ifdef CONFIG_HAS_MEM_PAGING
    if ( p2m_is_paging(p2mt) )
    {
        if ( page )
            put_page(page);

        p2m_mem_paging_populate(d, gfn_x(gfn));
        return -EAGAIN;
    }
#endif
#ifdef CONFIG_HAS_MEM_SHARING
    if ( (q & P2M_UNSHARE) && p2m_is_shared(p2mt) )
    {
        if ( page )
            put_page(page);

        return -EAGAIN;
    }
#endif

    if ( !page )
        return -EINVAL;

    *p2mt_p = p2mt;
    *page_p = page;
    return 0;
}

int prepare_ring_for_helper(
    struct domain *d, unsigned long gmfn, struct page_info **_page,
    void **_va)
{
    p2m_type_t p2mt;
    struct page_info *page;
    void *va;
    int rc;

    rc = check_get_page_from_gfn(d, _gfn(gmfn), false, &p2mt, &page);
    if ( rc )
        return (rc == -EAGAIN) ? -ENOENT : rc;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        return -EINVAL;
    }

    va = __map_domain_page_global(page);
    if ( va == NULL )
    {
        put_page_and_type(page);
        return -ENOMEM;
    }

    *_va = va;
    *_page = page;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
