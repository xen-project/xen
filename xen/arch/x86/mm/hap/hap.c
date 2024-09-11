/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/hap/hap.c
 *
 * hardware assisted paging
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Parts of this code are Copyright (c) 2007 by XenSource Inc.
 */

#include <xen/types.h>
#include <xen/mm.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <asm/altp2m.h>
#include <asm/event.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/shared.h>
#include <asm/hap.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/domain.h>
#include <xen/numa.h>
#include <asm/hvm/nestedhvm.h>
#include <public/sched.h>

#include "private.h"

/************************************************/
/*          HAP VRAM TRACKING SUPPORT           */
/************************************************/

/*
 * hap_track_dirty_vram()
 * Create the domain's dv_dirty_vram struct on demand.
 * Create a dirty vram range on demand when some [begin_pfn:begin_pfn+nr] is
 * first encountered.
 * Collect the guest_dirty bitmask, a bit mask of the dirty vram pages, by
 * calling paging_log_dirty_range(), which interrogates each vram
 * page's p2m type looking for pages that have been made writable.
 */

int hap_track_dirty_vram(struct domain *d,
                         unsigned long begin_pfn,
                         unsigned int nr_frames,
                         XEN_GUEST_HANDLE(void) guest_dirty_bitmap)
{
    long rc = 0;
    struct sh_dirty_vram *dirty_vram;
    uint8_t *dirty_bitmap = NULL;

    if ( nr_frames )
    {
        unsigned int size = DIV_ROUND_UP(nr_frames, BITS_PER_BYTE);

        rc = -ENOMEM;
        dirty_bitmap = vzalloc(size);
        if ( !dirty_bitmap )
            goto out;

        paging_lock(d);

        dirty_vram = d->arch.hvm.dirty_vram;
        if ( !dirty_vram )
        {
            rc = -ENOMEM;
            if ( (dirty_vram = xzalloc(struct sh_dirty_vram)) == NULL )
            {
                paging_unlock(d);
                goto out;
            }

            d->arch.hvm.dirty_vram = dirty_vram;
        }

        if ( begin_pfn != dirty_vram->begin_pfn ||
             begin_pfn + nr_frames != dirty_vram->end_pfn )
        {
            unsigned long ostart = dirty_vram->begin_pfn;
            unsigned long oend = dirty_vram->end_pfn;

            dirty_vram->begin_pfn = begin_pfn;
            dirty_vram->end_pfn = begin_pfn + nr_frames;

            paging_unlock(d);

            domain_pause(d);
            p2m_enable_hardware_log_dirty(d);
            domain_unpause(d);

            if ( oend > ostart )
                p2m_change_type_range(d, ostart, oend,
                                      p2m_ram_logdirty, p2m_ram_rw);

            /*
             * Switch vram to log dirty mode, either by setting l1e entries of
             * P2M table to be read-only, or via hardware-assisted log-dirty.
             */
            p2m_change_type_range(d, begin_pfn, begin_pfn + nr_frames,
                                  p2m_ram_rw, p2m_ram_logdirty);

            guest_flush_tlb_mask(d, d->dirty_cpumask);

            memset(dirty_bitmap, 0xff, size); /* consider all pages dirty */
        }
        else
        {
            paging_unlock(d);

            domain_pause(d);

            /* Flush dirty GFNs potentially cached by hardware. */
            p2m_flush_hardware_cached_dirty(d);

            /* get the bitmap */
            paging_log_dirty_range(d, begin_pfn, nr_frames, dirty_bitmap);

            domain_unpause(d);
        }

        rc = -EFAULT;
        if ( copy_to_guest(guest_dirty_bitmap, dirty_bitmap, size) == 0 )
            rc = 0;
    }
    else
    {
        paging_lock(d);

        dirty_vram = d->arch.hvm.dirty_vram;
        if ( dirty_vram )
        {
            /*
             * If zero pages specified while tracking dirty vram
             * then stop tracking
             */
            begin_pfn = dirty_vram->begin_pfn;
            nr_frames = dirty_vram->end_pfn - dirty_vram->begin_pfn;
            xfree(dirty_vram);
            d->arch.hvm.dirty_vram = NULL;
        }

        paging_unlock(d);

        if ( nr_frames )
            p2m_change_type_range(d, begin_pfn, begin_pfn + nr_frames,
                                  p2m_ram_logdirty, p2m_ram_rw);
    }
out:
    vfree(dirty_bitmap);

    return rc;
}

/************************************************/
/*            HAP LOG DIRTY SUPPORT             */
/************************************************/

/*
 * hap code to call when log_dirty is enable. return 0 if no problem found.
 *
 * NB: Domains having a device assigned should not come here, because
 * there is no way to track the memory updating from device.
 */
static int cf_check hap_enable_log_dirty(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    /*
     * Refuse to turn on global log-dirty mode if
     * there are outstanding p2m_ioreq_server pages.
     */
    if ( read_atomic(&p2m->ioreq.entry_count) )
        return -EBUSY;

    /* turn on PG_log_dirty bit in paging mode */
    paging_lock(d);
    d->arch.paging.mode |= PG_log_dirty;
    paging_unlock(d);

    /* Enable hardware-assisted log-dirty if it is supported. */
    p2m_enable_hardware_log_dirty(d);

    /*
     * Switch to log dirty mode, either by setting l1e entries of P2M table
     * to be read-only, or via hardware-assisted log-dirty.
     */
    p2m_change_entry_type_global(d, p2m_ram_rw, p2m_ram_logdirty);
    guest_flush_tlb_mask(d, d->dirty_cpumask);

    return 0;
}

static int cf_check hap_disable_log_dirty(struct domain *d)
{
    paging_lock(d);
    d->arch.paging.mode &= ~PG_log_dirty;
    paging_unlock(d);

    /* Disable hardware-assisted log-dirty if it is supported. */
    p2m_disable_hardware_log_dirty(d);

    /*
     * switch to normal mode, either by setting l1e entries of P2M table to
     * normal mode, or via hardware-assisted log-dirty.
     */
    p2m_change_entry_type_global(d, p2m_ram_logdirty, p2m_ram_rw);
    return 0;
}

static void cf_check hap_clean_dirty_bitmap(struct domain *d)
{
    /*
     * Switch to log-dirty mode, either by setting l1e entries of P2M table to
     * be read-only, or via hardware-assisted log-dirty.
     */
    p2m_change_entry_type_global(d, p2m_ram_rw, p2m_ram_logdirty);
    guest_flush_tlb_mask(d, d->dirty_cpumask);
}

/************************************************/
/*             HAP SUPPORT FUNCTIONS            */
/************************************************/
static struct page_info *hap_alloc(struct domain *d)
{
    struct page_info *pg;

    ASSERT(paging_locked_by_me(d));

    if ( unlikely(d->is_dying) )
        return NULL;

    pg = page_list_remove_head(&d->arch.paging.freelist);
    if ( unlikely(!pg) )
        return NULL;

    d->arch.paging.free_pages--;

    clear_domain_page(page_to_mfn(pg));

    return pg;
}

static void hap_free(struct domain *d, mfn_t mfn)
{
    struct page_info *pg = mfn_to_page(mfn);

    ASSERT(paging_locked_by_me(d));

    /*
     * For dying domains, actually free the memory here. This way less work is
     * left to paging_final_teardown(), which cannot easily have preemption
     * checks added.
     */
    if ( unlikely(d->is_dying) )
    {
        free_domheap_page(pg);
        d->arch.paging.total_pages--;
        return;
    }

    d->arch.paging.free_pages++;
    page_list_add_tail(pg, &d->arch.paging.freelist);
}

static struct page_info *cf_check hap_alloc_p2m_page(struct domain *d)
{
    struct page_info *pg;

    /* This is called both from the p2m code (which never holds the 
     * paging lock) and the log-dirty code (which always does). */
    paging_lock_recursive(d);
    pg = hap_alloc(d);

    if ( likely(pg != NULL) )
    {
        d->arch.paging.total_pages--;
        d->arch.paging.p2m_pages++;
        ASSERT(!page_get_owner(pg) && !(pg->count_info & PGC_count_mask));
    }
    else if ( !d->arch.paging.p2m_alloc_failed && !d->is_dying )
    {
        d->arch.paging.p2m_alloc_failed = 1;
        dprintk(XENLOG_ERR, "d%i failed to allocate from HAP pool\n",
                d->domain_id);
    }

    paging_unlock(d);
    return pg;
}

static void cf_check hap_free_p2m_page(struct domain *d, struct page_info *pg)
{
    struct domain *owner = page_get_owner(pg);

    /* This is called both from the p2m code (which never holds the 
     * paging lock) and the log-dirty code (which always does). */
    paging_lock_recursive(d);

    /* Should still have no owner and count zero. */
    if ( owner || (pg->count_info & PGC_count_mask) )
    {
        printk(XENLOG_WARNING
               "d%d: Odd p2m page %"PRI_mfn" d=%d c=%lx t=%"PRtype_info"\n",
               d->domain_id, mfn_x(page_to_mfn(pg)),
               owner ? owner->domain_id : DOMID_INVALID,
               pg->count_info, pg->u.inuse.type_info);
        WARN();
        pg->count_info &= ~PGC_count_mask;
        page_set_owner(pg, NULL);
    }
    d->arch.paging.p2m_pages--;
    d->arch.paging.total_pages++;
    hap_free(d, page_to_mfn(pg));

    paging_unlock(d);
}

/* Return the size of the pool, rounded up to the nearest MB */
unsigned int hap_get_allocation(struct domain *d)
{
    unsigned int pg = d->arch.paging.total_pages
        + d->arch.paging.p2m_pages;

    return ((pg >> (20 - PAGE_SHIFT))
            + ((pg & ((1 << (20 - PAGE_SHIFT)) - 1)) ? 1 : 0));
}

/* Set the pool of pages to the required number of pages.
 * Returns 0 for success, non-zero for failure. */
int hap_set_allocation(struct domain *d, unsigned int pages, bool *preempted)
{
    struct page_info *pg;

    ASSERT(paging_locked_by_me(d));

    if ( pages < d->arch.paging.p2m_pages )
        pages = 0;
    else
        pages -= d->arch.paging.p2m_pages;

    for ( ; ; )
    {
        if ( d->arch.paging.total_pages < pages )
        {
            /* Need to allocate more memory from domheap */
            pg = alloc_domheap_page(d, MEMF_no_owner);
            if ( pg == NULL )
            {
                HAP_PRINTK("failed to allocate hap pages.\n");
                return -ENOMEM;
            }
            d->arch.paging.free_pages++;
            d->arch.paging.total_pages++;
            page_list_add_tail(pg, &d->arch.paging.freelist);
        }
        else if ( d->arch.paging.total_pages > pages )
        {
            /* Need to return memory to domheap */
            if ( page_list_empty(&d->arch.paging.freelist) )
            {
                HAP_PRINTK("failed to free enough hap pages.\n");
                return -ENOMEM;
            }
            pg = page_list_remove_head(&d->arch.paging.freelist);
            ASSERT(pg);
            d->arch.paging.free_pages--;
            d->arch.paging.total_pages--;
            free_domheap_page(pg);
        }
        else
            break;

        /* Check to see if we need to yield and try again */
        if ( preempted && general_preempt_check() )
        {
            *preempted = true;
            return 0;
        }
    }

    return 0;
}

static mfn_t hap_make_monitor_table(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct page_info *pg;
    l4_pgentry_t *l4e;
    mfn_t m4mfn;

    ASSERT(pagetable_get_pfn(v->arch.hvm.monitor_table) == 0);

    if ( (pg = hap_alloc(d)) == NULL )
        goto oom;

    m4mfn = page_to_mfn(pg);
    l4e = map_domain_page(m4mfn);

    init_xen_l4_slots(l4e, m4mfn, d, INVALID_MFN, false);
    unmap_domain_page(l4e);

    return m4mfn;

 oom:
    if ( !d->is_dying &&
         (!d->is_shutting_down || d->shutdown_code != SHUTDOWN_crash) )
    {
        printk(XENLOG_G_ERR "%pd: out of memory building monitor pagetable\n",
               d);
        domain_crash(d);
    }
    return INVALID_MFN;
}

static void hap_destroy_monitor_table(struct vcpu* v, mfn_t mmfn)
{
    struct domain *d = v->domain;

    /* Put the memory back in the pool */
    hap_free(d, mmfn);
}

/************************************************/
/*          HAP DOMAIN LEVEL FUNCTIONS          */
/************************************************/

static void cf_check hap_update_paging_modes(struct vcpu *v);
static bool cf_check flush_tlb(const unsigned long *vcpu_bitmap);

void hap_domain_init(struct domain *d)
{
    static const struct log_dirty_ops hap_ops = {
        .enable  = hap_enable_log_dirty,
        .disable = hap_disable_log_dirty,
        .clean   = hap_clean_dirty_bitmap,
    };

    /* Use HAP logdirty mechanism. */
    paging_log_dirty_init(d, &hap_ops);

    d->arch.paging.update_paging_modes = hap_update_paging_modes;
    d->arch.paging.flush_tlb           = flush_tlb;
}

/* return 0 for success, -errno for failure */
int hap_enable(struct domain *d, u32 mode)
{
    unsigned int old_pages;
    unsigned int i;
    int rv = 0;

    if ( mode != (PG_external | PG_translate | PG_refcounts) )
        return -EINVAL;

    /* The function can only be called once per domain. */
    if ( d->arch.paging.mode != 0 )
        return -EEXIST;

    domain_pause(d);

    old_pages = d->arch.paging.total_pages;
    if ( old_pages == 0 )
    {
        paging_lock(d);
        rv = hap_set_allocation(d, 256, NULL);
        if ( rv != 0 )
        {
            hap_set_allocation(d, 0, NULL);
            paging_unlock(d);
            goto out;
        }
        paging_unlock(d);
    }

    /* Allow p2m and log-dirty code to borrow our memory */
    d->arch.paging.alloc_page = hap_alloc_p2m_page;
    d->arch.paging.free_page = hap_free_p2m_page;

    /* allocate P2M table */
    rv = p2m_alloc_table(p2m_get_hostp2m(d));
    if ( rv != 0 )
        goto out;

    for ( i = 0; i < MAX_NESTEDP2M; i++ )
    {
        rv = p2m_alloc_table(d->arch.nested_p2m[i]);
        if ( rv != 0 )
           goto out;
    }

    if ( hvm_altp2m_supported() )
    {
        /* Init alternate p2m data */
        if ( (d->arch.altp2m_eptp = alloc_xenheap_page()) == NULL )
        {
            rv = -ENOMEM;
            goto out;
        }

        if ( (d->arch.altp2m_visible_eptp = alloc_xenheap_page()) == NULL )
        {
            rv = -ENOMEM;
            goto out;
        }

        for ( i = 0; i < MAX_EPTP; i++ )
        {
            d->arch.altp2m_eptp[i] = mfn_x(INVALID_MFN);
            d->arch.altp2m_visible_eptp[i] = mfn_x(INVALID_MFN);
        }

        for ( i = 0; i < MAX_ALTP2M; i++ )
        {
            rv = p2m_alloc_table(d->arch.altp2m_p2m[i]);
            if ( rv != 0 )
               goto out;
        }

        d->arch.altp2m_active = false;
    }

    /* Now let other users see the new mode */
    d->arch.paging.mode = mode | PG_HAP_enable;

 out:
    domain_unpause(d);
    return rv;
}

void hap_final_teardown(struct domain *d)
{
    unsigned int i;

    if ( hvm_altp2m_supported() )
        for ( i = 0; i < MAX_ALTP2M; i++ )
            p2m_teardown(d->arch.altp2m_p2m[i], true, NULL);

    /* Destroy nestedp2m's first */
    for (i = 0; i < MAX_NESTEDP2M; i++) {
        p2m_teardown(d->arch.nested_p2m[i], true, NULL);
    }
}

void hap_vcpu_teardown(struct vcpu *v)
{
    struct domain *d = v->domain;
    mfn_t mfn;

    paging_lock(d);

    if ( !paging_mode_hap(d) || !v->arch.paging.mode )
        goto out;

    mfn = pagetable_get_mfn(v->arch.hvm.monitor_table);
    if ( mfn_x(mfn) )
        hap_destroy_monitor_table(v, mfn);
    v->arch.hvm.monitor_table = pagetable_null();

 out:
    paging_unlock(d);
}

void hap_teardown(struct domain *d, bool *preempted)
{
    struct vcpu *v;
    unsigned int i;

    ASSERT(d->is_dying);
    ASSERT(d != current->domain);

    /* TODO - Remove when the teardown path is better structured. */
    for_each_vcpu ( d, v )
        hap_vcpu_teardown(v);

    /* Leave the root pt in case we get further attempts to modify the p2m. */
    if ( hvm_altp2m_supported() )
    {
        if ( altp2m_active(d) )
            for_each_vcpu ( d, v )
                altp2m_vcpu_disable_ve(v);

        d->arch.altp2m_active = false;

        FREE_XENHEAP_PAGE(d->arch.altp2m_eptp);
        FREE_XENHEAP_PAGE(d->arch.altp2m_visible_eptp);

        for ( i = 0; i < MAX_ALTP2M; i++ )
        {
            p2m_teardown(d->arch.altp2m_p2m[i], false, preempted);
            if ( preempted && *preempted )
                return;
        }
    }

    /* Destroy nestedp2m's after altp2m. */
    for ( i = 0; i < MAX_NESTEDP2M; i++ )
    {
        p2m_teardown(d->arch.nested_p2m[i], false, preempted);
        if ( preempted && *preempted )
            return;
    }

    p2m_teardown(p2m_get_hostp2m(d), false, preempted);
    if ( preempted && *preempted )
        return;

    paging_lock(d); /* Keep various asserts happy */

    if ( d->arch.paging.total_pages != 0 )
    {
        hap_set_allocation(d, 0, preempted);

        if ( preempted && *preempted )
            goto out;

        ASSERT(d->arch.paging.total_pages == 0);
    }

    d->arch.paging.mode &= ~PG_log_dirty;

    XFREE(d->arch.hvm.dirty_vram);

out:
    paging_unlock(d);
}

int hap_domctl(struct domain *d, struct xen_domctl_shadow_op *sc,
               XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    int rc;
    bool preempted = false;

    switch ( sc->op )
    {
    case XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION:
        paging_lock(d);
        rc = hap_set_allocation(d, sc->mb << (20 - PAGE_SHIFT), &preempted);
        paging_unlock(d);
        if ( preempted )
            /* Not finished.  Set up to re-run the call. */
            rc = hypercall_create_continuation(__HYPERVISOR_domctl, "h",
                                               u_domctl);
        else
            /* Finished.  Return the new allocation */
            sc->mb = hap_get_allocation(d);
        return rc;
    case XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION:
        sc->mb = hap_get_allocation(d);
        fallthrough;
    case XEN_DOMCTL_SHADOW_OP_OFF:
        return 0;
    default:
        HAP_PRINTK("Bad hap domctl op %u\n", sc->op);
        return -EINVAL;
    }
}

static const struct paging_mode hap_paging_real_mode;
static const struct paging_mode hap_paging_protected_mode;
static const struct paging_mode hap_paging_pae_mode;
static const struct paging_mode hap_paging_long_mode;

void hap_vcpu_init(struct vcpu *v)
{
    v->arch.paging.mode = &hap_paging_real_mode;
    v->arch.paging.nestedmode = &hap_paging_real_mode;
}

/************************************************/
/*          HAP PAGING MODE FUNCTIONS           */
/************************************************/
/*
 * HAP guests can handle page faults (in the guest page tables) without
 * needing any action from Xen, so we should not be intercepting them.
 */
static int cf_check hap_page_fault(
    struct vcpu *v, unsigned long va, struct cpu_user_regs *regs)
{
    struct domain *d = v->domain;

    printk(XENLOG_G_ERR "Intercepted #PF from %pv with HAP enabled\n", v);
    domain_crash(d);
    return 0;
}

/*
 * HAP guests can handle invlpg without needing any action from Xen, so
 * should not be intercepting it.  However, we need to correctly handle
 * getting here from instruction emulation.
 */
static bool cf_check hap_invlpg(struct vcpu *v, unsigned long linear)
{
    /*
     * Emulate INVLPGA:
     * Must perform the flush right now or an other vcpu may
     * use it when we use the next VMRUN emulation, otherwise.
     */
    if ( nestedhvm_enabled(v->domain) && vcpu_nestedhvm(v).nv_p2m )
        p2m_flush(v, vcpu_nestedhvm(v).nv_p2m);

    return 1;
}

static pagetable_t cf_check hap_update_cr3(struct vcpu *v, bool noflush)
{
    v->arch.hvm.hw_cr[3] = v->arch.hvm.guest_cr[3];
    hvm_update_guest_cr3(v, noflush);

    return pagetable_null();
}

static bool flush_vcpu(const struct vcpu *v, const unsigned long *vcpu_bitmap)
{
    return !vcpu_bitmap || test_bit(v->vcpu_id, vcpu_bitmap);
}

/* Flush TLB of selected vCPUs.  NULL for all. */
static bool cf_check flush_tlb(const unsigned long *vcpu_bitmap)
{
    static DEFINE_PER_CPU(cpumask_t, flush_cpumask);
    cpumask_t *mask = &this_cpu(flush_cpumask);
    struct domain *d = current->domain;
    unsigned int this_cpu = smp_processor_id();
    struct vcpu *v;

    cpumask_clear(mask);

    /* Flush paging-mode soft state (e.g., va->gfn cache; PAE PDPE cache). */
    for_each_vcpu ( d, v )
    {
        unsigned int cpu;

        if ( !flush_vcpu(v, vcpu_bitmap) )
            continue;

        hvm_asid_flush_vcpu(v);

        cpu = read_atomic(&v->dirty_cpu);
        if ( cpu != this_cpu && is_vcpu_dirty_cpu(cpu) && v->is_running )
            __cpumask_set_cpu(cpu, mask);
    }

    /*
     * Trigger a vmexit on all pCPUs with dirty vCPU state in order to force an
     * ASID/VPID change and hence accomplish a guest TLB flush. Note that vCPUs
     * not currently running will already be flushed when scheduled because of
     * the ASID tickle done in the loop above.
     */
    on_selected_cpus(mask, NULL, NULL, 0);

    return true;
}

const struct paging_mode *
hap_paging_get_mode(struct vcpu *v)
{
    return (!hvm_paging_enabled(v)  ? &hap_paging_real_mode :
            hvm_long_mode_active(v) ? &hap_paging_long_mode :
            hvm_pae_enabled(v)      ? &hap_paging_pae_mode  :
                                      &hap_paging_protected_mode);
}

static void cf_check hap_update_paging_modes(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned long cr3_gfn = v->arch.hvm.guest_cr[3] >> PAGE_SHIFT;
    p2m_type_t t;

    /* We hold onto the cr3 as it may be modified later, and
     * we need to respect lock ordering. No need for 
     * checks here as they are performed by vmx_load_pdptrs
     * (the potential user of the cr3) */
    (void)get_gfn(d, cr3_gfn, &t);
    paging_lock(d);

    v->arch.paging.mode = hap_paging_get_mode(v);

    if ( pagetable_is_null(v->arch.hvm.monitor_table) )
    {
        mfn_t mmfn = hap_make_monitor_table(v);

        if ( mfn_eq(mmfn, INVALID_MFN) )
            goto unlock;
        v->arch.hvm.monitor_table = pagetable_from_mfn(mmfn);
        make_cr3(v, mmfn);
        hvm_update_host_cr3(v);
    }

    /* CR3 is effectively updated by a mode change. Flush ASIDs, etc. */
    hap_update_cr3(v, false);

 unlock:
    paging_unlock(d);
    put_gfn(d, cr3_gfn);
}

static void cf_check
hap_write_p2m_entry_post(struct p2m_domain *p2m, unsigned int oflags)
{
    struct domain *d = p2m->domain;

    if ( oflags & _PAGE_PRESENT )
        guest_flush_tlb_mask(d, d->dirty_cpumask);
}

void hap_p2m_init(struct p2m_domain *p2m)
{
    p2m->write_p2m_entry_post = hap_write_p2m_entry_post;
}

static unsigned long cf_check hap_gva_to_gfn_real_mode(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long gva, uint32_t *pfec)
{
    return ((paddr_t)gva >> PAGE_SHIFT);
}

static unsigned long cf_check hap_p2m_ga_to_gfn_real_mode(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order)
{
    if ( page_order )
        *page_order = PAGE_ORDER_4K;
    return (ga >> PAGE_SHIFT);
}

/* Entry points into this mode of the hap code. */
static const struct paging_mode hap_paging_real_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_real_mode,
    .p2m_ga_to_gfn          = hap_p2m_ga_to_gfn_real_mode,
    .update_cr3             = hap_update_cr3,
    .guest_levels           = 1
};

static const struct paging_mode hap_paging_protected_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_2_levels,
    .p2m_ga_to_gfn          = hap_p2m_ga_to_gfn_2_levels,
    .update_cr3             = hap_update_cr3,
    .guest_levels           = 2
};

static const struct paging_mode hap_paging_pae_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_3_levels,
    .p2m_ga_to_gfn          = hap_p2m_ga_to_gfn_3_levels,
    .update_cr3             = hap_update_cr3,
    .guest_levels           = 3
};

static const struct paging_mode hap_paging_long_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_4_levels,
    .p2m_ga_to_gfn          = hap_p2m_ga_to_gfn_4_levels,
    .update_cr3             = hap_update_cr3,
    .guest_levels           = 4
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
