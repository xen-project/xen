/******************************************************************************
 * arch/x86/mm/hap/hap.c
 *
 * hardware assisted paging
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Parts of this code are Copyright (c) 2007 by XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
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

#include "private.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

/************************************************/
/*          HAP VRAM TRACKING SUPPORT           */
/************************************************/

int hap_enable_vram_tracking(struct domain *d)
{
    int i;
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return -EINVAL;

    /* turn on PG_log_dirty bit in paging mode */
    hap_lock(d);
    d->arch.paging.mode |= PG_log_dirty;
    hap_unlock(d);

    /* set l1e entries of P2M table to be read-only. */
    for (i = dirty_vram->begin_pfn; i < dirty_vram->end_pfn; i++)
        p2m_change_type(d, i, p2m_ram_rw, p2m_ram_logdirty);

    flush_tlb_mask(&d->domain_dirty_cpumask);
    return 0;
}

int hap_disable_vram_tracking(struct domain *d)
{
    int i;
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return -EINVAL;

    hap_lock(d);
    d->arch.paging.mode &= ~PG_log_dirty;
    hap_unlock(d);

    /* set l1e entries of P2M table with normal mode */
    for (i = dirty_vram->begin_pfn; i < dirty_vram->end_pfn; i++)
        p2m_change_type(d, i, p2m_ram_logdirty, p2m_ram_rw);

    flush_tlb_mask(&d->domain_dirty_cpumask);
    return 0;
}

void hap_clean_vram_tracking(struct domain *d)
{
    int i;
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return;

    /* set l1e entries of P2M table to be read-only. */
    for (i = dirty_vram->begin_pfn; i < dirty_vram->end_pfn; i++)
        p2m_change_type(d, i, p2m_ram_rw, p2m_ram_logdirty);

    flush_tlb_mask(&d->domain_dirty_cpumask);
}

void hap_vram_tracking_init(struct domain *d)
{
    paging_log_dirty_init(d, hap_enable_vram_tracking,
                          hap_disable_vram_tracking,
                          hap_clean_vram_tracking);
}

int hap_track_dirty_vram(struct domain *d,
                         unsigned long begin_pfn,
                         unsigned long nr,
                         XEN_GUEST_HANDLE_64(uint8) dirty_bitmap)
{
    long rc = 0;
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( nr )
    {
        if ( paging_mode_log_dirty(d) && dirty_vram )
        {
            if ( begin_pfn != dirty_vram->begin_pfn ||
                 begin_pfn + nr != dirty_vram->end_pfn )
            {
                paging_log_dirty_disable(d);
                dirty_vram->begin_pfn = begin_pfn;
                dirty_vram->end_pfn = begin_pfn + nr;
                rc = paging_log_dirty_enable(d);
                if (rc != 0)
                    goto param_fail;
            }
        }
        else if ( !paging_mode_log_dirty(d) && !dirty_vram )
        {
            rc -ENOMEM;
            if ( (dirty_vram = xmalloc(struct sh_dirty_vram)) == NULL )
                goto param_fail;

            dirty_vram->begin_pfn = begin_pfn;
            dirty_vram->end_pfn = begin_pfn + nr;
            d->arch.hvm_domain.dirty_vram = dirty_vram;
            hap_vram_tracking_init(d);
            rc = paging_log_dirty_enable(d);
            if (rc != 0)
                goto param_fail;
        }
        else
        {
            if ( !paging_mode_log_dirty(d) && dirty_vram )
                rc = -EINVAL;
            else
                rc = -ENODATA;
            goto param_fail;
        }
        /* get the bitmap */
        rc = paging_log_dirty_range(d, begin_pfn, nr, dirty_bitmap);
    }
    else
    {
        if ( paging_mode_log_dirty(d) && dirty_vram ) {
            rc = paging_log_dirty_disable(d);
            xfree(dirty_vram);
            dirty_vram = d->arch.hvm_domain.dirty_vram = NULL;
        } else
            rc = 0;
    }

    return rc;

param_fail:
    if ( dirty_vram )
    {
        xfree(dirty_vram);
        dirty_vram = d->arch.hvm_domain.dirty_vram = NULL;
    }
    return rc;
}

/************************************************/
/*            HAP LOG DIRTY SUPPORT             */
/************************************************/

/* hap code to call when log_dirty is enable. return 0 if no problem found. */
int hap_enable_log_dirty(struct domain *d)
{
    /* turn on PG_log_dirty bit in paging mode */
    hap_lock(d);
    d->arch.paging.mode |= PG_log_dirty;
    hap_unlock(d);

    /* set l1e entries of P2M table to be read-only. */
    p2m_change_entry_type_global(d, p2m_ram_rw, p2m_ram_logdirty);
    flush_tlb_mask(&d->domain_dirty_cpumask);
    return 0;
}

int hap_disable_log_dirty(struct domain *d)
{
    hap_lock(d);
    d->arch.paging.mode &= ~PG_log_dirty;
    hap_unlock(d);

    /* set l1e entries of P2M table with normal mode */
    p2m_change_entry_type_global(d, p2m_ram_logdirty, p2m_ram_rw);
    return 0;
}

void hap_clean_dirty_bitmap(struct domain *d)
{
    /* set l1e entries of P2M table to be read-only. */
    p2m_change_entry_type_global(d, p2m_ram_rw, p2m_ram_logdirty);
    flush_tlb_mask(&d->domain_dirty_cpumask);
}

void hap_logdirty_init(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;
    if ( paging_mode_log_dirty(d) && dirty_vram )
    {
        paging_log_dirty_disable(d);
        xfree(dirty_vram);
        dirty_vram = d->arch.hvm_domain.dirty_vram = NULL;
    }

    /* Reinitialize logdirty mechanism */
    paging_log_dirty_init(d, hap_enable_log_dirty,
                          hap_disable_log_dirty,
                          hap_clean_dirty_bitmap);
}

/************************************************/
/*             HAP SUPPORT FUNCTIONS            */
/************************************************/
static struct page_info *hap_alloc(struct domain *d)
{
    struct page_info *pg = NULL;
    void *p;

    ASSERT(hap_locked_by_me(d));

    pg = page_list_remove_head(&d->arch.paging.hap.freelist);
    if ( unlikely(!pg) )
        return NULL;

    d->arch.paging.hap.free_pages--;

    p = __map_domain_page(pg);
    ASSERT(p != NULL);
    clear_page(p);
    hap_unmap_domain_page(p);

    return pg;
}

static void hap_free(struct domain *d, mfn_t mfn)
{
    struct page_info *pg = mfn_to_page(mfn);

    ASSERT(hap_locked_by_me(d));

    d->arch.paging.hap.free_pages++;
    page_list_add_tail(pg, &d->arch.paging.hap.freelist);
}

static struct page_info *hap_alloc_p2m_page(struct domain *d)
{
    struct page_info *pg;

    hap_lock(d);
    pg = hap_alloc(d);

#if CONFIG_PAGING_LEVELS == 3
    /* Under PAE mode, top-level P2M table should be allocated below 4GB space
     * because the size of h_cr3 is only 32-bit. We use alloc_domheap_pages to
     * force this requirement, and exchange the guaranteed 32-bit-clean
     * page for the one we just hap_alloc()ed. */
    if ( d->arch.paging.hap.p2m_pages == 0
         && mfn_x(page_to_mfn(pg)) >= (1UL << (32 - PAGE_SHIFT)) )
    {
        free_domheap_page(pg);
        pg = alloc_domheap_page(
            NULL, MEMF_bits(32) | MEMF_node(domain_to_node(d)));
        if ( likely(pg != NULL) )
        {
            void *p = __map_domain_page(pg);
            clear_page(p);
            hap_unmap_domain_page(p);
        }
    }
#endif

    if ( likely(pg != NULL) )
    {
        d->arch.paging.hap.total_pages--;
        d->arch.paging.hap.p2m_pages++;
        page_set_owner(pg, d);
        pg->count_info |= 1;
    }

    hap_unlock(d);
    return pg;
}

void hap_free_p2m_page(struct domain *d, struct page_info *pg)
{
    hap_lock(d);
    ASSERT(page_get_owner(pg) == d);
    /* Should have just the one ref we gave it in alloc_p2m_page() */
    if ( (pg->count_info & PGC_count_mask) != 1 )
        HAP_ERROR("Odd p2m page count c=%#lx t=%"PRtype_info"\n",
                  pg->count_info, pg->u.inuse.type_info);
    pg->count_info &= ~PGC_count_mask;
    /* Free should not decrement domain's total allocation, since
     * these pages were allocated without an owner. */
    page_set_owner(pg, NULL);
    free_domheap_page(pg);
    d->arch.paging.hap.p2m_pages--;
    ASSERT(d->arch.paging.hap.p2m_pages >= 0);
    hap_unlock(d);
}

/* Return the size of the pool, rounded up to the nearest MB */
static unsigned int
hap_get_allocation(struct domain *d)
{
    unsigned int pg = d->arch.paging.hap.total_pages;

    return ((pg >> (20 - PAGE_SHIFT))
            + ((pg & ((1 << (20 - PAGE_SHIFT)) - 1)) ? 1 : 0));
}

/* Set the pool of pages to the required number of pages.
 * Returns 0 for success, non-zero for failure. */
static unsigned int
hap_set_allocation(struct domain *d, unsigned int pages, int *preempted)
{
    struct page_info *pg;

    ASSERT(hap_locked_by_me(d));

    while ( d->arch.paging.hap.total_pages != pages )
    {
        if ( d->arch.paging.hap.total_pages < pages )
        {
            /* Need to allocate more memory from domheap */
            pg = alloc_domheap_page(NULL, MEMF_node(domain_to_node(d)));
            if ( pg == NULL )
            {
                HAP_PRINTK("failed to allocate hap pages.\n");
                return -ENOMEM;
            }
            d->arch.paging.hap.free_pages++;
            d->arch.paging.hap.total_pages++;
            page_list_add_tail(pg, &d->arch.paging.hap.freelist);
        }
        else if ( d->arch.paging.hap.total_pages > pages )
        {
            /* Need to return memory to domheap */
            pg = page_list_remove_head(&d->arch.paging.hap.freelist);
            ASSERT(pg);
            d->arch.paging.hap.free_pages--;
            d->arch.paging.hap.total_pages--;
            free_domheap_page(pg);
        }

        /* Check to see if we need to yield and try again */
        if ( preempted && hypercall_preempt_check() )
        {
            *preempted = 1;
            return 0;
        }
    }

    return 0;
}

#if CONFIG_PAGING_LEVELS == 4
static void hap_install_xen_entries_in_l4(struct vcpu *v, mfn_t l4mfn)
{
    struct domain *d = v->domain;
    l4_pgentry_t *l4e;

    l4e = hap_map_domain_page(l4mfn);
    ASSERT(l4e != NULL);

    /* Copy the common Xen mappings from the idle domain */
    memcpy(&l4e[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           ROOT_PAGETABLE_XEN_SLOTS * sizeof(l4_pgentry_t));

    /* Install the per-domain mappings for this domain */
    l4e[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_pfn(mfn_x(page_to_mfn(virt_to_page(d->arch.mm_perdomain_l3))),
                     __PAGE_HYPERVISOR);

    /* Install a linear mapping */
    l4e[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_pfn(mfn_x(l4mfn), __PAGE_HYPERVISOR);

    /* Install the domain-specific P2M table */
    l4e[l4_table_offset(RO_MPT_VIRT_START)] =
        l4e_from_pfn(mfn_x(pagetable_get_mfn(d->arch.phys_table)),
                     __PAGE_HYPERVISOR);

    hap_unmap_domain_page(l4e);
}
#endif /* CONFIG_PAGING_LEVELS == 4 */

#if CONFIG_PAGING_LEVELS == 3
static void hap_install_xen_entries_in_l2h(struct vcpu *v, mfn_t l2hmfn)
{
    struct domain *d = v->domain;
    l2_pgentry_t *l2e;
    l3_pgentry_t *p2m;
    int i;

    l2e = hap_map_domain_page(l2hmfn);
    ASSERT(l2e != NULL);

    /* Copy the common Xen mappings from the idle domain */
    memcpy(&l2e[L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1)],
           &idle_pg_table_l2[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));

    /* Install the per-domain mappings for this domain */
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        l2e[l2_table_offset(PERDOMAIN_VIRT_START) + i] =
            l2e_from_pfn(
                mfn_x(page_to_mfn(perdomain_pt_page(d, i))),
                __PAGE_HYPERVISOR);

    /* No linear mapping; will be set up by monitor-table contructor. */
    for ( i = 0; i < 4; i++ )
        l2e[l2_table_offset(LINEAR_PT_VIRT_START) + i] =
            l2e_empty();

    /* Install the domain-specific p2m table */
    ASSERT(pagetable_get_pfn(d->arch.phys_table) != 0);
    p2m = hap_map_domain_page(pagetable_get_mfn(d->arch.phys_table));
    for ( i = 0; i < MACHPHYS_MBYTES>>1; i++ )
    {
        l2e[l2_table_offset(RO_MPT_VIRT_START) + i] =
            (l3e_get_flags(p2m[i]) & _PAGE_PRESENT)
            ? l2e_from_pfn(mfn_x(_mfn(l3e_get_pfn(p2m[i]))),
                           __PAGE_HYPERVISOR)
            : l2e_empty();
    }
    hap_unmap_domain_page(p2m);
    hap_unmap_domain_page(l2e);
}
#endif

static mfn_t hap_make_monitor_table(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct page_info *pg;

    ASSERT(pagetable_get_pfn(v->arch.monitor_table) == 0);

#if CONFIG_PAGING_LEVELS == 4
    {
        mfn_t m4mfn;
        if ( (pg = hap_alloc(d)) == NULL )
            goto oom;
        m4mfn = page_to_mfn(pg);
        hap_install_xen_entries_in_l4(v, m4mfn);
        return m4mfn;
    }
#elif CONFIG_PAGING_LEVELS == 3
    {
        mfn_t m3mfn, m2mfn;
        l3_pgentry_t *l3e;
        l2_pgentry_t *l2e;
        int i;

        if ( (pg = hap_alloc(d)) == NULL )
            goto oom;
        m3mfn = page_to_mfn(pg);

        /* Install a monitor l2 table in slot 3 of the l3 table.
         * This is used for all Xen entries, including linear maps
         */
        if ( (pg = hap_alloc(d)) == NULL )
            goto oom;
        m2mfn = page_to_mfn(pg);
        l3e = hap_map_domain_page(m3mfn);
        l3e[3] = l3e_from_pfn(mfn_x(m2mfn), _PAGE_PRESENT);
        hap_install_xen_entries_in_l2h(v, m2mfn);
        /* Install the monitor's own linear map */
        l2e = hap_map_domain_page(m2mfn);
        for ( i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
            l2e[l2_table_offset(LINEAR_PT_VIRT_START) + i] =
                (l3e_get_flags(l3e[i]) & _PAGE_PRESENT)
                ? l2e_from_pfn(l3e_get_pfn(l3e[i]), __PAGE_HYPERVISOR)
                : l2e_empty();
        hap_unmap_domain_page(l2e);
        hap_unmap_domain_page(l3e);

        HAP_PRINTK("new monitor table: %#lx\n", mfn_x(m3mfn));
        return m3mfn;
    }
#endif

 oom:
    HAP_ERROR("out of memory building monitor pagetable\n");
    domain_crash(d);
    return _mfn(INVALID_MFN);
}

static void hap_destroy_monitor_table(struct vcpu* v, mfn_t mmfn)
{
    struct domain *d = v->domain;

#if CONFIG_PAGING_LEVELS == 3
    /* Need to destroy the l2 monitor page in slot 4 too */
    {
        l3_pgentry_t *l3e = hap_map_domain_page(mmfn);
        ASSERT(l3e_get_flags(l3e[3]) & _PAGE_PRESENT);
        hap_free(d, _mfn(l3e_get_pfn(l3e[3])));
        hap_unmap_domain_page(l3e);
    }
#endif

    /* Put the memory back in the pool */
    hap_free(d, mmfn);
}

/************************************************/
/*          HAP DOMAIN LEVEL FUNCTIONS          */
/************************************************/
void hap_domain_init(struct domain *d)
{
    hap_lock_init(d);
    INIT_PAGE_LIST_HEAD(&d->arch.paging.hap.freelist);
}

/* return 0 for success, -errno for failure */
int hap_enable(struct domain *d, u32 mode)
{
    unsigned int old_pages;
    int rv = 0;

    domain_pause(d);
    /* error check */
    if ( (d == current->domain) )
    {
        rv = -EINVAL;
        goto out;
    }

    old_pages = d->arch.paging.hap.total_pages;
    if ( old_pages == 0 )
    {
        unsigned int r;
        hap_lock(d);
        r = hap_set_allocation(d, 256, NULL);
        hap_unlock(d);
        if ( r != 0 )
        {
            hap_set_allocation(d, 0, NULL);
            rv = -ENOMEM;
            goto out;
        }
    }

    /* allocate P2m table */
    if ( mode & PG_translate )
    {
        rv = p2m_alloc_table(d, hap_alloc_p2m_page, hap_free_p2m_page);
        if ( rv != 0 )
            goto out;
    }

    d->arch.paging.mode = mode | PG_HAP_enable;

 out:
    domain_unpause(d);
    return rv;
}

void hap_final_teardown(struct domain *d)
{
    if ( d->arch.paging.hap.total_pages != 0 )
        hap_teardown(d);

    p2m_teardown(d);
    ASSERT(d->arch.paging.hap.p2m_pages == 0);
}

void hap_teardown(struct domain *d)
{
    struct vcpu *v;
    mfn_t mfn;

    ASSERT(d->is_dying);
    ASSERT(d != current->domain);

    if ( !hap_locked_by_me(d) )
        hap_lock(d); /* Keep various asserts happy */

    if ( paging_mode_enabled(d) )
    {
        /* release the monitor table held by each vcpu */
        for_each_vcpu ( d, v )
        {
            if ( v->arch.paging.mode && paging_mode_external(d) )
            {
                mfn = pagetable_get_mfn(v->arch.monitor_table);
                if ( mfn_valid(mfn) && (mfn_x(mfn) != 0) )
                    hap_destroy_monitor_table(v, mfn);
                v->arch.monitor_table = pagetable_null();
            }
        }
    }

    if ( d->arch.paging.hap.total_pages != 0 )
    {
        HAP_PRINTK("teardown of domain %u starts."
                      "  pages total = %u, free = %u, p2m=%u\n",
                      d->domain_id,
                      d->arch.paging.hap.total_pages,
                      d->arch.paging.hap.free_pages,
                      d->arch.paging.hap.p2m_pages);
        hap_set_allocation(d, 0, NULL);
        HAP_PRINTK("teardown done."
                      "  pages total = %u, free = %u, p2m=%u\n",
                      d->arch.paging.hap.total_pages,
                      d->arch.paging.hap.free_pages,
                      d->arch.paging.hap.p2m_pages);
        ASSERT(d->arch.paging.hap.total_pages == 0);
    }

    d->arch.paging.mode &= ~PG_log_dirty;

    hap_unlock(d);
}

int hap_domctl(struct domain *d, xen_domctl_shadow_op_t *sc,
               XEN_GUEST_HANDLE(void) u_domctl)
{
    int rc, preempted = 0;

    switch ( sc->op )
    {
    case XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION:
        hap_lock(d);
        rc = hap_set_allocation(d, sc->mb << (20 - PAGE_SHIFT), &preempted);
        hap_unlock(d);
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
        return 0;
    default:
        HAP_ERROR("Bad hap domctl op %u\n", sc->op);
        return -EINVAL;
    }
}

void hap_vcpu_init(struct vcpu *v)
{
    v->arch.paging.mode = &hap_paging_real_mode;
}

/************************************************/
/*          HAP PAGING MODE FUNCTIONS           */
/************************************************/
/*
 * HAP guests can handle page faults (in the guest page tables) without
 * needing any action from Xen, so we should not be intercepting them.
 */
static int hap_page_fault(struct vcpu *v, unsigned long va,
                          struct cpu_user_regs *regs)
{
    HAP_ERROR("Intercepted a guest #PF (%u:%u) with HAP enabled.\n",
              v->domain->domain_id, v->vcpu_id);
    domain_crash(v->domain);
    return 0;
}

/*
 * HAP guests can handle invlpg without needing any action from Xen, so
 * should not be intercepting it.
 */
static int hap_invlpg(struct vcpu *v, unsigned long va)
{
    HAP_ERROR("Intercepted a guest INVLPG (%u:%u) with HAP enabled.\n",
              v->domain->domain_id, v->vcpu_id);
    domain_crash(v->domain);
    return 0;
}

static void hap_update_cr3(struct vcpu *v, int do_locking)
{
    v->arch.hvm_vcpu.hw_cr[3] = v->arch.hvm_vcpu.guest_cr[3];
    hvm_update_guest_cr(v, 3);
}

static void hap_update_paging_modes(struct vcpu *v)
{
    struct domain *d = v->domain;

    hap_lock(d);

    v->arch.paging.mode =
        !hvm_paging_enabled(v)   ? &hap_paging_real_mode :
        hvm_long_mode_enabled(v) ? &hap_paging_long_mode :
        hvm_pae_enabled(v)       ? &hap_paging_pae_mode  :
                                   &hap_paging_protected_mode;

    if ( pagetable_is_null(v->arch.monitor_table) )
    {
        mfn_t mmfn = hap_make_monitor_table(v);
        v->arch.monitor_table = pagetable_from_mfn(mmfn);
        make_cr3(v, mfn_x(mmfn));
        hvm_update_host_cr3(v);
    }

    /* CR3 is effectively updated by a mode change. Flush ASIDs, etc. */
    hap_update_cr3(v, 0);

    hap_unlock(d);
}

#if CONFIG_PAGING_LEVELS == 3
static void p2m_install_entry_in_monitors(struct domain *d, l3_pgentry_t *l3e)
/* Special case, only used for PAE hosts: update the mapping of the p2m
 * table.  This is trivial in other paging modes (one top-level entry
 * points to the top-level p2m, no maintenance needed), but PAE makes
 * life difficult by needing a copy of the p2m table in eight l2h slots
 * in the monitor table.  This function makes fresh copies when a p2m
 * l3e changes. */
{
    l2_pgentry_t *ml2e;
    struct vcpu *v;
    unsigned int index;

    index = ((unsigned long)l3e & ~PAGE_MASK) / sizeof(l3_pgentry_t);
    ASSERT(index < MACHPHYS_MBYTES>>1);

    for_each_vcpu ( d, v )
    {
        if ( pagetable_get_pfn(v->arch.monitor_table) == 0 )
            continue;

        ASSERT(paging_mode_external(v->domain));

        if ( v == current ) /* OK to use linear map of monitor_table */
            ml2e = __linear_l2_table + l2_linear_offset(RO_MPT_VIRT_START);
        else {
            l3_pgentry_t *ml3e;
            ml3e = hap_map_domain_page(
                pagetable_get_mfn(v->arch.monitor_table));
            ASSERT(l3e_get_flags(ml3e[3]) & _PAGE_PRESENT);
            ml2e = hap_map_domain_page(_mfn(l3e_get_pfn(ml3e[3])));
            ml2e += l2_table_offset(RO_MPT_VIRT_START);
            hap_unmap_domain_page(ml3e);
        }
        ml2e[index] = l2e_from_pfn(l3e_get_pfn(*l3e), __PAGE_HYPERVISOR);
        if ( v != current )
            hap_unmap_domain_page(ml2e);
    }
}
#endif

static void
hap_write_p2m_entry(struct vcpu *v, unsigned long gfn, l1_pgentry_t *p,
                    mfn_t table_mfn, l1_pgentry_t new, unsigned int level)
{
    uint32_t old_flags;

    hap_lock(v->domain);

    old_flags = l1e_get_flags(*p);
    safe_write_pte(p, new);
    if ( (old_flags & _PAGE_PRESENT)
         && (level == 1 || (level == 2 && (old_flags & _PAGE_PSE))) )
             flush_tlb_mask(&v->domain->domain_dirty_cpumask);

#if CONFIG_PAGING_LEVELS == 3
    /* install P2M in monitor table for PAE Xen */
    if ( level == 3 )
        /* We have written to the p2m l3: need to sync the per-vcpu
         * copies of it in the monitor tables */
        p2m_install_entry_in_monitors(v->domain, (l3_pgentry_t *)p);
#endif

    hap_unlock(v->domain);
}

static unsigned long hap_gva_to_gfn_real_mode(
    struct vcpu *v, unsigned long gva, uint32_t *pfec)
{
    return ((paddr_t)gva >> PAGE_SHIFT);
}

/* Entry points into this mode of the hap code. */
struct paging_mode hap_paging_real_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_real_mode,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .write_p2m_entry        = hap_write_p2m_entry,
    .guest_levels           = 1
};

struct paging_mode hap_paging_protected_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_2level,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .write_p2m_entry        = hap_write_p2m_entry,
    .guest_levels           = 2
};

struct paging_mode hap_paging_pae_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_3level,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .write_p2m_entry        = hap_write_p2m_entry,
    .guest_levels           = 3
};

struct paging_mode hap_paging_long_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_4level,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .write_p2m_entry        = hap_write_p2m_entry,
    .guest_levels           = 4
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */


