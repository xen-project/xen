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
#include <asm/domain.h>

#include "private.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) (frame_table + mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) (mfn_x(_mfn) < max_page)
#undef page_to_mfn
#define page_to_mfn(_pg) (_mfn((_pg) - frame_table))

/************************************************/
/*             HAP SUPPORT FUNCTIONS            */
/************************************************/
mfn_t hap_alloc(struct domain *d)
{
    struct page_info *sp = NULL;
    void *p;

    ASSERT(hap_locked_by_me(d));

    sp = list_entry(d->arch.paging.hap.freelists.next, struct page_info, list);
    list_del(&sp->list);
    d->arch.paging.hap.free_pages -= 1;

    /* Now safe to clear the page for reuse */
    p = hap_map_domain_page(page_to_mfn(sp));
    ASSERT(p != NULL);
    clear_page(p);
    hap_unmap_domain_page(p);

    return page_to_mfn(sp);
}

void hap_free(struct domain *d, mfn_t smfn)
{
    struct page_info *sp = mfn_to_page(smfn); 

    ASSERT(hap_locked_by_me(d));

    d->arch.paging.hap.free_pages += 1;
    list_add_tail(&sp->list, &d->arch.paging.hap.freelists);
}

struct page_info * hap_alloc_p2m_page(struct domain *d)
{
    struct page_info *pg;
    mfn_t mfn;
    void *p;

    hap_lock(d);

#if CONFIG_PAGING_LEVELS == 3
    /* Under PAE mode, top-level P2M table should be allocated below 4GB space
     * because the size of h_cr3 is only 32-bit. We use alloc_domheap_pages to 
     * force this requirement. This page will be de-allocated in 
     * hap_free_p2m_page(), like other P2M pages.
    */
    if ( d->arch.paging.hap.p2m_pages == 0 ) 
    {
	pg = alloc_domheap_pages(NULL, 0, MEMF_bits(32));
	d->arch.paging.hap.p2m_pages += 1;
    }
    else
#endif
    {
	pg = mfn_to_page(hap_alloc(d));
	
	d->arch.paging.hap.p2m_pages += 1;
	d->arch.paging.hap.total_pages -= 1;
    }	

    if ( pg == NULL ) {
	hap_unlock(d);
	return NULL;
    }   

    hap_unlock(d);

    page_set_owner(pg, d);
    pg->count_info = 1;
    mfn = page_to_mfn(pg);
    p = hap_map_domain_page(mfn);
    clear_page(p);
    hap_unmap_domain_page(p);

    return pg;
}

void hap_free_p2m_page(struct domain *d, struct page_info *pg)
{
    ASSERT(page_get_owner(pg) == d);
    /* Should have just the one ref we gave it in alloc_p2m_page() */
    if ( (pg->count_info & PGC_count_mask) != 1 ) {
        HAP_ERROR("Odd p2m page count c=%#x t=%"PRtype_info"\n",
                  pg->count_info, pg->u.inuse.type_info);
    }
    pg->count_info = 0;
    /* Free should not decrement domain's total allocation, since 
     * these pages were allocated without an owner. */
    page_set_owner(pg, NULL); 
    free_domheap_pages(pg, 0);
    d->arch.paging.hap.p2m_pages--;
    ASSERT( d->arch.paging.hap.p2m_pages >= 0 );
}

/* Return the size of the pool, rounded up to the nearest MB */
static unsigned int
hap_get_allocation(struct domain *d)
{
    unsigned int pg = d->arch.paging.hap.total_pages;

    HERE_I_AM;
    return ((pg >> (20 - PAGE_SHIFT))
            + ((pg & ((1 << (20 - PAGE_SHIFT)) - 1)) ? 1 : 0));
}

/* Set the pool of pages to the required number of pages.
 * Returns 0 for success, non-zero for failure. */
static unsigned int
hap_set_allocation(struct domain *d, unsigned int pages, int *preempted)
{
    struct page_info *sp;

    ASSERT(hap_locked_by_me(d));

    while ( d->arch.paging.hap.total_pages != pages ) {
        if ( d->arch.paging.hap.total_pages < pages ) {
            /* Need to allocate more memory from domheap */
            sp = alloc_domheap_pages(NULL, 0, 0);
            if ( sp == NULL ) {
                HAP_PRINTK("failed to allocate hap pages.\n");
                return -ENOMEM;
            }
            d->arch.paging.hap.free_pages += 1;
            d->arch.paging.hap.total_pages += 1;
            list_add_tail(&sp->list, &d->arch.paging.hap.freelists);
        }
        else if ( d->arch.paging.hap.total_pages > pages ) {
            /* Need to return memory to domheap */
            ASSERT(!list_empty(&d->arch.paging.hap.freelists));
            sp = list_entry(d->arch.paging.hap.freelists.next,
                            struct page_info, list);
            list_del(&sp->list);
            d->arch.paging.hap.free_pages -= 1;
            d->arch.paging.hap.total_pages -= 1;
            sp->count_info = 0;
            free_domheap_pages(sp, 0);
        }
        
        /* Check to see if we need to yield and try again */
        if ( preempted && hypercall_preempt_check() ) {
            *preempted = 1;
            return 0;
        }
    }

    return 0;
}

#if CONFIG_PAGING_LEVELS == 4
void hap_install_xen_entries_in_l4(struct vcpu *v, mfn_t gl4mfn, mfn_t sl4mfn)
{
    struct domain *d = v->domain;
    l4_pgentry_t *sl4e;

    sl4e = hap_map_domain_page(sl4mfn);
    ASSERT(sl4e != NULL);

    /* Copy the common Xen mappings from the idle domain */
    memcpy(&sl4e[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           ROOT_PAGETABLE_XEN_SLOTS * sizeof(l4_pgentry_t));

    /* Install the per-domain mappings for this domain */
    sl4e[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_pfn(mfn_x(page_to_mfn(virt_to_page(d->arch.mm_perdomain_l3))),
                     __PAGE_HYPERVISOR);

    sl4e[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_pfn(mfn_x(gl4mfn), __PAGE_HYPERVISOR);

    /* install domain-specific P2M table */
    sl4e[l4_table_offset(RO_MPT_VIRT_START)] =
        l4e_from_pfn(mfn_x(pagetable_get_mfn(d->arch.phys_table)),
                     __PAGE_HYPERVISOR);

    hap_unmap_domain_page(sl4e);
}
#endif /* CONFIG_PAGING_LEVELS == 4 */

#if CONFIG_PAGING_LEVELS == 3
void hap_install_xen_entries_in_l2h(struct vcpu *v, mfn_t sl2hmfn)
{
    struct domain *d = v->domain;
    l2_pgentry_t *sl2e;

    int i;

    sl2e = hap_map_domain_page(sl2hmfn);
    ASSERT(sl2e != NULL);
    
    /* Copy the common Xen mappings from the idle domain */
    memcpy(&sl2e[L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1)],
           &idle_pg_table_l2[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));

    /* Install the per-domain mappings for this domain */
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        sl2e[l2_table_offset(PERDOMAIN_VIRT_START) + i] =
            l2e_from_pfn(
                         mfn_x(page_to_mfn(virt_to_page(d->arch.mm_perdomain_pt) + i)),
                         __PAGE_HYPERVISOR);
    
    for ( i = 0; i < HAP_L3_PAGETABLE_ENTRIES; i++ )
        sl2e[l2_table_offset(LINEAR_PT_VIRT_START) + i] =
            l2e_empty();

    if ( paging_mode_translate(d) )
    {
        /* Install the domain-specific p2m table */
        l3_pgentry_t *p2m;
        ASSERT(pagetable_get_pfn(d->arch.phys_table) != 0);
        p2m = hap_map_domain_page(pagetable_get_mfn(d->arch.phys_table));
        for ( i = 0; i < MACHPHYS_MBYTES>>1; i++ )
        {
            sl2e[l2_table_offset(RO_MPT_VIRT_START) + i] =
                (l3e_get_flags(p2m[i]) & _PAGE_PRESENT)
                ? l2e_from_pfn(mfn_x(_mfn(l3e_get_pfn(p2m[i]))),
                                      __PAGE_HYPERVISOR)
                : l2e_empty();
        }
        hap_unmap_domain_page(p2m);
    }

    hap_unmap_domain_page(sl2e);
}
#endif

#if CONFIG_PAGING_LEVELS == 2
void hap_install_xen_entries_in_l2(struct vcpu *v, mfn_t gl2mfn, mfn_t sl2mfn)
{
    struct domain *d = v->domain;
    l2_pgentry_t *sl2e;
    int i;

    sl2e = hap_map_domain_page(sl2mfn);
    ASSERT(sl2e != NULL);
    
    /* Copy the common Xen mappings from the idle domain */
    memcpy(&sl2e[L2_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));

    /* Install the per-domain mappings for this domain */
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        sl2e[l2_table_offset(PERDOMAIN_VIRT_START) + i] =
            l2e_from_pfn(
                mfn_x(page_to_mfn(virt_to_page(d->arch.mm_perdomain_pt) + i)),
                __PAGE_HYPERVISOR);


    sl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
        l2e_from_pfn(mfn_x(gl2mfn), __PAGE_HYPERVISOR);

    /* install domain-specific P2M table */
    sl2e[l2_table_offset(RO_MPT_VIRT_START)] =
        l2e_from_pfn(mfn_x(pagetable_get_mfn(d->arch.phys_table)),
                            __PAGE_HYPERVISOR);

    hap_unmap_domain_page(sl2e);
}
#endif

mfn_t hap_make_monitor_table(struct vcpu *v)
{
    struct domain *d = v->domain;

    ASSERT(pagetable_get_pfn(v->arch.monitor_table) == 0);

#if CONFIG_PAGING_LEVELS == 4
    {
        mfn_t m4mfn;
        m4mfn = hap_alloc(d);
        hap_install_xen_entries_in_l4(v, m4mfn, m4mfn);
        return m4mfn;
    }
#elif CONFIG_PAGING_LEVELS == 3
    {
        mfn_t m3mfn, m2mfn; 
        l3_pgentry_t *l3e;
        l2_pgentry_t *l2e;
        int i;

        m3mfn = hap_alloc(d);

        /* Install a monitor l2 table in slot 3 of the l3 table.
         * This is used for all Xen entries, including linear maps
         */
        m2mfn = hap_alloc(d);
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
#else
    {
        mfn_t m2mfn;
        
        m2mfn = hap_alloc(d);
        hap_install_xen_entries_in_l2(v, m2mfn, m2mfn);
    
        return m2mfn;
    }
#endif
}

void hap_destroy_monitor_table(struct vcpu* v, mfn_t mmfn)
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
    INIT_LIST_HEAD(&d->arch.paging.hap.freelists);
}

/* return 0 for success, -errno for failure */
int hap_enable(struct domain *d, u32 mode)
{
    unsigned int old_pages;
    int rv = 0;

    HERE_I_AM;

    domain_pause(d);
    /* error check */
    if ( (d == current->domain) ) {
        rv = -EINVAL;
        goto out;
    }

    old_pages = d->arch.paging.hap.total_pages;
    if ( old_pages == 0 ) {
        unsigned int r;
        hap_lock(d);
        r = hap_set_allocation(d, 256, NULL);
        hap_unlock(d);
        if ( r != 0 ) {
            hap_set_allocation(d, 0, NULL);
            rv = -ENOMEM;
            goto out;
        }
    }

    /* allocate P2m table */
    if ( mode & PG_translate ) {
        rv = p2m_alloc_table(d, hap_alloc_p2m_page, hap_free_p2m_page);
        if ( rv != 0 )
            goto out;
    }

    d->arch.paging.mode = mode | PG_SH_enable;

 out:
    domain_unpause(d);
    return rv;
}

void hap_final_teardown(struct domain *d)
{
    HERE_I_AM;

    if ( d->arch.paging.hap.total_pages != 0 )
        hap_teardown(d);

    p2m_teardown(d);
    ASSERT( d->arch.paging.hap.p2m_pages == 0 );
}

void hap_teardown(struct domain *d)
{
    struct vcpu *v;
    mfn_t mfn;
    HERE_I_AM;

    ASSERT(d->is_dying);
    ASSERT(d != current->domain);

    if ( !hap_locked_by_me(d) )
        hap_lock(d); /* Keep various asserts happy */

    if ( paging_mode_enabled(d) ) {
        /* release the monitor table held by each vcpu */
        for_each_vcpu(d, v) {
            if ( v->arch.paging.mode && paging_mode_external(d) ) {
                mfn = pagetable_get_mfn(v->arch.monitor_table);
                if ( mfn_valid(mfn) && (mfn_x(mfn) != 0) )
                    hap_destroy_monitor_table(v, mfn);
                v->arch.monitor_table = pagetable_null();
            }
        }
    }

    if ( d->arch.paging.hap.total_pages != 0 ) {
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

    HERE_I_AM;

    if ( unlikely(d == current->domain) ) {
        gdprintk(XENLOG_INFO, "Don't try to do a hap op on yourself!\n");
        return -EINVAL;
    }
    
    switch ( sc->op ) {
    case XEN_DOMCTL_SHADOW_OP_OFF:
    case XEN_DOMCTL_SHADOW_OP_ENABLE_TEST:
    case XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY:
    case XEN_DOMCTL_SHADOW_OP_ENABLE_TRANSLATE:
    case XEN_DOMCTL_SHADOW_OP_CLEAN:
    case XEN_DOMCTL_SHADOW_OP_PEEK:
    case XEN_DOMCTL_SHADOW_OP_ENABLE:
        HAP_ERROR("Bad hap domctl op %u\n", sc->op);
        domain_crash(d);
        return -EINVAL;
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
/* In theory, hap should not intercept guest page fault. This function can 
 * be recycled to handle host/nested page fault, if needed.
 */
int hap_page_fault(struct vcpu *v, unsigned long va, 
                   struct cpu_user_regs *regs)
{
    HERE_I_AM;
    domain_crash(v->domain);
    return 0;
}

/* called when guest issues a invlpg request. 
 * Return 1 if need to issue page invalidation on CPU; Return 0 if does not
 * need to do so.
 */
int hap_invlpg(struct vcpu *v, unsigned long va)
{
    HERE_I_AM;
    return 0;
}

void hap_update_cr3(struct vcpu *v, int do_locking)
{
    struct domain *d = v->domain;
    mfn_t gmfn;

    HERE_I_AM;
    /* Don't do anything on an uninitialised vcpu */
    if ( !is_hvm_domain(d) && !v->is_initialised )
    {
        ASSERT(v->arch.cr3 == 0);
        return;
    }

    if ( do_locking )
        hap_lock(v->domain);
    
    ASSERT(hap_locked_by_me(v->domain));
    ASSERT(v->arch.paging.mode);
    
    gmfn = pagetable_get_mfn(v->arch.guest_table);

    make_cr3(v, pagetable_get_pfn(v->arch.monitor_table));
    
    hvm_update_guest_cr3(v, pagetable_get_paddr(v->arch.monitor_table));

    HAP_PRINTK("d=%u v=%u guest_table=%05lx, monitor_table = %05lx\n", 
               d->domain_id, v->vcpu_id, 
               (unsigned long)pagetable_get_pfn(v->arch.guest_table),
               (unsigned long)pagetable_get_pfn(v->arch.monitor_table));

    flush_tlb_mask(d->domain_dirty_cpumask);

    if ( do_locking )
        hap_unlock(v->domain);
}

void hap_update_paging_modes(struct vcpu *v)
{
    struct domain *d;

    HERE_I_AM;

    d = v->domain;
    hap_lock(d);

    /* update guest paging mode. Note that we rely on hvm functions to detect
     * guest's paging mode. So, make sure the shadow registers (CR0, CR4, EFER)
     * reflect guest's status correctly.
     */
    if ( hvm_paging_enabled(v) ) {
        if ( hvm_long_mode_enabled(v) )
            v->arch.paging.mode = &hap_paging_long_mode;
        else if ( hvm_pae_enabled(v) )
            v->arch.paging.mode = &hap_paging_pae_mode;
        else
            v->arch.paging.mode = &hap_paging_protected_mode;
    }
    else {
        v->arch.paging.mode = &hap_paging_real_mode;
    }

    v->arch.paging.translate_enabled = !!hvm_paging_enabled(v);    

    if ( pagetable_is_null(v->arch.monitor_table) ) {
        mfn_t mmfn = hap_make_monitor_table(v);
        v->arch.monitor_table = pagetable_from_mfn(mmfn);
        make_cr3(v, mfn_x(mmfn));
    }

    flush_tlb_mask(d->domain_dirty_cpumask);
    hap_unlock(d);
}

#if CONFIG_PAGING_LEVELS == 3
static void p2m_install_entry_in_monitors(struct domain *d, l3_pgentry_t *l3e) 
/* Special case, only used for external-mode domains on PAE hosts:
 * update the mapping of the p2m table.  Once again, this is trivial in
 * other paging modes (one top-level entry points to the top-level p2m,
 * no maintenance needed), but PAE makes life difficult by needing a
 * copy l3es of the p2m table in eight l2h slots in the monitor table.  This 
 * function makes fresh copies when a p2m l3e changes. */
{
    l2_pgentry_t *ml2e;
    struct vcpu *v;
    unsigned int index;
    
    index = ((unsigned long)l3e & ~PAGE_MASK) / sizeof(l3_pgentry_t);
    ASSERT(index < MACHPHYS_MBYTES>>1);
    
    for_each_vcpu(d, v) {
	if ( pagetable_get_pfn(v->arch.monitor_table) == 0 ) 
	    continue;

	ASSERT(paging_mode_external(v->domain));

        if ( v == current ) /* OK to use linear map of monitor_table */
	    ml2e = __linear_l2_table + l2_linear_offset(RO_MPT_VIRT_START);
        else {
	    l3_pgentry_t *ml3e;
            ml3e = hap_map_domain_page(pagetable_get_mfn(v->arch.monitor_table));
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

void 
hap_write_p2m_entry(struct vcpu *v, unsigned long gfn, l1_pgentry_t *p,
                    l1_pgentry_t new, unsigned int level)
{
    hap_lock(v->domain);
    safe_write_pte(p, new);
#if CONFIG_PAGING_LEVELS == 3
    /* install P2M in monitor table for PAE Xen */
    if ( level == 3 ) {
	/* We have written to the p2m l3: need to sync the per-vcpu
         * copies of it in the monitor tables */
	p2m_install_entry_in_monitors(v->domain, (l3_pgentry_t *)p);
	
    }
#endif
    hap_unlock(v->domain);
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
    .gva_to_gfn             = hap_gva_to_gfn_protected_mode,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .write_p2m_entry        = hap_write_p2m_entry,
    .guest_levels           = 2
};

struct paging_mode hap_paging_pae_mode = {
    .page_fault             = hap_page_fault, 
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_pae_mode,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .write_p2m_entry        = hap_write_p2m_entry,
    .guest_levels           = 3
};

struct paging_mode hap_paging_long_mode = {
    .page_fault             = hap_page_fault, 
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_long_mode,
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


