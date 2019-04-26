/******************************************************************************
 * include/asm-x86/shadow.h
 * 
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _XEN_SHADOW_H
#define _XEN_SHADOW_H

#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/domain_page.h>
#include <asm/flushtlb.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/spec_ctrl.h>

/*****************************************************************************
 * Macros to tell which shadow paging mode a domain is in*/

#define shadow_mode_enabled(_d)    paging_mode_shadow(_d)
#define shadow_mode_refcounts(_d) (paging_mode_shadow(_d) && \
                                   paging_mode_refcounts(_d))
#define shadow_mode_log_dirty(_d) (paging_mode_shadow(_d) && \
                                   paging_mode_log_dirty(_d))
#define shadow_mode_translate(_d) (paging_mode_shadow(_d) && \
                                   paging_mode_translate(_d))
#define shadow_mode_external(_d)  (paging_mode_shadow(_d) && \
                                   paging_mode_external(_d))

/*****************************************************************************
 * Entry points into the shadow code */

/* Set up the shadow-specific parts of a domain struct at start of day.
 * Called from paging_domain_init(). */
int shadow_domain_init(struct domain *d);

/* Setup the shadow-specific parts of a vcpu struct. It is called by
 * paging_vcpu_init() in paging.c */
void shadow_vcpu_init(struct vcpu *v);

#ifdef CONFIG_SHADOW_PAGING

/* Enable an arbitrary shadow mode.  Call once at domain creation. */
int shadow_enable(struct domain *d, u32 mode);

/* Enable VRAM dirty bit tracking. */
int shadow_track_dirty_vram(struct domain *d,
                            unsigned long first_pfn,
                            unsigned long nr,
                            XEN_GUEST_HANDLE_PARAM(void) dirty_bitmap);

/* Handler for shadow control ops: operations from user-space to enable
 * and disable ephemeral shadow modes (test mode and log-dirty mode) and
 * manipulate the log-dirty bitmap. */
int shadow_domctl(struct domain *d, 
                  struct xen_domctl_shadow_op *sc,
                  XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

/* Call when destroying a domain */
void shadow_teardown(struct domain *d, bool *preempted);

/* Call once all of the references to the domain have gone away */
void shadow_final_teardown(struct domain *d);

void sh_remove_shadows(struct domain *d, mfn_t gmfn, int fast, int all);

/* Adjust shadows ready for a guest page to change its type. */
void shadow_prepare_page_type_change(struct domain *d, struct page_info *page,
                                     unsigned long new_type);

/* Discard _all_ mappings from the domain's shadows. */
void shadow_blow_tables_per_domain(struct domain *d);

/* Set the pool of shadow pages to the required number of pages.
 * Input will be rounded up to at least shadow_min_acceptable_pages(),
 * plus space for the p2m table.
 * Returns 0 for success, non-zero for failure. */
int shadow_set_allocation(struct domain *d, unsigned int pages,
                          bool *preempted);

#else /* !CONFIG_SHADOW_PAGING */

#define shadow_teardown(d, p) ASSERT(is_pv_domain(d))
#define shadow_final_teardown(d) ASSERT(is_pv_domain(d))
#define shadow_enable(d, mode) \
    ({ ASSERT(is_pv_domain(d)); -EOPNOTSUPP; })
#define shadow_track_dirty_vram(d, begin_pfn, nr, bitmap) \
    ({ ASSERT_UNREACHABLE(); -EOPNOTSUPP; })
#define shadow_set_allocation(d, pages, preempted) \
    ({ ASSERT_UNREACHABLE(); -EOPNOTSUPP; })

static inline void sh_remove_shadows(struct domain *d, mfn_t gmfn,
                                     int fast, int all) {}

static inline void shadow_prepare_page_type_change(struct domain *d,
                                                   struct page_info *page,
                                                   unsigned long new_type) {}

static inline void shadow_blow_tables_per_domain(struct domain *d) {}

static inline int shadow_domctl(struct domain *d,
                                struct xen_domctl_shadow_op *sc,
                                XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    return -EINVAL;
}

#endif /* CONFIG_SHADOW_PAGING */

/*
 * Mitigations for L1TF / CVE-2018-3620 for PV guests.
 *
 * We cannot alter an architecturally-legitimate PTE which a PV guest has
 * chosen to write, as traditional paged-out metadata is L1TF-vulnerable.
 * What we can do is force a PV guest which writes a vulnerable PTE into
 * shadow mode, so Xen controls the pagetables which are reachable by the CPU
 * pagewalk.
 *
 * The core of the L1TF vulnerability is that the address bits of the PTE
 * (accounting for PSE and factoring in the level-relevant part of the linear
 * access) are sent for an L1D lookup (to retrieve the next-level PTE, or
 * eventual memory address) before the Present or reserved bits (which would
 * cause a terminal fault) are accounted for.  If an L1D hit occurs, the
 * resulting data is available for potentially dependent instructions.
 *
 * For Present PTEs, the PV type-count safety logic ensures that the address
 * bits always point at a guest-accessible frame, which is safe WRT L1TF from
 * Xen's point of view.  In practice, a PV guest should be unable to set any
 * reserved bits, so should be unable to create any present L1TF-vulnerable
 * PTEs at all.
 *
 * Therefore, these safety checks apply to Not-Present PTEs only, where
 * traditionally, Xen would have let the guest write any value it chose.
 *
 * The all-zero PTE potentially leaks mfn 0.  All software on the system is
 * expected to cooperate and not put any secrets there.  In a Xen system,
 * neither Xen nor dom0 are expected to touch mfn 0, as it typically contains
 * the real mode IVT and Bios Data Area.  Therefore, mfn 0 is considered safe.
 *
 * Any PTE whose address is higher than the maximum cacheable address is safe,
 * as it won't get an L1D hit.
 *
 * Speculative superpages also need accounting for, as PSE is considered
 * irrespective of Present.  We disallow PSE being set, as it allows an
 * attacker to leak 2M or 1G of data starting from mfn 0.  Also, because of
 * recursive/linear pagetables, we must consider PSE even at L4, as hardware
 * will interpret an L4e as an L3e during a recursive walk.
 */

static inline bool is_l1tf_safe_maddr(intpte_t pte)
{
    paddr_t maddr = pte & l1tf_addr_mask;

    return maddr == 0 || maddr >= l1tf_safe_maddr;
}

#ifdef CONFIG_PV

static inline bool pv_l1tf_check_pte(struct domain *d, unsigned int level,
                                     intpte_t pte)
{
    ASSERT(is_pv_domain(d));
    ASSERT(!(pte & _PAGE_PRESENT));

    if ( d->arch.pv.check_l1tf && !paging_mode_sh_forced(d) &&
         (((level > 1) && (pte & _PAGE_PSE)) || !is_l1tf_safe_maddr(pte)) )
    {
#ifdef CONFIG_SHADOW_PAGING
        struct tasklet *t = &d->arch.paging.shadow.pv_l1tf_tasklet;

        printk(XENLOG_G_WARNING
               "d%d L1TF-vulnerable L%ue %016"PRIx64" - Shadowing\n",
               d->domain_id, level, pte);
        /*
         * Safety consideration for accessing tasklet.scheduled_on without the
         * tasklet lock.  This is a singleshot tasklet with the side effect of
         * setting PG_SH_forced (checked just above).  Multiple vcpus can race
         * to schedule the tasklet, but if we observe it scheduled anywhere,
         * that is good enough.
         */
        smp_rmb();
        if ( !tasklet_is_scheduled(t) )
            tasklet_schedule(t);
#else
        printk(XENLOG_G_ERR
               "d%d L1TF-vulnerable L%ue %016"PRIx64" - Crashing\n",
               d->domain_id, level, pte);
        domain_crash(d);
#endif
        return true;
    }

    return false;
}

static inline bool pv_l1tf_check_l1e(struct domain *d, l1_pgentry_t l1e)
{
    return pv_l1tf_check_pte(d, 1, l1e.l1);
}

static inline bool pv_l1tf_check_l2e(struct domain *d, l2_pgentry_t l2e)
{
    return pv_l1tf_check_pte(d, 2, l2e.l2);
}

static inline bool pv_l1tf_check_l3e(struct domain *d, l3_pgentry_t l3e)
{
    return pv_l1tf_check_pte(d, 3, l3e.l3);
}

static inline bool pv_l1tf_check_l4e(struct domain *d, l4_pgentry_t l4e)
{
    return pv_l1tf_check_pte(d, 4, l4e.l4);
}

void pv_l1tf_tasklet(void *data);

static inline void pv_l1tf_domain_init(struct domain *d)
{
    d->arch.pv.check_l1tf = is_hardware_domain(d) ? opt_pv_l1tf_hwdom
                                                  : opt_pv_l1tf_domu;

#ifdef CONFIG_SHADOW_PAGING
    tasklet_init(&d->arch.paging.shadow.pv_l1tf_tasklet, pv_l1tf_tasklet, d);
#endif
}

static inline void pv_l1tf_domain_destroy(struct domain *d)
{
#ifdef CONFIG_SHADOW_PAGING
    tasklet_kill(&d->arch.paging.shadow.pv_l1tf_tasklet);
#endif
}

#endif /* CONFIG_PV */

/* Remove all shadows of the guest mfn. */
static inline void shadow_remove_all_shadows(struct domain *d, mfn_t gmfn)
{
    /* See the comment about locking in sh_remove_shadows */
    sh_remove_shadows(d, gmfn, 0 /* Be thorough */, 1 /* Must succeed */);
}

#endif /* _XEN_SHADOW_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
