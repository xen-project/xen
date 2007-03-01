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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

/* Xen traps & emulates all reads of all page table pages:
 * not yet supported */
#define shadow_mode_trap_reads(_d) ({ (void)(_d); 0; })

/*
 * 32on64 support
 */
#ifdef __x86_64__
#define pv_32bit_guest(_v) (!is_hvm_vcpu(_v) && IS_COMPAT((_v)->domain))
#else
#define pv_32bit_guest(_v) (!is_hvm_vcpu(_v))
#endif


/*****************************************************************************
 * Entry points into the shadow code */

/* Set up the shadow-specific parts of a domain struct at start of day.
 * Called from paging_domain_init(). */
void shadow_domain_init(struct domain *d);

/* Setup the shadow-specific parts of a vcpu struct. It is called by
 * paging_vcpu_init() in paging.c */
void shadow_vcpu_init(struct vcpu *v);

/* Enable an arbitrary shadow mode.  Call once at domain creation. */
int shadow_enable(struct domain *d, u32 mode);

/* Handler for shadow control ops: operations from user-space to enable
 * and disable ephemeral shadow modes (test mode and log-dirty mode) and
 * manipulate the log-dirty bitmap. */
int shadow_domctl(struct domain *d, 
                  xen_domctl_shadow_op_t *sc,
                  XEN_GUEST_HANDLE(void) u_domctl);

/* Call when destroying a domain */
void shadow_teardown(struct domain *d);

/* Call once all of the references to the domain have gone away */
void shadow_final_teardown(struct domain *d);

/* Mark a page as dirty in the log-dirty bitmap: called when Xen 
 * makes changes to guest memory on its behalf. */
void sh_mark_dirty(struct domain *d, mfn_t gmfn);
/* Cleaner version so we don't pepper shadow_mode tests all over the place */
static inline void mark_dirty(struct domain *d, unsigned long gmfn)
{
    if ( unlikely(shadow_mode_log_dirty(d)) )
        /* See the comment about locking in sh_mark_dirty */
        sh_mark_dirty(d, _mfn(gmfn));
}

/* Update all the things that are derived from the guest's CR0/CR3/CR4.
 * Called to initialize paging structures if the paging mode
 * has changed, and when bringing up a VCPU for the first time. */
void shadow_update_paging_modes(struct vcpu *v);


/* Remove all mappings of the guest page from the shadows. 
 * This is called from common code.  It does not flush TLBs. */
int sh_remove_all_mappings(struct vcpu *v, mfn_t target_mfn);
static inline void 
shadow_drop_references(struct domain *d, struct page_info *p)
{
    if ( unlikely(shadow_mode_enabled(d)) )
        /* See the comment about locking in sh_remove_all_mappings */
        sh_remove_all_mappings(d->vcpu[0], _mfn(page_to_mfn(p)));
}

/* Remove all shadows of the guest mfn. */
void sh_remove_shadows(struct vcpu *v, mfn_t gmfn, int fast, int all);
static inline void shadow_remove_all_shadows(struct vcpu *v, mfn_t gmfn)
{
    /* See the comment about locking in sh_remove_shadows */
    sh_remove_shadows(v, gmfn, 0 /* Be thorough */, 1 /* Must succeed */);
}

#define guest_physmap_max_mem_pages(d, n) (0)

#endif /* _XEN_SHADOW_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
