/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/shadow/pv.c
 *
 * PV-only shadow code (which hence does not need to be multiply compiled).
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 */

#include <xen/types.h>
#include <asm/shadow.h>
#include "private.h"

/*
 * Write a new value into the guest pagetable, and update the shadows
 * appropriately.
 */
void
shadow_write_guest_entry(struct vcpu *v, intpte_t *p, intpte_t new, mfn_t gmfn)
{
    paging_lock(v->domain);
    write_atomic(p, new);
    sh_validate_guest_entry(v, gmfn, p, sizeof(new));
    paging_unlock(v->domain);
}

/*
 * Compare and exchange a guest pagetable entry, and update the shadows
 * appropriately.  Returns the previous entry found, which the caller is
 * expected to check to see if the cmpxchg was successful.
 */
intpte_t
shadow_cmpxchg_guest_entry(struct vcpu *v, intpte_t *p, intpte_t old,
                           intpte_t new, mfn_t gmfn)
{
    intpte_t t;

    paging_lock(v->domain);
    t = cmpxchg(p, old, new);
    if ( t == old )
        sh_validate_guest_entry(v, gmfn, p, sizeof(new));
    paging_unlock(v->domain);

    return t;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
