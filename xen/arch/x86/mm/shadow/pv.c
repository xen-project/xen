/******************************************************************************
 * arch/x86/mm/shadow/pv.c
 *
 * PV-only shadow code (which hence does not need to be multiply compiled).
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

#include <xen/types.h>
#include <asm/shadow.h>
#include "private.h"

/*
 * Write a new value into the guest pagetable, and update the shadows
 * appropriately.
 */
void cf_check
sh_write_guest_entry(struct vcpu *v, intpte_t *p, intpte_t new, mfn_t gmfn)
{
    paging_lock(v->domain);
    write_atomic(p, new);
    sh_validate_guest_entry(v, gmfn, p, sizeof(new));
    paging_unlock(v->domain);
}

/*
 * Cmpxchg a new value into the guest pagetable, and update the shadows
 * appropriately.  Returns the previous entry found, which the caller is
 * expected to check to see if the cmpxchg was successful.
 */
intpte_t cf_check
sh_cmpxchg_guest_entry(struct vcpu *v, intpte_t *p, intpte_t old,
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
