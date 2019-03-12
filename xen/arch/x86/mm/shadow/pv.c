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
 * appropriately.  Returns false if we page-faulted, true for success.
 */
bool
sh_write_guest_entry(struct vcpu *v, intpte_t *p, intpte_t new, mfn_t gmfn)
{
    unsigned int failed;

    paging_lock(v->domain);
    failed = __copy_to_user(p, &new, sizeof(new));
    if ( failed != sizeof(new) )
        sh_validate_guest_entry(v, gmfn, p, sizeof(new));
    paging_unlock(v->domain);

    return !failed;
}

/*
 * Cmpxchg a new value into the guest pagetable, and update the shadows
 * appropriately. Returns false if we page-faulted, true if not.
 * N.B. caller should check the value of "old" to see if the cmpxchg itself
 * was successful.
 */
bool
sh_cmpxchg_guest_entry(struct vcpu *v, intpte_t *p, intpte_t *old,
                       intpte_t new, mfn_t gmfn)
{
    bool failed;
    intpte_t t = *old;

    paging_lock(v->domain);
    failed = cmpxchg_user(p, t, new);
    if ( t == *old )
        sh_validate_guest_entry(v, gmfn, p, sizeof(new));
    *old = t;
    paging_unlock(v->domain);

    return !failed;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
