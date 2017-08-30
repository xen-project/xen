/******************************************************************************
 * arch/x86/mm/mem_paging.c
 *
 * Memory paging support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
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


#include <asm/p2m.h>
#include <xen/guest_access.h>
#include <xen/vm_event.h>
#include <xsm/xsm.h>

int mem_paging_memop(XEN_GUEST_HANDLE_PARAM(xen_mem_paging_op_t) arg)
{
    int rc;
    xen_mem_paging_op_t mpo;
    struct domain *d;
    bool_t copyback = 0;

    if ( copy_from_guest(&mpo, arg, 1) )
        return -EFAULT;

    rc = rcu_lock_live_remote_domain_by_id(mpo.domain, &d);
    if ( rc )
        return rc;

    rc = xsm_mem_paging(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    rc = -ENODEV;
    if ( unlikely(!vm_event_check_ring(d->vm_event_paging)) )
        goto out;

    switch( mpo.op )
    {
    case XENMEM_paging_op_nominate:
        rc = p2m_mem_paging_nominate(d, mpo.gfn);
        break;

    case XENMEM_paging_op_evict:
        rc = p2m_mem_paging_evict(d, mpo.gfn);
        break;

    case XENMEM_paging_op_prep:
        rc = p2m_mem_paging_prep(d, mpo.gfn, mpo.buffer);
        if ( !rc )
            copyback = 1;
        break;

    default:
        rc = -ENOSYS;
        break;
    }

    if ( copyback && __copy_to_guest(arg, &mpo, 1) )
        rc = -EFAULT;

out:
    rcu_unlock_domain(d);
    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
