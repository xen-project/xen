/******************************************************************************
 * mem_access.c
 *
 * Memory access support.
 *
 * Copyright (c) 2011 Virtuata, Inc.
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


#include <xen/sched.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/vm_event.h>
#include <public/memory.h>
#include <asm/p2m.h>
#include <xsm/xsm.h>

int mem_access_memop(unsigned long cmd,
                     XEN_GUEST_HANDLE_PARAM(xen_mem_access_op_t) arg)
{
    unsigned long start_iter = cmd & ~MEMOP_CMD_MASK;
    long rc;
    xen_mem_access_op_t mao;
    struct domain *d;

    if ( copy_from_guest(&mao, arg, 1) )
        return -EFAULT;

    rc = rcu_lock_live_remote_domain_by_id(mao.domid, &d);
    if ( rc )
        return rc;

    rc = -EINVAL;
    if ( !p2m_mem_access_sanity_check(d) )
        goto out;

    rc = xsm_mem_access(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    rc = -ENODEV;
    if ( unlikely(!d->vm_event->monitor.ring_page) )
        goto out;

    switch ( mao.op )
    {

    case XENMEM_access_op_set_access:
        rc = -EINVAL;
        if ( (mao.pfn != ~0ull) &&
             (mao.nr < start_iter ||
              ((mao.pfn + mao.nr - 1) < mao.pfn) ||
              ((mao.pfn + mao.nr - 1) > domain_get_maximum_gpfn(d))) )
            break;

        rc = p2m_set_mem_access(d, _gfn(mao.pfn), mao.nr, start_iter,
                                MEMOP_CMD_MASK, mao.access);
        if ( rc > 0 )
        {
            ASSERT(!(rc & MEMOP_CMD_MASK));
            rc = hypercall_create_continuation(__HYPERVISOR_memory_op, "lh",
                                               XENMEM_access_op | rc, arg);
        }
        break;

    case XENMEM_access_op_get_access:
    {
        xenmem_access_t access;

        rc = -ENOSYS;
        if ( unlikely(start_iter) )
            break;

        rc = -EINVAL;
        if ( (mao.pfn > domain_get_maximum_gpfn(d)) && mao.pfn != ~0ull )
            break;

        rc = p2m_get_mem_access(d, _gfn(mao.pfn), &access);
        if ( rc != 0 )
            break;

        mao.access = access;
        rc = __copy_field_to_guest(arg, &mao, access) ? -EFAULT : 0;

        break;
    }

    case XENMEM_access_op_enable_emulate:
        rc = p2m_mem_access_enable_emulate(d);
        break;

    case XENMEM_access_op_disable_emulate:
        rc = p2m_mem_access_disable_emulate(d);
        break;

    default:
        rc = -ENOSYS;
        break;
    }

 out:
    rcu_unlock_domain(d);
    return rc;
}

int mem_access_send_req(struct domain *d, vm_event_request_t *req)
{
    int rc = vm_event_claim_slot(d, &d->vm_event->monitor);
    if ( rc < 0 )
        return rc;

    vm_event_put_request(d, &d->vm_event->monitor, req);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
