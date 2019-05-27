/*
 * xen/common/monitor.c
 *
 * Common monitor_op domctl handler.
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 * Copyright (c) 2016, Bitdefender S.R.L.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/event.h>
#include <xen/monitor.h>
#include <xen/sched.h>
#include <xen/vm_event.h>
#include <xsm/xsm.h>
#include <asm/altp2m.h>
#include <asm/monitor.h>
#include <asm/vm_event.h>

int monitor_domctl(struct domain *d, struct xen_domctl_monitor_op *mop)
{
    int rc;
    bool requested_status = false;

    if ( unlikely(current->domain == d) ) /* no domain_pause() */
        return -EPERM;

    rc = xsm_vm_event_control(XSM_PRIV, d, mop->op, mop->event);
    if ( unlikely(rc) )
        return rc;

    switch ( mop->op )
    {
    case XEN_DOMCTL_MONITOR_OP_ENABLE:
        requested_status = true;
        /* fallthrough */
    case XEN_DOMCTL_MONITOR_OP_DISABLE:
        /* sanity check: avoid left-shift undefined behavior */
        if ( unlikely(mop->event > 31) )
            return -EINVAL;
        /* Check if event type is available. */
        if ( unlikely(!(arch_monitor_get_capabilities(d) & (1U << mop->event))) )
            return -EOPNOTSUPP;
        break;

    case XEN_DOMCTL_MONITOR_OP_GET_CAPABILITIES:
        mop->event = arch_monitor_get_capabilities(d);
        return 0;

    default:
        /* The monitor op is probably handled on the arch-side. */
        return arch_monitor_domctl_op(d, mop);
    }

    switch ( mop->event )
    {
    case XEN_DOMCTL_MONITOR_EVENT_GUEST_REQUEST:
    {
        bool old_status = d->monitor.guest_request_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        d->monitor.guest_request_sync = mop->u.guest_request.sync;
        d->monitor.guest_request_enabled = requested_status;
        arch_monitor_allow_userspace(d, mop->u.guest_request.allow_userspace);
        domain_unpause(d);
        break;
    }

    default:
        /* Give arch-side the chance to handle this event */
        return arch_monitor_domctl_event(d, mop);
    }

    return 0;
}

int monitor_traps(struct vcpu *v, bool sync, vm_event_request_t *req)
{
    int rc;
    struct domain *d = v->domain;

    rc = vm_event_claim_slot(d, d->vm_event_monitor);
    switch ( rc )
    {
    case 0:
        break;
    case -EOPNOTSUPP:
        /*
         * If there was no ring to handle the event, then
         * simply continue executing normally.
         */
        return 0;
    default:
        return rc;
    };

    req->vcpu_id = v->vcpu_id;

    if ( sync )
    {
        req->flags |= VM_EVENT_FLAG_VCPU_PAUSED;
        vm_event_sync_event(v, true);
        vm_event_vcpu_pause(v);
        rc = 1;
    }

    if ( altp2m_active(d) )
    {
        req->flags |= VM_EVENT_FLAG_ALTERNATE_P2M;
        req->altp2m_idx = altp2m_vcpu_idx(v);
    }

    vm_event_fill_regs(req);
    vm_event_put_request(d, d->vm_event_monitor, req);

    return rc;
}

void monitor_guest_request(void)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;

    if ( d->monitor.guest_request_enabled )
    {
        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_GUEST_REQUEST,
            .vcpu_id = curr->vcpu_id,
        };

        monitor_traps(curr, d->monitor.guest_request_sync, &req);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
