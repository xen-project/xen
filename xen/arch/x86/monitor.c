/*
 * arch/x86/monitor.c
 *
 * Arch-specific monitor_op domctl handler.
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

#include <asm/monitor.h>
#include <public/vm_event.h>

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop)
{
    struct arch_domain *ad = &d->arch;
    bool_t requested_status = (XEN_DOMCTL_MONITOR_OP_ENABLE == mop->op);

    switch ( mop->event )
    {
    case XEN_DOMCTL_MONITOR_EVENT_WRITE_CTRLREG:
    {
        unsigned int ctrlreg_bitmask;
        bool_t old_status;

        /* sanity check: avoid left-shift undefined behavior */
        if ( unlikely(mop->u.mov_to_cr.index > 31) )
            return -EINVAL;

        ctrlreg_bitmask = monitor_ctrlreg_bitmask(mop->u.mov_to_cr.index);
        old_status = !!(ad->monitor.write_ctrlreg_enabled & ctrlreg_bitmask);

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);

        if ( mop->u.mov_to_cr.sync )
            ad->monitor.write_ctrlreg_sync |= ctrlreg_bitmask;
        else
            ad->monitor.write_ctrlreg_sync &= ~ctrlreg_bitmask;

        if ( mop->u.mov_to_cr.onchangeonly )
            ad->monitor.write_ctrlreg_onchangeonly |= ctrlreg_bitmask;
        else
            ad->monitor.write_ctrlreg_onchangeonly &= ~ctrlreg_bitmask;

        if ( requested_status )
            ad->monitor.write_ctrlreg_enabled |= ctrlreg_bitmask;
        else
            ad->monitor.write_ctrlreg_enabled &= ~ctrlreg_bitmask;

        if ( VM_EVENT_X86_CR3 == mop->u.mov_to_cr.index )
        {
            struct vcpu *v;
            /* Latches new CR3 mask through CR0 code. */
            for_each_vcpu ( d, v )
                hvm_update_guest_cr(v, 0);
        }

        domain_unpause(d);

        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR:
    {
        bool_t old_status = ad->monitor.mov_to_msr_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        if ( requested_status && mop->u.mov_to_msr.extended_capture &&
             !hvm_enable_msr_exit_interception(d) )
            return -EOPNOTSUPP;

        domain_pause(d);

        if ( requested_status && mop->u.mov_to_msr.extended_capture )
            ad->monitor.mov_to_msr_extended = 1;
        else
            ad->monitor.mov_to_msr_extended = 0;

        ad->monitor.mov_to_msr_enabled = requested_status;
        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP:
    {
        bool_t old_status = ad->monitor.singlestep_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        ad->monitor.singlestep_enabled = requested_status;
        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_SOFTWARE_BREAKPOINT:
    {
        bool_t old_status = ad->monitor.software_breakpoint_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        ad->monitor.software_breakpoint_enabled = requested_status;
        domain_unpause(d);
        break;
    }

    default:
        /*
         * Should not be reached unless vm_event_monitor_get_capabilities() is
         * not properly implemented.
         */
        ASSERT_UNREACHABLE();
        return -EOPNOTSUPP;
    }

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
