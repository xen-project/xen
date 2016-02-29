/*
 * arch/x86/hvm/event.c
 *
 * Arch-specific hardware virtual machine event abstractions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 * Copyright (c) 2016, Bitdefender S.R.L.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/vm_event.h>
#include <asm/hvm/event.h>
#include <asm/monitor.h>
#include <asm/vm_event.h>
#include <public/vm_event.h>

bool_t hvm_event_cr(unsigned int index, unsigned long value, unsigned long old)
{
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    unsigned int ctrlreg_bitmask = monitor_ctrlreg_bitmask(index);

    if ( (ad->monitor.write_ctrlreg_enabled & ctrlreg_bitmask) &&
         (!(ad->monitor.write_ctrlreg_onchangeonly & ctrlreg_bitmask) ||
          value != old) )
    {
        bool_t sync = !!(ad->monitor.write_ctrlreg_sync & ctrlreg_bitmask);

        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_WRITE_CTRLREG,
            .vcpu_id = curr->vcpu_id,
            .u.write_ctrlreg.index = index,
            .u.write_ctrlreg.new_value = value,
            .u.write_ctrlreg.old_value = old
        };

        vm_event_monitor_traps(curr, sync, &req);
        return 1;
    }

    return 0;
}

void hvm_event_msr(unsigned int msr, uint64_t value)
{
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;

    if ( ad->monitor.mov_to_msr_enabled )
    {
        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_MOV_TO_MSR,
            .vcpu_id = curr->vcpu_id,
            .u.mov_to_msr.msr = msr,
            .u.mov_to_msr.value = value,
        };

        vm_event_monitor_traps(curr, 1, &req);
    }
}

static inline unsigned long gfn_of_rip(unsigned long rip)
{
    struct vcpu *curr = current;
    struct segment_register sreg;
    uint32_t pfec = PFEC_page_present | PFEC_insn_fetch;

    hvm_get_segment_register(curr, x86_seg_ss, &sreg);
    if ( sreg.attr.fields.dpl == 3 )
        pfec |= PFEC_user_mode;

    hvm_get_segment_register(curr, x86_seg_cs, &sreg);

    return paging_gva_to_gfn(curr, sreg.base + rip, &pfec);
}

int hvm_event_breakpoint(unsigned long rip,
                         enum hvm_event_breakpoint_type type)
{
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    vm_event_request_t req = {};

    switch ( type )
    {
    case HVM_EVENT_SOFTWARE_BREAKPOINT:
        if ( !ad->monitor.software_breakpoint_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_SOFTWARE_BREAKPOINT;
        req.u.software_breakpoint.gfn = gfn_of_rip(rip);
        break;

    case HVM_EVENT_SINGLESTEP_BREAKPOINT:
        if ( !ad->monitor.singlestep_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_SINGLESTEP;
        req.u.singlestep.gfn = gfn_of_rip(rip);
        break;

    default:
        return -EOPNOTSUPP;
    }

    req.vcpu_id = curr->vcpu_id;

    return vm_event_monitor_traps(curr, 1, &req);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
