/*
 * arch/x86/hvm/monitor.c
 *
 * Arch-specific hardware virtual machine event abstractions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 * Copyright (c) 2016, Bitdefender S.R.L.
 * Copyright (c) 2016, Tamas K Lengyel (tamas@tklengyel.com)
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
#include <xen/monitor.h>
#include <asm/hvm/monitor.h>
#include <asm/monitor.h>
#include <asm/paging.h>
#include <asm/vm_event.h>
#include <public/vm_event.h>

bool_t hvm_monitor_cr(unsigned int index, unsigned long value, unsigned long old)
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
            .u.write_ctrlreg.index = index,
            .u.write_ctrlreg.new_value = value,
            .u.write_ctrlreg.old_value = old
        };

        if ( monitor_traps(curr, sync, &req) >= 0 )
            return 1;
    }

    return 0;
}

void hvm_monitor_msr(unsigned int msr, uint64_t value)
{
    struct vcpu *curr = current;

    if ( monitored_msr(curr->domain, msr) )
    {
        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_MOV_TO_MSR,
            .u.mov_to_msr.msr = msr,
            .u.mov_to_msr.value = value,
        };

        monitor_traps(curr, 1, &req);
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

int hvm_monitor_debug(unsigned long rip, enum hvm_monitor_debug_type type,
                      unsigned long trap_type, unsigned long insn_length)
{
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    vm_event_request_t req = {};
    bool_t sync;

    switch ( type )
    {
    case HVM_MONITOR_SOFTWARE_BREAKPOINT:
        if ( !ad->monitor.software_breakpoint_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_SOFTWARE_BREAKPOINT;
        req.u.software_breakpoint.gfn = gfn_of_rip(rip);
        req.u.software_breakpoint.type = trap_type;
        req.u.software_breakpoint.insn_length = insn_length;
        sync = 1;
        break;

    case HVM_MONITOR_SINGLESTEP_BREAKPOINT:
        if ( !ad->monitor.singlestep_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_SINGLESTEP;
        req.u.singlestep.gfn = gfn_of_rip(rip);
        sync = 1;
        break;

    case HVM_MONITOR_DEBUG_EXCEPTION:
        if ( !ad->monitor.debug_exception_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_DEBUG_EXCEPTION;
        req.u.debug_exception.gfn = gfn_of_rip(rip);
        req.u.debug_exception.type = trap_type;
        req.u.debug_exception.insn_length = insn_length;
        sync = !!ad->monitor.debug_exception_sync;
        break;

    default:
        return -EOPNOTSUPP;
    }

    return monitor_traps(curr, sync, &req);
}

int hvm_monitor_cpuid(unsigned long insn_length, unsigned int leaf,
                      unsigned int subleaf)
{
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    vm_event_request_t req = {};

    if ( !ad->monitor.cpuid_enabled )
        return 0;

    req.reason = VM_EVENT_REASON_CPUID;
    req.u.cpuid.insn_length = insn_length;
    req.u.cpuid.leaf = leaf;
    req.u.cpuid.subleaf = subleaf;

    return monitor_traps(curr, 1, &req);
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
