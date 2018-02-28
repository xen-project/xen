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

bool hvm_monitor_cr(unsigned int index, unsigned long value, unsigned long old)
{
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    unsigned int ctrlreg_bitmask = monitor_ctrlreg_bitmask(index);

    if ( index == VM_EVENT_X86_CR3 && hvm_pcid_enabled(curr) )
        value &= ~X86_CR3_NOFLUSH; /* Clear the noflush bit. */

    if ( (ad->monitor.write_ctrlreg_enabled & ctrlreg_bitmask) &&
         (!(ad->monitor.write_ctrlreg_onchangeonly & ctrlreg_bitmask) ||
          value != old) &&
         ((value ^ old) & ~ad->monitor.write_ctrlreg_mask[index]) )
    {
        bool sync = ad->monitor.write_ctrlreg_sync & ctrlreg_bitmask;

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

bool hvm_monitor_emul_unimplemented(void)
{
    struct vcpu *curr = current;

    /*
     * Send a vm_event to the monitor to signal that the current
     * instruction couldn't be emulated.
     */
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_EMUL_UNIMPLEMENTED,
        .vcpu_id  = curr->vcpu_id,
    };

    return curr->domain->arch.monitor.emul_unimplemented_enabled &&
        monitor_traps(curr, true, &req) == 1;
}

void hvm_monitor_msr(unsigned int msr, uint64_t new_value, uint64_t old_value)
{
    struct vcpu *curr = current;

    if ( monitored_msr(curr->domain, msr) &&
         (!monitored_msr_onchangeonly(curr->domain, msr) ||
           new_value != old_value) )
    {
        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_MOV_TO_MSR,
            .u.mov_to_msr.msr = msr,
            .u.mov_to_msr.new_value = new_value,
            .u.mov_to_msr.old_value = old_value
        };

        monitor_traps(curr, 1, &req);
    }
}

void hvm_monitor_descriptor_access(uint64_t exit_info,
                                   uint64_t vmx_exit_qualification,
                                   uint8_t descriptor, bool is_write)
{
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_DESCRIPTOR_ACCESS,
        .u.desc_access.descriptor = descriptor,
        .u.desc_access.is_write = is_write,
    };

    if ( cpu_has_vmx )
    {
        req.u.desc_access.arch.vmx.instr_info = exit_info;
        req.u.desc_access.arch.vmx.exit_qualification = vmx_exit_qualification;
    }
    else
    {
        req.u.desc_access.arch.svm.exitinfo = exit_info;
    }

    monitor_traps(current, true, &req);
}

static inline unsigned long gfn_of_rip(unsigned long rip)
{
    struct vcpu *curr = current;
    struct segment_register sreg;
    uint32_t pfec = PFEC_page_present | PFEC_insn_fetch;

    if ( hvm_get_cpl(curr) == 3 )
        pfec |= PFEC_user_mode;

    hvm_get_segment_register(curr, x86_seg_cs, &sreg);

    return paging_gva_to_gfn(curr, sreg.base + rip, &pfec);
}

int hvm_monitor_debug(unsigned long rip, enum hvm_monitor_debug_type type,
                      unsigned long trap_type, unsigned long insn_length)
{
   /*
    * rc < 0 error in monitor/vm_event, crash
    * !rc    continue normally
    * rc > 0 paused waiting for response, work here is done
    */
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    vm_event_request_t req = {};
    bool sync;

    switch ( type )
    {
    case HVM_MONITOR_SOFTWARE_BREAKPOINT:
        if ( !ad->monitor.software_breakpoint_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_SOFTWARE_BREAKPOINT;
        req.u.software_breakpoint.gfn = gfn_of_rip(rip);
        req.u.software_breakpoint.type = trap_type;
        req.u.software_breakpoint.insn_length = insn_length;
        sync = true;
        break;

    case HVM_MONITOR_SINGLESTEP_BREAKPOINT:
        if ( !ad->monitor.singlestep_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_SINGLESTEP;
        req.u.singlestep.gfn = gfn_of_rip(rip);
        sync = true;
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

void hvm_monitor_interrupt(unsigned int vector, unsigned int type,
                           unsigned int err, uint64_t cr2)
{
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_INTERRUPT,
        .u.interrupt.x86.vector = vector,
        .u.interrupt.x86.type = type,
        .u.interrupt.x86.error_code = err,
        .u.interrupt.x86.cr2 = cr2,
    };

    monitor_traps(current, 1, &req);
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
