/*
 * arch/x86/hvm/event.c
 *
 * Arch-specific hardware virtual machine event abstractions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
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
#include <xen/paging.h>
#include <asm/hvm/event.h>
#include <asm/monitor.h>
#include <asm/altp2m.h>
#include <public/vm_event.h>

static void hvm_event_fill_regs(vm_event_request_t *req)
{
    const struct cpu_user_regs *regs = guest_cpu_user_regs();
    const struct vcpu *curr = current;

    req->data.regs.x86.rax = regs->eax;
    req->data.regs.x86.rcx = regs->ecx;
    req->data.regs.x86.rdx = regs->edx;
    req->data.regs.x86.rbx = regs->ebx;
    req->data.regs.x86.rsp = regs->esp;
    req->data.regs.x86.rbp = regs->ebp;
    req->data.regs.x86.rsi = regs->esi;
    req->data.regs.x86.rdi = regs->edi;

    req->data.regs.x86.r8  = regs->r8;
    req->data.regs.x86.r9  = regs->r9;
    req->data.regs.x86.r10 = regs->r10;
    req->data.regs.x86.r11 = regs->r11;
    req->data.regs.x86.r12 = regs->r12;
    req->data.regs.x86.r13 = regs->r13;
    req->data.regs.x86.r14 = regs->r14;
    req->data.regs.x86.r15 = regs->r15;

    req->data.regs.x86.rflags = regs->eflags;
    req->data.regs.x86.rip    = regs->eip;

    req->data.regs.x86.msr_efer = curr->arch.hvm_vcpu.guest_efer;
    req->data.regs.x86.cr0 = curr->arch.hvm_vcpu.guest_cr[0];
    req->data.regs.x86.cr3 = curr->arch.hvm_vcpu.guest_cr[3];
    req->data.regs.x86.cr4 = curr->arch.hvm_vcpu.guest_cr[4];
}

static int hvm_event_traps(uint8_t sync, vm_event_request_t *req)
{
    int rc;
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;

    rc = vm_event_claim_slot(currd, &currd->vm_event->monitor);
    switch ( rc )
    {
    case 0:
        break;
    case -ENOSYS:
        /*
         * If there was no ring to handle the event, then
         * simply continue executing normally.
         */
        return 1;
    default:
        return rc;
    };

    if ( sync )
    {
        req->flags |= VM_EVENT_FLAG_VCPU_PAUSED;
        vm_event_vcpu_pause(curr);
    }

    if ( altp2m_active(currd) )
    {
        req->flags |= VM_EVENT_FLAG_ALTERNATE_P2M;
        req->altp2m_idx = vcpu_altp2m(curr).p2midx;
    }

    hvm_event_fill_regs(req);
    vm_event_put_request(currd, &currd->vm_event->monitor, req);

    return 1;
}

bool_t hvm_event_cr(unsigned int index, unsigned long value, unsigned long old)
{
    struct arch_domain *currad = &current->domain->arch;
    unsigned int ctrlreg_bitmask = monitor_ctrlreg_bitmask(index);

    if ( (currad->monitor.write_ctrlreg_enabled & ctrlreg_bitmask) &&
         (!(currad->monitor.write_ctrlreg_onchangeonly & ctrlreg_bitmask) ||
          value != old) )
    {
        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_WRITE_CTRLREG,
            .vcpu_id = current->vcpu_id,
            .u.write_ctrlreg.index = index,
            .u.write_ctrlreg.new_value = value,
            .u.write_ctrlreg.old_value = old
        };

        hvm_event_traps(currad->monitor.write_ctrlreg_sync & ctrlreg_bitmask,
                        &req);
        return 1;
    }

    return 0;
}

void hvm_event_msr(unsigned int msr, uint64_t value)
{
    struct vcpu *curr = current;
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_MOV_TO_MSR,
        .vcpu_id = curr->vcpu_id,
        .u.mov_to_msr.msr = msr,
        .u.mov_to_msr.value = value,
    };

    if ( curr->domain->arch.monitor.mov_to_msr_enabled )
        hvm_event_traps(1, &req);
}

void hvm_event_guest_request(void)
{
    struct vcpu *curr = current;
    struct arch_domain *currad = &curr->domain->arch;

    if ( currad->monitor.guest_request_enabled )
    {
        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_GUEST_REQUEST,
            .vcpu_id = curr->vcpu_id,
        };

        hvm_event_traps(currad->monitor.guest_request_sync, &req);
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
    vm_event_request_t req;

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

    return hvm_event_traps(1, &req);
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
