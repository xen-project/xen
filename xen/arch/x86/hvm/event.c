/*
* event.c: Common hardware virtual machine event abstractions.
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
* this program; if not, write to the Free Software Foundation, Inc., 59 Temple
* Place - Suite 330, Boston, MA 02111-1307 USA.
*/

#include <xen/vm_event.h>
#include <xen/paging.h>
#include <public/vm_event.h>

static void hvm_event_fill_regs(vm_event_request_t *req)
{
    const struct cpu_user_regs *regs = guest_cpu_user_regs();
    const struct vcpu *curr = current;

    req->regs.x86.rax = regs->eax;
    req->regs.x86.rcx = regs->ecx;
    req->regs.x86.rdx = regs->edx;
    req->regs.x86.rbx = regs->ebx;
    req->regs.x86.rsp = regs->esp;
    req->regs.x86.rbp = regs->ebp;
    req->regs.x86.rsi = regs->esi;
    req->regs.x86.rdi = regs->edi;

    req->regs.x86.r8  = regs->r8;
    req->regs.x86.r9  = regs->r9;
    req->regs.x86.r10 = regs->r10;
    req->regs.x86.r11 = regs->r11;
    req->regs.x86.r12 = regs->r12;
    req->regs.x86.r13 = regs->r13;
    req->regs.x86.r14 = regs->r14;
    req->regs.x86.r15 = regs->r15;

    req->regs.x86.rflags = regs->eflags;
    req->regs.x86.rip    = regs->eip;

    req->regs.x86.msr_efer = curr->arch.hvm_vcpu.guest_efer;
    req->regs.x86.cr0 = curr->arch.hvm_vcpu.guest_cr[0];
    req->regs.x86.cr3 = curr->arch.hvm_vcpu.guest_cr[3];
    req->regs.x86.cr4 = curr->arch.hvm_vcpu.guest_cr[4];
}

static int hvm_event_traps(uint64_t parameters, vm_event_request_t *req)
{
    int rc;
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;

    if ( !(parameters & HVMPME_MODE_MASK) )
        return 0;

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

    if ( (parameters & HVMPME_MODE_MASK) == HVMPME_mode_sync )
    {
        req->flags |= VM_EVENT_FLAG_VCPU_PAUSED;
        vm_event_vcpu_pause(curr);
    }

    hvm_event_fill_regs(req);
    vm_event_put_request(currd, &currd->vm_event->monitor, req);

    return 1;
}

static void hvm_event_cr(uint32_t reason, unsigned long value,
                         unsigned long old, uint64_t parameters)
{
    vm_event_request_t req = {
        .reason = reason,
        .vcpu_id = current->vcpu_id,
        .u.mov_to_cr.new_value = value,
        .u.mov_to_cr.old_value = old
    };

    if ( (parameters & HVMPME_onchangeonly) && (value == old) )
        return;

    hvm_event_traps(parameters, &req);
}

void hvm_event_cr0(unsigned long value, unsigned long old)
{
    hvm_event_cr(VM_EVENT_REASON_MOV_TO_CR0, value, old,
                 current->domain->arch.hvm_domain
                      .params[HVM_PARAM_MEMORY_EVENT_CR0]);
}

void hvm_event_cr3(unsigned long value, unsigned long old)
{
    hvm_event_cr(VM_EVENT_REASON_MOV_TO_CR3, value, old,
                 current->domain->arch.hvm_domain
                      .params[HVM_PARAM_MEMORY_EVENT_CR3]);
}

void hvm_event_cr4(unsigned long value, unsigned long old)
{
    hvm_event_cr(VM_EVENT_REASON_MOV_TO_CR4, value, old,
                 current->domain->arch.hvm_domain
                      .params[HVM_PARAM_MEMORY_EVENT_CR4]);
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
    uint64_t params = curr->domain->arch.hvm_domain
                        .params[HVM_PARAM_MEMORY_EVENT_MSR];

    hvm_event_traps(params, &req);
}

int hvm_event_int3(unsigned long gla)
{
    uint32_t pfec = PFEC_page_present;
    struct vcpu *curr = current;
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_SOFTWARE_BREAKPOINT,
        .vcpu_id = curr->vcpu_id,
        .u.software_breakpoint.gfn = paging_gva_to_gfn(curr, gla, &pfec)
    };
    uint64_t params = curr->domain->arch.hvm_domain
                        .params[HVM_PARAM_MEMORY_EVENT_INT3];

    return hvm_event_traps(params, &req);
}

int hvm_event_single_step(unsigned long gla)
{
    uint32_t pfec = PFEC_page_present;
    struct vcpu *curr = current;
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_SINGLESTEP,
        .vcpu_id = curr->vcpu_id,
        .u.singlestep.gfn = paging_gva_to_gfn(curr, gla, &pfec)
    };
    uint64_t params = curr->domain->arch.hvm_domain
                        .params[HVM_PARAM_MEMORY_EVENT_SINGLE_STEP];

    return hvm_event_traps(params, &req);
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
