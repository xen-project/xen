/*
 * arch/x86/vm_event.c
 *
 * Architecture-specific vm_event handling routines
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
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

#include <xen/sched.h>
#include <xen/mem_access.h>
#include <asm/vm_event.h>

/* Implicitly serialized by the domctl lock. */
int vm_event_init_domain(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        if ( v->arch.vm_event )
            continue;

        v->arch.vm_event = xzalloc(struct arch_vm_event);

        if ( !v->arch.vm_event )
            return -ENOMEM;
    }

    return 0;
}

/*
 * Implicitly serialized by the domctl lock,
 * or on domain cleanup paths only.
 */
void vm_event_cleanup_domain(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        xfree(v->arch.vm_event);
        v->arch.vm_event = NULL;
    }

    d->arch.mem_access_emulate_each_rep = 0;
}

void vm_event_toggle_singlestep(struct domain *d, struct vcpu *v,
                                vm_event_response_t *rsp)
{
    if ( !(rsp->flags & (VM_EVENT_FLAG_TOGGLE_SINGLESTEP |
                         VM_EVENT_FLAG_FAST_SINGLESTEP)) )
        return;

    if ( !is_hvm_domain(d) )
        return;

    ASSERT(atomic_read(&v->vm_event_pause_count));

    if ( rsp->flags & VM_EVENT_FLAG_TOGGLE_SINGLESTEP )
        hvm_toggle_singlestep(v);
    else
        hvm_fast_singlestep(v, rsp->u.fast_singlestep.p2midx);
}

void vm_event_register_write_resume(struct vcpu *v, vm_event_response_t *rsp)
{
    if ( rsp->flags & VM_EVENT_FLAG_DENY )
    {
        struct monitor_write_data *w;

        ASSERT(v->arch.vm_event);

        /* deny flag requires the vCPU to be paused */
        if ( !atomic_read(&v->vm_event_pause_count) )
            return;

        w = &v->arch.vm_event->write_data;

        switch ( rsp->reason )
        {
        case VM_EVENT_REASON_MOV_TO_MSR:
            w->do_write.msr = 0;
            break;
        case VM_EVENT_REASON_WRITE_CTRLREG:
            switch ( rsp->u.write_ctrlreg.index )
            {
            case VM_EVENT_X86_CR0:
                w->do_write.cr0 = 0;
                break;
            case VM_EVENT_X86_CR3:
                w->do_write.cr3 = 0;
                break;
            case VM_EVENT_X86_CR4:
                w->do_write.cr4 = 0;
                break;
            }
            break;
        }
    }
}

void vm_event_set_registers(struct vcpu *v, vm_event_response_t *rsp)
{
    ASSERT(atomic_read(&v->vm_event_pause_count));

    v->arch.vm_event->gprs = rsp->data.regs.x86;
    v->arch.vm_event->set_gprs = true;
}

void vm_event_monitor_next_interrupt(struct vcpu *v)
{
    v->arch.monitor.next_interrupt_enabled = true;
}

void vm_event_sync_event(struct vcpu *v, bool value)
{
    v->arch.vm_event->sync_event = value;
}

#ifdef CONFIG_HVM
static void vm_event_pack_segment_register(enum x86_segment segment,
                                           struct vm_event_regs_x86 *reg)
{
    struct segment_register seg;

    hvm_get_segment_register(current, segment, &seg);

    switch ( segment )
    {
    case x86_seg_ss:
        reg->ss_base = seg.base;
        reg->ss.limit = seg.g ? seg.limit >> 12 : seg.limit;
        reg->ss.ar = seg.attr;
        reg->ss_sel = seg.sel;
        break;

    case x86_seg_fs:
        reg->fs_base = seg.base;
        reg->fs.limit = seg.g ? seg.limit >> 12 : seg.limit;
        reg->fs.ar = seg.attr;
        reg->fs_sel = seg.sel;
        break;

    case x86_seg_gs:
        reg->gs_base = seg.base;
        reg->gs.limit = seg.g ? seg.limit >> 12 : seg.limit;
        reg->gs.ar = seg.attr;
        reg->gs_sel = seg.sel;
        break;

    case x86_seg_cs:
        reg->cs_base = seg.base;
        reg->cs.limit = seg.g ? seg.limit >> 12 : seg.limit;
        reg->cs.ar = seg.attr;
        reg->cs_sel = seg.sel;
        break;

    case x86_seg_ds:
        reg->ds_base = seg.base;
        reg->ds.limit = seg.g ? seg.limit >> 12 : seg.limit;
        reg->ds.ar = seg.attr;
        reg->ds_sel = seg.sel;
        break;

    case x86_seg_es:
        reg->es_base = seg.base;
        reg->es.limit = seg.g ? seg.limit >> 12 : seg.limit;
        reg->es.ar = seg.attr;
        reg->es_sel = seg.sel;
        break;

    case x86_seg_gdtr:
        reg->gdtr_base = seg.base;
        reg->gdtr_limit = seg.limit;
        break;

    default:
        ASSERT_UNREACHABLE();
    }
}
#endif

void vm_event_fill_regs(vm_event_request_t *req)
{
#ifdef CONFIG_HVM
    const struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct hvm_hw_cpu ctxt = {};
    struct vcpu *curr = current;

    ASSERT(is_hvm_vcpu(curr));

    /* Architecture-specific vmcs/vmcb bits */
    hvm_funcs.save_cpu_ctxt(curr, &ctxt);

    req->data.regs.x86.rax = regs->rax;
    req->data.regs.x86.rcx = regs->rcx;
    req->data.regs.x86.rdx = regs->rdx;
    req->data.regs.x86.rbx = regs->rbx;
    req->data.regs.x86.rsp = regs->rsp;
    req->data.regs.x86.rbp = regs->rbp;
    req->data.regs.x86.rsi = regs->rsi;
    req->data.regs.x86.rdi = regs->rdi;

    req->data.regs.x86.r8  = regs->r8;
    req->data.regs.x86.r9  = regs->r9;
    req->data.regs.x86.r10 = regs->r10;
    req->data.regs.x86.r11 = regs->r11;
    req->data.regs.x86.r12 = regs->r12;
    req->data.regs.x86.r13 = regs->r13;
    req->data.regs.x86.r14 = regs->r14;
    req->data.regs.x86.r15 = regs->r15;

    req->data.regs.x86.rflags = regs->rflags;
    req->data.regs.x86.rip    = regs->rip;

    req->data.regs.x86.dr7 = curr->arch.dr7;
    req->data.regs.x86.cr0 = curr->arch.hvm.guest_cr[0];
    req->data.regs.x86.cr2 = curr->arch.hvm.guest_cr[2];
    req->data.regs.x86.cr3 = curr->arch.hvm.guest_cr[3];
    req->data.regs.x86.cr4 = curr->arch.hvm.guest_cr[4];

    req->data.regs.x86.sysenter_cs = ctxt.sysenter_cs;
    req->data.regs.x86.sysenter_esp = ctxt.sysenter_esp;
    req->data.regs.x86.sysenter_eip = ctxt.sysenter_eip;

    req->data.regs.x86.msr_efer = curr->arch.hvm.guest_efer;
    req->data.regs.x86.msr_star = ctxt.msr_star;
    req->data.regs.x86.msr_lstar = ctxt.msr_lstar;

    vm_event_pack_segment_register(x86_seg_fs, &req->data.regs.x86);
    vm_event_pack_segment_register(x86_seg_gs, &req->data.regs.x86);
    vm_event_pack_segment_register(x86_seg_cs, &req->data.regs.x86);
    vm_event_pack_segment_register(x86_seg_ss, &req->data.regs.x86);
    vm_event_pack_segment_register(x86_seg_ds, &req->data.regs.x86);
    vm_event_pack_segment_register(x86_seg_es, &req->data.regs.x86);
    vm_event_pack_segment_register(x86_seg_gdtr, &req->data.regs.x86);

    req->data.regs.x86.shadow_gs = ctxt.shadow_gs;
    req->data.regs.x86.dr6 = ctxt.dr6;
#endif
}

void vm_event_emulate_check(struct vcpu *v, vm_event_response_t *rsp)
{
    if ( !(rsp->flags & VM_EVENT_FLAG_EMULATE) )
    {
        v->arch.vm_event->emulate_flags = 0;
        return;
    }

    switch ( rsp->reason )
    {
    case VM_EVENT_REASON_MEM_ACCESS:
        /*
         * Emulate iff this is a response to a mem_access violation and there
         * are still conflicting mem_access permissions in-place.
         */
        if ( p2m_mem_access_emulate_check(v, rsp) )
        {
            if ( rsp->flags & VM_EVENT_FLAG_SET_EMUL_READ_DATA )
                v->arch.vm_event->emul.read = rsp->data.emul.read;

            v->arch.vm_event->emulate_flags = rsp->flags;
        }
        break;

    case VM_EVENT_REASON_SOFTWARE_BREAKPOINT:
        if ( rsp->flags & VM_EVENT_FLAG_SET_EMUL_INSN_DATA )
        {
            v->arch.vm_event->emul.insn = rsp->data.emul.insn;
            v->arch.vm_event->emulate_flags = rsp->flags;
        }
        break;

    case VM_EVENT_REASON_DESCRIPTOR_ACCESS:
        if ( rsp->flags & VM_EVENT_FLAG_SET_EMUL_READ_DATA )
            v->arch.vm_event->emul.read = rsp->data.emul.read;
        v->arch.vm_event->emulate_flags = rsp->flags;
        break;

    default:
        break;
    };
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
