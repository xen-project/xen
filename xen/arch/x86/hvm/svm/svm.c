/*
 * svm.c: handling SVM architecture-related VM exits
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/hypercall.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/io.h>
#include <asm/hvm/svm/asid.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/emulate.h>
#include <asm/hvm/svm/intr.h>
#include <asm/x86_emulate.h>
#include <public/sched.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/trace.h>
#include <asm/hap.h>

u32 svm_feature_flags;

#define set_segment_register(name, value)  \
    asm volatile ( "movw %%ax ,%%" STR(name) "" : : "a" (value) )

enum handler_return { HNDL_done, HNDL_unhandled, HNDL_exception_raised };

int inst_copy_from_guest(unsigned char *buf, unsigned long guest_eip,
                         int inst_len);
asmlinkage void do_IRQ(struct cpu_user_regs *);

static int svm_reset_to_realmode(
    struct vcpu *v, struct cpu_user_regs *regs);
static void svm_update_guest_cr(struct vcpu *v, unsigned int cr);

/* va of hardware host save area     */
static void *hsa[NR_CPUS] __read_mostly;

/* vmcb used for extended host state */
static void *root_vmcb[NR_CPUS] __read_mostly;

static void svm_update_guest_efer(struct vcpu *v);

static void inline __update_guest_eip(
    struct cpu_user_regs *regs, int inst_len) 
{
    ASSERT(inst_len > 0);
    regs->eip += inst_len;
    regs->eflags &= ~X86_EFLAGS_RF;
}

static void svm_inject_exception(
    struct vcpu *v, int trap, int ev, int error_code)
{
    eventinj_t event;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( trap == TRAP_page_fault )
        HVMTRACE_2D(PF_INJECT, v, v->arch.hvm_vcpu.guest_cr[2], error_code);
    else
        HVMTRACE_2D(INJ_EXC, v, trap, error_code);

    event.bytes = 0;            
    event.fields.v = 1;
    event.fields.type = X86_EVENTTYPE_HW_EXCEPTION;
    event.fields.vector = trap;
    event.fields.ev = ev;
    event.fields.errorcode = error_code;

    vmcb->eventinj = event;
}

static void svm_cpu_down(void)
{
    write_efer(read_efer() & ~EFER_SVME);
}

static enum handler_return long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content = (u32)regs->eax | ((u64)regs->edx << 32);
    u32 ecx = regs->ecx;

    HVM_DBG_LOG(DBG_LEVEL_0, "msr %x msr_content %"PRIx64,
                ecx, msr_content);

    switch ( ecx )
    {
    case MSR_EFER:
        if ( !hvm_set_efer(msr_content) )
            return HNDL_exception_raised;
        break;

    case MSR_IA32_MC4_MISC: /* Threshold register */
        /*
         * MCA/MCE: Threshold register is reported to be locked, so we ignore
         * all write accesses. This behaviour matches real HW, so guests should
         * have no problem with this.
         */
        break;

    default:
        return HNDL_unhandled;
    }

    return HNDL_done;
}

static void svm_save_dr(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( !v->arch.hvm_vcpu.flag_dr_dirty )
        return;

    /* Clear the DR dirty flag and re-enable intercepts for DR accesses. */
    v->arch.hvm_vcpu.flag_dr_dirty = 0;
    v->arch.hvm_svm.vmcb->dr_intercepts = ~0u;

    v->arch.guest_context.debugreg[0] = read_debugreg(0);
    v->arch.guest_context.debugreg[1] = read_debugreg(1);
    v->arch.guest_context.debugreg[2] = read_debugreg(2);
    v->arch.guest_context.debugreg[3] = read_debugreg(3);
    v->arch.guest_context.debugreg[6] = vmcb->dr6;
    v->arch.guest_context.debugreg[7] = vmcb->dr7;
}

static void __restore_debug_registers(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(!v->arch.hvm_vcpu.flag_dr_dirty);
    v->arch.hvm_vcpu.flag_dr_dirty = 1;
    vmcb->dr_intercepts = 0;

    write_debugreg(0, v->arch.guest_context.debugreg[0]);
    write_debugreg(1, v->arch.guest_context.debugreg[1]);
    write_debugreg(2, v->arch.guest_context.debugreg[2]);
    write_debugreg(3, v->arch.guest_context.debugreg[3]);
    vmcb->dr6 = v->arch.guest_context.debugreg[6];
    vmcb->dr7 = v->arch.guest_context.debugreg[7];
}

/*
 * DR7 is saved and restored on every vmexit.  Other debug registers only
 * need to be restored if their value is going to affect execution -- i.e.,
 * if one of the breakpoints is enabled.  So mask out all bits that don't
 * enable some breakpoint functionality.
 */
#define DR7_ACTIVE_MASK 0xff

static void svm_restore_dr(struct vcpu *v)
{
    if ( unlikely(v->arch.guest_context.debugreg[7] & DR7_ACTIVE_MASK) )
        __restore_debug_registers(v);
}

int svm_vmcb_save(struct vcpu *v, struct hvm_hw_cpu *c)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    c->cr0 = v->arch.hvm_vcpu.guest_cr[0];
    c->cr2 = v->arch.hvm_vcpu.guest_cr[2];
    c->cr3 = v->arch.hvm_vcpu.guest_cr[3];
    c->cr4 = v->arch.hvm_vcpu.guest_cr[4];

    c->idtr_limit = vmcb->idtr.limit;
    c->idtr_base  = vmcb->idtr.base;

    c->gdtr_limit = vmcb->gdtr.limit;
    c->gdtr_base  = vmcb->gdtr.base; 

    c->cs_sel = vmcb->cs.sel;
    c->cs_limit = vmcb->cs.limit;
    c->cs_base = vmcb->cs.base;
    c->cs_arbytes = vmcb->cs.attr.bytes;

    c->ds_sel = vmcb->ds.sel;
    c->ds_limit = vmcb->ds.limit;
    c->ds_base = vmcb->ds.base;
    c->ds_arbytes = vmcb->ds.attr.bytes;

    c->es_sel = vmcb->es.sel;
    c->es_limit = vmcb->es.limit;
    c->es_base = vmcb->es.base;
    c->es_arbytes = vmcb->es.attr.bytes;

    c->ss_sel = vmcb->ss.sel;
    c->ss_limit = vmcb->ss.limit;
    c->ss_base = vmcb->ss.base;
    c->ss_arbytes = vmcb->ss.attr.bytes;

    c->fs_sel = vmcb->fs.sel;
    c->fs_limit = vmcb->fs.limit;
    c->fs_base = vmcb->fs.base;
    c->fs_arbytes = vmcb->fs.attr.bytes;

    c->gs_sel = vmcb->gs.sel;
    c->gs_limit = vmcb->gs.limit;
    c->gs_base = vmcb->gs.base;
    c->gs_arbytes = vmcb->gs.attr.bytes;

    c->tr_sel = vmcb->tr.sel;
    c->tr_limit = vmcb->tr.limit;
    c->tr_base = vmcb->tr.base;
    c->tr_arbytes = vmcb->tr.attr.bytes;

    c->ldtr_sel = vmcb->ldtr.sel;
    c->ldtr_limit = vmcb->ldtr.limit;
    c->ldtr_base = vmcb->ldtr.base;
    c->ldtr_arbytes = vmcb->ldtr.attr.bytes;

    c->sysenter_cs = vmcb->sysenter_cs;
    c->sysenter_esp = vmcb->sysenter_esp;
    c->sysenter_eip = vmcb->sysenter_eip;

    c->pending_event = 0;
    c->error_code = 0;
    if ( vmcb->eventinj.fields.v &&
         hvm_event_needs_reinjection(vmcb->eventinj.fields.type,
                                     vmcb->eventinj.fields.vector) )
    {
        c->pending_event = (uint32_t)vmcb->eventinj.bytes;
        c->error_code = vmcb->eventinj.fields.errorcode;
    }

    return 1;
}


int svm_vmcb_restore(struct vcpu *v, struct hvm_hw_cpu *c)
{
    unsigned long mfn = 0;
    p2m_type_t p2mt;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( c->pending_valid &&
         ((c->pending_type == 1) || (c->pending_type > 6) ||
          (c->pending_reserved != 0)) )
    {
        gdprintk(XENLOG_ERR, "Invalid pending event 0x%"PRIx32".\n",
                 c->pending_event);
        return -EINVAL;
    }

    if ( !paging_mode_hap(v->domain) )
    {
        if ( c->cr0 & X86_CR0_PG )
        {
            mfn = mfn_x(gfn_to_mfn(v->domain, c->cr3 >> PAGE_SHIFT, &p2mt));
            if ( !p2m_is_ram(p2mt) || !get_page(mfn_to_page(mfn), v->domain) )
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value=0x%"PRIx64"\n",
                         c->cr3);
                return -EINVAL;
            }
        }

        if ( v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG )
            put_page(pagetable_get_page(v->arch.guest_table));

        v->arch.guest_table = pagetable_from_pfn(mfn);
    }

    v->arch.hvm_vcpu.guest_cr[0] = c->cr0 | X86_CR0_ET;
    v->arch.hvm_vcpu.guest_cr[2] = c->cr2;
    v->arch.hvm_vcpu.guest_cr[3] = c->cr3;
    v->arch.hvm_vcpu.guest_cr[4] = c->cr4;
    svm_update_guest_cr(v, 0);
    svm_update_guest_cr(v, 2);
    svm_update_guest_cr(v, 4);

#ifdef HVM_DEBUG_SUSPEND
    printk("%s: cr3=0x%"PRIx64", cr0=0x%"PRIx64", cr4=0x%"PRIx64".\n",
           __func__, c->cr3, c->cr0, c->cr4);
#endif

    vmcb->idtr.limit = c->idtr_limit;
    vmcb->idtr.base  = c->idtr_base;

    vmcb->gdtr.limit = c->gdtr_limit;
    vmcb->gdtr.base  = c->gdtr_base;

    vmcb->cs.sel        = c->cs_sel;
    vmcb->cs.limit      = c->cs_limit;
    vmcb->cs.base       = c->cs_base;
    vmcb->cs.attr.bytes = c->cs_arbytes;

    vmcb->ds.sel        = c->ds_sel;
    vmcb->ds.limit      = c->ds_limit;
    vmcb->ds.base       = c->ds_base;
    vmcb->ds.attr.bytes = c->ds_arbytes;

    vmcb->es.sel        = c->es_sel;
    vmcb->es.limit      = c->es_limit;
    vmcb->es.base       = c->es_base;
    vmcb->es.attr.bytes = c->es_arbytes;

    vmcb->ss.sel        = c->ss_sel;
    vmcb->ss.limit      = c->ss_limit;
    vmcb->ss.base       = c->ss_base;
    vmcb->ss.attr.bytes = c->ss_arbytes;
    vmcb->cpl           = vmcb->ss.attr.fields.dpl;

    vmcb->fs.sel        = c->fs_sel;
    vmcb->fs.limit      = c->fs_limit;
    vmcb->fs.base       = c->fs_base;
    vmcb->fs.attr.bytes = c->fs_arbytes;

    vmcb->gs.sel        = c->gs_sel;
    vmcb->gs.limit      = c->gs_limit;
    vmcb->gs.base       = c->gs_base;
    vmcb->gs.attr.bytes = c->gs_arbytes;

    vmcb->tr.sel        = c->tr_sel;
    vmcb->tr.limit      = c->tr_limit;
    vmcb->tr.base       = c->tr_base;
    vmcb->tr.attr.bytes = c->tr_arbytes;

    vmcb->ldtr.sel        = c->ldtr_sel;
    vmcb->ldtr.limit      = c->ldtr_limit;
    vmcb->ldtr.base       = c->ldtr_base;
    vmcb->ldtr.attr.bytes = c->ldtr_arbytes;

    vmcb->sysenter_cs =  c->sysenter_cs;
    vmcb->sysenter_esp = c->sysenter_esp;
    vmcb->sysenter_eip = c->sysenter_eip;

    if ( paging_mode_hap(v->domain) )
    {
        vmcb->np_enable = 1;
        vmcb->g_pat = 0x0007040600070406ULL; /* guest PAT */
        vmcb->h_cr3 = pagetable_get_paddr(v->domain->arch.phys_table);
    }

    if ( c->pending_valid ) 
    {
        gdprintk(XENLOG_INFO, "Re-injecting 0x%"PRIx32", 0x%"PRIx32"\n",
                 c->pending_event, c->error_code);

        if ( hvm_event_needs_reinjection(c->pending_type, c->pending_vector) )
        {
            vmcb->eventinj.bytes = c->pending_event;
            vmcb->eventinj.fields.errorcode = c->error_code;
        }
    }

    paging_update_paging_modes(v);

    return 0;
}

        
static void svm_save_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    data->shadow_gs        = vmcb->kerngsbase;
    data->msr_lstar        = vmcb->lstar;
    data->msr_star         = vmcb->star;
    data->msr_cstar        = vmcb->cstar;
    data->msr_syscall_mask = vmcb->sfmask;
    data->msr_efer         = v->arch.hvm_vcpu.guest_efer;
    data->msr_flags        = -1ULL;

    data->tsc = hvm_get_guest_time(v);
}


static void svm_load_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    vmcb->kerngsbase = data->shadow_gs;
    vmcb->lstar      = data->msr_lstar;
    vmcb->star       = data->msr_star;
    vmcb->cstar      = data->msr_cstar;
    vmcb->sfmask     = data->msr_syscall_mask;
    v->arch.hvm_vcpu.guest_efer = data->msr_efer;
    svm_update_guest_efer(v);

    hvm_set_guest_time(v, data->tsc);
}

static void svm_save_vmcb_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    svm_save_cpu_state(v, ctxt);
    svm_vmcb_save(v, ctxt);
}

static int svm_load_vmcb_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    svm_load_cpu_state(v, ctxt);
    if (svm_vmcb_restore(v, ctxt)) {
        printk("svm_vmcb restore failed!\n");
        domain_crash(v->domain);
        return -EINVAL;
    }

    return 0;
}

static enum hvm_intblk svm_interrupt_blocked(
    struct vcpu *v, struct hvm_intack intack)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( vmcb->interrupt_shadow )
        return hvm_intblk_shadow;

    if ( intack.source == hvm_intsrc_nmi )
        return hvm_intblk_none;

    ASSERT((intack.source == hvm_intsrc_pic) ||
           (intack.source == hvm_intsrc_lapic));

    if ( !(guest_cpu_user_regs()->eflags & X86_EFLAGS_IF) )
        return hvm_intblk_rflags_ie;

    if ( (intack.source == hvm_intsrc_lapic) &&
         ((vmcb->vintr.fields.tpr & 0xf) >= (intack.vector >> 4)) )
        return hvm_intblk_tpr;

    return hvm_intblk_none;
}

static int svm_guest_x86_mode(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( unlikely(!(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE)) )
        return 0;
    if ( unlikely(guest_cpu_user_regs()->eflags & X86_EFLAGS_VM) )
        return 1;
    if ( hvm_long_mode_enabled(v) && likely(vmcb->cs.attr.fields.l) )
        return 8;
    return (likely(vmcb->cs.attr.fields.db) ? 4 : 2);
}

static void svm_update_host_cr3(struct vcpu *v)
{
    /* SVM doesn't have a HOST_CR3 equivalent to update. */
}

static void svm_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    switch ( cr )
    {
    case 0:
        /* TS cleared? Then initialise FPU now. */
        if ( (v == current) && !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) &&
             (vmcb->cr0 & X86_CR0_TS) )
        {
            setup_fpu(v);
            vmcb->exception_intercepts &= ~(1U << TRAP_no_device);
        }

        vmcb->cr0 = v->arch.hvm_vcpu.guest_cr[0];
        if ( !paging_mode_hap(v->domain) )
            vmcb->cr0 |= X86_CR0_PG | X86_CR0_WP;
        break;
    case 2:
        vmcb->cr2 = v->arch.hvm_vcpu.guest_cr[2];
        break;
    case 3:
        vmcb->cr3 = v->arch.hvm_vcpu.hw_cr[3];
        svm_asid_inv_asid(v);
        break;
    case 4:
        vmcb->cr4 = HVM_CR4_HOST_MASK;
        if ( paging_mode_hap(v->domain) )
            vmcb->cr4 &= ~X86_CR4_PAE;
        vmcb->cr4 |= v->arch.hvm_vcpu.guest_cr[4];
        break;
    default:
        BUG();
    }
}

static void svm_update_guest_efer(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    vmcb->efer = (v->arch.hvm_vcpu.guest_efer | EFER_SVME) & ~EFER_LME;
    if ( vmcb->efer & EFER_LMA )
        vmcb->efer |= EFER_LME;
}

static void svm_flush_guest_tlbs(void)
{
    /* Roll over the CPU's ASID generation, so it gets a clean TLB when we
     * next VMRUN.  (If ASIDs are disabled, the whole TLB is flushed on
     * VMRUN anyway). */
    svm_asid_inc_generation();
}

static void svm_update_vtpr(struct vcpu *v, unsigned long value)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    vmcb->vintr.fields.tpr = value & 0x0f;
}

static void svm_sync_vmcb(struct vcpu *v)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;

    if ( arch_svm->vmcb_in_sync )
        return;

    arch_svm->vmcb_in_sync = 1;

    svm_vmsave(arch_svm->vmcb);
}

static unsigned long svm_get_segment_base(struct vcpu *v, enum x86_segment seg)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int long_mode = vmcb->cs.attr.fields.l && hvm_long_mode_enabled(v);

    switch ( seg )
    {
    case x86_seg_cs: return long_mode ? 0 : vmcb->cs.base;
    case x86_seg_ds: return long_mode ? 0 : vmcb->ds.base;
    case x86_seg_es: return long_mode ? 0 : vmcb->es.base;
    case x86_seg_fs: svm_sync_vmcb(v); return vmcb->fs.base;
    case x86_seg_gs: svm_sync_vmcb(v); return vmcb->gs.base;
    case x86_seg_ss: return long_mode ? 0 : vmcb->ss.base;
    case x86_seg_tr: svm_sync_vmcb(v); return vmcb->tr.base;
    case x86_seg_gdtr: return vmcb->gdtr.base;
    case x86_seg_idtr: return vmcb->idtr.base;
    case x86_seg_ldtr: svm_sync_vmcb(v); return vmcb->ldtr.base;
    }
    BUG();
    return 0;
}

static void svm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(v == current);

    switch ( seg )
    {
    case x86_seg_cs:
        memcpy(reg, &vmcb->cs, sizeof(*reg));
        break;
    case x86_seg_ds:
        memcpy(reg, &vmcb->ds, sizeof(*reg));
        break;
    case x86_seg_es:
        memcpy(reg, &vmcb->es, sizeof(*reg));
        break;
    case x86_seg_fs:
        svm_sync_vmcb(v);
        memcpy(reg, &vmcb->fs, sizeof(*reg));
        break;
    case x86_seg_gs:
        svm_sync_vmcb(v);
        memcpy(reg, &vmcb->gs, sizeof(*reg));
        break;
    case x86_seg_ss:
        memcpy(reg, &vmcb->ss, sizeof(*reg));
        break;
    case x86_seg_tr:
        svm_sync_vmcb(v);
        memcpy(reg, &vmcb->tr, sizeof(*reg));
        break;
    case x86_seg_gdtr:
        memcpy(reg, &vmcb->gdtr, sizeof(*reg));
        break;
    case x86_seg_idtr:
        memcpy(reg, &vmcb->idtr, sizeof(*reg));
        break;
    case x86_seg_ldtr:
        svm_sync_vmcb(v);
        memcpy(reg, &vmcb->ldtr, sizeof(*reg));
        break;
    default:
        BUG();
    }
}

static void svm_set_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(v == current);

    switch ( seg )
    {
    case x86_seg_cs:
        memcpy(&vmcb->cs, reg, sizeof(*reg));
        break;
    case x86_seg_ds:
        memcpy(&vmcb->ds, reg, sizeof(*reg));
        break;
    case x86_seg_es:
        memcpy(&vmcb->es, reg, sizeof(*reg));
        break;
    case x86_seg_fs:
        svm_sync_vmcb(v);
        memcpy(&vmcb->fs, reg, sizeof(*reg));
        svm_vmload(vmcb);
        break;
    case x86_seg_gs:
        svm_sync_vmcb(v);
        memcpy(&vmcb->gs, reg, sizeof(*reg));
        svm_vmload(vmcb);
        break;
    case x86_seg_ss:
        memcpy(&vmcb->ss, reg, sizeof(*reg));
        vmcb->cpl = vmcb->ss.attr.fields.dpl;
        break;
    case x86_seg_tr:
        svm_sync_vmcb(v);
        memcpy(&vmcb->tr, reg, sizeof(*reg));
        svm_vmload(vmcb);
        break;
    case x86_seg_gdtr:
        memcpy(&vmcb->gdtr, reg, sizeof(*reg));
        break;
    case x86_seg_idtr:
        memcpy(&vmcb->idtr, reg, sizeof(*reg));
        break;
    case x86_seg_ldtr:
        svm_sync_vmcb(v);
        memcpy(&vmcb->ldtr, reg, sizeof(*reg));
        svm_vmload(vmcb);
        break;
    default:
        BUG();
    }
}

/* Make sure that xen intercepts any FP accesses from current */
static void svm_stts(struct vcpu *v) 
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    /*
     * If the guest does not have TS enabled then we must cause and handle an 
     * exception on first use of the FPU. If the guest *does* have TS enabled 
     * then this is not necessary: no FPU activity can occur until the guest 
     * clears CR0.TS, and we will initialise the FPU when that happens.
     */
    if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
    {
        v->arch.hvm_svm.vmcb->exception_intercepts |= 1U << TRAP_no_device;
        vmcb->cr0 |= X86_CR0_TS;
    }
}


static void svm_set_tsc_offset(struct vcpu *v, u64 offset)
{
    v->arch.hvm_svm.vmcb->tsc_offset = offset;
}


static void svm_init_ap_context(
    struct vcpu_guest_context *ctxt, int vcpuid, int trampoline_vector)
{
    struct vcpu *v;
    struct vmcb_struct *vmcb;
    cpu_user_regs_t *regs;
    u16 cs_sel;

    /* We know this is safe because hvm_bringup_ap() does it */
    v = current->domain->vcpu[vcpuid];
    vmcb = v->arch.hvm_svm.vmcb;
    regs = &v->arch.guest_context.user_regs;

    memset(ctxt, 0, sizeof(*ctxt));

    /*
     * We execute the trampoline code in real mode. The trampoline vector
     * passed to us is page alligned and is the physical frame number for
     * the code. We will execute this code in real mode.
     */
    cs_sel = trampoline_vector << 8;
    ctxt->user_regs.eip = 0x0;
    ctxt->user_regs.cs = cs_sel;

    /*
     * This is the launch of an AP; set state so that we begin executing
     * the trampoline code in real-mode.
     */
    svm_reset_to_realmode(v, regs);  
    /* Adjust the vmcb's hidden register state. */
    vmcb->cs.sel = cs_sel;
    vmcb->cs.base = (cs_sel << 4);
}

static void svm_init_hypercall_page(struct domain *d, void *hypercall_page)
{
    char *p;
    int i;

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p + 0) = 0xb8; /* mov imm32, %eax */
        *(u32 *)(p + 1) = i;
        *(u8  *)(p + 5) = 0x0f; /* vmmcall */
        *(u8  *)(p + 6) = 0x01;
        *(u8  *)(p + 7) = 0xd9;
        *(u8  *)(p + 8) = 0xc3; /* ret */
    }

    /* Don't support HYPERVISOR_iret at the moment */
    *(u16 *)(hypercall_page + (__HYPERVISOR_iret * 32)) = 0x0b0f; /* ud2 */
}

static void svm_ctxt_switch_from(struct vcpu *v)
{
    int cpu = smp_processor_id();

    svm_save_dr(v);

    svm_sync_vmcb(v);
    svm_vmload(root_vmcb[cpu]);

#ifdef __x86_64__
    /* Resume use of ISTs now that the host TR is reinstated. */
    idt_tables[cpu][TRAP_double_fault].a  |= IST_DF << 32;
    idt_tables[cpu][TRAP_nmi].a           |= IST_NMI << 32;
    idt_tables[cpu][TRAP_machine_check].a |= IST_MCE << 32;
#endif
}

static void svm_ctxt_switch_to(struct vcpu *v)
{
    int cpu = smp_processor_id();

#ifdef  __x86_64__
    /* 
     * This is required, because VMRUN does consistency check
     * and some of the DOM0 selectors are pointing to 
     * invalid GDT locations, and cause AMD processors
     * to shutdown.
     */
    set_segment_register(ds, 0);
    set_segment_register(es, 0);
    set_segment_register(ss, 0);

    /*
     * Cannot use ISTs for NMI/#MC/#DF while we are running with the guest TR.
     * But this doesn't matter: the IST is only req'd to handle SYSCALL/SYSRET.
     */
    idt_tables[cpu][TRAP_double_fault].a  &= ~(7UL << 32);
    idt_tables[cpu][TRAP_nmi].a           &= ~(7UL << 32);
    idt_tables[cpu][TRAP_machine_check].a &= ~(7UL << 32);
#endif

    svm_restore_dr(v);

    svm_vmsave(root_vmcb[cpu]);
    svm_vmload(v->arch.hvm_svm.vmcb);
}

static void svm_do_resume(struct vcpu *v) 
{
    bool_t debug_state = v->domain->debugger_attached;

    if ( unlikely(v->arch.hvm_vcpu.debug_state_latch != debug_state) )
    {
        uint32_t mask = (1U << TRAP_debug) | (1U << TRAP_int3);
        v->arch.hvm_vcpu.debug_state_latch = debug_state;
        if ( debug_state )
            v->arch.hvm_svm.vmcb->exception_intercepts |= mask;
        else
            v->arch.hvm_svm.vmcb->exception_intercepts &= ~mask;
    }

    if ( v->arch.hvm_svm.launch_core != smp_processor_id() )
    {
        v->arch.hvm_svm.launch_core = smp_processor_id();
        hvm_migrate_timers(v);

        /* Migrating to another ASID domain.  Request a new ASID. */
        svm_asid_init_vcpu(v);
    }

    hvm_do_resume(v);
    reset_stack_and_jump(svm_asm_do_resume);
}

static int svm_domain_initialise(struct domain *d)
{
    return 0;
}

static void svm_domain_destroy(struct domain *d)
{
}

static int svm_vcpu_initialise(struct vcpu *v)
{
    int rc;

    v->arch.schedule_tail    = svm_do_resume;
    v->arch.ctxt_switch_from = svm_ctxt_switch_from;
    v->arch.ctxt_switch_to   = svm_ctxt_switch_to;

    v->arch.hvm_svm.launch_core = -1;

    if ( (rc = svm_create_vmcb(v)) != 0 )
    {
        dprintk(XENLOG_WARNING,
                "Failed to create VMCB for vcpu %d: err=%d.\n",
                v->vcpu_id, rc);
        return rc;
    }

    return 0;
}

static void svm_vcpu_destroy(struct vcpu *v)
{
    svm_destroy_vmcb(v);
}

static void svm_hvm_inject_exception(
    unsigned int trapnr, int errcode, unsigned long cr2)
{
    struct vcpu *v = current;
    if ( trapnr == TRAP_page_fault )
        v->arch.hvm_svm.vmcb->cr2 = v->arch.hvm_vcpu.guest_cr[2] = cr2;
    svm_inject_exception(v, trapnr, (errcode != -1), errcode);
}

static int svm_event_pending(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    return vmcb->eventinj.fields.v;
}

static struct hvm_function_table svm_function_table = {
    .name                 = "SVM",
    .cpu_down             = svm_cpu_down,
    .domain_initialise    = svm_domain_initialise,
    .domain_destroy       = svm_domain_destroy,
    .vcpu_initialise      = svm_vcpu_initialise,
    .vcpu_destroy         = svm_vcpu_destroy,
    .save_cpu_ctxt        = svm_save_vmcb_ctxt,
    .load_cpu_ctxt        = svm_load_vmcb_ctxt,
    .interrupt_blocked    = svm_interrupt_blocked,
    .guest_x86_mode       = svm_guest_x86_mode,
    .get_segment_base     = svm_get_segment_base,
    .get_segment_register = svm_get_segment_register,
    .set_segment_register = svm_set_segment_register,
    .update_host_cr3      = svm_update_host_cr3,
    .update_guest_cr      = svm_update_guest_cr,
    .update_guest_efer    = svm_update_guest_efer,
    .flush_guest_tlbs     = svm_flush_guest_tlbs,
    .update_vtpr          = svm_update_vtpr,
    .stts                 = svm_stts,
    .set_tsc_offset       = svm_set_tsc_offset,
    .inject_exception     = svm_hvm_inject_exception,
    .init_ap_context      = svm_init_ap_context,
    .init_hypercall_page  = svm_init_hypercall_page,
    .event_pending        = svm_event_pending
};

int start_svm(struct cpuinfo_x86 *c)
{
    u32 eax, ecx, edx;
    u32 phys_hsa_lo, phys_hsa_hi;   
    u64 phys_hsa;
    int cpu = smp_processor_id();
 
    /* Xen does not fill x86_capability words except 0. */
    ecx = cpuid_ecx(0x80000001);
    boot_cpu_data.x86_capability[5] = ecx;
    
    if ( !(test_bit(X86_FEATURE_SVME, &boot_cpu_data.x86_capability)) )
        return 0;

    /* Check whether SVM feature is disabled in BIOS */
    rdmsr(MSR_K8_VM_CR, eax, edx);
    if ( eax & K8_VMCR_SVME_DISABLE )
    {
        printk("AMD SVM Extension is disabled in BIOS.\n");
        return 0;
    }

    if ( ((hsa[cpu] = alloc_host_save_area()) == NULL) ||
         ((root_vmcb[cpu] = alloc_vmcb()) == NULL) )
        return 0;

    write_efer(read_efer() | EFER_SVME);

    /* Initialize the HSA for this core. */
    phys_hsa = (u64) virt_to_maddr(hsa[cpu]);
    phys_hsa_lo = (u32) phys_hsa;
    phys_hsa_hi = (u32) (phys_hsa >> 32);    
    wrmsr(MSR_K8_VM_HSAVE_PA, phys_hsa_lo, phys_hsa_hi);

    /* Initialize core's ASID handling. */
    svm_asid_init(c);

    if ( cpu != 0 )
        return 1;

    setup_vmcb_dump();

    svm_feature_flags = ((cpuid_eax(0x80000000) >= 0x8000000A) ?
                         cpuid_edx(0x8000000A) : 0);

    svm_function_table.hap_supported = cpu_has_svm_npt;

    hvm_enable(&svm_function_table);

    return 1;
}

static void svm_do_nested_pgfault(paddr_t gpa, struct cpu_user_regs *regs)
{
    p2m_type_t p2mt;
    mfn_t mfn;
    unsigned long gfn = gpa >> PAGE_SHIFT;

    /* If this GFN is emulated MMIO, pass the fault to the mmio handler */
    mfn = gfn_to_mfn_current(gfn, &p2mt);
    if ( p2mt == p2m_mmio_dm )
    {
        handle_mmio(gpa);
        return;
    }

    /* Log-dirty: mark the page dirty and let the guest write it again */
    paging_mark_dirty(current->domain, mfn_x(mfn));
    p2m_change_type(current->domain, gfn, p2m_ram_logdirty, p2m_ram_rw);
}

static void svm_do_no_device_fault(struct vmcb_struct *vmcb)
{
    struct vcpu *v = current;

    setup_fpu(v);    
    vmcb->exception_intercepts &= ~(1U << TRAP_no_device);

    if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
        vmcb->cr0 &= ~X86_CR0_TS;
}

/* Reserved bits ECX: [31:14], [12:4], [2:1]*/
#define SVM_VCPU_CPUID_L1_ECX_RESERVED 0xffffdff6
/* Reserved bits EDX: [31:29], [27], [22:20], [18], [10] */
#define SVM_VCPU_CPUID_L1_EDX_RESERVED 0xe8740400

static void svm_vmexit_do_cpuid(struct vmcb_struct *vmcb,
                                struct cpu_user_regs *regs)
{
    unsigned long input = regs->eax;
    unsigned int eax, ebx, ecx, edx;
    struct vcpu *v = current;
    int inst_len;

    hvm_cpuid(input, &eax, &ebx, &ecx, &edx);

    switch ( input )
    {
    case 0x00000001:
        /* Clear out reserved bits. */
        ecx &= ~SVM_VCPU_CPUID_L1_ECX_RESERVED;
        edx &= ~SVM_VCPU_CPUID_L1_EDX_RESERVED;

        /* Guest should only see one logical processor.
         * See details on page 23 of AMD CPUID Specification.
         */
        __clear_bit(X86_FEATURE_HT & 31, &edx);
        ebx &= 0xFF00FFFF;  /* clear the logical processor count when HTT=0 */
        ebx |= 0x00010000;  /* set to 1 just for precaution */
        break;

    case 0x80000001:
        if ( vlapic_hw_disabled(vcpu_vlapic(v)) )
            __clear_bit(X86_FEATURE_APIC & 31, &edx);

#if CONFIG_PAGING_LEVELS >= 3
        if ( !v->domain->arch.hvm_domain.params[HVM_PARAM_PAE_ENABLED] )
#endif
            __clear_bit(X86_FEATURE_PAE & 31, &edx);

        __clear_bit(X86_FEATURE_PSE36 & 31, &edx);

        /* Clear the Cmp_Legacy bit
         * This bit is supposed to be zero when HTT = 0.
         * See details on page 23 of AMD CPUID Specification.
         */
        __clear_bit(X86_FEATURE_CMP_LEGACY & 31, &ecx);

        /* Make SVM feature invisible to the guest. */
        __clear_bit(X86_FEATURE_SVME & 31, &ecx);
        __clear_bit(X86_FEATURE_SKINIT & 31, &ecx);

        __clear_bit(X86_FEATURE_OSVW & 31, &ecx);
        __clear_bit(X86_FEATURE_WDT & 31, &ecx);

        /* So far, we do not support 3DNow for the guest. */
        __clear_bit(X86_FEATURE_3DNOW & 31, &edx);
        __clear_bit(X86_FEATURE_3DNOWEXT & 31, &edx);
        break;

    case 0x80000007:
    case 0x8000000A:
        /* Mask out features of power management and SVM extension. */
        eax = ebx = ecx = edx = 0;
        break;

    case 0x80000008:
        /* Make sure Number of CPU core is 1 when HTT=0 */
        ecx &= 0xFFFFFF00;
        break;
    }

    regs->eax = eax;
    regs->ebx = ebx;
    regs->ecx = ecx;
    regs->edx = edx;

    HVMTRACE_3D(CPUID, v, input,
                ((uint64_t)eax << 32) | ebx, ((uint64_t)ecx << 32) | edx);

    inst_len = __get_instruction_length(v, INSTR_CPUID, NULL);
    ASSERT(inst_len > 0);
    __update_guest_eip(regs, inst_len);
}

static unsigned long *get_reg_p(
    unsigned int gpreg, 
    struct cpu_user_regs *regs, struct vmcb_struct *vmcb)
{
    unsigned long *reg_p = NULL;
    switch (gpreg)
    {
    case SVM_REG_EAX:
        reg_p = (unsigned long *)&regs->eax;
        break;
    case SVM_REG_EBX:
        reg_p = (unsigned long *)&regs->ebx;
        break;
    case SVM_REG_ECX:
        reg_p = (unsigned long *)&regs->ecx;
        break;
    case SVM_REG_EDX:
        reg_p = (unsigned long *)&regs->edx;
        break;
    case SVM_REG_EDI:
        reg_p = (unsigned long *)&regs->edi;
        break;
    case SVM_REG_ESI:
        reg_p = (unsigned long *)&regs->esi;
        break;
    case SVM_REG_EBP:
        reg_p = (unsigned long *)&regs->ebp;
        break;
    case SVM_REG_ESP:
        reg_p = (unsigned long *)&regs->esp;
        break;
#ifdef __x86_64__
    case SVM_REG_R8:
        reg_p = (unsigned long *)&regs->r8;
        break;
    case SVM_REG_R9:
        reg_p = (unsigned long *)&regs->r9;
        break;
    case SVM_REG_R10:
        reg_p = (unsigned long *)&regs->r10;
        break;
    case SVM_REG_R11:
        reg_p = (unsigned long *)&regs->r11;
        break;
    case SVM_REG_R12:
        reg_p = (unsigned long *)&regs->r12;
        break;
    case SVM_REG_R13:
        reg_p = (unsigned long *)&regs->r13;
        break;
    case SVM_REG_R14:
        reg_p = (unsigned long *)&regs->r14;
        break;
    case SVM_REG_R15:
        reg_p = (unsigned long *)&regs->r15;
        break;
#endif
    default:
        BUG();
    } 
    
    return reg_p;
}


static unsigned long get_reg(
    unsigned int gpreg, struct cpu_user_regs *regs, struct vmcb_struct *vmcb)
{
    unsigned long *gp;
    gp = get_reg_p(gpreg, regs, vmcb);
    return *gp;
}


static void set_reg(
    unsigned int gpreg, unsigned long value, 
    struct cpu_user_regs *regs, struct vmcb_struct *vmcb)
{
    unsigned long *gp;
    gp = get_reg_p(gpreg, regs, vmcb);
    *gp = value;
}
                           

static void svm_dr_access(struct vcpu *v, struct cpu_user_regs *regs)
{
    HVMTRACE_0D(DR_WRITE, v);
    __restore_debug_registers(v);
}


static void svm_get_prefix_info(struct vcpu *v, unsigned int dir, 
                                svm_segment_register_t **seg, 
                                unsigned int *asize)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned char inst[MAX_INST_LEN];
    int i;

    memset(inst, 0, MAX_INST_LEN);
    if (inst_copy_from_guest(inst, svm_rip2pointer(v), sizeof(inst)) 
        != MAX_INST_LEN) 
    {
        gdprintk(XENLOG_ERR, "get guest instruction failed\n");
        domain_crash(current->domain);
        return;
    }

    for (i = 0; i < MAX_INST_LEN; i++)
    {
        switch (inst[i])
        {
        case 0xf3: /* REPZ */
        case 0xf2: /* REPNZ */
        case 0xf0: /* LOCK */
        case 0x66: /* data32 */
#ifdef __x86_64__
            /* REX prefixes */
        case 0x40:
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:

        case 0x48:
        case 0x49:
        case 0x4a:
        case 0x4b:
        case 0x4c:
        case 0x4d:
        case 0x4e:
        case 0x4f:
#endif
            continue;
        case 0x67: /* addr32 */
            *asize ^= 48;        /* Switch 16/32 bits */
            continue;
        case 0x2e: /* CS */
            *seg = &vmcb->cs;
            continue;
        case 0x36: /* SS */
            *seg = &vmcb->ss;
            continue;
        case 0x26: /* ES */
            *seg = &vmcb->es;
            continue;
        case 0x64: /* FS */
            svm_sync_vmcb(v);
            *seg = &vmcb->fs;
            continue;
        case 0x65: /* GS */
            svm_sync_vmcb(v);
            *seg = &vmcb->gs;
            continue;
        case 0x3e: /* DS */
            *seg = &vmcb->ds;
            continue;
        default:
            break;
        }
        return;
    }
}


/* Get the address of INS/OUTS instruction */
static int svm_get_io_address(
    struct vcpu *v, struct cpu_user_regs *regs,
    unsigned int size, ioio_info_t info,
    unsigned long *count, unsigned long *addr)
{
    unsigned long        reg;
    unsigned int         asize, isize;
    int                  long_mode = 0;
    svm_segment_register_t *seg = NULL;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    /* If we're in long mode, don't check the segment presence & limit */
    long_mode = vmcb->cs.attr.fields.l && hvm_long_mode_enabled(v);

    /* d field of cs.attr is 1 for 32-bit, 0 for 16 or 64 bit. 
     * l field combined with EFER_LMA says whether it's 16 or 64 bit. 
     */
    asize = (long_mode)?64:((vmcb->cs.attr.fields.db)?32:16);


    /* The ins/outs instructions are single byte, so if we have got more 
     * than one byte (+ maybe rep-prefix), we have some prefix so we need 
     * to figure out what it is...
     */
    isize = vmcb->exitinfo2 - regs->eip;

    if (info.fields.rep)
        isize --;

    if (isize > 1) 
        svm_get_prefix_info(v, info.fields.type, &seg, &asize);

    if (info.fields.type == IOREQ_WRITE)
    {
        reg = regs->esi;
        if (!seg)               /* If no prefix, used DS. */
            seg = &vmcb->ds;
        if (!long_mode && (seg->attr.fields.type & 0xa) == 0x8) {
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            return 0;
        }
    }
    else
    {
        reg = regs->edi;
        seg = &vmcb->es;        /* Note: This is ALWAYS ES. */
        if (!long_mode && (seg->attr.fields.type & 0xa) != 0x2) {
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            return 0;
        }
    }

    /* If the segment isn't present, give GP fault! */
    if (!long_mode && !seg->attr.fields.p) 
    {
        svm_inject_exception(v, TRAP_gp_fault, 1, 0);
        return 0;
    }

    if (asize == 16) 
    {
        *addr = (reg & 0xFFFF);
        *count = regs->ecx & 0xffff;
    }
    else
    {
        *addr = reg;
        *count = regs->ecx;
    }
    if (!info.fields.rep)
        *count = 1;

    if (!long_mode)
    {
        ASSERT(*addr == (u32)*addr);
        if ((u32)(*addr + size - 1) < (u32)*addr ||
            (seg->attr.fields.type & 0xc) != 0x4 ?
            *addr + size - 1 > seg->limit :
            *addr <= seg->limit)
        {
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            return 0;
        }

        /* Check the limit for repeated instructions, as above we checked only
           the first instance. Truncate the count if a limit violation would
           occur. Note that the checking is not necessary for page granular
           segments as transfers crossing page boundaries will be broken up
           anyway. */
        if (!seg->attr.fields.g && *count > 1)
        {
            if ((seg->attr.fields.type & 0xc) != 0x4)
            {
                /* expand-up */
                if (!(regs->eflags & EF_DF))
                {
                    if (*addr + *count * size - 1 < *addr ||
                        *addr + *count * size - 1 > seg->limit)
                        *count = (seg->limit + 1UL - *addr) / size;
                }
                else
                {
                    if (*count - 1 > *addr / size)
                        *count = *addr / size + 1;
                }
            }
            else
            {
                /* expand-down */
                if (!(regs->eflags & EF_DF))
                {
                    if (*count - 1 > -(s32)*addr / size)
                        *count = -(s32)*addr / size + 1UL;
                }
                else
                {
                    if (*addr < (*count - 1) * size ||
                        *addr - (*count - 1) * size <= seg->limit)
                        *count = (*addr - seg->limit - 1) / size + 1;
                }
            }
            ASSERT(*count);
        }

        *addr += seg->base;
    }
#ifdef __x86_64__
    else
    {
        if (seg == &vmcb->fs || seg == &vmcb->gs)
            *addr += seg->base;

        if (!is_canonical_address(*addr) ||
            !is_canonical_address(*addr + size - 1))
        {
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            return 0;
        }
        if (*count > (1UL << 48) / size)
            *count = (1UL << 48) / size;
        if (!(regs->eflags & EF_DF))
        {
            if (*addr + *count * size - 1 < *addr ||
                !is_canonical_address(*addr + *count * size - 1))
                *count = (*addr & ~((1UL << 48) - 1)) / size;
        }
        else
        {
            if ((*count - 1) * size > *addr ||
                !is_canonical_address(*addr + (*count - 1) * size))
                *count = (*addr & ~((1UL << 48) - 1)) / size + 1;
        }
        ASSERT(*count);
    }
#endif

    return 1;
}


static void svm_io_instruction(struct vcpu *v)
{
    struct cpu_user_regs *regs;
    struct hvm_io_op *pio_opp;
    unsigned int port;
    unsigned int size, dir, df;
    ioio_info_t info;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    pio_opp = &current->arch.hvm_vcpu.io_op;
    pio_opp->instr = INSTR_PIO;
    pio_opp->flags = 0;

    regs = &pio_opp->io_context;

    /* Copy current guest state into io instruction state structure. */
    memcpy(regs, guest_cpu_user_regs(), HVM_CONTEXT_STACK_BYTES);

    info.bytes = vmcb->exitinfo1;

    port = info.fields.port; /* port used to be addr */
    dir = info.fields.type; /* direction */ 
    df = regs->eflags & X86_EFLAGS_DF ? 1 : 0;

    if (info.fields.sz32) 
        size = 4;
    else if (info.fields.sz16)
        size = 2;
    else 
        size = 1;

    if (dir==IOREQ_READ)
        HVMTRACE_2D(IO_READ,  v, port, size);
    else
        HVMTRACE_3D(IO_WRITE, v, port, size, regs->eax);

    HVM_DBG_LOG(DBG_LEVEL_IO, 
                "svm_io_instruction: port 0x%x eip=%x:%"PRIx64", "
                "exit_qualification = %"PRIx64,
                port, vmcb->cs.sel, (uint64_t)regs->eip, info.bytes);

    /* string instruction */
    if (info.fields.str)
    { 
        unsigned long addr, count;
        paddr_t paddr;
        unsigned long gfn;
        int sign = regs->eflags & X86_EFLAGS_DF ? -1 : 1;

        if (!svm_get_io_address(v, regs, size, info, &count, &addr))
        {
            /* We failed to get a valid address, so don't do the IO operation -
             * it would just get worse if we do! Hopefully the guest is handing
             * gp-faults... 
             */
            return;
        }

        /* "rep" prefix */
        if (info.fields.rep) 
        {
            pio_opp->flags |= REPZ;
        }

        /* Translate the address to a physical address */
        gfn = paging_gva_to_gfn(v, addr);
        if ( gfn == INVALID_GFN ) 
        {
            /* The guest does not have the RAM address mapped. 
             * Need to send in a page fault */
            int errcode = 0;
            /* IO read --> memory write */
            if ( dir == IOREQ_READ ) errcode |= PFEC_write_access;
            svm_hvm_inject_exception(TRAP_page_fault, errcode, addr);
            return;
        }
        paddr = (paddr_t)gfn << PAGE_SHIFT | (addr & ~PAGE_MASK);

        /*
         * Handle string pio instructions that cross pages or that
         * are unaligned. See the comments in hvm_platform.c/handle_mmio()
         */
        if ((addr & PAGE_MASK) != ((addr + size - 1) & PAGE_MASK))
        {
            unsigned long value = 0;

            pio_opp->flags |= OVERLAP;
            pio_opp->addr = addr;

            if (dir == IOREQ_WRITE)   /* OUTS */
            {
                if ( hvm_paging_enabled(current) )
                {
                    int rv = hvm_copy_from_guest_virt(&value, addr, size);
                    if ( rv != 0 ) 
                    {
                        /* Failed on the page-spanning copy.  Inject PF into
                         * the guest for the address where we failed. */
                        addr += size - rv;
                        gdprintk(XENLOG_DEBUG, "Pagefault reading non-io side "
                                 "of a page-spanning PIO: va=%#lx\n", addr);
                        svm_hvm_inject_exception(TRAP_page_fault, 0, addr);
                        return;
                    }
                }
                else
                    (void) hvm_copy_from_guest_phys(&value, addr, size);
            } else /* dir != IOREQ_WRITE */
                /* Remember where to write the result, as a *VA*.
                 * Must be a VA so we can handle the page overlap 
                 * correctly in hvm_pio_assist() */
                pio_opp->addr = addr;

            if (count == 1)
                regs->eip = vmcb->exitinfo2;

            send_pio_req(port, 1, size, value, dir, df, 0);
        } 
        else 
        {
            unsigned long last_addr = sign > 0 ? addr + count * size - 1
                                               : addr - (count - 1) * size;

            if ((addr & PAGE_MASK) != (last_addr & PAGE_MASK))
            {
                if (sign > 0)
                    count = (PAGE_SIZE - (addr & ~PAGE_MASK)) / size;
                else
                    count = (addr & ~PAGE_MASK) / size + 1;
            }
            else    
                regs->eip = vmcb->exitinfo2;

            send_pio_req(port, count, size, paddr, dir, df, 1);
        }
    } 
    else 
    {
        /* 
         * On SVM, the RIP of the intruction following the IN/OUT is saved in
         * ExitInfo2
         */
        regs->eip = vmcb->exitinfo2;

        if (port == 0xe9 && dir == IOREQ_WRITE && size == 1) 
            hvm_print_line(v, regs->eax); /* guest debug output */
    
        send_pio_req(port, 1, size, regs->eax, dir, df, 0);
    }
}

static void mov_from_cr(int cr, int gp, struct cpu_user_regs *regs)
{
    unsigned long value = 0;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    switch ( cr )
    {
    case 0:
        value = v->arch.hvm_vcpu.guest_cr[0];
        break;
    case 3:
        value = (unsigned long)v->arch.hvm_vcpu.guest_cr[3];
        break;
    case 4:
        value = (unsigned long)v->arch.hvm_vcpu.guest_cr[4];
        break;
    default:
        gdprintk(XENLOG_ERR, "invalid cr: %d\n", cr);
        domain_crash(v->domain);
        return;
    }

    HVMTRACE_2D(CR_READ, v, cr, value);

    set_reg(gp, value, regs, vmcb);

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "mov_from_cr: CR%d, value = %lx", cr, value);
}

static int mov_to_cr(int gpreg, int cr, struct cpu_user_regs *regs)
{
    unsigned long value;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    value = get_reg(gpreg, regs, vmcb);

    HVMTRACE_2D(CR_WRITE, v, cr, value);

    HVM_DBG_LOG(DBG_LEVEL_1, "mov_to_cr: CR%d, value = %lx, current = %p",
                cr, value, v);

    switch ( cr )
    {
    case 0: 
        return hvm_set_cr0(value);
    case 3:
        return hvm_set_cr3(value);
    case 4:
        return hvm_set_cr4(value);
    default:
        gdprintk(XENLOG_ERR, "invalid cr: %d\n", cr);
        domain_crash(v->domain);
        return 0;
    }

    return 1;
}

static void svm_cr_access(
    struct vcpu *v, unsigned int cr, unsigned int type,
    struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int inst_len = 0;
    int index,addr_size,i;
    unsigned int gpreg,offset;
    unsigned long value,addr;
    u8 buffer[MAX_INST_LEN];   
    u8 prefix = 0;
    u8 modrm;
    enum x86_segment seg;
    int result = 1;
    enum instruction_index list_a[] = {INSTR_MOV2CR, INSTR_CLTS, INSTR_LMSW};
    enum instruction_index list_b[] = {INSTR_MOVCR2, INSTR_SMSW};
    enum instruction_index match;

    inst_copy_from_guest(buffer, svm_rip2pointer(v), sizeof(buffer));

    /* get index to first actual instruction byte - as we will need to know 
       where the prefix lives later on */
    index = skip_prefix_bytes(buffer, sizeof(buffer));
    
    if ( type == TYPE_MOV_TO_CR )
    {
        inst_len = __get_instruction_length_from_list(
            v, list_a, ARRAY_SIZE(list_a), &buffer[index], &match);
    }
    else /* type == TYPE_MOV_FROM_CR */
    {
        inst_len = __get_instruction_length_from_list(
            v, list_b, ARRAY_SIZE(list_b), &buffer[index], &match);
    }

    ASSERT(inst_len > 0);

    inst_len += index;

    /* Check for REX prefix - it's ALWAYS the last byte of any prefix bytes */
    if (index > 0 && (buffer[index-1] & 0xF0) == 0x40)
        prefix = buffer[index-1];

    HVM_DBG_LOG(DBG_LEVEL_1, "eip = %lx", (unsigned long)regs->eip);

    switch ( match )

    {
    case INSTR_MOV2CR:
        gpreg = decode_src_reg(prefix, buffer[index+2]);
        result = mov_to_cr(gpreg, cr, regs);
        break;

    case INSTR_MOVCR2:
        gpreg = decode_src_reg(prefix, buffer[index+2]);
        mov_from_cr(cr, gpreg, regs);
        break;

    case INSTR_CLTS:
        /* TS being cleared means that it's time to restore fpu state. */
        setup_fpu(current);
        vmcb->exception_intercepts &= ~(1U << TRAP_no_device);
        vmcb->cr0 &= ~X86_CR0_TS; /* clear TS */
        v->arch.hvm_vcpu.guest_cr[0] &= ~X86_CR0_TS; /* clear TS */
        HVMTRACE_0D(CLTS, current);
        break;

    case INSTR_LMSW:
        gpreg = decode_src_reg(prefix, buffer[index+2]);
        value = get_reg(gpreg, regs, vmcb) & 0xF;
        value = (v->arch.hvm_vcpu.guest_cr[0] & ~0xF) | value;
        result = hvm_set_cr0(value);
        HVMTRACE_1D(LMSW, current, value);
        break;

    case INSTR_SMSW:
        value = v->arch.hvm_vcpu.guest_cr[0] & 0xFFFF;
        modrm = buffer[index+2];
        addr_size = svm_guest_x86_mode(v);
        if ( addr_size < 2 )
            addr_size = 2;
        if ( likely((modrm & 0xC0) >> 6 == 3) )
        {
            gpreg = decode_src_reg(prefix, modrm);
            set_reg(gpreg, value, regs, vmcb);
        }
        /*
         * For now, only implement decode of the offset mode, since that's the
         * only mode observed in a real-world OS. This code is also making the
         * assumption that we'll never hit this code in long mode.
         */
        else if ( (modrm == 0x26) || (modrm == 0x25) )
        {   
            seg = x86_seg_ds;
            i = index;
            /* Segment or address size overrides? */
            while ( i-- )
            {
                switch ( buffer[i] )
                {
                   case 0x26: seg = x86_seg_es; break;
                   case 0x2e: seg = x86_seg_cs; break;
                   case 0x36: seg = x86_seg_ss; break;
                   case 0x64: seg = x86_seg_fs; break;
                   case 0x65: seg = x86_seg_gs; break;
                   case 0x67: addr_size ^= 6;   break;
                }
            }
            /* Bail unless this really is a seg_base + offset case */
            if ( ((modrm == 0x26) && (addr_size == 4)) ||
                 ((modrm == 0x25) && (addr_size == 2)) )
            {
                gdprintk(XENLOG_ERR, "SMSW emulation at guest address: "
                         "%lx failed due to unhandled addressing mode."
                         "ModRM byte was: %x \n", svm_rip2pointer(v), modrm);
                domain_crash(v->domain);
            }
            inst_len += addr_size;
            offset = *(( unsigned int *) ( void *) &buffer[index + 3]);
            offset = ( addr_size == 4 ) ? offset : ( offset & 0xFFFF );
            addr = hvm_get_segment_base(v, seg);
            addr += offset;
            hvm_copy_to_guest_virt(addr,&value,2);
        }
        else
        {
           gdprintk(XENLOG_ERR, "SMSW emulation at guest address: %lx "
                    "failed due to unhandled addressing mode!"
                    "ModRM byte was: %x \n", svm_rip2pointer(v), modrm);
           domain_crash(v->domain);
        }
        break;

    default:
        BUG();
    }

    ASSERT(inst_len);

    if ( result )
        __update_guest_eip(regs, inst_len);
}

static void svm_do_msr_access(
    struct vcpu *v, struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int  inst_len;
    u64 msr_content=0;
    u32 ecx = regs->ecx, eax, edx;

    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x, eax=%x, edx=%x, exitinfo = %lx",
                ecx, (u32)regs->eax, (u32)regs->edx,
                (unsigned long)vmcb->exitinfo1);

    /* is it a read? */
    if (vmcb->exitinfo1 == 0)
    {
        switch (ecx) {
        case MSR_IA32_TSC:
            msr_content = hvm_get_guest_time(v);
            break;

        case MSR_IA32_APICBASE:
            msr_content = vcpu_vlapic(v)->hw.apic_base_msr;
            break;

        case MSR_EFER:
            msr_content = v->arch.hvm_vcpu.guest_efer;
            break;

        case MSR_IA32_MC4_MISC: /* Threshold register */
            /*
             * MCA/MCE: We report that the threshold register is unavailable
             * for OS use (locked by the BIOS).
             */
            msr_content = 1ULL << 61; /* MC4_MISC.Locked */
            break;

        case MSR_IA32_EBC_FREQUENCY_ID:
            /*
             * This Intel-only register may be accessed if this HVM guest
             * has been migrated from an Intel host. The value zero is not
             * particularly meaningful, but at least avoids the guest crashing!
             */
            msr_content = 0;
            break;

        case MSR_K8_VM_HSAVE_PA:
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            break;

        case MSR_IA32_MCG_CAP:
        case MSR_IA32_MCG_STATUS:
        case MSR_IA32_MC0_STATUS:
        case MSR_IA32_MC1_STATUS:
        case MSR_IA32_MC2_STATUS:
        case MSR_IA32_MC3_STATUS:
        case MSR_IA32_MC4_STATUS:
        case MSR_IA32_MC5_STATUS:
            /* No point in letting the guest see real MCEs */
            msr_content = 0;
            break;

        case MSR_IA32_DEBUGCTLMSR:
            msr_content = vmcb->debugctlmsr;
            break;

        case MSR_IA32_LASTBRANCHFROMIP:
            msr_content = vmcb->lastbranchfromip;
            break;

        case MSR_IA32_LASTBRANCHTOIP:
            msr_content = vmcb->lastbranchtoip;
            break;

        case MSR_IA32_LASTINTFROMIP:
            msr_content = vmcb->lastintfromip;
            break;

        case MSR_IA32_LASTINTTOIP:
            msr_content = vmcb->lastinttoip;
            break;

        default:
            if ( rdmsr_hypervisor_regs(ecx, &eax, &edx) ||
                 rdmsr_safe(ecx, eax, edx) == 0 )
            {
                regs->eax = eax;
                regs->edx = edx;
                goto done;
            }
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            return;
        }
        regs->eax = msr_content & 0xFFFFFFFF;
        regs->edx = msr_content >> 32;

 done:
        hvmtrace_msr_read(v, ecx, msr_content);
        HVM_DBG_LOG(DBG_LEVEL_1, "returns: ecx=%x, eax=%lx, edx=%lx",
                    ecx, (unsigned long)regs->eax, (unsigned long)regs->edx);

        inst_len = __get_instruction_length(v, INSTR_RDMSR, NULL);
    }
    else
    {
        msr_content = (u32)regs->eax | ((u64)regs->edx << 32);

        hvmtrace_msr_write(v, ecx, msr_content);

        switch (ecx)
        {
        case MSR_IA32_TSC:
            hvm_set_guest_time(v, msr_content);
            pt_reset(v);
            break;

        case MSR_IA32_APICBASE:
            vlapic_msr_set(vcpu_vlapic(v), msr_content);
            break;

        case MSR_K8_VM_HSAVE_PA:
            svm_inject_exception(v, TRAP_gp_fault, 1, 0);
            break;

        case MSR_IA32_DEBUGCTLMSR:
            vmcb->debugctlmsr = msr_content;
            if ( !msr_content || !cpu_has_svm_lbrv )
                break;
            vmcb->lbr_control.fields.enable = 1;
            svm_disable_intercept_for_msr(v, MSR_IA32_DEBUGCTLMSR);
            svm_disable_intercept_for_msr(v, MSR_IA32_LASTBRANCHFROMIP);
            svm_disable_intercept_for_msr(v, MSR_IA32_LASTBRANCHTOIP);
            svm_disable_intercept_for_msr(v, MSR_IA32_LASTINTFROMIP);
            svm_disable_intercept_for_msr(v, MSR_IA32_LASTINTTOIP);
            break;

        case MSR_IA32_LASTBRANCHFROMIP:
            vmcb->lastbranchfromip = msr_content;
            break;

        case MSR_IA32_LASTBRANCHTOIP:
            vmcb->lastbranchtoip = msr_content;
            break;

        case MSR_IA32_LASTINTFROMIP:
            vmcb->lastintfromip = msr_content;
            break;

        case MSR_IA32_LASTINTTOIP:
            vmcb->lastinttoip = msr_content;
            break;

        default:
            switch ( long_mode_do_msr_write(regs) )
            {
            case HNDL_unhandled:
                wrmsr_hypervisor_regs(ecx, regs->eax, regs->edx);
                break;
            case HNDL_exception_raised:
                return;
            case HNDL_done:
                break;
            }
            break;
        }

        inst_len = __get_instruction_length(v, INSTR_WRMSR, NULL);
    }

    __update_guest_eip(regs, inst_len);
}

static void svm_vmexit_do_hlt(struct vmcb_struct *vmcb,
                              struct cpu_user_regs *regs)
{
    struct hvm_intack intack = hvm_vcpu_has_pending_irq(current);

    __update_guest_eip(regs, 1);

    /* Check for interrupt not handled or new interrupt. */
    if ( vmcb->eventinj.fields.v ||
         ((intack.source != hvm_intsrc_none) &&
          !svm_interrupt_blocked(current, intack)) )
    {
        HVMTRACE_1D(HLT, current, /*int pending=*/ 1);
        return;
    }

    HVMTRACE_1D(HLT, current, /*int pending=*/ 0);
    hvm_hlt(regs->eflags);
}

static void svm_vmexit_do_invd(struct cpu_user_regs *regs)
{
    int inst_len;
    
    /* Invalidate the cache - we can't really do that safely - maybe we should 
     * WBINVD, but I think it's just fine to completely ignore it - we should 
     * have cache-snooping that solves it anyways. -- Mats P. 
     */

    /* Tell the user that we did this - just in case someone runs some really 
     * weird operating system and wants to know why it's not working...
     */
    gdprintk(XENLOG_WARNING, "INVD instruction intercepted - ignored\n");
    
    inst_len = __get_instruction_length(current, INSTR_INVD, NULL);
    __update_guest_eip(regs, inst_len);
}    
        
void svm_handle_invlpg(const short invlpga, struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    u8 opcode[MAX_INST_LEN], prefix, length = MAX_INST_LEN;
    unsigned long g_vaddr;
    int inst_len;

    /* 
     * Unknown how many bytes the invlpg instruction will take.  Use the
     * maximum instruction length here
     */
    if (inst_copy_from_guest(opcode, svm_rip2pointer(v), length) < length)
    {
        gdprintk(XENLOG_ERR, "Error reading memory %d bytes\n", length);
        domain_crash(v->domain);
        return;
    }

    if (invlpga)
    {
        inst_len = __get_instruction_length(v, INSTR_INVLPGA, opcode);
        ASSERT(inst_len > 0);
        __update_guest_eip(regs, inst_len);

        /* 
         * The address is implicit on this instruction. At the moment, we don't
         * use ecx (ASID) to identify individual guests pages 
         */
        g_vaddr = regs->eax;
    }
    else
    {
        /* What about multiple prefix codes? */
        prefix = (is_prefix(opcode[0])?opcode[0]:0);
        inst_len = __get_instruction_length(v, INSTR_INVLPG, opcode);
        ASSERT(inst_len > 0);

        inst_len--;
        length -= inst_len;

        /* 
         * Decode memory operand of the instruction including ModRM, SIB, and
         * displacement to get effective address and length in bytes.  Assume
         * the system in either 32- or 64-bit mode.
         */
        g_vaddr = get_effective_addr_modrm64(regs, prefix, inst_len,
                                             &opcode[inst_len], &length);

        inst_len += length;
        __update_guest_eip(regs, inst_len);
    }

    HVMTRACE_3D(INVLPG, v, (invlpga?1:0), g_vaddr, (invlpga?regs->ecx:0));

    paging_invlpg(v, g_vaddr);
    svm_asid_g_invlpg(v, g_vaddr);
}


/*
 * Reset to realmode causes execution to start at 0xF000:0xFFF0 in
 * 16-bit realmode.  Basically, this mimics a processor reset.
 *
 * returns 0 on success, non-zero otherwise
 */
static int svm_reset_to_realmode(struct vcpu *v, 
                                 struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    memset(regs, 0, sizeof(struct cpu_user_regs));

    regs->eflags = 2;

    v->arch.hvm_vcpu.guest_cr[0] = X86_CR0_ET;
    svm_update_guest_cr(v, 0);

    v->arch.hvm_vcpu.guest_cr[2] = 0;
    svm_update_guest_cr(v, 2);

    v->arch.hvm_vcpu.guest_cr[4] = 0;
    svm_update_guest_cr(v, 4);

    vmcb->efer = EFER_SVME;

    /* This will jump to ROMBIOS */
    regs->eip = 0xFFF0;

    /* Set up the segment registers and all their hidden states. */
    vmcb->cs.sel = 0xF000;
    vmcb->cs.attr.bytes = 0x089b;
    vmcb->cs.limit = 0xffff;
    vmcb->cs.base = 0x000F0000;

    vmcb->ss.sel = 0x00;
    vmcb->ss.attr.bytes = 0x0893;
    vmcb->ss.limit = 0xffff;
    vmcb->ss.base = 0x00;

    vmcb->ds.sel = 0x00;
    vmcb->ds.attr.bytes = 0x0893;
    vmcb->ds.limit = 0xffff;
    vmcb->ds.base = 0x00;
    
    vmcb->es.sel = 0x00;
    vmcb->es.attr.bytes = 0x0893;
    vmcb->es.limit = 0xffff;
    vmcb->es.base = 0x00;
    
    vmcb->fs.sel = 0x00;
    vmcb->fs.attr.bytes = 0x0893;
    vmcb->fs.limit = 0xffff;
    vmcb->fs.base = 0x00;
    
    vmcb->gs.sel = 0x00;
    vmcb->gs.attr.bytes = 0x0893;
    vmcb->gs.limit = 0xffff;
    vmcb->gs.base = 0x00;

    vmcb->ldtr.sel = 0x00;
    vmcb->ldtr.attr.bytes = 0x0000;
    vmcb->ldtr.limit = 0x0;
    vmcb->ldtr.base = 0x00;

    vmcb->gdtr.sel = 0x00;
    vmcb->gdtr.attr.bytes = 0x0000;
    vmcb->gdtr.limit = 0x0;
    vmcb->gdtr.base = 0x00;
    
    vmcb->tr.sel = 0;
    vmcb->tr.attr.bytes = 0;
    vmcb->tr.limit = 0x0;
    vmcb->tr.base = 0;

    vmcb->idtr.sel = 0x00;
    vmcb->idtr.attr.bytes = 0x0000;
    vmcb->idtr.limit = 0x3ff;
    vmcb->idtr.base = 0x00;

    return 0;
}

asmlinkage void svm_vmexit_handler(struct cpu_user_regs *regs)
{
    unsigned int exit_reason;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    eventinj_t eventinj;
    int inst_len, rc;

    /*
     * Before doing anything else, we need to sync up the VLAPIC's TPR with
     * SVM's vTPR. It's OK if the guest doesn't touch CR8 (e.g. 32-bit Windows)
     * because we update the vTPR on MMIO writes to the TPR.
     */
    vlapic_set_reg(vcpu_vlapic(v), APIC_TASKPRI,
                   (vmcb->vintr.fields.tpr & 0x0F) << 4);

    exit_reason = vmcb->exitcode;

    hvmtrace_vmexit(v, regs->eip, exit_reason);

    if ( unlikely(exit_reason == VMEXIT_INVALID) )
    {
        svm_dump_vmcb(__func__, vmcb);
        goto exit_and_crash;
    }

    perfc_incra(svmexits, exit_reason);

    /* Event delivery caused this intercept? Queue for redelivery. */
    eventinj = vmcb->exitintinfo;
    if ( unlikely(eventinj.fields.v) &&
         hvm_event_needs_reinjection(eventinj.fields.type,
                                     eventinj.fields.vector) )
        vmcb->eventinj = eventinj;

    switch ( exit_reason )
    {
    case VMEXIT_INTR:
        /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
        HVMTRACE_0D(INTR, v);
        break;

    case VMEXIT_NMI:
        /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
        HVMTRACE_0D(NMI, v);
        break;

    case VMEXIT_SMI:
        /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
        HVMTRACE_0D(SMI, v);
        break;

    case VMEXIT_EXCEPTION_DB:
        if ( !v->domain->debugger_attached )
            goto exit_and_crash;
        domain_pause_for_debugger();
        break;

    case VMEXIT_EXCEPTION_BP:
        if ( !v->domain->debugger_attached )
            goto exit_and_crash;
        /* AMD Vol2, 15.11: INT3, INTO, BOUND intercepts do not update RIP. */
        inst_len = __get_instruction_length(v, INSTR_INT3, NULL);
        __update_guest_eip(regs, inst_len);
        domain_pause_for_debugger();
        break;

    case VMEXIT_EXCEPTION_NM:
        svm_do_no_device_fault(vmcb);
        break;  

    case VMEXIT_EXCEPTION_PF: {
        unsigned long va;
        va = vmcb->exitinfo2;
        regs->error_code = vmcb->exitinfo1;
        HVM_DBG_LOG(DBG_LEVEL_VMMU,
                    "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                    (unsigned long)regs->eax, (unsigned long)regs->ebx,
                    (unsigned long)regs->ecx, (unsigned long)regs->edx,
                    (unsigned long)regs->esi, (unsigned long)regs->edi);

        if ( paging_fault(va, regs) )
        {
            HVMTRACE_2D(PF_XEN, v, va, regs->error_code);
            break;
        }

        v->arch.hvm_vcpu.guest_cr[2] = vmcb->cr2 = va;
        svm_inject_exception(v, TRAP_page_fault, 1, regs->error_code);
        break;
    }

    /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
    case VMEXIT_EXCEPTION_MC:
        HVMTRACE_0D(MCE, v);
        break;

    case VMEXIT_VINTR:
        vmcb->vintr.fields.irq = 0;
        vmcb->general1_intercepts &= ~GENERAL1_INTERCEPT_VINTR;
        break;

    case VMEXIT_INVD:
        svm_vmexit_do_invd(regs);
        break;

    case VMEXIT_TASK_SWITCH: {
        enum hvm_task_switch_reason reason;
        int32_t errcode = -1;
        if ( (vmcb->exitinfo2 >> 36) & 1 )
            reason = TSW_iret;
        else if ( (vmcb->exitinfo2 >> 38) & 1 )
            reason = TSW_jmp;
        else
            reason = TSW_call_or_int;
        if ( (vmcb->exitinfo2 >> 44) & 1 )
            errcode = (uint32_t)vmcb->exitinfo2;
        hvm_task_switch((uint16_t)vmcb->exitinfo1, reason, errcode);
        break;
    }

    case VMEXIT_CPUID:
        svm_vmexit_do_cpuid(vmcb, regs);
        break;

    case VMEXIT_HLT:
        svm_vmexit_do_hlt(vmcb, regs);
        break;

    case VMEXIT_INVLPG:
        svm_handle_invlpg(0, regs);
        break;

    case VMEXIT_INVLPGA:
        svm_handle_invlpg(1, regs);
        break;

    case VMEXIT_VMMCALL:
        inst_len = __get_instruction_length(v, INSTR_VMCALL, NULL);
        ASSERT(inst_len > 0);
        HVMTRACE_1D(VMMCALL, v, regs->eax);
        rc = hvm_do_hypercall(regs);
        if ( rc != HVM_HCALL_preempted )
        {
            __update_guest_eip(regs, inst_len);
            if ( rc == HVM_HCALL_invalidate )
                send_invalidate_req();
        }
        break;

    case VMEXIT_CR0_READ ... VMEXIT_CR15_READ:
        svm_cr_access(v, exit_reason - VMEXIT_CR0_READ,
                      TYPE_MOV_FROM_CR, regs);
        break;

    case VMEXIT_CR0_WRITE ... VMEXIT_CR15_WRITE:
        svm_cr_access(v, exit_reason - VMEXIT_CR0_WRITE,
                      TYPE_MOV_TO_CR, regs);
        break;

    case VMEXIT_DR0_WRITE ... VMEXIT_DR7_WRITE:
        svm_dr_access(v, regs);
        break;

    case VMEXIT_IOIO:
        svm_io_instruction(v);
        break;

    case VMEXIT_MSR:
        svm_do_msr_access(v, regs);
        break;

    case VMEXIT_SHUTDOWN:
        hvm_triple_fault();
        break;

    case VMEXIT_VMRUN:
    case VMEXIT_VMLOAD:
    case VMEXIT_VMSAVE:
    case VMEXIT_STGI:
    case VMEXIT_CLGI:
    case VMEXIT_SKINIT:
        /* Report "Invalid opcode" on any VM-operation except VMMCALL */
        svm_inject_exception(v, TRAP_invalid_op, 0, 0);
        break;

    case VMEXIT_NPF:
        perfc_incra(svmexits, VMEXIT_NPF_PERFC);
        regs->error_code = vmcb->exitinfo1;
        svm_do_nested_pgfault(vmcb->exitinfo2, regs);
        break;

    default:
    exit_and_crash:
        gdprintk(XENLOG_ERR, "unexpected VMEXIT: exit reason = 0x%x, "
                 "exitinfo1 = %"PRIx64", exitinfo2 = %"PRIx64"\n",
                 exit_reason, 
                 (u64)vmcb->exitinfo1, (u64)vmcb->exitinfo2);
        domain_crash(v->domain);
        break;
    }
}

asmlinkage void svm_trace_vmentry(void)
{
    struct vcpu *v = current;

    /* This is the last C code before the VMRUN instruction. */
    hvmtrace_vmentry(v);
}
  
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
