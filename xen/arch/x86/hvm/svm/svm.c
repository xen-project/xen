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
 * this program; If not, see <http://www.gnu.org/licenses/>.
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
#include <xen/xenoprof.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/mem_sharing.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/amd.h>
#include <asm/guest_access.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/i387.h>
#include <asm/iocap.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/io.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/svm/asid.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/emulate.h>
#include <asm/hvm/svm/intr.h>
#include <asm/hvm/svm/svmdebug.h>
#include <asm/hvm/svm/nestedsvm.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/x86_emulate.h>
#include <public/sched.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/trace.h>
#include <asm/hap.h>
#include <asm/apic.h>
#include <asm/debugger.h>
#include <asm/xstate.h>

void svm_asm_do_resume(void);

u32 svm_feature_flags;

/* Indicates whether guests may use EFER.LMSLE. */
bool_t cpu_has_lmsl;

static void svm_update_guest_efer(struct vcpu *);

static struct hvm_function_table svm_function_table;

/* va of hardware host save area     */
static DEFINE_PER_CPU_READ_MOSTLY(void *, hsa);

/* vmcb used for extended host state */
static DEFINE_PER_CPU_READ_MOSTLY(void *, root_vmcb);

static bool_t amd_erratum383_found __read_mostly;

/* OSVW bits */
static uint64_t osvw_length, osvw_status;
static DEFINE_SPINLOCK(osvw_lock);

/* Only crash the guest if the problem originates in kernel mode. */
static void svm_crash_or_fault(struct vcpu *v)
{
    if ( vmcb_get_cpl(v->arch.hvm_svm.vmcb) )
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
    else
        domain_crash(v->domain);
}

void __update_guest_eip(struct cpu_user_regs *regs, unsigned int inst_len)
{
    struct vcpu *curr = current;

    if ( unlikely(inst_len == 0) )
        return;

    if ( unlikely(inst_len > MAX_INST_LEN) )
    {
        gdprintk(XENLOG_ERR, "Bad instruction length %u\n", inst_len);
        svm_crash_or_fault(curr);
        return;
    }

    ASSERT(regs == guest_cpu_user_regs());

    regs->eip += inst_len;
    regs->eflags &= ~X86_EFLAGS_RF;

    curr->arch.hvm_svm.vmcb->interrupt_shadow = 0;

    if ( regs->eflags & X86_EFLAGS_TF )
        hvm_inject_hw_exception(TRAP_debug, HVM_DELIVER_NO_ERROR_CODE);
}

static void svm_cpu_down(void)
{
    write_efer(read_efer() & ~EFER_SVME);
}

unsigned long *
svm_msrbit(unsigned long *msr_bitmap, uint32_t msr)
{
    unsigned long *msr_bit = NULL;

    /*
     * See AMD64 Programmers Manual, Vol 2, Section 15.10 (MSR-Bitmap Address).
     */
    if ( msr <= 0x1fff )
        msr_bit = msr_bitmap + 0x0000 / BYTES_PER_LONG;
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
        msr_bit = msr_bitmap + 0x0800 / BYTES_PER_LONG;
    else if ( (msr >= 0xc0010000) && (msr <= 0xc0011fff) )
        msr_bit = msr_bitmap + 0x1000 / BYTES_PER_LONG;

    return msr_bit;
}

void svm_intercept_msr(struct vcpu *v, uint32_t msr, int flags)
{
    unsigned long *msr_bit;

    msr_bit = svm_msrbit(v->arch.hvm_svm.msrpm, msr);
    BUG_ON(msr_bit == NULL);
    msr &= 0x1fff;

    if ( flags & MSR_INTERCEPT_READ )
         __set_bit(msr * 2, msr_bit);
    else
         __clear_bit(msr * 2, msr_bit);

    if ( flags & MSR_INTERCEPT_WRITE )
        __set_bit(msr * 2 + 1, msr_bit);
    else
        __clear_bit(msr * 2 + 1, msr_bit);
}

static void svm_save_dr(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned int flag_dr_dirty = v->arch.hvm_vcpu.flag_dr_dirty;

    if ( !flag_dr_dirty )
        return;

    /* Clear the DR dirty flag and re-enable intercepts for DR accesses. */
    v->arch.hvm_vcpu.flag_dr_dirty = 0;
    vmcb_set_dr_intercepts(vmcb, ~0u);

    if ( flag_dr_dirty & 2 )
    {
        svm_intercept_msr(v, MSR_AMD64_DR0_ADDRESS_MASK, MSR_INTERCEPT_RW);
        svm_intercept_msr(v, MSR_AMD64_DR1_ADDRESS_MASK, MSR_INTERCEPT_RW);
        svm_intercept_msr(v, MSR_AMD64_DR2_ADDRESS_MASK, MSR_INTERCEPT_RW);
        svm_intercept_msr(v, MSR_AMD64_DR3_ADDRESS_MASK, MSR_INTERCEPT_RW);

        rdmsrl(MSR_AMD64_DR0_ADDRESS_MASK, v->arch.hvm_svm.dr_mask[0]);
        rdmsrl(MSR_AMD64_DR1_ADDRESS_MASK, v->arch.hvm_svm.dr_mask[1]);
        rdmsrl(MSR_AMD64_DR2_ADDRESS_MASK, v->arch.hvm_svm.dr_mask[2]);
        rdmsrl(MSR_AMD64_DR3_ADDRESS_MASK, v->arch.hvm_svm.dr_mask[3]);
    }

    v->arch.debugreg[0] = read_debugreg(0);
    v->arch.debugreg[1] = read_debugreg(1);
    v->arch.debugreg[2] = read_debugreg(2);
    v->arch.debugreg[3] = read_debugreg(3);
    v->arch.debugreg[6] = vmcb_get_dr6(vmcb);
    v->arch.debugreg[7] = vmcb_get_dr7(vmcb);
}

static void __restore_debug_registers(struct vmcb_struct *vmcb, struct vcpu *v)
{
    unsigned int ecx;

    if ( v->arch.hvm_vcpu.flag_dr_dirty )
        return;

    v->arch.hvm_vcpu.flag_dr_dirty = 1;
    vmcb_set_dr_intercepts(vmcb, 0);

    ASSERT(v == current);
    hvm_cpuid(0x80000001, NULL, NULL, &ecx, NULL);
    if ( test_bit(X86_FEATURE_DBEXT & 31, &ecx) )
    {
        svm_intercept_msr(v, MSR_AMD64_DR0_ADDRESS_MASK, MSR_INTERCEPT_NONE);
        svm_intercept_msr(v, MSR_AMD64_DR1_ADDRESS_MASK, MSR_INTERCEPT_NONE);
        svm_intercept_msr(v, MSR_AMD64_DR2_ADDRESS_MASK, MSR_INTERCEPT_NONE);
        svm_intercept_msr(v, MSR_AMD64_DR3_ADDRESS_MASK, MSR_INTERCEPT_NONE);

        wrmsrl(MSR_AMD64_DR0_ADDRESS_MASK, v->arch.hvm_svm.dr_mask[0]);
        wrmsrl(MSR_AMD64_DR1_ADDRESS_MASK, v->arch.hvm_svm.dr_mask[1]);
        wrmsrl(MSR_AMD64_DR2_ADDRESS_MASK, v->arch.hvm_svm.dr_mask[2]);
        wrmsrl(MSR_AMD64_DR3_ADDRESS_MASK, v->arch.hvm_svm.dr_mask[3]);

        /* Can't use hvm_cpuid() in svm_save_dr(): v != current. */
        v->arch.hvm_vcpu.flag_dr_dirty |= 2;
    }

    write_debugreg(0, v->arch.debugreg[0]);
    write_debugreg(1, v->arch.debugreg[1]);
    write_debugreg(2, v->arch.debugreg[2]);
    write_debugreg(3, v->arch.debugreg[3]);
    vmcb_set_dr6(vmcb, v->arch.debugreg[6]);
    vmcb_set_dr7(vmcb, v->arch.debugreg[7]);
}

/*
 * DR7 is saved and restored on every vmexit.  Other debug registers only
 * need to be restored if their value is going to affect execution -- i.e.,
 * if one of the breakpoints is enabled.  So mask out all bits that don't
 * enable some breakpoint functionality.
 */
static void svm_restore_dr(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    if ( unlikely(v->arch.debugreg[7] & DR7_ACTIVE_MASK) )
        __restore_debug_registers(vmcb, v);
}

static int svm_vmcb_save(struct vcpu *v, struct hvm_hw_cpu *c)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    c->cr0 = v->arch.hvm_vcpu.guest_cr[0];
    c->cr2 = v->arch.hvm_vcpu.guest_cr[2];
    c->cr3 = v->arch.hvm_vcpu.guest_cr[3];
    c->cr4 = v->arch.hvm_vcpu.guest_cr[4];

    c->sysenter_cs = v->arch.hvm_svm.guest_sysenter_cs;
    c->sysenter_esp = v->arch.hvm_svm.guest_sysenter_esp;
    c->sysenter_eip = v->arch.hvm_svm.guest_sysenter_eip;

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

static int svm_vmcb_restore(struct vcpu *v, struct hvm_hw_cpu *c)
{
    struct page_info *page = NULL;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct p2m_domain *p2m = p2m_get_hostp2m(v->domain);

    if ( c->pending_valid &&
         ((c->pending_type == 1) || (c->pending_type > 6) ||
          (c->pending_reserved != 0)) )
    {
        gdprintk(XENLOG_ERR, "Invalid pending event %#"PRIx32".\n",
                 c->pending_event);
        return -EINVAL;
    }

    if ( !paging_mode_hap(v->domain) )
    {
        if ( c->cr0 & X86_CR0_PG )
        {
            page = get_page_from_gfn(v->domain, c->cr3 >> PAGE_SHIFT,
                                     NULL, P2M_ALLOC);
            if ( !page )
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value=%#"PRIx64"\n",
                         c->cr3);
                return -EINVAL;
            }
        }

        if ( v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG )
            put_page(pagetable_get_page(v->arch.guest_table));

        v->arch.guest_table =
            page ? pagetable_from_page(page) : pagetable_null();
    }

    v->arch.hvm_vcpu.guest_cr[0] = c->cr0 | X86_CR0_ET;
    v->arch.hvm_vcpu.guest_cr[2] = c->cr2;
    v->arch.hvm_vcpu.guest_cr[3] = c->cr3;
    v->arch.hvm_vcpu.guest_cr[4] = c->cr4;
    svm_update_guest_cr(v, 0);
    svm_update_guest_cr(v, 2);
    svm_update_guest_cr(v, 4);

    /* Load sysenter MSRs into both VMCB save area and VCPU fields. */
    vmcb->sysenter_cs = v->arch.hvm_svm.guest_sysenter_cs = c->sysenter_cs;
    vmcb->sysenter_esp = v->arch.hvm_svm.guest_sysenter_esp = c->sysenter_esp;
    vmcb->sysenter_eip = v->arch.hvm_svm.guest_sysenter_eip = c->sysenter_eip;
    
    if ( paging_mode_hap(v->domain) )
    {
        vmcb_set_np_enable(vmcb, 1);
        vmcb_set_g_pat(vmcb, MSR_IA32_CR_PAT_RESET /* guest PAT */);
        vmcb_set_h_cr3(vmcb, pagetable_get_paddr(p2m_get_pagetable(p2m)));
    }

    if ( c->pending_valid &&
         hvm_event_needs_reinjection(c->pending_type, c->pending_vector) )
    {
        gdprintk(XENLOG_INFO, "Re-injecting %#"PRIx32", %#"PRIx32"\n",
                 c->pending_event, c->error_code);
        vmcb->eventinj.bytes = c->pending_event;
        vmcb->eventinj.fields.errorcode = c->error_code;
    }
    else
        vmcb->eventinj.bytes = 0;

    vmcb->cleanbits.bytes = 0;
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
    data->msr_flags        = 0;
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
        gdprintk(XENLOG_ERR, "svm_vmcb restore failed!\n");
        domain_crash(v->domain);
        return -EINVAL;
    }

    return 0;
}

static unsigned int __init svm_init_msr(void)
{
    return boot_cpu_has(X86_FEATURE_DBEXT) ? 4 : 0;
}

static void svm_save_msr(struct vcpu *v, struct hvm_msr *ctxt)
{
    if ( boot_cpu_has(X86_FEATURE_DBEXT) )
    {
        ctxt->msr[ctxt->count].val = v->arch.hvm_svm.dr_mask[0];
        if ( ctxt->msr[ctxt->count].val )
            ctxt->msr[ctxt->count++].index = MSR_AMD64_DR0_ADDRESS_MASK;

        ctxt->msr[ctxt->count].val = v->arch.hvm_svm.dr_mask[1];
        if ( ctxt->msr[ctxt->count].val )
            ctxt->msr[ctxt->count++].index = MSR_AMD64_DR1_ADDRESS_MASK;

        ctxt->msr[ctxt->count].val = v->arch.hvm_svm.dr_mask[2];
        if ( ctxt->msr[ctxt->count].val )
            ctxt->msr[ctxt->count++].index = MSR_AMD64_DR2_ADDRESS_MASK;

        ctxt->msr[ctxt->count].val = v->arch.hvm_svm.dr_mask[3];
        if ( ctxt->msr[ctxt->count].val )
            ctxt->msr[ctxt->count++].index = MSR_AMD64_DR3_ADDRESS_MASK;
    }
}

static int svm_load_msr(struct vcpu *v, struct hvm_msr *ctxt)
{
    unsigned int i, idx;
    int err = 0;

    for ( i = 0; i < ctxt->count; ++i )
    {
        switch ( idx = ctxt->msr[i].index )
        {
        case MSR_AMD64_DR0_ADDRESS_MASK:
            if ( !boot_cpu_has(X86_FEATURE_DBEXT) )
                err = -ENXIO;
            else if ( ctxt->msr[i].val >> 32 )
                err = -EDOM;
            else
                v->arch.hvm_svm.dr_mask[0] = ctxt->msr[i].val;
            break;

        case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
            if ( !boot_cpu_has(X86_FEATURE_DBEXT) )
                err = -ENXIO;
            else if ( ctxt->msr[i].val >> 32 )
                err = -EDOM;
            else
                v->arch.hvm_svm.dr_mask[idx - MSR_AMD64_DR1_ADDRESS_MASK + 1] =
                    ctxt->msr[i].val;
            break;

        default:
            continue;
        }
        if ( err )
            break;
        ctxt->msr[i]._rsvd = 1;
    }

    return err;
}

static void svm_fpu_enter(struct vcpu *v)
{
    struct vmcb_struct *n1vmcb = vcpu_nestedhvm(v).nv_n1vmcx;

    vcpu_restore_fpu_lazy(v);
    vmcb_set_exception_intercepts(
        n1vmcb,
        vmcb_get_exception_intercepts(n1vmcb) & ~(1U << TRAP_no_device));
}

static void svm_fpu_leave(struct vcpu *v)
{
    struct vmcb_struct *n1vmcb = vcpu_nestedhvm(v).nv_n1vmcx;

    ASSERT(!v->fpu_dirtied);
    ASSERT(read_cr0() & X86_CR0_TS);

    /*
     * If the guest does not have TS enabled then we must cause and handle an 
     * exception on first use of the FPU. If the guest *does* have TS enabled 
     * then this is not necessary: no FPU activity can occur until the guest 
     * clears CR0.TS, and we will initialise the FPU when that happens.
     */
    if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
    {
        vmcb_set_exception_intercepts(
            n1vmcb,
            vmcb_get_exception_intercepts(n1vmcb) | (1U << TRAP_no_device));
        vmcb_set_cr0(n1vmcb, vmcb_get_cr0(n1vmcb) | X86_CR0_TS);
    }
}

static unsigned int svm_get_interrupt_shadow(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned int intr_shadow = 0;

    if ( vmcb->interrupt_shadow )
        intr_shadow |= HVM_INTR_SHADOW_MOV_SS | HVM_INTR_SHADOW_STI;

    if ( vmcb_get_general1_intercepts(vmcb) & GENERAL1_INTERCEPT_IRET )
        intr_shadow |= HVM_INTR_SHADOW_NMI;

    return intr_shadow;
}

static void svm_set_interrupt_shadow(struct vcpu *v, unsigned int intr_shadow)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);

    vmcb->interrupt_shadow =
        !!(intr_shadow & (HVM_INTR_SHADOW_MOV_SS|HVM_INTR_SHADOW_STI));

    general1_intercepts &= ~GENERAL1_INTERCEPT_IRET;
    if ( intr_shadow & HVM_INTR_SHADOW_NMI )
        general1_intercepts |= GENERAL1_INTERCEPT_IRET;
    vmcb_set_general1_intercepts(vmcb, general1_intercepts);
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

void svm_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    uint64_t value;

    switch ( cr )
    {
    case 0: {
        unsigned long hw_cr0_mask = 0;

        if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
        {
            if ( v != current )
                hw_cr0_mask |= X86_CR0_TS;
            else if ( vmcb_get_cr0(vmcb) & X86_CR0_TS )
                svm_fpu_enter(v);
        }

        value = v->arch.hvm_vcpu.guest_cr[0] | hw_cr0_mask;
        if ( !paging_mode_hap(v->domain) )
            value |= X86_CR0_PG | X86_CR0_WP;
        vmcb_set_cr0(vmcb, value);
        break;
    }
    case 2:
        vmcb_set_cr2(vmcb, v->arch.hvm_vcpu.guest_cr[2]);
        break;
    case 3:
        vmcb_set_cr3(vmcb, v->arch.hvm_vcpu.hw_cr[3]);
        if ( !nestedhvm_enabled(v->domain) )
            hvm_asid_flush_vcpu(v);
        else if ( nestedhvm_vmswitch_in_progress(v) )
            ; /* CR3 switches during VMRUN/VMEXIT do not flush the TLB. */
        else
            hvm_asid_flush_vcpu_asid(
                nestedhvm_vcpu_in_guestmode(v)
                ? &vcpu_nestedhvm(v).nv_n2asid : &v->arch.hvm_vcpu.n1asid);
        break;
    case 4:
        value = HVM_CR4_HOST_MASK;
        if ( paging_mode_hap(v->domain) )
            value &= ~X86_CR4_PAE;
        value |= v->arch.hvm_vcpu.guest_cr[4];

        if ( !hvm_paging_enabled(v) )
        {
            /*
             * When the guest thinks paging is disabled, Xen may need to hide
             * the effects of shadow paging, as hardware runs with the host
             * paging settings, rather than the guests settings.
             *
             * Without CR0.PG, all memory accesses are user mode, so
             * _PAGE_USER must be set in the shadow pagetables for guest
             * userspace to function.  This in turn trips up guest supervisor
             * mode if SMEP/SMAP are left active in context.  They wouldn't
             * have any effect if paging was actually disabled, so hide them
             * behind the back of the guest.
             */
            value &= ~(X86_CR4_SMEP | X86_CR4_SMAP);
        }

        vmcb_set_cr4(vmcb, value);
        break;
    default:
        BUG();
    }
}

static void svm_update_guest_efer(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    bool_t lma = !!(v->arch.hvm_vcpu.guest_efer & EFER_LMA);
    uint64_t new_efer;

    new_efer = (v->arch.hvm_vcpu.guest_efer | EFER_SVME) & ~EFER_LME;
    if ( lma )
        new_efer |= EFER_LME;
    vmcb_set_efer(vmcb, new_efer);
}

static void svm_update_guest_vendor(struct vcpu *v)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = arch_svm->vmcb;
    u32 bitmap = vmcb_get_exception_intercepts(vmcb);

    if ( opt_hvm_fep ||
         (v->domain->arch.x86_vendor != boot_cpu_data.x86_vendor) )
        bitmap |= (1U << TRAP_invalid_op);
    else
        bitmap &= ~(1U << TRAP_invalid_op);

    vmcb_set_exception_intercepts(vmcb, bitmap);
}

static void svm_sync_vmcb(struct vcpu *v)
{
    struct arch_svm_struct *arch_svm = &v->arch.hvm_svm;

    if ( arch_svm->vmcb_in_sync )
        return;

    arch_svm->vmcb_in_sync = 1;

    svm_vmsave(arch_svm->vmcb);
}

static void svm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT((v == current) || !vcpu_runnable(v));

    switch ( seg )
    {
    case x86_seg_cs:
        memcpy(reg, &vmcb->cs, sizeof(*reg));
        reg->attr.fields.p = 1;
        reg->attr.fields.g = reg->limit > 0xFFFFF;
        break;
    case x86_seg_ds:
        memcpy(reg, &vmcb->ds, sizeof(*reg));
        if ( reg->attr.fields.type != 0 )
            reg->attr.fields.type |= 0x1;
        break;
    case x86_seg_es:
        memcpy(reg, &vmcb->es, sizeof(*reg));
        if ( reg->attr.fields.type != 0 )
            reg->attr.fields.type |= 0x1;
        break;
    case x86_seg_fs:
        svm_sync_vmcb(v);
        memcpy(reg, &vmcb->fs, sizeof(*reg));
        if ( reg->attr.fields.type != 0 )
            reg->attr.fields.type |= 0x1;
        break;
    case x86_seg_gs:
        svm_sync_vmcb(v);
        memcpy(reg, &vmcb->gs, sizeof(*reg));
        if ( reg->attr.fields.type != 0 )
            reg->attr.fields.type |= 0x1;
        break;
    case x86_seg_ss:
        memcpy(reg, &vmcb->ss, sizeof(*reg));
        reg->attr.fields.dpl = vmcb->_cpl;
        if ( reg->attr.fields.type == 0 )
            reg->attr.fields.db = 0;
        break;
    case x86_seg_tr:
        svm_sync_vmcb(v);
        memcpy(reg, &vmcb->tr, sizeof(*reg));
        reg->attr.fields.p = 1;
        reg->attr.fields.type |= 0x2;
        break;
    case x86_seg_gdtr:
        memcpy(reg, &vmcb->gdtr, sizeof(*reg));
        reg->attr.bytes = 0x80;
        break;
    case x86_seg_idtr:
        memcpy(reg, &vmcb->idtr, sizeof(*reg));
        reg->attr.bytes = 0x80;
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
    int sync = 0;

    ASSERT((v == current) || !vcpu_runnable(v));

    switch ( seg )
    {
    case x86_seg_cs:
    case x86_seg_ds:
    case x86_seg_es:
    case x86_seg_ss: /* cpl */
        vmcb->cleanbits.fields.seg = 0;
        break;
    case x86_seg_gdtr:
    case x86_seg_idtr:
        vmcb->cleanbits.fields.dt = 0;
        break;
    case x86_seg_fs:
    case x86_seg_gs:
    case x86_seg_tr:
    case x86_seg_ldtr:
        sync = (v == current);
        break;
    default:
        break;
    }

    if ( sync )
        svm_sync_vmcb(v);

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
        memcpy(&vmcb->fs, reg, sizeof(*reg));
        break;
    case x86_seg_gs:
        memcpy(&vmcb->gs, reg, sizeof(*reg));
        break;
    case x86_seg_ss:
        memcpy(&vmcb->ss, reg, sizeof(*reg));
        vmcb->_cpl = vmcb->ss.attr.fields.dpl;
        break;
    case x86_seg_tr:
        memcpy(&vmcb->tr, reg, sizeof(*reg));
        break;
    case x86_seg_gdtr:
        vmcb->gdtr.base = reg->base;
        vmcb->gdtr.limit = (uint16_t)reg->limit;
        break;
    case x86_seg_idtr:
        vmcb->idtr.base = reg->base;
        vmcb->idtr.limit = (uint16_t)reg->limit;
        break;
    case x86_seg_ldtr:
        memcpy(&vmcb->ldtr, reg, sizeof(*reg));
        break;
    default:
        BUG();
    }

    if ( sync )
        svm_vmload(vmcb);
}

static unsigned long svm_get_shadow_gs_base(struct vcpu *v)
{
    return v->arch.hvm_svm.vmcb->kerngsbase;
}

static int svm_set_guest_pat(struct vcpu *v, u64 gpat)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( !paging_mode_hap(v->domain) )
        return 0;

    vmcb_set_g_pat(vmcb, gpat);
    return 1;
}

static int svm_get_guest_pat(struct vcpu *v, u64 *gpat)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    if ( !paging_mode_hap(v->domain) )
        return 0;

    *gpat = vmcb_get_g_pat(vmcb);
    return 1;
}

static uint64_t scale_tsc(uint64_t host_tsc, uint64_t ratio)
{
    uint64_t mult, frac, scaled_host_tsc;

    if ( ratio == DEFAULT_TSC_RATIO )
        return host_tsc;

    /*
     * Suppose the most significant 32 bits of host_tsc and ratio are
     * tsc_h and mult, and the least 32 bits of them are tsc_l and frac,
     * then
     *     host_tsc * ratio * 2^-32
     *     = host_tsc * (mult * 2^32 + frac) * 2^-32
     *     = host_tsc * mult + (tsc_h * 2^32 + tsc_l) * frac * 2^-32
     *     = host_tsc * mult + tsc_h * frac + ((tsc_l * frac) >> 32)
     *
     * Multiplications in the last two terms are between 32-bit integers,
     * so both of them can fit in 64-bit integers.
     *
     * Because mult is usually less than 10 in practice, it's very rare
     * that host_tsc * mult can overflow a 64-bit integer.
     */
    mult = ratio >> 32;
    frac = ratio & ((1ULL << 32) - 1);
    scaled_host_tsc  = host_tsc * mult;
    scaled_host_tsc += (host_tsc >> 32) * frac;
    scaled_host_tsc += ((host_tsc & ((1ULL << 32) - 1)) * frac) >> 32;

    return scaled_host_tsc;
}

static uint64_t svm_get_tsc_offset(uint64_t host_tsc, uint64_t guest_tsc,
    uint64_t ratio)
{
    return guest_tsc - scale_tsc(host_tsc, ratio);
}

static void svm_set_tsc_offset(struct vcpu *v, u64 offset, u64 at_tsc)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct vmcb_struct *n1vmcb, *n2vmcb;
    uint64_t n2_tsc_offset = 0;
    struct domain *d = v->domain;

    if ( !nestedhvm_enabled(d) ) {
        vmcb_set_tsc_offset(vmcb, offset);
        return;
    }

    n1vmcb = vcpu_nestedhvm(v).nv_n1vmcx;
    n2vmcb = vcpu_nestedhvm(v).nv_n2vmcx;

    if ( nestedhvm_vcpu_in_guestmode(v) ) {
        struct nestedsvm *svm = &vcpu_nestedsvm(v);

        n2_tsc_offset = vmcb_get_tsc_offset(n2vmcb) -
                        vmcb_get_tsc_offset(n1vmcb);
        if ( svm->ns_tscratio != DEFAULT_TSC_RATIO ) {
            uint64_t guest_tsc = hvm_get_guest_tsc_fixed(v, at_tsc);

            n2_tsc_offset = svm_get_tsc_offset(guest_tsc,
                                               guest_tsc + n2_tsc_offset,
                                               svm->ns_tscratio);
        }
        vmcb_set_tsc_offset(n1vmcb, offset);
    }

    vmcb_set_tsc_offset(vmcb, offset + n2_tsc_offset);
}

static void svm_set_rdtsc_exiting(struct vcpu *v, bool_t enable)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);
    u32 general2_intercepts = vmcb_get_general2_intercepts(vmcb);

    general1_intercepts &= ~GENERAL1_INTERCEPT_RDTSC;
    general2_intercepts &= ~GENERAL2_INTERCEPT_RDTSCP;

    if ( enable )
    {
        general1_intercepts |= GENERAL1_INTERCEPT_RDTSC;
        general2_intercepts |= GENERAL2_INTERCEPT_RDTSCP;
    }

    vmcb_set_general1_intercepts(vmcb, general1_intercepts);
    vmcb_set_general2_intercepts(vmcb, general2_intercepts);
}

static unsigned int svm_get_insn_bytes(struct vcpu *v, uint8_t *buf)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned int len = v->arch.hvm_svm.cached_insn_len;

    if ( len != 0 )
    {
        /* Latch and clear the cached instruction. */
        memcpy(buf, vmcb->guest_ins, MAX_INST_LEN);
        v->arch.hvm_svm.cached_insn_len = 0;
    }

    return len;
}

static void svm_init_hypercall_page(struct domain *d, void *hypercall_page)
{
    char *p;
    int i;

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        if ( i == __HYPERVISOR_iret )
            continue;

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

static void svm_lwp_interrupt(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;

    ack_APIC_irq();
    vlapic_set_irq(
        vcpu_vlapic(curr),
        (curr->arch.hvm_svm.guest_lwp_cfg >> 40) & 0xff,
        0);
}

static inline void svm_lwp_save(struct vcpu *v)
{
    /* Don't mess up with other guests. Disable LWP for next VCPU. */
    if ( v->arch.hvm_svm.guest_lwp_cfg )
    {
        wrmsrl(MSR_AMD64_LWP_CFG, 0x0);
        wrmsrl(MSR_AMD64_LWP_CBADDR, 0x0);
    }
}

static inline void svm_lwp_load(struct vcpu *v)
{
    /* Only LWP_CFG is reloaded. LWP_CBADDR will be reloaded via xrstor. */
   if ( v->arch.hvm_svm.guest_lwp_cfg ) 
       wrmsrl(MSR_AMD64_LWP_CFG, v->arch.hvm_svm.cpu_lwp_cfg);
}

/* Update LWP_CFG MSR (0xc0000105). Return -1 if error; otherwise returns 0. */
static int svm_update_lwp_cfg(struct vcpu *v, uint64_t msr_content)
{
    unsigned int edx;
    uint32_t msr_low;
    static uint8_t lwp_intr_vector;

    if ( xsave_enabled(v) && cpu_has_lwp )
    {
        hvm_cpuid(0x8000001c, NULL, NULL, NULL, &edx);
        msr_low = (uint32_t)msr_content;
        
        /* generate #GP if guest tries to turn on unsupported features. */
        if ( msr_low & ~edx)
            return -1;

        v->arch.hvm_svm.guest_lwp_cfg = msr_content;

        /* setup interrupt handler if needed */
        if ( (msr_content & 0x80000000) && ((msr_content >> 40) & 0xff) )
        {
            alloc_direct_apic_vector(&lwp_intr_vector, svm_lwp_interrupt);
            v->arch.hvm_svm.cpu_lwp_cfg = (msr_content & 0xffff00ffffffffffULL)
                | ((uint64_t)lwp_intr_vector << 40);
        }
        else
        {
            /* otherwise disable it */
            v->arch.hvm_svm.cpu_lwp_cfg = msr_content & 0xffff00ff7fffffffULL;
        }
        
        wrmsrl(MSR_AMD64_LWP_CFG, v->arch.hvm_svm.cpu_lwp_cfg);

        /* track nonalzy state if LWP_CFG is non-zero. */
        v->arch.nonlazy_xstate_used = !!(msr_content);
    }

    return 0;
}

static inline void svm_tsc_ratio_save(struct vcpu *v)
{
    /* Other vcpus might not have vtsc enabled. So disable TSC_RATIO here. */
    if ( cpu_has_tsc_ratio && !v->domain->arch.vtsc )
        wrmsrl(MSR_AMD64_TSC_RATIO, DEFAULT_TSC_RATIO);
}

static inline void svm_tsc_ratio_load(struct vcpu *v)
{
    if ( cpu_has_tsc_ratio && !v->domain->arch.vtsc ) 
        wrmsrl(MSR_AMD64_TSC_RATIO, hvm_tsc_scaling_ratio(v->domain));
}

static void svm_ctxt_switch_from(struct vcpu *v)
{
    int cpu = smp_processor_id();

    /*
     * Return early if trying to do a context switch without SVM enabled,
     * this can happen when the hypervisor shuts down with HVM guests
     * still running.
     */
    if ( unlikely((read_efer() & EFER_SVME) == 0) )
        return;

    svm_fpu_leave(v);

    svm_save_dr(v);
    svm_lwp_save(v);
    svm_tsc_ratio_save(v);

    svm_sync_vmcb(v);
    svm_vmload(per_cpu(root_vmcb, cpu));

    /* Resume use of ISTs now that the host TR is reinstated. */
    set_ist(&idt_tables[cpu][TRAP_double_fault],  IST_DF);
    set_ist(&idt_tables[cpu][TRAP_nmi],           IST_NMI);
    set_ist(&idt_tables[cpu][TRAP_machine_check], IST_MCE);
}

static void svm_ctxt_switch_to(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int cpu = smp_processor_id();

    /*
     * This is required, because VMRUN does consistency check and some of the
     * DOM0 selectors are pointing to invalid GDT locations, and cause AMD
     * processors to shutdown.
     */
    asm volatile ("mov %0, %%ds; mov %0, %%es; mov %0, %%ss;" :: "r" (0));

    /*
     * Cannot use ISTs for NMI/#MC/#DF while we are running with the guest TR.
     * But this doesn't matter: the IST is only req'd to handle SYSCALL/SYSRET.
     */
    set_ist(&idt_tables[cpu][TRAP_double_fault],  IST_NONE);
    set_ist(&idt_tables[cpu][TRAP_nmi],           IST_NONE);
    set_ist(&idt_tables[cpu][TRAP_machine_check], IST_NONE);

    svm_restore_dr(v);

    svm_vmsave(per_cpu(root_vmcb, cpu));
    svm_vmload(vmcb);
    vmcb->cleanbits.bytes = 0;
    svm_lwp_load(v);
    svm_tsc_ratio_load(v);

    if ( cpu_has_rdtscp )
        wrmsrl(MSR_TSC_AUX, hvm_msr_tsc_aux(v));
}

static void noreturn svm_do_resume(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    bool_t debug_state = v->domain->debugger_attached;
    bool_t vcpu_guestmode = 0;
    struct vlapic *vlapic = vcpu_vlapic(v);

    if ( nestedhvm_enabled(v->domain) && nestedhvm_vcpu_in_guestmode(v) )
        vcpu_guestmode = 1;

    if ( !vcpu_guestmode &&
        unlikely(v->arch.hvm_vcpu.debug_state_latch != debug_state) )
    {
        uint32_t intercepts = vmcb_get_exception_intercepts(vmcb);

        v->arch.hvm_vcpu.debug_state_latch = debug_state;
        vmcb_set_exception_intercepts(
            vmcb, debug_state ? (intercepts | (1U << TRAP_int3))
                              : (intercepts & ~(1U << TRAP_int3)));
    }

    if ( v->arch.hvm_svm.launch_core != smp_processor_id() )
    {
        v->arch.hvm_svm.launch_core = smp_processor_id();
        hvm_migrate_timers(v);
        hvm_migrate_pirqs(v);
        /* Migrating to another ASID domain.  Request a new ASID. */
        hvm_asid_flush_vcpu(v);
    }

    if ( !vcpu_guestmode && !vlapic_hw_disabled(vlapic) )
    {
        vintr_t intr;

        /* Reflect the vlapic's TPR in the hardware vtpr */
        intr = vmcb_get_vintr(vmcb);
        intr.fields.tpr =
            (vlapic_get_reg(vlapic, APIC_TASKPRI) & 0xFF) >> 4;
        vmcb_set_vintr(vmcb, intr);
    }

    hvm_do_resume(v);

    reset_stack_and_jump(svm_asm_do_resume);
}

static void svm_guest_osvw_init(struct vcpu *vcpu)
{
    if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD )
        return;

    /*
     * Guests should see errata 400 and 415 as fixed (assuming that
     * HLT and IO instructions are intercepted).
     */
    vcpu->arch.hvm_svm.osvw.length = (osvw_length >= 3) ? osvw_length : 3;
    vcpu->arch.hvm_svm.osvw.status = osvw_status & ~(6ULL);

    /*
     * By increasing VCPU's osvw.length to 3 we are telling the guest that
     * all osvw.status bits inside that length, including bit 0 (which is
     * reserved for erratum 298), are valid. However, if host processor's
     * osvw_len is 0 then osvw_status[0] carries no information. We need to
     * be conservative here and therefore we tell the guest that erratum 298
     * is present (because we really don't know).
     */
    if ( osvw_length == 0 && boot_cpu_data.x86 == 0x10 )
        vcpu->arch.hvm_svm.osvw.status |= 1;
}

void svm_host_osvw_reset()
{
    spin_lock(&osvw_lock);

    osvw_length = 64; /* One register (MSRC001_0141) worth of errata */
    osvw_status = 0;

    spin_unlock(&osvw_lock);
}

void svm_host_osvw_init()
{
    spin_lock(&osvw_lock);

    /*
     * Get OSVW bits. If bits are not the same on different processors then
     * choose the worst case (i.e. if erratum is present on one processor and
     * not on another assume that the erratum is present everywhere).
     */
    if ( test_bit(X86_FEATURE_OSVW, &boot_cpu_data.x86_capability) )
    {
        uint64_t len, status;

        if ( rdmsr_safe(MSR_AMD_OSVW_ID_LENGTH, len) ||
             rdmsr_safe(MSR_AMD_OSVW_STATUS, status) )
            len = status = 0;

        if (len < osvw_length)
            osvw_length = len;

        osvw_status |= status;
        osvw_status &= (1ULL << osvw_length) - 1;
    }
    else
        osvw_length = osvw_status = 0;

    spin_unlock(&osvw_lock);
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

    /* PVH's VPMU is initialized via hypercall */
    if ( has_vlapic(v->domain) )
        vpmu_initialise(v);

    svm_guest_osvw_init(v);

    return 0;
}

static void svm_vcpu_destroy(struct vcpu *v)
{
    vpmu_destroy(v);
    svm_destroy_vmcb(v);
    passive_domain_destroy(v);
}

static void svm_inject_trap(const struct hvm_trap *trap)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm_svm.vmcb;
    eventinj_t event = vmcb->eventinj;
    struct hvm_trap _trap = *trap;
    const struct cpu_user_regs *regs = guest_cpu_user_regs();

    switch ( _trap.vector )
    {
    case TRAP_debug:
        if ( regs->eflags & X86_EFLAGS_TF )
        {
            __restore_debug_registers(vmcb, curr);
            vmcb_set_dr6(vmcb, vmcb_get_dr6(vmcb) | 0x4000);
        }
        /* fall through */
    case TRAP_int3:
        if ( curr->domain->debugger_attached )
        {
            /* Debug/Int3: Trap to debugger. */
            domain_pause_for_debugger();
            return;
        }
    }

    if ( unlikely(event.fields.v) &&
         (event.fields.type == X86_EVENTTYPE_HW_EXCEPTION) )
    {
        _trap.vector = hvm_combine_hw_exceptions(
            event.fields.vector, _trap.vector);
        if ( _trap.vector == TRAP_double_fault )
            _trap.error_code = 0;
    }

    event.bytes = 0;
    event.fields.v = 1;
    event.fields.vector = _trap.vector;

    /* Refer to AMD Vol 2: System Programming, 15.20 Event Injection. */
    switch ( _trap.type )
    {
    case X86_EVENTTYPE_SW_INTERRUPT: /* int $n */
        /*
         * Software interrupts (type 4) cannot be properly injected if the
         * processor doesn't support NextRIP.  Without NextRIP, the emulator
         * will have performed DPL and presence checks for us, and will have
         * moved eip forward if appropriate.
         */
        if ( cpu_has_svm_nrips )
            vmcb->nextrip = regs->eip + _trap.insn_len;
        event.fields.type = X86_EVENTTYPE_SW_INTERRUPT;
        break;

    case X86_EVENTTYPE_PRI_SW_EXCEPTION: /* icebp */
        /*
         * icebp's injection must always be emulated.  Software injection help
         * in x86_emulate has moved eip forward, but NextRIP (if used) still
         * needs setting or execution will resume from 0.
         */
        if ( cpu_has_svm_nrips )
            vmcb->nextrip = regs->eip;
        event.fields.type = X86_EVENTTYPE_HW_EXCEPTION;
        break;

    case X86_EVENTTYPE_SW_EXCEPTION: /* int3, into */
        /*
         * The AMD manual states that .type=3 (HW exception), .vector=3 or 4,
         * will perform DPL checks.  Experimentally, DPL and presence checks
         * are indeed performed, even without NextRIP support.
         *
         * However without NextRIP support, the event injection still needs
         * fully emulating to get the correct eip in the trap frame, yet get
         * the correct faulting eip should a fault occur.
         */
        if ( cpu_has_svm_nrips )
            vmcb->nextrip = regs->eip + _trap.insn_len;
        event.fields.type = X86_EVENTTYPE_HW_EXCEPTION;
        break;

    default:
        event.fields.type = X86_EVENTTYPE_HW_EXCEPTION;
        event.fields.ev = (_trap.error_code != HVM_DELIVER_NO_ERROR_CODE);
        event.fields.errorcode = _trap.error_code;
        break;
    }

    vmcb->eventinj = event;

    if ( _trap.vector == TRAP_page_fault )
    {
        curr->arch.hvm_vcpu.guest_cr[2] = _trap.cr2;
        vmcb_set_cr2(vmcb, _trap.cr2);
        HVMTRACE_LONG_2D(PF_INJECT, _trap.error_code, TRC_PAR_LONG(_trap.cr2));
    }
    else
    {
        HVMTRACE_2D(INJ_EXC, _trap.vector, _trap.error_code);
    }
}

static int svm_event_pending(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    return vmcb->eventinj.fields.v;
}

static void svm_cpu_dead(unsigned int cpu)
{
    free_xenheap_page(per_cpu(hsa, cpu));
    per_cpu(hsa, cpu) = NULL;
    free_vmcb(per_cpu(root_vmcb, cpu));
    per_cpu(root_vmcb, cpu) = NULL;
}

static int svm_cpu_up_prepare(unsigned int cpu)
{
    if ( ((per_cpu(hsa, cpu) == NULL) &&
          ((per_cpu(hsa, cpu) = alloc_host_save_area()) == NULL)) ||
         ((per_cpu(root_vmcb, cpu) == NULL) &&
          ((per_cpu(root_vmcb, cpu) = alloc_vmcb()) == NULL)) )
    {
        svm_cpu_dead(cpu);
        return -ENOMEM;
    }

    return 0;
}

static void svm_init_erratum_383(struct cpuinfo_x86 *c)
{
    uint64_t msr_content;

    /* check whether CPU is affected */
    if ( !cpu_has_amd_erratum(c, AMD_ERRATUM_383) )
        return;

    /* use safe methods to be compatible with nested virtualization */
    if (rdmsr_safe(MSR_AMD64_DC_CFG, msr_content) == 0 &&
        wrmsr_safe(MSR_AMD64_DC_CFG, msr_content | (1ULL << 47)) == 0)
    {
        amd_erratum383_found = 1;
    } else {
        printk("Failed to enable erratum 383\n");
    }
}

static int svm_handle_osvw(struct vcpu *v, uint32_t msr, uint64_t *val, bool_t read)
{
    unsigned int ecx;

    /* Guest OSVW support */
    hvm_cpuid(0x80000001, NULL, NULL, &ecx, NULL);
    if ( !test_bit((X86_FEATURE_OSVW & 31), &ecx) )
        return -1;

    if ( read )
    {
        if (msr == MSR_AMD_OSVW_ID_LENGTH)
            *val = v->arch.hvm_svm.osvw.length;
        else
            *val = v->arch.hvm_svm.osvw.status;
    }
    /* Writes are ignored */

    return 0;
}

static int svm_cpu_up(void)
{
    uint64_t msr_content;
    int rc, cpu = smp_processor_id();
    struct cpuinfo_x86 *c = &cpu_data[cpu];
 
    /* Check whether SVM feature is disabled in BIOS */
    rdmsrl(MSR_K8_VM_CR, msr_content);
    if ( msr_content & K8_VMCR_SVME_DISABLE )
    {
        printk("CPU%d: AMD SVM Extension is disabled in BIOS.\n", cpu);
        return -EINVAL;
    }

    if ( (rc = svm_cpu_up_prepare(cpu)) != 0 )
        return rc;

    write_efer(read_efer() | EFER_SVME);

    /* Initialize the HSA for this core. */
    wrmsrl(MSR_K8_VM_HSAVE_PA, (uint64_t)virt_to_maddr(per_cpu(hsa, cpu)));

    /* check for erratum 383 */
    svm_init_erratum_383(c);

    /* Initialize core's ASID handling. */
    svm_asid_init(c);

    /*
     * Check whether EFER.LMSLE can be written.
     * Unfortunately there's no feature bit defined for this.
     */
    msr_content = read_efer();
    if ( wrmsr_safe(MSR_EFER, msr_content | EFER_LMSLE) == 0 )
        rdmsrl(MSR_EFER, msr_content);
    if ( msr_content & EFER_LMSLE )
    {
        if ( c == &boot_cpu_data )
            cpu_has_lmsl = 1;
        wrmsrl(MSR_EFER, msr_content ^ EFER_LMSLE);
    }
    else
    {
        if ( cpu_has_lmsl )
            printk(XENLOG_WARNING "Inconsistent LMSLE support across CPUs!\n");
        cpu_has_lmsl = 0;
    }

    /* Initialize OSVW bits to be used by guests */
    svm_host_osvw_init();

    return 0;
}

const struct hvm_function_table * __init start_svm(void)
{
    bool_t printed = 0;

    svm_host_osvw_reset();

    if ( svm_cpu_up() )
    {
        printk("SVM: failed to initialise.\n");
        return NULL;
    }

    setup_vmcb_dump();

    svm_feature_flags = (current_cpu_data.extended_cpuid_level >= 0x8000000A ?
                         cpuid_edx(0x8000000A) : 0);

    printk("SVM: Supported advanced features:\n");

    /* DecodeAssists fast paths assume nextrip is valid for fast rIP update. */
    if ( !cpu_has_svm_nrips )
        clear_bit(SVM_FEATURE_DECODEASSISTS, &svm_feature_flags);

    if ( cpu_has_tsc_ratio )
        svm_function_table.tsc_scaling.ratio_frac_bits = 32;

#define P(p,s) if ( p ) { printk(" - %s\n", s); printed = 1; }
    P(cpu_has_svm_npt, "Nested Page Tables (NPT)");
    P(cpu_has_svm_lbrv, "Last Branch Record (LBR) Virtualisation");
    P(cpu_has_svm_nrips, "Next-RIP Saved on #VMEXIT");
    P(cpu_has_svm_cleanbits, "VMCB Clean Bits");
    P(cpu_has_svm_decode, "DecodeAssists");
    P(cpu_has_pause_filter, "Pause-Intercept Filter");
    P(cpu_has_tsc_ratio, "TSC Rate MSR");
#undef P

    if ( !printed )
        printk(" - none\n");

    svm_function_table.hap_supported = !!cpu_has_svm_npt;
    svm_function_table.hap_capabilities = HVM_HAP_SUPERPAGE_2MB |
        ((cpuid_edx(0x80000001) & 0x04000000) ? HVM_HAP_SUPERPAGE_1GB : 0);

    return &svm_function_table;
}

static void svm_do_nested_pgfault(struct vcpu *v,
    struct cpu_user_regs *regs, uint64_t pfec, paddr_t gpa)
{
    int ret;
    unsigned long gfn = gpa >> PAGE_SHIFT;
    mfn_t mfn;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    struct p2m_domain *p2m = NULL;

    /*
     * Since HW doesn't explicitly provide a read access bit and we need to
     * somehow describe read-modify-write instructions we will conservatively
     * set read_access for all memory accesses that are not instruction fetches.
     */
    struct npfec npfec = {
        .read_access = !(pfec & PFEC_insn_fetch),
        .write_access = !!(pfec & PFEC_write_access),
        .insn_fetch = !!(pfec & PFEC_insn_fetch),
        .present = !!(pfec & PFEC_page_present),
    };

    /* These bits are mutually exclusive */
    if ( pfec & NPT_PFEC_with_gla )
        npfec.kind = npfec_kind_with_gla;
    else if ( pfec & NPT_PFEC_in_gpt )
        npfec.kind = npfec_kind_in_gpt;

    ret = hvm_hap_nested_page_fault(gpa, ~0ul, npfec);

    if ( tb_init_done )
    {
        struct {
            uint64_t gpa;
            uint64_t mfn;
            uint32_t qualification;
            uint32_t p2mt;
        } _d;

        p2m = p2m_get_p2m(v);
        _d.gpa = gpa;
        _d.qualification = 0;
        mfn = __get_gfn_type_access(p2m, gfn, &_d.p2mt, &p2ma, 0, NULL, 0);
        _d.mfn = mfn_x(mfn);
        
        __trace_var(TRC_HVM_NPF, 0, sizeof(_d), &_d);
    }

    switch (ret) {
    case 0:
        break;
    case 1:
        return;
    case -1:
        ASSERT(nestedhvm_enabled(v->domain) && nestedhvm_vcpu_in_guestmode(v));
        /* inject #VMEXIT(NPF) into guest. */
        nestedsvm_vmexit_defer(v, VMEXIT_NPF, pfec, gpa);
        return;
    }

    if ( p2m == NULL )
        p2m = p2m_get_p2m(v);
    /* Everything else is an error. */
    mfn = __get_gfn_type_access(p2m, gfn, &p2mt, &p2ma, 0, NULL, 0);
    gdprintk(XENLOG_ERR,
         "SVM violation gpa %#"PRIpaddr", mfn %#lx, type %i\n",
         gpa, mfn_x(mfn), p2mt);
    domain_crash(v->domain);
}

static void svm_fpu_dirty_intercept(void)
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct vmcb_struct *n1vmcb = vcpu_nestedhvm(v).nv_n1vmcx;

    svm_fpu_enter(v);

    if ( vmcb != n1vmcb )
    {
       /* Check if l1 guest must make FPU ready for the l2 guest */
       if ( v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS )
           hvm_inject_hw_exception(TRAP_no_device, HVM_DELIVER_NO_ERROR_CODE);
       else
           vmcb_set_cr0(n1vmcb, vmcb_get_cr0(n1vmcb) & ~X86_CR0_TS);
       return;
    }

    if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
        vmcb_set_cr0(vmcb, vmcb_get_cr0(vmcb) & ~X86_CR0_TS);
}

static void svm_cpuid_intercept(
    unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx)
{
    unsigned int input = *eax;
    struct vcpu *v = current;

    hvm_cpuid(input, eax, ebx, ecx, edx);

    switch (input) {
    case 0x8000001c: 
    {
        /* LWP capability CPUID */
        uint64_t lwp_cfg = v->arch.hvm_svm.guest_lwp_cfg;

        if ( cpu_has_lwp )
        {
            if ( !(v->arch.xcr0 & XSTATE_LWP) )
           {
                *eax = 0x0;
                break;
            }

            /* turn on available bit and other features specified in lwp_cfg */
            *eax = (*edx & lwp_cfg) | 0x00000001;
        }
        break;
    }
    default:
        break;
    }

    HVMTRACE_5D (CPUID, input, *eax, *ebx, *ecx, *edx);
}

static void svm_vmexit_do_cpuid(struct cpu_user_regs *regs)
{
    unsigned int eax, ebx, ecx, edx, inst_len;

    if ( (inst_len = __get_instruction_length(current, INSTR_CPUID)) == 0 )
        return;

    eax = regs->eax;
    ebx = regs->ebx;
    ecx = regs->ecx;
    edx = regs->edx;

    svm_cpuid_intercept(&eax, &ebx, &ecx, &edx);

    regs->eax = eax;
    regs->ebx = ebx;
    regs->ecx = ecx;
    regs->edx = edx;

    __update_guest_eip(regs, inst_len);
}

static void svm_vmexit_do_cr_access(
    struct vmcb_struct *vmcb, struct cpu_user_regs *regs)
{
    int gp, cr, dir, rc;

    cr = vmcb->exitcode - VMEXIT_CR0_READ;
    dir = (cr > 15);
    cr &= 0xf;
    gp = vmcb->exitinfo1 & 0xf;

    rc = dir ? hvm_mov_to_cr(cr, gp) : hvm_mov_from_cr(cr, gp);

    if ( rc == X86EMUL_OKAY )
        __update_guest_eip(regs, vmcb->nextrip - vmcb->rip);
}

static void svm_dr_access(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = vcpu_nestedhvm(v).nv_n1vmcx;

    HVMTRACE_0D(DR_WRITE);
    __restore_debug_registers(vmcb, v);
}

static int svm_msr_read_intercept(unsigned int msr, uint64_t *msr_content)
{
    int ret;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    switch ( msr )
    {
        unsigned int ecx;

    case MSR_IA32_SYSENTER_CS:
        *msr_content = v->arch.hvm_svm.guest_sysenter_cs;
        break;
    case MSR_IA32_SYSENTER_ESP:
        *msr_content = v->arch.hvm_svm.guest_sysenter_esp;
        break;
    case MSR_IA32_SYSENTER_EIP:
        *msr_content = v->arch.hvm_svm.guest_sysenter_eip;
        break;

    case MSR_IA32_MCx_MISC(4): /* Threshold register */
    case MSR_F10_MC4_MISC1 ... MSR_F10_MC4_MISC3:
        /*
         * MCA/MCE: We report that the threshold register is unavailable
         * for OS use (locked by the BIOS).
         */
        *msr_content = 1ULL << 61; /* MC4_MISC.Locked */
        break;

    case MSR_IA32_EBC_FREQUENCY_ID:
        /*
         * This Intel-only register may be accessed if this HVM guest
         * has been migrated from an Intel host. The value zero is not
         * particularly meaningful, but at least avoids the guest crashing!
         */
        *msr_content = 0;
        break;

    case MSR_IA32_DEBUGCTLMSR:
        *msr_content = vmcb_get_debugctlmsr(vmcb);
        break;

    case MSR_IA32_LASTBRANCHFROMIP:
        *msr_content = vmcb_get_lastbranchfromip(vmcb);
        break;

    case MSR_IA32_LASTBRANCHTOIP:
        *msr_content = vmcb_get_lastbranchtoip(vmcb);
        break;

    case MSR_IA32_LASTINTFROMIP:
        *msr_content = vmcb_get_lastintfromip(vmcb);
        break;

    case MSR_IA32_LASTINTTOIP:
        *msr_content = vmcb_get_lastinttoip(vmcb);
        break;

    case MSR_AMD64_LWP_CFG:
        *msr_content = v->arch.hvm_svm.guest_lwp_cfg;
        break;

    case MSR_K7_PERFCTR0:
    case MSR_K7_PERFCTR1:
    case MSR_K7_PERFCTR2:
    case MSR_K7_PERFCTR3:
    case MSR_K7_EVNTSEL0:
    case MSR_K7_EVNTSEL1:
    case MSR_K7_EVNTSEL2:
    case MSR_K7_EVNTSEL3:
    case MSR_AMD_FAM15H_PERFCTR0:
    case MSR_AMD_FAM15H_PERFCTR1:
    case MSR_AMD_FAM15H_PERFCTR2:
    case MSR_AMD_FAM15H_PERFCTR3:
    case MSR_AMD_FAM15H_PERFCTR4:
    case MSR_AMD_FAM15H_PERFCTR5:
    case MSR_AMD_FAM15H_EVNTSEL0:
    case MSR_AMD_FAM15H_EVNTSEL1:
    case MSR_AMD_FAM15H_EVNTSEL2:
    case MSR_AMD_FAM15H_EVNTSEL3:
    case MSR_AMD_FAM15H_EVNTSEL4:
    case MSR_AMD_FAM15H_EVNTSEL5:
        if ( vpmu_do_rdmsr(msr, msr_content) )
            goto gpf;
        break;

    case MSR_AMD64_DR0_ADDRESS_MASK:
        hvm_cpuid(0x80000001, NULL, NULL, &ecx, NULL);
        if ( !test_bit(X86_FEATURE_DBEXT & 31, &ecx) )
            goto gpf;
        *msr_content = v->arch.hvm_svm.dr_mask[0];
        break;

    case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
        hvm_cpuid(0x80000001, NULL, NULL, &ecx, NULL);
        if ( !test_bit(X86_FEATURE_DBEXT & 31, &ecx) )
            goto gpf;
        *msr_content =
            v->arch.hvm_svm.dr_mask[msr - MSR_AMD64_DR1_ADDRESS_MASK + 1];
        break;

    case MSR_AMD_OSVW_ID_LENGTH:
    case MSR_AMD_OSVW_STATUS:
        ret = svm_handle_osvw(v, msr, msr_content, 1);
        if ( ret < 0 )
            goto gpf;
        break;

    default:
        ret = nsvm_rdmsr(v, msr, msr_content);
        if ( ret < 0 )
            goto gpf;
        else if ( ret )
            break;

        if ( rdmsr_viridian_regs(msr, msr_content) ||
             rdmsr_hypervisor_regs(msr, msr_content) )
            break;

        if ( rdmsr_safe(msr, *msr_content) == 0 )
            break;

        if ( boot_cpu_data.x86 == 0xf && msr == MSR_F10_BU_CFG )
        {
            /* Win2k8 x64 reads this MSR on revF chips, where it
             * wasn't publically available; it uses a magic constant
             * in %rdi as a password, which we don't have in
             * rdmsr_safe().  Since we'll ignore the later writes,
             * just use a plausible value here (the reset value from
             * rev10h chips) if the real CPU didn't provide one. */
            *msr_content = 0x0000000010200020ull;
            break;
        }

        goto gpf;
    }

    HVM_DBG_LOG(DBG_LEVEL_MSR, "returns: ecx=%x, msr_value=%"PRIx64,
                msr, *msr_content);
    return X86EMUL_OKAY;

 gpf:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

static int svm_msr_write_intercept(unsigned int msr, uint64_t msr_content)
{
    int ret, result = X86EMUL_OKAY;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int sync = 0;

    switch ( msr )
    {
    case MSR_IA32_SYSENTER_CS:
    case MSR_IA32_SYSENTER_ESP:
    case MSR_IA32_SYSENTER_EIP:
        sync = 1;
        break;
    default:
        break;
    }

    if ( sync )
        svm_sync_vmcb(v);    

    switch ( msr )
    {
        unsigned int ecx;

    case MSR_IA32_SYSENTER_CS:
        vmcb->sysenter_cs = v->arch.hvm_svm.guest_sysenter_cs = msr_content;
        break;
    case MSR_IA32_SYSENTER_ESP:
        vmcb->sysenter_esp = v->arch.hvm_svm.guest_sysenter_esp = msr_content;
        break;
    case MSR_IA32_SYSENTER_EIP:
        vmcb->sysenter_eip = v->arch.hvm_svm.guest_sysenter_eip = msr_content;
        break;

    case MSR_IA32_DEBUGCTLMSR:
        vmcb_set_debugctlmsr(vmcb, msr_content);
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
        vmcb_set_lastbranchfromip(vmcb, msr_content);
        break;

    case MSR_IA32_LASTBRANCHTOIP:
        vmcb_set_lastbranchtoip(vmcb, msr_content);
        break;

    case MSR_IA32_LASTINTFROMIP:
        vmcb_set_lastintfromip(vmcb, msr_content);
        break;

    case MSR_IA32_LASTINTTOIP:
        vmcb_set_lastinttoip(vmcb, msr_content);
        break;

    case MSR_AMD64_LWP_CFG:
        if ( svm_update_lwp_cfg(v, msr_content) < 0 )
            goto gpf;
        break;

    case MSR_K7_PERFCTR0:
    case MSR_K7_PERFCTR1:
    case MSR_K7_PERFCTR2:
    case MSR_K7_PERFCTR3:
    case MSR_K7_EVNTSEL0:
    case MSR_K7_EVNTSEL1:
    case MSR_K7_EVNTSEL2:
    case MSR_K7_EVNTSEL3:
    case MSR_AMD_FAM15H_PERFCTR0:
    case MSR_AMD_FAM15H_PERFCTR1:
    case MSR_AMD_FAM15H_PERFCTR2:
    case MSR_AMD_FAM15H_PERFCTR3:
    case MSR_AMD_FAM15H_PERFCTR4:
    case MSR_AMD_FAM15H_PERFCTR5:
    case MSR_AMD_FAM15H_EVNTSEL0:
    case MSR_AMD_FAM15H_EVNTSEL1:
    case MSR_AMD_FAM15H_EVNTSEL2:
    case MSR_AMD_FAM15H_EVNTSEL3:
    case MSR_AMD_FAM15H_EVNTSEL4:
    case MSR_AMD_FAM15H_EVNTSEL5:
        if ( vpmu_do_wrmsr(msr, msr_content, 0) )
            goto gpf;
        break;

    case MSR_IA32_MCx_MISC(4): /* Threshold register */
    case MSR_F10_MC4_MISC1 ... MSR_F10_MC4_MISC3:
        /*
         * MCA/MCE: Threshold register is reported to be locked, so we ignore
         * all write accesses. This behaviour matches real HW, so guests should
         * have no problem with this.
         */
        break;

    case MSR_AMD64_DR0_ADDRESS_MASK:
        hvm_cpuid(0x80000001, NULL, NULL, &ecx, NULL);
        if ( !test_bit(X86_FEATURE_DBEXT & 31, &ecx) || (msr_content >> 32) )
            goto gpf;
        v->arch.hvm_svm.dr_mask[0] = msr_content;
        break;

    case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
        hvm_cpuid(0x80000001, NULL, NULL, &ecx, NULL);
        if ( !test_bit(X86_FEATURE_DBEXT & 31, &ecx) || (msr_content >> 32) )
            goto gpf;
        v->arch.hvm_svm.dr_mask[msr - MSR_AMD64_DR1_ADDRESS_MASK + 1] =
            msr_content;
        break;

    case MSR_AMD_OSVW_ID_LENGTH:
    case MSR_AMD_OSVW_STATUS:
        ret = svm_handle_osvw(v, msr, &msr_content, 0);
        if ( ret < 0 )
            goto gpf;
        break;

    default:
        ret = nsvm_wrmsr(v, msr, msr_content);
        if ( ret < 0 )
            goto gpf;
        else if ( ret )
            break;

        if ( wrmsr_viridian_regs(msr, msr_content) )
            break;

        switch ( wrmsr_hypervisor_regs(msr, msr_content) )
        {
        case -ERESTART:
            result = X86EMUL_RETRY;
            break;
        case 0:
        case 1:
            break;
        default:
            goto gpf;
        }
        break;
    }

    if ( sync )
        svm_vmload(vmcb);

    return result;

 gpf:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

static void svm_do_msr_access(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    bool rdmsr = curr->arch.hvm_svm.vmcb->exitinfo1 == 0;
    int rc, inst_len = __get_instruction_length(
        curr, rdmsr ? INSTR_RDMSR : INSTR_WRMSR);

    if ( inst_len == 0 )
        return;

    if ( rdmsr )
    {
        uint64_t msr_content = 0;

        rc = hvm_msr_read_intercept(regs->_ecx, &msr_content);
        if ( rc == X86EMUL_OKAY )
        {
            regs->rax = (uint32_t)msr_content;
            regs->rdx = (uint32_t)(msr_content >> 32);
        }
    }
    else
        rc = hvm_msr_write_intercept(regs->_ecx,
                                     (regs->rdx << 32) | regs->_eax, 1);

    if ( rc == X86EMUL_OKAY )
        __update_guest_eip(regs, inst_len);
}

static void svm_vmexit_do_hlt(struct vmcb_struct *vmcb,
                              struct cpu_user_regs *regs)
{
    unsigned int inst_len;

    if ( (inst_len = __get_instruction_length(current, INSTR_HLT)) == 0 )
        return;
    __update_guest_eip(regs, inst_len);

    hvm_hlt(regs->eflags);
}

static void svm_vmexit_do_rdtsc(struct cpu_user_regs *regs)
{
    unsigned int inst_len;

    if ( (inst_len = __get_instruction_length(current, INSTR_RDTSC)) == 0 )
        return;
    __update_guest_eip(regs, inst_len);

    hvm_rdtsc_intercept(regs);
}

static void svm_vmexit_do_pause(struct cpu_user_regs *regs)
{
    unsigned int inst_len;

    if ( (inst_len = __get_instruction_length(current, INSTR_PAUSE)) == 0 )
        return;
    __update_guest_eip(regs, inst_len);

    /*
     * The guest is running a contended spinlock and we've detected it.
     * Do something useful, like reschedule the guest
     */
    perfc_incr(pauseloop_exits);
    do_sched_op(SCHEDOP_yield, guest_handle_from_ptr(NULL, void));
}

static void
svm_vmexit_do_vmrun(struct cpu_user_regs *regs,
                    struct vcpu *v, uint64_t vmcbaddr)
{
    if ( !nsvm_efer_svm_enabled(v) )
    {
        gdprintk(XENLOG_ERR, "VMRUN: nestedhvm disabled, injecting #UD\n");
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        return;
    }

    if ( !nestedsvm_vmcb_map(v, vmcbaddr) )
    {
        gdprintk(XENLOG_ERR, "VMRUN: mapping vmcb failed, injecting #GP\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return;
    }

    vcpu_nestedhvm(v).nv_vmentry_pending = 1;
    return;
}

static struct page_info *
nsvm_get_nvmcb_page(struct vcpu *v, uint64_t vmcbaddr)
{
    p2m_type_t p2mt;
    struct page_info *page;
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);

    if ( !nestedsvm_vmcb_map(v, vmcbaddr) )
        return NULL;

    /* Need to translate L1-GPA to MPA */
    page = get_page_from_gfn(v->domain, 
                            nv->nv_vvmcxaddr >> PAGE_SHIFT, 
                            &p2mt, P2M_ALLOC | P2M_UNSHARE);
    if ( !page )
        return NULL;

    if ( !p2m_is_ram(p2mt) || p2m_is_readonly(p2mt) )
    {
        put_page(page);
        return NULL; 
    }

    return  page;
}

static void
svm_vmexit_do_vmload(struct vmcb_struct *vmcb,
                     struct cpu_user_regs *regs,
                     struct vcpu *v, uint64_t vmcbaddr)
{
    unsigned int inst_len;
    struct page_info *page;

    if ( (inst_len = __get_instruction_length(v, INSTR_VMLOAD)) == 0 )
        return;

    if ( !nsvm_efer_svm_enabled(v) ) 
    {
        gdprintk(XENLOG_ERR, "VMLOAD: nestedhvm disabled, injecting #UD\n");
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        return;
    }

    page = nsvm_get_nvmcb_page(v, vmcbaddr);
    if ( !page )
    {
        gdprintk(XENLOG_ERR,
            "VMLOAD: mapping failed, injecting #GP\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return;
    }

    svm_vmload_pa(page_to_maddr(page));
    put_page(page);

    /* State in L1 VMCB is stale now */
    v->arch.hvm_svm.vmcb_in_sync = 0;

    __update_guest_eip(regs, inst_len);
}

static void
svm_vmexit_do_vmsave(struct vmcb_struct *vmcb,
                     struct cpu_user_regs *regs,
                     struct vcpu *v, uint64_t vmcbaddr)
{
    unsigned int inst_len;
    struct page_info *page;

    if ( (inst_len = __get_instruction_length(v, INSTR_VMSAVE)) == 0 )
        return;

    if ( !nsvm_efer_svm_enabled(v) ) 
    {
        gdprintk(XENLOG_ERR, "VMSAVE: nestedhvm disabled, injecting #UD\n");
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        return;
    }

    page = nsvm_get_nvmcb_page(v, vmcbaddr);
    if ( !page )
    {
        gdprintk(XENLOG_ERR,
            "VMSAVE: mapping vmcb failed, injecting #GP\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return;
    }

    svm_vmsave_pa(page_to_maddr(page));
    put_page(page);
    __update_guest_eip(regs, inst_len);
}

static int svm_is_erratum_383(struct cpu_user_regs *regs)
{
    uint64_t msr_content;
    uint32_t i;
    struct vcpu *v = current;

    if ( !amd_erratum383_found )
        return 0;

    rdmsrl(MSR_IA32_MC0_STATUS, msr_content);
    /* Bit 62 may or may not be set for this mce */
    msr_content &= ~(1ULL << 62);

    if ( msr_content != 0xb600000000010015ULL )
        return 0;
    
    /* Clear MCi_STATUS registers */
    for (i = 0; i < nr_mce_banks; i++)
        wrmsrl(MSR_IA32_MCx_STATUS(i), 0ULL);
    
    rdmsrl(MSR_IA32_MCG_STATUS, msr_content);
    wrmsrl(MSR_IA32_MCG_STATUS, msr_content & ~(1ULL << 2));

    /* flush TLB */
    flush_tlb_mask(v->domain->domain_dirty_cpumask);

    return 1;
}

static void svm_vmexit_mce_intercept(
    struct vcpu *v, struct cpu_user_regs *regs)
{
    if ( svm_is_erratum_383(regs) )
    {
        gdprintk(XENLOG_ERR, "SVM hits AMD erratum 383\n");
        domain_crash(v->domain);
    }
}

static void svm_wbinvd_intercept(void)
{
    if ( cache_flush_permitted(current->domain) )
        flush_all(FLUSH_CACHE);
}

static void svm_vmexit_do_invalidate_cache(struct cpu_user_regs *regs)
{
    static const enum instruction_index list[] = { INSTR_INVD, INSTR_WBINVD };
    int inst_len;

    inst_len = __get_instruction_length_from_list(
        current, list, ARRAY_SIZE(list));
    if ( inst_len == 0 )
        return;

    svm_wbinvd_intercept();

    __update_guest_eip(regs, inst_len);
}

static void svm_invlpga_intercept(
    struct vcpu *v, unsigned long vaddr, uint32_t asid)
{
    svm_invlpga(vaddr,
                (asid == 0)
                ? v->arch.hvm_vcpu.n1asid.asid
                : vcpu_nestedhvm(v).nv_n2asid.asid);
}

static void svm_invlpg_intercept(unsigned long vaddr)
{
    HVMTRACE_LONG_2D(INVLPG, 0, TRC_PAR_LONG(vaddr));
    paging_invlpg(current, vaddr);
}

static void svm_invlpg(struct vcpu *v, unsigned long vaddr)
{
    svm_asid_g_invlpg(v, vaddr);
}

static struct hvm_function_table __initdata svm_function_table = {
    .name                 = "SVM",
    .cpu_up_prepare       = svm_cpu_up_prepare,
    .cpu_dead             = svm_cpu_dead,
    .cpu_up               = svm_cpu_up,
    .cpu_down             = svm_cpu_down,
    .domain_initialise    = svm_domain_initialise,
    .domain_destroy       = svm_domain_destroy,
    .vcpu_initialise      = svm_vcpu_initialise,
    .vcpu_destroy         = svm_vcpu_destroy,
    .save_cpu_ctxt        = svm_save_vmcb_ctxt,
    .load_cpu_ctxt        = svm_load_vmcb_ctxt,
    .init_msr             = svm_init_msr,
    .save_msr             = svm_save_msr,
    .load_msr             = svm_load_msr,
    .get_interrupt_shadow = svm_get_interrupt_shadow,
    .set_interrupt_shadow = svm_set_interrupt_shadow,
    .guest_x86_mode       = svm_guest_x86_mode,
    .get_segment_register = svm_get_segment_register,
    .set_segment_register = svm_set_segment_register,
    .get_shadow_gs_base   = svm_get_shadow_gs_base,
    .update_guest_cr      = svm_update_guest_cr,
    .update_guest_efer    = svm_update_guest_efer,
    .update_guest_vendor  = svm_update_guest_vendor,
    .set_guest_pat        = svm_set_guest_pat,
    .get_guest_pat        = svm_get_guest_pat,
    .set_tsc_offset       = svm_set_tsc_offset,
    .inject_trap          = svm_inject_trap,
    .init_hypercall_page  = svm_init_hypercall_page,
    .event_pending        = svm_event_pending,
    .invlpg               = svm_invlpg,
    .cpuid_intercept      = svm_cpuid_intercept,
    .wbinvd_intercept     = svm_wbinvd_intercept,
    .fpu_dirty_intercept  = svm_fpu_dirty_intercept,
    .msr_read_intercept   = svm_msr_read_intercept,
    .msr_write_intercept  = svm_msr_write_intercept,
    .set_rdtsc_exiting    = svm_set_rdtsc_exiting,
    .get_insn_bytes       = svm_get_insn_bytes,

    .nhvm_vcpu_initialise = nsvm_vcpu_initialise,
    .nhvm_vcpu_destroy = nsvm_vcpu_destroy,
    .nhvm_vcpu_reset = nsvm_vcpu_reset,
    .nhvm_vcpu_vmexit_trap = nsvm_vcpu_vmexit_trap,
    .nhvm_vcpu_p2m_base = nsvm_vcpu_hostcr3,
    .nhvm_vmcx_guest_intercepts_trap = nsvm_vmcb_guest_intercepts_trap,
    .nhvm_vmcx_hap_enabled = nsvm_vmcb_hap_enabled,
    .nhvm_intr_blocked = nsvm_intr_blocked,
    .nhvm_hap_walk_L1_p2m = nsvm_hap_walk_L1_p2m,

    .tsc_scaling = {
        .max_ratio = ~TSC_RATIO_RSVD_BITS,
    },
};

void svm_vmexit_handler(struct cpu_user_regs *regs)
{
    uint64_t exit_reason;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    eventinj_t eventinj;
    int inst_len, rc;
    vintr_t intr;
    bool_t vcpu_guestmode = 0;
    struct vlapic *vlapic = vcpu_vlapic(v);

    hvm_invalidate_regs_fields(regs);

    if ( paging_mode_hap(v->domain) )
        v->arch.hvm_vcpu.guest_cr[3] = v->arch.hvm_vcpu.hw_cr[3] =
            vmcb_get_cr3(vmcb);

    if ( nestedhvm_enabled(v->domain) && nestedhvm_vcpu_in_guestmode(v) )
        vcpu_guestmode = 1;

    /*
     * Before doing anything else, we need to sync up the VLAPIC's TPR with
     * SVM's vTPR. It's OK if the guest doesn't touch CR8 (e.g. 32-bit Windows)
     * because we update the vTPR on MMIO writes to the TPR.
     * NB. We need to preserve the low bits of the TPR to make checked builds
     * of Windows work, even though they don't actually do anything.
     */
    if ( !vcpu_guestmode && !vlapic_hw_disabled(vlapic) )
    {
        intr = vmcb_get_vintr(vmcb);
        vlapic_set_reg(vlapic, APIC_TASKPRI,
                   ((intr.fields.tpr & 0x0F) << 4) |
                   (vlapic_get_reg(vlapic, APIC_TASKPRI) & 0x0F));
    }

    exit_reason = vmcb->exitcode;

    if ( hvm_long_mode_enabled(v) )
        HVMTRACE_ND(VMEXIT64, vcpu_guestmode ? TRC_HVM_NESTEDFLAG : 0,
                    1/*cycles*/, 3, exit_reason,
                    (uint32_t)regs->eip, (uint32_t)((uint64_t)regs->eip >> 32),
                    0, 0, 0);
    else
        HVMTRACE_ND(VMEXIT, vcpu_guestmode ? TRC_HVM_NESTEDFLAG : 0,
                    1/*cycles*/, 2, exit_reason,
                    (uint32_t)regs->eip,
                    0, 0, 0, 0);

    if ( vcpu_guestmode ) {
        enum nestedhvm_vmexits nsret;
        struct nestedvcpu *nv = &vcpu_nestedhvm(v);
        struct vmcb_struct *ns_vmcb = nv->nv_vvmcx;
        uint64_t exitinfo1, exitinfo2;

        paging_update_nestedmode(v);

        /* Write real exitinfo1 back into virtual vmcb.
         * nestedsvm_check_intercepts() expects to have the correct
         * exitinfo1 value there.
         */
        exitinfo1 = ns_vmcb->exitinfo1;
        ns_vmcb->exitinfo1 = vmcb->exitinfo1;
        nsret = nestedsvm_check_intercepts(v, regs, exit_reason);
        switch (nsret) {
        case NESTEDHVM_VMEXIT_CONTINUE:
            BUG();
            break;
        case NESTEDHVM_VMEXIT_HOST:
            break;
        case NESTEDHVM_VMEXIT_INJECT:
            /* Switch vcpu from l2 to l1 guest. We must perform
             * the switch here to have svm_do_resume() working
             * as intended.
             */
            exitinfo1 = vmcb->exitinfo1;
            exitinfo2 = vmcb->exitinfo2;
            nv->nv_vmswitch_in_progress = 1;
            nsret = nestedsvm_vmexit_n2n1(v, regs);
            nv->nv_vmswitch_in_progress = 0;
            switch (nsret) {
            case NESTEDHVM_VMEXIT_DONE:
                /* defer VMEXIT injection */
                nestedsvm_vmexit_defer(v, exit_reason, exitinfo1, exitinfo2);
                goto out;
            case NESTEDHVM_VMEXIT_FATALERROR:
                gdprintk(XENLOG_ERR, "unexpected nestedsvm_vmexit() error\n");
                domain_crash(v->domain);
                goto out;
            default:
                BUG();
            case NESTEDHVM_VMEXIT_ERROR:
                break;
            }
            /* fallthrough */
        case NESTEDHVM_VMEXIT_ERROR:
            gdprintk(XENLOG_ERR,
                "nestedsvm_check_intercepts() returned NESTEDHVM_VMEXIT_ERROR\n");
            goto out;
        case NESTEDHVM_VMEXIT_FATALERROR:
            gdprintk(XENLOG_ERR,
                "unexpected nestedsvm_check_intercepts() error\n");
            domain_crash(v->domain);
            goto out;
        default:
            gdprintk(XENLOG_INFO, "nestedsvm_check_intercepts() returned %i\n",
                nsret);
            domain_crash(v->domain);
            goto out;
        }
    }

    if ( unlikely(exit_reason == VMEXIT_INVALID) )
    {
        gdprintk(XENLOG_ERR, "invalid VMCB state:\n");
        svm_vmcb_dump(__func__, vmcb);
        domain_crash(v->domain);
        goto out;
    }

    perfc_incra(svmexits, exit_reason);

    hvm_maybe_deassert_evtchn_irq();

    vmcb->cleanbits.bytes = cpu_has_svm_cleanbits ? ~0u : 0u;

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
        HVMTRACE_0D(INTR);
        break;

    case VMEXIT_NMI:
        /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
        HVMTRACE_0D(NMI);
        break;

    case VMEXIT_SMI:
        /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
        HVMTRACE_0D(SMI);
        break;

    case VMEXIT_EXCEPTION_DB:
        if ( !v->domain->debugger_attached )
            hvm_inject_hw_exception(TRAP_debug, HVM_DELIVER_NO_ERROR_CODE);
        else
            domain_pause_for_debugger();
        break;

    case VMEXIT_EXCEPTION_BP:
        if ( !v->domain->debugger_attached )
            goto unexpected_exit_type;
        /* AMD Vol2, 15.11: INT3, INTO, BOUND intercepts do not update RIP. */
        if ( (inst_len = __get_instruction_length(v, INSTR_INT3)) == 0 )
            break;
        __update_guest_eip(regs, inst_len);
        current->arch.gdbsx_vcpu_event = TRAP_int3;
        domain_pause_for_debugger();
        break;

    case VMEXIT_EXCEPTION_NM:
        svm_fpu_dirty_intercept();
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

        if ( cpu_has_svm_decode )
            v->arch.hvm_svm.cached_insn_len = vmcb->guest_ins_len & 0xf;
        rc = paging_fault(va, regs);
        v->arch.hvm_svm.cached_insn_len = 0;

        if ( rc )
        {
            if ( trace_will_trace_event(TRC_SHADOW) )
                break;
            if ( hvm_long_mode_enabled(v) )
                HVMTRACE_LONG_2D(PF_XEN, regs->error_code, TRC_PAR_LONG(va));
            else
                HVMTRACE_2D(PF_XEN, regs->error_code, va);
            break;
        }

        hvm_inject_page_fault(regs->error_code, va);
        break;
    }

    case VMEXIT_EXCEPTION_AC:
        HVMTRACE_1D(TRAP, TRAP_alignment_check);
        hvm_inject_hw_exception(TRAP_alignment_check, vmcb->exitinfo1);
        break;

    case VMEXIT_EXCEPTION_UD:
        hvm_ud_intercept(regs);
        break;

    /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
    case VMEXIT_EXCEPTION_MC:
        HVMTRACE_0D(MCE);
        svm_vmexit_mce_intercept(v, regs);
        break;

    case VMEXIT_VINTR: {
        u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);
        intr = vmcb_get_vintr(vmcb);

        intr.fields.irq = 0;
        general1_intercepts &= ~GENERAL1_INTERCEPT_VINTR;

        vmcb_set_vintr(vmcb, intr);
        vmcb_set_general1_intercepts(vmcb, general1_intercepts);
        break;
    }

    case VMEXIT_INVD:
    case VMEXIT_WBINVD:
        svm_vmexit_do_invalidate_cache(regs);
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

        /*
         * Some processors set the EXITINTINFO field when the task switch
         * is caused by a task gate in the IDT. In this case we will be
         * emulating the event injection, so we do not want the processor
         * to re-inject the original event!
         */
        vmcb->eventinj.bytes = 0;

        hvm_task_switch((uint16_t)vmcb->exitinfo1, reason, errcode);
        break;
    }

    case VMEXIT_CPUID:
        svm_vmexit_do_cpuid(regs);
        break;

    case VMEXIT_HLT:
        svm_vmexit_do_hlt(vmcb, regs);
        break;

    case VMEXIT_IOIO:
        if ( (vmcb->exitinfo1 & (1u<<2)) == 0 )
        {
            uint16_t port = (vmcb->exitinfo1 >> 16) & 0xFFFF;
            int bytes = ((vmcb->exitinfo1 >> 4) & 0x07);
            int dir = (vmcb->exitinfo1 & 1) ? IOREQ_READ : IOREQ_WRITE;
            if ( handle_pio(port, bytes, dir) )
                __update_guest_eip(regs, vmcb->exitinfo2 - vmcb->rip);
        }
        else if ( !handle_mmio() )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case VMEXIT_CR0_READ ... VMEXIT_CR15_READ:
    case VMEXIT_CR0_WRITE ... VMEXIT_CR15_WRITE:
        if ( cpu_has_svm_decode && (vmcb->exitinfo1 & (1ULL << 63)) )
            svm_vmexit_do_cr_access(vmcb, regs);
        else if ( !handle_mmio() ) 
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case VMEXIT_INVLPG:
        if ( cpu_has_svm_decode )
        {
            svm_invlpg_intercept(vmcb->exitinfo1);
            __update_guest_eip(regs, vmcb->nextrip - vmcb->rip);
        }
        else if ( !handle_mmio() )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case VMEXIT_INVLPGA:
        if ( (inst_len = __get_instruction_length(v, INSTR_INVLPGA)) == 0 )
            break;
        svm_invlpga_intercept(v, regs->eax, regs->ecx);
        __update_guest_eip(regs, inst_len);
        break;

    case VMEXIT_VMMCALL:
        if ( (inst_len = __get_instruction_length(v, INSTR_VMCALL)) == 0 )
            break;
        BUG_ON(vcpu_guestmode);
        HVMTRACE_1D(VMMCALL, regs->eax);
        rc = hvm_do_hypercall(regs);
        if ( rc != HVM_HCALL_preempted )
        {
            __update_guest_eip(regs, inst_len);
            if ( rc == HVM_HCALL_invalidate )
                send_invalidate_req();
        }
        break;

    case VMEXIT_DR0_READ ... VMEXIT_DR7_READ:
    case VMEXIT_DR0_WRITE ... VMEXIT_DR7_WRITE:
        svm_dr_access(v, regs);
        break;

    case VMEXIT_MSR:
        svm_do_msr_access(regs);
        break;

    case VMEXIT_SHUTDOWN:
        hvm_triple_fault();
        break;

    case VMEXIT_RDTSCP:
        regs->ecx = hvm_msr_tsc_aux(v);
        /* fall through */
    case VMEXIT_RDTSC:
        svm_vmexit_do_rdtsc(regs);
        break;

    case VMEXIT_MONITOR:
    case VMEXIT_MWAIT:
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;

    case VMEXIT_VMRUN:
        svm_vmexit_do_vmrun(regs, v, regs->eax);
        break;
    case VMEXIT_VMLOAD:
        svm_vmexit_do_vmload(vmcb, regs, v, regs->eax);
        break;
    case VMEXIT_VMSAVE:
        svm_vmexit_do_vmsave(vmcb, regs, v, regs->eax);
        break;
    case VMEXIT_STGI:
        svm_vmexit_do_stgi(regs, v);
        break;
    case VMEXIT_CLGI:
        svm_vmexit_do_clgi(regs, v);
        break;
    case VMEXIT_SKINIT:
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;

    case VMEXIT_XSETBV:
        if ( vmcb_get_cpl(vmcb) )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        else if ( (inst_len = __get_instruction_length(v, INSTR_XSETBV)) &&
                  hvm_handle_xsetbv(regs->ecx,
                                    (regs->rdx << 32) | regs->_eax) == 0 )
            __update_guest_eip(regs, inst_len);
        break;

    case VMEXIT_NPF:
        perfc_incra(svmexits, VMEXIT_NPF_PERFC);
        if ( cpu_has_svm_decode )
            v->arch.hvm_svm.cached_insn_len = vmcb->guest_ins_len & 0xf;
        rc = vmcb->exitinfo1 & PFEC_page_present
             ? p2m_pt_handle_deferred_changes(vmcb->exitinfo2) : 0;
        if ( rc >= 0 )
            svm_do_nested_pgfault(v, regs, vmcb->exitinfo1, vmcb->exitinfo2);
        else
        {
            printk(XENLOG_G_ERR
                   "%pv: Error %d handling NPF (gpa=%08lx ec=%04lx)\n",
                   v, rc, vmcb->exitinfo2, vmcb->exitinfo1);
            domain_crash(v->domain);
        }
        v->arch.hvm_svm.cached_insn_len = 0;
        break;

    case VMEXIT_IRET: {
        u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);

        /*
         * IRET clears the NMI mask. However because we clear the mask
         * /before/ executing IRET, we set the interrupt shadow to prevent
         * a pending NMI from being injected immediately. This will work
         * perfectly unless the IRET instruction faults: in that case we
         * may inject an NMI before the NMI handler's IRET instruction is
         * retired.
         */
        general1_intercepts &= ~GENERAL1_INTERCEPT_IRET;
        vmcb->interrupt_shadow = 1;

        vmcb_set_general1_intercepts(vmcb, general1_intercepts);
        break;
    }

    case VMEXIT_PAUSE:
        svm_vmexit_do_pause(regs);
        break;

    default:
    unexpected_exit_type:
        gdprintk(XENLOG_ERR, "unexpected VMEXIT: exit reason = %#"PRIx64", "
                 "exitinfo1 = %#"PRIx64", exitinfo2 = %#"PRIx64"\n",
                 exit_reason, 
                 (u64)vmcb->exitinfo1, (u64)vmcb->exitinfo2);
        svm_crash_or_fault(v);
        break;
    }

  out:
    if ( vcpu_guestmode || vlapic_hw_disabled(vlapic) )
        return;

    /* The exit may have updated the TPR: reflect this in the hardware vtpr */
    intr = vmcb_get_vintr(vmcb);
    intr.fields.tpr =
        (vlapic_get_reg(vlapic, APIC_TASKPRI) & 0xFF) >> 4;
    vmcb_set_vintr(vmcb, intr);
}

void svm_trace_vmentry(void)
{
    struct vcpu *curr = current;
    HVMTRACE_ND(VMENTRY,
                nestedhvm_vcpu_in_guestmode(curr) ? TRC_HVM_NESTEDFLAG : 0,
                1/*cycles*/, 0, 0, 0, 0, 0, 0, 0);
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
