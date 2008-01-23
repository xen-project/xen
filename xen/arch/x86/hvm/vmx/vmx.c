/*
 * vmx.c: handling VMX architecture-related VM exits
 * Copyright (c) 2004, Intel Corporation.
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
#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/perfc.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/vmx/cpu.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/vpt.h>
#include <public/hvm/save.h>
#include <asm/hvm/trace.h>

enum handler_return { HNDL_done, HNDL_unhandled, HNDL_exception_raised };

static void vmx_ctxt_switch_from(struct vcpu *v);
static void vmx_ctxt_switch_to(struct vcpu *v);

static int  vmx_alloc_vlapic_mapping(struct domain *d);
static void vmx_free_vlapic_mapping(struct domain *d);
static void vmx_install_vlapic_mapping(struct vcpu *v);
static void vmx_update_guest_cr(struct vcpu *v, unsigned int cr);
static void vmx_update_guest_efer(struct vcpu *v);

static int vmx_domain_initialise(struct domain *d)
{
    return vmx_alloc_vlapic_mapping(d);
}

static void vmx_domain_destroy(struct domain *d)
{
    vmx_free_vlapic_mapping(d);
}

static int vmx_vcpu_initialise(struct vcpu *v)
{
    int rc;

    spin_lock_init(&v->arch.hvm_vmx.vmcs_lock);

    v->arch.schedule_tail    = vmx_do_resume;
    v->arch.ctxt_switch_from = vmx_ctxt_switch_from;
    v->arch.ctxt_switch_to   = vmx_ctxt_switch_to;

    if ( (rc = vmx_create_vmcs(v)) != 0 )
    {
        dprintk(XENLOG_WARNING,
                "Failed to create VMCS for vcpu %d: err=%d.\n",
                v->vcpu_id, rc);
        return rc;
    }

    vmx_install_vlapic_mapping(v);

#ifndef VMXASSIST
    if ( v->vcpu_id == 0 )
        v->arch.guest_context.user_regs.eax = 1;
    v->arch.hvm_vcpu.io_complete = vmx_realmode_io_complete;
#endif

    return 0;
}

static void vmx_vcpu_destroy(struct vcpu *v)
{
    vmx_destroy_vmcs(v);
}

#ifdef __x86_64__

static DEFINE_PER_CPU(struct vmx_msr_state, host_msr_state);

static u32 msr_index[VMX_MSR_COUNT] =
{
    MSR_LSTAR, MSR_STAR, MSR_SYSCALL_MASK
};

static void vmx_save_host_msrs(void)
{
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);
    int i;

    for ( i = 0; i < VMX_MSR_COUNT; i++ )
        rdmsrl(msr_index[i], host_msr_state->msrs[i]);
}

#define WRITE_MSR(address)                                              \
        guest_msr_state->msrs[VMX_INDEX_MSR_ ## address] = msr_content; \
        set_bit(VMX_INDEX_MSR_ ## address, &guest_msr_state->flags);    \
        wrmsrl(MSR_ ## address, msr_content);                           \
        set_bit(VMX_INDEX_MSR_ ## address, &host_msr_state->flags);     \
        break

static enum handler_return long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    u32 ecx = regs->ecx;
    struct vcpu *v = current;
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;

    switch ( ecx )
    {
    case MSR_EFER:
        msr_content = v->arch.hvm_vcpu.guest_efer;
        break;

    case MSR_FS_BASE:
        msr_content = __vmread(GUEST_FS_BASE);
        goto check_long_mode;

    case MSR_GS_BASE:
        msr_content = __vmread(GUEST_GS_BASE);
        goto check_long_mode;

    case MSR_SHADOW_GS_BASE:
        msr_content = v->arch.hvm_vmx.shadow_gs;
    check_long_mode:
        if ( !(hvm_long_mode_enabled(v)) )
        {
            vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            return HNDL_exception_raised;
        }
        break;

    case MSR_STAR:
        msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_STAR];
        break;

    case MSR_LSTAR:
        msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_LSTAR];
        break;

    case MSR_CSTAR:
        msr_content = v->arch.hvm_vmx.cstar;
        break;

    case MSR_SYSCALL_MASK:
        msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK];
        break;

    default:
        return HNDL_unhandled;
    }

    HVM_DBG_LOG(DBG_LEVEL_0, "msr 0x%x content 0x%"PRIx64, ecx, msr_content);

    regs->eax = (u32)(msr_content >>  0);
    regs->edx = (u32)(msr_content >> 32);

    return HNDL_done;
}

static enum handler_return long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content = (u32)regs->eax | ((u64)regs->edx << 32);
    u32 ecx = regs->ecx;
    struct vcpu *v = current;
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);

    HVM_DBG_LOG(DBG_LEVEL_0, "msr 0x%x content 0x%"PRIx64, ecx, msr_content);

    switch ( ecx )
    {
    case MSR_EFER:
        if ( !hvm_set_efer(msr_content) )
            goto exception_raised;
        break;

    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        if ( !hvm_long_mode_enabled(v) )
            goto gp_fault;

        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;

        if ( ecx == MSR_FS_BASE )
            __vmwrite(GUEST_FS_BASE, msr_content);
        else if ( ecx == MSR_GS_BASE )
            __vmwrite(GUEST_GS_BASE, msr_content);
        else
        {
            v->arch.hvm_vmx.shadow_gs = msr_content;
            wrmsrl(MSR_SHADOW_GS_BASE, msr_content);
        }

        break;

    case MSR_STAR:
        WRITE_MSR(STAR);

    case MSR_LSTAR:
        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;
        WRITE_MSR(LSTAR);

    case MSR_CSTAR:
        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;
        v->arch.hvm_vmx.cstar = msr_content;
        break;

    case MSR_SYSCALL_MASK:
        WRITE_MSR(SYSCALL_MASK);

    default:
        return HNDL_unhandled;
    }

    return HNDL_done;

 uncanonical_address:
    HVM_DBG_LOG(DBG_LEVEL_0, "Not cano address of msr write %x", ecx);
 gp_fault:
    vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
 exception_raised:
    return HNDL_exception_raised;
}

/*
 * To avoid MSR save/restore at every VM exit/entry time, we restore
 * the x86_64 specific MSRs at domain switch time. Since these MSRs
 * are not modified once set for para domains, we don't save them,
 * but simply reset them to values set in percpu_traps_init().
 */
static void vmx_restore_host_msrs(void)
{
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);
    int i;

    while ( host_msr_state->flags )
    {
        i = find_first_set_bit(host_msr_state->flags);
        wrmsrl(msr_index[i], host_msr_state->msrs[i]);
        clear_bit(i, &host_msr_state->flags);
    }

    if ( cpu_has_nx && !(read_efer() & EFER_NX) )
        write_efer(read_efer() | EFER_NX);
}

static void vmx_save_guest_msrs(struct vcpu *v)
{
    /* MSR_SHADOW_GS_BASE may have been changed by swapgs instruction. */
    rdmsrl(MSR_SHADOW_GS_BASE, v->arch.hvm_vmx.shadow_gs);
}

static void vmx_restore_guest_msrs(struct vcpu *v)
{
    struct vmx_msr_state *guest_msr_state, *host_msr_state;
    unsigned long guest_flags;
    int i;

    guest_msr_state = &v->arch.hvm_vmx.msr_state;
    host_msr_state = &this_cpu(host_msr_state);

    wrmsrl(MSR_SHADOW_GS_BASE, v->arch.hvm_vmx.shadow_gs);

    guest_flags = guest_msr_state->flags;

    while ( guest_flags )
    {
        i = find_first_set_bit(guest_flags);

        HVM_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's index %d msr %x with value %lx",
                    i, msr_index[i], guest_msr_state->msrs[i]);
        set_bit(i, &host_msr_state->flags);
        wrmsrl(msr_index[i], guest_msr_state->msrs[i]);
        clear_bit(i, &guest_flags);
    }

    if ( (v->arch.hvm_vcpu.guest_efer ^ read_efer()) & (EFER_NX | EFER_SCE) )
    {
        HVM_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's EFER with value %lx",
                    v->arch.hvm_vcpu.guest_efer);
        write_efer((read_efer() & ~(EFER_NX | EFER_SCE)) |
                   (v->arch.hvm_vcpu.guest_efer & (EFER_NX | EFER_SCE)));
    }
}

#else  /* __i386__ */

#define vmx_save_host_msrs()        ((void)0)

static void vmx_restore_host_msrs(void)
{
    if ( cpu_has_nx && !(read_efer() & EFER_NX) )
        write_efer(read_efer() | EFER_NX);
}

#define vmx_save_guest_msrs(v)      ((void)0)

static void vmx_restore_guest_msrs(struct vcpu *v)
{
    if ( (v->arch.hvm_vcpu.guest_efer ^ read_efer()) & EFER_NX )
    {
        HVM_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's EFER with value %lx",
                    v->arch.hvm_vcpu.guest_efer);
        write_efer((read_efer() & ~EFER_NX) |
                   (v->arch.hvm_vcpu.guest_efer & EFER_NX));
    }
}

static enum handler_return long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    struct vcpu *v = current;

    switch ( regs->ecx )
    {
    case MSR_EFER:
        msr_content = v->arch.hvm_vcpu.guest_efer;
        break;

    default:
        return HNDL_unhandled;
    }

    regs->eax = msr_content >>  0;
    regs->edx = msr_content >> 32;

    return HNDL_done;
}

static enum handler_return long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content = regs->eax | ((u64)regs->edx << 32);

    switch ( regs->ecx )
    {
    case MSR_EFER:
        if ( !hvm_set_efer(msr_content) )
            return HNDL_exception_raised;
        break;

    default:
        return HNDL_unhandled;
    }

    return HNDL_done;
}

#endif /* __i386__ */

static int vmx_guest_x86_mode(struct vcpu *v)
{
    unsigned int cs_ar_bytes;

    if ( unlikely(!(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE)) )
        return 0;
    if ( unlikely(guest_cpu_user_regs()->eflags & X86_EFLAGS_VM) )
        return 1;
    cs_ar_bytes = __vmread(GUEST_CS_AR_BYTES);
    if ( hvm_long_mode_enabled(v) &&
         likely(cs_ar_bytes & X86_SEG_AR_CS_LM_ACTIVE) )
        return 8;
    return (likely(cs_ar_bytes & X86_SEG_AR_DEF_OP_SIZE) ? 4 : 2);
}

static void vmx_save_dr(struct vcpu *v)
{
    if ( !v->arch.hvm_vcpu.flag_dr_dirty )
        return;

    /* Clear the DR dirty flag and re-enable intercepts for DR accesses. */
    v->arch.hvm_vcpu.flag_dr_dirty = 0;
    v->arch.hvm_vmx.exec_control |= CPU_BASED_MOV_DR_EXITING;
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vmx.exec_control);

    v->arch.guest_context.debugreg[0] = read_debugreg(0);
    v->arch.guest_context.debugreg[1] = read_debugreg(1);
    v->arch.guest_context.debugreg[2] = read_debugreg(2);
    v->arch.guest_context.debugreg[3] = read_debugreg(3);
    v->arch.guest_context.debugreg[6] = read_debugreg(6);
    /* DR7 must be saved as it is used by vmx_restore_dr(). */
    v->arch.guest_context.debugreg[7] = __vmread(GUEST_DR7);
}

static void __restore_debug_registers(struct vcpu *v)
{
    if ( v->arch.hvm_vcpu.flag_dr_dirty )
        return;

    v->arch.hvm_vcpu.flag_dr_dirty = 1;

    write_debugreg(0, v->arch.guest_context.debugreg[0]);
    write_debugreg(1, v->arch.guest_context.debugreg[1]);
    write_debugreg(2, v->arch.guest_context.debugreg[2]);
    write_debugreg(3, v->arch.guest_context.debugreg[3]);
    write_debugreg(6, v->arch.guest_context.debugreg[6]);
    /* DR7 is loaded from the VMCS. */
}

/*
 * DR7 is saved and restored on every vmexit.  Other debug registers only
 * need to be restored if their value is going to affect execution -- i.e.,
 * if one of the breakpoints is enabled.  So mask out all bits that don't
 * enable some breakpoint functionality.
 */
static void vmx_restore_dr(struct vcpu *v)
{
    /* NB. __vmread() is not usable here, so we cannot read from the VMCS. */
    if ( unlikely(v->arch.guest_context.debugreg[7] & DR7_ACTIVE_MASK) )
        __restore_debug_registers(v);
}

void vmx_vmcs_save(struct vcpu *v, struct hvm_hw_cpu *c)
{
    uint32_t ev;

    vmx_vmcs_enter(v);

    c->cr0 = v->arch.hvm_vcpu.guest_cr[0];
    c->cr2 = v->arch.hvm_vcpu.guest_cr[2];
    c->cr3 = v->arch.hvm_vcpu.guest_cr[3];
    c->cr4 = v->arch.hvm_vcpu.guest_cr[4];

    c->msr_efer = v->arch.hvm_vcpu.guest_efer;

    c->idtr_limit = __vmread(GUEST_IDTR_LIMIT);
    c->idtr_base = __vmread(GUEST_IDTR_BASE);

    c->gdtr_limit = __vmread(GUEST_GDTR_LIMIT);
    c->gdtr_base = __vmread(GUEST_GDTR_BASE);

    c->cs_sel = __vmread(GUEST_CS_SELECTOR);
    c->cs_limit = __vmread(GUEST_CS_LIMIT);
    c->cs_base = __vmread(GUEST_CS_BASE);
    c->cs_arbytes = __vmread(GUEST_CS_AR_BYTES);

    c->ds_sel = __vmread(GUEST_DS_SELECTOR);
    c->ds_limit = __vmread(GUEST_DS_LIMIT);
    c->ds_base = __vmread(GUEST_DS_BASE);
    c->ds_arbytes = __vmread(GUEST_DS_AR_BYTES);

    c->es_sel = __vmread(GUEST_ES_SELECTOR);
    c->es_limit = __vmread(GUEST_ES_LIMIT);
    c->es_base = __vmread(GUEST_ES_BASE);
    c->es_arbytes = __vmread(GUEST_ES_AR_BYTES);

    c->ss_sel = __vmread(GUEST_SS_SELECTOR);
    c->ss_limit = __vmread(GUEST_SS_LIMIT);
    c->ss_base = __vmread(GUEST_SS_BASE);
    c->ss_arbytes = __vmread(GUEST_SS_AR_BYTES);

    c->fs_sel = __vmread(GUEST_FS_SELECTOR);
    c->fs_limit = __vmread(GUEST_FS_LIMIT);
    c->fs_base = __vmread(GUEST_FS_BASE);
    c->fs_arbytes = __vmread(GUEST_FS_AR_BYTES);

    c->gs_sel = __vmread(GUEST_GS_SELECTOR);
    c->gs_limit = __vmread(GUEST_GS_LIMIT);
    c->gs_base = __vmread(GUEST_GS_BASE);
    c->gs_arbytes = __vmread(GUEST_GS_AR_BYTES);

    c->tr_sel = __vmread(GUEST_TR_SELECTOR);
    c->tr_limit = __vmread(GUEST_TR_LIMIT);
    c->tr_base = __vmread(GUEST_TR_BASE);
    c->tr_arbytes = __vmread(GUEST_TR_AR_BYTES);

    c->ldtr_sel = __vmread(GUEST_LDTR_SELECTOR);
    c->ldtr_limit = __vmread(GUEST_LDTR_LIMIT);
    c->ldtr_base = __vmread(GUEST_LDTR_BASE);
    c->ldtr_arbytes = __vmread(GUEST_LDTR_AR_BYTES);

    c->sysenter_cs = __vmread(GUEST_SYSENTER_CS);
    c->sysenter_esp = __vmread(GUEST_SYSENTER_ESP);
    c->sysenter_eip = __vmread(GUEST_SYSENTER_EIP);

    c->pending_event = 0;
    c->error_code = 0;
    if ( ((ev = __vmread(VM_ENTRY_INTR_INFO)) & INTR_INFO_VALID_MASK) &&
         hvm_event_needs_reinjection((ev >> 8) & 7, ev & 0xff) )
    {
        c->pending_event = ev;
        c->error_code = __vmread(VM_ENTRY_EXCEPTION_ERROR_CODE);
    }

    vmx_vmcs_exit(v);
}

static int vmx_restore_cr0_cr3(
    struct vcpu *v, unsigned long cr0, unsigned long cr3)
{
    unsigned long mfn = 0;
    p2m_type_t p2mt;

    if ( cr0 & X86_CR0_PG )
    {
        mfn = mfn_x(gfn_to_mfn(v->domain, cr3 >> PAGE_SHIFT, &p2mt));
        if ( !p2m_is_ram(p2mt) || !get_page(mfn_to_page(mfn), v->domain) )
        {
            gdprintk(XENLOG_ERR, "Invalid CR3 value=0x%lx\n", cr3);
            return -EINVAL;
        }
    }

    if ( v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG )
        put_page(pagetable_get_page(v->arch.guest_table));

    v->arch.guest_table = pagetable_from_pfn(mfn);

    v->arch.hvm_vcpu.guest_cr[0] = cr0 | X86_CR0_ET;
    v->arch.hvm_vcpu.guest_cr[3] = cr3;

    return 0;
}

int vmx_vmcs_restore(struct vcpu *v, struct hvm_hw_cpu *c)
{
    int rc;

    if ( c->pending_valid &&
         ((c->pending_type == 1) || (c->pending_type > 6) ||
          (c->pending_reserved != 0)) )
    {
        gdprintk(XENLOG_ERR, "Invalid pending event 0x%"PRIx32".\n",
                 c->pending_event);
        return -EINVAL;
    }

    rc = vmx_restore_cr0_cr3(v, c->cr0, c->cr3);
    if ( rc )
        return rc;

    vmx_vmcs_enter(v);

    v->arch.hvm_vcpu.guest_cr[2] = c->cr2;
    v->arch.hvm_vcpu.guest_cr[4] = c->cr4;
    vmx_update_guest_cr(v, 0);
    vmx_update_guest_cr(v, 2);
    vmx_update_guest_cr(v, 4);

#ifdef HVM_DEBUG_SUSPEND
    printk("%s: cr3=0x%"PRIx64", cr0=0x%"PRIx64", cr4=0x%"PRIx64".\n",
           __func__, c->cr3, c->cr0, c->cr4);
#endif

    v->arch.hvm_vcpu.guest_efer = c->msr_efer;
    vmx_update_guest_efer(v);

    __vmwrite(GUEST_IDTR_LIMIT, c->idtr_limit);
    __vmwrite(GUEST_IDTR_BASE, c->idtr_base);

    __vmwrite(GUEST_GDTR_LIMIT, c->gdtr_limit);
    __vmwrite(GUEST_GDTR_BASE, c->gdtr_base);

    __vmwrite(GUEST_CS_SELECTOR, c->cs_sel);
    __vmwrite(GUEST_CS_LIMIT, c->cs_limit);
    __vmwrite(GUEST_CS_BASE, c->cs_base);
    __vmwrite(GUEST_CS_AR_BYTES, c->cs_arbytes);

    __vmwrite(GUEST_DS_SELECTOR, c->ds_sel);
    __vmwrite(GUEST_DS_LIMIT, c->ds_limit);
    __vmwrite(GUEST_DS_BASE, c->ds_base);
    __vmwrite(GUEST_DS_AR_BYTES, c->ds_arbytes);

    __vmwrite(GUEST_ES_SELECTOR, c->es_sel);
    __vmwrite(GUEST_ES_LIMIT, c->es_limit);
    __vmwrite(GUEST_ES_BASE, c->es_base);
    __vmwrite(GUEST_ES_AR_BYTES, c->es_arbytes);

    __vmwrite(GUEST_SS_SELECTOR, c->ss_sel);
    __vmwrite(GUEST_SS_LIMIT, c->ss_limit);
    __vmwrite(GUEST_SS_BASE, c->ss_base);
    __vmwrite(GUEST_SS_AR_BYTES, c->ss_arbytes);

    __vmwrite(GUEST_FS_SELECTOR, c->fs_sel);
    __vmwrite(GUEST_FS_LIMIT, c->fs_limit);
    __vmwrite(GUEST_FS_BASE, c->fs_base);
    __vmwrite(GUEST_FS_AR_BYTES, c->fs_arbytes);

    __vmwrite(GUEST_GS_SELECTOR, c->gs_sel);
    __vmwrite(GUEST_GS_LIMIT, c->gs_limit);
    __vmwrite(GUEST_GS_BASE, c->gs_base);
    __vmwrite(GUEST_GS_AR_BYTES, c->gs_arbytes);

    __vmwrite(GUEST_TR_SELECTOR, c->tr_sel);
    __vmwrite(GUEST_TR_LIMIT, c->tr_limit);
    __vmwrite(GUEST_TR_BASE, c->tr_base);
    __vmwrite(GUEST_TR_AR_BYTES, c->tr_arbytes);

    __vmwrite(GUEST_LDTR_SELECTOR, c->ldtr_sel);
    __vmwrite(GUEST_LDTR_LIMIT, c->ldtr_limit);
    __vmwrite(GUEST_LDTR_BASE, c->ldtr_base);
    __vmwrite(GUEST_LDTR_AR_BYTES, c->ldtr_arbytes);

    __vmwrite(GUEST_SYSENTER_CS, c->sysenter_cs);
    __vmwrite(GUEST_SYSENTER_ESP, c->sysenter_esp);
    __vmwrite(GUEST_SYSENTER_EIP, c->sysenter_eip);

    __vmwrite(GUEST_DR7, c->dr7);

    vmx_vmcs_exit(v);

    paging_update_paging_modes(v);

    if ( c->pending_valid )
    {
        gdprintk(XENLOG_INFO, "Re-injecting 0x%"PRIx32", 0x%"PRIx32"\n",
                 c->pending_event, c->error_code);

        if ( hvm_event_needs_reinjection(c->pending_type, c->pending_vector) )
        {
            vmx_vmcs_enter(v);
            __vmwrite(VM_ENTRY_INTR_INFO, c->pending_event);
            __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, c->error_code);
            vmx_vmcs_exit(v);
        }
    }

    return 0;
}

#if defined(__x86_64__) && defined(HVM_DEBUG_SUSPEND)
static void dump_msr_state(struct vmx_msr_state *m)
{
    int i = 0;
    printk("**** msr state ****\n");
    printk("shadow_gs=0x%lx, flags=0x%lx, msr_items:", m->shadow_gs, m->flags);
    for ( i = 0; i < VMX_MSR_COUNT; i++ )
        printk("0x%lx,", m->msrs[i]);
    printk("\n");
}
#else
#define dump_msr_state(m) ((void)0)
#endif

static void vmx_save_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
#ifdef __x86_64__
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;
    unsigned long guest_flags = guest_state->flags;

    data->shadow_gs = v->arch.hvm_vmx.shadow_gs;
    data->msr_cstar = v->arch.hvm_vmx.cstar;

    /* save msrs */
    data->msr_flags        = guest_flags;
    data->msr_lstar        = guest_state->msrs[VMX_INDEX_MSR_LSTAR];
    data->msr_star         = guest_state->msrs[VMX_INDEX_MSR_STAR];
    data->msr_syscall_mask = guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK];
#endif

    data->tsc = hvm_get_guest_time(v);

    dump_msr_state(guest_state);
}

static void vmx_load_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
#ifdef __x86_64__
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;

    /* restore msrs */
    guest_state->flags = data->msr_flags;
    guest_state->msrs[VMX_INDEX_MSR_LSTAR]        = data->msr_lstar;
    guest_state->msrs[VMX_INDEX_MSR_STAR]         = data->msr_star;
    guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK] = data->msr_syscall_mask;

    v->arch.hvm_vmx.cstar     = data->msr_cstar;
    v->arch.hvm_vmx.shadow_gs = data->shadow_gs;
#endif

#ifdef VMXASSIST
    v->arch.hvm_vmx.vmxassist_enabled = !(data->cr0 & X86_CR0_PE);
#endif

    hvm_set_guest_time(v, data->tsc);

    dump_msr_state(guest_state);
}


static void vmx_save_vmcs_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    vmx_save_cpu_state(v, ctxt);
    vmx_vmcs_save(v, ctxt);
}

static int vmx_load_vmcs_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    vmx_load_cpu_state(v, ctxt);

    if ( vmx_vmcs_restore(v, ctxt) )
    {
        gdprintk(XENLOG_ERR, "vmx_vmcs restore failed!\n");
        domain_crash(v->domain);
        return -EINVAL;
    }

    return 0;
}

static void vmx_ctxt_switch_from(struct vcpu *v)
{
    vmx_save_guest_msrs(v);
    vmx_restore_host_msrs();
    vmx_save_dr(v);
}

static void vmx_ctxt_switch_to(struct vcpu *v)
{
    /* HOST_CR4 in VMCS is always mmu_cr4_features. Sync CR4 now. */
    if ( unlikely(read_cr4() != mmu_cr4_features) )
        write_cr4(mmu_cr4_features);

    vmx_restore_guest_msrs(v);
    vmx_restore_dr(v);
}

static unsigned long vmx_get_segment_base(struct vcpu *v, enum x86_segment seg)
{
    unsigned long base = 0;
    int long_mode = 0;

    ASSERT(v == current);

    if ( hvm_long_mode_enabled(v) &&
         (__vmread(GUEST_CS_AR_BYTES) & X86_SEG_AR_CS_LM_ACTIVE) )
        long_mode = 1;

    switch ( seg )
    {
    case x86_seg_cs: if ( !long_mode ) base = __vmread(GUEST_CS_BASE); break;
    case x86_seg_ds: if ( !long_mode ) base = __vmread(GUEST_DS_BASE); break;
    case x86_seg_es: if ( !long_mode ) base = __vmread(GUEST_ES_BASE); break;
    case x86_seg_fs: base = __vmread(GUEST_FS_BASE); break;
    case x86_seg_gs: base = __vmread(GUEST_GS_BASE); break;
    case x86_seg_ss: if ( !long_mode ) base = __vmread(GUEST_SS_BASE); break;
    case x86_seg_tr: base = __vmread(GUEST_TR_BASE); break;
    case x86_seg_gdtr: base = __vmread(GUEST_GDTR_BASE); break;
    case x86_seg_idtr: base = __vmread(GUEST_IDTR_BASE); break;
    case x86_seg_ldtr: base = __vmread(GUEST_LDTR_BASE); break;
    default: BUG(); break;
    }

    return base;
}

static void vmx_get_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    uint32_t attr = 0;

    ASSERT(v == current);

    switch ( seg )
    {
    case x86_seg_cs:
        reg->sel   = __vmread(GUEST_CS_SELECTOR);
        reg->limit = __vmread(GUEST_CS_LIMIT);
        reg->base  = __vmread(GUEST_CS_BASE);
        attr       = __vmread(GUEST_CS_AR_BYTES);
        break;
    case x86_seg_ds:
        reg->sel   = __vmread(GUEST_DS_SELECTOR);
        reg->limit = __vmread(GUEST_DS_LIMIT);
        reg->base  = __vmread(GUEST_DS_BASE);
        attr       = __vmread(GUEST_DS_AR_BYTES);
        break;
    case x86_seg_es:
        reg->sel   = __vmread(GUEST_ES_SELECTOR);
        reg->limit = __vmread(GUEST_ES_LIMIT);
        reg->base  = __vmread(GUEST_ES_BASE);
        attr       = __vmread(GUEST_ES_AR_BYTES);
        break;
    case x86_seg_fs:
        reg->sel   = __vmread(GUEST_FS_SELECTOR);
        reg->limit = __vmread(GUEST_FS_LIMIT);
        reg->base  = __vmread(GUEST_FS_BASE);
        attr       = __vmread(GUEST_FS_AR_BYTES);
        break;
    case x86_seg_gs:
        reg->sel   = __vmread(GUEST_GS_SELECTOR);
        reg->limit = __vmread(GUEST_GS_LIMIT);
        reg->base  = __vmread(GUEST_GS_BASE);
        attr       = __vmread(GUEST_GS_AR_BYTES);
        break;
    case x86_seg_ss:
        reg->sel   = __vmread(GUEST_SS_SELECTOR);
        reg->limit = __vmread(GUEST_SS_LIMIT);
        reg->base  = __vmread(GUEST_SS_BASE);
        attr       = __vmread(GUEST_SS_AR_BYTES);
        break;
    case x86_seg_tr:
        reg->sel   = __vmread(GUEST_TR_SELECTOR);
        reg->limit = __vmread(GUEST_TR_LIMIT);
        reg->base  = __vmread(GUEST_TR_BASE);
        attr       = __vmread(GUEST_TR_AR_BYTES);
        break;
    case x86_seg_gdtr:
        reg->limit = __vmread(GUEST_GDTR_LIMIT);
        reg->base  = __vmread(GUEST_GDTR_BASE);
        break;
    case x86_seg_idtr:
        reg->limit = __vmread(GUEST_IDTR_LIMIT);
        reg->base  = __vmread(GUEST_IDTR_BASE);
        break;
    case x86_seg_ldtr:
        reg->sel   = __vmread(GUEST_LDTR_SELECTOR);
        reg->limit = __vmread(GUEST_LDTR_LIMIT);
        reg->base  = __vmread(GUEST_LDTR_BASE);
        attr       = __vmread(GUEST_LDTR_AR_BYTES);
        break;
    default:
        BUG();
    }

    reg->attr.bytes = (attr & 0xff) | ((attr >> 4) & 0xf00);
    /* Unusable flag is folded into Present flag. */
    if ( attr & (1u<<16) )
        reg->attr.fields.p = 0;
}

static void vmx_set_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    uint32_t attr;

    ASSERT((v == current) || !vcpu_runnable(v));

    attr = reg->attr.bytes;
    attr = ((attr & 0xf00) << 4) | (attr & 0xff);

    /* Not-present must mean unusable. */
    if ( !reg->attr.fields.p )
        attr |= (1u << 16);

    vmx_vmcs_enter(v);

    switch ( seg )
    {
    case x86_seg_cs:
        __vmwrite(GUEST_CS_SELECTOR, reg->sel);
        __vmwrite(GUEST_CS_LIMIT, reg->limit);
        __vmwrite(GUEST_CS_BASE, reg->base);
        __vmwrite(GUEST_CS_AR_BYTES, attr);
        break;
    case x86_seg_ds:
        __vmwrite(GUEST_DS_SELECTOR, reg->sel);
        __vmwrite(GUEST_DS_LIMIT, reg->limit);
        __vmwrite(GUEST_DS_BASE, reg->base);
        __vmwrite(GUEST_DS_AR_BYTES, attr);
        break;
    case x86_seg_es:
        __vmwrite(GUEST_ES_SELECTOR, reg->sel);
        __vmwrite(GUEST_ES_LIMIT, reg->limit);
        __vmwrite(GUEST_ES_BASE, reg->base);
        __vmwrite(GUEST_ES_AR_BYTES, attr);
        break;
    case x86_seg_fs:
        __vmwrite(GUEST_FS_SELECTOR, reg->sel);
        __vmwrite(GUEST_FS_LIMIT, reg->limit);
        __vmwrite(GUEST_FS_BASE, reg->base);
        __vmwrite(GUEST_FS_AR_BYTES, attr);
        break;
    case x86_seg_gs:
        __vmwrite(GUEST_GS_SELECTOR, reg->sel);
        __vmwrite(GUEST_GS_LIMIT, reg->limit);
        __vmwrite(GUEST_GS_BASE, reg->base);
        __vmwrite(GUEST_GS_AR_BYTES, attr);
        break;
    case x86_seg_ss:
        __vmwrite(GUEST_SS_SELECTOR, reg->sel);
        __vmwrite(GUEST_SS_LIMIT, reg->limit);
        __vmwrite(GUEST_SS_BASE, reg->base);
        __vmwrite(GUEST_SS_AR_BYTES, attr);
        break;
    case x86_seg_tr:
        __vmwrite(GUEST_TR_SELECTOR, reg->sel);
        __vmwrite(GUEST_TR_LIMIT, reg->limit);
        __vmwrite(GUEST_TR_BASE, reg->base);
        __vmwrite(GUEST_TR_AR_BYTES, attr);
        break;
    case x86_seg_gdtr:
        __vmwrite(GUEST_GDTR_LIMIT, reg->limit);
        __vmwrite(GUEST_GDTR_BASE, reg->base);
        break;
    case x86_seg_idtr:
        __vmwrite(GUEST_IDTR_LIMIT, reg->limit);
        __vmwrite(GUEST_IDTR_BASE, reg->base);
        break;
    case x86_seg_ldtr:
        __vmwrite(GUEST_LDTR_SELECTOR, reg->sel);
        __vmwrite(GUEST_LDTR_LIMIT, reg->limit);
        __vmwrite(GUEST_LDTR_BASE, reg->base);
        __vmwrite(GUEST_LDTR_AR_BYTES, attr);
        break;
    default:
        BUG();
    }

    vmx_vmcs_exit(v);
}

/* Make sure that xen intercepts any FP accesses from current */
static void vmx_stts(struct vcpu *v)
{
    /* VMX depends on operating on the current vcpu */
    ASSERT(v == current);

    /*
     * If the guest does not have TS enabled then we must cause and handle an
     * exception on first use of the FPU. If the guest *does* have TS enabled
     * then this is not necessary: no FPU activity can occur until the guest
     * clears CR0.TS, and we will initialise the FPU when that happens.
     */
    if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
    {
        v->arch.hvm_vcpu.hw_cr[0] |= X86_CR0_TS;
        __vmwrite(GUEST_CR0, v->arch.hvm_vcpu.hw_cr[0]);
        __vm_set_bit(EXCEPTION_BITMAP, TRAP_no_device);
    }
}

static void vmx_set_tsc_offset(struct vcpu *v, u64 offset)
{
    vmx_vmcs_enter(v);
    __vmwrite(TSC_OFFSET, offset);
#if defined (__i386__)
    __vmwrite(TSC_OFFSET_HIGH, offset >> 32);
#endif
    vmx_vmcs_exit(v);
}

void do_nmi(struct cpu_user_regs *);

static void vmx_init_hypercall_page(struct domain *d, void *hypercall_page)
{
    char *p;
    int i;

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p + 0) = 0xb8; /* mov imm32, %eax */
        *(u32 *)(p + 1) = i;
        *(u8  *)(p + 5) = 0x0f; /* vmcall */
        *(u8  *)(p + 6) = 0x01;
        *(u8  *)(p + 7) = 0xc1;
        *(u8  *)(p + 8) = 0xc3; /* ret */
    }

    /* Don't support HYPERVISOR_iret at the moment */
    *(u16 *)(hypercall_page + (__HYPERVISOR_iret * 32)) = 0x0b0f; /* ud2 */
}

static enum hvm_intblk vmx_interrupt_blocked(
    struct vcpu *v, struct hvm_intack intack)
{
    unsigned long intr_shadow;

    intr_shadow = __vmread(GUEST_INTERRUPTIBILITY_INFO);

    if ( intr_shadow & (VMX_INTR_SHADOW_STI|VMX_INTR_SHADOW_MOV_SS) )
        return hvm_intblk_shadow;

    if ( intack.source == hvm_intsrc_nmi )
        return ((intr_shadow & VMX_INTR_SHADOW_NMI) ?
                hvm_intblk_nmi_iret : hvm_intblk_none);

    ASSERT((intack.source == hvm_intsrc_pic) ||
           (intack.source == hvm_intsrc_lapic));

    if ( !(guest_cpu_user_regs()->eflags & X86_EFLAGS_IF) )
        return hvm_intblk_rflags_ie;

    return hvm_intblk_none;
}

static void vmx_update_host_cr3(struct vcpu *v)
{
    ASSERT((v == current) || !vcpu_runnable(v));
    vmx_vmcs_enter(v);
    __vmwrite(HOST_CR3, v->arch.cr3);
    vmx_vmcs_exit(v);
}

static void vmx_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    ASSERT((v == current) || !vcpu_runnable(v));

    vmx_vmcs_enter(v);

    switch ( cr )
    {
    case 0:
        /* TS cleared? Then initialise FPU now. */
        if ( (v == current) && !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) &&
             (v->arch.hvm_vcpu.hw_cr[0] & X86_CR0_TS) )
        {
            setup_fpu(v);
            __vm_clear_bit(EXCEPTION_BITMAP, TRAP_no_device);
        }

        v->arch.hvm_vcpu.hw_cr[0] =
            v->arch.hvm_vcpu.guest_cr[0] |
            X86_CR0_NE | X86_CR0_PG | X86_CR0_WP | X86_CR0_PE;
        __vmwrite(GUEST_CR0, v->arch.hvm_vcpu.hw_cr[0]);
        __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vcpu.guest_cr[0]);
        break;
    case 2:
        /* CR2 is updated in exit stub. */
        break;
    case 3:
        __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr[3]);
        break;
    case 4:
        v->arch.hvm_vcpu.hw_cr[4] =
            v->arch.hvm_vcpu.guest_cr[4] | HVM_CR4_HOST_MASK;
        __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4]);
        __vmwrite(CR4_READ_SHADOW, v->arch.hvm_vcpu.guest_cr[4]);
        break;
    default:
        BUG();
    }

    vmx_vmcs_exit(v);
}

static void vmx_update_guest_efer(struct vcpu *v)
{
#ifdef __x86_64__
    unsigned long vm_entry_value;

    ASSERT((v == current) || !vcpu_runnable(v));

    vmx_vmcs_enter(v);

    vm_entry_value = __vmread(VM_ENTRY_CONTROLS);
    if ( v->arch.hvm_vcpu.guest_efer & EFER_LMA )
        vm_entry_value |= VM_ENTRY_IA32E_MODE;
    else
        vm_entry_value &= ~VM_ENTRY_IA32E_MODE;
    __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);

    vmx_vmcs_exit(v);
#endif

    if ( v == current )
        write_efer((read_efer() & ~(EFER_NX|EFER_SCE)) |
                   (v->arch.hvm_vcpu.guest_efer & (EFER_NX|EFER_SCE)));
}

static void vmx_flush_guest_tlbs(void)
{
    /* No tagged TLB support on VMX yet.  The fact that we're in Xen
     * at all means any guest will have a clean TLB when it's next run,
     * because VMRESUME will flush it for us. */
}

static void vmx_inject_exception(
    unsigned int trapnr, int errcode, unsigned long cr2)
{
    struct vcpu *curr = current;

    vmx_inject_hw_exception(curr, trapnr, errcode);

    if ( trapnr == TRAP_page_fault )
        curr->arch.hvm_vcpu.guest_cr[2] = cr2;

    if ( (trapnr == TRAP_debug) &&
         (guest_cpu_user_regs()->eflags & X86_EFLAGS_TF) )
    {
        __restore_debug_registers(curr);
        write_debugreg(6, read_debugreg(6) | 0x4000);
    }
}

static int vmx_event_pending(struct vcpu *v)
{
    ASSERT(v == current);
    return (__vmread(VM_ENTRY_INTR_INFO) & INTR_INFO_VALID_MASK);
}

static struct hvm_function_table vmx_function_table = {
    .name                 = "VMX",
    .domain_initialise    = vmx_domain_initialise,
    .domain_destroy       = vmx_domain_destroy,
    .vcpu_initialise      = vmx_vcpu_initialise,
    .vcpu_destroy         = vmx_vcpu_destroy,
    .save_cpu_ctxt        = vmx_save_vmcs_ctxt,
    .load_cpu_ctxt        = vmx_load_vmcs_ctxt,
    .interrupt_blocked    = vmx_interrupt_blocked,
    .guest_x86_mode       = vmx_guest_x86_mode,
    .get_segment_base     = vmx_get_segment_base,
    .get_segment_register = vmx_get_segment_register,
    .set_segment_register = vmx_set_segment_register,
    .update_host_cr3      = vmx_update_host_cr3,
    .update_guest_cr      = vmx_update_guest_cr,
    .update_guest_efer    = vmx_update_guest_efer,
    .flush_guest_tlbs     = vmx_flush_guest_tlbs,
    .stts                 = vmx_stts,
    .set_tsc_offset       = vmx_set_tsc_offset,
    .inject_exception     = vmx_inject_exception,
    .init_hypercall_page  = vmx_init_hypercall_page,
    .event_pending        = vmx_event_pending,
    .cpu_up               = vmx_cpu_up,
    .cpu_down             = vmx_cpu_down,
};

void start_vmx(void)
{
    static int bootstrapped;

    vmx_save_host_msrs();

    if ( bootstrapped )
    {
        if ( hvm_enabled && !vmx_cpu_up() )
        {
            printk("VMX: FATAL: failed to initialise CPU%d!\n",
                   smp_processor_id());
            BUG();
        }
        return;
    }

    bootstrapped = 1;

    /* Xen does not fill x86_capability words except 0. */
    boot_cpu_data.x86_capability[4] = cpuid_ecx(1);

    if ( !test_bit(X86_FEATURE_VMXE, &boot_cpu_data.x86_capability) )
        return;

    set_in_cr4(X86_CR4_VMXE);

    if ( !vmx_cpu_up() )
    {
        printk("VMX: failed to initialise.\n");
        return;
    }

    setup_vmcs_dump();

    hvm_enable(&vmx_function_table);
}

/*
 * Not all cases receive valid value in the VM-exit instruction length field.
 * Callers must know what they're doing!
 */
static int __get_instruction_length(void)
{
    int len;
    len = __vmread(VM_EXIT_INSTRUCTION_LEN); /* Safe: callers audited */
    BUG_ON((len < 1) || (len > 15));
    return len;
}

static void __update_guest_eip(unsigned long inst_len)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    unsigned long x;

    regs->eip += inst_len;
    regs->eflags &= ~X86_EFLAGS_RF;

    x = __vmread(GUEST_INTERRUPTIBILITY_INFO);
    if ( x & (VMX_INTR_SHADOW_STI | VMX_INTR_SHADOW_MOV_SS) )
    {
        x &= ~(VMX_INTR_SHADOW_STI | VMX_INTR_SHADOW_MOV_SS);
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, x);
    }

    if ( regs->eflags & X86_EFLAGS_TF )
        vmx_inject_exception(TRAP_debug, HVM_DELIVER_NO_ERROR_CODE, 0);
}

void vmx_do_no_device_fault(void)
{
    struct vcpu *v = current;

    setup_fpu(current);
    __vm_clear_bit(EXCEPTION_BITMAP, TRAP_no_device);

    /* Disable TS in guest CR0 unless the guest wants the exception too. */
    if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
    {
        v->arch.hvm_vcpu.hw_cr[0] &= ~X86_CR0_TS;
        __vmwrite(GUEST_CR0, v->arch.hvm_vcpu.hw_cr[0]);
    }
}

#define bitmaskof(idx)  (1U << ((idx) & 31))
void vmx_cpuid_intercept(
    unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx)
{
    unsigned int input = *eax;
    unsigned int count = *ecx;

#ifdef VMXASSIST
    if ( input == 0x40000003 )
    {
        /*
         * NB. Unsupported interface for private use of VMXASSIST only.
         * Note that this leaf lives at <max-hypervisor-leaf> + 1.
         */
        u64 value = ((u64)*edx << 32) | (u32)*ecx;
        p2m_type_t p2mt;
        unsigned long mfn;
        struct vcpu *v = current;
        char *p;

        mfn = mfn_x(gfn_to_mfn_current(value >> PAGE_SHIFT, &p2mt));

        gdprintk(XENLOG_INFO, "Input address is 0x%"PRIx64".\n", value);

        /* 8-byte aligned valid pseudophys address from vmxassist, please. */
        if ( (value & 7) || !p2m_is_ram(p2mt) ||
             !v->arch.hvm_vmx.vmxassist_enabled )
        {
            domain_crash(v->domain);
            return;
        }
        ASSERT(mfn_valid(mfn));

        p = map_domain_page(mfn);
        value = *((uint64_t *)(p + (value & (PAGE_SIZE - 1))));
        unmap_domain_page(p);

        gdprintk(XENLOG_INFO, "Output value is 0x%"PRIx64".\n", value);
        *ecx = (u32)value;
        *edx = (u32)(value >> 32);
        return;
    }
#endif

    hvm_cpuid(input, eax, ebx, ecx, edx);

    switch ( input )
    {
    case 0x00000001:
        *ecx &= ~VMX_VCPU_CPUID_L1_ECX_RESERVED;
        *ebx &= NUM_THREADS_RESET_MASK;
        *ecx &= ~(bitmaskof(X86_FEATURE_VMXE) |
                  bitmaskof(X86_FEATURE_EST)  |
                  bitmaskof(X86_FEATURE_TM2)  |
                  bitmaskof(X86_FEATURE_CID)  |
                  bitmaskof(X86_FEATURE_PDCM) |
                  bitmaskof(X86_FEATURE_DSCPL));
        *edx &= ~(bitmaskof(X86_FEATURE_HT)   |
                  bitmaskof(X86_FEATURE_ACPI) |
                  bitmaskof(X86_FEATURE_ACC)  |
                  bitmaskof(X86_FEATURE_DS));
        break;

    case 0x00000004:
        cpuid_count(input, count, eax, ebx, ecx, edx);
        *eax &= NUM_CORES_RESET_MASK;
        break;

    case 0x00000006:
    case 0x00000009:
    case 0x0000000A:
        *eax = *ebx = *ecx = *edx = 0;
        break;

    case 0x80000001:
        /* Only a few features are advertised in Intel's 0x80000001. */
        *ecx &= (bitmaskof(X86_FEATURE_LAHF_LM));
        *edx &= (bitmaskof(X86_FEATURE_NX) |
                 bitmaskof(X86_FEATURE_LM) |
                 bitmaskof(X86_FEATURE_SYSCALL));
        break;
    }

    HVMTRACE_3D(CPUID, current, input,
                ((uint64_t)*eax << 32) | *ebx, ((uint64_t)*ecx << 32) | *edx);
}

static void vmx_do_cpuid(struct cpu_user_regs *regs)
{
    unsigned int eax, ebx, ecx, edx;

    eax = regs->eax;
    ebx = regs->ebx;
    ecx = regs->ecx;
    edx = regs->edx;

    vmx_cpuid_intercept(&eax, &ebx, &ecx, &edx);

    regs->eax = eax;
    regs->ebx = ebx;
    regs->ecx = ecx;
    regs->edx = edx;
}

#define CASE_GET_REG_P(REG, reg)    \
    case REG_ ## REG: reg_p = (unsigned long *)&(regs->reg); break

#ifdef __i386__
#define CASE_EXTEND_GET_REG_P
#else
#define CASE_EXTEND_GET_REG_P       \
    CASE_GET_REG_P(R8, r8);         \
    CASE_GET_REG_P(R9, r9);         \
    CASE_GET_REG_P(R10, r10);       \
    CASE_GET_REG_P(R11, r11);       \
    CASE_GET_REG_P(R12, r12);       \
    CASE_GET_REG_P(R13, r13);       \
    CASE_GET_REG_P(R14, r14);       \
    CASE_GET_REG_P(R15, r15)
#endif

static void vmx_dr_access(unsigned long exit_qualification,
                          struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    HVMTRACE_0D(DR_WRITE, v);

    if ( !v->arch.hvm_vcpu.flag_dr_dirty )
        __restore_debug_registers(v);

    /* Allow guest direct access to DR registers */
    v->arch.hvm_vmx.exec_control &= ~CPU_BASED_MOV_DR_EXITING;
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vmx.exec_control);
}

/*
 * Invalidate the TLB for va. Invalidate the shadow page corresponding
 * the address va.
 */
static void vmx_do_invlpg(unsigned long va)
{
    struct vcpu *v = current;

    HVMTRACE_2D(INVLPG, v, /*invlpga=*/ 0, va);

    /*
     * We do the safest things first, then try to update the shadow
     * copying from guest
     */
    paging_invlpg(v, va);
}

/* Get segment for OUTS according to guest instruction. */
static enum x86_segment vmx_outs_get_segment(
    int long_mode, unsigned long eip, int inst_len)
{
    unsigned char inst[MAX_INST_LEN];
    enum x86_segment seg = x86_seg_ds;
    int i;
    extern int inst_copy_from_guest(unsigned char *, unsigned long, int);

    if ( likely(cpu_has_vmx_ins_outs_instr_info) )
    {
        unsigned int instr_info = __vmread(VMX_INSTRUCTION_INFO);

        /* Get segment register according to bits 17:15. */
        switch ( (instr_info >> 15) & 7 )
        {
        case 0: seg = x86_seg_es; break;
        case 1: seg = x86_seg_cs; break;
        case 2: seg = x86_seg_ss; break;
        case 3: seg = x86_seg_ds; break;
        case 4: seg = x86_seg_fs; break;
        case 5: seg = x86_seg_gs; break;
        default: BUG();
        }

        goto out;
    }

    if ( !long_mode )
        eip += __vmread(GUEST_CS_BASE);

    memset(inst, 0, MAX_INST_LEN);
    if ( inst_copy_from_guest(inst, eip, inst_len) != inst_len )
    {
        gdprintk(XENLOG_ERR, "Get guest instruction failed\n");
        domain_crash(current->domain);
        goto out;
    }

    for ( i = 0; i < inst_len; i++ )
    {
        switch ( inst[i] )
        {
        case 0xf3: /* REPZ */
        case 0xf2: /* REPNZ */
        case 0xf0: /* LOCK */
        case 0x66: /* data32 */
        case 0x67: /* addr32 */
#ifdef __x86_64__
        case 0x40 ... 0x4f: /* REX */
#endif
            continue;
        case 0x2e: /* CS */
            seg = x86_seg_cs;
            continue;
        case 0x36: /* SS */
            seg = x86_seg_ss;
            continue;
        case 0x26: /* ES */
            seg = x86_seg_es;
            continue;
        case 0x64: /* FS */
            seg = x86_seg_fs;
            continue;
        case 0x65: /* GS */
            seg = x86_seg_gs;
            continue;
        case 0x3e: /* DS */
            seg = x86_seg_ds;
            continue;
        }
    }

 out:
    return seg;
}

static int vmx_str_pio_check_descriptor(int long_mode, unsigned long eip,
                                        int inst_len, enum x86_segment seg,
                                        unsigned long *base, u32 *limit,
                                        u32 *ar_bytes)
{
    enum vmcs_field ar_field, base_field, limit_field;

    *base = 0;
    *limit = 0;
    if ( seg != x86_seg_es )
        seg = vmx_outs_get_segment(long_mode, eip, inst_len);

    switch ( seg )
    {
    case x86_seg_cs:
        ar_field = GUEST_CS_AR_BYTES;
        base_field = GUEST_CS_BASE;
        limit_field = GUEST_CS_LIMIT;
        break;
    case x86_seg_ds:
        ar_field = GUEST_DS_AR_BYTES;
        base_field = GUEST_DS_BASE;
        limit_field = GUEST_DS_LIMIT;
        break;
    case x86_seg_es:
        ar_field = GUEST_ES_AR_BYTES;
        base_field = GUEST_ES_BASE;
        limit_field = GUEST_ES_LIMIT;
        break;
    case x86_seg_fs:
        ar_field = GUEST_FS_AR_BYTES;
        base_field = GUEST_FS_BASE;
        limit_field = GUEST_FS_LIMIT;
        break;
    case x86_seg_gs:
        ar_field = GUEST_GS_AR_BYTES;
        base_field = GUEST_GS_BASE;
        limit_field = GUEST_GS_LIMIT;
        break;
    case x86_seg_ss:
        ar_field = GUEST_SS_AR_BYTES;
        base_field = GUEST_SS_BASE;
        limit_field = GUEST_SS_LIMIT;
        break;
    default:
        BUG();
        return 0;
    }

    if ( !long_mode || seg == x86_seg_fs || seg == x86_seg_gs )
    {
        *base = __vmread(base_field);
        *limit = __vmread(limit_field);
    }
    *ar_bytes = __vmread(ar_field);

    return !(*ar_bytes & X86_SEG_AR_SEG_UNUSABLE);
}


static int vmx_str_pio_check_limit(u32 limit, unsigned int size,
                                   u32 ar_bytes, unsigned long addr,
                                   unsigned long base, int df,
                                   unsigned long *count)
{
    unsigned long ea = addr - base;

    /* Offset must be within limits. */
    ASSERT(ea == (u32)ea);
    if ( (u32)(ea + size - 1) < (u32)ea ||
         (ar_bytes & 0xc) != 0x4 ? ea + size - 1 > limit
                                 : ea <= limit )
        return 0;

    /* Check the limit for repeated instructions, as above we checked
       only the first instance. Truncate the count if a limit violation
       would occur. Note that the checking is not necessary for page
       granular segments as transfers crossing page boundaries will be
       broken up anyway. */
    if ( !(ar_bytes & X86_SEG_AR_GRANULARITY) && *count > 1 )
    {
        if ( (ar_bytes & 0xc) != 0x4 )
        {
            /* expand-up */
            if ( !df )
            {
                if ( ea + *count * size - 1 < ea ||
                     ea + *count * size - 1 > limit )
                    *count = (limit + 1UL - ea) / size;
            }
            else
            {
                if ( *count - 1 > ea / size )
                    *count = ea / size + 1;
            }
        }
        else
        {
            /* expand-down */
            if ( !df )
            {
                if ( *count - 1 > -(s32)ea / size )
                    *count = -(s32)ea / size + 1UL;
            }
            else
            {
                if ( ea < (*count - 1) * size ||
                     ea - (*count - 1) * size <= limit )
                    *count = (ea - limit - 1) / size + 1;
            }
        }
        ASSERT(*count);
    }

    return 1;
}

#ifdef __x86_64__
static int vmx_str_pio_lm_check_limit(struct cpu_user_regs *regs,
                                      unsigned int size,
                                      unsigned long addr,
                                      unsigned long *count)
{
    if ( !is_canonical_address(addr) ||
         !is_canonical_address(addr + size - 1) )
        return 0;

    if ( *count > (1UL << 48) / size )
        *count = (1UL << 48) / size;

    if ( !(regs->eflags & EF_DF) )
    {
        if ( addr + *count * size - 1 < addr ||
             !is_canonical_address(addr + *count * size - 1) )
            *count = (addr & ~((1UL << 48) - 1)) / size;
    }
    else
    {
        if ( (*count - 1) * size > addr ||
             !is_canonical_address(addr + (*count - 1) * size) )
            *count = (addr & ~((1UL << 48) - 1)) / size + 1;
    }

    ASSERT(*count);

    return 1;
}
#endif

static void vmx_send_str_pio(struct cpu_user_regs *regs,
                             struct hvm_io_op *pio_opp,
                             unsigned long inst_len, unsigned int port,
                             int sign, unsigned int size, int dir,
                             int df, unsigned long addr,
                             paddr_t paddr, unsigned long count)
{
    /*
     * Handle string pio instructions that cross pages or that
     * are unaligned. See the comments in hvm_domain.c/handle_mmio()
     */
    if ( (addr & PAGE_MASK) != ((addr + size - 1) & PAGE_MASK) ) {
        unsigned long value = 0;

        pio_opp->flags |= OVERLAP;

        if ( dir == IOREQ_WRITE )   /* OUTS */
        {
            if ( hvm_paging_enabled(current) )
            {
                int rv = hvm_copy_from_guest_virt(&value, addr, size);
                if ( rv == HVMCOPY_bad_gva_to_gfn )
                    return; /* exception already injected */
            }
            else
                (void)hvm_copy_from_guest_phys(&value, addr, size);
        }
        else /* dir != IOREQ_WRITE */
            /* Remember where to write the result, as a *VA*.
             * Must be a VA so we can handle the page overlap
             * correctly in hvm_pio_assist() */
            pio_opp->addr = addr;

        if ( count == 1 )
            regs->eip += inst_len;

        send_pio_req(port, 1, size, value, dir, df, 0);
    } else {
        unsigned long last_addr = sign > 0 ? addr + count * size - 1
                                           : addr - (count - 1) * size;

        if ( (addr & PAGE_MASK) != (last_addr & PAGE_MASK) )
        {
            if ( sign > 0 )
                count = (PAGE_SIZE - (addr & ~PAGE_MASK)) / size;
            else
                count = (addr & ~PAGE_MASK) / size + 1;
        } else
            regs->eip += inst_len;

        send_pio_req(port, count, size, paddr, dir, df, 1);
    }
}

static void vmx_do_str_pio(unsigned long exit_qualification,
                           unsigned long inst_len,
                           struct cpu_user_regs *regs,
                           struct hvm_io_op *pio_opp)
{
    unsigned int port, size;
    int dir, df, vm86;
    unsigned long addr, count = 1, base;
    paddr_t paddr;
    unsigned long gfn;
    u32 ar_bytes, limit, pfec;
    int sign;
    int long_mode = 0;

    vm86 = regs->eflags & X86_EFLAGS_VM ? 1 : 0;
    df = regs->eflags & X86_EFLAGS_DF ? 1 : 0;

    if ( test_bit(6, &exit_qualification) )
        port = (exit_qualification >> 16) & 0xFFFF;
    else
        port = regs->edx & 0xffff;

    size = (exit_qualification & 7) + 1;
    dir = test_bit(3, &exit_qualification); /* direction */

    if ( dir == IOREQ_READ )
        HVMTRACE_2D(IO_READ,  current, port, size);
    else
        HVMTRACE_2D(IO_WRITE, current, port, size);

    sign = regs->eflags & X86_EFLAGS_DF ? -1 : 1;
    ar_bytes = __vmread(GUEST_CS_AR_BYTES);
    if ( hvm_long_mode_enabled(current) &&
         (ar_bytes & X86_SEG_AR_CS_LM_ACTIVE) )
        long_mode = 1;
    addr = __vmread(GUEST_LINEAR_ADDRESS);

    if ( test_bit(5, &exit_qualification) ) { /* "rep" prefix */
        pio_opp->flags |= REPZ;
        count = regs->ecx;
        if ( !long_mode &&
            (vm86 || !(ar_bytes & X86_SEG_AR_DEF_OP_SIZE)) )
            count &= 0xFFFF;
    }

    /*
     * In protected mode, guest linear address is invalid if the
     * selector is null.
     */
    if ( !vmx_str_pio_check_descriptor(long_mode, regs->eip, inst_len,
                                       dir==IOREQ_WRITE ? x86_seg_ds :
                                       x86_seg_es, &base, &limit,
                                       &ar_bytes) ) {
        if ( !long_mode ) {
            vmx_inject_hw_exception(current, TRAP_gp_fault, 0);
            return;
        }
        addr = dir == IOREQ_WRITE ? base + regs->esi : regs->edi;
    }

    if ( !long_mode )
    {
        /* Segment must be readable for outs and writeable for ins. */
        if ( ((dir == IOREQ_WRITE)
              ? ((ar_bytes & 0xa) == 0x8)
              : ((ar_bytes & 0xa) != 0x2)) ||
             !vmx_str_pio_check_limit(limit, size, ar_bytes,
                                      addr, base, df, &count) )
        {
            vmx_inject_hw_exception(current, TRAP_gp_fault, 0);
            return;
        }
    }
#ifdef __x86_64__
    else if ( !vmx_str_pio_lm_check_limit(regs, size, addr, &count) )
    {
        vmx_inject_hw_exception(current, TRAP_gp_fault, 0);
        return;
    }
#endif

    /* Translate the address to a physical address */
    pfec = PFEC_page_present;
    if ( dir == IOREQ_READ ) /* Read from PIO --> write to RAM */
        pfec |= PFEC_write_access;
    if ( ((__vmread(GUEST_SS_AR_BYTES) >> 5) & 3) == 3 )
        pfec |= PFEC_user_mode;
    gfn = paging_gva_to_gfn(current, addr, &pfec);
    if ( gfn == INVALID_GFN )
    {
        /* The guest does not have the RAM address mapped.
         * Need to send in a page fault */
        vmx_inject_exception(TRAP_page_fault, pfec, addr);
        return;
    }
    paddr = (paddr_t)gfn << PAGE_SHIFT | (addr & ~PAGE_MASK);

    vmx_send_str_pio(regs, pio_opp, inst_len, port, sign,
                     size, dir, df, addr, paddr, count);
}

static void vmx_io_instruction(unsigned long exit_qualification,
                               unsigned long inst_len)
{
    struct cpu_user_regs *regs;
    struct hvm_io_op *pio_opp;

    pio_opp = &current->arch.hvm_vcpu.io_op;
    pio_opp->instr = INSTR_PIO;
    pio_opp->flags = 0;

    regs = &pio_opp->io_context;

    /* Copy current guest state into io instruction state structure. */
    memcpy(regs, guest_cpu_user_regs(), HVM_CONTEXT_STACK_BYTES);

    HVM_DBG_LOG(DBG_LEVEL_IO, "vm86 %d, eip=%x:%lx, "
                "exit_qualification = %lx",
                regs->eflags & X86_EFLAGS_VM ? 1 : 0,
                regs->cs, (unsigned long)regs->eip, exit_qualification);

    if ( test_bit(4, &exit_qualification) ) /* string instrucation */
        vmx_do_str_pio(exit_qualification, inst_len, regs, pio_opp);
    else
    {
        unsigned int port, size;
        int dir, df;

        df = regs->eflags & X86_EFLAGS_DF ? 1 : 0;

        if ( test_bit(6, &exit_qualification) )
            port = (exit_qualification >> 16) & 0xFFFF;
        else
            port = regs->edx & 0xffff;

        size = (exit_qualification & 7) + 1;
        dir = test_bit(3, &exit_qualification); /* direction */

        if ( dir == IOREQ_READ )
            HVMTRACE_2D(IO_READ,  current, port, size);
        else
            HVMTRACE_3D(IO_WRITE, current, port, size, regs->eax);

        if ( port == 0xe9 && dir == IOREQ_WRITE && size == 1 )
            hvm_print_line(current, regs->eax); /* guest debug output */

        regs->eip += inst_len;
        send_pio_req(port, 1, size, regs->eax, dir, df, 0);
    }
}

#ifdef VMXASSIST

static void vmx_world_save(struct vcpu *v, struct vmx_assist_context *c)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();

    c->eip  = regs->eip;
    c->eip += __get_instruction_length(); /* Safe: MOV Cn, LMSW, CLTS */
    c->esp = regs->esp;
    c->eflags = regs->eflags & ~X86_EFLAGS_RF;

    c->cr0 = v->arch.hvm_vcpu.guest_cr[0];
    c->cr3 = v->arch.hvm_vcpu.guest_cr[3];
    c->cr4 = v->arch.hvm_vcpu.guest_cr[4];

    c->idtr_limit = __vmread(GUEST_IDTR_LIMIT);
    c->idtr_base = __vmread(GUEST_IDTR_BASE);

    c->gdtr_limit = __vmread(GUEST_GDTR_LIMIT);
    c->gdtr_base = __vmread(GUEST_GDTR_BASE);

    c->cs_sel = __vmread(GUEST_CS_SELECTOR);
    c->cs_limit = __vmread(GUEST_CS_LIMIT);
    c->cs_base = __vmread(GUEST_CS_BASE);
    c->cs_arbytes.bytes = __vmread(GUEST_CS_AR_BYTES);

    c->ds_sel = __vmread(GUEST_DS_SELECTOR);
    c->ds_limit = __vmread(GUEST_DS_LIMIT);
    c->ds_base = __vmread(GUEST_DS_BASE);
    c->ds_arbytes.bytes = __vmread(GUEST_DS_AR_BYTES);

    c->es_sel = __vmread(GUEST_ES_SELECTOR);
    c->es_limit = __vmread(GUEST_ES_LIMIT);
    c->es_base = __vmread(GUEST_ES_BASE);
    c->es_arbytes.bytes = __vmread(GUEST_ES_AR_BYTES);

    c->ss_sel = __vmread(GUEST_SS_SELECTOR);
    c->ss_limit = __vmread(GUEST_SS_LIMIT);
    c->ss_base = __vmread(GUEST_SS_BASE);
    c->ss_arbytes.bytes = __vmread(GUEST_SS_AR_BYTES);

    c->fs_sel = __vmread(GUEST_FS_SELECTOR);
    c->fs_limit = __vmread(GUEST_FS_LIMIT);
    c->fs_base = __vmread(GUEST_FS_BASE);
    c->fs_arbytes.bytes = __vmread(GUEST_FS_AR_BYTES);

    c->gs_sel = __vmread(GUEST_GS_SELECTOR);
    c->gs_limit = __vmread(GUEST_GS_LIMIT);
    c->gs_base = __vmread(GUEST_GS_BASE);
    c->gs_arbytes.bytes = __vmread(GUEST_GS_AR_BYTES);

    c->tr_sel = __vmread(GUEST_TR_SELECTOR);
    c->tr_limit = __vmread(GUEST_TR_LIMIT);
    c->tr_base = __vmread(GUEST_TR_BASE);
    c->tr_arbytes.bytes = __vmread(GUEST_TR_AR_BYTES);

    c->ldtr_sel = __vmread(GUEST_LDTR_SELECTOR);
    c->ldtr_limit = __vmread(GUEST_LDTR_LIMIT);
    c->ldtr_base = __vmread(GUEST_LDTR_BASE);
    c->ldtr_arbytes.bytes = __vmread(GUEST_LDTR_AR_BYTES);
}

static int vmx_world_restore(struct vcpu *v, struct vmx_assist_context *c)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    int rc;

    rc = vmx_restore_cr0_cr3(v, c->cr0, c->cr3);
    if ( rc )
        return rc;

    regs->eip = c->eip;
    regs->esp = c->esp;
    regs->eflags = c->eflags | 2;

    v->arch.hvm_vcpu.guest_cr[4] = c->cr4;
    vmx_update_guest_cr(v, 0);
    vmx_update_guest_cr(v, 4);

    __vmwrite(GUEST_IDTR_LIMIT, c->idtr_limit);
    __vmwrite(GUEST_IDTR_BASE, c->idtr_base);

    __vmwrite(GUEST_GDTR_LIMIT, c->gdtr_limit);
    __vmwrite(GUEST_GDTR_BASE, c->gdtr_base);

    __vmwrite(GUEST_CS_SELECTOR, c->cs_sel);
    __vmwrite(GUEST_CS_LIMIT, c->cs_limit);
    __vmwrite(GUEST_CS_BASE, c->cs_base);
    __vmwrite(GUEST_CS_AR_BYTES, c->cs_arbytes.bytes);

    __vmwrite(GUEST_DS_SELECTOR, c->ds_sel);
    __vmwrite(GUEST_DS_LIMIT, c->ds_limit);
    __vmwrite(GUEST_DS_BASE, c->ds_base);
    __vmwrite(GUEST_DS_AR_BYTES, c->ds_arbytes.bytes);

    __vmwrite(GUEST_ES_SELECTOR, c->es_sel);
    __vmwrite(GUEST_ES_LIMIT, c->es_limit);
    __vmwrite(GUEST_ES_BASE, c->es_base);
    __vmwrite(GUEST_ES_AR_BYTES, c->es_arbytes.bytes);

    __vmwrite(GUEST_SS_SELECTOR, c->ss_sel);
    __vmwrite(GUEST_SS_LIMIT, c->ss_limit);
    __vmwrite(GUEST_SS_BASE, c->ss_base);
    __vmwrite(GUEST_SS_AR_BYTES, c->ss_arbytes.bytes);

    __vmwrite(GUEST_FS_SELECTOR, c->fs_sel);
    __vmwrite(GUEST_FS_LIMIT, c->fs_limit);
    __vmwrite(GUEST_FS_BASE, c->fs_base);
    __vmwrite(GUEST_FS_AR_BYTES, c->fs_arbytes.bytes);

    __vmwrite(GUEST_GS_SELECTOR, c->gs_sel);
    __vmwrite(GUEST_GS_LIMIT, c->gs_limit);
    __vmwrite(GUEST_GS_BASE, c->gs_base);
    __vmwrite(GUEST_GS_AR_BYTES, c->gs_arbytes.bytes);

    __vmwrite(GUEST_TR_SELECTOR, c->tr_sel);
    __vmwrite(GUEST_TR_LIMIT, c->tr_limit);
    __vmwrite(GUEST_TR_BASE, c->tr_base);
    __vmwrite(GUEST_TR_AR_BYTES, c->tr_arbytes.bytes);

    __vmwrite(GUEST_LDTR_SELECTOR, c->ldtr_sel);
    __vmwrite(GUEST_LDTR_LIMIT, c->ldtr_limit);
    __vmwrite(GUEST_LDTR_BASE, c->ldtr_base);
    __vmwrite(GUEST_LDTR_AR_BYTES, c->ldtr_arbytes.bytes);

    paging_update_paging_modes(v);
    return 0;
}

enum { VMX_ASSIST_INVOKE = 0, VMX_ASSIST_RESTORE };

static int vmx_assist(struct vcpu *v, int mode)
{
    struct vmx_assist_context c;
    struct hvm_hw_vpic *vpic = v->domain->arch.hvm_domain.vpic;
    u32 magic, cp;

    if ( hvm_copy_from_guest_phys(&magic, VMXASSIST_MAGIC_OFFSET,
                                  sizeof(magic)) )
    {
        gdprintk(XENLOG_ERR, "No vmxassist: can't execute real mode code\n");
        domain_crash(v->domain);
        return 0;
    }

    if ( magic != VMXASSIST_MAGIC )
    {
        gdprintk(XENLOG_ERR, "vmxassist magic number not match\n");
        domain_crash(v->domain);
        return 0;
    }

    switch ( mode ) {
        /*
         * Transfer control to vmxassist.
         * Store the current context in VMXASSIST_OLD_CONTEXT and load
         * the new VMXASSIST_NEW_CONTEXT context. This context was created
         * by vmxassist and will transfer control to it.
         */
    case VMX_ASSIST_INVOKE:
        /* save the old context */
        if ( hvm_copy_from_guest_phys(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp)) )
            goto error;
        if ( cp != 0 ) {
            vmx_world_save(v, &c);
            if ( hvm_copy_to_guest_phys(cp, &c, sizeof(c)) )
                goto error;
        }

        /* restore the new context, this should activate vmxassist */
        if ( hvm_copy_from_guest_phys(&cp, VMXASSIST_NEW_CONTEXT, sizeof(cp)) )
            goto error;
        if ( cp != 0 ) {
            if ( hvm_copy_from_guest_phys(&c, cp, sizeof(c)) )
                goto error;
            if ( vmx_world_restore(v, &c) != 0 )
                goto error;
            v->arch.hvm_vmx.pm_irqbase[0] = vpic[0].irq_base;
            v->arch.hvm_vmx.pm_irqbase[1] = vpic[1].irq_base;
            vpic[0].irq_base = NR_EXCEPTION_HANDLER;
            vpic[1].irq_base = NR_EXCEPTION_HANDLER + 8;
            v->arch.hvm_vmx.vmxassist_enabled = 1;
            return 1;
        }
        break;

        /*
         * Restore the VMXASSIST_OLD_CONTEXT that was saved by
         * VMX_ASSIST_INVOKE above.
         */
    case VMX_ASSIST_RESTORE:
        /* save the old context */
        if ( hvm_copy_from_guest_phys(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp)) )
            goto error;
        if ( cp != 0 ) {
            if ( hvm_copy_from_guest_phys(&c, cp, sizeof(c)) )
                goto error;
            if ( vmx_world_restore(v, &c) != 0 )
                goto error;
            if ( v->arch.hvm_vmx.irqbase_mode ) {
                vpic[0].irq_base = c.rm_irqbase[0] & 0xf8;
                vpic[1].irq_base = c.rm_irqbase[1] & 0xf8;
            } else {
                vpic[0].irq_base = v->arch.hvm_vmx.pm_irqbase[0];
                vpic[1].irq_base = v->arch.hvm_vmx.pm_irqbase[1];
            }
            v->arch.hvm_vmx.vmxassist_enabled = 0;
            return 1;
        }
        break;
    }

 error:
    gdprintk(XENLOG_ERR, "Failed to transfer to vmxassist\n");
    domain_crash(v->domain);
    return 0;
}

static int vmx_set_cr0(unsigned long value)
{
    struct vcpu *v = current;

    if ( hvm_set_cr0(value) == 0 )
        return 0;

    /*
     * VMX does not implement real-mode virtualization. We emulate
     * real-mode by performing a world switch to VMXAssist whenever
     * a partition disables the CR0.PE bit.
     */
    if ( !(value & X86_CR0_PE) )
    {
        if ( vmx_assist(v, VMX_ASSIST_INVOKE) )
            return 0; /* do not update eip! */
    }
    else if ( v->arch.hvm_vmx.vmxassist_enabled )
    {
        if ( vmx_assist(v, VMX_ASSIST_RESTORE) )
            return 0; /* do not update eip! */
    }

    return 1;
}

#else /* !defined(VMXASSIST) */

#define vmx_set_cr0(v) hvm_set_cr0(v)

#endif

#define CASE_SET_REG(REG, reg)      \
    case REG_ ## REG: regs->reg = value; break
#define CASE_GET_REG(REG, reg)      \
    case REG_ ## REG: value = regs->reg; break

#define CASE_EXTEND_SET_REG         \
    CASE_EXTEND_REG(S)
#define CASE_EXTEND_GET_REG         \
    CASE_EXTEND_REG(G)

#ifdef __i386__
#define CASE_EXTEND_REG(T)
#else
#define CASE_EXTEND_REG(T)          \
    CASE_ ## T ## ET_REG(R8, r8);   \
    CASE_ ## T ## ET_REG(R9, r9);   \
    CASE_ ## T ## ET_REG(R10, r10); \
    CASE_ ## T ## ET_REG(R11, r11); \
    CASE_ ## T ## ET_REG(R12, r12); \
    CASE_ ## T ## ET_REG(R13, r13); \
    CASE_ ## T ## ET_REG(R14, r14); \
    CASE_ ## T ## ET_REG(R15, r15)
#endif

static int mov_to_cr(int gp, int cr, struct cpu_user_regs *regs)
{
    unsigned long value;
    struct vcpu *v = current;
    struct vlapic *vlapic = vcpu_vlapic(v);

    switch ( gp )
    {
    CASE_GET_REG(EAX, eax);
    CASE_GET_REG(ECX, ecx);
    CASE_GET_REG(EDX, edx);
    CASE_GET_REG(EBX, ebx);
    CASE_GET_REG(EBP, ebp);
    CASE_GET_REG(ESI, esi);
    CASE_GET_REG(EDI, edi);
    CASE_GET_REG(ESP, esp);
    CASE_EXTEND_GET_REG;
    default:
        gdprintk(XENLOG_ERR, "invalid gp: %d\n", gp);
        goto exit_and_crash;
    }

    HVMTRACE_2D(CR_WRITE, v, cr, value);

    HVM_DBG_LOG(DBG_LEVEL_1, "CR%d, value = %lx", cr, value);

    switch ( cr )
    {
    case 0:
        return vmx_set_cr0(value);

    case 3:
        return hvm_set_cr3(value);

    case 4:
        return hvm_set_cr4(value);

    case 8:
        vlapic_set_reg(vlapic, APIC_TASKPRI, ((value & 0x0F) << 4));
        break;

    default:
        gdprintk(XENLOG_ERR, "invalid cr: %d\n", cr);
        goto exit_and_crash;
    }

    return 1;

 exit_and_crash:
    domain_crash(v->domain);
    return 0;
}

/*
 * Read from control registers. CR0 and CR4 are read from the shadow.
 */
static void mov_from_cr(int cr, int gp, struct cpu_user_regs *regs)
{
    unsigned long value = 0;
    struct vcpu *v = current;
    struct vlapic *vlapic = vcpu_vlapic(v);

    switch ( cr )
    {
    case 3:
        value = (unsigned long)v->arch.hvm_vcpu.guest_cr[3];
        break;
    case 8:
        value = (unsigned long)vlapic_get_reg(vlapic, APIC_TASKPRI);
        value = (value & 0xF0) >> 4;
        break;
    default:
        gdprintk(XENLOG_ERR, "invalid cr: %d\n", cr);
        domain_crash(v->domain);
        break;
    }

    switch ( gp ) {
    CASE_SET_REG(EAX, eax);
    CASE_SET_REG(ECX, ecx);
    CASE_SET_REG(EDX, edx);
    CASE_SET_REG(EBX, ebx);
    CASE_SET_REG(EBP, ebp);
    CASE_SET_REG(ESI, esi);
    CASE_SET_REG(EDI, edi);
    CASE_SET_REG(ESP, esp);
    CASE_EXTEND_SET_REG;
    default:
        printk("invalid gp: %d\n", gp);
        domain_crash(v->domain);
        break;
    }

    HVMTRACE_2D(CR_READ, v, cr, value);

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR%d, value = %lx", cr, value);
}

static int vmx_cr_access(unsigned long exit_qualification,
                         struct cpu_user_regs *regs)
{
    unsigned int gp, cr;
    unsigned long value;
    struct vcpu *v = current;

    switch ( exit_qualification & CONTROL_REG_ACCESS_TYPE )
    {
    case TYPE_MOV_TO_CR:
        gp = exit_qualification & CONTROL_REG_ACCESS_REG;
        cr = exit_qualification & CONTROL_REG_ACCESS_NUM;
        return mov_to_cr(gp, cr, regs);
    case TYPE_MOV_FROM_CR:
        gp = exit_qualification & CONTROL_REG_ACCESS_REG;
        cr = exit_qualification & CONTROL_REG_ACCESS_NUM;
        mov_from_cr(cr, gp, regs);
        break;
    case TYPE_CLTS:
        /* We initialise the FPU now, to avoid needing another vmexit. */
        setup_fpu(v);
        __vm_clear_bit(EXCEPTION_BITMAP, TRAP_no_device);

        v->arch.hvm_vcpu.hw_cr[0] &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(GUEST_CR0, v->arch.hvm_vcpu.hw_cr[0]);

        v->arch.hvm_vcpu.guest_cr[0] &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vcpu.guest_cr[0]);
        HVMTRACE_0D(CLTS, current);
        break;
    case TYPE_LMSW:
        value = v->arch.hvm_vcpu.guest_cr[0];
        value = (value & ~0xF) |
            (((exit_qualification & LMSW_SOURCE_DATA) >> 16) & 0xF);
        HVMTRACE_1D(LMSW, current, value);
        return vmx_set_cr0(value);
    default:
        BUG();
    }

    return 1;
}

static const struct lbr_info {
    u32 base, count;
} p4_lbr[] = {
    { MSR_P4_LER_FROM_LIP,          1 },
    { MSR_P4_LER_TO_LIP,            1 },
    { MSR_P4_LASTBRANCH_TOS,        1 },
    { MSR_P4_LASTBRANCH_0_FROM_LIP, NUM_MSR_P4_LASTBRANCH_FROM_TO },
    { MSR_P4_LASTBRANCH_0_TO_LIP,   NUM_MSR_P4_LASTBRANCH_FROM_TO },
    { 0, 0 }
}, c2_lbr[] = {
    { MSR_IA32_LASTINTFROMIP,       1 },
    { MSR_IA32_LASTINTTOIP,         1 },
    { MSR_C2_LASTBRANCH_TOS,        1 },
    { MSR_C2_LASTBRANCH_0_FROM_IP,  NUM_MSR_C2_LASTBRANCH_FROM_TO },
    { MSR_C2_LASTBRANCH_0_TO_IP,    NUM_MSR_C2_LASTBRANCH_FROM_TO },
    { 0, 0 }
#ifdef __i386__
}, pm_lbr[] = {
    { MSR_IA32_LASTINTFROMIP,       1 },
    { MSR_IA32_LASTINTTOIP,         1 },
    { MSR_PM_LASTBRANCH_TOS,        1 },
    { MSR_PM_LASTBRANCH_0,          NUM_MSR_PM_LASTBRANCH },
    { 0, 0 }
#endif
};

static const struct lbr_info *last_branch_msr_get(void)
{
    switch ( boot_cpu_data.x86 )
    {
    case 6:
        switch ( boot_cpu_data.x86_model )
        {
#ifdef __i386__
        /* PentiumM */
        case 9: case 13:
        /* Core Solo/Duo */
        case 14:
            return pm_lbr;
            break;
#endif
        /* Core2 Duo */
        case 15:
            return c2_lbr;
            break;
        }
        break;

    case 15:
        switch ( boot_cpu_data.x86_model )
        {
        /* Pentium4/Xeon with em64t */
        case 3: case 4: case 6:
            return p4_lbr;
            break;
        }
        break;
    }

    return NULL;
}

static int is_last_branch_msr(u32 ecx)
{
    const struct lbr_info *lbr = last_branch_msr_get();

    if ( lbr == NULL )
        return 0;

    for ( ; lbr->count; lbr++ )
        if ( (ecx >= lbr->base) && (ecx < (lbr->base + lbr->count)) )
            return 1;

    return 0;
}

static int vmx_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    u32 ecx = regs->ecx, eax, edx;
    struct vcpu *v = current;
    int index;
    u64 *var_range_base = (u64*)v->arch.hvm_vcpu.mtrr.var_ranges;
    u64 *fixed_range_base =  (u64*)v->arch.hvm_vcpu.mtrr.fixed_ranges;

    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x", ecx);

    switch ( ecx )
    {
    case MSR_IA32_TSC:
        msr_content = hvm_get_guest_time(v);
        break;
    case MSR_IA32_SYSENTER_CS:
        msr_content = (u32)__vmread(GUEST_SYSENTER_CS);
        break;
    case MSR_IA32_SYSENTER_ESP:
        msr_content = __vmread(GUEST_SYSENTER_ESP);
        break;
    case MSR_IA32_SYSENTER_EIP:
        msr_content = __vmread(GUEST_SYSENTER_EIP);
        break;
    case MSR_IA32_APICBASE:
        msr_content = vcpu_vlapic(v)->hw.apic_base_msr;
        break;
    case MSR_IA32_CR_PAT:
        msr_content = v->arch.hvm_vcpu.pat_cr;
        break;
    case MSR_MTRRcap:
        msr_content = v->arch.hvm_vcpu.mtrr.mtrr_cap;
        break;
    case MSR_MTRRdefType:
        msr_content = v->arch.hvm_vcpu.mtrr.def_type
                        | (v->arch.hvm_vcpu.mtrr.enabled << 10);
        break;
    case MSR_MTRRfix64K_00000:
        msr_content = fixed_range_base[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        index = regs->ecx - MSR_MTRRfix16K_80000;
        msr_content = fixed_range_base[index + 1];
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        index = regs->ecx - MSR_MTRRfix4K_C0000;
        msr_content = fixed_range_base[index + 3];
        break;
    case MSR_IA32_MTRR_PHYSBASE0...MSR_IA32_MTRR_PHYSMASK7:
        index = regs->ecx - MSR_IA32_MTRR_PHYSBASE0;
        msr_content = var_range_base[index];
        break;
    case MSR_IA32_DEBUGCTLMSR:
        if ( vmx_read_guest_msr(v, ecx, &msr_content) != 0 )
            msr_content = 0;
        break;
    case MSR_IA32_VMX_BASIC...MSR_IA32_VMX_PROCBASED_CTLS2:
        goto gp_fault;
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
    default:
        switch ( long_mode_do_msr_read(regs) )
        {
            case HNDL_unhandled:
                break;
            case HNDL_exception_raised:
                return 0;
            case HNDL_done:
                goto done;
        }

        if ( vmx_read_guest_msr(v, ecx, &msr_content) == 0 )
            break;

        if ( is_last_branch_msr(ecx) )
        {
            msr_content = 0;
            break;
        }

        if ( rdmsr_hypervisor_regs(ecx, &eax, &edx) ||
             rdmsr_safe(ecx, eax, edx) == 0 )
        {
            regs->eax = eax;
            regs->edx = edx;
            goto done;
        }

        goto gp_fault;
    }

    regs->eax = msr_content & 0xFFFFFFFF;
    regs->edx = msr_content >> 32;

done:
    hvmtrace_msr_read(v, ecx, msr_content);
    HVM_DBG_LOG(DBG_LEVEL_1, "returns: ecx=%x, eax=%lx, edx=%lx",
                ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
    return 1;

gp_fault:
    vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
    return 0;
}

static int vmx_alloc_vlapic_mapping(struct domain *d)
{
    void *apic_va;

    if ( !cpu_has_vmx_virtualize_apic_accesses )
        return 0;

    apic_va = alloc_xenheap_page();
    if ( apic_va == NULL )
        return -ENOMEM;
    share_xen_page_with_guest(virt_to_page(apic_va), d, XENSHARE_writable);
    set_mmio_p2m_entry(
        d, paddr_to_pfn(APIC_DEFAULT_PHYS_BASE), _mfn(virt_to_mfn(apic_va)));
    d->arch.hvm_domain.vmx_apic_access_mfn = virt_to_mfn(apic_va);

    return 0;
}

static void vmx_free_vlapic_mapping(struct domain *d)
{
    unsigned long mfn = d->arch.hvm_domain.vmx_apic_access_mfn;
    if ( mfn != 0 )
        free_xenheap_page(mfn_to_virt(mfn));
}

static void vmx_install_vlapic_mapping(struct vcpu *v)
{
    paddr_t virt_page_ma, apic_page_ma;

    if ( !cpu_has_vmx_virtualize_apic_accesses )
        return;

    virt_page_ma = page_to_maddr(vcpu_vlapic(v)->regs_page);
    apic_page_ma = v->domain->arch.hvm_domain.vmx_apic_access_mfn;
    apic_page_ma <<= PAGE_SHIFT;

    vmx_vmcs_enter(v);
    __vmwrite(VIRTUAL_APIC_PAGE_ADDR, virt_page_ma);
    __vmwrite(APIC_ACCESS_ADDR, apic_page_ma);
    vmx_vmcs_exit(v);
}

void vmx_vlapic_msr_changed(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    uint32_t ctl;

    if ( !cpu_has_vmx_virtualize_apic_accesses )
        return;

    vmx_vmcs_enter(v);
    ctl  = __vmread(SECONDARY_VM_EXEC_CONTROL);
    ctl &= ~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
    if ( !vlapic_hw_disabled(vlapic) &&
         (vlapic_base_address(vlapic) == APIC_DEFAULT_PHYS_BASE) )
        ctl |= SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
    __vmwrite(SECONDARY_VM_EXEC_CONTROL, ctl);
    vmx_vmcs_exit(v);
}

extern bool_t mtrr_var_range_msr_set(struct mtrr_state *v,
        u32 msr, u64 msr_content);
extern bool_t mtrr_fix_range_msr_set(struct mtrr_state *v,
        int row, u64 msr_content);
extern bool_t mtrr_def_type_msr_set(struct mtrr_state *v, u64 msr_content);
extern bool_t pat_msr_set(u64 *pat, u64 msr);

static int vmx_do_msr_write(struct cpu_user_regs *regs)
{
    u32 ecx = regs->ecx;
    u64 msr_content;
    struct vcpu *v = current;
    int index;

    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x, eax=%x, edx=%x",
                ecx, (u32)regs->eax, (u32)regs->edx);

    msr_content = (u32)regs->eax | ((u64)regs->edx << 32);

    hvmtrace_msr_write(v, ecx, msr_content);

    switch ( ecx )
    {
    case MSR_IA32_TSC:
        hvm_set_guest_time(v, msr_content);
        pt_reset(v);
        break;
    case MSR_IA32_SYSENTER_CS:
        __vmwrite(GUEST_SYSENTER_CS, msr_content);
        break;
    case MSR_IA32_SYSENTER_ESP:
        __vmwrite(GUEST_SYSENTER_ESP, msr_content);
        break;
    case MSR_IA32_SYSENTER_EIP:
        __vmwrite(GUEST_SYSENTER_EIP, msr_content);
        break;
    case MSR_IA32_APICBASE:
        vlapic_msr_set(vcpu_vlapic(v), msr_content);
        break;
    case MSR_IA32_CR_PAT:
        if ( !pat_msr_set(&v->arch.hvm_vcpu.pat_cr, msr_content) )
           goto gp_fault;
        break;
    case MSR_MTRRdefType:
        if ( !mtrr_def_type_msr_set(&v->arch.hvm_vcpu.mtrr, msr_content) )
           goto gp_fault;
        break;
    case MSR_MTRRfix64K_00000:
        if ( !mtrr_fix_range_msr_set(&v->arch.hvm_vcpu.mtrr, 0, msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        index = regs->ecx - MSR_MTRRfix16K_80000 + 1;
        if ( !mtrr_fix_range_msr_set(&v->arch.hvm_vcpu.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        index = regs->ecx - MSR_MTRRfix4K_C0000 + 3;
        if ( !mtrr_fix_range_msr_set(&v->arch.hvm_vcpu.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_IA32_MTRR_PHYSBASE0...MSR_IA32_MTRR_PHYSMASK7:
        if ( !mtrr_var_range_msr_set(&v->arch.hvm_vcpu.mtrr,
                                     regs->ecx, msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRcap:
        goto gp_fault;
    case MSR_IA32_DEBUGCTLMSR: {
        int i, rc = 0;

        if ( !msr_content || (msr_content & ~3) )
            break;

        if ( msr_content & 1 )
        {
            const struct lbr_info *lbr = last_branch_msr_get();
            if ( lbr == NULL )
                break;

            for ( ; (rc == 0) && lbr->count; lbr++ )
                for ( i = 0; (rc == 0) && (i < lbr->count); i++ )
                    if ( (rc = vmx_add_guest_msr(v, lbr->base + i)) == 0 )
                        vmx_disable_intercept_for_msr(v, lbr->base + i);
        }

        if ( (rc < 0) ||
             (vmx_add_guest_msr(v, ecx) < 0) ||
             (vmx_add_host_load_msr(v, ecx) < 0) )
            vmx_inject_hw_exception(v, TRAP_machine_check, 0);
        else
            vmx_write_guest_msr(v, ecx, msr_content);

        break;
    }
    case MSR_IA32_VMX_BASIC...MSR_IA32_VMX_PROCBASED_CTLS2:
        goto gp_fault;
    default:
        switch ( long_mode_do_msr_write(regs) )
        {
            case HNDL_unhandled:
                if ( (vmx_write_guest_msr(v, ecx, msr_content) != 0) &&
                     !is_last_branch_msr(ecx) )
                    wrmsr_hypervisor_regs(ecx, regs->eax, regs->edx);
                break;
            case HNDL_exception_raised:
                return 0;
            case HNDL_done:
                break;
        }
        break;
    }

    return 1;

gp_fault:
    vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
    return 0;
}

static void vmx_do_hlt(struct cpu_user_regs *regs)
{
    unsigned long intr_info = __vmread(VM_ENTRY_INTR_INFO);
    struct vcpu *curr = current;

    /* Check for pending exception. */
    if ( intr_info & INTR_INFO_VALID_MASK )
    {
        HVMTRACE_1D(HLT, curr, /*int pending=*/ 1);
        return;
    }

    HVMTRACE_1D(HLT, curr, /*int pending=*/ 0);
    hvm_hlt(regs->eflags);
}

static void vmx_do_extint(struct cpu_user_regs *regs)
{
    unsigned int vector;

    asmlinkage void do_IRQ(struct cpu_user_regs *);
    fastcall void smp_apic_timer_interrupt(struct cpu_user_regs *);
    fastcall void smp_event_check_interrupt(void);
    fastcall void smp_invalidate_interrupt(void);
    fastcall void smp_call_function_interrupt(void);
    fastcall void smp_spurious_interrupt(struct cpu_user_regs *regs);
    fastcall void smp_error_interrupt(struct cpu_user_regs *regs);
#ifdef CONFIG_X86_MCE_P4THERMAL
    fastcall void smp_thermal_interrupt(struct cpu_user_regs *regs);
#endif

    vector = __vmread(VM_EXIT_INTR_INFO);
    BUG_ON(!(vector & INTR_INFO_VALID_MASK));

    vector &= INTR_INFO_VECTOR_MASK;
    HVMTRACE_1D(INTR, current, vector);

    switch ( vector )
    {
    case LOCAL_TIMER_VECTOR:
        smp_apic_timer_interrupt(regs);
        break;
    case EVENT_CHECK_VECTOR:
        smp_event_check_interrupt();
        break;
    case INVALIDATE_TLB_VECTOR:
        smp_invalidate_interrupt();
        break;
    case CALL_FUNCTION_VECTOR:
        smp_call_function_interrupt();
        break;
    case SPURIOUS_APIC_VECTOR:
        smp_spurious_interrupt(regs);
        break;
    case ERROR_APIC_VECTOR:
        smp_error_interrupt(regs);
        break;
#ifdef CONFIG_X86_MCE_P4THERMAL
    case THERMAL_APIC_VECTOR:
        smp_thermal_interrupt(regs);
        break;
#endif
    default:
        regs->entry_vector = vector;
        do_IRQ(regs);
        break;
    }
}

static void wbinvd_ipi(void *info)
{
    wbinvd();
}

void vmx_wbinvd_intercept(void)
{
    if ( list_empty(&(domain_hvm_iommu(current->domain)->pdev_list)) )
        return;

    if ( cpu_has_wbinvd_exiting )
        on_each_cpu(wbinvd_ipi, NULL, 1, 1);
    else
        wbinvd();
}

static void vmx_failed_vmentry(unsigned int exit_reason,
                               struct cpu_user_regs *regs)
{
    unsigned int failed_vmentry_reason = (uint16_t)exit_reason;
    unsigned long exit_qualification = __vmread(EXIT_QUALIFICATION);
    struct vcpu *curr = current;

    printk("Failed vm entry (exit reason 0x%x) ", exit_reason);
    switch ( failed_vmentry_reason )
    {
    case EXIT_REASON_INVALID_GUEST_STATE:
        printk("caused by invalid guest state (%ld).\n", exit_qualification);
        break;
    case EXIT_REASON_MSR_LOADING:
        printk("caused by MSR entry %ld loading.\n", exit_qualification);
        break;
    case EXIT_REASON_MACHINE_CHECK:
        printk("caused by machine check.\n");
        HVMTRACE_0D(MCE, curr);
        do_machine_check(regs);
        break;
    default:
        printk("reason not known yet!");
        break;
    }

    printk("************* VMCS Area **************\n");
    vmcs_dump_vcpu(curr);
    printk("**************************************\n");

    domain_crash(curr->domain);
}

asmlinkage void vmx_vmexit_handler(struct cpu_user_regs *regs)
{
    unsigned int exit_reason, idtv_info;
    unsigned long exit_qualification, inst_len = 0;
    struct vcpu *v = current;

    exit_reason = __vmread(VM_EXIT_REASON);

    hvmtrace_vmexit(v, regs->eip, exit_reason);

    perfc_incra(vmexits, exit_reason);

    if ( exit_reason != EXIT_REASON_EXTERNAL_INTERRUPT )
        local_irq_enable();

    if ( unlikely(exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) )
        return vmx_failed_vmentry(exit_reason, regs);

    hvm_maybe_deassert_evtchn_irq();

    /* Event delivery caused this intercept? Queue for redelivery. */
    idtv_info = __vmread(IDT_VECTORING_INFO);
    if ( unlikely(idtv_info & INTR_INFO_VALID_MASK) &&
         (exit_reason != EXIT_REASON_TASK_SWITCH) )
    {
        if ( hvm_event_needs_reinjection((idtv_info>>8)&7, idtv_info&0xff) )
        {
            /* See SDM 3B 25.7.1.1 and .2 for info about masking resvd bits. */
            __vmwrite(VM_ENTRY_INTR_INFO,
                      idtv_info & ~INTR_INFO_RESVD_BITS_MASK);
            if ( idtv_info & INTR_INFO_DELIVER_CODE_MASK )
                __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE,
                          __vmread(IDT_VECTORING_ERROR_CODE));
        }

        /*
         * Clear NMI-blocking interruptibility info if an NMI delivery faulted.
         * Re-delivery will re-set it (see SDM 3B 25.7.1.2).
         */
        if ( (idtv_info & INTR_INFO_INTR_TYPE_MASK) == (X86_EVENTTYPE_NMI<<8) )
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO,
                      __vmread(GUEST_INTERRUPTIBILITY_INFO) &
                      ~VMX_INTR_SHADOW_NMI);
    }

    switch ( exit_reason )
    {
    case EXIT_REASON_EXCEPTION_NMI:
    {
        /*
         * We don't set the software-interrupt exiting (INT n).
         * (1) We can get an exception (e.g. #PG) in the guest, or
         * (2) NMI
         */
        unsigned int intr_info, vector;

        intr_info = __vmread(VM_EXIT_INTR_INFO);
        BUG_ON(!(intr_info & INTR_INFO_VALID_MASK));

        vector = intr_info & INTR_INFO_VECTOR_MASK;

        /*
         * Re-set the NMI shadow if vmexit caused by a guest IRET fault (see 3B
         * 25.7.1.2, "Resuming Guest Software after Handling an Exception").
         * (NB. If we emulate this IRET for any reason, we should re-clear!)
         */
        if ( unlikely(intr_info & INTR_INFO_NMI_UNBLOCKED_BY_IRET) &&
             !(__vmread(IDT_VECTORING_INFO) & INTR_INFO_VALID_MASK) &&
             (vector != TRAP_double_fault) )
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO,
                    __vmread(GUEST_INTERRUPTIBILITY_INFO)|VMX_INTR_SHADOW_NMI);

        perfc_incra(cause_vector, vector);

        switch ( vector )
        {
        case TRAP_debug:
        case TRAP_int3:
            if ( !v->domain->debugger_attached )
                goto exit_and_crash;
            domain_pause_for_debugger();
            break;
        case TRAP_no_device:
            vmx_do_no_device_fault();
            break;
        case TRAP_page_fault:
            exit_qualification = __vmread(EXIT_QUALIFICATION);
            regs->error_code = __vmread(VM_EXIT_INTR_ERROR_CODE);

            HVM_DBG_LOG(DBG_LEVEL_VMMU,
                        "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                        (unsigned long)regs->eax, (unsigned long)regs->ebx,
                        (unsigned long)regs->ecx, (unsigned long)regs->edx,
                        (unsigned long)regs->esi, (unsigned long)regs->edi);

            if ( paging_fault(exit_qualification, regs) )
            {
                hvmtrace_pf_xen(v, exit_qualification, regs->error_code);
                break;
            }

            v->arch.hvm_vcpu.guest_cr[2] = exit_qualification;
            vmx_inject_hw_exception(v, TRAP_page_fault, regs->error_code);
            break;
        case TRAP_nmi:
            if ( (intr_info & INTR_INFO_INTR_TYPE_MASK) !=
                 (X86_EVENTTYPE_NMI << 8) )
                goto exit_and_crash;
            HVMTRACE_0D(NMI, v);
            do_nmi(regs); /* Real NMI, vector 2: normal processing. */
            break;
        case TRAP_machine_check:
            HVMTRACE_0D(MCE, v);
            do_machine_check(regs);
            break;
        default:
            goto exit_and_crash;
        }
        break;
    }
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        vmx_do_extint(regs);
        break;
    case EXIT_REASON_TRIPLE_FAULT:
        hvm_triple_fault();
        break;
    case EXIT_REASON_PENDING_VIRT_INTR:
        /* Disable the interrupt window. */
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                  v->arch.hvm_vmx.exec_control);
        break;
    case EXIT_REASON_PENDING_VIRT_NMI:
        /* Disable the NMI window. */
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                  v->arch.hvm_vmx.exec_control);
        break;
    case EXIT_REASON_TASK_SWITCH: {
        const enum hvm_task_switch_reason reasons[] = {
            TSW_call_or_int, TSW_iret, TSW_jmp, TSW_call_or_int };
        int32_t errcode = -1;
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        if ( (idtv_info & INTR_INFO_VALID_MASK) &&
             (idtv_info & INTR_INFO_DELIVER_CODE_MASK) )
            errcode = __vmread(IDT_VECTORING_ERROR_CODE);
        hvm_task_switch((uint16_t)exit_qualification,
                        reasons[(exit_qualification >> 30) & 3],
                        errcode);
        break;
    }
    case EXIT_REASON_CPUID:
        inst_len = __get_instruction_length(); /* Safe: CPUID */
        __update_guest_eip(inst_len);
        vmx_do_cpuid(regs);
        break;
    case EXIT_REASON_HLT:
        inst_len = __get_instruction_length(); /* Safe: HLT */
        __update_guest_eip(inst_len);
        vmx_do_hlt(regs);
        break;
    case EXIT_REASON_INVLPG:
    {
        inst_len = __get_instruction_length(); /* Safe: INVLPG */
        __update_guest_eip(inst_len);
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        vmx_do_invlpg(exit_qualification);
        break;
    }
    case EXIT_REASON_VMCALL:
    {
        int rc;
        HVMTRACE_1D(VMMCALL, v, regs->eax);
        inst_len = __get_instruction_length(); /* Safe: VMCALL */
        rc = hvm_do_hypercall(regs);
        if ( rc != HVM_HCALL_preempted )
        {
            __update_guest_eip(inst_len);
            if ( rc == HVM_HCALL_invalidate )
                send_invalidate_req();
        }
        break;
    }
    case EXIT_REASON_CR_ACCESS:
    {
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        inst_len = __get_instruction_length(); /* Safe: MOV Cn, LMSW, CLTS */
        if ( vmx_cr_access(exit_qualification, regs) )
            __update_guest_eip(inst_len);
        break;
    }
    case EXIT_REASON_DR_ACCESS:
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        vmx_dr_access(exit_qualification, regs);
        break;
    case EXIT_REASON_IO_INSTRUCTION:
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        inst_len = __get_instruction_length(); /* Safe: IN, INS, OUT, OUTS */
        vmx_io_instruction(exit_qualification, inst_len);
        break;
    case EXIT_REASON_MSR_READ:
        inst_len = __get_instruction_length(); /* Safe: RDMSR */
        if ( vmx_do_msr_read(regs) )
            __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_MSR_WRITE:
        inst_len = __get_instruction_length(); /* Safe: WRMSR */
        if ( vmx_do_msr_write(regs) )
            __update_guest_eip(inst_len);
        break;

    case EXIT_REASON_MWAIT_INSTRUCTION:
    case EXIT_REASON_MONITOR_INSTRUCTION:
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        vmx_inject_hw_exception(v, TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;

    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        break;

    case EXIT_REASON_APIC_ACCESS:
    {
        unsigned long offset;
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        offset = exit_qualification & 0x0fffUL;
        handle_mmio(APIC_DEFAULT_PHYS_BASE | offset);
        break;
    }

    case EXIT_REASON_INVD:
    case EXIT_REASON_WBINVD:
    {
        inst_len = __get_instruction_length(); /* Safe: INVD, WBINVD */
        __update_guest_eip(inst_len);
        vmx_wbinvd_intercept();
        break;
    }

    default:
    exit_and_crash:
        gdprintk(XENLOG_ERR, "Bad vmexit (reason %x)\n", exit_reason);
        domain_crash(v->domain);
        break;
    }
}

asmlinkage void vmx_trace_vmentry(void)
{
    struct vcpu *v = current;
    
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
