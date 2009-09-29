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
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/vpt.h>
#include <public/hvm/save.h>
#include <asm/hvm/trace.h>
#include <asm/xenoprof.h>

enum handler_return { HNDL_done, HNDL_unhandled, HNDL_exception_raised };

static void vmx_ctxt_switch_from(struct vcpu *v);
static void vmx_ctxt_switch_to(struct vcpu *v);

static int  vmx_alloc_vlapic_mapping(struct domain *d);
static void vmx_free_vlapic_mapping(struct domain *d);
static int  vmx_alloc_vpid(struct vcpu *v);
static void vmx_free_vpid(struct vcpu *v);
static void vmx_install_vlapic_mapping(struct vcpu *v);
static void vmx_update_guest_cr(struct vcpu *v, unsigned int cr);
static void vmx_update_guest_efer(struct vcpu *v);
static void vmx_cpuid_intercept(
    unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx);
static void vmx_wbinvd_intercept(void);
static void vmx_fpu_dirty_intercept(void);
static int vmx_msr_read_intercept(struct cpu_user_regs *regs);
static int vmx_msr_write_intercept(struct cpu_user_regs *regs);
static void vmx_invlpg_intercept(unsigned long vaddr);
static void __ept_sync_domain(void *info);

static int vmx_domain_initialise(struct domain *d)
{
    int rc;

    d->arch.hvm_domain.vmx.ept_control.etmt = EPT_DEFAULT_MT;
    d->arch.hvm_domain.vmx.ept_control.gaw  = EPT_DEFAULT_GAW;
    d->arch.hvm_domain.vmx.ept_control.asr  =
        pagetable_get_pfn(d->arch.phys_table);


    if ( (rc = vmx_alloc_vlapic_mapping(d)) != 0 )
        return rc;

    return 0;
}

static void vmx_domain_destroy(struct domain *d)
{
    if ( d->arch.hvm_domain.hap_enabled )
        on_each_cpu(__ept_sync_domain, d, 1);
    vmx_free_vlapic_mapping(d);
}

static int vmx_vcpu_initialise(struct vcpu *v)
{
    int rc;

    spin_lock_init(&v->arch.hvm_vmx.vmcs_lock);

    if ( (rc = vmx_alloc_vpid(v)) != 0 )
        return rc;

    v->arch.schedule_tail    = vmx_do_resume;
    v->arch.ctxt_switch_from = vmx_ctxt_switch_from;
    v->arch.ctxt_switch_to   = vmx_ctxt_switch_to;

    if ( (rc = vmx_create_vmcs(v)) != 0 )
    {
        dprintk(XENLOG_WARNING,
                "Failed to create VMCS for vcpu %d: err=%d.\n",
                v->vcpu_id, rc);
        vmx_free_vpid(v);
        return rc;
    }

    vpmu_initialise(v);

    vmx_install_vlapic_mapping(v);

    /* %eax == 1 signals full real-mode support to the guest loader. */
    if ( v->vcpu_id == 0 )
        v->arch.guest_context.user_regs.eax = 1;

    return 0;
}

static void vmx_vcpu_destroy(struct vcpu *v)
{
    vmx_destroy_vmcs(v);
    vpmu_destroy(v);
    passive_domain_destroy(v);
    vmx_free_vpid(v);
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
        break;

    case MSR_GS_BASE:
        msr_content = __vmread(GUEST_GS_BASE);
        break;

    case MSR_SHADOW_GS_BASE:
        rdmsrl(MSR_SHADOW_GS_BASE, msr_content);
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
        if ( hvm_set_efer(msr_content) )
            goto exception_raised;
        break;

    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;

        if ( ecx == MSR_FS_BASE )
            __vmwrite(GUEST_FS_BASE, msr_content);
        else if ( ecx == MSR_GS_BASE )
            __vmwrite(GUEST_GS_BASE, msr_content);
        else
            wrmsrl(MSR_SHADOW_GS_BASE, msr_content);

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
    vmx_inject_hw_exception(TRAP_gp_fault, 0);
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
}

static void vmx_save_guest_msrs(struct vcpu *v)
{
    /*
     * We cannot cache SHADOW_GS_BASE while the VCPU runs, as it can
     * be updated at any time via SWAPGS, which we cannot trap.
     */
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

    if ( (v->arch.hvm_vcpu.guest_efer ^ read_efer()) & EFER_SCE )
    {
        HVM_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's EFER with value %lx",
                    v->arch.hvm_vcpu.guest_efer);
        write_efer((read_efer() & ~EFER_SCE) |
                   (v->arch.hvm_vcpu.guest_efer & EFER_SCE));
    }
}

#else  /* __i386__ */

#define vmx_save_host_msrs()        ((void)0)
#define vmx_restore_host_msrs()     ((void)0)

#define vmx_save_guest_msrs(v)      ((void)0)
#define vmx_restore_guest_msrs(v)   ((void)0)

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
        if ( hvm_set_efer(msr_content) )
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

static void vmx_vmcs_save(struct vcpu *v, struct hvm_hw_cpu *c)
{
    uint32_t ev;

    vmx_vmcs_enter(v);

    c->cr0 = v->arch.hvm_vcpu.guest_cr[0];
    c->cr2 = v->arch.hvm_vcpu.guest_cr[2];
    c->cr3 = v->arch.hvm_vcpu.guest_cr[3];
    c->cr4 = v->arch.hvm_vcpu.guest_cr[4];

    c->msr_efer = v->arch.hvm_vcpu.guest_efer;

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

    if ( paging_mode_shadow(v->domain) )
    {
        if ( cr0 & X86_CR0_PG )
        {
            mfn = mfn_x(gfn_to_mfn(v->domain, cr3 >> PAGE_SHIFT, &p2mt));
            if ( !p2m_is_ram(p2mt) || !get_page(mfn_to_page(mfn), v->domain) )
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value=0x%lx\n", cr3);
                return -EINVAL;
            }
        }

        if ( hvm_paging_enabled(v) )
            put_page(pagetable_get_page(v->arch.guest_table));

        v->arch.guest_table = pagetable_from_pfn(mfn);
    }

    v->arch.hvm_vcpu.guest_cr[0] = cr0 | X86_CR0_ET;
    v->arch.hvm_vcpu.guest_cr[3] = cr3;

    return 0;
}

static int vmx_vmcs_restore(struct vcpu *v, struct hvm_hw_cpu *c)
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

    v->arch.hvm_vcpu.guest_efer = c->msr_efer;
    vmx_update_guest_efer(v);

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

    data->tsc = hvm_get_guest_tsc(v);
}

static void vmx_load_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
#ifdef __x86_64__
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;

    /* restore msrs */
    guest_state->flags = data->msr_flags & 7;
    guest_state->msrs[VMX_INDEX_MSR_LSTAR]        = data->msr_lstar;
    guest_state->msrs[VMX_INDEX_MSR_STAR]         = data->msr_star;
    guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK] = data->msr_syscall_mask;

    v->arch.hvm_vmx.cstar     = data->msr_cstar;
    v->arch.hvm_vmx.shadow_gs = data->shadow_gs;
#endif

    hvm_set_guest_tsc(v, data->tsc);
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

static void vmx_fpu_enter(struct vcpu *v)
{
    setup_fpu(v);
    __vm_clear_bit(EXCEPTION_BITMAP, TRAP_no_device);
    v->arch.hvm_vmx.host_cr0 &= ~X86_CR0_TS;
    __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);
}

static void vmx_fpu_leave(struct vcpu *v)
{
    ASSERT(!v->fpu_dirtied);
    ASSERT(read_cr0() & X86_CR0_TS);

    if ( !(v->arch.hvm_vmx.host_cr0 & X86_CR0_TS) )
    {
        v->arch.hvm_vmx.host_cr0 |= X86_CR0_TS;
        __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);
    }

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

static void vmx_ctxt_switch_from(struct vcpu *v)
{
    vmx_fpu_leave(v);
    vmx_save_guest_msrs(v);
    vmx_restore_host_msrs();
    vmx_save_dr(v);
    vpmu_save(v);
}

static void vmx_ctxt_switch_to(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned long old_cr4 = read_cr4(), new_cr4 = mmu_cr4_features;

    /* HOST_CR4 in VMCS is always mmu_cr4_features and
     * CR4_OSXSAVE(if supported). Sync CR4 now. */
    if ( cpu_has_xsave )
        new_cr4 |= X86_CR4_OSXSAVE;
    if ( old_cr4 != new_cr4 )
        write_cr4(new_cr4);

    if ( d->arch.hvm_domain.hap_enabled )
    {
        unsigned int cpu = smp_processor_id();
        /* Test-and-test-and-set this CPU in the EPT-is-synced mask. */
        if ( !cpu_isset(cpu, d->arch.hvm_domain.vmx.ept_synced) &&
             !cpu_test_and_set(cpu, d->arch.hvm_domain.vmx.ept_synced) )
            __invept(1, d->arch.hvm_domain.vmx.ept_control.eptp, 0);
    }

    vmx_restore_guest_msrs(v);
    vmx_restore_dr(v);
    vpmu_load(v);
}


/* SDM volume 3b section 22.3.1.2: we can only enter virtual 8086 mode
 * if all of CS, SS, DS, ES, FS and GS are 16bit ring-3 data segments.
 * The guest thinks it's got ring-0 segments, so we need to fudge
 * things.  We store the ring-3 version in the VMCS to avoid lots of
 * shuffling on vmenter and vmexit, and translate in these accessors. */

#define rm_cs_attr (((union segment_attributes) {                       \
        .fields = { .type = 0xb, .s = 1, .dpl = 0, .p = 1, .avl = 0,    \
                    .l = 0, .db = 0, .g = 0, .pad = 0 } }).bytes)
#define rm_ds_attr (((union segment_attributes) {                       \
        .fields = { .type = 0x3, .s = 1, .dpl = 0, .p = 1, .avl = 0,    \
                    .l = 0, .db = 0, .g = 0, .pad = 0 } }).bytes)
#define vm86_ds_attr (((union segment_attributes) {                     \
        .fields = { .type = 0x3, .s = 1, .dpl = 3, .p = 1, .avl = 0,    \
                    .l = 0, .db = 0, .g = 0, .pad = 0 } }).bytes)
#define vm86_tr_attr (((union segment_attributes) {                     \
        .fields = { .type = 0xb, .s = 0, .dpl = 0, .p = 1, .avl = 0,    \
                    .l = 0, .db = 0, .g = 0, .pad = 0 } }).bytes)

static void vmx_get_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    uint32_t attr = 0;

    vmx_vmcs_enter(v);

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

    vmx_vmcs_exit(v);

    reg->attr.bytes = (attr & 0xff) | ((attr >> 4) & 0xf00);
    /* Unusable flag is folded into Present flag. */
    if ( attr & (1u<<16) )
        reg->attr.fields.p = 0;

    /* Adjust for virtual 8086 mode */
    if ( v->arch.hvm_vmx.vmx_realmode && seg <= x86_seg_tr 
         && !(v->arch.hvm_vmx.vm86_segment_mask & (1u << seg)) )
    {
        struct segment_register *sreg = &v->arch.hvm_vmx.vm86_saved_seg[seg];
        if ( seg == x86_seg_tr ) 
            *reg = *sreg;
        else if ( reg->base != sreg->base || seg == x86_seg_ss )
        {
            /* If the guest's reloaded the segment, remember the new version.
             * We can't tell if the guest reloaded the segment with another 
             * one that has the same base.  By default we assume it hasn't,
             * since we don't want to lose big-real-mode segment attributes,
             * but for SS we assume it has: the Ubuntu graphical bootloader
             * does this and gets badly confused if we leave the old SS in 
             * place. */
            reg->attr.bytes = (seg == x86_seg_cs ? rm_cs_attr : rm_ds_attr);
            *sreg = *reg;
        }
        else 
        {
            /* Always give realmode guests a selector that matches the base
             * but keep the attr and limit from before */
            *reg = *sreg;
            reg->sel = reg->base >> 4;
        }
    }
}

static void vmx_set_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    uint32_t attr, sel, limit;
    uint64_t base;

    sel = reg->sel;
    attr = reg->attr.bytes;
    limit = reg->limit;
    base = reg->base;

    /* Adjust CS/SS/DS/ES/FS/GS/TR for virtual 8086 mode */
    if ( v->arch.hvm_vmx.vmx_realmode && seg <= x86_seg_tr )
    {
        /* Remember the proper contents */
        v->arch.hvm_vmx.vm86_saved_seg[seg] = *reg;
        
        if ( seg == x86_seg_tr ) 
        {
            if ( v->domain->arch.hvm_domain.params[HVM_PARAM_VM86_TSS] )
            {
                sel = 0;
                attr = vm86_tr_attr;
                limit = 0xff;
                base = v->domain->arch.hvm_domain.params[HVM_PARAM_VM86_TSS];
                v->arch.hvm_vmx.vm86_segment_mask &= ~(1u << seg);
            }
            else
                v->arch.hvm_vmx.vm86_segment_mask |= (1u << seg);
        }
        else
        {
            /* Try to fake it out as a 16bit data segment.  This could
             * cause confusion for the guest if it reads the selector,
             * but otherwise we have to emulate if *any* segment hasn't
             * been reloaded. */
            if ( base < 0x100000 && !(base & 0xf) && limit >= 0xffff
                 && reg->attr.fields.p )
            {
                sel = base >> 4;
                attr = vm86_ds_attr;
                limit = 0xffff;
                v->arch.hvm_vmx.vm86_segment_mask &= ~(1u << seg);
            }
            else 
                v->arch.hvm_vmx.vm86_segment_mask |= (1u << seg);
        }
    }

    attr = ((attr & 0xf00) << 4) | (attr & 0xff);

    /* Not-present must mean unusable. */
    if ( !reg->attr.fields.p )
        attr |= (1u << 16);

    /* VMX has strict consistency requirement for flag G. */
    attr |= !!(limit >> 20) << 15;

    vmx_vmcs_enter(v);

    switch ( seg )
    {
    case x86_seg_cs:
        __vmwrite(GUEST_CS_SELECTOR, sel);
        __vmwrite(GUEST_CS_LIMIT, limit);
        __vmwrite(GUEST_CS_BASE, base);
        __vmwrite(GUEST_CS_AR_BYTES, attr);
        break;
    case x86_seg_ds:
        __vmwrite(GUEST_DS_SELECTOR, sel);
        __vmwrite(GUEST_DS_LIMIT, limit);
        __vmwrite(GUEST_DS_BASE, base);
        __vmwrite(GUEST_DS_AR_BYTES, attr);
        break;
    case x86_seg_es:
        __vmwrite(GUEST_ES_SELECTOR, sel);
        __vmwrite(GUEST_ES_LIMIT, limit);
        __vmwrite(GUEST_ES_BASE, base);
        __vmwrite(GUEST_ES_AR_BYTES, attr);
        break;
    case x86_seg_fs:
        __vmwrite(GUEST_FS_SELECTOR, sel);
        __vmwrite(GUEST_FS_LIMIT, limit);
        __vmwrite(GUEST_FS_BASE, base);
        __vmwrite(GUEST_FS_AR_BYTES, attr);
        break;
    case x86_seg_gs:
        __vmwrite(GUEST_GS_SELECTOR, sel);
        __vmwrite(GUEST_GS_LIMIT, limit);
        __vmwrite(GUEST_GS_BASE, base);
        __vmwrite(GUEST_GS_AR_BYTES, attr);
        break;
    case x86_seg_ss:
        __vmwrite(GUEST_SS_SELECTOR, sel);
        __vmwrite(GUEST_SS_LIMIT, limit);
        __vmwrite(GUEST_SS_BASE, base);
        __vmwrite(GUEST_SS_AR_BYTES, attr);
        break;
    case x86_seg_tr:
        __vmwrite(GUEST_TR_SELECTOR, sel);
        __vmwrite(GUEST_TR_LIMIT, limit);
        __vmwrite(GUEST_TR_BASE, base);
        /* VMX checks that the the busy flag (bit 1) is set. */
        __vmwrite(GUEST_TR_AR_BYTES, attr | 2);
        break;
    case x86_seg_gdtr:
        __vmwrite(GUEST_GDTR_LIMIT, limit);
        __vmwrite(GUEST_GDTR_BASE, base);
        break;
    case x86_seg_idtr:
        __vmwrite(GUEST_IDTR_LIMIT, limit);
        __vmwrite(GUEST_IDTR_BASE, base);
        break;
    case x86_seg_ldtr:
        __vmwrite(GUEST_LDTR_SELECTOR, sel);
        __vmwrite(GUEST_LDTR_LIMIT, limit);
        __vmwrite(GUEST_LDTR_BASE, base);
        __vmwrite(GUEST_LDTR_AR_BYTES, attr);
        break;
    default:
        BUG();
    }

    vmx_vmcs_exit(v);
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

static void vmx_set_rdtsc_exiting(struct vcpu *v, bool_t enable)
{
    vmx_vmcs_enter(v);
    v->arch.hvm_vmx.exec_control &= ~CPU_BASED_RDTSC_EXITING;
    if ( enable )
        v->arch.hvm_vmx.exec_control |= CPU_BASED_RDTSC_EXITING;
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vmx.exec_control);
    vmx_vmcs_exit(v);
}

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

static unsigned int vmx_get_interrupt_shadow(struct vcpu *v)
{
    return __vmread(GUEST_INTERRUPTIBILITY_INFO);
}

static void vmx_set_interrupt_shadow(struct vcpu *v, unsigned int intr_shadow)
{
    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
}

static void vmx_load_pdptrs(struct vcpu *v)
{
    unsigned long cr3 = v->arch.hvm_vcpu.guest_cr[3], mfn;
    uint64_t *guest_pdptrs;
    p2m_type_t p2mt;
    char *p;

    /* EPT needs to load PDPTRS into VMCS for PAE. */
    if ( !hvm_pae_enabled(v) || (v->arch.hvm_vcpu.guest_efer & EFER_LMA) )
        return;

    if ( cr3 & 0x1fUL )
        goto crash;

    mfn = mfn_x(gfn_to_mfn(v->domain, cr3 >> PAGE_SHIFT, &p2mt));
    if ( !p2m_is_ram(p2mt) )
        goto crash;

    p = map_domain_page(mfn);

    guest_pdptrs = (uint64_t *)(p + (cr3 & ~PAGE_MASK));

    /*
     * We do not check the PDPTRs for validity. The CPU will do this during
     * vm entry, and we can handle the failure there and crash the guest.
     * The only thing we could do better here is #GP instead.
     */

    vmx_vmcs_enter(v);

    __vmwrite(GUEST_PDPTR0, guest_pdptrs[0]);
    __vmwrite(GUEST_PDPTR1, guest_pdptrs[1]);
    __vmwrite(GUEST_PDPTR2, guest_pdptrs[2]);
    __vmwrite(GUEST_PDPTR3, guest_pdptrs[3]);
#ifdef __i386__
    __vmwrite(GUEST_PDPTR0_HIGH, guest_pdptrs[0] >> 32);
    __vmwrite(GUEST_PDPTR1_HIGH, guest_pdptrs[1] >> 32);
    __vmwrite(GUEST_PDPTR2_HIGH, guest_pdptrs[2] >> 32);
    __vmwrite(GUEST_PDPTR3_HIGH, guest_pdptrs[3] >> 32);
#endif

    vmx_vmcs_exit(v);

    unmap_domain_page(p);
    return;

 crash:
    domain_crash(v->domain);
}

static void vmx_update_host_cr3(struct vcpu *v)
{
    vmx_vmcs_enter(v);
    __vmwrite(HOST_CR3, v->arch.cr3);
    vmx_vmcs_exit(v);
}

void vmx_update_debug_state(struct vcpu *v)
{
    unsigned long intercepts, mask;

    ASSERT(v == current);

    mask = 1u << TRAP_int3;
    if ( !cpu_has_monitor_trap_flag )
        mask |= 1u << TRAP_debug;

    intercepts = __vmread(EXCEPTION_BITMAP);
    if ( v->arch.hvm_vcpu.debug_state_latch )
        intercepts |= mask;
    else
        intercepts &= ~mask;
    __vmwrite(EXCEPTION_BITMAP, intercepts);
}

static void vmx_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    vmx_vmcs_enter(v);

    switch ( cr )
    {
    case 0: {
        int realmode;
        unsigned long hw_cr0_mask = X86_CR0_NE;

        if ( !vmx_unrestricted_guest(v) )
            hw_cr0_mask |= X86_CR0_PG | X86_CR0_PE;

        if ( paging_mode_shadow(v->domain) )
           hw_cr0_mask |= X86_CR0_WP;

        if ( paging_mode_hap(v->domain) )
        {
            /* We manage GUEST_CR3 when guest CR0.PE is zero. */
            uint32_t cr3_ctls = (CPU_BASED_CR3_LOAD_EXITING |
                                 CPU_BASED_CR3_STORE_EXITING);
            v->arch.hvm_vmx.exec_control &= ~cr3_ctls;
            if ( !hvm_paging_enabled(v) )
                v->arch.hvm_vmx.exec_control |= cr3_ctls;
            __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vmx.exec_control);

            /* Changing CR0.PE can change some bits in real CR4. */
            vmx_update_guest_cr(v, 4);
        }

        if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
        {
            if ( v != current )
                hw_cr0_mask |= X86_CR0_TS;
            else if ( v->arch.hvm_vcpu.hw_cr[0] & X86_CR0_TS )
                vmx_fpu_enter(v);
        }

        realmode = !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE); 

        if ( (!vmx_unrestricted_guest(v)) &&
             (realmode != v->arch.hvm_vmx.vmx_realmode) )
        {
            enum x86_segment s; 
            struct segment_register reg[x86_seg_tr + 1];

            /* Entering or leaving real mode: adjust the segment registers.
             * Need to read them all either way, as realmode reads can update
             * the saved values we'll use when returning to prot mode. */
            for ( s = x86_seg_cs ; s <= x86_seg_tr ; s++ )
                vmx_get_segment_register(v, s, &reg[s]);
            v->arch.hvm_vmx.vmx_realmode = realmode;
            
            if ( realmode )
            {
                for ( s = x86_seg_cs ; s <= x86_seg_tr ; s++ )
                    vmx_set_segment_register(v, s, &reg[s]);
                v->arch.hvm_vcpu.hw_cr[4] |= X86_CR4_VME;
                __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4]);
                __vmwrite(EXCEPTION_BITMAP, 0xffffffff);
            }
            else 
            {
                for ( s = x86_seg_cs ; s <= x86_seg_tr ; s++ ) 
                    if ( !(v->arch.hvm_vmx.vm86_segment_mask & (1<<s)) )
                        vmx_set_segment_register(
                            v, s, &v->arch.hvm_vmx.vm86_saved_seg[s]);
                v->arch.hvm_vcpu.hw_cr[4] =
                    ((v->arch.hvm_vcpu.hw_cr[4] & ~X86_CR4_VME)
                     |(v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_VME));
                __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4]);
                __vmwrite(EXCEPTION_BITMAP, 
                          HVM_TRAP_MASK
                          | (paging_mode_hap(v->domain) ?
                             0 : (1U << TRAP_page_fault))
                          | (1U << TRAP_no_device));
                vmx_update_debug_state(v);
            }
        }

        v->arch.hvm_vcpu.hw_cr[0] =
            v->arch.hvm_vcpu.guest_cr[0] | hw_cr0_mask;
        __vmwrite(GUEST_CR0, v->arch.hvm_vcpu.hw_cr[0]);
        __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vcpu.guest_cr[0]);
        break;
    }
    case 2:
        /* CR2 is updated in exit stub. */
        break;
    case 3:
        if ( paging_mode_hap(v->domain) )
        {
            if ( !hvm_paging_enabled(v) )
                v->arch.hvm_vcpu.hw_cr[3] =
                    v->domain->arch.hvm_domain.params[HVM_PARAM_IDENT_PT];
            vmx_load_pdptrs(v);
        }
 
        __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr[3]);
        vpid_sync_vcpu_all(v);
        break;
    case 4:
        v->arch.hvm_vcpu.hw_cr[4] = HVM_CR4_HOST_MASK;
        if ( paging_mode_hap(v->domain) )
            v->arch.hvm_vcpu.hw_cr[4] &= ~X86_CR4_PAE;
        v->arch.hvm_vcpu.hw_cr[4] |= v->arch.hvm_vcpu.guest_cr[4];
        if ( v->arch.hvm_vmx.vmx_realmode ) 
            v->arch.hvm_vcpu.hw_cr[4] |= X86_CR4_VME;
        if ( paging_mode_hap(v->domain) && !hvm_paging_enabled(v) )
        {
            v->arch.hvm_vcpu.hw_cr[4] |= X86_CR4_PSE;
            v->arch.hvm_vcpu.hw_cr[4] &= ~X86_CR4_PAE;
        }
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
        write_efer((read_efer() & ~EFER_SCE) |
                   (v->arch.hvm_vcpu.guest_efer & EFER_SCE));
}

static void vmx_flush_guest_tlbs(void)
{
    /*
     * If VPID (i.e. tagged TLB support) is not enabled, the fact that
     * we're in Xen at all means any guest will have a clean TLB when
     * it's next run, because VMRESUME will flush it for us.
     *
     * If enabled, we invalidate all translations associated with all
     * VPID values.
     */
    vpid_sync_all();
}

static void __ept_sync_domain(void *info)
{
    struct domain *d = info;
    __invept(1, d->arch.hvm_domain.vmx.ept_control.eptp, 0);
}

void ept_sync_domain(struct domain *d)
{
    /* Only if using EPT and this domain has some VCPUs to dirty. */
    if ( !d->arch.hvm_domain.hap_enabled || !d->vcpu || !d->vcpu[0] )
        return;

    ASSERT(local_irq_is_enabled());
    ASSERT(p2m_locked_by_me(d->arch.p2m));

    /*
     * Flush active cpus synchronously. Flush others the next time this domain
     * is scheduled onto them. We accept the race of other CPUs adding to
     * the ept_synced mask before on_selected_cpus() reads it, resulting in
     * unnecessary extra flushes, to avoid allocating a cpumask_t on the stack.
     */
    d->arch.hvm_domain.vmx.ept_synced = d->domain_dirty_cpumask;
    on_selected_cpus(&d->arch.hvm_domain.vmx.ept_synced,
                     __ept_sync_domain, d, 1);
}

static void __vmx_inject_exception(int trap, int type, int error_code)
{
    unsigned long intr_fields;
    struct vcpu *curr = current;

    /*
     * NB. Callers do not need to worry about clearing STI/MOV-SS blocking:
     *  "If the VM entry is injecting, there is no blocking by STI or by
     *   MOV SS following the VM entry, regardless of the contents of the
     *   interruptibility-state field [in the guest-state area before the
     *   VM entry]", PRM Vol. 3, 22.6.1 (Interruptibility State).
     */

    intr_fields = (INTR_INFO_VALID_MASK | (type<<8) | trap);
    if ( error_code != HVM_DELIVER_NO_ERROR_CODE ) {
        __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
        intr_fields |= INTR_INFO_DELIVER_CODE_MASK;
    }

    __vmwrite(VM_ENTRY_INTR_INFO, intr_fields);

    /* Can't inject exceptions in virtual 8086 mode because they would 
     * use the protected-mode IDT.  Emulate at the next vmenter instead. */
    if ( curr->arch.hvm_vmx.vmx_realmode ) 
        curr->arch.hvm_vmx.vmx_emulate = 1;
}

void vmx_inject_hw_exception(int trap, int error_code)
{
    unsigned long intr_info = __vmread(VM_ENTRY_INTR_INFO);
    struct vcpu *curr = current;

    switch ( trap )
    {
    case TRAP_debug:
        if ( guest_cpu_user_regs()->eflags & X86_EFLAGS_TF )
        {
            __restore_debug_registers(curr);
            write_debugreg(6, read_debugreg(6) | 0x4000);
        }
        if ( cpu_has_monitor_trap_flag )
            break;
    case TRAP_int3:
        if ( curr->domain->debugger_attached )
        {
            /* Debug/Int3: Trap to debugger. */
            domain_pause_for_debugger();
            return;
        }
    }

    if ( unlikely(intr_info & INTR_INFO_VALID_MASK) &&
         (((intr_info >> 8) & 7) == X86_EVENTTYPE_HW_EXCEPTION) )
    {
        trap = hvm_combine_hw_exceptions((uint8_t)intr_info, trap);
        if ( trap == TRAP_double_fault )
            error_code = 0;
    }

    __vmx_inject_exception(trap, X86_EVENTTYPE_HW_EXCEPTION, error_code);

    if ( trap == TRAP_page_fault )
        HVMTRACE_LONG_2D(PF_INJECT, error_code,
                         TRC_PAR_LONG(current->arch.hvm_vcpu.guest_cr[2]));
    else
        HVMTRACE_2D(INJ_EXC, trap, error_code);
}

void vmx_inject_extint(int trap)
{
    __vmx_inject_exception(trap, X86_EVENTTYPE_EXT_INTR,
                           HVM_DELIVER_NO_ERROR_CODE);
}

void vmx_inject_nmi(void)
{
    __vmx_inject_exception(2, X86_EVENTTYPE_NMI,
                           HVM_DELIVER_NO_ERROR_CODE);
}

static void vmx_inject_exception(
    unsigned int trapnr, int errcode, unsigned long cr2)
{
    if ( trapnr == TRAP_page_fault )
        current->arch.hvm_vcpu.guest_cr[2] = cr2;

    vmx_inject_hw_exception(trapnr, errcode);
}

static int vmx_event_pending(struct vcpu *v)
{
    ASSERT(v == current);
    return (__vmread(VM_ENTRY_INTR_INFO) & INTR_INFO_VALID_MASK);
}

static int vmx_do_pmu_interrupt(struct cpu_user_regs *regs)
{
    return vpmu_do_interrupt(regs);
}

static void vmx_set_uc_mode(struct vcpu *v)
{
    if ( paging_mode_hap(v->domain) )
        ept_change_entry_emt_with_range(
            v->domain, 0, v->domain->arch.p2m->max_mapped_pfn);
    vpid_sync_all();
}

static void vmx_set_info_guest(struct vcpu *v)
{
    unsigned long intr_shadow;

    vmx_vmcs_enter(v);

    __vmwrite(GUEST_DR7, v->arch.guest_context.debugreg[7]);

    /* 
     * If the interruptibility-state field indicates blocking by STI,
     * setting the TF flag in the EFLAGS may cause VM entry to fail
     * and crash the guest. See SDM 3B 22.3.1.5.
     * Resetting the VMX_INTR_SHADOW_STI flag looks hackish but
     * to set the GUEST_PENDING_DBG_EXCEPTIONS.BS here incurs
     * immediately vmexit and hence make no progress.
     */
    intr_shadow = __vmread(GUEST_INTERRUPTIBILITY_INFO);
    if ( v->domain->debugger_attached &&
         (v->arch.guest_context.user_regs.eflags & X86_EFLAGS_TF) &&
         (intr_shadow & VMX_INTR_SHADOW_STI) )
    {
        intr_shadow &= ~VMX_INTR_SHADOW_STI;
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
    }

    vmx_vmcs_exit(v);
}

static struct hvm_function_table vmx_function_table = {
    .name                 = "VMX",
    .domain_initialise    = vmx_domain_initialise,
    .domain_destroy       = vmx_domain_destroy,
    .vcpu_initialise      = vmx_vcpu_initialise,
    .vcpu_destroy         = vmx_vcpu_destroy,
    .save_cpu_ctxt        = vmx_save_vmcs_ctxt,
    .load_cpu_ctxt        = vmx_load_vmcs_ctxt,
    .get_interrupt_shadow = vmx_get_interrupt_shadow,
    .set_interrupt_shadow = vmx_set_interrupt_shadow,
    .guest_x86_mode       = vmx_guest_x86_mode,
    .get_segment_register = vmx_get_segment_register,
    .set_segment_register = vmx_set_segment_register,
    .update_host_cr3      = vmx_update_host_cr3,
    .update_guest_cr      = vmx_update_guest_cr,
    .update_guest_efer    = vmx_update_guest_efer,
    .flush_guest_tlbs     = vmx_flush_guest_tlbs,
    .set_tsc_offset       = vmx_set_tsc_offset,
    .inject_exception     = vmx_inject_exception,
    .init_hypercall_page  = vmx_init_hypercall_page,
    .event_pending        = vmx_event_pending,
    .do_pmu_interrupt     = vmx_do_pmu_interrupt,
    .cpu_up               = vmx_cpu_up,
    .cpu_down             = vmx_cpu_down,
    .cpuid_intercept      = vmx_cpuid_intercept,
    .wbinvd_intercept     = vmx_wbinvd_intercept,
    .fpu_dirty_intercept  = vmx_fpu_dirty_intercept,
    .msr_read_intercept   = vmx_msr_read_intercept,
    .msr_write_intercept  = vmx_msr_write_intercept,
    .invlpg_intercept     = vmx_invlpg_intercept,
    .set_uc_mode          = vmx_set_uc_mode,
    .set_info_guest       = vmx_set_info_guest,
    .set_rdtsc_exiting    = vmx_set_rdtsc_exiting
};

static unsigned long *vpid_bitmap;
#define VPID_BITMAP_SIZE (1u << VMCS_VPID_WIDTH)

void start_vmx(void)
{
    static bool_t bootstrapped;

    vmx_save_host_msrs();

    if ( test_and_set_bool(bootstrapped) )
    {
        if ( hvm_enabled && !vmx_cpu_up() )
        {
            printk("VMX: FATAL: failed to initialise CPU%d!\n",
                   smp_processor_id());
            BUG();
        }
        return;
    }

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

    if ( cpu_has_vmx_ept )
        vmx_function_table.hap_supported = 1;

    if ( cpu_has_vmx_vpid )
    {
        vpid_bitmap = xmalloc_array(
            unsigned long, BITS_TO_LONGS(VPID_BITMAP_SIZE));
        BUG_ON(vpid_bitmap == NULL);
        memset(vpid_bitmap, 0, BITS_TO_LONGS(VPID_BITMAP_SIZE) * sizeof(long));

        /* VPID 0 is used by VMX root mode (the hypervisor). */
        __set_bit(0, vpid_bitmap);
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
        vmx_inject_hw_exception(TRAP_debug, HVM_DELIVER_NO_ERROR_CODE);
}

static void vmx_fpu_dirty_intercept(void)
{
    struct vcpu *curr = current;

    vmx_fpu_enter(curr);

    /* Disable TS in guest CR0 unless the guest wants the exception too. */
    if ( !(curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
    {
        curr->arch.hvm_vcpu.hw_cr[0] &= ~X86_CR0_TS;
        __vmwrite(GUEST_CR0, curr->arch.hvm_vcpu.hw_cr[0]);
    }
}

#define bitmaskof(idx)  (1U << ((idx) & 31))
static void vmx_cpuid_intercept(
    unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx)
{
    unsigned int input = *eax;
    struct segment_register cs;
    struct vcpu *v = current;

    hvm_cpuid(input, eax, ebx, ecx, edx);

    switch ( input )
    {
        case 0x80000001:
            /* SYSCALL is visible iff running in long mode. */
            hvm_get_segment_register(v, x86_seg_cs, &cs);
            if ( cs.attr.fields.l )
                *edx |= bitmaskof(X86_FEATURE_SYSCALL);
            else
                *edx &= ~(bitmaskof(X86_FEATURE_SYSCALL));
            break;
    }

    HVMTRACE_5D (CPUID, input, *eax, *ebx, *ecx, *edx);
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

static void vmx_dr_access(unsigned long exit_qualification,
                          struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    HVMTRACE_0D(DR_WRITE);

    if ( !v->arch.hvm_vcpu.flag_dr_dirty )
        __restore_debug_registers(v);

    /* Allow guest direct access to DR registers */
    v->arch.hvm_vmx.exec_control &= ~CPU_BASED_MOV_DR_EXITING;
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vmx.exec_control);
}

static void vmx_invlpg_intercept(unsigned long vaddr)
{
    struct vcpu *curr = current;
    HVMTRACE_LONG_2D(INVLPG, /*invlpga=*/ 0, TRC_PAR_LONG(vaddr));
    if ( paging_invlpg(curr, vaddr) )
        vpid_sync_vcpu_gva(curr, vaddr);
}

#define CASE_SET_REG(REG, reg)      \
    case VMX_CONTROL_REG_ACCESS_GPR_ ## REG: regs->reg = value; break
#define CASE_GET_REG(REG, reg)      \
    case VMX_CONTROL_REG_ACCESS_GPR_ ## REG: value = regs->reg; break

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

    HVMTRACE_LONG_2D(CR_WRITE, cr, TRC_PAR_LONG(value));

    HVM_DBG_LOG(DBG_LEVEL_1, "CR%d, value = %lx", cr, value);

    switch ( cr )
    {
    case 0:
        return !hvm_set_cr0(value);

    case 3:
        return !hvm_set_cr3(value);

    case 4:
        return !hvm_set_cr4(value);

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

    HVMTRACE_LONG_2D(CR_READ, cr, TRC_PAR_LONG(value));

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR%d, value = %lx", cr, value);
}

static int vmx_cr_access(unsigned long exit_qualification,
                         struct cpu_user_regs *regs)
{
    unsigned int gp, cr;
    unsigned long value;
    struct vcpu *v = current;

    switch ( exit_qualification & VMX_CONTROL_REG_ACCESS_TYPE )
    {
    case VMX_CONTROL_REG_ACCESS_TYPE_MOV_TO_CR:
        gp = exit_qualification & VMX_CONTROL_REG_ACCESS_GPR;
        cr = exit_qualification & VMX_CONTROL_REG_ACCESS_NUM;
        return mov_to_cr(gp, cr, regs);
    case VMX_CONTROL_REG_ACCESS_TYPE_MOV_FROM_CR:
        gp = exit_qualification & VMX_CONTROL_REG_ACCESS_GPR;
        cr = exit_qualification & VMX_CONTROL_REG_ACCESS_NUM;
        mov_from_cr(cr, gp, regs);
        break;
    case VMX_CONTROL_REG_ACCESS_TYPE_CLTS:
        v->arch.hvm_vcpu.guest_cr[0] &= ~X86_CR0_TS;
        vmx_update_guest_cr(v, 0);
        HVMTRACE_0D(CLTS);
        break;
    case VMX_CONTROL_REG_ACCESS_TYPE_LMSW:
        value = v->arch.hvm_vcpu.guest_cr[0];
        /* LMSW can: (1) set bits 0-3; (2) clear bits 1-3. */
        value = (value & ~0xe) | ((exit_qualification >> 16) & 0xf);
        HVMTRACE_LONG_1D(LMSW, value);
        return !hvm_set_cr0(value);
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

static int vmx_msr_read_intercept(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    u32 ecx = regs->ecx, eax, edx;

    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x", ecx);

    switch ( ecx )
    {
    case MSR_IA32_SYSENTER_CS:
        msr_content = (u32)__vmread(GUEST_SYSENTER_CS);
        break;
    case MSR_IA32_SYSENTER_ESP:
        msr_content = __vmread(GUEST_SYSENTER_ESP);
        break;
    case MSR_IA32_SYSENTER_EIP:
        msr_content = __vmread(GUEST_SYSENTER_EIP);
        break;
    case MSR_IA32_DEBUGCTLMSR:
        msr_content = __vmread(GUEST_IA32_DEBUGCTL);
#ifdef __i386__
        msr_content |= (u64)__vmread(GUEST_IA32_DEBUGCTL_HIGH) << 32;
#endif
        break;
    case MSR_IA32_VMX_BASIC...MSR_IA32_VMX_PROCBASED_CTLS2:
        goto gp_fault;
    case MSR_IA32_MISC_ENABLE:
        rdmsrl(MSR_IA32_MISC_ENABLE, msr_content);
        /* Debug Trace Store is not supported. */
        msr_content |= MSR_IA32_MISC_ENABLE_BTS_UNAVAIL |
                       MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL;
        break;
    default:
        if ( vpmu_do_rdmsr(regs) )
            goto done;
        if ( passive_domain_do_rdmsr(regs) )
            goto done;
        switch ( long_mode_do_msr_read(regs) )
        {
            case HNDL_unhandled:
                break;
            case HNDL_exception_raised:
                return X86EMUL_EXCEPTION;
            case HNDL_done:
                goto done;
        }

        if ( vmx_read_guest_msr(ecx, &msr_content) == 0 )
            break;

        if ( is_last_branch_msr(ecx) )
        {
            msr_content = 0;
            break;
        }

        if ( rdmsr_viridian_regs(ecx, &msr_content) ||
             rdmsr_hypervisor_regs(ecx, &msr_content) )
            break;

        if ( rdmsr_safe(ecx, eax, edx) == 0 )
        {
            msr_content = ((uint64_t)edx << 32) | eax;
            break;
        }

        goto gp_fault;
    }

    regs->eax = (uint32_t)msr_content;
    regs->edx = (uint32_t)(msr_content >> 32);

done:
    HVMTRACE_3D (MSR_READ, ecx, regs->eax, regs->edx);
    HVM_DBG_LOG(DBG_LEVEL_1, "returns: ecx=%x, eax=%lx, edx=%lx",
                ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
    return X86EMUL_OKAY;

gp_fault:
    vmx_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
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
    d->arch.hvm_domain.vmx.apic_access_mfn = virt_to_mfn(apic_va);

    return 0;
}

static void vmx_free_vlapic_mapping(struct domain *d)
{
    unsigned long mfn = d->arch.hvm_domain.vmx.apic_access_mfn;
    if ( mfn != 0 )
        free_xenheap_page(mfn_to_virt(mfn));
}

static int vmx_alloc_vpid(struct vcpu *v)
{
    int idx;

    if ( !cpu_has_vmx_vpid )
        return 0;

    do {
        idx = find_first_zero_bit(vpid_bitmap, VPID_BITMAP_SIZE);
        if ( idx >= VPID_BITMAP_SIZE )
        {
            dprintk(XENLOG_WARNING, "VMX VPID space exhausted.\n");
            return -EBUSY;
        }
    }
    while ( test_and_set_bit(idx, vpid_bitmap) );

    v->arch.hvm_vmx.vpid = idx;
    return 0;
}

static void vmx_free_vpid(struct vcpu *v)
{
    if ( !cpu_has_vmx_vpid )
        return;

    if ( v->arch.hvm_vmx.vpid )
        clear_bit(v->arch.hvm_vmx.vpid, vpid_bitmap);
}

static void vmx_install_vlapic_mapping(struct vcpu *v)
{
    paddr_t virt_page_ma, apic_page_ma;

    if ( !cpu_has_vmx_virtualize_apic_accesses )
        return;

    virt_page_ma = page_to_maddr(vcpu_vlapic(v)->regs_page);
    apic_page_ma = v->domain->arch.hvm_domain.vmx.apic_access_mfn;
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

static int vmx_msr_write_intercept(struct cpu_user_regs *regs)
{
    u32 ecx = regs->ecx;
    u64 msr_content;
    struct vcpu *v = current;

    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x, eax=%x, edx=%x",
                ecx, (u32)regs->eax, (u32)regs->edx);

    msr_content = (u32)regs->eax | ((u64)regs->edx << 32);

    HVMTRACE_3D (MSR_WRITE, ecx, regs->eax, regs->edx);

    switch ( ecx )
    {
    case MSR_IA32_SYSENTER_CS:
        __vmwrite(GUEST_SYSENTER_CS, msr_content);
        break;
    case MSR_IA32_SYSENTER_ESP:
        __vmwrite(GUEST_SYSENTER_ESP, msr_content);
        break;
    case MSR_IA32_SYSENTER_EIP:
        __vmwrite(GUEST_SYSENTER_EIP, msr_content);
        break;
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
                    if ( (rc = vmx_add_guest_msr(lbr->base + i)) == 0 )
                        vmx_disable_intercept_for_msr(v, lbr->base + i);
        }

        if ( (rc < 0) ||
             (vmx_add_host_load_msr(ecx) < 0) )
            vmx_inject_hw_exception(TRAP_machine_check, 0);
        else
        {
            __vmwrite(GUEST_IA32_DEBUGCTL, msr_content);
#ifdef __i386__
            __vmwrite(GUEST_IA32_DEBUGCTL_HIGH, msr_content >> 32);
#endif
        }

        break;
    }
    case MSR_IA32_VMX_BASIC...MSR_IA32_VMX_PROCBASED_CTLS2:
        goto gp_fault;
    default:
        if ( vpmu_do_wrmsr(regs) )
            return X86EMUL_OKAY;
        if ( passive_domain_do_wrmsr(regs) )
            return X86EMUL_OKAY;

        if ( wrmsr_viridian_regs(ecx, msr_content) ) 
            break;

        switch ( long_mode_do_msr_write(regs) )
        {
            case HNDL_unhandled:
                if ( (vmx_write_guest_msr(ecx, msr_content) != 0) &&
                     !is_last_branch_msr(ecx) )
                    wrmsr_hypervisor_regs(ecx, msr_content);
                break;
            case HNDL_exception_raised:
                return X86EMUL_EXCEPTION;
            case HNDL_done:
                break;
        }
        break;
    }

    return X86EMUL_OKAY;

gp_fault:
    vmx_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

static void vmx_do_extint(struct cpu_user_regs *regs)
{
    unsigned int vector;

    asmlinkage void do_IRQ(struct cpu_user_regs *);
    fastcall void smp_apic_timer_interrupt(struct cpu_user_regs *);
    fastcall void smp_event_check_interrupt(struct cpu_user_regs *regs);
    fastcall void smp_invalidate_interrupt(void);
    fastcall void smp_call_function_interrupt(struct cpu_user_regs *regs);
    fastcall void smp_spurious_interrupt(struct cpu_user_regs *regs);
    fastcall void smp_error_interrupt(struct cpu_user_regs *regs);
    fastcall void smp_pmu_apic_interrupt(struct cpu_user_regs *regs);
    fastcall void smp_cmci_interrupt(struct cpu_user_regs *regs);
    fastcall void smp_irq_move_cleanup_interrupt(struct cpu_user_regs *regs);
#ifdef CONFIG_X86_MCE_THERMAL
    fastcall void smp_thermal_interrupt(struct cpu_user_regs *regs);
#endif

    vector = __vmread(VM_EXIT_INTR_INFO);
    BUG_ON(!(vector & INTR_INFO_VALID_MASK));

    vector &= INTR_INFO_VECTOR_MASK;
    HVMTRACE_1D(INTR, vector);

    switch ( vector )
    {
    case IRQ_MOVE_CLEANUP_VECTOR:
        smp_irq_move_cleanup_interrupt(regs);
        break;
    case LOCAL_TIMER_VECTOR:
        smp_apic_timer_interrupt(regs);
        break;
    case EVENT_CHECK_VECTOR:
        smp_event_check_interrupt(regs);
        break;
    case INVALIDATE_TLB_VECTOR:
        smp_invalidate_interrupt();
        break;
    case CALL_FUNCTION_VECTOR:
        smp_call_function_interrupt(regs);
        break;
    case SPURIOUS_APIC_VECTOR:
        smp_spurious_interrupt(regs);
        break;
    case ERROR_APIC_VECTOR:
        smp_error_interrupt(regs);
        break;
    case CMCI_APIC_VECTOR:
        smp_cmci_interrupt(regs);
        break;
    case PMU_APIC_VECTOR:
        smp_pmu_apic_interrupt(regs);
        break;
#ifdef CONFIG_X86_MCE_THERMAL
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

static void vmx_wbinvd_intercept(void)
{
    if ( !has_arch_pdevs(current->domain) )
        return;

    if ( cpu_has_wbinvd_exiting )
        on_each_cpu(wbinvd_ipi, NULL, 1);
    else
        wbinvd();
}

static void ept_handle_violation(unsigned long qualification, paddr_t gpa)
{
    unsigned long gla_validity = qualification & EPT_GLA_VALIDITY_MASK;
    struct domain *d = current->domain;
    unsigned long gla, gfn = gpa >> PAGE_SHIFT;
    mfn_t mfn;
    p2m_type_t t;

    mfn = gfn_to_mfn_guest(d, gfn, &t);

    /* There are three legitimate reasons for taking an EPT violation. 
     * One is a guest access to MMIO space. */
    if ( gla_validity == EPT_GLA_VALIDITY_MATCH && p2m_is_mmio(t) )
    {
        handle_mmio();
        return;
    }

    /* The second is log-dirty mode, writing to a read-only page;
     * The third is populating a populate-on-demand page. */
    if ( (gla_validity == EPT_GLA_VALIDITY_MATCH
          || gla_validity == EPT_GLA_VALIDITY_GPT_WALK)
         && p2m_is_ram(t) && (t != p2m_ram_ro) )
    {
        if ( paging_mode_log_dirty(d) )
        {
            paging_mark_dirty(d, mfn_x(mfn));
            p2m_change_type(d, gfn, p2m_ram_logdirty, p2m_ram_rw);
            flush_tlb_mask(&d->domain_dirty_cpumask);
        }
        return;
    }

    /* Everything else is an error. */
    gla = __vmread(GUEST_LINEAR_ADDRESS);
    gdprintk(XENLOG_ERR, "EPT violation %#lx (%c%c%c/%c%c%c), "
             "gpa %#"PRIpaddr", mfn %#lx, type %i.\n", 
             qualification, 
             (qualification & EPT_READ_VIOLATION) ? 'r' : '-',
             (qualification & EPT_WRITE_VIOLATION) ? 'w' : '-',
             (qualification & EPT_EXEC_VIOLATION) ? 'x' : '-',
             (qualification & EPT_EFFECTIVE_READ) ? 'r' : '-',
             (qualification & EPT_EFFECTIVE_WRITE) ? 'w' : '-',
             (qualification & EPT_EFFECTIVE_EXEC) ? 'x' : '-',
             gpa, mfn_x(mfn), t);

    if ( qualification & EPT_GAW_VIOLATION )
        gdprintk(XENLOG_ERR, " --- GPA too wide (max %u bits)\n", 
                 9 * (unsigned) d->arch.hvm_domain.vmx.ept_control.gaw + 21);

    switch ( gla_validity )
    {
    case EPT_GLA_VALIDITY_PDPTR_LOAD:
        gdprintk(XENLOG_ERR, " --- PDPTR load failed\n"); 
        break;
    case EPT_GLA_VALIDITY_GPT_WALK:
        gdprintk(XENLOG_ERR, " --- guest PT walk to %#lx failed\n", gla);
        break;
    case EPT_GLA_VALIDITY_RSVD:
        gdprintk(XENLOG_ERR, " --- GLA_validity 2 (reserved)\n");
        break;
    case EPT_GLA_VALIDITY_MATCH:
        gdprintk(XENLOG_ERR, " --- guest access to %#lx failed\n", gla);
        break;
    }

    domain_crash(d);
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
    case EXIT_REASON_MCE_DURING_VMENTRY:
        printk("caused by machine check.\n");
        HVMTRACE_0D(MCE);
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

asmlinkage void vmx_enter_realmode(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    /* Adjust RFLAGS to enter virtual 8086 mode with IOPL == 3.  Since
     * we have CR4.VME == 1 and our own TSS with an empty interrupt
     * redirection bitmap, all software INTs will be handled by vm86 */
    v->arch.hvm_vmx.vm86_saved_eflags = regs->eflags;
    regs->eflags |= (X86_EFLAGS_VM | X86_EFLAGS_IOPL);
}

static void vmx_vmexit_ud_intercept(struct cpu_user_regs *regs)
{
    struct hvm_emulate_ctxt ctxt;
    int rc;

    hvm_emulate_prepare(&ctxt, regs);

    rc = hvm_emulate_one(&ctxt);

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        vmx_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_exception(ctxt.exn_vector, ctxt.exn_error_code, 0);
        /* fall through */
    default:
        hvm_emulate_writeback(&ctxt);
        break;
    }
}

static int vmx_handle_eoi_write(void)
{
    unsigned long exit_qualification = __vmread(EXIT_QUALIFICATION);

    /*
     * 1. Must be a linear access data write.
     * 2. Data write must be to the EOI register.
     */
    if ( (((exit_qualification >> 12) & 0xf) == 1) &&
         ((exit_qualification & 0xfff) == APIC_EOI) )
    {
        int inst_len = __get_instruction_length(); /* Safe: APIC data write */
        __update_guest_eip(inst_len);
        vlapic_EOI_set(vcpu_vlapic(current));
        return 1;
    }

    return 0;
}

static int vmx_handle_xsetbv(u64 new_bv)
{
    struct vcpu *v = current;
    u64 xfeature = (((u64)xfeature_high) << 32) | xfeature_low;
    struct segment_register sreg;

    hvm_get_segment_register(v, x86_seg_ss, &sreg);
    if ( sreg.attr.fields.dpl != 0 )
        goto err;

    if ( ((new_bv ^ xfeature) & ~xfeature) || !(new_bv & 1) )
        goto err;

    if ( (xfeature & XSTATE_YMM & new_bv) && !(new_bv & XSTATE_SSE) )
        goto err;

    v->arch.hvm_vcpu.xfeature_mask = new_bv;
    set_xcr0(new_bv);
    return 0;
err:
    vmx_inject_hw_exception(TRAP_gp_fault, 0);
    return -1;
}

asmlinkage void vmx_vmexit_handler(struct cpu_user_regs *regs)
{
    unsigned int exit_reason, idtv_info;
    unsigned long exit_qualification, inst_len = 0;
    struct vcpu *v = current;

    if ( paging_mode_hap(v->domain) && hvm_paging_enabled(v) )
        v->arch.hvm_vcpu.guest_cr[3] = v->arch.hvm_vcpu.hw_cr[3] =
            __vmread(GUEST_CR3);

    exit_reason = __vmread(VM_EXIT_REASON);

    if ( hvm_long_mode_enabled(v) )
        HVMTRACE_ND(VMEXIT64, 1/*cycles*/, 3, exit_reason,
                    (uint32_t)regs->eip, (uint32_t)((uint64_t)regs->eip >> 32),
                    0, 0, 0);
    else
        HVMTRACE_ND(VMEXIT, 1/*cycles*/, 2, exit_reason,
                    (uint32_t)regs->eip, 
                    0, 0, 0, 0);

    perfc_incra(vmexits, exit_reason);

    /* Handle the interrupt we missed before allowing any more in. */
    if ( exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT )
        vmx_do_extint(regs);

    /* Now enable interrupts so it's safe to take locks. */
    local_irq_enable();

    if ( unlikely(exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) )
        return vmx_failed_vmentry(exit_reason, regs);

    if ( v->arch.hvm_vmx.vmx_realmode )
    {
        unsigned int vector;

        /* Put RFLAGS back the way the guest wants it */
        regs->eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IOPL);
        regs->eflags |= (v->arch.hvm_vmx.vm86_saved_eflags & X86_EFLAGS_IOPL);

        /* Unless this exit was for an interrupt, we've hit something
         * vm86 can't handle.  Try again, using the emulator. */
        switch ( exit_reason )
        {
        case EXIT_REASON_EXCEPTION_NMI:
            vector = __vmread(VM_EXIT_INTR_INFO) & INTR_INFO_VECTOR_MASK;
            if ( vector != TRAP_page_fault
                 && vector != TRAP_nmi 
                 && vector != TRAP_machine_check ) 
            {
                perfc_incr(realmode_exits);
                v->arch.hvm_vmx.vmx_emulate = 1;
                return;
            }
        case EXIT_REASON_EXTERNAL_INTERRUPT:
        case EXIT_REASON_INIT:
        case EXIT_REASON_SIPI:
        case EXIT_REASON_PENDING_VIRT_INTR:
        case EXIT_REASON_PENDING_VIRT_NMI:
        case EXIT_REASON_MCE_DURING_VMENTRY:
            break;
        default:
            v->arch.hvm_vmx.vmx_emulate = 1;
            perfc_incr(realmode_exits);
            return;
        }
    }

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
             !(idtv_info & INTR_INFO_VALID_MASK) &&
             (vector != TRAP_double_fault) )
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO,
                      __vmread(GUEST_INTERRUPTIBILITY_INFO)
                      | VMX_INTR_SHADOW_NMI);

        perfc_incra(cause_vector, vector);

        switch ( vector )
        {
        case TRAP_debug:
            /*
             * Updates DR6 where debugger can peek (See 3B 23.2.1,
             * Table 23-1, "Exit Qualification for Debug Exceptions").
             */
            exit_qualification = __vmread(EXIT_QUALIFICATION);
            write_debugreg(6, exit_qualification | 0xffff0ff0);
            if ( !v->domain->debugger_attached || cpu_has_monitor_trap_flag )
                goto exit_and_crash;
            domain_pause_for_debugger();
            break;
        case TRAP_int3:
            if ( !v->domain->debugger_attached )
                goto exit_and_crash;
            inst_len = __get_instruction_length(); /* Safe: INT3 */
            __update_guest_eip(inst_len);
            domain_pause_for_debugger();
            break;
        case TRAP_no_device:
            vmx_fpu_dirty_intercept();
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
                if ( trace_will_trace_event(TRC_SHADOW) )
                    break;
                if ( hvm_long_mode_enabled(v) )
                    HVMTRACE_LONG_2D(PF_XEN, regs->error_code,
                                     TRC_PAR_LONG(exit_qualification) );
                else
                    HVMTRACE_2D(PF_XEN,
                                regs->error_code, exit_qualification );
                break;
            }

            v->arch.hvm_vcpu.guest_cr[2] = exit_qualification;
            vmx_inject_hw_exception(TRAP_page_fault, regs->error_code);
            break;
        case TRAP_nmi:
            if ( (intr_info & INTR_INFO_INTR_TYPE_MASK) !=
                 (X86_EVENTTYPE_NMI << 8) )
                goto exit_and_crash;
            HVMTRACE_0D(NMI);
            self_nmi(); /* Real NMI, vector 2: normal processing. */
            break;
        case TRAP_machine_check:
            HVMTRACE_0D(MCE);
            do_machine_check(regs);
            break;
        case TRAP_invalid_op:
            vmx_vmexit_ud_intercept(regs);
            break;
        default:
            goto exit_and_crash;
        }
        break;
    }
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        /* Already handled above. */
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
        int32_t ecode = -1, source;
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        source = (exit_qualification >> 30) & 3;
        inst_len = __get_instruction_length(); /* Safe: See SDM 3B 23.2.4 */
        if ( (source == 3) && (idtv_info & INTR_INFO_VALID_MASK) )
        {
            /* ExtInt, NMI, HWException: no instruction to skip over. */
            if ( !(idtv_info & (1u<<10)) ) /* 0 <= IntrType <= 3? */
                inst_len = 0;
            /* If there's an error code then we pass it along. */
            if ( idtv_info & INTR_INFO_DELIVER_CODE_MASK )
                ecode = __vmread(IDT_VECTORING_ERROR_CODE);
        }
        regs->eip += inst_len;
        hvm_task_switch((uint16_t)exit_qualification, reasons[source], ecode);
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
        hvm_hlt(regs->eflags);
        break;
    case EXIT_REASON_INVLPG:
    {
        inst_len = __get_instruction_length(); /* Safe: INVLPG */
        __update_guest_eip(inst_len);
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        vmx_invlpg_intercept(exit_qualification);
        break;
    }
    case EXIT_REASON_RDTSC:
        inst_len = __get_instruction_length();
        __update_guest_eip(inst_len);
        hvm_rdtsc_intercept(regs);
        break;
    case EXIT_REASON_VMCALL:
    {
        int rc;
        HVMTRACE_1D(VMMCALL, regs->eax);
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
    case EXIT_REASON_MSR_READ:
        inst_len = __get_instruction_length(); /* Safe: RDMSR */
        if ( hvm_msr_read_intercept(regs) == X86EMUL_OKAY )
            __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_MSR_WRITE:
        inst_len = __get_instruction_length(); /* Safe: WRMSR */
        if ( hvm_msr_write_intercept(regs) == X86EMUL_OKAY )
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
        vmx_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;

    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        break;

    case EXIT_REASON_APIC_ACCESS:
        if ( !vmx_handle_eoi_write() && !handle_mmio() )
            vmx_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case EXIT_REASON_IO_INSTRUCTION:
        if ( !handle_mmio() )
            vmx_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case EXIT_REASON_INVD:
    case EXIT_REASON_WBINVD:
    {
        inst_len = __get_instruction_length(); /* Safe: INVD, WBINVD */
        __update_guest_eip(inst_len);
        vmx_wbinvd_intercept();
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        paddr_t gpa = __vmread(GUEST_PHYSICAL_ADDRESS);
#ifdef __i386__
        gpa |= (paddr_t)__vmread(GUEST_PHYSICAL_ADDRESS_HIGH) << 32;
#endif
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        ept_handle_violation(exit_qualification, gpa);
        break;
    }

    case EXIT_REASON_MONITOR_TRAP_FLAG:
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_MONITOR_TRAP_FLAG;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vmx.exec_control);
        if ( v->domain->debugger_attached && v->arch.hvm_vcpu.single_step )
            domain_pause_for_debugger();
        break;

    case EXIT_REASON_PAUSE_INSTRUCTION:
        perfc_incr(pauseloop_exits);
        do_sched_op_compat(SCHEDOP_yield, 0);
        break;

    case EXIT_REASON_XSETBV:
    {
        u64 new_bv  =  (((u64)regs->edx) << 32) | regs->eax;
        if ( vmx_handle_xsetbv(new_bv) == 0 )
        {
            inst_len = __get_instruction_length();
            __update_guest_eip(inst_len);
        }
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
    HVMTRACE_ND (VMENTRY, 1/*cycles*/, 0, 0, 0, 0, 0, 0, 0);
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
