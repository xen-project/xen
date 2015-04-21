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
#include <asm/iocap.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/mem_sharing.h>
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
#include <asm/debugger.h>
#include <asm/apic.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/event.h>
#include <public/arch-x86/cpuid.h>

static bool_t __initdata opt_force_ept;
boolean_param("force-ept", opt_force_ept);

enum handler_return { HNDL_done, HNDL_unhandled, HNDL_exception_raised };

static void vmx_ctxt_switch_from(struct vcpu *v);
static void vmx_ctxt_switch_to(struct vcpu *v);

static int  vmx_alloc_vlapic_mapping(struct domain *d);
static void vmx_free_vlapic_mapping(struct domain *d);
static void vmx_install_vlapic_mapping(struct vcpu *v);
static void vmx_update_guest_cr(struct vcpu *v, unsigned int cr);
static void vmx_update_guest_efer(struct vcpu *v);
static void vmx_cpuid_intercept(
    unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx);
static void vmx_wbinvd_intercept(void);
static void vmx_fpu_dirty_intercept(void);
static int vmx_msr_read_intercept(unsigned int msr, uint64_t *msr_content);
static int vmx_msr_write_intercept(unsigned int msr, uint64_t msr_content);
static void vmx_invlpg_intercept(unsigned long vaddr);

uint8_t __read_mostly posted_intr_vector;

static int vmx_domain_initialise(struct domain *d)
{
    int rc;

    if ( (rc = vmx_alloc_vlapic_mapping(d)) != 0 )
        return rc;

    return 0;
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

    vpmu_initialise(v);

    vmx_install_vlapic_mapping(v);

    /* %eax == 1 signals full real-mode support to the guest loader. */
    if ( v->vcpu_id == 0 )
        v->arch.user_regs.eax = 1;

    return 0;
}

static void vmx_vcpu_destroy(struct vcpu *v)
{
    vmx_destroy_vmcs(v);
    vpmu_destroy(v);
    passive_domain_destroy(v);
}

static DEFINE_PER_CPU(struct vmx_msr_state, host_msr_state);

static const u32 msr_index[] =
{
    MSR_LSTAR, MSR_STAR, MSR_SYSCALL_MASK
};

#define MSR_INDEX_SIZE (ARRAY_SIZE(msr_index))

void vmx_save_host_msrs(void)
{
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);
    int i;

    for ( i = 0; i < MSR_INDEX_SIZE; i++ )
        rdmsrl(msr_index[i], host_msr_state->msrs[i]);
}

#define WRITE_MSR(address)                                              \
        guest_msr_state->msrs[VMX_INDEX_MSR_ ## address] = msr_content; \
        set_bit(VMX_INDEX_MSR_ ## address, &guest_msr_state->flags);    \
        wrmsrl(MSR_ ## address, msr_content);                           \
        set_bit(VMX_INDEX_MSR_ ## address, &host_msr_state->flags);     \
        break

static enum handler_return
long_mode_do_msr_read(unsigned int msr, uint64_t *msr_content)
{
    struct vcpu *v = current;
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;

    switch ( msr )
    {
    case MSR_FS_BASE:
        __vmread(GUEST_FS_BASE, msr_content);
        break;

    case MSR_GS_BASE:
        __vmread(GUEST_GS_BASE, msr_content);
        break;

    case MSR_SHADOW_GS_BASE:
        rdmsrl(MSR_SHADOW_GS_BASE, *msr_content);
        break;

    case MSR_STAR:
        *msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_STAR];
        break;

    case MSR_LSTAR:
        *msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_LSTAR];
        break;

    case MSR_CSTAR:
        *msr_content = v->arch.hvm_vmx.cstar;
        break;

    case MSR_SYSCALL_MASK:
        *msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK];
        break;

    default:
        return HNDL_unhandled;
    }

    HVM_DBG_LOG(DBG_LEVEL_MSR, "msr %#x content %#"PRIx64, msr, *msr_content);

    return HNDL_done;
}

static enum handler_return
long_mode_do_msr_write(unsigned int msr, uint64_t msr_content)
{
    struct vcpu *v = current;
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);

    HVM_DBG_LOG(DBG_LEVEL_MSR, "msr %#x content %#"PRIx64, msr, msr_content);

    switch ( msr )
    {
    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;

        if ( msr == MSR_FS_BASE )
            __vmwrite(GUEST_FS_BASE, msr_content);
        else if ( msr == MSR_GS_BASE )
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
    HVM_DBG_LOG(DBG_LEVEL_MSR, "Not cano address of msr write %x", msr);
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
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

    if ( cpu_has_rdtscp )
        wrmsrl(MSR_TSC_AUX, hvm_msr_tsc_aux(v));
}

void vmx_update_cpu_exec_control(struct vcpu *v)
{
    if ( nestedhvm_vcpu_in_guestmode(v) )
        nvmx_update_exec_control(v, v->arch.hvm_vmx.exec_control);
    else
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vmx.exec_control);
}

void vmx_update_secondary_exec_control(struct vcpu *v)
{
    if ( nestedhvm_vcpu_in_guestmode(v) )
        nvmx_update_secondary_exec_control(v,
            v->arch.hvm_vmx.secondary_exec_control);
    else
        __vmwrite(SECONDARY_VM_EXEC_CONTROL,
                  v->arch.hvm_vmx.secondary_exec_control);
}

void vmx_update_exception_bitmap(struct vcpu *v)
{
    if ( nestedhvm_vcpu_in_guestmode(v) )
        nvmx_update_exception_bitmap(v, v->arch.hvm_vmx.exception_bitmap);
    else
        __vmwrite(EXCEPTION_BITMAP, v->arch.hvm_vmx.exception_bitmap);
}

static int vmx_guest_x86_mode(struct vcpu *v)
{
    unsigned long cs_ar_bytes;

    if ( unlikely(!(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE)) )
        return 0;
    if ( unlikely(guest_cpu_user_regs()->eflags & X86_EFLAGS_VM) )
        return 1;
    __vmread(GUEST_CS_AR_BYTES, &cs_ar_bytes);
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
    vmx_update_cpu_exec_control(v);

    v->arch.debugreg[0] = read_debugreg(0);
    v->arch.debugreg[1] = read_debugreg(1);
    v->arch.debugreg[2] = read_debugreg(2);
    v->arch.debugreg[3] = read_debugreg(3);
    v->arch.debugreg[6] = read_debugreg(6);
    /* DR7 must be saved as it is used by vmx_restore_dr(). */
    __vmread(GUEST_DR7, &v->arch.debugreg[7]);
}

static void __restore_debug_registers(struct vcpu *v)
{
    if ( v->arch.hvm_vcpu.flag_dr_dirty )
        return;

    v->arch.hvm_vcpu.flag_dr_dirty = 1;

    write_debugreg(0, v->arch.debugreg[0]);
    write_debugreg(1, v->arch.debugreg[1]);
    write_debugreg(2, v->arch.debugreg[2]);
    write_debugreg(3, v->arch.debugreg[3]);
    write_debugreg(6, v->arch.debugreg[6]);
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
    if ( unlikely(v->arch.debugreg[7] & DR7_ACTIVE_MASK) )
        __restore_debug_registers(v);
}

static void vmx_vmcs_save(struct vcpu *v, struct hvm_hw_cpu *c)
{
    unsigned long ev;

    vmx_vmcs_enter(v);

    c->cr0 = v->arch.hvm_vcpu.guest_cr[0];
    c->cr2 = v->arch.hvm_vcpu.guest_cr[2];
    c->cr3 = v->arch.hvm_vcpu.guest_cr[3];
    c->cr4 = v->arch.hvm_vcpu.guest_cr[4];

    c->msr_efer = v->arch.hvm_vcpu.guest_efer;

    __vmread(GUEST_SYSENTER_CS, &c->sysenter_cs);
    __vmread(GUEST_SYSENTER_ESP, &c->sysenter_esp);
    __vmread(GUEST_SYSENTER_EIP, &c->sysenter_eip);

    c->pending_event = 0;
    c->error_code = 0;
    __vmread(VM_ENTRY_INTR_INFO, &ev);
    if ( (ev & INTR_INFO_VALID_MASK) &&
         hvm_event_needs_reinjection(MASK_EXTR(ev, INTR_INFO_INTR_TYPE_MASK),
                                     ev & INTR_INFO_VECTOR_MASK) )
    {
        c->pending_event = ev;
        __vmread(VM_ENTRY_EXCEPTION_ERROR_CODE, &ev);
        c->error_code = ev;
    }

    vmx_vmcs_exit(v);
}

static int vmx_restore_cr0_cr3(
    struct vcpu *v, unsigned long cr0, unsigned long cr3)
{
    struct page_info *page = NULL;

    if ( paging_mode_shadow(v->domain) )
    {
        if ( cr0 & X86_CR0_PG )
        {
            page = get_page_from_gfn(v->domain, cr3 >> PAGE_SHIFT,
                                     NULL, P2M_ALLOC);
            if ( !page )
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value=%#lx\n", cr3);
                return -EINVAL;
            }
        }

        if ( hvm_paging_enabled(v) )
            put_page(pagetable_get_page(v->arch.guest_table));

        v->arch.guest_table =
            page ? pagetable_from_page(page) : pagetable_null();
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
        gdprintk(XENLOG_ERR, "Invalid pending event %#"PRIx32".\n",
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

    if ( c->pending_valid &&
         hvm_event_needs_reinjection(c->pending_type, c->pending_vector) )
    {
        gdprintk(XENLOG_INFO, "Re-injecting %#"PRIx32", %#"PRIx32"\n",
                 c->pending_event, c->error_code);
        __vmwrite(VM_ENTRY_INTR_INFO, c->pending_event);
        __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, c->error_code);
    }
    else
    {
        __vmwrite(VM_ENTRY_INTR_INFO, 0);
        __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
    }
    vmx_vmcs_exit(v);

    paging_update_paging_modes(v);

    return 0;
}

static void vmx_save_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;
    unsigned long guest_flags = guest_state->flags;

    data->shadow_gs = v->arch.hvm_vmx.shadow_gs;
    data->msr_cstar = v->arch.hvm_vmx.cstar;

    /* save msrs */
    data->msr_flags        = guest_flags;
    data->msr_lstar        = guest_state->msrs[VMX_INDEX_MSR_LSTAR];
    data->msr_star         = guest_state->msrs[VMX_INDEX_MSR_STAR];
    data->msr_syscall_mask = guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK];

    data->tsc = hvm_get_guest_tsc_fixed(v,
                                        v->domain->arch.hvm_domain.sync_tsc);
}

static void vmx_load_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;

    /* restore msrs */
    guest_state->flags = data->msr_flags & 7;
    guest_state->msrs[VMX_INDEX_MSR_LSTAR]        = data->msr_lstar;
    guest_state->msrs[VMX_INDEX_MSR_STAR]         = data->msr_star;
    guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK] = data->msr_syscall_mask;

    v->arch.hvm_vmx.cstar     = data->msr_cstar;
    v->arch.hvm_vmx.shadow_gs = data->shadow_gs;

    hvm_set_guest_tsc_fixed(v, data->tsc, v->domain->arch.hvm_domain.sync_tsc);
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

static unsigned int __init vmx_init_msr(void)
{
    return !!cpu_has_mpx;
}

static void vmx_save_msr(struct vcpu *v, struct hvm_msr *ctxt)
{
    vmx_vmcs_enter(v);

    if ( cpu_has_mpx )
    {
        __vmread(GUEST_BNDCFGS, &ctxt->msr[ctxt->count].val);
        if ( ctxt->msr[ctxt->count].val )
            ctxt->msr[ctxt->count++].index = MSR_IA32_BNDCFGS;
    }

    vmx_vmcs_exit(v);
}

static int vmx_load_msr(struct vcpu *v, struct hvm_msr *ctxt)
{
    unsigned int i;
    int err = 0;

    vmx_vmcs_enter(v);

    for ( i = 0; i < ctxt->count; ++i )
    {
        switch ( ctxt->msr[i].index )
        {
        case MSR_IA32_BNDCFGS:
            if ( cpu_has_mpx )
                __vmwrite(GUEST_BNDCFGS, ctxt->msr[i].val);
            else
                err = -ENXIO;
            break;
        default:
            continue;
        }
        if ( err )
            break;
        ctxt->msr[i]._rsvd = 1;
    }

    vmx_vmcs_exit(v);

    return err;
}

static void vmx_fpu_enter(struct vcpu *v)
{
    vcpu_restore_fpu_lazy(v);
    v->arch.hvm_vmx.exception_bitmap &= ~(1u << TRAP_no_device);
    vmx_update_exception_bitmap(v);
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
        v->arch.hvm_vmx.exception_bitmap |= (1u << TRAP_no_device);
        vmx_update_exception_bitmap(v);
    }
}

static void vmx_ctxt_switch_from(struct vcpu *v)
{
    /*
     * Return early if trying to do a context switch without VMX enabled,
     * this can happen when the hypervisor shuts down with HVM guests
     * still running.
     */
    if ( unlikely(!this_cpu(vmxon)) )
        return;

    vmx_fpu_leave(v);
    vmx_save_guest_msrs(v);
    vmx_restore_host_msrs();
    vmx_save_dr(v);
}

static void vmx_ctxt_switch_to(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned long old_cr4 = read_cr4(), new_cr4 = mmu_cr4_features;
    struct ept_data *ept_data = &p2m_get_hostp2m(d)->ept;

    /* HOST_CR4 in VMCS is always mmu_cr4_features. Sync CR4 now. */
    if ( old_cr4 != new_cr4 )
        write_cr4(new_cr4);

    if ( paging_mode_hap(d) )
    {
        unsigned int cpu = smp_processor_id();
        /* Test-and-test-and-set this CPU in the EPT-is-synced mask. */
        if ( !cpumask_test_cpu(cpu, ept_get_synced_mask(ept_data)) &&
             !cpumask_test_and_set_cpu(cpu,
                                       ept_get_synced_mask(ept_data)) )
            __invept(INVEPT_SINGLE_CONTEXT, ept_get_eptp(ept_data), 0);
    }

    vmx_restore_guest_msrs(v);
    vmx_restore_dr(v);
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

void vmx_get_segment_register(struct vcpu *v, enum x86_segment seg,
                              struct segment_register *reg)
{
    unsigned long attr = 0, sel = 0, limit;

    /*
     * We may get here in the context of dump_execstate(), which may have
     * interrupted context switching between setting "current" and
     * vmx_do_resume() reaching the end of vmx_load_vmcs(). That would make
     * all the VMREADs below fail if we don't bail right away.
     */
    if ( unlikely(!vmx_vmcs_try_enter(v)) )
    {
        static bool_t warned;

        if ( !warned )
        {
            warned = 1;
            printk(XENLOG_WARNING "Segment register inaccessible for %pv\n"
                   "(If you see this outside of debugging activity,"
                   " please report to xen-devel@lists.xenproject.org)\n",
                   v);
        }
        memset(reg, 0, sizeof(*reg));
        return;
    }

    switch ( seg )
    {
    case x86_seg_cs:
        __vmread(GUEST_CS_SELECTOR, &sel);
        __vmread(GUEST_CS_LIMIT,    &limit);
        __vmread(GUEST_CS_BASE,     &reg->base);
        __vmread(GUEST_CS_AR_BYTES, &attr);
        break;
    case x86_seg_ds:
        __vmread(GUEST_DS_SELECTOR, &sel);
        __vmread(GUEST_DS_LIMIT,    &limit);
        __vmread(GUEST_DS_BASE,     &reg->base);
        __vmread(GUEST_DS_AR_BYTES, &attr);
        break;
    case x86_seg_es:
        __vmread(GUEST_ES_SELECTOR, &sel);
        __vmread(GUEST_ES_LIMIT,    &limit);
        __vmread(GUEST_ES_BASE,     &reg->base);
        __vmread(GUEST_ES_AR_BYTES, &attr);
        break;
    case x86_seg_fs:
        __vmread(GUEST_FS_SELECTOR, &sel);
        __vmread(GUEST_FS_LIMIT,    &limit);
        __vmread(GUEST_FS_BASE,     &reg->base);
        __vmread(GUEST_FS_AR_BYTES, &attr);
        break;
    case x86_seg_gs:
        __vmread(GUEST_GS_SELECTOR, &sel);
        __vmread(GUEST_GS_LIMIT,    &limit);
        __vmread(GUEST_GS_BASE,     &reg->base);
        __vmread(GUEST_GS_AR_BYTES, &attr);
        break;
    case x86_seg_ss:
        __vmread(GUEST_SS_SELECTOR, &sel);
        __vmread(GUEST_SS_LIMIT,    &limit);
        __vmread(GUEST_SS_BASE,     &reg->base);
        __vmread(GUEST_SS_AR_BYTES, &attr);
        break;
    case x86_seg_tr:
        __vmread(GUEST_TR_SELECTOR, &sel);
        __vmread(GUEST_TR_LIMIT,    &limit);
        __vmread(GUEST_TR_BASE,     &reg->base);
        __vmread(GUEST_TR_AR_BYTES, &attr);
        break;
    case x86_seg_gdtr:
        __vmread(GUEST_GDTR_LIMIT, &limit);
        __vmread(GUEST_GDTR_BASE,  &reg->base);
        break;
    case x86_seg_idtr:
        __vmread(GUEST_IDTR_LIMIT, &limit);
        __vmread(GUEST_IDTR_BASE,  &reg->base);
        break;
    case x86_seg_ldtr:
        __vmread(GUEST_LDTR_SELECTOR, &sel);
        __vmread(GUEST_LDTR_LIMIT,    &limit);
        __vmread(GUEST_LDTR_BASE,     &reg->base);
        __vmread(GUEST_LDTR_AR_BYTES, &attr);
        break;
    default:
        BUG();
        return;
    }

    vmx_vmcs_exit(v);

    reg->sel = sel;
    reg->limit = limit;

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

static unsigned long vmx_get_shadow_gs_base(struct vcpu *v)
{
    return v->arch.hvm_vmx.shadow_gs;
}

static int vmx_set_guest_pat(struct vcpu *v, u64 gpat)
{
    if ( !paging_mode_hap(v->domain) ||
         unlikely(v->arch.hvm_vcpu.cache_mode == NO_FILL_CACHE_MODE) )
        return 0;

    vmx_vmcs_enter(v);
    __vmwrite(GUEST_PAT, gpat);
    vmx_vmcs_exit(v);
    return 1;
}

static int vmx_get_guest_pat(struct vcpu *v, u64 *gpat)
{
    if ( !paging_mode_hap(v->domain) ||
         unlikely(v->arch.hvm_vcpu.cache_mode == NO_FILL_CACHE_MODE) )
        return 0;

    vmx_vmcs_enter(v);
    __vmread(GUEST_PAT, gpat);
    vmx_vmcs_exit(v);
    return 1;
}

static void vmx_handle_cd(struct vcpu *v, unsigned long value)
{
    if ( !paging_mode_hap(v->domain) )
    {
        /*
         * For shadow, 'load IA32_PAT' VM-entry control is 0, so it cannot
         * set guest memory type as UC via IA32_PAT. Xen drop all shadows
         * so that any new ones would be created on demand.
         */
        hvm_shadow_handle_cd(v, value);
    }
    else
    {
        u64 *pat = &v->arch.hvm_vcpu.pat_cr;

        if ( value & X86_CR0_CD )
        {
            /*
             * For EPT, set guest IA32_PAT fields as UC so that guest
             * memory type are all UC.
             */
            u64 uc_pat =
                ((uint64_t)PAT_TYPE_UNCACHABLE)       |       /* PAT0 */
                ((uint64_t)PAT_TYPE_UNCACHABLE << 8)  |       /* PAT1 */
                ((uint64_t)PAT_TYPE_UNCACHABLE << 16) |       /* PAT2 */
                ((uint64_t)PAT_TYPE_UNCACHABLE << 24) |       /* PAT3 */
                ((uint64_t)PAT_TYPE_UNCACHABLE << 32) |       /* PAT4 */
                ((uint64_t)PAT_TYPE_UNCACHABLE << 40) |       /* PAT5 */
                ((uint64_t)PAT_TYPE_UNCACHABLE << 48) |       /* PAT6 */
                ((uint64_t)PAT_TYPE_UNCACHABLE << 56);        /* PAT7 */

            vmx_get_guest_pat(v, pat);
            vmx_set_guest_pat(v, uc_pat);
            vmx_enable_intercept_for_msr(v, MSR_IA32_CR_PAT,
                                         MSR_TYPE_R | MSR_TYPE_W);

            wbinvd();               /* flush possibly polluted cache */
            hvm_asid_flush_vcpu(v); /* invalidate memory type cached in TLB */
            v->arch.hvm_vcpu.cache_mode = NO_FILL_CACHE_MODE;
        }
        else
        {
            v->arch.hvm_vcpu.cache_mode = NORMAL_CACHE_MODE;
            vmx_set_guest_pat(v, *pat);
            if ( !iommu_enabled || iommu_snoop )
                vmx_disable_intercept_for_msr(v, MSR_IA32_CR_PAT,
                                              MSR_TYPE_R | MSR_TYPE_W);
            hvm_asid_flush_vcpu(v); /* no need to flush cache */
        }
    }
}

static void vmx_set_tsc_offset(struct vcpu *v, u64 offset, u64 at_tsc)
{
    vmx_vmcs_enter(v);

    if ( nestedhvm_vcpu_in_guestmode(v) )
        offset += nvmx_get_tsc_offset(v);

    __vmwrite(TSC_OFFSET, offset);
    vmx_vmcs_exit(v);
}

static void vmx_set_rdtsc_exiting(struct vcpu *v, bool_t enable)
{
    vmx_vmcs_enter(v);
    v->arch.hvm_vmx.exec_control &= ~CPU_BASED_RDTSC_EXITING;
    if ( enable )
        v->arch.hvm_vmx.exec_control |= CPU_BASED_RDTSC_EXITING;
    vmx_update_cpu_exec_control(v);
    vmx_vmcs_exit(v);
}

static void vmx_init_hypercall_page(struct domain *d, void *hypercall_page)
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
    unsigned long intr_shadow;

    __vmread(GUEST_INTERRUPTIBILITY_INFO, &intr_shadow);

    return intr_shadow;
}

static void vmx_set_interrupt_shadow(struct vcpu *v, unsigned int intr_shadow)
{
    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
}

static void vmx_load_pdptrs(struct vcpu *v)
{
    unsigned long cr3 = v->arch.hvm_vcpu.guest_cr[3];
    uint64_t *guest_pdptrs;
    struct page_info *page;
    p2m_type_t p2mt;
    char *p;

    /* EPT needs to load PDPTRS into VMCS for PAE. */
    if ( !hvm_pae_enabled(v) || (v->arch.hvm_vcpu.guest_efer & EFER_LMA) )
        return;

    if ( (cr3 & 0x1fUL) && !hvm_pcid_enabled(v) )
        goto crash;

    page = get_page_from_gfn(v->domain, cr3 >> PAGE_SHIFT, &p2mt, P2M_UNSHARE);
    if ( !page )
    {
        /* Ideally you don't want to crash but rather go into a wait 
         * queue, but this is the wrong place. We're holding at least
         * the paging lock */
        gdprintk(XENLOG_ERR,
                 "Bad cr3 on load pdptrs gfn %lx type %d\n",
                 cr3 >> PAGE_SHIFT, (int) p2mt);
        goto crash;
    }

    p = __map_domain_page(page);

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

    vmx_vmcs_exit(v);

    unmap_domain_page(p);
    put_page(page);
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
    unsigned long mask;

    mask = 1u << TRAP_int3;
    if ( !cpu_has_monitor_trap_flag )
        mask |= 1u << TRAP_debug;

    if ( v->arch.hvm_vcpu.debug_state_latch )
        v->arch.hvm_vmx.exception_bitmap |= mask;
    else
        v->arch.hvm_vmx.exception_bitmap &= ~mask;

    vmx_vmcs_enter(v);
    vmx_update_exception_bitmap(v);
    vmx_vmcs_exit(v);
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
            /* Manage GUEST_CR3 when CR0.PE=0. */
            uint32_t cr3_ctls = (CPU_BASED_CR3_LOAD_EXITING |
                                 CPU_BASED_CR3_STORE_EXITING);
            v->arch.hvm_vmx.exec_control &= ~cr3_ctls;
            if ( !hvm_paging_enabled(v) && !vmx_unrestricted_guest(v) )
                v->arch.hvm_vmx.exec_control |= cr3_ctls;

            /* Trap CR3 updates if CR3 memory events are enabled. */
            if ( v->domain->arch.hvm_domain.params[HVM_PARAM_MEMORY_EVENT_CR3] )
                v->arch.hvm_vmx.exec_control |= CPU_BASED_CR3_LOAD_EXITING;

            vmx_update_cpu_exec_control(v);
        }

        if ( !nestedhvm_vcpu_in_guestmode(v) )
            __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vcpu.guest_cr[0]);
        else
            nvmx_set_cr_read_shadow(v, 0);

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
                v->arch.hvm_vmx.exception_bitmap = 0xffffffff;
                vmx_update_exception_bitmap(v);
            }
            else 
            {
                for ( s = x86_seg_cs ; s <= x86_seg_tr ; s++ ) 
                    if ( !(v->arch.hvm_vmx.vm86_segment_mask & (1<<s)) )
                        vmx_set_segment_register(
                            v, s, &v->arch.hvm_vmx.vm86_saved_seg[s]);
                v->arch.hvm_vmx.exception_bitmap = HVM_TRAP_MASK
                          | (paging_mode_hap(v->domain) ?
                             0 : (1U << TRAP_page_fault))
                          | (1U << TRAP_no_device);
                vmx_update_exception_bitmap(v);
                vmx_update_debug_state(v);
            }
        }

        v->arch.hvm_vcpu.hw_cr[0] =
            v->arch.hvm_vcpu.guest_cr[0] | hw_cr0_mask;
        __vmwrite(GUEST_CR0, v->arch.hvm_vcpu.hw_cr[0]);

        /* Changing CR0 can change some bits in real CR4. */
        vmx_update_guest_cr(v, 4);
        break;
    }
    case 2:
        /* CR2 is updated in exit stub. */
        break;
    case 3:
        if ( paging_mode_hap(v->domain) )
        {
            if ( !hvm_paging_enabled(v) && !vmx_unrestricted_guest(v) )
                v->arch.hvm_vcpu.hw_cr[3] =
                    v->domain->arch.hvm_domain.params[HVM_PARAM_IDENT_PT];
            vmx_load_pdptrs(v);
        }
 
        __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr[3]);
        hvm_asid_flush_vcpu(v);
        break;
    case 4:
        v->arch.hvm_vcpu.hw_cr[4] = HVM_CR4_HOST_MASK;
        if ( paging_mode_hap(v->domain) )
            v->arch.hvm_vcpu.hw_cr[4] &= ~X86_CR4_PAE;

        if ( !nestedhvm_vcpu_in_guestmode(v) )
            __vmwrite(CR4_READ_SHADOW, v->arch.hvm_vcpu.guest_cr[4]);
        else
            nvmx_set_cr_read_shadow(v, 4);

        v->arch.hvm_vcpu.hw_cr[4] |= v->arch.hvm_vcpu.guest_cr[4];
        if ( v->arch.hvm_vmx.vmx_realmode ) 
            v->arch.hvm_vcpu.hw_cr[4] |= X86_CR4_VME;
        if ( paging_mode_hap(v->domain) && !hvm_paging_enabled(v) )
        {
            v->arch.hvm_vcpu.hw_cr[4] |= X86_CR4_PSE;
            v->arch.hvm_vcpu.hw_cr[4] &= ~X86_CR4_PAE;
        }
        if ( !hvm_paging_enabled(v) )
        {
            /*
             * SMEP/SMAP is disabled if CPU is in non-paging mode in hardware.
             * However Xen always uses paging mode to emulate guest non-paging
             * mode. To emulate this behavior, SMEP/SMAP needs to be manually
             * disabled when guest VCPU is in non-paging mode.
             */
            v->arch.hvm_vcpu.hw_cr[4] &= ~(X86_CR4_SMEP | X86_CR4_SMAP);
        }
        __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4]);
        break;
    default:
        BUG();
    }

    vmx_vmcs_exit(v);
}

static void vmx_update_guest_efer(struct vcpu *v)
{
    unsigned long vm_entry_value;

    vmx_vmcs_enter(v);

    __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
    if ( v->arch.hvm_vcpu.guest_efer & EFER_LMA )
        vm_entry_value |= VM_ENTRY_IA32E_MODE;
    else
        vm_entry_value &= ~VM_ENTRY_IA32E_MODE;
    __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);

    vmx_vmcs_exit(v);

    if ( v == current )
        write_efer((read_efer() & ~EFER_SCE) |
                   (v->arch.hvm_vcpu.guest_efer & EFER_SCE));
}

void nvmx_enqueue_n2_exceptions(struct vcpu *v, 
            unsigned long intr_fields, int error_code, uint8_t source)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);

    if ( !(nvmx->intr.intr_info & INTR_INFO_VALID_MASK) ) {
        /* enqueue the exception till the VMCS switch back to L1 */
        nvmx->intr.intr_info = intr_fields;
        nvmx->intr.error_code = error_code;
        nvmx->intr.source = source;
        vcpu_nestedhvm(v).nv_vmexit_pending = 1;
        return;
    }
    else
        gdprintk(XENLOG_ERR, "Double Fault on Nested Guest: exception %lx %x"
                 "on %lx %x\n", intr_fields, error_code,
                 nvmx->intr.intr_info, nvmx->intr.error_code);
}

static int nvmx_vmexit_trap(struct vcpu *v, struct hvm_trap *trap)
{
    nvmx_enqueue_n2_exceptions(v, trap->vector, trap->error_code,
                               hvm_intsrc_none);
    return NESTEDHVM_VMEXIT_DONE;
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

void vmx_inject_extint(int trap, uint8_t source)
{
    struct vcpu *v = current;
    u32    pin_based_cntrl;

    if ( nestedhvm_vcpu_in_guestmode(v) ) {
        pin_based_cntrl = __get_vvmcs(vcpu_nestedhvm(v).nv_vvmcx, 
                                     PIN_BASED_VM_EXEC_CONTROL);
        if ( pin_based_cntrl & PIN_BASED_EXT_INTR_MASK ) {
            nvmx_enqueue_n2_exceptions (v, 
               INTR_INFO_VALID_MASK | (X86_EVENTTYPE_EXT_INTR<<8) | trap,
               HVM_DELIVER_NO_ERROR_CODE, source);
            return;
        }
    }
    __vmx_inject_exception(trap, X86_EVENTTYPE_EXT_INTR,
                           HVM_DELIVER_NO_ERROR_CODE);
}

void vmx_inject_nmi(void)
{
    struct vcpu *v = current;
    u32    pin_based_cntrl;

    if ( nestedhvm_vcpu_in_guestmode(v) ) {
        pin_based_cntrl = __get_vvmcs(vcpu_nestedhvm(v).nv_vvmcx, 
                                     PIN_BASED_VM_EXEC_CONTROL);
        if ( pin_based_cntrl & PIN_BASED_NMI_EXITING ) {
            nvmx_enqueue_n2_exceptions (v, 
               INTR_INFO_VALID_MASK | (X86_EVENTTYPE_NMI<<8) | TRAP_nmi,
               HVM_DELIVER_NO_ERROR_CODE, hvm_intsrc_nmi);
            return;
        }
    }
    __vmx_inject_exception(2, X86_EVENTTYPE_NMI,
                           HVM_DELIVER_NO_ERROR_CODE);
}

/*
 * Generate a virtual event in the guest.
 * NOTES:
 *  - INT 3 (CC) and INTO (CE) are X86_EVENTTYPE_SW_EXCEPTION;
 *  - INT nn (CD nn) is X86_EVENTTYPE_SW_INTERRUPT;
 *  - #DB is X86_EVENTTYPE_HW_EXCEPTION, except when generated by
 *    opcode 0xf1 (which is X86_EVENTTYPE_PRI_SW_EXCEPTION)
 */
static void vmx_inject_trap(struct hvm_trap *trap)
{
    unsigned long intr_info;
    struct vcpu *curr = current;
    struct hvm_trap _trap = *trap;

    if ( (_trap.vector == TRAP_page_fault) &&
         (_trap.type == X86_EVENTTYPE_HW_EXCEPTION) )
        current->arch.hvm_vcpu.guest_cr[2] = _trap.cr2;

    if ( nestedhvm_vcpu_in_guestmode(curr) )
        intr_info = vcpu_2_nvmx(curr).intr.intr_info;
    else
        __vmread(VM_ENTRY_INTR_INFO, &intr_info);

    switch ( _trap.vector )
    {
    case TRAP_debug:
        if ( guest_cpu_user_regs()->eflags & X86_EFLAGS_TF )
        {
            __restore_debug_registers(curr);
            write_debugreg(6, read_debugreg(6) | 0x4000);
        }
        if ( cpu_has_monitor_trap_flag )
            break;
        /* fall through */
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
        _trap.vector = hvm_combine_hw_exceptions(
            (uint8_t)intr_info, _trap.vector);
        if ( _trap.vector == TRAP_double_fault )
            _trap.error_code = 0;
    }

    if ( _trap.type >= X86_EVENTTYPE_SW_INTERRUPT )
        __vmwrite(VM_ENTRY_INSTRUCTION_LEN, _trap.insn_len);

    if ( nestedhvm_vcpu_in_guestmode(curr) &&
         nvmx_intercepts_exception(curr, _trap.vector, _trap.error_code) )
    {
        nvmx_enqueue_n2_exceptions (curr, 
            INTR_INFO_VALID_MASK | (_trap.type<<8) | _trap.vector,
            _trap.error_code, hvm_intsrc_none);
        return;
    }
    else
        __vmx_inject_exception(_trap.vector, _trap.type, _trap.error_code);

    if ( (_trap.vector == TRAP_page_fault) &&
         (_trap.type == X86_EVENTTYPE_HW_EXCEPTION) )
        HVMTRACE_LONG_2D(PF_INJECT, _trap.error_code,
                         TRC_PAR_LONG(current->arch.hvm_vcpu.guest_cr[2]));
    else
        HVMTRACE_2D(INJ_EXC, _trap.vector, _trap.error_code);
}

static int vmx_event_pending(struct vcpu *v)
{
    unsigned long intr_info;

    ASSERT(v == current);
    __vmread(VM_ENTRY_INTR_INFO, &intr_info);

    return intr_info & INTR_INFO_VALID_MASK;
}

static void vmx_set_info_guest(struct vcpu *v)
{
    unsigned long intr_shadow;

    vmx_vmcs_enter(v);

    __vmwrite(GUEST_DR7, v->arch.debugreg[7]);

    /* 
     * If the interruptibility-state field indicates blocking by STI,
     * setting the TF flag in the EFLAGS may cause VM entry to fail
     * and crash the guest. See SDM 3B 22.3.1.5.
     * Resetting the VMX_INTR_SHADOW_STI flag looks hackish but
     * to set the GUEST_PENDING_DBG_EXCEPTIONS.BS here incurs
     * immediately vmexit and hence make no progress.
     */
    __vmread(GUEST_INTERRUPTIBILITY_INFO, &intr_shadow);
    if ( v->domain->debugger_attached &&
         (v->arch.user_regs.eflags & X86_EFLAGS_TF) &&
         (intr_shadow & VMX_INTR_SHADOW_STI) )
    {
        intr_shadow &= ~VMX_INTR_SHADOW_STI;
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
    }

    vmx_vmcs_exit(v);
}

static void vmx_update_eoi_exit_bitmap(struct vcpu *v, u8 vector, u8 trig)
{
    if ( trig )
        vmx_set_eoi_exit_bitmap(v, vector);
    else
        vmx_clear_eoi_exit_bitmap(v, vector);
}

static int vmx_virtual_intr_delivery_enabled(void)
{
    return cpu_has_vmx_virtual_intr_delivery;
}

static void vmx_process_isr(int isr, struct vcpu *v)
{
    unsigned long status;
    u8 old;
    unsigned int i;
    const struct vlapic *vlapic = vcpu_vlapic(v);

    if ( isr < 0 )
        isr = 0;

    vmx_vmcs_enter(v);
    __vmread(GUEST_INTR_STATUS, &status);
    old = status >> VMX_GUEST_INTR_STATUS_SVI_OFFSET;
    if ( isr != old )
    {
        status &= VMX_GUEST_INTR_STATUS_SUBFIELD_BITMASK;
        status |= isr << VMX_GUEST_INTR_STATUS_SVI_OFFSET;
        __vmwrite(GUEST_INTR_STATUS, status);
    }

    /*
     * Theoretically, only level triggered interrupts can have their
     * corresponding bits set in the eoi exit bitmap. That is, the bits
     * set in the eoi exit bitmap should also be set in TMR. But a periodic
     * timer interrupt does not follow the rule: it is edge triggered, but
     * requires its corresponding bit be set in the eoi exit bitmap. So we
     * should not construct the eoi exit bitmap based on TMR.
     * Here we will construct the eoi exit bitmap via (IRR | ISR). This
     * means that EOIs to the interrupts that are set in the IRR or ISR will
     * cause VM exits after restoring, regardless of the trigger modes. It
     * is acceptable because the subsequent interrupts will set up the eoi
     * bitmap correctly.
     */
    for ( i = 0x10; i < NR_VECTORS; ++i )
        if ( vlapic_test_vector(i, &vlapic->regs->data[APIC_IRR]) ||
             vlapic_test_vector(i, &vlapic->regs->data[APIC_ISR]) )
            set_bit(i, v->arch.hvm_vmx.eoi_exit_bitmap);

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm_vmx.eoi_exit_bitmap); ++i )
        __vmwrite(EOI_EXIT_BITMAP(i), v->arch.hvm_vmx.eoi_exit_bitmap[i]);

    vmx_vmcs_exit(v);
}

static void __vmx_deliver_posted_interrupt(struct vcpu *v)
{
    bool_t running = v->is_running;

    vcpu_unblock(v);
    if ( running && (in_irq() || (v != current)) )
    {
        unsigned int cpu = v->processor;

        if ( !test_and_set_bit(VCPU_KICK_SOFTIRQ, &softirq_pending(cpu))
             && (cpu != smp_processor_id()) )
            send_IPI_mask(cpumask_of(cpu), posted_intr_vector);
    }
}

static void vmx_deliver_posted_intr(struct vcpu *v, u8 vector)
{
    if ( pi_test_and_set_pir(vector, &v->arch.hvm_vmx.pi_desc) )
        return;

    if ( unlikely(v->arch.hvm_vmx.eoi_exitmap_changed) )
    {
        /*
         * If EOI exitbitmap needs to changed or notification vector
         * can't be allocated, interrupt will not be injected till
         * VMEntry as it used to be.
         */
        pi_set_on(&v->arch.hvm_vmx.pi_desc);
    }
    else if ( !pi_test_and_set_on(&v->arch.hvm_vmx.pi_desc) )
    {
        __vmx_deliver_posted_interrupt(v);
        return;
    }

    vcpu_kick(v);
}

static void vmx_sync_pir_to_irr(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned int group, i;
    DECLARE_BITMAP(pending_intr, NR_VECTORS);

    if ( !pi_test_and_clear_on(&v->arch.hvm_vmx.pi_desc) )
        return;

    for ( group = 0; group < ARRAY_SIZE(pending_intr); group++ )
        pending_intr[group] = pi_get_pir(&v->arch.hvm_vmx.pi_desc, group);

    for_each_set_bit(i, pending_intr, NR_VECTORS)
        vlapic_set_vector(i, &vlapic->regs->data[APIC_IRR]);
}

static void vmx_handle_eoi(u8 vector)
{
    unsigned long status;

    /* We need to clear the SVI field. */
    __vmread(GUEST_INTR_STATUS, &status);
    status &= VMX_GUEST_INTR_STATUS_SUBFIELD_BITMASK;
    __vmwrite(GUEST_INTR_STATUS, status);
}

void vmx_hypervisor_cpuid_leaf(uint32_t sub_idx,
                               uint32_t *eax, uint32_t *ebx,
                               uint32_t *ecx, uint32_t *edx)
{
    if ( sub_idx != 0 )
        return;
    if ( cpu_has_vmx_apic_reg_virt )
        *eax |= XEN_HVM_CPUID_APIC_ACCESS_VIRT;
    /*
     * We want to claim that x2APIC is virtualized if APIC MSR accesses are
     * not intercepted. When all three of these are true both rdmsr and wrmsr
     * in the guest will run without VMEXITs (see vmx_vlapic_msr_changed()).
     */
    if ( cpu_has_vmx_virtualize_x2apic_mode && cpu_has_vmx_apic_reg_virt &&
         cpu_has_vmx_virtual_intr_delivery )
        *eax |= XEN_HVM_CPUID_X2APIC_VIRT;
}

static void vmx_enable_msr_exit_interception(struct domain *d)
{
    struct vcpu *v;
    unsigned int i;

    /* Enable interception for MSRs needed for memory introspection. */
    for_each_vcpu ( d, v )
        for ( i = 0; i < vmx_introspection_force_enabled_msrs_size; i++ )
            vmx_enable_intercept_for_msr(v, vmx_introspection_force_enabled_msrs[i],
                                         MSR_TYPE_W);
}

static struct hvm_function_table __initdata vmx_function_table = {
    .name                 = "VMX",
    .cpu_up_prepare       = vmx_cpu_up_prepare,
    .cpu_dead             = vmx_cpu_dead,
    .domain_initialise    = vmx_domain_initialise,
    .domain_destroy       = vmx_domain_destroy,
    .vcpu_initialise      = vmx_vcpu_initialise,
    .vcpu_destroy         = vmx_vcpu_destroy,
    .save_cpu_ctxt        = vmx_save_vmcs_ctxt,
    .load_cpu_ctxt        = vmx_load_vmcs_ctxt,
    .init_msr             = vmx_init_msr,
    .save_msr             = vmx_save_msr,
    .load_msr             = vmx_load_msr,
    .get_interrupt_shadow = vmx_get_interrupt_shadow,
    .set_interrupt_shadow = vmx_set_interrupt_shadow,
    .guest_x86_mode       = vmx_guest_x86_mode,
    .get_segment_register = vmx_get_segment_register,
    .set_segment_register = vmx_set_segment_register,
    .get_shadow_gs_base   = vmx_get_shadow_gs_base,
    .update_host_cr3      = vmx_update_host_cr3,
    .update_guest_cr      = vmx_update_guest_cr,
    .update_guest_efer    = vmx_update_guest_efer,
    .set_guest_pat        = vmx_set_guest_pat,
    .get_guest_pat        = vmx_get_guest_pat,
    .set_tsc_offset       = vmx_set_tsc_offset,
    .inject_trap          = vmx_inject_trap,
    .init_hypercall_page  = vmx_init_hypercall_page,
    .event_pending        = vmx_event_pending,
    .cpu_up               = vmx_cpu_up,
    .cpu_down             = vmx_cpu_down,
    .cpuid_intercept      = vmx_cpuid_intercept,
    .wbinvd_intercept     = vmx_wbinvd_intercept,
    .fpu_dirty_intercept  = vmx_fpu_dirty_intercept,
    .msr_read_intercept   = vmx_msr_read_intercept,
    .msr_write_intercept  = vmx_msr_write_intercept,
    .invlpg_intercept     = vmx_invlpg_intercept,
    .handle_cd            = vmx_handle_cd,
    .set_info_guest       = vmx_set_info_guest,
    .set_rdtsc_exiting    = vmx_set_rdtsc_exiting,
    .nhvm_vcpu_initialise = nvmx_vcpu_initialise,
    .nhvm_vcpu_destroy    = nvmx_vcpu_destroy,
    .nhvm_vcpu_reset      = nvmx_vcpu_reset,
    .nhvm_vcpu_guestcr3   = nvmx_vcpu_guestcr3,
    .nhvm_vcpu_p2m_base   = nvmx_vcpu_eptp_base,
    .nhvm_vcpu_asid       = nvmx_vcpu_asid,
    .nhvm_vmcx_hap_enabled = nvmx_ept_enabled,
    .nhvm_vmcx_guest_intercepts_trap = nvmx_intercepts_exception,
    .nhvm_vcpu_vmexit_trap = nvmx_vmexit_trap,
    .nhvm_intr_blocked    = nvmx_intr_blocked,
    .nhvm_domain_relinquish_resources = nvmx_domain_relinquish_resources,
    .update_eoi_exit_bitmap = vmx_update_eoi_exit_bitmap,
    .virtual_intr_delivery_enabled = vmx_virtual_intr_delivery_enabled,
    .process_isr          = vmx_process_isr,
    .deliver_posted_intr  = vmx_deliver_posted_intr,
    .sync_pir_to_irr      = vmx_sync_pir_to_irr,
    .handle_eoi           = vmx_handle_eoi,
    .nhvm_hap_walk_L1_p2m = nvmx_hap_walk_L1_p2m,
    .hypervisor_cpuid_leaf = vmx_hypervisor_cpuid_leaf,
    .enable_msr_exit_interception = vmx_enable_msr_exit_interception,
};

const struct hvm_function_table * __init start_vmx(void)
{
    set_in_cr4(X86_CR4_VMXE);

    if ( vmx_cpu_up() )
    {
        printk("VMX: failed to initialise.\n");
        return NULL;
    }

    /*
     * Do not enable EPT when (!cpu_has_vmx_pat), to prevent security hole
     * (refer to http://xenbits.xen.org/xsa/advisory-60.html).
     */
    if ( cpu_has_vmx_ept && (cpu_has_vmx_pat || opt_force_ept) )
    {
        vmx_function_table.hap_supported = 1;

        vmx_function_table.hap_capabilities = 0;

        if ( cpu_has_vmx_ept_2mb )
            vmx_function_table.hap_capabilities |= HVM_HAP_SUPERPAGE_2MB;
        if ( cpu_has_vmx_ept_1gb )
            vmx_function_table.hap_capabilities |= HVM_HAP_SUPERPAGE_1GB;

        setup_ept_dump();
    }

    if ( !cpu_has_vmx_virtual_intr_delivery )
    {
        vmx_function_table.update_eoi_exit_bitmap = NULL;
        vmx_function_table.process_isr = NULL;
        vmx_function_table.handle_eoi = NULL;
    }

    if ( cpu_has_vmx_posted_intr_processing )
        alloc_direct_apic_vector(&posted_intr_vector, event_check_interrupt);
    else
    {
        vmx_function_table.deliver_posted_intr = NULL;
        vmx_function_table.sync_pir_to_irr = NULL;
    }

    if ( cpu_has_vmx_ept
         && cpu_has_vmx_pat
         && cpu_has_vmx_msr_bitmap
         && cpu_has_vmx_secondary_exec_control )
        vmx_function_table.pvh_supported = 1;

    setup_vmcs_dump();

    return &vmx_function_table;
}

/*
 * Not all cases receive valid value in the VM-exit instruction length field.
 * Callers must know what they're doing!
 */
static int get_instruction_length(void)
{
    unsigned long len;

    __vmread(VM_EXIT_INSTRUCTION_LEN, &len); /* Safe: callers audited */
    BUG_ON((len < 1) || (len > 15));
    return len;
}

void update_guest_eip(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    unsigned long x;

    regs->eip += get_instruction_length(); /* Safe: callers audited */
    regs->eflags &= ~X86_EFLAGS_RF;

    __vmread(GUEST_INTERRUPTIBILITY_INFO, &x);
    if ( x & (VMX_INTR_SHADOW_STI | VMX_INTR_SHADOW_MOV_SS) )
    {
        x &= ~(VMX_INTR_SHADOW_STI | VMX_INTR_SHADOW_MOV_SS);
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, x);
    }

    if ( regs->eflags & X86_EFLAGS_TF )
        hvm_inject_hw_exception(TRAP_debug, HVM_DELIVER_NO_ERROR_CODE);
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
            vmx_get_segment_register(v, x86_seg_cs, &cs);
            if ( cs.attr.fields.l )
                *edx |= cpufeat_mask(X86_FEATURE_SYSCALL);
            else
                *edx &= ~(cpufeat_mask(X86_FEATURE_SYSCALL));

            break;
    }

    vpmu_do_cpuid(input, eax, ebx, ecx, edx);

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
    vmx_update_cpu_exec_control(v);
}

static void vmx_invlpg_intercept(unsigned long vaddr)
{
    struct vcpu *curr = current;
    HVMTRACE_LONG_2D(INVLPG, /*invlpga=*/ 0, TRC_PAR_LONG(vaddr));
    if ( paging_invlpg(curr, vaddr) && cpu_has_vmx_vpid )
        vpid_sync_vcpu_gva(curr, vaddr);
}

static int vmx_cr_access(unsigned long exit_qualification)
{
    struct vcpu *curr = current;

    switch ( VMX_CONTROL_REG_ACCESS_TYPE(exit_qualification) )
    {
    case VMX_CONTROL_REG_ACCESS_TYPE_MOV_TO_CR: {
        unsigned long gp = VMX_CONTROL_REG_ACCESS_GPR(exit_qualification);
        unsigned long cr = VMX_CONTROL_REG_ACCESS_NUM(exit_qualification);
        return hvm_mov_to_cr(cr, gp);
    }
    case VMX_CONTROL_REG_ACCESS_TYPE_MOV_FROM_CR: {
        unsigned long gp = VMX_CONTROL_REG_ACCESS_GPR(exit_qualification);
        unsigned long cr = VMX_CONTROL_REG_ACCESS_NUM(exit_qualification);
        return hvm_mov_from_cr(cr, gp);
    }
    case VMX_CONTROL_REG_ACCESS_TYPE_CLTS: {
        unsigned long old = curr->arch.hvm_vcpu.guest_cr[0];
        curr->arch.hvm_vcpu.guest_cr[0] &= ~X86_CR0_TS;
        vmx_update_guest_cr(curr, 0);
        hvm_memory_event_cr0(curr->arch.hvm_vcpu.guest_cr[0], old);
        HVMTRACE_0D(CLTS);
        break;
    }
    case VMX_CONTROL_REG_ACCESS_TYPE_LMSW: {
        unsigned long value = curr->arch.hvm_vcpu.guest_cr[0];
        /* LMSW can: (1) set bits 0-3; (2) clear bits 1-3. */
        value = (value & ~0xe) | ((exit_qualification >> 16) & 0xf);
        HVMTRACE_LONG_1D(LMSW, value);
        return hvm_set_cr0(value);
    }
    default:
        BUG();
    }

    return X86EMUL_OKAY;
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
}, nh_lbr[] = {
    { MSR_IA32_LASTINTFROMIP,       1 },
    { MSR_IA32_LASTINTTOIP,         1 },
    { MSR_C2_LASTBRANCH_TOS,        1 },
    { MSR_P4_LASTBRANCH_0_FROM_LIP, NUM_MSR_P4_LASTBRANCH_FROM_TO },
    { MSR_P4_LASTBRANCH_0_TO_LIP,   NUM_MSR_P4_LASTBRANCH_FROM_TO },
    { 0, 0 }
}, at_lbr[] = {
    { MSR_IA32_LASTINTFROMIP,       1 },
    { MSR_IA32_LASTINTTOIP,         1 },
    { MSR_C2_LASTBRANCH_TOS,        1 },
    { MSR_C2_LASTBRANCH_0_FROM_IP,  NUM_MSR_ATOM_LASTBRANCH_FROM_TO },
    { MSR_C2_LASTBRANCH_0_TO_IP,    NUM_MSR_ATOM_LASTBRANCH_FROM_TO },
    { 0, 0 }
};

static const struct lbr_info *last_branch_msr_get(void)
{
    switch ( boot_cpu_data.x86 )
    {
    case 6:
        switch ( boot_cpu_data.x86_model )
        {
        /* Core2 Duo */
        case 15:
        /* Enhanced Core */
        case 23:
            return c2_lbr;
            break;
        /* Nehalem */
        case 26: case 30: case 31: case 46:
        /* Westmere */
        case 37: case 44: case 47:
        /* Sandy Bridge */
        case 42: case 45:
        /* Ivy Bridge */
        case 58: case 62:
        /* Haswell */
        case 60: case 63: case 69: case 70:
        /* future */
        case 61: case 78:
            return nh_lbr;
            break;
        /* Atom */
        case 28: case 38: case 39: case 53: case 54:
        /* Silvermont */
        case 55: case 74: case 77: case 90: case 93:
            return at_lbr;
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

static int vmx_msr_read_intercept(unsigned int msr, uint64_t *msr_content)
{
    HVM_DBG_LOG(DBG_LEVEL_MSR, "ecx=%#x", msr);

    switch ( msr )
    {
    case MSR_IA32_SYSENTER_CS:
        __vmread(GUEST_SYSENTER_CS, msr_content);
        break;
    case MSR_IA32_SYSENTER_ESP:
        __vmread(GUEST_SYSENTER_ESP, msr_content);
        break;
    case MSR_IA32_SYSENTER_EIP:
        __vmread(GUEST_SYSENTER_EIP, msr_content);
        break;
    case MSR_IA32_DEBUGCTLMSR:
        __vmread(GUEST_IA32_DEBUGCTL, msr_content);
        break;
    case IA32_FEATURE_CONTROL_MSR:
    case MSR_IA32_VMX_BASIC...MSR_IA32_VMX_TRUE_ENTRY_CTLS:
        if ( !nvmx_msr_read_intercept(msr, msr_content) )
            goto gp_fault;
        break;
    case MSR_IA32_MISC_ENABLE:
        rdmsrl(MSR_IA32_MISC_ENABLE, *msr_content);
        /* Debug Trace Store is not supported. */
        *msr_content |= MSR_IA32_MISC_ENABLE_BTS_UNAVAIL |
                       MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL;
        /* Perhaps vpmu will change some bits. */
        if ( vpmu_do_rdmsr(msr, msr_content) )
            goto done;
        break;
    default:
        if ( vpmu_do_rdmsr(msr, msr_content) )
            break;
        if ( passive_domain_do_rdmsr(msr, msr_content) )
            goto done;
        switch ( long_mode_do_msr_read(msr, msr_content) )
        {
            case HNDL_unhandled:
                break;
            case HNDL_exception_raised:
                return X86EMUL_EXCEPTION;
            case HNDL_done:
                goto done;
        }

        if ( vmx_read_guest_msr(msr, msr_content) == 0 )
            break;

        if ( is_last_branch_msr(msr) )
        {
            *msr_content = 0;
            break;
        }

        if ( rdmsr_viridian_regs(msr, msr_content) ||
             rdmsr_hypervisor_regs(msr, msr_content) )
            break;

        if ( rdmsr_safe(msr, *msr_content) == 0 )
            break;

        goto gp_fault;
    }

done:
    HVM_DBG_LOG(DBG_LEVEL_MSR, "returns: ecx=%#x, msr_value=%#"PRIx64,
                msr, *msr_content);
    return X86EMUL_OKAY;

gp_fault:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
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
    d->arch.hvm_domain.vmx.apic_access_mfn = virt_to_mfn(apic_va);
    set_mmio_p2m_entry(d, paddr_to_pfn(APIC_DEFAULT_PHYS_BASE),
        _mfn(virt_to_mfn(apic_va)));

    return 0;
}

static void vmx_free_vlapic_mapping(struct domain *d)
{
    unsigned long mfn = d->arch.hvm_domain.vmx.apic_access_mfn;
    if ( mfn != 0 )
        free_xenheap_page(mfn_to_virt(mfn));
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
    int virtualize_x2apic_mode;
    struct vlapic *vlapic = vcpu_vlapic(v);
    unsigned int msr;

    virtualize_x2apic_mode = ( (cpu_has_vmx_apic_reg_virt ||
                                cpu_has_vmx_virtual_intr_delivery) &&
                               cpu_has_vmx_virtualize_x2apic_mode );

    if ( !cpu_has_vmx_virtualize_apic_accesses &&
         !virtualize_x2apic_mode )
        return;

    vmx_vmcs_enter(v);
    v->arch.hvm_vmx.secondary_exec_control &=
        ~(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
          SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE);
    if ( !vlapic_hw_disabled(vlapic) &&
         (vlapic_base_address(vlapic) == APIC_DEFAULT_PHYS_BASE) )
    {
        if ( virtualize_x2apic_mode && vlapic_x2apic_mode(vlapic) )
        {
            v->arch.hvm_vmx.secondary_exec_control |=
                SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;
            if ( cpu_has_vmx_apic_reg_virt )
            {
                for ( msr = MSR_IA32_APICBASE_MSR;
                      msr <= MSR_IA32_APICBASE_MSR + 0xff; msr++ )
                    vmx_disable_intercept_for_msr(v, msr, MSR_TYPE_R);

                vmx_enable_intercept_for_msr(v, MSR_IA32_APICPPR_MSR,
                                             MSR_TYPE_R);
                vmx_enable_intercept_for_msr(v, MSR_IA32_APICTMICT_MSR,
                                             MSR_TYPE_R);
                vmx_enable_intercept_for_msr(v, MSR_IA32_APICTMCCT_MSR,
                                             MSR_TYPE_R);
            }
            if ( cpu_has_vmx_virtual_intr_delivery )
            {
                vmx_disable_intercept_for_msr(v, MSR_IA32_APICTPR_MSR,
                                              MSR_TYPE_W);
                vmx_disable_intercept_for_msr(v, MSR_IA32_APICEOI_MSR,
                                              MSR_TYPE_W);
                vmx_disable_intercept_for_msr(v, MSR_IA32_APICSELF_MSR,
                                              MSR_TYPE_W);
            }
        }
        else
            v->arch.hvm_vmx.secondary_exec_control |=
                SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
    }
    if ( !(v->arch.hvm_vmx.secondary_exec_control &
           SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE) )
        for ( msr = MSR_IA32_APICBASE_MSR;
              msr <= MSR_IA32_APICBASE_MSR + 0xff; msr++ )
            vmx_enable_intercept_for_msr(v, msr, MSR_TYPE_R | MSR_TYPE_W);

    vmx_update_secondary_exec_control(v);
    vmx_vmcs_exit(v);
}

static int vmx_msr_write_intercept(unsigned int msr, uint64_t msr_content)
{
    struct vcpu *v = current;

    HVM_DBG_LOG(DBG_LEVEL_MSR, "ecx=%#x, msr_value=%#"PRIx64, msr, msr_content);

    switch ( msr )
    {
    case MSR_IA32_SYSENTER_CS:
        __vmwrite(GUEST_SYSENTER_CS, msr_content);
        break;
    case MSR_IA32_SYSENTER_ESP:
        if ( !is_canonical_address(msr_content) )
            goto gp_fault;
        __vmwrite(GUEST_SYSENTER_ESP, msr_content);
        break;
    case MSR_IA32_SYSENTER_EIP:
        if ( !is_canonical_address(msr_content) )
            goto gp_fault;
        __vmwrite(GUEST_SYSENTER_EIP, msr_content);
        break;
    case MSR_IA32_DEBUGCTLMSR: {
        int i, rc = 0;
        uint64_t supported = IA32_DEBUGCTLMSR_LBR | IA32_DEBUGCTLMSR_BTF;

        if ( boot_cpu_has(X86_FEATURE_RTM) )
            supported |= IA32_DEBUGCTLMSR_RTM;
        if ( msr_content & ~supported )
        {
            /* Perhaps some other bits are supported in vpmu. */
            if ( !vpmu_do_wrmsr(msr, msr_content, supported) )
                break;
        }
        if ( msr_content & IA32_DEBUGCTLMSR_LBR )
        {
            const struct lbr_info *lbr = last_branch_msr_get();
            if ( lbr == NULL )
                break;

            for ( ; (rc == 0) && lbr->count; lbr++ )
                for ( i = 0; (rc == 0) && (i < lbr->count); i++ )
                    if ( (rc = vmx_add_guest_msr(lbr->base + i)) == 0 )
                        vmx_disable_intercept_for_msr(v, lbr->base + i, MSR_TYPE_R | MSR_TYPE_W);
        }

        if ( (rc < 0) ||
             (msr_content && (vmx_add_host_load_msr(msr) < 0)) )
            hvm_inject_hw_exception(TRAP_machine_check, 0);
        else
            __vmwrite(GUEST_IA32_DEBUGCTL, msr_content);

        break;
    }
    case IA32_FEATURE_CONTROL_MSR:
    case MSR_IA32_VMX_BASIC...MSR_IA32_VMX_TRUE_ENTRY_CTLS:
        if ( !nvmx_msr_write_intercept(msr, msr_content) )
            goto gp_fault;
        break;
    default:
        if ( vpmu_do_wrmsr(msr, msr_content, 0) )
            return X86EMUL_OKAY;
        if ( passive_domain_do_wrmsr(msr, msr_content) )
            return X86EMUL_OKAY;

        if ( wrmsr_viridian_regs(msr, msr_content) ) 
            break;

        switch ( long_mode_do_msr_write(msr, msr_content) )
        {
            case HNDL_unhandled:
                if ( (vmx_write_guest_msr(msr, msr_content) != 0) &&
                     !is_last_branch_msr(msr) )
                    switch ( wrmsr_hypervisor_regs(msr, msr_content) )
                    {
                    case -ERESTART:
                        return X86EMUL_RETRY;
                    case 0:
                    case 1:
                        break;
                    default:
                        goto gp_fault;
                    }
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
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

static void vmx_do_extint(struct cpu_user_regs *regs)
{
    unsigned long vector;

    __vmread(VM_EXIT_INTR_INFO, &vector);
    BUG_ON(!(vector & INTR_INFO_VALID_MASK));

    vector &= INTR_INFO_VECTOR_MASK;
    HVMTRACE_1D(INTR, vector);

    regs->entry_vector = vector;
    do_IRQ(regs);
}

static void vmx_wbinvd_intercept(void)
{
    if ( !cache_flush_permitted(current->domain) || iommu_snoop )
        return;

    if ( cpu_has_wbinvd_exiting )
        flush_all(FLUSH_CACHE);
    else
        wbinvd();
}

static void ept_handle_violation(unsigned long qualification, paddr_t gpa)
{
    unsigned long gla, gfn = gpa >> PAGE_SHIFT;
    mfn_t mfn;
    p2m_type_t p2mt;
    int ret;
    struct domain *d = current->domain;

    /*
     * We treat all write violations also as read violations.
     * The reason why this is required is the following warning:
     * "An EPT violation that occurs during as a result of execution of a
     * read-modify-write operation sets bit 1 (data write). Whether it also
     * sets bit 0 (data read) is implementation-specific and, for a given
     * implementation, may differ for different kinds of read-modify-write
     * operations."
     * - Intel(R) 64 and IA-32 Architectures Software Developer's Manual
     *   Volume 3C: System Programming Guide, Part 3
     */
    struct npfec npfec = {
        .read_access = !!(qualification & EPT_READ_VIOLATION) ||
                       !!(qualification & EPT_WRITE_VIOLATION),
        .write_access = !!(qualification & EPT_WRITE_VIOLATION),
        .insn_fetch = !!(qualification & EPT_EXEC_VIOLATION)
    };

    if ( tb_init_done )
    {
        struct {
            uint64_t gpa;
            uint64_t mfn;
            u32 qualification;
            u32 p2mt;
        } _d;

        _d.gpa = gpa;
        _d.qualification = qualification;
        _d.mfn = mfn_x(get_gfn_query_unlocked(d, gfn, &_d.p2mt));

        __trace_var(TRC_HVM_NPF, 0, sizeof(_d), &_d);
    }

    if ( qualification & EPT_GLA_VALID )
    {
        __vmread(GUEST_LINEAR_ADDRESS, &gla);
        npfec.gla_valid = 1;
        if( qualification & EPT_GLA_FAULT )
            npfec.kind = npfec_kind_with_gla;
        else
            npfec.kind = npfec_kind_in_gpt;
    }
    else
        gla = ~0ull;

    ret = hvm_hap_nested_page_fault(gpa, gla, npfec);
    switch ( ret )
    {
    case 0:         // Unhandled L1 EPT violation
        break;
    case 1:         // This violation is handled completly
        /*Current nested EPT maybe flushed by other vcpus, so need
         * to re-set its shadow EPTP pointer.
         */
        if ( nestedhvm_vcpu_in_guestmode(current) &&
                        nestedhvm_paging_mode_hap(current ) )
            __vmwrite(EPT_POINTER, get_shadow_eptp(current));
        return;
    case -1:        // This vioaltion should be injected to L1 VMM
        vcpu_nestedhvm(current).nv_vmexit_pending = 1;
        return;
    }

    /* Everything else is an error. */
    mfn = get_gfn_query_unlocked(d, gfn, &p2mt);
    gdprintk(XENLOG_ERR, "EPT violation %#lx (%c%c%c/%c%c%c), "
             "gpa %#"PRIpaddr", mfn %#lx, type %i.\n", 
             qualification, 
             (qualification & EPT_READ_VIOLATION) ? 'r' : '-',
             (qualification & EPT_WRITE_VIOLATION) ? 'w' : '-',
             (qualification & EPT_EXEC_VIOLATION) ? 'x' : '-',
             (qualification & EPT_EFFECTIVE_READ) ? 'r' : '-',
             (qualification & EPT_EFFECTIVE_WRITE) ? 'w' : '-',
             (qualification & EPT_EFFECTIVE_EXEC) ? 'x' : '-',
             gpa, mfn_x(mfn), p2mt);

    ept_walk_table(d, gfn);

    if ( qualification & EPT_GLA_VALID )
        gdprintk(XENLOG_ERR, " --- GLA %#lx\n", gla);

    domain_crash(d);
}

static void vmx_failed_vmentry(unsigned int exit_reason,
                               struct cpu_user_regs *regs)
{
    unsigned int failed_vmentry_reason = (uint16_t)exit_reason;
    unsigned long exit_qualification;
    struct vcpu *curr = current;

    printk("Failed vm entry (exit reason %#x) ", exit_reason);
    __vmread(EXIT_QUALIFICATION, &exit_qualification);
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
        /* Already handled. */
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

void vmx_enter_realmode(struct cpu_user_regs *regs)
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

    if ( opt_hvm_fep )
    {
        char sig[5]; /* ud2; .ascii "xen" */

        if ( (hvm_fetch_from_guest_virt_nofault(
                  sig, regs->eip, sizeof(sig), 0) == HVMCOPY_okay) &&
             (memcmp(sig, "\xf\xbxen", sizeof(sig)) == 0) )
        {
            regs->eip += sizeof(sig);
            regs->eflags &= ~X86_EFLAGS_RF;
        }
    }

    hvm_emulate_prepare(&ctxt, regs);

    rc = hvm_emulate_one(&ctxt);

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_trap(&ctxt.trap);
        /* fall through */
    default:
        hvm_emulate_writeback(&ctxt);
        break;
    }
}

static int vmx_handle_eoi_write(void)
{
    unsigned long exit_qualification;

    /*
     * 1. Must be a linear access data write.
     * 2. Data write must be to the EOI register.
     */
    __vmread(EXIT_QUALIFICATION, &exit_qualification);
    if ( (((exit_qualification >> 12) & 0xf) == 1) &&
         ((exit_qualification & 0xfff) == APIC_EOI) )
    {
        update_guest_eip(); /* Safe: APIC data write */
        vlapic_EOI_set(vcpu_vlapic(current));
        HVMTRACE_0D(VLAPIC);
        return 1;
    }

    return 0;
}

static void vmx_idtv_reinject(unsigned long idtv_info)
{

    /* Event delivery caused this intercept? Queue for redelivery. */
    if ( unlikely(idtv_info & INTR_INFO_VALID_MASK) )
    {
        if ( hvm_event_needs_reinjection(MASK_EXTR(idtv_info,
                                                   INTR_INFO_INTR_TYPE_MASK),
                                         idtv_info & INTR_INFO_VECTOR_MASK) )
        {
            /* See SDM 3B 25.7.1.1 and .2 for info about masking resvd bits. */
            __vmwrite(VM_ENTRY_INTR_INFO,
                      idtv_info & ~INTR_INFO_RESVD_BITS_MASK);
            if ( idtv_info & INTR_INFO_DELIVER_CODE_MASK )
            {
                unsigned long ec;

                __vmread(IDT_VECTORING_ERROR_CODE, &ec);
                __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, ec);
            }
        }

        /*
         * Clear NMI-blocking interruptibility info if an NMI delivery faulted.
         * Re-delivery will re-set it (see SDM 3B 25.7.1.2).
         */
        if ( cpu_has_vmx_vnmi && ((idtv_info & INTR_INFO_INTR_TYPE_MASK) ==
                                 (X86_EVENTTYPE_NMI<<8)) )
        {
            unsigned long intr_info;

            __vmread(GUEST_INTERRUPTIBILITY_INFO, &intr_info);
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO,
                      intr_info & ~VMX_INTR_SHADOW_NMI);
        }
    }
}

static int vmx_handle_apic_write(void)
{
    unsigned long exit_qualification;

    ASSERT(cpu_has_vmx_apic_reg_virt);
    __vmread(EXIT_QUALIFICATION, &exit_qualification);

    return vlapic_apicv_write(current, exit_qualification & 0xfff);
}

/*
 * When "Virtual Interrupt Delivery" is enabled, this function is used
 * to handle EOI-induced VM exit
 */
void vmx_handle_EOI_induced_exit(struct vlapic *vlapic, int vector)
{
    ASSERT(cpu_has_vmx_virtual_intr_delivery);

    vlapic_handle_EOI_induced_exit(vlapic, vector);
}

void vmx_vmexit_handler(struct cpu_user_regs *regs)
{
    unsigned long exit_qualification, exit_reason, idtv_info, intr_info = 0;
    unsigned int vector = 0;
    struct vcpu *v = current;

    __vmread(GUEST_RIP,    &regs->rip);
    __vmread(GUEST_RSP,    &regs->rsp);
    __vmread(GUEST_RFLAGS, &regs->rflags);

    hvm_invalidate_regs_fields(regs);

    if ( paging_mode_hap(v->domain) )
    {
        __vmread(GUEST_CR3, &v->arch.hvm_vcpu.hw_cr[3]);
        if ( vmx_unrestricted_guest(v) || hvm_paging_enabled(v) )
            v->arch.hvm_vcpu.guest_cr[3] = v->arch.hvm_vcpu.hw_cr[3];
    }

    __vmread(VM_EXIT_REASON, &exit_reason);

    if ( hvm_long_mode_enabled(v) )
        HVMTRACE_ND(VMEXIT64, 0, 1/*cycles*/, 3, exit_reason,
                    (uint32_t)regs->eip, (uint32_t)((uint64_t)regs->eip >> 32),
                    0, 0, 0);
    else
        HVMTRACE_ND(VMEXIT, 0, 1/*cycles*/, 2, exit_reason,
                    (uint32_t)regs->eip, 
                    0, 0, 0, 0);

    perfc_incra(vmexits, exit_reason);

    /* Handle the interrupt we missed before allowing any more in. */
    switch ( (uint16_t)exit_reason )
    {
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        vmx_do_extint(regs);
        break;
    case EXIT_REASON_EXCEPTION_NMI:
        __vmread(VM_EXIT_INTR_INFO, &intr_info);
        BUG_ON(!(intr_info & INTR_INFO_VALID_MASK));
        vector = intr_info & INTR_INFO_VECTOR_MASK;
        if ( vector == TRAP_machine_check )
            do_machine_check(regs);
        if ( vector == TRAP_nmi
             && ((intr_info & INTR_INFO_INTR_TYPE_MASK) ==
                 (X86_EVENTTYPE_NMI << 8)) )
        {
            exception_table[TRAP_nmi](regs);
            enable_nmis();
        }
        break;
    case EXIT_REASON_MCE_DURING_VMENTRY:
        do_machine_check(regs);
        break;
    }

    /* Now enable interrupts so it's safe to take locks. */
    local_irq_enable();

    /* XXX: This looks ugly, but we need a mechanism to ensure
     * any pending vmresume has really happened
     */
    vcpu_nestedhvm(v).nv_vmswitch_in_progress = 0;
    if ( nestedhvm_vcpu_in_guestmode(v) )
    {
        paging_update_nestedmode(v);
        if ( nvmx_n2_vmexit_handler(regs, exit_reason) )
            goto out;
    }

    if ( unlikely(exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) )
        return vmx_failed_vmentry(exit_reason, regs);

    if ( v->arch.hvm_vmx.vmx_realmode )
    {
        /* Put RFLAGS back the way the guest wants it */
        regs->eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IOPL);
        regs->eflags |= (v->arch.hvm_vmx.vm86_saved_eflags & X86_EFLAGS_IOPL);

        /* Unless this exit was for an interrupt, we've hit something
         * vm86 can't handle.  Try again, using the emulator. */
        switch ( exit_reason )
        {
        case EXIT_REASON_EXCEPTION_NMI:
            if ( vector != TRAP_page_fault
                 && vector != TRAP_nmi 
                 && vector != TRAP_machine_check ) 
            {
                perfc_incr(realmode_exits);
                v->arch.hvm_vmx.vmx_emulate = 1;
                HVMTRACE_0D(REALMODE_EMULATE);
                return;
            }
        case EXIT_REASON_EXTERNAL_INTERRUPT:
        case EXIT_REASON_INIT:
        case EXIT_REASON_SIPI:
        case EXIT_REASON_PENDING_VIRT_INTR:
        case EXIT_REASON_PENDING_VIRT_NMI:
        case EXIT_REASON_MCE_DURING_VMENTRY:
        case EXIT_REASON_GETSEC:
        case EXIT_REASON_ACCESS_GDTR_OR_IDTR:
        case EXIT_REASON_ACCESS_LDTR_OR_TR:
        case EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
        case EXIT_REASON_INVEPT:
        case EXIT_REASON_INVVPID:
            break;

        default:
            v->arch.hvm_vmx.vmx_emulate = 1;
            perfc_incr(realmode_exits);
            HVMTRACE_0D(REALMODE_EMULATE);
            return;
        }
    }

    hvm_maybe_deassert_evtchn_irq();

    __vmread(IDT_VECTORING_INFO, &idtv_info);
    if ( exit_reason != EXIT_REASON_TASK_SWITCH )
        vmx_idtv_reinject(idtv_info);

    switch ( exit_reason )
    {
        unsigned long ecode;

    case EXIT_REASON_EXCEPTION_NMI:
    {
        /*
         * We don't set the software-interrupt exiting (INT n).
         * (1) We can get an exception (e.g. #PG) in the guest, or
         * (2) NMI
         */

        /*
         * Re-set the NMI shadow if vmexit caused by a guest IRET fault (see 3B
         * 25.7.1.2, "Resuming Guest Software after Handling an Exception").
         * (NB. If we emulate this IRET for any reason, we should re-clear!)
         */
        if ( unlikely(intr_info & INTR_INFO_NMI_UNBLOCKED_BY_IRET) &&
             !(idtv_info & INTR_INFO_VALID_MASK) &&
             (vector != TRAP_double_fault) )
        {
            unsigned long guest_info;

            __vmread(GUEST_INTERRUPTIBILITY_INFO, &guest_info);
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO,
                      guest_info | VMX_INTR_SHADOW_NMI);
        }

        perfc_incra(cause_vector, vector);

        switch ( vector )
        {
        case TRAP_debug:
            /*
             * Updates DR6 where debugger can peek (See 3B 23.2.1,
             * Table 23-1, "Exit Qualification for Debug Exceptions").
             */
            __vmread(EXIT_QUALIFICATION, &exit_qualification);
            HVMTRACE_1D(TRAP_DEBUG, exit_qualification);
            write_debugreg(6, exit_qualification | 0xffff0ff0);
            if ( !v->domain->debugger_attached || cpu_has_monitor_trap_flag )
                goto exit_and_crash;
            domain_pause_for_debugger();
            break;
        case TRAP_int3: 
        {
            HVMTRACE_1D(TRAP, vector);
            if ( v->domain->debugger_attached )
            {
                update_guest_eip(); /* Safe: INT3 */            
                current->arch.gdbsx_vcpu_event = TRAP_int3;
                domain_pause_for_debugger();
                break;
            }
            else {
                int handled = hvm_memory_event_int3(regs->eip);
                
                if ( handled < 0 ) 
                {
                    struct hvm_trap trap = {
                        .vector = TRAP_int3,
                        .type = X86_EVENTTYPE_SW_EXCEPTION,
                        .error_code = HVM_DELIVER_NO_ERROR_CODE,
                    };
                    unsigned long insn_len;

                    __vmread(VM_EXIT_INSTRUCTION_LEN, &insn_len);
                    trap.insn_len = insn_len;
                    hvm_inject_trap(&trap);
                    break;
                }
                else if ( handled )
                    break;
            }

            goto exit_and_crash;
        }
        case TRAP_no_device:
            HVMTRACE_1D(TRAP, vector);
            vmx_fpu_dirty_intercept();
            break;
        case TRAP_page_fault:
            __vmread(EXIT_QUALIFICATION, &exit_qualification);
            __vmread(VM_EXIT_INTR_ERROR_CODE, &ecode);
            regs->error_code = ecode;

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

            hvm_inject_page_fault(regs->error_code, exit_qualification);
            break;
        case TRAP_nmi:
            if ( (intr_info & INTR_INFO_INTR_TYPE_MASK) !=
                 (X86_EVENTTYPE_NMI << 8) )
                goto exit_and_crash;
            HVMTRACE_0D(NMI);
            /* Already handled above. */
            break;
        case TRAP_machine_check:
            HVMTRACE_0D(MCE);
            /* Already handled above. */
            break;
        case TRAP_invalid_op:
            HVMTRACE_1D(TRAP, vector);
            vmx_vmexit_ud_intercept(regs);
            break;
        default:
            HVMTRACE_1D(TRAP, vector);
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
        vmx_update_cpu_exec_control(v);
        break;
    case EXIT_REASON_PENDING_VIRT_NMI:
        /* Disable the NMI window. */
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
        vmx_update_cpu_exec_control(v);
        break;
    case EXIT_REASON_TASK_SWITCH: {
        static const enum hvm_task_switch_reason reasons[] = {
            TSW_call_or_int, TSW_iret, TSW_jmp, TSW_call_or_int
        };
        unsigned int inst_len, source;

        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        source = (exit_qualification >> 30) & 3;
        /* Vectored event should fill in interrupt information. */
        WARN_ON((source == 3) && !(idtv_info & INTR_INFO_VALID_MASK));
        /*
         * In the following cases there is an instruction to skip over:
         *  - TSW is due to a CALL, IRET or JMP instruction.
         *  - TSW is a vectored event due to a SW exception or SW interrupt.
         */
        inst_len = ((source != 3) ||        /* CALL, IRET, or JMP? */
                    (idtv_info & (1u<<10))) /* IntrType > 3? */
            ? get_instruction_length() /* Safe: SDM 3B 23.2.4 */ : 0;
        if ( (source == 3) && (idtv_info & INTR_INFO_DELIVER_CODE_MASK) )
            __vmread(IDT_VECTORING_ERROR_CODE, &ecode);
        else
             ecode = -1;
        regs->eip += inst_len;
        hvm_task_switch((uint16_t)exit_qualification, reasons[source], ecode);
        break;
    }
    case EXIT_REASON_CPUID:
        is_pvh_vcpu(v) ? pv_cpuid(regs) : vmx_do_cpuid(regs);
        update_guest_eip(); /* Safe: CPUID */
        break;
    case EXIT_REASON_HLT:
        update_guest_eip(); /* Safe: HLT */
        hvm_hlt(regs->eflags);
        break;
    case EXIT_REASON_INVLPG:
        update_guest_eip(); /* Safe: INVLPG */
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        vmx_invlpg_intercept(exit_qualification);
        break;
    case EXIT_REASON_RDTSCP:
        regs->ecx = hvm_msr_tsc_aux(v);
        /* fall through */
    case EXIT_REASON_RDTSC:
        update_guest_eip(); /* Safe: RDTSC, RDTSCP */
        hvm_rdtsc_intercept(regs);
        break;
    case EXIT_REASON_VMCALL:
    {
        int rc;
        HVMTRACE_1D(VMMCALL, regs->eax);
        rc = hvm_do_hypercall(regs);
        if ( rc != HVM_HCALL_preempted )
        {
            update_guest_eip(); /* Safe: VMCALL */
            if ( rc == HVM_HCALL_invalidate )
                send_invalidate_req();
        }
        break;
    }
    case EXIT_REASON_CR_ACCESS:
    {
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        if ( vmx_cr_access(exit_qualification) == X86EMUL_OKAY )
            update_guest_eip(); /* Safe: MOV Cn, LMSW, CLTS */
        break;
    }
    case EXIT_REASON_DR_ACCESS:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        vmx_dr_access(exit_qualification, regs);
        break;
    case EXIT_REASON_MSR_READ:
    {
        uint64_t msr_content;
        if ( hvm_msr_read_intercept(regs->ecx, &msr_content) == X86EMUL_OKAY )
        {
            regs->eax = (uint32_t)msr_content;
            regs->edx = (uint32_t)(msr_content >> 32);
            update_guest_eip(); /* Safe: RDMSR */
        }
        break;
    }
    case EXIT_REASON_MSR_WRITE:
    {
        uint64_t msr_content;
        msr_content = ((uint64_t)regs->edx << 32) | (uint32_t)regs->eax;
        if ( hvm_msr_write_intercept(regs->ecx, msr_content) == X86EMUL_OKAY )
            update_guest_eip(); /* Safe: WRMSR */
        break;
    }

    case EXIT_REASON_VMXOFF:
        if ( nvmx_handle_vmxoff(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_VMXON:
        if ( nvmx_handle_vmxon(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_VMCLEAR:
        if ( nvmx_handle_vmclear(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;
 
    case EXIT_REASON_VMPTRLD:
        if ( nvmx_handle_vmptrld(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_VMPTRST:
        if ( nvmx_handle_vmptrst(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_VMREAD:
        if ( nvmx_handle_vmread(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;
 
    case EXIT_REASON_VMWRITE:
        if ( nvmx_handle_vmwrite(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_VMLAUNCH:
        if ( nvmx_handle_vmlaunch(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_VMRESUME:
        if ( nvmx_handle_vmresume(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_INVEPT:
        if ( nvmx_handle_invept(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_INVVPID:
        if ( nvmx_handle_invvpid(regs) == X86EMUL_OKAY )
            update_guest_eip();
        break;

    case EXIT_REASON_MWAIT_INSTRUCTION:
    case EXIT_REASON_MONITOR_INSTRUCTION:
    case EXIT_REASON_GETSEC:
        /*
         * We should never exit on GETSEC because CR4.SMXE is always 0 when
         * running in guest context, and the CPU checks that before getting
         * as far as vmexit.
         */
        WARN_ON(exit_reason == EXIT_REASON_GETSEC);
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;

    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        break;

    case EXIT_REASON_APIC_ACCESS:
        if ( !vmx_handle_eoi_write() && !handle_mmio() )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case EXIT_REASON_EOI_INDUCED:
    {
        int vector;

        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        vector = exit_qualification & 0xff;

        vmx_handle_EOI_induced_exit(vcpu_vlapic(current), vector);
        break;
    }

    case EXIT_REASON_IO_INSTRUCTION:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        if ( exit_qualification & 0x10 )
        {
            /* INS, OUTS */
            if ( unlikely(is_pvh_vcpu(v)) /* PVH fixme */ ||
                 !handle_mmio() )
                hvm_inject_hw_exception(TRAP_gp_fault, 0);
        }
        else
        {
            /* IN, OUT */
            uint16_t port = (exit_qualification >> 16) & 0xFFFF;
            int bytes = (exit_qualification & 0x07) + 1;
            int dir = (exit_qualification & 0x08) ? IOREQ_READ : IOREQ_WRITE;
            if ( handle_pio(port, bytes, dir) )
                update_guest_eip(); /* Safe: IN, OUT */
        }
        break;

    case EXIT_REASON_INVD:
    case EXIT_REASON_WBINVD:
    {
        update_guest_eip(); /* Safe: INVD, WBINVD */
        vmx_wbinvd_intercept();
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        paddr_t gpa;

        __vmread(GUEST_PHYSICAL_ADDRESS, &gpa);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        ept_handle_violation(exit_qualification, gpa);
        break;
    }

    case EXIT_REASON_EPT_MISCONFIG:
    {
        paddr_t gpa;

        __vmread(GUEST_PHYSICAL_ADDRESS, &gpa);
        if ( !ept_handle_misconfig(gpa) )
            goto exit_and_crash;
        break;
    }

    case EXIT_REASON_MONITOR_TRAP_FLAG:
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_MONITOR_TRAP_FLAG;
        vmx_update_cpu_exec_control(v);
        if ( v->arch.hvm_vcpu.single_step ) {
          hvm_memory_event_single_step(regs->eip);
          if ( v->domain->debugger_attached )
              domain_pause_for_debugger();
        }

        break;

    case EXIT_REASON_PAUSE_INSTRUCTION:
        perfc_incr(pauseloop_exits);
        do_sched_op_compat(SCHEDOP_yield, 0);
        break;

    case EXIT_REASON_XSETBV:
        if ( hvm_handle_xsetbv(regs->ecx,
                               (regs->rdx << 32) | regs->_eax) == 0 )
            update_guest_eip(); /* Safe: XSETBV */
        break;

    case EXIT_REASON_APIC_WRITE:
        vmx_handle_apic_write();
        break;

    case EXIT_REASON_ACCESS_GDTR_OR_IDTR:
    case EXIT_REASON_ACCESS_LDTR_OR_TR:
    case EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
    case EXIT_REASON_INVPCID:
    /* fall through */
    default:
    exit_and_crash:
        {
            struct segment_register ss;

            gdprintk(XENLOG_WARNING, "Bad vmexit (reason %#lx)\n",
                     exit_reason);

            vmx_get_segment_register(v, x86_seg_ss, &ss);
            if ( ss.attr.fields.dpl )
                hvm_inject_hw_exception(TRAP_invalid_op,
                                        HVM_DELIVER_NO_ERROR_CODE);
            else
                domain_crash(v->domain);
        }
        break;
    }

out:
    if ( nestedhvm_vcpu_in_guestmode(v) )
        nvmx_idtv_handling();
}

void vmx_vmenter_helper(const struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    u32 new_asid, old_asid;
    struct hvm_vcpu_asid *p_asid;
    bool_t need_flush;

    if ( !cpu_has_vmx_vpid )
        goto out;
    if ( nestedhvm_vcpu_in_guestmode(curr) )
        p_asid = &vcpu_nestedhvm(curr).nv_n2asid;
    else
        p_asid = &curr->arch.hvm_vcpu.n1asid;

    old_asid = p_asid->asid;
    need_flush = hvm_asid_handle_vmenter(p_asid);
    new_asid = p_asid->asid;

    if ( unlikely(new_asid != old_asid) )
    {
        __vmwrite(VIRTUAL_PROCESSOR_ID, new_asid);
        if ( !old_asid && new_asid )
        {
            /* VPID was disabled: now enabled. */
            curr->arch.hvm_vmx.secondary_exec_control |=
                SECONDARY_EXEC_ENABLE_VPID;
            vmx_update_secondary_exec_control(curr);
        }
        else if ( old_asid && !new_asid )
        {
            /* VPID was enabled: now disabled. */
            curr->arch.hvm_vmx.secondary_exec_control &=
                ~SECONDARY_EXEC_ENABLE_VPID;
            vmx_update_secondary_exec_control(curr);
        }
    }

    if ( unlikely(need_flush) )
        vpid_sync_all();

 out:
    HVMTRACE_ND(VMENTRY, 0, 1/*cycles*/, 0, 0, 0, 0, 0, 0, 0);

    __vmwrite(GUEST_RIP,    regs->rip);
    __vmwrite(GUEST_RSP,    regs->rsp);
    __vmwrite(GUEST_RFLAGS, regs->rflags | X86_EFLAGS_MBS);
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
