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
 *
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

char *vmx_msr_bitmap;

static void vmx_ctxt_switch_from(struct vcpu *v);
static void vmx_ctxt_switch_to(struct vcpu *v);

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
    MSR_LSTAR, MSR_STAR, MSR_CSTAR,
    MSR_SYSCALL_MASK, MSR_EFER,
};

static void vmx_save_host_msrs(void)
{
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);
    int i;

    for ( i = 0; i < VMX_MSR_COUNT; i++ )
        rdmsrl(msr_index[i], host_msr_state->msrs[i]);
}

#define WRITE_MSR(address)                                                  \
        guest_msr_state->msrs[VMX_INDEX_MSR_ ## address] = msr_content;     \
        if ( !test_bit(VMX_INDEX_MSR_ ## address, &guest_msr_state->flags) )\
            set_bit(VMX_INDEX_MSR_ ## address, &guest_msr_state->flags);    \
        wrmsrl(MSR_ ## address, msr_content);                               \
        set_bit(VMX_INDEX_MSR_ ## address, &host_msr_state->flags);         \
        break

static inline int long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    struct vcpu *v = current;
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;

    switch ( (u32)regs->ecx ) {
    case MSR_EFER:
        HVM_DBG_LOG(DBG_LEVEL_2, "EFER msr_content 0x%"PRIx64, msr_content);
        msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_EFER];
        break;

    case MSR_FS_BASE:
        msr_content = __vmread(GUEST_FS_BASE);
        goto check_long_mode;

    case MSR_GS_BASE:
        msr_content = __vmread(GUEST_GS_BASE);
        goto check_long_mode;

    case MSR_SHADOW_GS_BASE:
        msr_content = guest_msr_state->shadow_gs;
    check_long_mode:
        if ( !(vmx_long_mode_enabled(v)) )
        {
            vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            return 0;
        }
        break;

    case MSR_STAR:
        msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_STAR];
        break;

    case MSR_LSTAR:
        msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_LSTAR];
        break;

    case MSR_CSTAR:
        msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_CSTAR];
        break;

    case MSR_SYSCALL_MASK:
        msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK];
        break;

    default:
        return 0;
    }

    HVM_DBG_LOG(DBG_LEVEL_2, "msr_content: 0x%"PRIx64, msr_content);

    regs->eax = (u32)(msr_content >>  0);
    regs->edx = (u32)(msr_content >> 32);

    return 1;
}

static inline int long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content = (u32)regs->eax | ((u64)regs->edx << 32);
    u32 ecx = regs->ecx;
    struct vcpu *v = current;
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);

    HVM_DBG_LOG(DBG_LEVEL_1, "msr 0x%x msr_content 0x%"PRIx64"\n",
                ecx, msr_content);

    switch ( ecx )
    {
    case MSR_EFER:
        /* offending reserved bit will cause #GP */
        if ( msr_content & ~(EFER_LME | EFER_LMA | EFER_NX | EFER_SCE) )
        {
            gdprintk(XENLOG_WARNING, "Trying to set reserved bit in "
                     "EFER: %"PRIx64"\n", msr_content);
            goto gp_fault;
        }

        if ( (msr_content & EFER_LME)
             &&  !(guest_msr_state->msrs[VMX_INDEX_MSR_EFER] & EFER_LME) )
        {
            if ( unlikely(vmx_paging_enabled(v)) )
            {
                gdprintk(XENLOG_WARNING,
                         "Trying to set EFER.LME with paging enabled\n");
                goto gp_fault;
            }
        }
        else if ( !(msr_content & EFER_LME)
                  && (guest_msr_state->msrs[VMX_INDEX_MSR_EFER] & EFER_LME) )
        {
            if ( unlikely(vmx_paging_enabled(v)) )
            {
                gdprintk(XENLOG_WARNING,
                         "Trying to clear EFER.LME with paging enabled\n");
                goto gp_fault;
            }
        }

        guest_msr_state->msrs[VMX_INDEX_MSR_EFER] = msr_content;
        break;

    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        if ( !vmx_long_mode_enabled(v) )
            goto gp_fault;

        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;

        if ( ecx == MSR_FS_BASE )
            __vmwrite(GUEST_FS_BASE, msr_content);
        else if ( ecx == MSR_GS_BASE )
            __vmwrite(GUEST_GS_BASE, msr_content);
        else
        {
            v->arch.hvm_vmx.msr_state.shadow_gs = msr_content;
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
        WRITE_MSR(CSTAR);

    case MSR_SYSCALL_MASK:
        WRITE_MSR(SYSCALL_MASK);

    default:
        return 0;
    }

    return 1;

 uncanonical_address:
    HVM_DBG_LOG(DBG_LEVEL_1, "Not cano address of msr write %x\n", ecx);
 gp_fault:
    vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
    return 0;
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
    /* MSR_SHADOW_GS_BASE may have been changed by swapgs instruction. */
    rdmsrl(MSR_SHADOW_GS_BASE, v->arch.hvm_vmx.msr_state.shadow_gs);
}

static void vmx_restore_guest_msrs(struct vcpu *v)
{
    struct vmx_msr_state *guest_msr_state, *host_msr_state;
    unsigned long guest_flags;
    int i;

    guest_msr_state = &v->arch.hvm_vmx.msr_state;
    host_msr_state = &this_cpu(host_msr_state);

    wrmsrl(MSR_SHADOW_GS_BASE, guest_msr_state->shadow_gs);

    guest_flags = guest_msr_state->flags;
    if ( !guest_flags )
        return;

    while ( guest_flags ) {
        i = find_first_set_bit(guest_flags);

        HVM_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's index %d msr %x with value %lx",
                    i, msr_index[i], guest_msr_state->msrs[i]);
        set_bit(i, &host_msr_state->flags);
        wrmsrl(msr_index[i], guest_msr_state->msrs[i]);
        clear_bit(i, &guest_flags);
    }
}

#else  /* __i386__ */

#define vmx_save_host_msrs()        ((void)0)
#define vmx_restore_host_msrs()     ((void)0)
#define vmx_save_guest_msrs(v)      ((void)0)
#define vmx_restore_guest_msrs(v)   ((void)0)

static inline int long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    return 0;
}

static inline int long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    return 0;
}

#endif /* __i386__ */

#define loaddebug(_v,_reg)  \
    __asm__ __volatile__ ("mov %0,%%db" #_reg : : "r" ((_v)->debugreg[_reg]))
#define savedebug(_v,_reg)  \
    __asm__ __volatile__ ("mov %%db" #_reg ",%0" : : "r" ((_v)->debugreg[_reg]))

static inline void vmx_save_dr(struct vcpu *v)
{
    if ( !v->arch.hvm_vcpu.flag_dr_dirty )
        return;

    /* Clear the DR dirty flag and re-enable intercepts for DR accesses. */
    v->arch.hvm_vcpu.flag_dr_dirty = 0;
    v->arch.hvm_vcpu.u.vmx.exec_control |= CPU_BASED_MOV_DR_EXITING;
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vcpu.u.vmx.exec_control);

    savedebug(&v->arch.guest_context, 0);
    savedebug(&v->arch.guest_context, 1);
    savedebug(&v->arch.guest_context, 2);
    savedebug(&v->arch.guest_context, 3);
    savedebug(&v->arch.guest_context, 6);
    v->arch.guest_context.debugreg[7] = __vmread(GUEST_DR7);
}

static inline void __restore_debug_registers(struct vcpu *v)
{
    loaddebug(&v->arch.guest_context, 0);
    loaddebug(&v->arch.guest_context, 1);
    loaddebug(&v->arch.guest_context, 2);
    loaddebug(&v->arch.guest_context, 3);
    /* No 4 and 5 */
    loaddebug(&v->arch.guest_context, 6);
    /* DR7 is loaded from the VMCS. */
}

int vmx_vmcs_save(struct vcpu *v, struct hvm_hw_cpu *c)
{    
    c->eip = __vmread(GUEST_RIP);
    c->esp = __vmread(GUEST_RSP);
    c->eflags = __vmread(GUEST_RFLAGS);

    c->cr0 = v->arch.hvm_vmx.cpu_shadow_cr0;
    c->cr3 = v->arch.hvm_vmx.cpu_cr3;
    c->cr4 = v->arch.hvm_vmx.cpu_shadow_cr4;

#ifdef HVM_DEBUG_SUSPEND
    printk("vmx_vmcs_save: cr3=0x%"PRIx64", cr0=0x%"PRIx64", cr4=0x%"PRIx64".\n",
            c->cr3,
            c->cr0,
            c->cr4);
#endif

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

    return 1;
}

int vmx_vmcs_restore(struct vcpu *v, struct hvm_hw_cpu *c)
{
    unsigned long mfn, old_base_mfn;

    vmx_vmcs_enter(v);

    __vmwrite(GUEST_RIP, c->eip);
    __vmwrite(GUEST_RSP, c->esp);
    __vmwrite(GUEST_RFLAGS, c->eflags);

    v->arch.hvm_vmx.cpu_shadow_cr0 = c->cr0;
    __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr0);

#ifdef HVM_DEBUG_SUSPEND
    printk("vmx_vmcs_restore: cr3=0x%"PRIx64", cr0=0x%"PRIx64", cr4=0x%"PRIx64".\n",
            c->cr3,
            c->cr0,
            c->cr4);
#endif

    if (!vmx_paging_enabled(v)) {
        printk("vmx_vmcs_restore: paging not enabled.");
        goto skip_cr3;
    }

    if (c->cr3 == v->arch.hvm_vmx.cpu_cr3) {
        /*
         * This is simple TLB flush, implying the guest has
         * removed some translation or changed page attributes.
         * We simply invalidate the shadow.
         */
        mfn = gmfn_to_mfn(v->domain, c->cr3 >> PAGE_SHIFT);
        if (mfn != pagetable_get_pfn(v->arch.guest_table)) {
            goto bad_cr3;
        }
    } else {
        /*
         * If different, make a shadow. Check if the PDBR is valid
         * first.
         */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 c->cr3 = %"PRIx64"", c->cr3);
        /* current!=vcpu as not called by arch_vmx_do_launch */
        mfn = gmfn_to_mfn(v->domain, c->cr3 >> PAGE_SHIFT);
        if( !mfn_valid(mfn) || !get_page(mfn_to_page(mfn), v->domain)) {
            goto bad_cr3;
        }
        old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
        v->arch.guest_table = pagetable_from_pfn(mfn);
        if (old_base_mfn)
             put_page(mfn_to_page(old_base_mfn));
        v->arch.hvm_vmx.cpu_cr3 = c->cr3;
    }

 skip_cr3:
#if defined(__x86_64__)
    if (vmx_long_mode_enabled(v)) {
        unsigned long vm_entry_value;
        vm_entry_value = __vmread(VM_ENTRY_CONTROLS);
        vm_entry_value |= VM_ENTRY_IA32E_MODE;
        __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
    }
#endif

    __vmwrite(GUEST_CR4, (c->cr4 | VMX_CR4_HOST_MASK));
    v->arch.hvm_vmx.cpu_shadow_cr4 = c->cr4;
    __vmwrite(CR4_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr4);

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

    vmx_vmcs_exit(v);

    paging_update_paging_modes(v);
    return 0;

 bad_cr3:
    gdprintk(XENLOG_ERR, "Invalid CR3 value=0x%"PRIx64"", c->cr3);
    vmx_vmcs_exit(v);
    return -EINVAL;
}

#ifdef HVM_DEBUG_SUSPEND
static void dump_msr_state(struct vmx_msr_state *m)
{
    int i = 0;
    printk("**** msr state ****\n");
    printk("shadow_gs=0x%lx, flags=0x%lx, msr_items:", m->shadow_gs, m->flags);
    for (i = 0; i < VMX_MSR_COUNT; i++)
        printk("0x%lx,", m->msrs[i]);
    printk("\n");
}
#else
static void dump_msr_state(struct vmx_msr_state *m)
{
}
#endif
        
void vmx_save_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;
    unsigned long guest_flags = guest_state->flags;

    data->shadow_gs = guest_state->shadow_gs;

    /* save msrs */
    data->flags = guest_flags;
    data->msr_lstar        = guest_state->msrs[VMX_INDEX_MSR_LSTAR];
    data->msr_star         = guest_state->msrs[VMX_INDEX_MSR_STAR];
    data->msr_cstar        = guest_state->msrs[VMX_INDEX_MSR_CSTAR];
    data->msr_syscall_mask = guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK];
    data->msr_efer         = guest_state->msrs[VMX_INDEX_MSR_EFER];

    data->tsc = hvm_get_guest_time(v);
    
    dump_msr_state(guest_state);
}

void vmx_load_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;

    /* restore msrs */
    guest_state->flags = data->flags;
    guest_state->msrs[VMX_INDEX_MSR_LSTAR]        = data->msr_lstar;
    guest_state->msrs[VMX_INDEX_MSR_STAR]         = data->msr_star;
    guest_state->msrs[VMX_INDEX_MSR_CSTAR]        = data->msr_cstar;
    guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK] = data->msr_syscall_mask;
    guest_state->msrs[VMX_INDEX_MSR_EFER]         = data->msr_efer;

    guest_state->shadow_gs = data->shadow_gs;

    v->arch.hvm_vmx.vmxassist_enabled = !(data->cr0 & X86_CR0_PE);

    hvm_set_guest_time(v, data->tsc);

    dump_msr_state(guest_state);
}


void vmx_save_vmcs_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    vmx_save_cpu_state(v, ctxt);
    vmx_vmcs_enter(v);
    vmx_vmcs_save(v, ctxt);
    vmx_vmcs_exit(v);
}

int vmx_load_vmcs_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    vmx_load_cpu_state(v, ctxt);
    if (vmx_vmcs_restore(v, ctxt)) {
        printk("vmx_vmcs restore failed!\n");
        domain_crash(v->domain);
        return -EINVAL;
    }

    return 0;
}

/*
 * DR7 is saved and restored on every vmexit.  Other debug registers only
 * need to be restored if their value is going to affect execution -- i.e.,
 * if one of the breakpoints is enabled.  So mask out all bits that don't
 * enable some breakpoint functionality.
 */
#define DR7_ACTIVE_MASK 0xff

static inline void vmx_restore_dr(struct vcpu *v)
{
    /* NB. __vmread() is not usable here, so we cannot read from the VMCS. */
    if ( unlikely(v->arch.guest_context.debugreg[7] & DR7_ACTIVE_MASK) )
        __restore_debug_registers(v);
}

static void vmx_ctxt_switch_from(struct vcpu *v)
{
    vmx_save_guest_msrs(v);
    vmx_restore_host_msrs();
    vmx_save_dr(v);
}

static void vmx_ctxt_switch_to(struct vcpu *v)
{
    vmx_restore_guest_msrs(v);
    vmx_restore_dr(v);
}

static void stop_vmx(void)
{
    if ( !(read_cr4() & X86_CR4_VMXE) )
        return;

    __vmxoff();
    clear_in_cr4(X86_CR4_VMXE);
}

static void vmx_store_cpu_guest_regs(
    struct vcpu *v, struct cpu_user_regs *regs, unsigned long *crs)
{
    vmx_vmcs_enter(v);

    if ( regs != NULL )
    {
        regs->eflags = __vmread(GUEST_RFLAGS);
        regs->ss = __vmread(GUEST_SS_SELECTOR);
        regs->cs = __vmread(GUEST_CS_SELECTOR);
        regs->eip = __vmread(GUEST_RIP);
        regs->esp = __vmread(GUEST_RSP);
    }

    if ( crs != NULL )
    {
        crs[0] = v->arch.hvm_vmx.cpu_shadow_cr0;
        crs[2] = v->arch.hvm_vmx.cpu_cr2;
        crs[3] = v->arch.hvm_vmx.cpu_cr3;
        crs[4] = v->arch.hvm_vmx.cpu_shadow_cr4;
    }

    vmx_vmcs_exit(v);
}

static void vmx_load_cpu_guest_regs(struct vcpu *v, struct cpu_user_regs *regs)
{
    unsigned long base;

    vmx_vmcs_enter(v);

    __vmwrite(GUEST_SS_SELECTOR, regs->ss);
    __vmwrite(GUEST_RSP, regs->esp);

    /* NB. Bit 1 of RFLAGS must be set for VMENTRY to succeed. */
    __vmwrite(GUEST_RFLAGS, regs->eflags | 2UL);

    if ( regs->eflags & EF_VM )
    {
        /*
         * The VMX spec (section 4.3.1.2, Checks on Guest Segment
         * Registers) says that virtual-8086 mode guests' segment
         * base-address fields in the VMCS must be equal to their
         * corresponding segment selector field shifted right by
         * four bits upon vmentry.
         */
        base = __vmread(GUEST_CS_BASE);
        if ( (regs->cs << 4) != base )
            __vmwrite(GUEST_CS_BASE, regs->cs << 4);
        base = __vmread(GUEST_SS_BASE);
        if ( (regs->ss << 4) != base )
            __vmwrite(GUEST_SS_BASE, regs->ss << 4);
    }

    __vmwrite(GUEST_CS_SELECTOR, regs->cs);
    __vmwrite(GUEST_RIP, regs->eip);

    vmx_vmcs_exit(v);
}

static unsigned long vmx_get_ctrl_reg(struct vcpu *v, unsigned int num)
{
    switch ( num )
    {
    case 0:
        return v->arch.hvm_vmx.cpu_cr0;
    case 2:
        return v->arch.hvm_vmx.cpu_cr2;
    case 3:
        return v->arch.hvm_vmx.cpu_cr3;
    case 4:
        return v->arch.hvm_vmx.cpu_shadow_cr4;
    default:
        BUG();
    }
    return 0;                   /* dummy */
}

static unsigned long vmx_get_segment_base(struct vcpu *v, enum x86_segment seg)
{
    unsigned long base = 0;
    int long_mode = 0;

    ASSERT(v == current);

#ifdef __x86_64__
    if ( vmx_long_mode_enabled(v) && (__vmread(GUEST_CS_AR_BYTES) & (1u<<13)) )
        long_mode = 1;
#endif

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
    u16 attr = 0;

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
    if ( !(v->arch.hvm_vmx.cpu_shadow_cr0 & X86_CR0_TS) )
    {
        v->arch.hvm_vmx.cpu_cr0 |= X86_CR0_TS;
        __vmwrite(GUEST_CR0, v->arch.hvm_vmx.cpu_cr0);
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

static void vmx_init_ap_context(
    struct vcpu_guest_context *ctxt, int vcpuid, int trampoline_vector)
{
    memset(ctxt, 0, sizeof(*ctxt));
    ctxt->user_regs.eip = VMXASSIST_BASE;
    ctxt->user_regs.edx = vcpuid;
    ctxt->user_regs.ebx = trampoline_vector;
}

void do_nmi(struct cpu_user_regs *);

static void vmx_init_hypercall_page(struct domain *d, void *hypercall_page)
{
    char *p;
    int i;

    memset(hypercall_page, 0, PAGE_SIZE);

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

static int vmx_realmode(struct vcpu *v)
{
    unsigned long rflags;

    ASSERT(v == current);

    rflags = __vmread(GUEST_RFLAGS);
    return rflags & X86_EFLAGS_VM;
}

static int vmx_guest_x86_mode(struct vcpu *v)
{
    unsigned long cs_ar_bytes;

    ASSERT(v == current);

    cs_ar_bytes = __vmread(GUEST_CS_AR_BYTES);

    if ( vmx_long_mode_enabled(v) && (cs_ar_bytes & (1u<<13)) )
        return 8;

    if ( vmx_realmode(v) )
        return 2;

    return ((cs_ar_bytes & (1u<<14)) ? 4 : 2);
}

static int vmx_pae_enabled(struct vcpu *v)
{
    unsigned long cr4 = v->arch.hvm_vmx.cpu_shadow_cr4;
    return (vmx_paging_enabled(v) && (cr4 & X86_CR4_PAE));
}

static int vmx_interrupts_enabled(struct vcpu *v) 
{
    unsigned long eflags = __vmread(GUEST_RFLAGS); 
    return !irq_masked(eflags); 
}


static void vmx_update_host_cr3(struct vcpu *v)
{
    ASSERT( (v == current) || !vcpu_runnable(v) );
    vmx_vmcs_enter(v);
    __vmwrite(HOST_CR3, v->arch.cr3);
    vmx_vmcs_exit(v);
}

static void vmx_update_guest_cr3(struct vcpu *v)
{
    ASSERT( (v == current) || !vcpu_runnable(v) );
    vmx_vmcs_enter(v);
    __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr3);
    vmx_vmcs_exit(v);
}


static void vmx_inject_exception(
    unsigned int trapnr, int errcode, unsigned long cr2)
{
    struct vcpu *v = current;
    vmx_inject_hw_exception(v, trapnr, errcode);
    if ( trapnr == TRAP_page_fault )
        v->arch.hvm_vmx.cpu_cr2 = cr2;
}

static void vmx_update_vtpr(struct vcpu *v, unsigned long value)
{
    /* VMX doesn't have a V_TPR field */
}

static int vmx_event_injection_faulted(struct vcpu *v)
{
    unsigned int idtv_info_field;

    ASSERT(v == current);

    idtv_info_field = __vmread(IDT_VECTORING_INFO_FIELD);
    return (idtv_info_field & INTR_INFO_VALID_MASK);
}

static void disable_intercept_for_msr(u32 msr)
{
    /*
     * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
     * have the write-low and read-high bitmap offsets the wrong way round.
     * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
     */
    if ( msr <= 0x1fff )
    {
        __clear_bit(msr, vmx_msr_bitmap + 0x000); /* read-low */
        __clear_bit(msr, vmx_msr_bitmap + 0x800); /* write-low */
    }
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
    {
        msr &= 0x1fff;
        __clear_bit(msr, vmx_msr_bitmap + 0x400); /* read-high */
        __clear_bit(msr, vmx_msr_bitmap + 0xc00); /* write-high */
    }
}

static struct hvm_function_table vmx_function_table = {
    .name                 = "VMX",
    .disable              = stop_vmx,
    .vcpu_initialise      = vmx_vcpu_initialise,
    .vcpu_destroy         = vmx_vcpu_destroy,
    .store_cpu_guest_regs = vmx_store_cpu_guest_regs,
    .load_cpu_guest_regs  = vmx_load_cpu_guest_regs,
    .save_cpu_ctxt        = vmx_save_vmcs_ctxt,
    .load_cpu_ctxt        = vmx_load_vmcs_ctxt,
    .paging_enabled       = vmx_paging_enabled,
    .long_mode_enabled    = vmx_long_mode_enabled,
    .pae_enabled          = vmx_pae_enabled,
    .interrupts_enabled   = vmx_interrupts_enabled,
    .guest_x86_mode       = vmx_guest_x86_mode,
    .get_guest_ctrl_reg   = vmx_get_ctrl_reg,
    .get_segment_base     = vmx_get_segment_base,
    .get_segment_register = vmx_get_segment_register,
    .update_host_cr3      = vmx_update_host_cr3,
    .update_guest_cr3     = vmx_update_guest_cr3,
    .update_vtpr          = vmx_update_vtpr,
    .stts                 = vmx_stts,
    .set_tsc_offset       = vmx_set_tsc_offset,
    .inject_exception     = vmx_inject_exception,
    .init_ap_context      = vmx_init_ap_context,
    .init_hypercall_page  = vmx_init_hypercall_page,
    .event_injection_faulted = vmx_event_injection_faulted
};

int start_vmx(void)
{
    u32 eax, edx;
    struct vmcs_struct *vmcs;

    /*
     * Xen does not fill x86_capability words except 0.
     */
    boot_cpu_data.x86_capability[4] = cpuid_ecx(1);

    if ( !test_bit(X86_FEATURE_VMXE, &boot_cpu_data.x86_capability) )
        return 0;

    rdmsr(IA32_FEATURE_CONTROL_MSR, eax, edx);

    if ( eax & IA32_FEATURE_CONTROL_MSR_LOCK )
    {
        if ( (eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON) == 0x0 )
        {
            printk("VMX disabled by Feature Control MSR.\n");
            return 0;
        }
    }
    else
    {
        wrmsr(IA32_FEATURE_CONTROL_MSR,
              IA32_FEATURE_CONTROL_MSR_LOCK |
              IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON, 0);
    }

    set_in_cr4(X86_CR4_VMXE);

    vmx_init_vmcs_config();

    if ( smp_processor_id() == 0 )
        setup_vmcs_dump();

    if ( (vmcs = vmx_alloc_host_vmcs()) == NULL )
    {
        clear_in_cr4(X86_CR4_VMXE);
        printk("Failed to allocate host VMCS\n");
        return 0;
    }

    if ( __vmxon(virt_to_maddr(vmcs)) )
    {
        clear_in_cr4(X86_CR4_VMXE);
        printk("VMXON failed\n");
        vmx_free_host_vmcs(vmcs);
        return 0;
    }

    vmx_save_host_msrs();

    if ( smp_processor_id() != 0 )
        return 1;

    hvm_enable(&vmx_function_table);

    if ( cpu_has_vmx_msr_bitmap )
    {
        printk("VMX: MSR intercept bitmap enabled\n");
        vmx_msr_bitmap = alloc_xenheap_page();
        BUG_ON(vmx_msr_bitmap == NULL);
        memset(vmx_msr_bitmap, ~0, PAGE_SIZE);
        disable_intercept_for_msr(MSR_FS_BASE);
        disable_intercept_for_msr(MSR_GS_BASE);
    }

    return 1;
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

static void inline __update_guest_eip(unsigned long inst_len)
{
    unsigned long current_eip;

    current_eip = __vmread(GUEST_RIP);
    __vmwrite(GUEST_RIP, current_eip + inst_len);
    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
}

static void vmx_do_no_device_fault(void)
{
    struct vcpu *v = current;

    setup_fpu(current);
    __vm_clear_bit(EXCEPTION_BITMAP, TRAP_no_device);

    /* Disable TS in guest CR0 unless the guest wants the exception too. */
    if ( !(v->arch.hvm_vmx.cpu_shadow_cr0 & X86_CR0_TS) )
    {
        v->arch.hvm_vmx.cpu_cr0 &= ~X86_CR0_TS;
        __vmwrite(GUEST_CR0, v->arch.hvm_vmx.cpu_cr0);
    }
}

#define bitmaskof(idx)  (1U << ((idx) & 31))
static void vmx_do_cpuid(struct cpu_user_regs *regs)
{
    unsigned int input = (unsigned int)regs->eax;
    unsigned int count = (unsigned int)regs->ecx;
    unsigned int eax, ebx, ecx, edx;

    if ( input == 0x00000004 )
    {
        cpuid_count(input, count, &eax, &ebx, &ecx, &edx);
        eax &= NUM_CORES_RESET_MASK;
    }
    else if ( input == 0x40000003 )
    {
        /*
         * NB. Unsupported interface for private use of VMXASSIST only.
         * Note that this leaf lives at <max-hypervisor-leaf> + 1.
         */
        u64 value = ((u64)regs->edx << 32) | (u32)regs->ecx;
        unsigned long mfn = get_mfn_from_gpfn(value >> PAGE_SHIFT);
        struct vcpu *v = current;
        char *p;

        gdprintk(XENLOG_INFO, "Input address is 0x%"PRIx64".\n", value);

        /* 8-byte aligned valid pseudophys address from vmxassist, please. */
        if ( (value & 7) || (mfn == INVALID_MFN) ||
             !v->arch.hvm_vmx.vmxassist_enabled )
        {
            domain_crash(v->domain);
            return;
        }

        p = map_domain_page(mfn);
        value = *((uint64_t *)(p + (value & (PAGE_SIZE - 1))));
        unmap_domain_page(p);

        gdprintk(XENLOG_INFO, "Output value is 0x%"PRIx64".\n", value);
        ecx = (u32)value;
        edx = (u32)(value >> 32);
    } else {
        hvm_cpuid(input, &eax, &ebx, &ecx, &edx);

        if ( input == 0x00000001 )
        {
            /* Mask off reserved bits. */
            ecx &= ~VMX_VCPU_CPUID_L1_ECX_RESERVED;

            ebx &= NUM_THREADS_RESET_MASK;

            /* Unsupportable for virtualised CPUs. */
            ecx &= ~(bitmaskof(X86_FEATURE_VMXE) |
                     bitmaskof(X86_FEATURE_EST)  |
                     bitmaskof(X86_FEATURE_TM2)  |
                     bitmaskof(X86_FEATURE_CID));

            edx &= ~(bitmaskof(X86_FEATURE_HT)   |
                     bitmaskof(X86_FEATURE_ACPI) |
                     bitmaskof(X86_FEATURE_ACC));
        }

        if ( input == 0x00000006 || input == 0x00000009 || input == 0x0000000A )
            eax = ebx = ecx = edx = 0x0;
    }

    regs->eax = (unsigned long)eax;
    regs->ebx = (unsigned long)ebx;
    regs->ecx = (unsigned long)ecx;
    regs->edx = (unsigned long)edx;

    HVMTRACE_3D(CPUID, current, input,
                ((uint64_t)eax << 32) | ebx, ((uint64_t)ecx << 32) | edx);
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

    v->arch.hvm_vcpu.flag_dr_dirty = 1;

    /* We could probably be smarter about this */
    __restore_debug_registers(v);

    /* Allow guest direct access to DR registers */
    v->arch.hvm_vcpu.u.vmx.exec_control &= ~CPU_BASED_MOV_DR_EXITING;
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
              v->arch.hvm_vcpu.u.vmx.exec_control);
}

/*
 * Invalidate the TLB for va. Invalidate the shadow page corresponding
 * the address va.
 */
static void vmx_do_invlpg(unsigned long va)
{
    unsigned long eip;
    struct vcpu *v = current;

    HVMTRACE_2D(INVLPG, v, /*invlpga=*/ 0, va);

    eip = __vmread(GUEST_RIP);

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "eip=%lx, va=%lx",
                eip, va);

    /*
     * We do the safest things first, then try to update the shadow
     * copying from guest
     */
    paging_invlpg(v, va);
}


static int vmx_check_descriptor(int long_mode, unsigned long eip, int inst_len,
                                enum x86_segment seg, unsigned long *base,
                                u32 *limit, u32 *ar_bytes)
{
    enum vmcs_field ar_field, base_field, limit_field;

    *base = 0;
    *limit = 0;
    if ( seg != x86_seg_es )
    {
        unsigned char inst[MAX_INST_LEN];
        int i;
        extern int inst_copy_from_guest(unsigned char *, unsigned long, int);

        if ( !long_mode )
            eip += __vmread(GUEST_CS_BASE);
        memset(inst, 0, MAX_INST_LEN);
        if ( inst_copy_from_guest(inst, eip, inst_len) != inst_len )
        {
            gdprintk(XENLOG_ERR, "Get guest instruction failed\n");
            domain_crash(current->domain);
            return 0;
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
    }

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
        ar_field = GUEST_FS_AR_BYTES;
        base_field = GUEST_FS_BASE;
        limit_field = GUEST_FS_LIMIT;
        break;
    case x86_seg_ss:
        ar_field = GUEST_GS_AR_BYTES;
        base_field = GUEST_GS_BASE;
        limit_field = GUEST_GS_LIMIT;
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

    return !(*ar_bytes & 0x10000);
}

static void vmx_io_instruction(unsigned long exit_qualification,
                               unsigned long inst_len)
{
    struct cpu_user_regs *regs;
    struct hvm_io_op *pio_opp;
    unsigned int port, size;
    int dir, df, vm86;

    pio_opp = &current->arch.hvm_vcpu.io_op;
    pio_opp->instr = INSTR_PIO;
    pio_opp->flags = 0;

    regs = &pio_opp->io_context;

    /* Copy current guest state into io instruction state structure. */
    memcpy(regs, guest_cpu_user_regs(), HVM_CONTEXT_STACK_BYTES);
    hvm_store_cpu_guest_regs(current, regs, NULL);

    vm86 = regs->eflags & X86_EFLAGS_VM ? 1 : 0;
    df = regs->eflags & X86_EFLAGS_DF ? 1 : 0;

    HVM_DBG_LOG(DBG_LEVEL_IO, "vm86 %d, eip=%x:%lx, "
                "exit_qualification = %lx",
                vm86, regs->cs, (unsigned long)regs->eip, exit_qualification);

    if ( test_bit(6, &exit_qualification) )
        port = (exit_qualification >> 16) & 0xFFFF;
    else
        port = regs->edx & 0xffff;

    size = (exit_qualification & 7) + 1;
    dir = test_bit(3, &exit_qualification); /* direction */

    if (dir==IOREQ_READ)
        HVMTRACE_2D(IO_READ,  current, port, size);
    else
        HVMTRACE_2D(IO_WRITE, current, port, size);

    if ( test_bit(4, &exit_qualification) ) { /* string instruction */
        unsigned long addr, count = 1, base;
        paddr_t paddr;
        unsigned long gfn;
        u32 ar_bytes, limit;
        int sign = regs->eflags & X86_EFLAGS_DF ? -1 : 1;
        int long_mode = 0;

        ar_bytes = __vmread(GUEST_CS_AR_BYTES);
#ifdef __x86_64__
        if ( vmx_long_mode_enabled(current) && (ar_bytes & (1u<<13)) )
            long_mode = 1;
#endif
        addr = __vmread(GUEST_LINEAR_ADDRESS);

        if ( test_bit(5, &exit_qualification) ) { /* "rep" prefix */
            pio_opp->flags |= REPZ;
            count = regs->ecx;
            if ( !long_mode && (vm86 || !(ar_bytes & (1u<<14))) )
                count &= 0xFFFF;
        }

        /*
         * In protected mode, guest linear address is invalid if the
         * selector is null.
         */
        if ( !vmx_check_descriptor(long_mode, regs->eip, inst_len,
                                   dir==IOREQ_WRITE ? x86_seg_ds : x86_seg_es,
                                   &base, &limit, &ar_bytes) ) {
            if ( !long_mode ) {
                vmx_inject_hw_exception(current, TRAP_gp_fault, 0);
                return;
            }
            addr = dir == IOREQ_WRITE ? base + regs->esi : regs->edi;
        }

        if ( !long_mode ) {
            unsigned long ea = addr - base;

            /* Segment must be readable for outs and writeable for ins. */
            if ( dir == IOREQ_WRITE ? (ar_bytes & 0xa) == 0x8
                                    : (ar_bytes & 0xa) != 0x2 ) {
                vmx_inject_hw_exception(current, TRAP_gp_fault, 0);
                return;
            }

            /* Offset must be within limits. */
            ASSERT(ea == (u32)ea);
            if ( (u32)(ea + size - 1) < (u32)ea ||
                 (ar_bytes & 0xc) != 0x4 ? ea + size - 1 > limit
                                         : ea <= limit )
            {
                vmx_inject_hw_exception(current, TRAP_gp_fault, 0);
                return;
            }

            /* Check the limit for repeated instructions, as above we checked
               only the first instance. Truncate the count if a limit violation
               would occur. Note that the checking is not necessary for page
               granular segments as transfers crossing page boundaries will be
               broken up anyway. */
            if ( !(ar_bytes & (1u<<15)) && count > 1 )
            {
                if ( (ar_bytes & 0xc) != 0x4 )
                {
                    /* expand-up */
                    if ( !df )
                    {
                        if ( ea + count * size - 1 < ea ||
                             ea + count * size - 1 > limit )
                            count = (limit + 1UL - ea) / size;
                    }
                    else
                    {
                        if ( count - 1 > ea / size )
                            count = ea / size + 1;
                    }
                }
                else
                {
                    /* expand-down */
                    if ( !df )
                    {
                        if ( count - 1 > -(s32)ea / size )
                            count = -(s32)ea / size + 1UL;
                    }
                    else
                    {
                        if ( ea < (count - 1) * size ||
                             ea - (count - 1) * size <= limit )
                            count = (ea - limit - 1) / size + 1;
                    }
                }
                ASSERT(count);
            }
        }
#ifdef __x86_64__
        else
        {
            if ( !is_canonical_address(addr) ||
                 !is_canonical_address(addr + size - 1) )
            {
                vmx_inject_hw_exception(current, TRAP_gp_fault, 0);
                return;
            }
            if ( count > (1UL << 48) / size )
                count = (1UL << 48) / size;
            if ( !(regs->eflags & EF_DF) )
            {
                if ( addr + count * size - 1 < addr ||
                     !is_canonical_address(addr + count * size - 1) )
                    count = (addr & ~((1UL << 48) - 1)) / size;
            }
            else
            {
                if ( (count - 1) * size > addr ||
                     !is_canonical_address(addr + (count - 1) * size) )
                    count = (addr & ~((1UL << 48) - 1)) / size + 1;
            }
            ASSERT(count);
        }
#endif

        /* Translate the address to a physical address */
        gfn = paging_gva_to_gfn(current, addr);
        if ( gfn == INVALID_GFN ) 
        {
            /* The guest does not have the RAM address mapped. 
             * Need to send in a page fault */
            int errcode = 0;
            /* IO read --> memory write */
            if ( dir == IOREQ_READ ) errcode |= PFEC_write_access;
            vmx_inject_exception(TRAP_page_fault, errcode, addr);
            return;
        }
        paddr = (paddr_t)gfn << PAGE_SHIFT | (addr & ~PAGE_MASK);

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
                    if ( rv != 0 ) 
                    {
                        /* Failed on the page-spanning copy.  Inject PF into
                         * the guest for the address where we failed. */ 
                        addr += size - rv;
                        gdprintk(XENLOG_DEBUG, "Pagefault reading non-io side "
                                 "of a page-spanning PIO: va=%#lx\n", addr);
                        vmx_inject_exception(TRAP_page_fault, 0, addr);
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
    } else {
        if ( port == 0xe9 && dir == IOREQ_WRITE && size == 1 )
            hvm_print_line(current, regs->eax); /* guest debug output */

        regs->eip += inst_len;
        send_pio_req(port, 1, size, regs->eax, dir, df, 0);
    }
}

static void vmx_world_save(struct vcpu *v, struct vmx_assist_context *c)
{
    /* NB. Skip transition instruction. */
    c->eip = __vmread(GUEST_RIP);
    c->eip += __get_instruction_length(); /* Safe: MOV Cn, LMSW, CLTS */

    c->esp = __vmread(GUEST_RSP);
    c->eflags = __vmread(GUEST_RFLAGS);

    c->cr0 = v->arch.hvm_vmx.cpu_shadow_cr0;
    c->cr3 = v->arch.hvm_vmx.cpu_cr3;
    c->cr4 = v->arch.hvm_vmx.cpu_shadow_cr4;

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
    unsigned long mfn, old_base_mfn;

    __vmwrite(GUEST_RIP, c->eip);
    __vmwrite(GUEST_RSP, c->esp);
    __vmwrite(GUEST_RFLAGS, c->eflags);

    v->arch.hvm_vmx.cpu_shadow_cr0 = c->cr0;
    __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr0);

    if ( !vmx_paging_enabled(v) )
        goto skip_cr3;

    if ( c->cr3 == v->arch.hvm_vmx.cpu_cr3 )
    {
        /*
         * This is simple TLB flush, implying the guest has
         * removed some translation or changed page attributes.
         * We simply invalidate the shadow.
         */
        mfn = get_mfn_from_gpfn(c->cr3 >> PAGE_SHIFT);
        if ( mfn != pagetable_get_pfn(v->arch.guest_table) )
            goto bad_cr3;
    }
    else
    {
        /*
         * If different, make a shadow. Check if the PDBR is valid
         * first.
         */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 c->cr3 = %x", c->cr3);
        mfn = get_mfn_from_gpfn(c->cr3 >> PAGE_SHIFT);
        if ( !mfn_valid(mfn) || !get_page(mfn_to_page(mfn), v->domain) )
            goto bad_cr3;
        old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
        v->arch.guest_table = pagetable_from_pfn(mfn);
        if (old_base_mfn)
             put_page(mfn_to_page(old_base_mfn));
        v->arch.hvm_vmx.cpu_cr3 = c->cr3;
    }

 skip_cr3:
    if ( !vmx_paging_enabled(v) )
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "switching to vmxassist. use phys table");
    else
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %x", c->cr3);

    __vmwrite(GUEST_CR4, (c->cr4 | VMX_CR4_HOST_MASK));
    v->arch.hvm_vmx.cpu_shadow_cr4 = c->cr4;
    __vmwrite(CR4_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr4);

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

 bad_cr3:
    gdprintk(XENLOG_ERR, "Invalid CR3 value=%x", c->cr3);
    return -EINVAL;
}

enum { VMX_ASSIST_INVOKE = 0, VMX_ASSIST_RESTORE };

static int vmx_assist(struct vcpu *v, int mode)
{
    struct vmx_assist_context c;
    u32 magic;
    u32 cp;

    /* make sure vmxassist exists (this is not an error) */
    if (hvm_copy_from_guest_phys(&magic, VMXASSIST_MAGIC_OFFSET,
                                 sizeof(magic)))
        return 0;
    if (magic != VMXASSIST_MAGIC)
        return 0;

    switch (mode) {
        /*
         * Transfer control to vmxassist.
         * Store the current context in VMXASSIST_OLD_CONTEXT and load
         * the new VMXASSIST_NEW_CONTEXT context. This context was created
         * by vmxassist and will transfer control to it.
         */
    case VMX_ASSIST_INVOKE:
        /* save the old context */
        if (hvm_copy_from_guest_phys(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp)))
            goto error;
        if (cp != 0) {
            vmx_world_save(v, &c);
            if (hvm_copy_to_guest_phys(cp, &c, sizeof(c)))
                goto error;
        }

        /* restore the new context, this should activate vmxassist */
        if (hvm_copy_from_guest_phys(&cp, VMXASSIST_NEW_CONTEXT, sizeof(cp)))
            goto error;
        if (cp != 0) {
            if (hvm_copy_from_guest_phys(&c, cp, sizeof(c)))
                goto error;
            if ( vmx_world_restore(v, &c) != 0 )
                goto error;
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
        if (hvm_copy_from_guest_phys(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp)))
            goto error;
        if (cp != 0) {
            if (hvm_copy_from_guest_phys(&c, cp, sizeof(c)))
                goto error;
            if ( vmx_world_restore(v, &c) != 0 )
                goto error;
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
    unsigned long mfn;
    unsigned long eip;
    int paging_enabled;
    unsigned long vm_entry_value;
    unsigned long old_cr0;
    unsigned long old_base_mfn;

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx\n", value);

    /* ET is reserved and should be always be 1. */
    value |= X86_CR0_ET;

    if ( (value & (X86_CR0_PE|X86_CR0_PG)) == X86_CR0_PG )
    {
        vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
        return 0;
    }

    /* TS cleared? Then initialise FPU now. */
    if ( !(value & X86_CR0_TS) )
    {
        setup_fpu(v);
        __vm_clear_bit(EXCEPTION_BITMAP, TRAP_no_device);
    }

    old_cr0 = v->arch.hvm_vmx.cpu_shadow_cr0;
    paging_enabled = old_cr0 & X86_CR0_PG;

    v->arch.hvm_vmx.cpu_cr0 = (value | X86_CR0_PE | X86_CR0_PG 
                               | X86_CR0_NE | X86_CR0_WP);
    __vmwrite(GUEST_CR0, v->arch.hvm_vmx.cpu_cr0);

    v->arch.hvm_vmx.cpu_shadow_cr0 = value;
    __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr0);

    if ( (value & X86_CR0_PE) && (value & X86_CR0_PG) && !paging_enabled )
    {
        /*
         * Trying to enable guest paging.
         * The guest CR3 must be pointing to the guest physical.
         */
        mfn = get_mfn_from_gpfn(v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT);
        if ( !mfn_valid(mfn) || !get_page(mfn_to_page(mfn), v->domain) )
        {
            gdprintk(XENLOG_ERR, "Invalid CR3 value = %lx (mfn=%lx)\n",
                     v->arch.hvm_vmx.cpu_cr3, mfn);
            domain_crash(v->domain);
            return 0;
        }

#if defined(__x86_64__)
        if ( vmx_lme_is_set(v) )
        {
            if ( !(v->arch.hvm_vmx.cpu_shadow_cr4 & X86_CR4_PAE) )
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Guest enabled paging "
                            "with EFER.LME set but not CR4.PAE\n");
                vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            }
            else
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Enabling long mode\n");
                v->arch.hvm_vmx.msr_state.msrs[VMX_INDEX_MSR_EFER]
                    |= EFER_LMA;
                vm_entry_value = __vmread(VM_ENTRY_CONTROLS);
                vm_entry_value |= VM_ENTRY_IA32E_MODE;
                __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
            }
        }
#endif

        /*
         * Now arch.guest_table points to machine physical.
         */
        old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
        v->arch.guest_table = pagetable_from_pfn(mfn);
        if (old_base_mfn)
            put_page(mfn_to_page(old_base_mfn));
        paging_update_paging_modes(v);

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                    (unsigned long) (mfn << PAGE_SHIFT));

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                    v->arch.hvm_vmx.cpu_cr3, mfn);
    }

    if ( !((value & X86_CR0_PE) && (value & X86_CR0_PG)) && paging_enabled )
        if ( v->arch.hvm_vmx.cpu_cr3 ) {
            put_page(mfn_to_page(get_mfn_from_gpfn(
                      v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT)));
            v->arch.guest_table = pagetable_null();
        }

    /*
     * VMX does not implement real-mode virtualization. We emulate
     * real-mode by performing a world switch to VMXAssist whenever
     * a partition disables the CR0.PE bit.
     */
    if ( (value & X86_CR0_PE) == 0 )
    {
        if ( value & X86_CR0_PG ) {
            /* inject GP here */
            vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            return 0;
        } else {
            /*
             * Disable paging here.
             * Same to PE == 1 && PG == 0
             */
            if ( vmx_long_mode_enabled(v) )
            {
                v->arch.hvm_vmx.msr_state.msrs[VMX_INDEX_MSR_EFER]
                    &= ~EFER_LMA;
                vm_entry_value = __vmread(VM_ENTRY_CONTROLS);
                vm_entry_value &= ~VM_ENTRY_IA32E_MODE;
                __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
            }
        }

        if ( vmx_assist(v, VMX_ASSIST_INVOKE) )
        {
            eip = __vmread(GUEST_RIP);
            HVM_DBG_LOG(DBG_LEVEL_1,
                        "Transfering control to vmxassist %%eip 0x%lx\n", eip);
            return 0; /* do not update eip! */
        }
    }
    else if ( v->arch.hvm_vmx.vmxassist_enabled )
    {
        eip = __vmread(GUEST_RIP);
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Enabling CR0.PE at %%eip 0x%lx\n", eip);
        if ( vmx_assist(v, VMX_ASSIST_RESTORE) )
        {
            eip = __vmread(GUEST_RIP);
            HVM_DBG_LOG(DBG_LEVEL_1,
                        "Restoring to %%eip 0x%lx\n", eip);
            return 0; /* do not update eip! */
        }
    }
    else if ( (value & (X86_CR0_PE | X86_CR0_PG)) == X86_CR0_PE )
    {
        if ( vmx_long_mode_enabled(v) )
        {
            v->arch.hvm_vmx.msr_state.msrs[VMX_INDEX_MSR_EFER] &= ~EFER_LMA;
            vm_entry_value = __vmread(VM_ENTRY_CONTROLS);
            vm_entry_value &= ~VM_ENTRY_IA32E_MODE;
            __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
        }
        paging_update_paging_modes(v);
    }

    return 1;
}

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

/*
 * Write to control registers
 */
static int mov_to_cr(int gp, int cr, struct cpu_user_regs *regs)
{
    unsigned long value, old_cr, old_base_mfn, mfn;
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
    CASE_EXTEND_GET_REG;
    case REG_ESP:
        value = __vmread(GUEST_RSP);
        break;
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
        /*
         * If paging is not enabled yet, simply copy the value to CR3.
         */
        if (!vmx_paging_enabled(v)) {
            v->arch.hvm_vmx.cpu_cr3 = value;
            break;
        }

        /*
         * We make a new one if the shadow does not exist.
         */
        if (value == v->arch.hvm_vmx.cpu_cr3) {
            /*
             * This is simple TLB flush, implying the guest has
             * removed some translation or changed page attributes.
             * We simply invalidate the shadow.
             */
            mfn = get_mfn_from_gpfn(value >> PAGE_SHIFT);
            if (mfn != pagetable_get_pfn(v->arch.guest_table))
                goto bad_cr3;
            paging_update_cr3(v);
        } else {
            /*
             * If different, make a shadow. Check if the PDBR is valid
             * first.
             */
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
            mfn = get_mfn_from_gpfn(value >> PAGE_SHIFT);
            if ( !mfn_valid(mfn) || !get_page(mfn_to_page(mfn), v->domain) )
                goto bad_cr3;
            old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
            v->arch.guest_table = pagetable_from_pfn(mfn);
            if (old_base_mfn)
                put_page(mfn_to_page(old_base_mfn));
            v->arch.hvm_vmx.cpu_cr3 = value;
            update_cr3(v);
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx", value);
        }
        break;

    case 4: /* CR4 */
        old_cr = v->arch.hvm_vmx.cpu_shadow_cr4;

        if ( (value & X86_CR4_PAE) && !(old_cr & X86_CR4_PAE) )
        {
            if ( vmx_pgbit_test(v) )
            {
                /* The guest is a 32-bit PAE guest. */
#if CONFIG_PAGING_LEVELS >= 3
                unsigned long mfn, old_base_mfn;
                mfn = get_mfn_from_gpfn(v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT);
                if ( !mfn_valid(mfn) ||
                     !get_page(mfn_to_page(mfn), v->domain) )
                    goto bad_cr3;

                /*
                 * Now arch.guest_table points to machine physical.
                 */

                old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
                v->arch.guest_table = pagetable_from_pfn(mfn);
                if ( old_base_mfn )
                    put_page(mfn_to_page(old_base_mfn));

                HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                            (unsigned long) (mfn << PAGE_SHIFT));

                HVM_DBG_LOG(DBG_LEVEL_VMMU, 
                            "Update CR3 value = %lx, mfn = %lx",
                            v->arch.hvm_vmx.cpu_cr3, mfn);
#endif
            }
        }
        else if ( !(value & X86_CR4_PAE) )
        {
            if ( unlikely(vmx_long_mode_enabled(v)) )
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Guest cleared CR4.PAE while "
                            "EFER.LMA is set\n");
                vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            }
        }

        __vmwrite(GUEST_CR4, value| VMX_CR4_HOST_MASK);
        v->arch.hvm_vmx.cpu_shadow_cr4 = value;
        __vmwrite(CR4_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr4);

        /*
         * Writing to CR4 to modify the PSE, PGE, or PAE flag invalidates
         * all TLB entries except global entries.
         */
        if ( (old_cr ^ value) & (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE) )
            paging_update_paging_modes(v);
        break;

    case 8:
        vlapic_set_reg(vlapic, APIC_TASKPRI, ((value & 0x0F) << 4));
        break;

    default:
        gdprintk(XENLOG_ERR, "invalid cr: %d\n", cr);
        domain_crash(v->domain);
        return 0;
    }

    return 1;

 bad_cr3:
    gdprintk(XENLOG_ERR, "Invalid CR3\n");
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
        value = (unsigned long)v->arch.hvm_vmx.cpu_cr3;
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
    CASE_EXTEND_SET_REG;
    case REG_ESP:
        __vmwrite(GUEST_RSP, value);
        regs->esp = value;
        break;
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

    switch (exit_qualification & CONTROL_REG_ACCESS_TYPE) {
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

        v->arch.hvm_vmx.cpu_cr0 &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(GUEST_CR0, v->arch.hvm_vmx.cpu_cr0);

        v->arch.hvm_vmx.cpu_shadow_cr0 &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr0);
        break;
    case TYPE_LMSW:
        value = v->arch.hvm_vmx.cpu_shadow_cr0;
        value = (value & ~0xF) |
            (((exit_qualification & LMSW_SOURCE_DATA) >> 16) & 0xF);
        return vmx_set_cr0(value);
    default:
        BUG();
    }

    return 1;
}

static inline int vmx_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    u32 ecx = regs->ecx, eax, edx;
    struct vcpu *v = current;

    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x, eax=%x, edx=%x",
                ecx, (u32)regs->eax, (u32)regs->edx);

    switch (ecx) {
    case MSR_IA32_TIME_STAMP_COUNTER:
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
    default:
        if ( long_mode_do_msr_read(regs) )
            goto done;

        if ( rdmsr_hypervisor_regs(ecx, &eax, &edx) ||
             rdmsr_safe(ecx, eax, edx) == 0 )
        {
            regs->eax = eax;
            regs->edx = edx;
            goto done;
        }
        vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
        return 0;
    }

    regs->eax = msr_content & 0xFFFFFFFF;
    regs->edx = msr_content >> 32;

done:
    HVMTRACE_2D(MSR_READ, v, ecx, msr_content);
    HVM_DBG_LOG(DBG_LEVEL_1, "returns: ecx=%x, eax=%lx, edx=%lx",
                ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
    return 1;
}

static inline int vmx_do_msr_write(struct cpu_user_regs *regs)
{
    u32 ecx = regs->ecx;
    u64 msr_content;
    struct vcpu *v = current;

    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x, eax=%x, edx=%x",
                ecx, (u32)regs->eax, (u32)regs->edx);

    msr_content = (u32)regs->eax | ((u64)regs->edx << 32);
    HVMTRACE_2D(MSR_WRITE, v, ecx, msr_content);

    switch (ecx) {
    case MSR_IA32_TIME_STAMP_COUNTER:
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
    default:
        if ( !long_mode_do_msr_write(regs) )
            wrmsr_hypervisor_regs(ecx, regs->eax, regs->edx);
        break;
    }

    return 1;
}

static void vmx_do_hlt(void)
{
    unsigned long rflags;
    HVMTRACE_0D(HLT, current);
    rflags = __vmread(GUEST_RFLAGS);
    hvm_hlt(rflags);
}

static inline void vmx_do_extint(struct cpu_user_regs *regs)
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

    switch(vector) {
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

static void vmx_reflect_exception(struct vcpu *v)
{
    int error_code, intr_info, vector;

    intr_info = __vmread(VM_EXIT_INTR_INFO);
    vector = intr_info & 0xff;
    if ( intr_info & INTR_INFO_DELIVER_CODE_MASK )
        error_code = __vmread(VM_EXIT_INTR_ERROR_CODE);
    else
        error_code = VMX_DELIVER_NO_ERROR_CODE;

#ifndef NDEBUG
    {
        unsigned long rip;

        rip = __vmread(GUEST_RIP);
        HVM_DBG_LOG(DBG_LEVEL_1, "rip = %lx, error_code = %x",
                    rip, error_code);
    }
#endif /* NDEBUG */

    /*
     * According to Intel Virtualization Technology Specification for
     * the IA-32 Intel Architecture (C97063-002 April 2005), section
     * 2.8.3, SW_EXCEPTION should be used for #BP and #OV, and
     * HW_EXCEPTION used for everything else.  The main difference
     * appears to be that for SW_EXCEPTION, the EIP/RIP is incremented
     * by VM_ENTER_INSTRUCTION_LEN bytes, whereas for HW_EXCEPTION,
     * it is not.
     */
    if ( (intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_SW_EXCEPTION )
    {
        int ilen = __get_instruction_length(); /* Safe: software exception */
        vmx_inject_sw_exception(v, vector, ilen);
    }
    else
    {
        vmx_inject_hw_exception(v, vector, error_code);
    }
}

static void vmx_failed_vmentry(unsigned int exit_reason)
{
    unsigned int failed_vmentry_reason = (uint16_t)exit_reason;
    unsigned long exit_qualification;

    exit_qualification = __vmread(EXIT_QUALIFICATION);
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
        break;
    default:
        printk("reason not known yet!");
        break;
    }

    printk("************* VMCS Area **************\n");
    vmcs_dump_vcpu();
    printk("**************************************\n");

    domain_crash(current->domain);
}

asmlinkage void vmx_vmexit_handler(struct cpu_user_regs *regs)
{
    unsigned int exit_reason;
    unsigned long exit_qualification, inst_len = 0;
    struct vcpu *v = current;

    exit_reason = __vmread(VM_EXIT_REASON);

    HVMTRACE_2D(VMEXIT, v, __vmread(GUEST_RIP), exit_reason);

    perfc_incra(vmexits, exit_reason);

    if ( exit_reason != EXIT_REASON_EXTERNAL_INTERRUPT )
        local_irq_enable();

    if ( unlikely(exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) )
        return vmx_failed_vmentry(exit_reason);

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
                HVMTRACE_2D(PF_XEN, v, exit_qualification, regs->error_code);
                break;
            }

            v->arch.hvm_vmx.cpu_cr2 = exit_qualification;
            vmx_inject_hw_exception(v, TRAP_page_fault, regs->error_code);
            break;
        case TRAP_nmi:
            HVMTRACE_0D(NMI, v);
            if ( (intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI )
                do_nmi(regs); /* Real NMI, vector 2: normal processing. */
            else
                vmx_reflect_exception(v);
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
    case EXIT_REASON_PENDING_INTERRUPT:
        /* Disable the interrupt window. */
        v->arch.hvm_vcpu.u.vmx.exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                  v->arch.hvm_vcpu.u.vmx.exec_control);
        break;
    case EXIT_REASON_TASK_SWITCH:
        goto exit_and_crash;
    case EXIT_REASON_CPUID:
        inst_len = __get_instruction_length(); /* Safe: CPUID */
        __update_guest_eip(inst_len);
        vmx_do_cpuid(regs);
        break;
    case EXIT_REASON_HLT:
        inst_len = __get_instruction_length(); /* Safe: HLT */
        __update_guest_eip(inst_len);
        vmx_do_hlt();
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
    case EXIT_REASON_PAUSE_INSTRUCTION:
        goto exit_and_crash;
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        /* Report invalid opcode exception when a VMX guest tries to execute
            any of the VMX instructions */
        vmx_inject_hw_exception(v, TRAP_invalid_op, VMX_DELIVER_NO_ERROR_CODE);
        break;

    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        break;

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
    HVMTRACE_0D(VMENTRY, v);
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
