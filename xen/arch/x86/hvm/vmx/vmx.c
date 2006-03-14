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
#include <asm/current.h>
#include <asm/io.h>
#include <asm/shadow.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/shadow.h>
#if CONFIG_PAGING_LEVELS >= 3
#include <asm/shadow_64.h>
#endif
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>

static unsigned long trace_values[NR_CPUS][4];
#define TRACE_VMEXIT(index,value) trace_values[smp_processor_id()][index]=value

void vmx_final_setup_guest(struct vcpu *v)
{
    v->arch.schedule_tail = arch_vmx_do_launch;

    if ( v->vcpu_id == 0 )
    {
        struct domain *d = v->domain;
        struct vcpu *vc;

        /* Initialize monitor page table */
        for_each_vcpu(d, vc)
            vc->arch.monitor_table = mk_pagetable(0);

        /*
         * Required to do this once per domain
         * XXX todo: add a seperate function to do these.
         */
        memset(&d->shared_info->evtchn_mask[0], 0xff,
               sizeof(d->shared_info->evtchn_mask));

        /* Put the domain in shadow mode even though we're going to be using
         * the shared 1:1 page table initially. It shouldn't hurt */
        shadow_mode_enable(d,
                           SHM_enable|SHM_refcounts|
                           SHM_translate|SHM_external|SHM_wr_pt_pte);
    }
}

void vmx_relinquish_resources(struct vcpu *v)
{
    struct hvm_virpit *vpit;

    if (v->vcpu_id == 0) {
        /* unmap IO shared page */
        struct domain *d = v->domain;
        if ( d->arch.hvm_domain.shared_page_va )
            unmap_domain_page_global(
	        (void *)d->arch.hvm_domain.shared_page_va);
        shadow_direct_map_clean(d);
    }

    vmx_request_clear_vmcs(v);
    destroy_vmcs(&v->arch.hvm_vmx);
    free_monitor_pagetable(v);
    vpit = &v->domain->arch.hvm_domain.vpit;
    kill_timer(&vpit->pit_timer);
    kill_timer(&v->arch.hvm_vmx.hlt_timer);
    if ( hvm_apic_support(v->domain) && (VLAPIC(v) != NULL) )
    {
        kill_timer(&VLAPIC(v)->vlapic_timer);
        xfree(VLAPIC(v));
    }
}

#ifdef __x86_64__
static struct vmx_msr_state percpu_msr[NR_CPUS];

static u32 msr_data_index[VMX_MSR_COUNT] =
{
    MSR_LSTAR, MSR_STAR, MSR_CSTAR,
    MSR_SYSCALL_MASK, MSR_EFER,
};

void vmx_save_segments(struct vcpu *v)
{
    rdmsrl(MSR_SHADOW_GS_BASE, v->arch.hvm_vmx.msr_content.shadow_gs);
}

/*
 * To avoid MSR save/restore at every VM exit/entry time, we restore
 * the x86_64 specific MSRs at domain switch time. Since those MSRs are
 * are not modified once set for generic domains, we don't save them,
 * but simply reset them to the values set at percpu_traps_init().
 */
void vmx_load_msrs(void)
{
    struct vmx_msr_state *host_state = &percpu_msr[smp_processor_id()];
    int i;

    while ( host_state->flags )
    {
        i = find_first_set_bit(host_state->flags);
        wrmsrl(msr_data_index[i], host_state->msr_items[i]);
        clear_bit(i, &host_state->flags);
    }
}

static void vmx_save_init_msrs(void)
{
    struct vmx_msr_state *host_state = &percpu_msr[smp_processor_id()];
    int i;

    for ( i = 0; i < VMX_MSR_COUNT; i++ )
        rdmsrl(msr_data_index[i], host_state->msr_items[i]);
}

#define CASE_READ_MSR(address)              \
    case MSR_ ## address:                 \
    msr_content = msr->msr_items[VMX_INDEX_MSR_ ## address]; \
    break

#define CASE_WRITE_MSR(address)                                     \
    case MSR_ ## address:                                           \
    {                                                               \
        msr->msr_items[VMX_INDEX_MSR_ ## address] = msr_content;    \
        if (!test_bit(VMX_INDEX_MSR_ ## address, &msr->flags)) {    \
            set_bit(VMX_INDEX_MSR_ ## address, &msr->flags);        \
        }                                                           \
        wrmsrl(MSR_ ## address, msr_content);                       \
        set_bit(VMX_INDEX_MSR_ ## address, &host_state->flags);     \
    }                                                               \
    break

#define IS_CANO_ADDRESS(add) 1
static inline int long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    u64     msr_content = 0;
    struct vcpu *vc = current;
    struct vmx_msr_state * msr = &vc->arch.hvm_vmx.msr_content;
    switch(regs->ecx){
    case MSR_EFER:
        msr_content = msr->msr_items[VMX_INDEX_MSR_EFER];
        HVM_DBG_LOG(DBG_LEVEL_2, "EFER msr_content %"PRIx64"\n", msr_content);
        if (test_bit(VMX_CPU_STATE_LME_ENABLED,
                     &vc->arch.hvm_vmx.cpu_state))
            msr_content |= 1 << _EFER_LME;

        if (VMX_LONG_GUEST(vc))
            msr_content |= 1 << _EFER_LMA;
        break;
    case MSR_FS_BASE:
        if (!(VMX_LONG_GUEST(vc)))
            /* XXX should it be GP fault */
            domain_crash_synchronous();
        __vmread(GUEST_FS_BASE, &msr_content);
        break;
    case MSR_GS_BASE:
        if (!(VMX_LONG_GUEST(vc)))
            domain_crash_synchronous();
        __vmread(GUEST_GS_BASE, &msr_content);
        break;
    case MSR_SHADOW_GS_BASE:
        msr_content = msr->shadow_gs;
        break;

        CASE_READ_MSR(STAR);
        CASE_READ_MSR(LSTAR);
        CASE_READ_MSR(CSTAR);
        CASE_READ_MSR(SYSCALL_MASK);
    default:
        return 0;
    }
    HVM_DBG_LOG(DBG_LEVEL_2, "mode_do_msr_read: msr_content: %"PRIx64"\n",
                msr_content);
    regs->eax = msr_content & 0xffffffff;
    regs->edx = msr_content >> 32;
    return 1;
}

static inline int long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64     msr_content = regs->eax | ((u64)regs->edx << 32);
    struct vcpu *vc = current;
    struct vmx_msr_state * msr = &vc->arch.hvm_vmx.msr_content;
    struct vmx_msr_state * host_state =
        &percpu_msr[smp_processor_id()];

    HVM_DBG_LOG(DBG_LEVEL_1, " mode_do_msr_write msr %lx "
                "msr_content %"PRIx64"\n",
                (unsigned long)regs->ecx, msr_content);

    switch (regs->ecx){
    case MSR_EFER:
        /* offending reserved bit will cause #GP */
        if ( msr_content &
                ~( EFER_LME | EFER_LMA | EFER_NX | EFER_SCE ) )
             vmx_inject_exception(vc, TRAP_gp_fault, 0);

        if ((msr_content & EFER_LME) ^
            test_bit(VMX_CPU_STATE_LME_ENABLED,
                     &vc->arch.hvm_vmx.cpu_state)){
            if (test_bit(VMX_CPU_STATE_PG_ENABLED,
                         &vc->arch.hvm_vmx.cpu_state) ||
                !test_bit(VMX_CPU_STATE_PAE_ENABLED,
                          &vc->arch.hvm_vmx.cpu_state)){
                vmx_inject_exception(vc, TRAP_gp_fault, 0);
            }
        }
        if (msr_content & EFER_LME)
            set_bit(VMX_CPU_STATE_LME_ENABLED,
                    &vc->arch.hvm_vmx.cpu_state);

        msr->msr_items[VMX_INDEX_MSR_EFER] =
            msr_content;
        break;

    case MSR_FS_BASE:
    case MSR_GS_BASE:
        if (!(VMX_LONG_GUEST(vc)))
            domain_crash_synchronous();
        if (!IS_CANO_ADDRESS(msr_content)){
            HVM_DBG_LOG(DBG_LEVEL_1, "Not cano address of msr write\n");
            vmx_inject_exception(vc, TRAP_gp_fault, 0);
        }
        if (regs->ecx == MSR_FS_BASE)
            __vmwrite(GUEST_FS_BASE, msr_content);
        else
            __vmwrite(GUEST_GS_BASE, msr_content);
        break;

    case MSR_SHADOW_GS_BASE:
        if (!(VMX_LONG_GUEST(vc)))
            domain_crash_synchronous();
        vc->arch.hvm_vmx.msr_content.shadow_gs = msr_content;
        wrmsrl(MSR_SHADOW_GS_BASE, msr_content);
        break;

        CASE_WRITE_MSR(STAR);
        CASE_WRITE_MSR(LSTAR);
        CASE_WRITE_MSR(CSTAR);
        CASE_WRITE_MSR(SYSCALL_MASK);
    default:
        return 0;
    }
    return 1;
}

void
vmx_restore_msrs(struct vcpu *v)
{
    int i = 0;
    struct vmx_msr_state *guest_state;
    struct vmx_msr_state *host_state;
    unsigned long guest_flags ;

    guest_state = &v->arch.hvm_vmx.msr_content;;
    host_state = &percpu_msr[smp_processor_id()];

    wrmsrl(MSR_SHADOW_GS_BASE, guest_state->shadow_gs);
    guest_flags = guest_state->flags;
    if (!guest_flags)
        return;

    while (guest_flags){
        i = find_first_set_bit(guest_flags);

        HVM_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's index %d msr %lx with %lx\n",
                    i, (unsigned long) msr_data_index[i], (unsigned long) guest_state->msr_items[i]);
        set_bit(i, &host_state->flags);
        wrmsrl(msr_data_index[i], guest_state->msr_items[i]);
        clear_bit(i, &guest_flags);
    }
}
#else  /* __i386__ */
#define  vmx_save_init_msrs()   ((void)0)

static inline int  long_mode_do_msr_read(struct cpu_user_regs *regs){
    return 0;
}
static inline int  long_mode_do_msr_write(struct cpu_user_regs *regs){
    return 0;
}
#endif

void stop_vmx(void)
{
    if (read_cr4() & X86_CR4_VMXE)
        __vmxoff();
}

int vmx_initialize_guest_resources(struct vcpu *v)
{
    vmx_final_setup_guest(v);
    return 1;
}

int vmx_relinquish_guest_resources(struct vcpu *v)
{
    vmx_relinquish_resources(v);
    return 1;
}

void vmx_migrate_timers(struct vcpu *v)
{
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);

    migrate_timer(&vpit->pit_timer, v->processor);
    migrate_timer(&v->arch.hvm_vmx.hlt_timer, v->processor);
    if ( hvm_apic_support(v->domain) && VLAPIC(v))
        migrate_timer(&(VLAPIC(v)->vlapic_timer), v->processor);
}

void vmx_store_cpu_guest_regs(struct vcpu *v, struct cpu_user_regs *regs)
{
#if defined (__x86_64__)
    __vmread(GUEST_RFLAGS, &regs->rflags);
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_GS_SELECTOR, &regs->gs);
    __vmread(GUEST_FS_SELECTOR, &regs->fs);
    __vmread(GUEST_RIP, &regs->rip);
    __vmread(GUEST_RSP, &regs->rsp);
#elif defined (__i386__)
    __vmread(GUEST_RFLAGS, &regs->eflags);
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_GS_SELECTOR, &regs->gs);
    __vmread(GUEST_FS_SELECTOR, &regs->fs);
    __vmread(GUEST_RIP, &regs->eip);
    __vmread(GUEST_RSP, &regs->esp);
#else
#error Unsupported architecture
#endif
}

void vmx_load_cpu_guest_regs(struct vcpu *v, struct cpu_user_regs *regs)
{
#if defined (__x86_64__)
    __vmwrite(GUEST_SS_SELECTOR, regs->ss);
    __vmwrite(GUEST_RSP, regs->rsp);

    __vmwrite(GUEST_RFLAGS, regs->rflags);
    if (regs->rflags & EF_TF)
        __vm_set_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);
    else
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);

    __vmwrite(GUEST_CS_SELECTOR, regs->cs);
    __vmwrite(GUEST_RIP, regs->rip);
#elif defined (__i386__)
    __vmwrite(GUEST_SS_SELECTOR, regs->ss);
    __vmwrite(GUEST_RSP, regs->esp);

    __vmwrite(GUEST_RFLAGS, regs->eflags);
    if (regs->eflags & EF_TF)
        __vm_set_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);
    else
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);

    __vmwrite(GUEST_CS_SELECTOR, regs->cs);
    __vmwrite(GUEST_RIP, regs->eip);
#else
#error Unsupported architecture
#endif
}

void vmx_store_cpu_guest_ctrl_regs(struct vcpu *v, unsigned long crs[8])
{
    __vmread(CR0_READ_SHADOW, &crs[0]);
    __vmread(GUEST_CR3, &crs[3]);
    __vmread(CR4_READ_SHADOW, &crs[4]);
}

void vmx_modify_guest_state(struct vcpu *v)
{
    modify_vmcs(&v->arch.hvm_vmx, &v->arch.guest_context.user_regs);
}

int vmx_realmode(struct vcpu *v)
{
    unsigned long rflags;

    __vmread(GUEST_RFLAGS, &rflags);
    return rflags & X86_EFLAGS_VM;
}

int vmx_instruction_length(struct vcpu *v)
{
    unsigned long inst_len;

    if (__vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len))
    	return 0;
    return inst_len;
}

unsigned long vmx_get_ctrl_reg(struct vcpu *v, unsigned int num)
{
    switch ( num )
    {
    case 0:
        return v->arch.hvm_vmx.cpu_cr0;
    case 2:
        return v->arch.hvm_vmx.cpu_cr2;
    case 3:
        return v->arch.hvm_vmx.cpu_cr3;
    default:
        BUG();
    }
    return 0;                   /* dummy */
}

/* SMP VMX guest support */
void vmx_init_ap_context(struct vcpu_guest_context *ctxt,
                         int vcpuid, int trampoline_vector)
{
    int i;

    memset(ctxt, 0, sizeof(*ctxt));

    /*
     * Initial register values:
     */
    ctxt->user_regs.eip = VMXASSIST_BASE;
    ctxt->user_regs.edx = vcpuid;
    ctxt->user_regs.ebx = trampoline_vector;

    ctxt->flags = VGCF_HVM_GUEST;

    /* Virtual IDT is empty at start-of-day. */
    for ( i = 0; i < 256; i++ )
    {
        ctxt->trap_ctxt[i].vector = i;
        ctxt->trap_ctxt[i].cs     = FLAT_KERNEL_CS;
    }

    /* No callback handlers. */
#if defined(__i386__)
    ctxt->event_callback_cs     = FLAT_KERNEL_CS;
    ctxt->failsafe_callback_cs  = FLAT_KERNEL_CS;
#endif
}

void do_nmi(struct cpu_user_regs *);

static int check_vmx_controls(u32 ctrls, u32 msr)
{
    u32 vmx_msr_low, vmx_msr_high;

    rdmsr(msr, vmx_msr_low, vmx_msr_high);
    if ( (ctrls < vmx_msr_low) || (ctrls > vmx_msr_high) )
    {
        printk("Insufficient VMX capability 0x%x, "
               "msr=0x%x,low=0x%8x,high=0x%x\n",
               ctrls, msr, vmx_msr_low, vmx_msr_high);
        return 0;
    }
    return 1;
}

int start_vmx(void)
{
    struct vmcs_struct *vmcs;
    u32 ecx;
    u32 eax, edx;
    u64 phys_vmcs;      /* debugging */

    /*
     * Xen does not fill x86_capability words except 0.
     */
    ecx = cpuid_ecx(1);
    boot_cpu_data.x86_capability[4] = ecx;

    if (!(test_bit(X86_FEATURE_VMXE, &boot_cpu_data.x86_capability)))
        return 0;

    rdmsr(IA32_FEATURE_CONTROL_MSR, eax, edx);

    if (eax & IA32_FEATURE_CONTROL_MSR_LOCK) {
        if ((eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON) == 0x0) {
            printk("VMX disabled by Feature Control MSR.\n");
            return 0;
        }
    }
    else {
        wrmsr(IA32_FEATURE_CONTROL_MSR,
              IA32_FEATURE_CONTROL_MSR_LOCK |
              IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON, 0);
    }

    if (!check_vmx_controls(MONITOR_PIN_BASED_EXEC_CONTROLS,
                            MSR_IA32_VMX_PINBASED_CTLS_MSR))
        return 0;
    if (!check_vmx_controls(MONITOR_CPU_BASED_EXEC_CONTROLS,
                            MSR_IA32_VMX_PROCBASED_CTLS_MSR))
        return 0;
    if (!check_vmx_controls(MONITOR_VM_EXIT_CONTROLS,
                            MSR_IA32_VMX_EXIT_CTLS_MSR))
        return 0;
    if (!check_vmx_controls(MONITOR_VM_ENTRY_CONTROLS,
                            MSR_IA32_VMX_ENTRY_CTLS_MSR))
        return 0;

    set_in_cr4(X86_CR4_VMXE);   /* Enable VMXE */

    if (!(vmcs = alloc_vmcs())) {
        printk("Failed to allocate VMCS\n");
        return 0;
    }

    phys_vmcs = (u64) virt_to_maddr(vmcs);

    if (!(__vmxon(phys_vmcs))) {
        printk("VMXON is done\n");
    }

    vmx_save_init_msrs();

    /* Setup HVM interfaces */
    hvm_funcs.disable = stop_vmx;

    hvm_funcs.initialize_guest_resources = vmx_initialize_guest_resources;
    hvm_funcs.relinquish_guest_resources = vmx_relinquish_guest_resources;

    hvm_funcs.store_cpu_guest_regs = vmx_store_cpu_guest_regs;
    hvm_funcs.load_cpu_guest_regs = vmx_load_cpu_guest_regs;

#ifdef __x86_64__
    hvm_funcs.save_segments = vmx_save_segments;
    hvm_funcs.load_msrs = vmx_load_msrs;
    hvm_funcs.restore_msrs = vmx_restore_msrs;
#endif

    hvm_funcs.store_cpu_guest_ctrl_regs = vmx_store_cpu_guest_ctrl_regs;
    hvm_funcs.modify_guest_state = vmx_modify_guest_state;

    hvm_funcs.realmode = vmx_realmode;
    hvm_funcs.paging_enabled = vmx_paging_enabled;
    hvm_funcs.instruction_length = vmx_instruction_length;
    hvm_funcs.get_guest_ctrl_reg = vmx_get_ctrl_reg;

    hvm_funcs.init_ap_context = vmx_init_ap_context;

    hvm_enabled = 1;

    return 1;
}

/*
 * Not all cases receive valid value in the VM-exit instruction length field.
 */
#define __get_instruction_length(len) \
    __vmread(VM_EXIT_INSTRUCTION_LEN, &(len)); \
     if ((len) < 1 || (len) > 15) \
        __hvm_bug(&regs);

static void inline __update_guest_eip(unsigned long inst_len)
{
    unsigned long current_eip;

    __vmread(GUEST_RIP, &current_eip);
    __vmwrite(GUEST_RIP, current_eip + inst_len);
    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
}


static int vmx_do_page_fault(unsigned long va, struct cpu_user_regs *regs)
{
    unsigned long gpa; /* FIXME: PAE */
    int result;

#if 0 /* keep for debugging */
    {
        unsigned long eip;

        __vmread(GUEST_RIP, &eip);
        HVM_DBG_LOG(DBG_LEVEL_VMMU,
                    "vmx_do_page_fault = 0x%lx, eip = %lx, error_code = %lx",
                    va, eip, (unsigned long)regs->error_code);
    }
#endif

    if ( !vmx_paging_enabled(current) )
    {
        /* construct 1-to-1 direct mapping */
        if ( shadow_direct_map_fault(va, regs) ) 
            return 1;

        handle_mmio(va, va);
        TRACE_VMEXIT (2,2);
        return 1;
    }
    gpa = gva_to_gpa(va);

    /* Use 1:1 page table to identify MMIO address space */
    if ( mmio_space(gpa) ){
        struct vcpu *v = current;
        /* No support for APIC */
        if (!hvm_apic_support(v->domain) && gpa >= 0xFEC00000) { 
            u32 inst_len;
            __vmread(VM_EXIT_INSTRUCTION_LEN, &(inst_len));
            __update_guest_eip(inst_len);
            return 1;
        }
        TRACE_VMEXIT (2,2);
        handle_mmio(va, gpa);
        return 1;
    }

    result = shadow_fault(va, regs);
    TRACE_VMEXIT (2,result);
#if 0
    if ( !result )
    {
        __vmread(GUEST_RIP, &eip);
        printk("vmx pgfault to guest va=%lx eip=%lx\n", va, eip);
    }
#endif

    return result;
}

static void vmx_do_no_device_fault(void)
{
    unsigned long cr0;
    struct vcpu *v = current;

    setup_fpu(current);
    __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);

    /* Disable TS in guest CR0 unless the guest wants the exception too. */
    __vmread_vcpu(v, CR0_READ_SHADOW, &cr0);
    if ( !(cr0 & X86_CR0_TS) )
    {
        __vmread_vcpu(v, GUEST_CR0, &cr0);
        cr0 &= ~X86_CR0_TS;
        __vmwrite(GUEST_CR0, cr0);
    }
}

/* Reserved bits: [31:15], [12:11], [9], [6], [2:1] */
#define VMX_VCPU_CPUID_L1_RESERVED 0xffff9a46

static void vmx_vmexit_do_cpuid(unsigned long input, struct cpu_user_regs *regs)
{
    unsigned int eax, ebx, ecx, edx;
    unsigned long eip;
    struct vcpu *v = current;

    __vmread(GUEST_RIP, &eip);

    HVM_DBG_LOG(DBG_LEVEL_1,
                "do_cpuid: (eax) %lx, (ebx) %lx, (ecx) %lx, (edx) %lx,"
                " (esi) %lx, (edi) %lx",
                (unsigned long)regs->eax, (unsigned long)regs->ebx,
                (unsigned long)regs->ecx, (unsigned long)regs->edx,
                (unsigned long)regs->esi, (unsigned long)regs->edi);

    cpuid(input, &eax, &ebx, &ecx, &edx);

    if ( input == 1 )
    {
        if ( hvm_apic_support(v->domain) &&
                !vlapic_global_enabled((VLAPIC(v))) )
            clear_bit(X86_FEATURE_APIC, &edx);

#if CONFIG_PAGING_LEVELS < 3
        clear_bit(X86_FEATURE_PAE, &edx);
        clear_bit(X86_FEATURE_PSE, &edx);
        clear_bit(X86_FEATURE_PSE36, &edx);
#else
        if ( v->domain->arch.ops->guest_paging_levels == PAGING_L2 )
        {
            if ( !v->domain->arch.hvm_domain.pae_enabled )
                clear_bit(X86_FEATURE_PAE, &edx);
            clear_bit(X86_FEATURE_PSE, &edx);
            clear_bit(X86_FEATURE_PSE36, &edx);
        }
#endif

        /* Unsupportable for virtualised CPUs. */
        ecx &= ~VMX_VCPU_CPUID_L1_RESERVED; /* mask off reserved bits */
        clear_bit(X86_FEATURE_VMXE & 31, &ecx);
        clear_bit(X86_FEATURE_MWAIT & 31, &ecx);
    }
#ifdef __i386__
    else if ( input == 0x80000001 )
    {
        /* Mask feature for Intel ia32e or AMD long mode. */
        clear_bit(X86_FEATURE_LM & 31, &edx);
    }
#endif

    regs->eax = (unsigned long) eax;
    regs->ebx = (unsigned long) ebx;
    regs->ecx = (unsigned long) ecx;
    regs->edx = (unsigned long) edx;

    HVM_DBG_LOG(DBG_LEVEL_1,
                "vmx_vmexit_do_cpuid: eip: %lx, input: %lx, out:eax=%x, ebx=%x, ecx=%x, edx=%x",
                eip, input, eax, ebx, ecx, edx);

}

#define CASE_GET_REG_P(REG, reg)    \
    case REG_ ## REG: reg_p = (unsigned long *)&(regs->reg); break

static void vmx_dr_access (unsigned long exit_qualification, struct cpu_user_regs *regs)
{
    unsigned int reg;
    unsigned long *reg_p = 0;
    struct vcpu *v = current;
    unsigned long eip;

    __vmread(GUEST_RIP, &eip);

    reg = exit_qualification & DEBUG_REG_ACCESS_NUM;

    HVM_DBG_LOG(DBG_LEVEL_1,
                "vmx_dr_access : eip=%lx, reg=%d, exit_qualification = %lx",
                eip, reg, exit_qualification);

    switch(exit_qualification & DEBUG_REG_ACCESS_REG) {
        CASE_GET_REG_P(EAX, eax);
        CASE_GET_REG_P(ECX, ecx);
        CASE_GET_REG_P(EDX, edx);
        CASE_GET_REG_P(EBX, ebx);
        CASE_GET_REG_P(EBP, ebp);
        CASE_GET_REG_P(ESI, esi);
        CASE_GET_REG_P(EDI, edi);
    case REG_ESP:
        break;
    default:
        __hvm_bug(regs);
    }

    switch (exit_qualification & DEBUG_REG_ACCESS_TYPE) {
    case TYPE_MOV_TO_DR:
        /* don't need to check the range */
        if (reg != REG_ESP)
            v->arch.guest_context.debugreg[reg] = *reg_p;
        else {
            unsigned long value;
            __vmread(GUEST_RSP, &value);
            v->arch.guest_context.debugreg[reg] = value;
        }
        break;
    case TYPE_MOV_FROM_DR:
        if (reg != REG_ESP)
            *reg_p = v->arch.guest_context.debugreg[reg];
        else {
            __vmwrite(GUEST_RSP, v->arch.guest_context.debugreg[reg]);
        }
        break;
    }
}

/*
 * Invalidate the TLB for va. Invalidate the shadow page corresponding
 * the address va.
 */
static void vmx_vmexit_do_invlpg(unsigned long va)
{
    unsigned long eip;
    struct vcpu *v = current;

    __vmread(GUEST_RIP, &eip);

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "vmx_vmexit_do_invlpg: eip=%lx, va=%lx",
                eip, va);

    /*
     * We do the safest things first, then try to update the shadow
     * copying from guest
     */
    shadow_invlpg(v, va);
}

static int check_for_null_selector(unsigned long eip)
{
    unsigned char inst[MAX_INST_LEN];
    unsigned long sel;
    int i, inst_len;
    int inst_copy_from_guest(unsigned char *, unsigned long, int);

    __vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
    memset(inst, 0, MAX_INST_LEN);
    if (inst_copy_from_guest(inst, eip, inst_len) != inst_len) {
        printf("check_for_null_selector: get guest instruction failed\n");
        domain_crash_synchronous();
    }

    for (i = 0; i < inst_len; i++) {
        switch (inst[i]) {
        case 0xf3: /* REPZ */
        case 0xf2: /* REPNZ */
        case 0xf0: /* LOCK */
        case 0x66: /* data32 */
        case 0x67: /* addr32 */
            continue;
        case 0x2e: /* CS */
            __vmread(GUEST_CS_SELECTOR, &sel);
            break;
        case 0x36: /* SS */
            __vmread(GUEST_SS_SELECTOR, &sel);
            break;
        case 0x26: /* ES */
            __vmread(GUEST_ES_SELECTOR, &sel);
            break;
        case 0x64: /* FS */
            __vmread(GUEST_FS_SELECTOR, &sel);
            break;
        case 0x65: /* GS */
            __vmread(GUEST_GS_SELECTOR, &sel);
            break;
        case 0x3e: /* DS */
            /* FALLTHROUGH */
        default:
            /* DS is the default */
            __vmread(GUEST_DS_SELECTOR, &sel);
        }
        return sel == 0 ? 1 : 0;
    }

    return 0;
}

extern void send_pio_req(struct cpu_user_regs *regs, unsigned long port,
                         unsigned long count, int size, long value,
			 int dir, int pvalid);

static void vmx_io_instruction(struct cpu_user_regs *regs,
                               unsigned long exit_qualification, unsigned long inst_len)
{
    struct mmio_op *mmio_opp;
    unsigned long eip, cs, eflags;
    unsigned long port, size, dir;
    int vm86;

    mmio_opp = &current->arch.hvm_vcpu.mmio_op;
    mmio_opp->instr = INSTR_PIO;
    mmio_opp->flags = 0;

    __vmread(GUEST_RIP, &eip);
    __vmread(GUEST_CS_SELECTOR, &cs);
    __vmread(GUEST_RFLAGS, &eflags);
    vm86 = eflags & X86_EFLAGS_VM ? 1 : 0;

    HVM_DBG_LOG(DBG_LEVEL_IO,
                "vmx_io_instruction: vm86 %d, eip=%lx:%lx, "
                "exit_qualification = %lx",
                vm86, cs, eip, exit_qualification);

    if (test_bit(6, &exit_qualification))
        port = (exit_qualification >> 16) & 0xFFFF;
    else
        port = regs->edx & 0xffff;
    TRACE_VMEXIT(2, port);
    size = (exit_qualification & 7) + 1;
    dir = test_bit(3, &exit_qualification); /* direction */

    if (test_bit(4, &exit_qualification)) { /* string instruction */
        unsigned long addr, count = 1;
        int sign = regs->eflags & EF_DF ? -1 : 1;

        __vmread(GUEST_LINEAR_ADDRESS, &addr);

        /*
         * In protected mode, guest linear address is invalid if the
         * selector is null.
         */
        if (!vm86 && check_for_null_selector(eip))
            addr = dir == IOREQ_WRITE ? regs->esi : regs->edi;

        if (test_bit(5, &exit_qualification)) { /* "rep" prefix */
            mmio_opp->flags |= REPZ;
            count = vm86 ? regs->ecx & 0xFFFF : regs->ecx;
        }

        /*
         * Handle string pio instructions that cross pages or that
         * are unaligned. See the comments in hvm_domain.c/handle_mmio()
         */
        if ((addr & PAGE_MASK) != ((addr + size - 1) & PAGE_MASK)) {
            unsigned long value = 0;

            mmio_opp->flags |= OVERLAP;
            if (dir == IOREQ_WRITE)
                hvm_copy(&value, addr, size, HVM_COPY_IN);
            send_pio_req(regs, port, 1, size, value, dir, 0);
        } else {
            if ((addr & PAGE_MASK) != ((addr + count * size - 1) & PAGE_MASK)) {
                if (sign > 0)
                    count = (PAGE_SIZE - (addr & ~PAGE_MASK)) / size;
                else
                    count = (addr & ~PAGE_MASK) / size;
            } else
                __update_guest_eip(inst_len);

            send_pio_req(regs, port, count, size, addr, dir, 1);
        }
    } else {
        if (port == 0xe9 && dir == IOREQ_WRITE && size == 1)
            hvm_print_line(current, regs->eax); /* guest debug output */

        __update_guest_eip(inst_len);
        send_pio_req(regs, port, 1, size, regs->eax, dir, 0);
    }
}

int
vmx_world_save(struct vcpu *v, struct vmx_assist_context *c)
{
    unsigned long inst_len;
    int error = 0;

    error |= __vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
    error |= __vmread(GUEST_RIP, &c->eip);
    c->eip += inst_len; /* skip transition instruction */
    error |= __vmread(GUEST_RSP, &c->esp);
    error |= __vmread(GUEST_RFLAGS, &c->eflags);

    error |= __vmread(CR0_READ_SHADOW, &c->cr0);
    c->cr3 = v->arch.hvm_vmx.cpu_cr3;
    error |= __vmread(CR4_READ_SHADOW, &c->cr4);

    error |= __vmread(GUEST_IDTR_LIMIT, &c->idtr_limit);
    error |= __vmread(GUEST_IDTR_BASE, &c->idtr_base);

    error |= __vmread(GUEST_GDTR_LIMIT, &c->gdtr_limit);
    error |= __vmread(GUEST_GDTR_BASE, &c->gdtr_base);

    error |= __vmread(GUEST_CS_SELECTOR, &c->cs_sel);
    error |= __vmread(GUEST_CS_LIMIT, &c->cs_limit);
    error |= __vmread(GUEST_CS_BASE, &c->cs_base);
    error |= __vmread(GUEST_CS_AR_BYTES, &c->cs_arbytes.bytes);

    error |= __vmread(GUEST_DS_SELECTOR, &c->ds_sel);
    error |= __vmread(GUEST_DS_LIMIT, &c->ds_limit);
    error |= __vmread(GUEST_DS_BASE, &c->ds_base);
    error |= __vmread(GUEST_DS_AR_BYTES, &c->ds_arbytes.bytes);

    error |= __vmread(GUEST_ES_SELECTOR, &c->es_sel);
    error |= __vmread(GUEST_ES_LIMIT, &c->es_limit);
    error |= __vmread(GUEST_ES_BASE, &c->es_base);
    error |= __vmread(GUEST_ES_AR_BYTES, &c->es_arbytes.bytes);

    error |= __vmread(GUEST_SS_SELECTOR, &c->ss_sel);
    error |= __vmread(GUEST_SS_LIMIT, &c->ss_limit);
    error |= __vmread(GUEST_SS_BASE, &c->ss_base);
    error |= __vmread(GUEST_SS_AR_BYTES, &c->ss_arbytes.bytes);

    error |= __vmread(GUEST_FS_SELECTOR, &c->fs_sel);
    error |= __vmread(GUEST_FS_LIMIT, &c->fs_limit);
    error |= __vmread(GUEST_FS_BASE, &c->fs_base);
    error |= __vmread(GUEST_FS_AR_BYTES, &c->fs_arbytes.bytes);

    error |= __vmread(GUEST_GS_SELECTOR, &c->gs_sel);
    error |= __vmread(GUEST_GS_LIMIT, &c->gs_limit);
    error |= __vmread(GUEST_GS_BASE, &c->gs_base);
    error |= __vmread(GUEST_GS_AR_BYTES, &c->gs_arbytes.bytes);

    error |= __vmread(GUEST_TR_SELECTOR, &c->tr_sel);
    error |= __vmread(GUEST_TR_LIMIT, &c->tr_limit);
    error |= __vmread(GUEST_TR_BASE, &c->tr_base);
    error |= __vmread(GUEST_TR_AR_BYTES, &c->tr_arbytes.bytes);

    error |= __vmread(GUEST_LDTR_SELECTOR, &c->ldtr_sel);
    error |= __vmread(GUEST_LDTR_LIMIT, &c->ldtr_limit);
    error |= __vmread(GUEST_LDTR_BASE, &c->ldtr_base);
    error |= __vmread(GUEST_LDTR_AR_BYTES, &c->ldtr_arbytes.bytes);

    return !error;
}

int
vmx_world_restore(struct vcpu *v, struct vmx_assist_context *c)
{
    unsigned long mfn, old_cr4, old_base_mfn;
    int error = 0;

    error |= __vmwrite(GUEST_RIP, c->eip);
    error |= __vmwrite(GUEST_RSP, c->esp);
    error |= __vmwrite(GUEST_RFLAGS, c->eflags);

    error |= __vmwrite(CR0_READ_SHADOW, c->cr0);

    if (!vmx_paging_enabled(v)) {
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "switching to vmxassist. use phys table");
        __vmwrite(GUEST_CR3, pagetable_get_paddr(v->domain->arch.phys_table));
        goto skip_cr3;
    }

    if (c->cr3 == v->arch.hvm_vmx.cpu_cr3) {
        /*
         * This is simple TLB flush, implying the guest has
         * removed some translation or changed page attributes.
         * We simply invalidate the shadow.
         */
        mfn = get_mfn_from_gpfn(c->cr3 >> PAGE_SHIFT);
        if (mfn != pagetable_get_pfn(v->arch.guest_table)) {
            printk("Invalid CR3 value=%x", c->cr3);
            domain_crash_synchronous();
            return 0;
        }
        shadow_sync_all(v->domain);
    } else {
        /*
         * If different, make a shadow. Check if the PDBR is valid
         * first.
         */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 c->cr3 = %x", c->cr3);
        if ((c->cr3 >> PAGE_SHIFT) > v->domain->max_pages) {
            printk("Invalid CR3 value=%x", c->cr3);
            domain_crash_synchronous();
            return 0;
        }
        mfn = get_mfn_from_gpfn(c->cr3 >> PAGE_SHIFT);
        if(!get_page(mfn_to_page(mfn), v->domain))
                return 0;
        old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
        v->arch.guest_table = mk_pagetable((u64)mfn << PAGE_SHIFT);
        if (old_base_mfn)
             put_page(mfn_to_page(old_base_mfn));
        /*
         * arch.shadow_table should now hold the next CR3 for shadow
         */
        v->arch.hvm_vmx.cpu_cr3 = c->cr3;
        update_pagetables(v);
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %x", c->cr3);
        __vmwrite(GUEST_CR3, pagetable_get_paddr(v->arch.shadow_table));
    }

 skip_cr3:

    error |= __vmread(CR4_READ_SHADOW, &old_cr4);
    error |= __vmwrite(GUEST_CR4, (c->cr4 | VMX_CR4_HOST_MASK));
    error |= __vmwrite(CR4_READ_SHADOW, c->cr4);

    error |= __vmwrite(GUEST_IDTR_LIMIT, c->idtr_limit);
    error |= __vmwrite(GUEST_IDTR_BASE, c->idtr_base);

    error |= __vmwrite(GUEST_GDTR_LIMIT, c->gdtr_limit);
    error |= __vmwrite(GUEST_GDTR_BASE, c->gdtr_base);

    error |= __vmwrite(GUEST_CS_SELECTOR, c->cs_sel);
    error |= __vmwrite(GUEST_CS_LIMIT, c->cs_limit);
    error |= __vmwrite(GUEST_CS_BASE, c->cs_base);
    error |= __vmwrite(GUEST_CS_AR_BYTES, c->cs_arbytes.bytes);

    error |= __vmwrite(GUEST_DS_SELECTOR, c->ds_sel);
    error |= __vmwrite(GUEST_DS_LIMIT, c->ds_limit);
    error |= __vmwrite(GUEST_DS_BASE, c->ds_base);
    error |= __vmwrite(GUEST_DS_AR_BYTES, c->ds_arbytes.bytes);

    error |= __vmwrite(GUEST_ES_SELECTOR, c->es_sel);
    error |= __vmwrite(GUEST_ES_LIMIT, c->es_limit);
    error |= __vmwrite(GUEST_ES_BASE, c->es_base);
    error |= __vmwrite(GUEST_ES_AR_BYTES, c->es_arbytes.bytes);

    error |= __vmwrite(GUEST_SS_SELECTOR, c->ss_sel);
    error |= __vmwrite(GUEST_SS_LIMIT, c->ss_limit);
    error |= __vmwrite(GUEST_SS_BASE, c->ss_base);
    error |= __vmwrite(GUEST_SS_AR_BYTES, c->ss_arbytes.bytes);

    error |= __vmwrite(GUEST_FS_SELECTOR, c->fs_sel);
    error |= __vmwrite(GUEST_FS_LIMIT, c->fs_limit);
    error |= __vmwrite(GUEST_FS_BASE, c->fs_base);
    error |= __vmwrite(GUEST_FS_AR_BYTES, c->fs_arbytes.bytes);

    error |= __vmwrite(GUEST_GS_SELECTOR, c->gs_sel);
    error |= __vmwrite(GUEST_GS_LIMIT, c->gs_limit);
    error |= __vmwrite(GUEST_GS_BASE, c->gs_base);
    error |= __vmwrite(GUEST_GS_AR_BYTES, c->gs_arbytes.bytes);

    error |= __vmwrite(GUEST_TR_SELECTOR, c->tr_sel);
    error |= __vmwrite(GUEST_TR_LIMIT, c->tr_limit);
    error |= __vmwrite(GUEST_TR_BASE, c->tr_base);
    error |= __vmwrite(GUEST_TR_AR_BYTES, c->tr_arbytes.bytes);

    error |= __vmwrite(GUEST_LDTR_SELECTOR, c->ldtr_sel);
    error |= __vmwrite(GUEST_LDTR_LIMIT, c->ldtr_limit);
    error |= __vmwrite(GUEST_LDTR_BASE, c->ldtr_base);
    error |= __vmwrite(GUEST_LDTR_AR_BYTES, c->ldtr_arbytes.bytes);

    return !error;
}

enum { VMX_ASSIST_INVOKE = 0, VMX_ASSIST_RESTORE };

int
vmx_assist(struct vcpu *v, int mode)
{
    struct vmx_assist_context c;
    u32 magic;
    u32 cp;

    /* make sure vmxassist exists (this is not an error) */
    if (!hvm_copy(&magic, VMXASSIST_MAGIC_OFFSET, sizeof(magic), HVM_COPY_IN))
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
        if (!hvm_copy(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp), HVM_COPY_IN))
            goto error;
        if (cp != 0) {
            if (!vmx_world_save(v, &c))
                goto error;
            if (!hvm_copy(&c, cp, sizeof(c), HVM_COPY_OUT))
                goto error;
        }

        /* restore the new context, this should activate vmxassist */
        if (!hvm_copy(&cp, VMXASSIST_NEW_CONTEXT, sizeof(cp), HVM_COPY_IN))
            goto error;
        if (cp != 0) {
            if (!hvm_copy(&c, cp, sizeof(c), HVM_COPY_IN))
                goto error;
            if (!vmx_world_restore(v, &c))
                goto error;
            return 1;
        }
        break;

        /*
         * Restore the VMXASSIST_OLD_CONTEXT that was saved by VMX_ASSIST_INVOKE
         * above.
         */
    case VMX_ASSIST_RESTORE:
        /* save the old context */
        if (!hvm_copy(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp), HVM_COPY_IN))
            goto error;
        if (cp != 0) {
            if (!hvm_copy(&c, cp, sizeof(c), HVM_COPY_IN))
                goto error;
            if (!vmx_world_restore(v, &c))
                goto error;
            return 1;
        }
        break;
    }

 error:
    printf("Failed to transfer to vmxassist\n");
    domain_crash_synchronous();
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

    /*
     * CR0: We don't want to lose PE and PG.
     */
    __vmread_vcpu(v, CR0_READ_SHADOW, &old_cr0);
    paging_enabled = (old_cr0 & X86_CR0_PE) && (old_cr0 & X86_CR0_PG);

    /* TS cleared? Then initialise FPU now. */
    if ( !(value & X86_CR0_TS) )
    {
        setup_fpu(v);
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);
    }

    __vmwrite(GUEST_CR0, value | X86_CR0_PE | X86_CR0_PG | X86_CR0_NE);
    __vmwrite(CR0_READ_SHADOW, value);

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx\n", value);

    if ( (value & X86_CR0_PE) && (value & X86_CR0_PG) && !paging_enabled )
    {
        unsigned long cr4;

        /*
         * Trying to enable guest paging.
         * The guest CR3 must be pointing to the guest physical.
         */
        if ( !VALID_MFN(mfn = get_mfn_from_gpfn(
            v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT)) ||
             !get_page(mfn_to_page(mfn), v->domain) )
        {
            printk("Invalid CR3 value = %lx", v->arch.hvm_vmx.cpu_cr3);
            domain_crash_synchronous(); /* need to take a clean path */
        }

#if defined(__x86_64__)
        if ( test_bit(VMX_CPU_STATE_LME_ENABLED,
                      &v->arch.hvm_vmx.cpu_state) &&
             !test_bit(VMX_CPU_STATE_PAE_ENABLED,
                       &v->arch.hvm_vmx.cpu_state) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Enable paging before PAE enabled\n");
            vmx_inject_exception(v, TRAP_gp_fault, 0);
        }

        if ( test_bit(VMX_CPU_STATE_LME_ENABLED,
                     &v->arch.hvm_vmx.cpu_state) )
        {
            /* Here the PAE is should be opened */
            HVM_DBG_LOG(DBG_LEVEL_1, "Enable long mode\n");
            set_bit(VMX_CPU_STATE_LMA_ENABLED,
                    &v->arch.hvm_vmx.cpu_state);

            __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
            vm_entry_value |= VM_ENTRY_CONTROLS_IA32E_MODE;
            __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);

            if ( !shadow_set_guest_paging_levels(v->domain, 4) ) {
                printk("Unsupported guest paging levels\n");
                domain_crash_synchronous(); /* need to take a clean path */
            }
        }
        else
#endif  /* __x86_64__ */
        {
#if CONFIG_PAGING_LEVELS >= 3
            if ( !shadow_set_guest_paging_levels(v->domain, 2) ) {
                printk("Unsupported guest paging levels\n");
                domain_crash_synchronous(); /* need to take a clean path */
            }
#endif
        }

        /* update CR4's PAE if needed */
        __vmread(GUEST_CR4, &cr4);
        if ( (!(cr4 & X86_CR4_PAE)) &&
             test_bit(VMX_CPU_STATE_PAE_ENABLED,
                      &v->arch.hvm_vmx.cpu_state) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "enable PAE in cr4\n");
            __vmwrite(GUEST_CR4, cr4 | X86_CR4_PAE);
        }

        /*
         * Now arch.guest_table points to machine physical.
         */
        v->arch.guest_table = mk_pagetable((u64)mfn << PAGE_SHIFT);
        update_pagetables(v);

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                    (unsigned long) (mfn << PAGE_SHIFT));

        __vmwrite(GUEST_CR3, pagetable_get_paddr(v->arch.shadow_table));
        /*
         * arch->shadow_table should hold the next CR3 for shadow
         */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                    v->arch.hvm_vmx.cpu_cr3, mfn);
    }

    if ( !((value & X86_CR0_PE) && (value & X86_CR0_PG)) && paging_enabled )
        if ( v->arch.hvm_vmx.cpu_cr3 ) {
            put_page(mfn_to_page(get_mfn_from_gpfn(
                      v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT)));
            v->arch.guest_table = mk_pagetable(0);
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
            vmx_inject_exception(v, TRAP_gp_fault, 0);
            return 0;
        } else {
            /*
             * Disable paging here.
             * Same to PE == 1 && PG == 0
             */
            if ( test_bit(VMX_CPU_STATE_LMA_ENABLED,
                          &v->arch.hvm_vmx.cpu_state) )
            {
                clear_bit(VMX_CPU_STATE_LMA_ENABLED,
                          &v->arch.hvm_vmx.cpu_state);
                __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
                vm_entry_value &= ~VM_ENTRY_CONTROLS_IA32E_MODE;
                __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
            }
        }

        clear_all_shadow_status(v->domain);
        if ( vmx_assist(v, VMX_ASSIST_INVOKE) ) {
            set_bit(VMX_CPU_STATE_ASSIST_ENABLED, &v->arch.hvm_vmx.cpu_state);
            __vmread(GUEST_RIP, &eip);
            HVM_DBG_LOG(DBG_LEVEL_1,
                        "Transfering control to vmxassist %%eip 0x%lx\n", eip);
            return 0; /* do not update eip! */
        }
    } else if ( test_bit(VMX_CPU_STATE_ASSIST_ENABLED,
                         &v->arch.hvm_vmx.cpu_state) )
    {
        __vmread(GUEST_RIP, &eip);
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Enabling CR0.PE at %%eip 0x%lx\n", eip);
        if ( vmx_assist(v, VMX_ASSIST_RESTORE) )
        {
            clear_bit(VMX_CPU_STATE_ASSIST_ENABLED,
                      &v->arch.hvm_vmx.cpu_state);
            __vmread(GUEST_RIP, &eip);
            HVM_DBG_LOG(DBG_LEVEL_1,
                        "Restoring to %%eip 0x%lx\n", eip);
            return 0; /* do not update eip! */
        }
    }

    return 1;
}

#define CASE_GET_REG(REG, reg)  \
    case REG_ ## REG: value = regs->reg; break

#define CASE_EXTEND_SET_REG \
      CASE_EXTEND_REG(S)
#define CASE_EXTEND_GET_REG \
      CASE_EXTEND_REG(G)

#ifdef __i386__
#define CASE_EXTEND_REG(T)
#else
#define CASE_EXTEND_REG(T)    \
    CASE_ ## T ## ET_REG(R8, r8); \
    CASE_ ## T ## ET_REG(R9, r9); \
    CASE_ ## T ## ET_REG(R10, r10); \
    CASE_ ## T ## ET_REG(R11, r11); \
    CASE_ ## T ## ET_REG(R12, r12); \
    CASE_ ## T ## ET_REG(R13, r13); \
    CASE_ ## T ## ET_REG(R14, r14); \
    CASE_ ## T ## ET_REG(R15, r15);
#endif


/*
 * Write to control registers
 */
static int mov_to_cr(int gp, int cr, struct cpu_user_regs *regs)
{
    unsigned long value;
    unsigned long old_cr;
    struct vcpu *v = current;

    switch (gp) {
        CASE_GET_REG(EAX, eax);
        CASE_GET_REG(ECX, ecx);
        CASE_GET_REG(EDX, edx);
        CASE_GET_REG(EBX, ebx);
        CASE_GET_REG(EBP, ebp);
        CASE_GET_REG(ESI, esi);
        CASE_GET_REG(EDI, edi);
        CASE_EXTEND_GET_REG
            case REG_ESP:
                __vmread(GUEST_RSP, &value);
        break;
    default:
        printk("invalid gp: %d\n", gp);
        __hvm_bug(regs);
    }

    HVM_DBG_LOG(DBG_LEVEL_1, "mov_to_cr: CR%d, value = %lx,", cr, value);
    HVM_DBG_LOG(DBG_LEVEL_1, "current = %lx,", (unsigned long) current);

    switch(cr) {
    case 0:
    {
        return vmx_set_cr0(value);
    }
    case 3:
    {
        unsigned long old_base_mfn, mfn;

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
                __hvm_bug(regs);
            shadow_sync_all(v->domain);
        } else {
            /*
             * If different, make a shadow. Check if the PDBR is valid
             * first.
             */
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
            if ( ((value >> PAGE_SHIFT) > v->domain->max_pages ) ||
                 !VALID_MFN(mfn = get_mfn_from_gpfn(value >> PAGE_SHIFT)) ||
                 !get_page(mfn_to_page(mfn), v->domain) )
            {
                printk("Invalid CR3 value=%lx", value);
                domain_crash_synchronous(); /* need to take a clean path */
            }
            old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
            v->arch.guest_table = mk_pagetable((u64)mfn << PAGE_SHIFT);
            if (old_base_mfn)
                put_page(mfn_to_page(old_base_mfn));
            /*
             * arch.shadow_table should now hold the next CR3 for shadow
             */
#if CONFIG_PAGING_LEVELS >= 3
            if ( v->domain->arch.ops->guest_paging_levels == PAGING_L3 )
                shadow_sync_all(v->domain);
#endif

            v->arch.hvm_vmx.cpu_cr3 = value;
            update_pagetables(v);
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx",
                        value);
            __vmwrite(GUEST_CR3, pagetable_get_paddr(v->arch.shadow_table));
        }
        break;
    }
    case 4: /* CR4 */
    {
        __vmread(CR4_READ_SHADOW, &old_cr);

        if ( value & X86_CR4_PAE && !(old_cr & X86_CR4_PAE) )
        {
            set_bit(VMX_CPU_STATE_PAE_ENABLED, &v->arch.hvm_vmx.cpu_state);

            if ( vmx_pgbit_test(v) )
            {
                /* The guest is 32 bit. */
#if CONFIG_PAGING_LEVELS >= 4
                unsigned long mfn, old_base_mfn;

                if( !shadow_set_guest_paging_levels(v->domain, 3) )
                {
                    printk("Unsupported guest paging levels\n");
                    domain_crash_synchronous(); /* need to take a clean path */
                }

                if ( !VALID_MFN(mfn = get_mfn_from_gpfn(
                                    v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT)) ||
                     !get_page(mfn_to_page(mfn), v->domain) )
                {
                    printk("Invalid CR3 value = %lx", v->arch.hvm_vmx.cpu_cr3);
                    domain_crash_synchronous(); /* need to take a clean path */
                }

                old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
                if ( old_base_mfn )
                    put_page(mfn_to_page(old_base_mfn));

                /*
                 * Now arch.guest_table points to machine physical.
                 */

                v->arch.guest_table = mk_pagetable((u64)mfn << PAGE_SHIFT);
                update_pagetables(v);

                HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                            (unsigned long) (mfn << PAGE_SHIFT));

                __vmwrite(GUEST_CR3, pagetable_get_paddr(v->arch.shadow_table));

                /*
                 * arch->shadow_table should hold the next CR3 for shadow
                 */

                HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                            v->arch.hvm_vmx.cpu_cr3, mfn);
#endif
            }
            else
            {
                /*  The guest is 64 bit. */
#if CONFIG_PAGING_LEVELS >= 4
                if ( !shadow_set_guest_paging_levels(v->domain, 4) )
                {
                    printk("Unsupported guest paging levels\n");
                    domain_crash_synchronous(); /* need to take a clean path */
                }
#endif
            }
        }
        else if ( value & X86_CR4_PAE )
            set_bit(VMX_CPU_STATE_PAE_ENABLED, &v->arch.hvm_vmx.cpu_state);
        else
        {
            if ( test_bit(VMX_CPU_STATE_LMA_ENABLED, &v->arch.hvm_vmx.cpu_state) )
                vmx_inject_exception(v, TRAP_gp_fault, 0);

            clear_bit(VMX_CPU_STATE_PAE_ENABLED, &v->arch.hvm_vmx.cpu_state);
        }

        __vmwrite(GUEST_CR4, value| VMX_CR4_HOST_MASK);
        __vmwrite(CR4_READ_SHADOW, value);

        /*
         * Writing to CR4 to modify the PSE, PGE, or PAE flag invalidates
         * all TLB entries except global entries.
         */
        if ( (old_cr ^ value) & (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE) )
            shadow_sync_all(v->domain);

        break;
    }
    default:
        printk("invalid cr: %d\n", gp);
        __hvm_bug(regs);
    }

    return 1;
}

#define CASE_SET_REG(REG, reg)      \
    case REG_ ## REG:       \
    regs->reg = value;      \
    break

/*
 * Read from control registers. CR0 and CR4 are read from the shadow.
 */
static void mov_from_cr(int cr, int gp, struct cpu_user_regs *regs)
{
    unsigned long value;
    struct vcpu *v = current;

    if (cr != 3)
        __hvm_bug(regs);

    value = (unsigned long) v->arch.hvm_vmx.cpu_cr3;

    switch (gp) {
        CASE_SET_REG(EAX, eax);
        CASE_SET_REG(ECX, ecx);
        CASE_SET_REG(EDX, edx);
        CASE_SET_REG(EBX, ebx);
        CASE_SET_REG(EBP, ebp);
        CASE_SET_REG(ESI, esi);
        CASE_SET_REG(EDI, edi);
        CASE_EXTEND_SET_REG
            case REG_ESP:
                __vmwrite(GUEST_RSP, value);
        regs->esp = value;
        break;
    default:
        printk("invalid gp: %d\n", gp);
        __hvm_bug(regs);
    }

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "mov_from_cr: CR%d, value = %lx,", cr, value);
}

static int vmx_cr_access(unsigned long exit_qualification, struct cpu_user_regs *regs)
{
    unsigned int gp, cr;
    unsigned long value;
    struct vcpu *v = current;

    switch (exit_qualification & CONTROL_REG_ACCESS_TYPE) {
    case TYPE_MOV_TO_CR:
        gp = exit_qualification & CONTROL_REG_ACCESS_REG;
        cr = exit_qualification & CONTROL_REG_ACCESS_NUM;
        TRACE_VMEXIT(1,TYPE_MOV_TO_CR);
        TRACE_VMEXIT(2,cr);
        TRACE_VMEXIT(3,gp);
        return mov_to_cr(gp, cr, regs);
    case TYPE_MOV_FROM_CR:
        gp = exit_qualification & CONTROL_REG_ACCESS_REG;
        cr = exit_qualification & CONTROL_REG_ACCESS_NUM;
        TRACE_VMEXIT(1,TYPE_MOV_FROM_CR);
        TRACE_VMEXIT(2,cr);
        TRACE_VMEXIT(3,gp);
        mov_from_cr(cr, gp, regs);
        break;
    case TYPE_CLTS:
        TRACE_VMEXIT(1,TYPE_CLTS);

        /* We initialise the FPU now, to avoid needing another vmexit. */
        setup_fpu(v);
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);

        __vmread_vcpu(v, GUEST_CR0, &value);
        value &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(GUEST_CR0, value);

        __vmread_vcpu(v, CR0_READ_SHADOW, &value);
        value &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(CR0_READ_SHADOW, value);
        break;
    case TYPE_LMSW:
        TRACE_VMEXIT(1,TYPE_LMSW);
        __vmread_vcpu(v, CR0_READ_SHADOW, &value);
        value = (value & ~0xF) |
            (((exit_qualification & LMSW_SOURCE_DATA) >> 16) & 0xF);
        return vmx_set_cr0(value);
        break;
    default:
        __hvm_bug(regs);
        break;
    }
    return 1;
}

static inline void vmx_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    struct vcpu *v = current;

    HVM_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_read: ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
    switch (regs->ecx) {
    case MSR_IA32_TIME_STAMP_COUNTER:
    {
        struct hvm_virpit *vpit;

        rdtscll(msr_content);
        vpit = &(v->domain->arch.hvm_domain.vpit);
        msr_content += vpit->shift;
        break;
    }
    case MSR_IA32_SYSENTER_CS:
        __vmread(GUEST_SYSENTER_CS, (u32 *)&msr_content);
        break;
    case MSR_IA32_SYSENTER_ESP:
        __vmread(GUEST_SYSENTER_ESP, &msr_content);
        break;
    case MSR_IA32_SYSENTER_EIP:
        __vmread(GUEST_SYSENTER_EIP, &msr_content);
        break;
    case MSR_IA32_APICBASE:
        msr_content = VLAPIC(v) ? VLAPIC(v)->apic_base_msr : 0;
        break;
    default:
        if(long_mode_do_msr_read(regs))
            return;
        rdmsr_safe(regs->ecx, regs->eax, regs->edx);
        break;
    }

    regs->eax = msr_content & 0xFFFFFFFF;
    regs->edx = msr_content >> 32;

    HVM_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_read returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
}

static inline void vmx_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content;
    struct vcpu *v = current;

    HVM_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_write: ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);

    msr_content = (regs->eax & 0xFFFFFFFF) | ((u64)regs->edx << 32);

    switch (regs->ecx) {
    case MSR_IA32_TIME_STAMP_COUNTER:
    {
        struct hvm_virpit *vpit;
        u64 host_tsc, drift;

        rdtscll(host_tsc);
        vpit = &(v->domain->arch.hvm_domain.vpit);
        drift = v->arch.hvm_vmx.tsc_offset - vpit->shift;
        vpit->shift = msr_content - host_tsc;
	v->arch.hvm_vmx.tsc_offset = vpit->shift + drift;
        __vmwrite(TSC_OFFSET, vpit->shift);

#if defined (__i386__)
        __vmwrite(TSC_OFFSET_HIGH, ((vpit->shift)>>32));
#endif
        break;
    }
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
        vlapic_msr_set(VLAPIC(v), msr_content);
        break;
    default:
        long_mode_do_msr_write(regs);
        break;
    }

    HVM_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_write returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
}

/*
 * Need to use this exit to reschedule
 */
void vmx_vmexit_do_hlt(void)
{
    struct vcpu *v=current;
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);
    s_time_t   next_pit=-1,next_wakeup;

    if ( !v->vcpu_id )
        next_pit = get_pit_scheduled(v,vpit);
    next_wakeup = get_apictime_scheduled(v);
    if ( (next_pit != -1 && next_pit < next_wakeup) || next_wakeup == -1 )
        next_wakeup = next_pit;
    if ( next_wakeup != - 1 ) 
        set_timer(&current->arch.hvm_vmx.hlt_timer, next_wakeup);
    hvm_safe_block();
}

static inline void vmx_vmexit_do_extint(struct cpu_user_regs *regs)
{
    unsigned int vector;
    int error;

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

    if ((error = __vmread(VM_EXIT_INTR_INFO, &vector))
        && !(vector & INTR_INFO_VALID_MASK))
        __hvm_bug(regs);

    vector &= 0xff;
    local_irq_disable();

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

#if defined (__x86_64__)
void store_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_RSP, &regs->rsp);
    __vmread(GUEST_RFLAGS, &regs->rflags);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_RIP, &regs->rip);
}
#elif defined (__i386__)
void store_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_RSP, &regs->esp);
    __vmread(GUEST_RFLAGS, &regs->eflags);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_RIP, &regs->eip);
}
#endif 

#ifdef XEN_DEBUGGER
void save_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->xss);
    __vmread(GUEST_RSP, &regs->esp);
    __vmread(GUEST_RFLAGS, &regs->eflags);
    __vmread(GUEST_CS_SELECTOR, &regs->xcs);
    __vmread(GUEST_RIP, &regs->eip);

    __vmread(GUEST_GS_SELECTOR, &regs->xgs);
    __vmread(GUEST_FS_SELECTOR, &regs->xfs);
    __vmread(GUEST_ES_SELECTOR, &regs->xes);
    __vmread(GUEST_DS_SELECTOR, &regs->xds);
}

void restore_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmwrite(GUEST_SS_SELECTOR, regs->xss);
    __vmwrite(GUEST_RSP, regs->esp);
    __vmwrite(GUEST_RFLAGS, regs->eflags);
    __vmwrite(GUEST_CS_SELECTOR, regs->xcs);
    __vmwrite(GUEST_RIP, regs->eip);

    __vmwrite(GUEST_GS_SELECTOR, regs->xgs);
    __vmwrite(GUEST_FS_SELECTOR, regs->xfs);
    __vmwrite(GUEST_ES_SELECTOR, regs->xes);
    __vmwrite(GUEST_DS_SELECTOR, regs->xds);
}
#endif

asmlinkage void vmx_vmexit_handler(struct cpu_user_regs regs)
{
    unsigned int exit_reason, idtv_info_field;
    unsigned long exit_qualification, eip, inst_len = 0;
    struct vcpu *v = current;
    int error;

    if ((error = __vmread(VM_EXIT_REASON, &exit_reason)))
        __hvm_bug(&regs);

    perfc_incra(vmexits, exit_reason);

    __vmread(IDT_VECTORING_INFO_FIELD, &idtv_info_field);
    if (idtv_info_field & INTR_INFO_VALID_MASK) {
        __vmwrite(VM_ENTRY_INTR_INFO_FIELD, idtv_info_field);

        __vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
        if (inst_len >= 1 && inst_len <= 15)
            __vmwrite(VM_ENTRY_INSTRUCTION_LEN, inst_len);

        if (idtv_info_field & 0x800) { /* valid error code */
            unsigned long error_code;
            __vmread(IDT_VECTORING_ERROR_CODE, &error_code);
            __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
        }

        HVM_DBG_LOG(DBG_LEVEL_1, "idtv_info_field=%x", idtv_info_field);
    }

    /* don't bother H/W interrutps */
    if (exit_reason != EXIT_REASON_EXTERNAL_INTERRUPT &&
        exit_reason != EXIT_REASON_VMCALL &&
        exit_reason != EXIT_REASON_IO_INSTRUCTION) 
        HVM_DBG_LOG(DBG_LEVEL_0, "exit reason = %x", exit_reason);

    if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
        printk("Failed vm entry\n");
        domain_crash_synchronous();
        return;
    }

    {
        __vmread(GUEST_RIP, &eip);
        TRACE_3D(TRC_VMX_VMEXIT, v->domain->domain_id, eip, exit_reason);
        TRACE_VMEXIT(0,exit_reason);
    }

    switch (exit_reason) {
    case EXIT_REASON_EXCEPTION_NMI:
    {
        /*
         * We don't set the software-interrupt exiting (INT n).
         * (1) We can get an exception (e.g. #PG) in the guest, or
         * (2) NMI
         */
        int error;
        unsigned int vector;
        unsigned long va;

        if ((error = __vmread(VM_EXIT_INTR_INFO, &vector))
            || !(vector & INTR_INFO_VALID_MASK))
            __hvm_bug(&regs);
        vector &= 0xff;

        TRACE_VMEXIT(1,vector);
        perfc_incra(cause_vector, vector);

        TRACE_3D(TRC_VMX_VECTOR, v->domain->domain_id, eip, vector);
        switch (vector) {
#ifdef XEN_DEBUGGER
        case TRAP_debug:
        {
            save_cpu_user_regs(&regs);
            pdb_handle_exception(1, &regs, 1);
            restore_cpu_user_regs(&regs);
            break;
        }
        case TRAP_int3:
        {
            save_cpu_user_regs(&regs);
            pdb_handle_exception(3, &regs, 1);
            restore_cpu_user_regs(&regs);
            break;
        }
#else
        case TRAP_debug:
        {
            void store_cpu_user_regs(struct cpu_user_regs *regs);

            store_cpu_user_regs(&regs);
            __vm_clear_bit(GUEST_PENDING_DBG_EXCEPTIONS, PENDING_DEBUG_EXC_BS);

            domain_pause_for_debugger();

            break;
        }
#endif
        case TRAP_no_device:
        {
            vmx_do_no_device_fault();
            break;
        }
        case TRAP_page_fault:
        {
            __vmread(EXIT_QUALIFICATION, &va);
            __vmread(VM_EXIT_INTR_ERROR_CODE, &regs.error_code);

            TRACE_VMEXIT(3,regs.error_code);
            TRACE_VMEXIT(4,va);

            HVM_DBG_LOG(DBG_LEVEL_VMMU,
                        "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                        (unsigned long)regs.eax, (unsigned long)regs.ebx,
                        (unsigned long)regs.ecx, (unsigned long)regs.edx,
                        (unsigned long)regs.esi, (unsigned long)regs.edi);
            v->arch.hvm_vcpu.mmio_op.inst_decoder_regs = &regs;

            if (!(error = vmx_do_page_fault(va, &regs))) {
                /*
                 * Inject #PG using Interruption-Information Fields
                 */
                vmx_inject_exception(v, TRAP_page_fault, regs.error_code);
                v->arch.hvm_vmx.cpu_cr2 = va;
                TRACE_3D(TRC_VMX_INT, v->domain->domain_id, TRAP_page_fault, va);
            }
            break;
        }
        case TRAP_nmi:
            do_nmi(&regs);
            break;
        default:
            vmx_reflect_exception(v);
            break;
        }
        break;
    }
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        vmx_vmexit_do_extint(&regs);
        break;
    case EXIT_REASON_PENDING_INTERRUPT:
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                  MONITOR_CPU_BASED_EXEC_CONTROLS);
        v->arch.hvm_vcpu.u.vmx.exec_control = MONITOR_CPU_BASED_EXEC_CONTROLS;
        break;
    case EXIT_REASON_TASK_SWITCH:
        __hvm_bug(&regs);
        break;
    case EXIT_REASON_CPUID:
        __get_instruction_length(inst_len);
        vmx_vmexit_do_cpuid(regs.eax, &regs);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_HLT:
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        vmx_vmexit_do_hlt();
        break;
    case EXIT_REASON_INVLPG:
    {
        unsigned long   va;

        __vmread(EXIT_QUALIFICATION, &va);
        vmx_vmexit_do_invlpg(va);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    }
#if 0 /* keep this for debugging */
    case EXIT_REASON_VMCALL:
        __get_instruction_length(inst_len);
        __vmread(GUEST_RIP, &eip);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);

        hvm_print_line(v, regs.eax); /* provides the current domain */
        __update_guest_eip(inst_len);
        break;
#endif
    case EXIT_REASON_CR_ACCESS:
    {
        __vmread(GUEST_RIP, &eip);
        __get_instruction_length(inst_len);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);

        HVM_DBG_LOG(DBG_LEVEL_1, "eip = %lx, inst_len =%lx, exit_qualification = %lx",
                    eip, inst_len, exit_qualification);
        if (vmx_cr_access(exit_qualification, &regs))
            __update_guest_eip(inst_len);
        TRACE_VMEXIT(3,regs.error_code);
        TRACE_VMEXIT(4,exit_qualification);
        break;
    }
    case EXIT_REASON_DR_ACCESS:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        vmx_dr_access(exit_qualification, &regs);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_IO_INSTRUCTION:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        __get_instruction_length(inst_len);
        vmx_io_instruction(&regs, exit_qualification, inst_len);
        TRACE_VMEXIT(4,exit_qualification);
        break;
    case EXIT_REASON_MSR_READ:
        __get_instruction_length(inst_len);
        vmx_do_msr_read(&regs);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_MSR_WRITE:
        __vmread(GUEST_RIP, &eip);
        vmx_do_msr_write(&regs);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_MWAIT_INSTRUCTION:
        __hvm_bug(&regs);
        break;
    case EXIT_REASON_VMCALL:
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMOFF:
    case EXIT_REASON_VMON:
        /* Report invalid opcode exception when a VMX guest tries to execute 
            any of the VMX instructions */
        vmx_inject_exception(v, TRAP_invalid_op, VMX_DELIVER_NO_ERROR_CODE);
        break;

    default:
        __hvm_bug(&regs);       /* should not happen */
    }
}

asmlinkage void vmx_load_cr2(void)
{
    struct vcpu *v = current;

    local_irq_disable();
#ifdef __i386__
    asm volatile("movl %0,%%cr2": :"r" (v->arch.hvm_vmx.cpu_cr2));
#else
    asm volatile("movq %0,%%cr2": :"r" (v->arch.hvm_vmx.cpu_cr2));
#endif
}

asmlinkage void vmx_trace_vmentry (void)
{
    TRACE_5D(TRC_VMENTRY,
             trace_values[smp_processor_id()][0],
             trace_values[smp_processor_id()][1],
             trace_values[smp_processor_id()][2],
             trace_values[smp_processor_id()][3],
             trace_values[smp_processor_id()][4]);
    TRACE_VMEXIT(0,9);
    TRACE_VMEXIT(1,9);
    TRACE_VMEXIT(2,9);
    TRACE_VMEXIT(3,9);
    TRACE_VMEXIT(4,9);
    return;
}

asmlinkage void vmx_trace_vmexit (void)
{
    TRACE_3D(TRC_VMEXIT,0,0,0);
    return;
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
