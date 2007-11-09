/*
 * vmcs.c: VMCS management
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
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/flushtlb.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/keyhandler.h>
#include <asm/shadow.h>
#include <asm/tboot.h>

/* Dynamic (run-time adjusted) execution control flags. */
u32 vmx_pin_based_exec_control __read_mostly;
u32 vmx_cpu_based_exec_control __read_mostly;
u32 vmx_secondary_exec_control __read_mostly;
u32 vmx_vmexit_control __read_mostly;
u32 vmx_vmentry_control __read_mostly;
bool_t cpu_has_vmx_ins_outs_instr_info __read_mostly;

static DEFINE_PER_CPU(struct vmcs_struct *, host_vmcs);
static DEFINE_PER_CPU(struct vmcs_struct *, current_vmcs);
static DEFINE_PER_CPU(struct list_head, active_vmcs_list);

static u32 vmcs_revision_id __read_mostly;

static u32 adjust_vmx_controls(u32 ctl_min, u32 ctl_opt, u32 msr)
{
    u32 vmx_msr_low, vmx_msr_high, ctl = ctl_min | ctl_opt;

    rdmsr(msr, vmx_msr_low, vmx_msr_high);

    ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
    ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

    /* Ensure minimum (required) set of control bits are supported. */
    BUG_ON(ctl_min & ~ctl);

    return ctl;
}

static void vmx_init_vmcs_config(void)
{
    u32 vmx_msr_low, vmx_msr_high, min, opt;
    u32 _vmx_pin_based_exec_control;
    u32 _vmx_cpu_based_exec_control;
    u32 _vmx_secondary_exec_control = 0;
    u32 _vmx_vmexit_control;
    u32 _vmx_vmentry_control;

    min = (PIN_BASED_EXT_INTR_MASK |
           PIN_BASED_NMI_EXITING);
    opt = PIN_BASED_VIRTUAL_NMIS;
    _vmx_pin_based_exec_control = adjust_vmx_controls(
        min, opt, MSR_IA32_VMX_PINBASED_CTLS);

    min = (CPU_BASED_HLT_EXITING |
           CPU_BASED_INVLPG_EXITING |
           CPU_BASED_MONITOR_EXITING |
           CPU_BASED_MWAIT_EXITING |
           CPU_BASED_MOV_DR_EXITING |
           CPU_BASED_ACTIVATE_IO_BITMAP |
           CPU_BASED_USE_TSC_OFFSETING);
    opt  = CPU_BASED_ACTIVATE_MSR_BITMAP;
    opt |= CPU_BASED_TPR_SHADOW;
    opt |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    _vmx_cpu_based_exec_control = adjust_vmx_controls(
        min, opt, MSR_IA32_VMX_PROCBASED_CTLS);
#ifdef __x86_64__
    if ( !(_vmx_cpu_based_exec_control & CPU_BASED_TPR_SHADOW) )
    {
        min |= CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING;
        _vmx_cpu_based_exec_control = adjust_vmx_controls(
            min, opt, MSR_IA32_VMX_PROCBASED_CTLS);
    }
#endif

    if ( _vmx_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS )
    {
        min = 0;
        opt = (SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
               SECONDARY_EXEC_WBINVD_EXITING);
        _vmx_secondary_exec_control = adjust_vmx_controls(
            min, opt, MSR_IA32_VMX_PROCBASED_CTLS2);
    }

#if defined(__i386__)
    /* If we can't virtualise APIC accesses, the TPR shadow is pointless. */
    if ( !(_vmx_secondary_exec_control &
           SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES) )
        _vmx_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif

    min = VM_EXIT_ACK_INTR_ON_EXIT;
    opt = 0;
#ifdef __x86_64__
    min |= VM_EXIT_IA32E_MODE;
#endif
    _vmx_vmexit_control = adjust_vmx_controls(
        min, opt, MSR_IA32_VMX_EXIT_CTLS);

    min = opt = 0;
    _vmx_vmentry_control = adjust_vmx_controls(
        min, opt, MSR_IA32_VMX_ENTRY_CTLS);

    rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

    if ( !vmx_pin_based_exec_control )
    {
        /* First time through. */
        vmcs_revision_id = vmx_msr_low;
        vmx_pin_based_exec_control = _vmx_pin_based_exec_control;
        vmx_cpu_based_exec_control = _vmx_cpu_based_exec_control;
        vmx_secondary_exec_control = _vmx_secondary_exec_control;
        vmx_vmexit_control         = _vmx_vmexit_control;
        vmx_vmentry_control        = _vmx_vmentry_control;
        cpu_has_vmx_ins_outs_instr_info = !!(vmx_msr_high & (1U<<22));
    }
    else
    {
        /* Globals are already initialised: re-check them. */
        BUG_ON(vmcs_revision_id != vmx_msr_low);
        BUG_ON(vmx_pin_based_exec_control != _vmx_pin_based_exec_control);
        BUG_ON(vmx_cpu_based_exec_control != _vmx_cpu_based_exec_control);
        BUG_ON(vmx_secondary_exec_control != _vmx_secondary_exec_control);
        BUG_ON(vmx_vmexit_control != _vmx_vmexit_control);
        BUG_ON(vmx_vmentry_control != _vmx_vmentry_control);
        BUG_ON(cpu_has_vmx_ins_outs_instr_info != !!(vmx_msr_high & (1U<<22)));
    }

    /* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
    BUG_ON((vmx_msr_high & 0x1fff) > PAGE_SIZE);

#ifdef __x86_64__
    /* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
    BUG_ON(vmx_msr_high & (1u<<16));
#endif

    /* Require Write-Back (WB) memory type for VMCS accesses. */
    BUG_ON(((vmx_msr_high >> 18) & 15) != 6);
}

static struct vmcs_struct *vmx_alloc_vmcs(void)
{
    struct vmcs_struct *vmcs;

    if ( (vmcs = alloc_xenheap_page()) == NULL )
    {
        gdprintk(XENLOG_WARNING, "Failed to allocate VMCS.\n");
        return NULL;
    }

    clear_page(vmcs);
    vmcs->vmcs_revision_id = vmcs_revision_id;

    return vmcs;
}

static void vmx_free_vmcs(struct vmcs_struct *vmcs)
{
    free_xenheap_page(vmcs);
}

static void __vmx_clear_vmcs(void *info)
{
    struct vcpu *v = info;
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    /* Otherwise we can nest (vmx_cpu_down() vs. vmx_clear_vmcs()). */
    ASSERT(!local_irq_is_enabled());

    if ( arch_vmx->active_cpu == smp_processor_id() )
    {
        __vmpclear(virt_to_maddr(arch_vmx->vmcs));

        arch_vmx->active_cpu = -1;
        arch_vmx->launched   = 0;

        list_del(&arch_vmx->active_list);

        if ( arch_vmx->vmcs == this_cpu(current_vmcs) )
            this_cpu(current_vmcs) = NULL;
    }
}

static void vmx_clear_vmcs(struct vcpu *v)
{
    int cpu = v->arch.hvm_vmx.active_cpu;

    if ( cpu != -1 )
        on_selected_cpus(cpumask_of_cpu(cpu), __vmx_clear_vmcs, v, 1, 1);
}

static void vmx_load_vmcs(struct vcpu *v)
{
    unsigned long flags;

    local_irq_save(flags);

    if ( v->arch.hvm_vmx.active_cpu == -1 )
    {
        list_add(&v->arch.hvm_vmx.active_list, &this_cpu(active_vmcs_list));
        v->arch.hvm_vmx.active_cpu = smp_processor_id();
    }

    ASSERT(v->arch.hvm_vmx.active_cpu == smp_processor_id());

    __vmptrld(virt_to_maddr(v->arch.hvm_vmx.vmcs));
    this_cpu(current_vmcs) = v->arch.hvm_vmx.vmcs;

    local_irq_restore(flags);
}

int vmx_cpu_up(void)
{
    u32 eax, edx;
    int cpu = smp_processor_id();
    u64 cr0, vmx_cr0_fixed0, vmx_cr0_fixed1;

    BUG_ON(!(read_cr4() & X86_CR4_VMXE));

    /* 
     * Ensure the current processor operating mode meets 
     * the requred CRO fixed bits in VMX operation. 
     */
    cr0 = read_cr0();
    rdmsrl(MSR_IA32_VMX_CR0_FIXED0, vmx_cr0_fixed0);
    rdmsrl(MSR_IA32_VMX_CR0_FIXED1, vmx_cr0_fixed1);
    if ( (~cr0 & vmx_cr0_fixed0) || (cr0 & ~vmx_cr0_fixed1) )
    {
        printk("CPU%d: some settings of host CR0 are " 
               "not allowed in VMX operation.\n", cpu);
        return 0;
    }

    rdmsr(IA32_FEATURE_CONTROL_MSR, eax, edx);

    if ( eax & IA32_FEATURE_CONTROL_MSR_LOCK )
    {
        if ( !(eax & (IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX |
                      IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX)) )
        {
            printk("CPU%d: VMX disabled by BIOS.\n", cpu);
            return 0;
        }
    }
    else
    {
        eax = (IA32_FEATURE_CONTROL_MSR_LOCK |
               IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX |
               IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX);
        wrmsr(IA32_FEATURE_CONTROL_MSR, eax, 0);
    }

    if ( !tboot_in_measured_env() &&
         !(eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX) )
    {
        printk("VMX only allowed in SMX but SMX not active.\n");
        return 0;
    }

    vmx_init_vmcs_config();

    INIT_LIST_HEAD(&this_cpu(active_vmcs_list));

    if ( this_cpu(host_vmcs) == NULL )
    {
        this_cpu(host_vmcs) = vmx_alloc_vmcs();
        if ( this_cpu(host_vmcs) == NULL )
        {
            printk("CPU%d: Could not allocate host VMCS\n", cpu);
            return 0;
        }
    }

    if ( __vmxon(virt_to_maddr(this_cpu(host_vmcs))) )
    {
        printk("CPU%d: VMXON failed\n", cpu);
        return 0;
    }

    return 1;
}

void vmx_cpu_down(void)
{
    struct list_head *active_vmcs_list = &this_cpu(active_vmcs_list);
    unsigned long flags;

    local_irq_save(flags);

    while ( !list_empty(active_vmcs_list) )
        __vmx_clear_vmcs(list_entry(active_vmcs_list->next,
                                    struct vcpu, arch.hvm_vmx.active_list));

    BUG_ON(!(read_cr4() & X86_CR4_VMXE));
    __vmxoff();

    local_irq_restore(flags);
}

struct foreign_vmcs {
    struct vcpu *v;
    unsigned int count;
};
static DEFINE_PER_CPU(struct foreign_vmcs, foreign_vmcs);

void vmx_vmcs_enter(struct vcpu *v)
{
    struct foreign_vmcs *fv;

    /*
     * NB. We must *always* run an HVM VCPU on its own VMCS, except for
     * vmx_vmcs_enter/exit critical regions.
     */
    if ( likely(v == current) )
        return;

    fv = &this_cpu(foreign_vmcs);

    if ( fv->v == v )
    {
        BUG_ON(fv->count == 0);
    }
    else
    {
        BUG_ON(fv->v != NULL);
        BUG_ON(fv->count != 0);

        vcpu_pause(v);
        spin_lock(&v->arch.hvm_vmx.vmcs_lock);

        vmx_clear_vmcs(v);
        vmx_load_vmcs(v);

        fv->v = v;
    }

    fv->count++;
}

void vmx_vmcs_exit(struct vcpu *v)
{
    struct foreign_vmcs *fv;

    if ( likely(v == current) )
        return;

    fv = &this_cpu(foreign_vmcs);
    BUG_ON(fv->v != v);
    BUG_ON(fv->count == 0);

    if ( --fv->count == 0 )
    {
        /* Don't confuse vmx_do_resume (for @v or @current!) */
        vmx_clear_vmcs(v);
        if ( is_hvm_vcpu(current) )
            vmx_load_vmcs(current);

        spin_unlock(&v->arch.hvm_vmx.vmcs_lock);
        vcpu_unpause(v);

        fv->v = NULL;
    }
}

struct xgt_desc {
    unsigned short size;
    unsigned long address __attribute__((packed));
};

static void vmx_set_host_env(struct vcpu *v)
{
    unsigned int tr, cpu;
    struct xgt_desc desc;

    cpu = smp_processor_id();

    __asm__ __volatile__ ( "sidt (%0) \n" : : "a" (&desc) : "memory" );
    __vmwrite(HOST_IDTR_BASE, desc.address);

    __asm__ __volatile__ ( "sgdt (%0) \n" : : "a" (&desc) : "memory" );
    __vmwrite(HOST_GDTR_BASE, desc.address);

    __asm__ __volatile__ ( "str (%0) \n" : : "a" (&tr) : "memory" );
    __vmwrite(HOST_TR_SELECTOR, tr);
    __vmwrite(HOST_TR_BASE, (unsigned long)&init_tss[cpu]);

    /*
     * Skip end of cpu_user_regs when entering the hypervisor because the
     * CPU does not save context onto the stack. SS,RSP,CS,RIP,RFLAGS,etc
     * all get saved into the VMCS instead.
     */
    __vmwrite(HOST_RSP,
              (unsigned long)&get_cpu_info()->guest_cpu_user_regs.error_code);
}

void vmx_disable_intercept_for_msr(struct vcpu *v, u32 msr)
{
    char *msr_bitmap = v->arch.hvm_vmx.msr_bitmap;

    /* VMX MSR bitmap supported? */
    if ( msr_bitmap == NULL )
        return;

    /*
     * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
     * have the write-low and read-high bitmap offsets the wrong way round.
     * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
     */
    if ( msr <= 0x1fff )
    {
        __clear_bit(msr, msr_bitmap + 0x000); /* read-low */
        __clear_bit(msr, msr_bitmap + 0x800); /* write-low */
    }
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
    {
        msr &= 0x1fff;
        __clear_bit(msr, msr_bitmap + 0x400); /* read-high */
        __clear_bit(msr, msr_bitmap + 0xc00); /* write-high */
    }
}

#define GUEST_SEGMENT_LIMIT     0xffffffff

static int construct_vmcs(struct vcpu *v)
{
    union vmcs_arbytes arbytes;

    vmx_vmcs_enter(v);

    /* VMCS controls. */
    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_control);
    __vmwrite(VM_EXIT_CONTROLS, vmx_vmexit_control);
    __vmwrite(VM_ENTRY_CONTROLS, vmx_vmentry_control);
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, vmx_cpu_based_exec_control);
    v->arch.hvm_vmx.exec_control = vmx_cpu_based_exec_control;
    if ( vmx_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS )
        __vmwrite(SECONDARY_VM_EXEC_CONTROL, vmx_secondary_exec_control);

    /* MSR access bitmap. */
    if ( cpu_has_vmx_msr_bitmap )
    {
        char *msr_bitmap = alloc_xenheap_page();

        if ( msr_bitmap == NULL )
            return -ENOMEM;

        memset(msr_bitmap, ~0, PAGE_SIZE);
        v->arch.hvm_vmx.msr_bitmap = msr_bitmap;
        __vmwrite(MSR_BITMAP, virt_to_maddr(msr_bitmap));

        vmx_disable_intercept_for_msr(v, MSR_FS_BASE);
        vmx_disable_intercept_for_msr(v, MSR_GS_BASE);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_CS);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_ESP);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_EIP);
    }

    /* I/O access bitmap. */
    __vmwrite(IO_BITMAP_A, virt_to_maddr(hvm_io_bitmap));
    __vmwrite(IO_BITMAP_B, virt_to_maddr(hvm_io_bitmap + PAGE_SIZE));

    /* Host data selectors. */
    __vmwrite(HOST_SS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_DS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_ES_SELECTOR, __HYPERVISOR_DS);
#if defined(__i386__)
    __vmwrite(HOST_FS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_GS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_FS_BASE, 0);
    __vmwrite(HOST_GS_BASE, 0);
#elif defined(__x86_64__)
    {
        unsigned long msr;
        rdmsrl(MSR_FS_BASE, msr); __vmwrite(HOST_FS_BASE, msr);
        rdmsrl(MSR_GS_BASE, msr); __vmwrite(HOST_GS_BASE, msr);
    }
#endif

    /* Host control registers. */
    __vmwrite(HOST_CR0, read_cr0() | X86_CR0_TS);
    __vmwrite(HOST_CR4, mmu_cr4_features);

    /* Host CS:RIP. */
    __vmwrite(HOST_CS_SELECTOR, __HYPERVISOR_CS);
    __vmwrite(HOST_RIP, (unsigned long)vmx_asm_vmexit_handler);

    /* MSR intercepts. */
    __vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
    __vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);

    __vmwrite(VM_ENTRY_INTR_INFO, 0);

    __vmwrite(CR0_GUEST_HOST_MASK, ~0UL);
    __vmwrite(CR4_GUEST_HOST_MASK, ~0UL);

    __vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmwrite(CR3_TARGET_COUNT, 0);

    __vmwrite(GUEST_ACTIVITY_STATE, 0);

    /* Guest segment bases. */
    __vmwrite(GUEST_ES_BASE, 0);
    __vmwrite(GUEST_SS_BASE, 0);
    __vmwrite(GUEST_DS_BASE, 0);
    __vmwrite(GUEST_FS_BASE, 0);
    __vmwrite(GUEST_GS_BASE, 0);
    __vmwrite(GUEST_CS_BASE, 0);

    /* Guest segment limits. */
    __vmwrite(GUEST_ES_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_SS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_DS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_FS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_GS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_CS_LIMIT, GUEST_SEGMENT_LIMIT);

    /* Guest segment AR bytes. */
    arbytes.bytes = 0;
    arbytes.fields.seg_type = 0x3;          /* type = 3 */
    arbytes.fields.s = 1;                   /* code or data, i.e. not system */
    arbytes.fields.dpl = 0;                 /* DPL = 3 */
    arbytes.fields.p = 1;                   /* segment present */
    arbytes.fields.default_ops_size = 1;    /* 32-bit */
    arbytes.fields.g = 1;
    arbytes.fields.null_bit = 0;            /* not null */
    __vmwrite(GUEST_ES_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_SS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_DS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_FS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_GS_AR_BYTES, arbytes.bytes);
    arbytes.fields.seg_type = 0xb;          /* type = 0xb */
    __vmwrite(GUEST_CS_AR_BYTES, arbytes.bytes);

    /* Guest GDT. */
    __vmwrite(GUEST_GDTR_BASE, 0);
    __vmwrite(GUEST_GDTR_LIMIT, 0);

    /* Guest IDT. */
    __vmwrite(GUEST_IDTR_BASE, 0);
    __vmwrite(GUEST_IDTR_LIMIT, 0);

    /* Guest LDT and TSS. */
    arbytes.fields.s = 0;                   /* not code or data segement */
    arbytes.fields.seg_type = 0x2;          /* LTD */
    arbytes.fields.default_ops_size = 0;    /* 16-bit */
    arbytes.fields.g = 0;
    __vmwrite(GUEST_LDTR_AR_BYTES, arbytes.bytes);
    arbytes.fields.seg_type = 0xb;          /* 32-bit TSS (busy) */
    __vmwrite(GUEST_TR_AR_BYTES, arbytes.bytes);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmwrite(GUEST_DR7, 0);
    __vmwrite(VMCS_LINK_POINTER, ~0UL);
#if defined(__i386__)
    __vmwrite(VMCS_LINK_POINTER_HIGH, ~0UL);
#endif

    __vmwrite(EXCEPTION_BITMAP, HVM_TRAP_MASK | (1U << TRAP_page_fault));

    v->arch.hvm_vcpu.guest_cr[0] = X86_CR0_PE | X86_CR0_ET;
    hvm_update_guest_cr(v, 0);

    v->arch.hvm_vcpu.guest_cr[4] = 0;
    hvm_update_guest_cr(v, 4);

    if ( cpu_has_vmx_tpr_shadow )
    {
        __vmwrite(VIRTUAL_APIC_PAGE_ADDR,
                  page_to_maddr(vcpu_vlapic(v)->regs_page));
        __vmwrite(TPR_THRESHOLD, 0);
    }

    __vmwrite(GUEST_LDTR_SELECTOR, 0);
    __vmwrite(GUEST_LDTR_BASE, 0);
    __vmwrite(GUEST_LDTR_LIMIT, 0);

    __vmwrite(GUEST_TR_BASE, 0);
    __vmwrite(GUEST_TR_LIMIT, 0xff);

    vmx_vmcs_exit(v);

    paging_update_paging_modes(v); /* will update HOST & GUEST_CR3 as reqd */

    vmx_vlapic_msr_changed(v);

    return 0;
}

int vmx_read_guest_msr(struct vcpu *v, u32 msr, u64 *val)
{
    unsigned int i, msr_count = v->arch.hvm_vmx.msr_count;
    const struct vmx_msr_entry *msr_area = v->arch.hvm_vmx.msr_area;

    for ( i = 0; i < msr_count; i++ )
    {
        if ( msr_area[i].index == msr )
        {
            *val = msr_area[i].data;
            return 0;
        }
    }

    return -ESRCH;
}

int vmx_write_guest_msr(struct vcpu *v, u32 msr, u64 val)
{
    unsigned int i, msr_count = v->arch.hvm_vmx.msr_count;
    struct vmx_msr_entry *msr_area = v->arch.hvm_vmx.msr_area;

    for ( i = 0; i < msr_count; i++ )
    {
        if ( msr_area[i].index == msr )
        {
            msr_area[i].data = val;
            return 0;
        }
    }

    return -ESRCH;
}

int vmx_add_guest_msr(struct vcpu *v, u32 msr)
{
    unsigned int i, msr_count = v->arch.hvm_vmx.msr_count;
    struct vmx_msr_entry *msr_area = v->arch.hvm_vmx.msr_area;

    for ( i = 0; i < msr_count; i++ )
        if ( msr_area[i].index == msr )
            return 0;

    if ( msr_count == (PAGE_SIZE / sizeof(struct vmx_msr_entry)) )
        return -ENOSPC;

    if ( msr_area == NULL )
    {
        if ( (msr_area = alloc_xenheap_page()) == NULL )
            return -ENOMEM;
        v->arch.hvm_vmx.msr_area = msr_area;
        __vmwrite(VM_EXIT_MSR_STORE_ADDR, virt_to_maddr(msr_area));
        __vmwrite(VM_ENTRY_MSR_LOAD_ADDR, virt_to_maddr(msr_area));
    }

    msr_area[msr_count].index = msr;
    msr_area[msr_count].mbz   = 0;
    msr_area[msr_count].data  = 0;
    v->arch.hvm_vmx.msr_count = ++msr_count;
    __vmwrite(VM_EXIT_MSR_STORE_COUNT, msr_count);
    __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, msr_count);

    return 0;
}

int vmx_add_host_load_msr(struct vcpu *v, u32 msr)
{
    unsigned int i, msr_count = v->arch.hvm_vmx.host_msr_count;
    struct vmx_msr_entry *msr_area = v->arch.hvm_vmx.host_msr_area;

    for ( i = 0; i < msr_count; i++ )
        if ( msr_area[i].index == msr )
            return 0;

    if ( msr_count == (PAGE_SIZE / sizeof(struct vmx_msr_entry)) )
        return -ENOSPC;

    if ( msr_area == NULL )
    {
        if ( (msr_area = alloc_xenheap_page()) == NULL )
            return -ENOMEM;
        v->arch.hvm_vmx.host_msr_area = msr_area;
        __vmwrite(VM_EXIT_MSR_LOAD_ADDR, virt_to_maddr(msr_area));
    }

    msr_area[msr_count].index = msr;
    msr_area[msr_count].mbz   = 0;
    rdmsrl(msr, msr_area[msr_count].data);
    v->arch.hvm_vmx.host_msr_count = ++msr_count;
    __vmwrite(VM_EXIT_MSR_LOAD_COUNT, msr_count);

    return 0;
}

int vmx_create_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;
    int rc;

    if ( arch_vmx->vmcs == NULL )
    {
        if ( (arch_vmx->vmcs = vmx_alloc_vmcs()) == NULL )
            return -ENOMEM;

        INIT_LIST_HEAD(&arch_vmx->active_list);
        __vmpclear(virt_to_maddr(arch_vmx->vmcs));
        arch_vmx->active_cpu = -1;
        arch_vmx->launched   = 0;
    }

    if ( (rc = construct_vmcs(v)) != 0 )
    {
        vmx_free_vmcs(arch_vmx->vmcs);
        arch_vmx->vmcs = NULL;
        return rc;
    }

    return 0;
}

void vmx_destroy_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    if ( arch_vmx->vmcs == NULL )
        return;

    vmx_clear_vmcs(v);

    vmx_free_vmcs(arch_vmx->vmcs);
    arch_vmx->vmcs = NULL;
}

void vm_launch_fail(unsigned long eflags)
{
    unsigned long error = __vmread(VM_INSTRUCTION_ERROR);
    printk("<vm_launch_fail> error code %lx\n", error);
    domain_crash_synchronous();
}

void vm_resume_fail(unsigned long eflags)
{
    unsigned long error = __vmread(VM_INSTRUCTION_ERROR);
    printk("<vm_resume_fail> error code %lx\n", error);
    domain_crash_synchronous();
}

static void flush_cache(void *info)
{
    wbinvd();
}

void vmx_do_resume(struct vcpu *v)
{
    bool_t debug_state;

    if ( v->arch.hvm_vmx.active_cpu == smp_processor_id() )
    {
        if ( v->arch.hvm_vmx.vmcs != this_cpu(current_vmcs) )
            vmx_load_vmcs(v);
    }
    else
    {
        /* For pass-through domain, guest PCI-E device driver may leverage the
         * "Non-Snoop" I/O, and explicitly "WBINVD" or "CFLUSH" to a RAM space.
         * In that case, if migration occurs before "WBINVD" or "CFLUSH", need
         * to maintain data consistency.
         */
        if ( !list_empty(&(domain_hvm_iommu(v->domain)->pdev_list)) )
        {
            int cpu = v->arch.hvm_vmx.active_cpu;
            if ( cpu != -1 )
                on_selected_cpus(cpumask_of_cpu(cpu), flush_cache, NULL, 1, 1);
        }

        vmx_clear_vmcs(v);
        vmx_load_vmcs(v);
        hvm_migrate_timers(v);
        vmx_set_host_env(v);
    }

    debug_state = v->domain->debugger_attached;
    if ( unlikely(v->arch.hvm_vcpu.debug_state_latch != debug_state) )
    {
        unsigned long intercepts = __vmread(EXCEPTION_BITMAP);
        unsigned long mask = (1U << TRAP_debug) | (1U << TRAP_int3);
        v->arch.hvm_vcpu.debug_state_latch = debug_state;
        if ( debug_state )
            intercepts |= mask;
        else
            intercepts &= ~mask;
        __vmwrite(EXCEPTION_BITMAP, intercepts);
    }

    hvm_do_resume(v);
    reset_stack_and_jump(vmx_asm_do_vmentry);
}

static void vmx_dump_sel(char *name, enum x86_segment seg)
{
    struct segment_register sreg;
    hvm_get_segment_register(current, seg, &sreg);
    printk("%s: sel=0x%04x, attr=0x%05x, limit=0x%08x, base=0x%016llx\n", 
           name, sreg.sel, sreg.attr.bytes, sreg.limit,
           (unsigned long long)sreg.base);
}

static unsigned long vmr(unsigned long field)
{
    int rc;
    unsigned long val;
    val = __vmread_safe(field, &rc);
    return rc ? 0 : val;
}

void vmcs_dump_vcpu(void)
{
    unsigned long long x;

    printk("*** Guest State ***\n");
    printk("CR0: actual=0x%016llx, shadow=0x%016llx, gh_mask=%016llx\n",
           (unsigned long long)vmr(GUEST_CR0),
           (unsigned long long)vmr(CR0_READ_SHADOW), 
           (unsigned long long)vmr(CR0_GUEST_HOST_MASK));
    printk("CR4: actual=0x%016llx, shadow=0x%016llx, gh_mask=%016llx\n",
           (unsigned long long)vmr(GUEST_CR4),
           (unsigned long long)vmr(CR4_READ_SHADOW), 
           (unsigned long long)vmr(CR4_GUEST_HOST_MASK));
    printk("CR3: actual=0x%016llx, target_count=%d\n",
           (unsigned long long)vmr(GUEST_CR3),
           (int)vmr(CR3_TARGET_COUNT));
    printk("     target0=%016llx, target1=%016llx\n",
           (unsigned long long)vmr(CR3_TARGET_VALUE0),
           (unsigned long long)vmr(CR3_TARGET_VALUE1));
    printk("     target2=%016llx, target3=%016llx\n",
           (unsigned long long)vmr(CR3_TARGET_VALUE2),
           (unsigned long long)vmr(CR3_TARGET_VALUE3));
    printk("RSP = 0x%016llx  RIP = 0x%016llx\n", 
           (unsigned long long)vmr(GUEST_RSP),
           (unsigned long long)vmr(GUEST_RIP));
    printk("RFLAGS=0x%016llx  DR7 = 0x%016llx\n", 
           (unsigned long long)vmr(GUEST_RFLAGS),
           (unsigned long long)vmr(GUEST_DR7));
    printk("Sysenter RSP=%016llx CS:RIP=%04x:%016llx\n",
           (unsigned long long)vmr(GUEST_SYSENTER_ESP),
           (int)vmr(GUEST_SYSENTER_CS),
           (unsigned long long)vmr(GUEST_SYSENTER_EIP));
    vmx_dump_sel("CS", x86_seg_cs);
    vmx_dump_sel("DS", x86_seg_ds);
    vmx_dump_sel("SS", x86_seg_ss);
    vmx_dump_sel("ES", x86_seg_es);
    vmx_dump_sel("FS", x86_seg_fs);
    vmx_dump_sel("GS", x86_seg_gs);
    vmx_dump_sel("GDTR", x86_seg_gdtr);
    vmx_dump_sel("LDTR", x86_seg_ldtr);
    vmx_dump_sel("IDTR", x86_seg_idtr);
    vmx_dump_sel("TR", x86_seg_tr);
    x  = (unsigned long long)vmr(TSC_OFFSET_HIGH) << 32;
    x |= (uint32_t)vmr(TSC_OFFSET);
    printk("TSC Offset = %016llx\n", x);
    x  = (unsigned long long)vmr(GUEST_IA32_DEBUGCTL) << 32;
    x |= (uint32_t)vmr(GUEST_IA32_DEBUGCTL);
    printk("DebugCtl=%016llx DebugExceptions=%016llx\n", x,
           (unsigned long long)vmr(GUEST_PENDING_DBG_EXCEPTIONS));
    printk("Interruptibility=%04x ActivityState=%04x\n",
           (int)vmr(GUEST_INTERRUPTIBILITY_INFO),
           (int)vmr(GUEST_ACTIVITY_STATE));

    printk("*** Host State ***\n");
    printk("RSP = 0x%016llx  RIP = 0x%016llx\n", 
           (unsigned long long)vmr(HOST_RSP),
           (unsigned long long)vmr(HOST_RIP));
    printk("CS=%04x DS=%04x ES=%04x FS=%04x GS=%04x SS=%04x TR=%04x\n",
           (uint16_t)vmr(HOST_CS_SELECTOR),
           (uint16_t)vmr(HOST_DS_SELECTOR),
           (uint16_t)vmr(HOST_ES_SELECTOR),
           (uint16_t)vmr(HOST_FS_SELECTOR),
           (uint16_t)vmr(HOST_GS_SELECTOR),
           (uint16_t)vmr(HOST_SS_SELECTOR),
           (uint16_t)vmr(HOST_TR_SELECTOR));
    printk("FSBase=%016llx GSBase=%016llx TRBase=%016llx\n",
           (unsigned long long)vmr(HOST_FS_BASE),
           (unsigned long long)vmr(HOST_GS_BASE),
           (unsigned long long)vmr(HOST_TR_BASE));
    printk("GDTBase=%016llx IDTBase=%016llx\n",
           (unsigned long long)vmr(HOST_GDTR_BASE),
           (unsigned long long)vmr(HOST_IDTR_BASE));
    printk("CR0=%016llx CR3=%016llx CR4=%016llx\n",
           (unsigned long long)vmr(HOST_CR0),
           (unsigned long long)vmr(HOST_CR3),
           (unsigned long long)vmr(HOST_CR4));
    printk("Sysenter RSP=%016llx CS:RIP=%04x:%016llx\n",
           (unsigned long long)vmr(HOST_IA32_SYSENTER_ESP),
           (int)vmr(HOST_IA32_SYSENTER_CS),
           (unsigned long long)vmr(HOST_IA32_SYSENTER_EIP));

    printk("*** Control State ***\n");
    printk("PinBased=%08x CPUBased=%08x SecondaryExec=%08x\n",
           (uint32_t)vmr(PIN_BASED_VM_EXEC_CONTROL),
           (uint32_t)vmr(CPU_BASED_VM_EXEC_CONTROL),
           (uint32_t)vmr(SECONDARY_VM_EXEC_CONTROL));
    printk("EntryControls=%08x ExitControls=%08x\n",
           (uint32_t)vmr(VM_ENTRY_CONTROLS),
           (uint32_t)vmr(VM_EXIT_CONTROLS));
    printk("ExceptionBitmap=%08x\n",
           (uint32_t)vmr(EXCEPTION_BITMAP));
    printk("VMEntry: intr_info=%08x errcode=%08x ilen=%08x\n",
           (uint32_t)vmr(VM_ENTRY_INTR_INFO),
           (uint32_t)vmr(VM_ENTRY_EXCEPTION_ERROR_CODE),
           (uint32_t)vmr(VM_ENTRY_INSTRUCTION_LEN));
    printk("VMExit: intr_info=%08x errcode=%08x ilen=%08x\n",
           (uint32_t)vmr(VM_EXIT_INTR_INFO),
           (uint32_t)vmr(VM_EXIT_INTR_ERROR_CODE),
           (uint32_t)vmr(VM_ENTRY_INSTRUCTION_LEN));
    printk("        reason=%08x qualification=%08x\n",
           (uint32_t)vmr(VM_EXIT_REASON),
           (uint32_t)vmr(EXIT_QUALIFICATION));
    printk("IDTVectoring: info=%08x errcode=%08x\n",
           (uint32_t)vmr(IDT_VECTORING_INFO),
           (uint32_t)vmr(IDT_VECTORING_ERROR_CODE));
    printk("TPR Threshold = 0x%02x\n",
           (uint32_t)vmr(TPR_THRESHOLD));
}

static void vmcs_dump(unsigned char ch)
{
    struct domain *d;
    struct vcpu *v;
    
    printk("*********** VMCS Areas **************\n");

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        if ( !is_hvm_domain(d) )
            continue;
        printk("\n>>> Domain %d <<<\n", d->domain_id);
        for_each_vcpu ( d, v )
        {
            printk("\tVCPU %d\n", v->vcpu_id);
            vmx_vmcs_enter(v);
            vmcs_dump_vcpu();
            vmx_vmcs_exit(v);
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    printk("**************************************\n");
}

void setup_vmcs_dump(void)
{
    register_keyhandler('v', vmcs_dump, "dump Intel's VMCS");
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
