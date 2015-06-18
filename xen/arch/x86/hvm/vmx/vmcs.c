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
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/keyhandler.h>
#include <xen/mem_event.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/xstate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vvmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/flushtlb.h>
#include <asm/shadow.h>
#include <asm/tboot.h>

static bool_t __read_mostly opt_vpid_enabled = 1;
boolean_param("vpid", opt_vpid_enabled);

static bool_t __read_mostly opt_unrestricted_guest_enabled = 1;
boolean_param("unrestricted_guest", opt_unrestricted_guest_enabled);

static bool_t __read_mostly opt_apicv_enabled = 1;
boolean_param("apicv", opt_apicv_enabled);

/*
 * These two parameters are used to config the controls for Pause-Loop Exiting:
 * ple_gap:    upper bound on the amount of time between two successive
 *             executions of PAUSE in a loop.
 * ple_window: upper bound on the amount of time a guest is allowed to execute
 *             in a PAUSE loop.
 * Time is measured based on a counter that runs at the same rate as the TSC,
 * refer SDM volume 3b section 21.6.13 & 22.1.3.
 */
static unsigned int __read_mostly ple_gap = 128;
integer_param("ple_gap", ple_gap);
static unsigned int __read_mostly ple_window = 4096;
integer_param("ple_window", ple_window);

/* Dynamic (run-time adjusted) execution control flags. */
u32 vmx_pin_based_exec_control __read_mostly;
u32 vmx_cpu_based_exec_control __read_mostly;
u32 vmx_secondary_exec_control __read_mostly;
u32 vmx_vmexit_control __read_mostly;
u32 vmx_vmentry_control __read_mostly;
u64 vmx_ept_vpid_cap __read_mostly;

const u32 vmx_introspection_force_enabled_msrs[] = {
    MSR_IA32_SYSENTER_EIP,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_MC0_CTL,
    MSR_STAR,
    MSR_LSTAR
};

const unsigned int vmx_introspection_force_enabled_msrs_size =
    ARRAY_SIZE(vmx_introspection_force_enabled_msrs);

static DEFINE_PER_CPU_READ_MOSTLY(struct vmcs_struct *, vmxon_region);
static DEFINE_PER_CPU(struct vmcs_struct *, current_vmcs);
static DEFINE_PER_CPU(struct list_head, active_vmcs_list);
DEFINE_PER_CPU(bool_t, vmxon);

static u32 vmcs_revision_id __read_mostly;
u64 __read_mostly vmx_basic_msr;

static void __init vmx_display_features(void)
{
    int printed = 0;

    printk("VMX: Supported advanced features:\n");

#define P(p,s) if ( p ) { printk(" - %s\n", s); printed = 1; }
    P(cpu_has_vmx_virtualize_apic_accesses, "APIC MMIO access virtualisation");
    P(cpu_has_vmx_tpr_shadow, "APIC TPR shadow");
    P(cpu_has_vmx_ept, "Extended Page Tables (EPT)");
    P(cpu_has_vmx_vpid, "Virtual-Processor Identifiers (VPID)");
    P(cpu_has_vmx_vnmi, "Virtual NMI");
    P(cpu_has_vmx_msr_bitmap, "MSR direct-access bitmap");
    P(cpu_has_vmx_unrestricted_guest, "Unrestricted Guest");
    P(cpu_has_vmx_apic_reg_virt, "APIC Register Virtualization");
    P(cpu_has_vmx_virtual_intr_delivery, "Virtual Interrupt Delivery");
    P(cpu_has_vmx_posted_intr_processing, "Posted Interrupt Processing");
    P(cpu_has_vmx_vmcs_shadowing, "VMCS shadowing");
#undef P

    if ( !printed )
        printk(" - none\n");
}

static u32 adjust_vmx_controls(
    const char *name, u32 ctl_min, u32 ctl_opt, u32 msr, bool_t *mismatch)
{
    u32 vmx_msr_low, vmx_msr_high, ctl = ctl_min | ctl_opt;

    rdmsr(msr, vmx_msr_low, vmx_msr_high);

    ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
    ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

    /* Ensure minimum (required) set of control bits are supported. */
    if ( ctl_min & ~ctl )
    {
        *mismatch = 1;
        printk("VMX: CPU%d has insufficient %s (%08x; requires %08x)\n",
               smp_processor_id(), name, ctl, ctl_min);
    }

    return ctl;
}

static bool_t cap_check(const char *name, u32 expected, u32 saw)
{
    if ( saw != expected )
        printk("VMX %s: saw %#x expected %#x\n", name, saw, expected);
    return saw != expected;
}

static int vmx_init_vmcs_config(void)
{
    u32 vmx_basic_msr_low, vmx_basic_msr_high, min, opt;
    u32 _vmx_pin_based_exec_control;
    u32 _vmx_cpu_based_exec_control;
    u32 _vmx_secondary_exec_control = 0;
    u64 _vmx_ept_vpid_cap = 0;
    u64 _vmx_misc_cap = 0;
    u32 _vmx_vmexit_control;
    u32 _vmx_vmentry_control;
    bool_t mismatch = 0;

    rdmsr(MSR_IA32_VMX_BASIC, vmx_basic_msr_low, vmx_basic_msr_high);

    min = (PIN_BASED_EXT_INTR_MASK |
           PIN_BASED_NMI_EXITING);
    opt = (PIN_BASED_VIRTUAL_NMIS |
           PIN_BASED_POSTED_INTERRUPT);
    _vmx_pin_based_exec_control = adjust_vmx_controls(
        "Pin-Based Exec Control", min, opt,
        MSR_IA32_VMX_PINBASED_CTLS, &mismatch);

    min = (CPU_BASED_HLT_EXITING |
           CPU_BASED_VIRTUAL_INTR_PENDING |
           CPU_BASED_CR8_LOAD_EXITING |
           CPU_BASED_CR8_STORE_EXITING |
           CPU_BASED_INVLPG_EXITING |
           CPU_BASED_CR3_LOAD_EXITING |
           CPU_BASED_CR3_STORE_EXITING |
           CPU_BASED_MONITOR_EXITING |
           CPU_BASED_MWAIT_EXITING |
           CPU_BASED_MOV_DR_EXITING |
           CPU_BASED_ACTIVATE_IO_BITMAP |
           CPU_BASED_USE_TSC_OFFSETING |
           CPU_BASED_RDTSC_EXITING);
    opt = (CPU_BASED_ACTIVATE_MSR_BITMAP |
           CPU_BASED_TPR_SHADOW |
           CPU_BASED_MONITOR_TRAP_FLAG |
           CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
    _vmx_cpu_based_exec_control = adjust_vmx_controls(
        "CPU-Based Exec Control", min, opt,
        MSR_IA32_VMX_PROCBASED_CTLS, &mismatch);
    _vmx_cpu_based_exec_control &= ~CPU_BASED_RDTSC_EXITING;
    if ( _vmx_cpu_based_exec_control & CPU_BASED_TPR_SHADOW )
        _vmx_cpu_based_exec_control &=
            ~(CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING);

    if ( _vmx_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS )
    {
        min = 0;
        opt = (SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
               SECONDARY_EXEC_WBINVD_EXITING |
               SECONDARY_EXEC_ENABLE_EPT |
               SECONDARY_EXEC_ENABLE_RDTSCP |
               SECONDARY_EXEC_PAUSE_LOOP_EXITING |
               SECONDARY_EXEC_ENABLE_INVPCID);
        rdmsrl(MSR_IA32_VMX_MISC, _vmx_misc_cap);
        if ( _vmx_misc_cap & VMX_MISC_VMWRITE_ALL )
            opt |= SECONDARY_EXEC_ENABLE_VMCS_SHADOWING;
        if ( opt_vpid_enabled )
            opt |= SECONDARY_EXEC_ENABLE_VPID;
        if ( opt_unrestricted_guest_enabled )
            opt |= SECONDARY_EXEC_UNRESTRICTED_GUEST;

        /*
         * "APIC Register Virtualization" and "Virtual Interrupt Delivery"
         * can be set only when "use TPR shadow" is set
         */
        if ( (_vmx_cpu_based_exec_control & CPU_BASED_TPR_SHADOW) &&
             opt_apicv_enabled )
            opt |= SECONDARY_EXEC_APIC_REGISTER_VIRT |
                   SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
                   SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;

        _vmx_secondary_exec_control = adjust_vmx_controls(
            "Secondary Exec Control", min, opt,
            MSR_IA32_VMX_PROCBASED_CTLS2, &mismatch);
    }

    /* The IA32_VMX_EPT_VPID_CAP MSR exists only when EPT or VPID available */
    if ( _vmx_secondary_exec_control & (SECONDARY_EXEC_ENABLE_EPT |
                                        SECONDARY_EXEC_ENABLE_VPID) )
    {
        rdmsrl(MSR_IA32_VMX_EPT_VPID_CAP, _vmx_ept_vpid_cap);

        /*
         * Additional sanity checking before using EPT:
         * 1) the CPU we are running on must support EPT WB, as we will set
         *    ept paging structures memory type to WB;
         * 2) the CPU must support the EPT page-walk length of 4 according to
         *    Intel SDM 25.2.2.
         * 3) the CPU must support INVEPT all context invalidation, because we
         *    will use it as final resort if other types are not supported.
         *
         * Or we just don't use EPT.
         */
        if ( !(_vmx_ept_vpid_cap & VMX_EPT_MEMORY_TYPE_WB) ||
             !(_vmx_ept_vpid_cap & VMX_EPT_WALK_LENGTH_4_SUPPORTED) ||
             !(_vmx_ept_vpid_cap & VMX_EPT_INVEPT_ALL_CONTEXT) )
            _vmx_secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_EPT;

        /*
         * the CPU must support INVVPID all context invalidation, because we
         * will use it as final resort if other types are not supported.
         *
         * Or we just don't use VPID.
         */
        if ( !(_vmx_ept_vpid_cap & VMX_VPID_INVVPID_ALL_CONTEXT) )
            _vmx_secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;
    }

    if ( _vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT )
    {
        /*
         * To use EPT we expect to be able to clear certain intercepts.
         * We check VMX_BASIC_MSR[55] to correctly handle default controls.
         */
        uint32_t must_be_one, must_be_zero, msr = MSR_IA32_VMX_PROCBASED_CTLS;
        if ( vmx_basic_msr_high & (VMX_BASIC_DEFAULT1_ZERO >> 32) )
            msr = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
        rdmsr(msr, must_be_one, must_be_zero);
        if ( must_be_one & (CPU_BASED_INVLPG_EXITING |
                            CPU_BASED_CR3_LOAD_EXITING |
                            CPU_BASED_CR3_STORE_EXITING) )
            _vmx_secondary_exec_control &=
                ~(SECONDARY_EXEC_ENABLE_EPT |
                  SECONDARY_EXEC_UNRESTRICTED_GUEST);
    }

    if ( (_vmx_secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING) &&
          ple_gap == 0 )
    {
        if ( !vmx_pin_based_exec_control )
            printk(XENLOG_INFO "Disable Pause-Loop Exiting.\n");
        _vmx_secondary_exec_control &= ~ SECONDARY_EXEC_PAUSE_LOOP_EXITING;
    }

    min = VM_EXIT_ACK_INTR_ON_EXIT;
    opt = VM_EXIT_SAVE_GUEST_PAT | VM_EXIT_LOAD_HOST_PAT |
          VM_EXIT_CLEAR_BNDCFGS;
    min |= VM_EXIT_IA32E_MODE;
    _vmx_vmexit_control = adjust_vmx_controls(
        "VMExit Control", min, opt, MSR_IA32_VMX_EXIT_CTLS, &mismatch);

    /*
     * "Process posted interrupt" can be set only when "virtual-interrupt
     * delivery" and "acknowledge interrupt on exit" is set
     */
    if ( !(_vmx_secondary_exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)
          || !(_vmx_vmexit_control & VM_EXIT_ACK_INTR_ON_EXIT) )
        _vmx_pin_based_exec_control  &= ~ PIN_BASED_POSTED_INTERRUPT;

    min = 0;
    opt = VM_ENTRY_LOAD_GUEST_PAT | VM_ENTRY_LOAD_BNDCFGS;
    _vmx_vmentry_control = adjust_vmx_controls(
        "VMEntry Control", min, opt, MSR_IA32_VMX_ENTRY_CTLS, &mismatch);

    if ( mismatch )
        return -EINVAL;

    if ( !vmx_pin_based_exec_control )
    {
        /* First time through. */
        vmcs_revision_id           = vmx_basic_msr_low & VMX_BASIC_REVISION_MASK;
        vmx_pin_based_exec_control = _vmx_pin_based_exec_control;
        vmx_cpu_based_exec_control = _vmx_cpu_based_exec_control;
        vmx_secondary_exec_control = _vmx_secondary_exec_control;
        vmx_ept_vpid_cap           = _vmx_ept_vpid_cap;
        vmx_vmexit_control         = _vmx_vmexit_control;
        vmx_vmentry_control        = _vmx_vmentry_control;
        vmx_basic_msr              = ((u64)vmx_basic_msr_high << 32) |
                                     vmx_basic_msr_low;
        vmx_display_features();

        /* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
        if ( (vmx_basic_msr_high & (VMX_BASIC_VMCS_SIZE_MASK >> 32)) >
             PAGE_SIZE )
        {
            printk("VMX: CPU%d VMCS size is too big (%Lu bytes)\n",
                   smp_processor_id(),
                   vmx_basic_msr_high & (VMX_BASIC_VMCS_SIZE_MASK >> 32));
            return -EINVAL;
        }
    }
    else
    {
        /* Globals are already initialised: re-check them. */
        mismatch |= cap_check(
            "VMCS revision ID",
            vmcs_revision_id, vmx_basic_msr_low & VMX_BASIC_REVISION_MASK);
        mismatch |= cap_check(
            "Pin-Based Exec Control",
            vmx_pin_based_exec_control, _vmx_pin_based_exec_control);
        mismatch |= cap_check(
            "CPU-Based Exec Control",
            vmx_cpu_based_exec_control, _vmx_cpu_based_exec_control);
        mismatch |= cap_check(
            "Secondary Exec Control",
            vmx_secondary_exec_control, _vmx_secondary_exec_control);
        mismatch |= cap_check(
            "VMExit Control",
            vmx_vmexit_control, _vmx_vmexit_control);
        mismatch |= cap_check(
            "VMEntry Control",
            vmx_vmentry_control, _vmx_vmentry_control);
        mismatch |= cap_check(
            "EPT and VPID Capability",
            vmx_ept_vpid_cap, _vmx_ept_vpid_cap);
        if ( cpu_has_vmx_ins_outs_instr_info !=
             !!(vmx_basic_msr_high & (VMX_BASIC_INS_OUT_INFO >> 32)) )
        {
            printk("VMX INS/OUTS Instruction Info: saw %d expected %d\n",
                   !!(vmx_basic_msr_high & (VMX_BASIC_INS_OUT_INFO >> 32)),
                   cpu_has_vmx_ins_outs_instr_info);
            mismatch = 1;
        }
        if ( (vmx_basic_msr_high & (VMX_BASIC_VMCS_SIZE_MASK >> 32)) !=
             ((vmx_basic_msr & VMX_BASIC_VMCS_SIZE_MASK) >> 32) )
        {
            printk("VMX: CPU%d unexpected VMCS size %Lu\n",
                   smp_processor_id(),
                   vmx_basic_msr_high & (VMX_BASIC_VMCS_SIZE_MASK >> 32));
            mismatch = 1;
        }
        if ( mismatch )
        {
            printk("VMX: Capabilities fatally differ between CPU%d and CPU0\n",
                   smp_processor_id());
            return -EINVAL;
        }
    }

    /* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
    if ( vmx_basic_msr_high & (VMX_BASIC_32BIT_ADDRESSES >> 32) )
    {
        printk("VMX: CPU%d limits VMX structure pointers to 32 bits\n",
               smp_processor_id());
        return -EINVAL;
    }

    /* Require Write-Back (WB) memory type for VMCS accesses. */
    opt = (vmx_basic_msr_high & (VMX_BASIC_MEMORY_TYPE_MASK >> 32)) /
          ((VMX_BASIC_MEMORY_TYPE_MASK & -VMX_BASIC_MEMORY_TYPE_MASK) >> 32);
    if ( opt != MTRR_TYPE_WRBACK )
    {
        printk("VMX: CPU%d has unexpected VMCS access type %u\n",
               smp_processor_id(), opt);
        return -EINVAL;
    }

    return 0;
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
        if ( arch_vmx->vmcs_shadow_maddr )
            __vmpclear(arch_vmx->vmcs_shadow_maddr);

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
        on_selected_cpus(cpumask_of(cpu), __vmx_clear_vmcs, v, 1);
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

int vmx_cpu_up_prepare(unsigned int cpu)
{
    /*
     * If nvmx_cpu_up_prepare() failed, do not return failure and just fallback
     * to legacy mode for vvmcs synchronization.
     */
    if ( nvmx_cpu_up_prepare(cpu) != 0 )
        printk("CPU%d: Could not allocate virtual VMCS buffer.\n", cpu);

    if ( per_cpu(vmxon_region, cpu) != NULL )
        return 0;

    per_cpu(vmxon_region, cpu) = vmx_alloc_vmcs();
    if ( per_cpu(vmxon_region, cpu) != NULL )
        return 0;

    printk("CPU%d: Could not allocate host VMCS\n", cpu);
    nvmx_cpu_dead(cpu);
    return -ENOMEM;
}

void vmx_cpu_dead(unsigned int cpu)
{
    vmx_free_vmcs(per_cpu(vmxon_region, cpu));
    per_cpu(vmxon_region, cpu) = NULL;
    nvmx_cpu_dead(cpu);
}

int vmx_cpu_up(void)
{
    u32 eax, edx;
    int rc, bios_locked, cpu = smp_processor_id();
    u64 cr0, vmx_cr0_fixed0, vmx_cr0_fixed1;

    BUG_ON(!(read_cr4() & X86_CR4_VMXE));

    vmx_save_host_msrs();

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
        return -EINVAL;
    }

    rdmsr(IA32_FEATURE_CONTROL_MSR, eax, edx);

    bios_locked = !!(eax & IA32_FEATURE_CONTROL_MSR_LOCK);
    if ( bios_locked )
    {
        if ( !(eax & (tboot_in_measured_env()
                      ? IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX
                      : IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX)) )
        {
            printk("CPU%d: VMX disabled by BIOS.\n", cpu);
            return -EINVAL;
        }
    }
    else
    {
        eax  = IA32_FEATURE_CONTROL_MSR_LOCK;
        eax |= IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX;
        if ( test_bit(X86_FEATURE_SMXE, &boot_cpu_data.x86_capability) )
            eax |= IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX;
        wrmsr(IA32_FEATURE_CONTROL_MSR, eax, 0);
    }

    if ( (rc = vmx_init_vmcs_config()) != 0 )
        return rc;

    INIT_LIST_HEAD(&this_cpu(active_vmcs_list));

    if ( (rc = vmx_cpu_up_prepare(cpu)) != 0 )
        return rc;

    switch ( __vmxon(virt_to_maddr(this_cpu(vmxon_region))) )
    {
    case -2: /* #UD or #GP */
        if ( bios_locked &&
             test_bit(X86_FEATURE_SMXE, &boot_cpu_data.x86_capability) &&
             (!(eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX) ||
              !(eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX)) )
        {
            printk("CPU%d: VMXON failed: perhaps because of TXT settings "
                   "in your BIOS configuration?\n", cpu);
            printk(" --> Disable TXT in your BIOS unless using a secure "
                   "bootloader.\n");
            return -EINVAL;
        }
        /* fall through */
    case -1: /* CF==1 or ZF==1 */
        printk("CPU%d: unexpected VMXON failure\n", cpu);
        return -EINVAL;
    case 0: /* success */
        this_cpu(vmxon) = 1;
        break;
    default:
        BUG();
    }

    hvm_asid_init(cpu_has_vmx_vpid ? (1u << VMCS_VPID_WIDTH) : 0);

    if ( cpu_has_vmx_ept )
        ept_sync_all();

    if ( cpu_has_vmx_vpid )
        vpid_sync_all();

    return 0;
}

void vmx_cpu_down(void)
{
    struct list_head *active_vmcs_list = &this_cpu(active_vmcs_list);
    unsigned long flags;

    if ( !this_cpu(vmxon) )
        return;

    local_irq_save(flags);

    while ( !list_empty(active_vmcs_list) )
        __vmx_clear_vmcs(list_entry(active_vmcs_list->next,
                                    struct vcpu, arch.hvm_vmx.active_list));

    BUG_ON(!(read_cr4() & X86_CR4_VMXE));
    this_cpu(vmxon) = 0;
    __vmxoff();

    local_irq_restore(flags);
}

struct foreign_vmcs {
    struct vcpu *v;
    unsigned int count;
};
static DEFINE_PER_CPU(struct foreign_vmcs, foreign_vmcs);

bool_t vmx_vmcs_try_enter(struct vcpu *v)
{
    struct foreign_vmcs *fv;

    /*
     * NB. We must *always* run an HVM VCPU on its own VMCS, except for
     * vmx_vmcs_enter/exit and scheduling tail critical regions.
     */
    if ( likely(v == current) )
        return v->arch.hvm_vmx.vmcs == this_cpu(current_vmcs);

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

    return 1;
}

void vmx_vmcs_enter(struct vcpu *v)
{
    bool_t okay = vmx_vmcs_try_enter(v);

    ASSERT(okay);
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
        if ( has_hvm_container_vcpu(current) )
            vmx_load_vmcs(current);

        spin_unlock(&v->arch.hvm_vmx.vmcs_lock);
        vcpu_unpause(v);

        fv->v = NULL;
    }
}

static void vmx_set_host_env(struct vcpu *v)
{
    unsigned int cpu = smp_processor_id();

    __vmwrite(HOST_GDTR_BASE,
              (unsigned long)(this_cpu(gdt_table) - FIRST_RESERVED_GDT_ENTRY));
    __vmwrite(HOST_IDTR_BASE, (unsigned long)idt_tables[cpu]);

    __vmwrite(HOST_TR_SELECTOR, TSS_ENTRY << 3);
    __vmwrite(HOST_TR_BASE, (unsigned long)&per_cpu(init_tss, cpu));

    __vmwrite(HOST_SYSENTER_ESP, get_stack_bottom());

    /*
     * Skip end of cpu_user_regs when entering the hypervisor because the
     * CPU does not save context onto the stack. SS,RSP,CS,RIP,RFLAGS,etc
     * all get saved into the VMCS instead.
     */
    __vmwrite(HOST_RSP,
              (unsigned long)&get_cpu_info()->guest_cpu_user_regs.error_code);
}

void vmx_disable_intercept_for_msr(struct vcpu *v, u32 msr, int type)
{
    unsigned long *msr_bitmap = v->arch.hvm_vmx.msr_bitmap;
    struct domain *d = v->domain;

    /* VMX MSR bitmap supported? */
    if ( msr_bitmap == NULL )
        return;

    if ( unlikely(d->arch.hvm_domain.introspection_enabled) &&
         mem_event_check_ring(&d->mem_event->access) )
    {
        unsigned int i;

        /* Filter out MSR-s needed for memory introspection */
        for ( i = 0; i < vmx_introspection_force_enabled_msrs_size; i++ )
            if ( msr == vmx_introspection_force_enabled_msrs[i] )
                return;
    }

    /*
     * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
     * have the write-low and read-high bitmap offsets the wrong way round.
     * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
     */
    if ( msr <= 0x1fff )
    {
        if ( type & MSR_TYPE_R )
            clear_bit(msr, msr_bitmap + 0x000/BYTES_PER_LONG); /* read-low */
        if ( type & MSR_TYPE_W )
            clear_bit(msr, msr_bitmap + 0x800/BYTES_PER_LONG); /* write-low */
    }
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
    {
        msr &= 0x1fff;
        if ( type & MSR_TYPE_R )
            clear_bit(msr, msr_bitmap + 0x400/BYTES_PER_LONG); /* read-high */
        if ( type & MSR_TYPE_W )
            clear_bit(msr, msr_bitmap + 0xc00/BYTES_PER_LONG); /* write-high */
    }
    else
        HVM_DBG_LOG(DBG_LEVEL_MSR,
                   "msr %x is out of the control range"
                   "0x00000000-0x00001fff and 0xc0000000-0xc0001fff"
                   "RDMSR or WRMSR will cause a VM exit", msr); 

}

void vmx_enable_intercept_for_msr(struct vcpu *v, u32 msr, int type)
{
    unsigned long *msr_bitmap = v->arch.hvm_vmx.msr_bitmap;

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
        if ( type & MSR_TYPE_R )
            set_bit(msr, msr_bitmap + 0x000/BYTES_PER_LONG); /* read-low */
        if ( type & MSR_TYPE_W )
            set_bit(msr, msr_bitmap + 0x800/BYTES_PER_LONG); /* write-low */
    }
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
    {
        msr &= 0x1fff;
        if ( type & MSR_TYPE_R )
            set_bit(msr, msr_bitmap + 0x400/BYTES_PER_LONG); /* read-high */
        if ( type & MSR_TYPE_W )
            set_bit(msr, msr_bitmap + 0xc00/BYTES_PER_LONG); /* write-high */
    }
    else
        HVM_DBG_LOG(DBG_LEVEL_MSR,
                   "msr %x is out of the control range"
                   "0x00000000-0x00001fff and 0xc0000000-0xc0001fff"
                   "RDMSR or WRMSR will cause a VM exit", msr); 
}

/*
 * access_type: read == 0, write == 1
 */
int vmx_check_msr_bitmap(unsigned long *msr_bitmap, u32 msr, int access_type)
{
    int ret = 1;
    if ( !msr_bitmap )
        return 1;

    if ( msr <= 0x1fff )
    {
        if ( access_type == 0 )
            ret = test_bit(msr, msr_bitmap + 0x000/BYTES_PER_LONG); /* read-low */
        else if ( access_type == 1 )
            ret = test_bit(msr, msr_bitmap + 0x800/BYTES_PER_LONG); /* write-low */
    }
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
    {
        msr &= 0x1fff;
        if ( access_type == 0 )
            ret = test_bit(msr, msr_bitmap + 0x400/BYTES_PER_LONG); /* read-high */
        else if ( access_type == 1 )
            ret = test_bit(msr, msr_bitmap + 0xc00/BYTES_PER_LONG); /* write-high */
    }
    return ret;
}


/*
 * Switch VMCS between layer 1 & 2 guest
 */
void vmx_vmcs_switch(struct vmcs_struct *from, struct vmcs_struct *to)
{
    struct arch_vmx_struct *vmx = &current->arch.hvm_vmx;
    spin_lock(&vmx->vmcs_lock);

    __vmpclear(virt_to_maddr(from));
    if ( vmx->vmcs_shadow_maddr )
        __vmpclear(vmx->vmcs_shadow_maddr);
    __vmptrld(virt_to_maddr(to));

    vmx->vmcs = to;
    vmx->launched = 0;
    this_cpu(current_vmcs) = to;

    if ( vmx->hostenv_migrated )
    {
        vmx->hostenv_migrated = 0;
        vmx_set_host_env(current);
    }

    spin_unlock(&vmx->vmcs_lock);
}

void virtual_vmcs_enter(void *vvmcs)
{
    __vmptrld(pfn_to_paddr(domain_page_map_to_mfn(vvmcs)));
}

void virtual_vmcs_exit(void *vvmcs)
{
    struct vmcs_struct *cur = this_cpu(current_vmcs);

    __vmpclear(pfn_to_paddr(domain_page_map_to_mfn(vvmcs)));
    if ( cur )
        __vmptrld(virt_to_maddr(cur));

}

u64 virtual_vmcs_vmread(void *vvmcs, u32 vmcs_encoding)
{
    u64 res;

    virtual_vmcs_enter(vvmcs);
    __vmread(vmcs_encoding, &res);
    virtual_vmcs_exit(vvmcs);

    return res;
}

void virtual_vmcs_vmwrite(void *vvmcs, u32 vmcs_encoding, u64 val)
{
    virtual_vmcs_enter(vvmcs);
    __vmwrite(vmcs_encoding, val);
    virtual_vmcs_exit(vvmcs);
}

static int construct_vmcs(struct vcpu *v)
{
    struct domain *d = v->domain;
    uint16_t sysenter_cs;
    unsigned long sysenter_eip;
    u32 vmexit_ctl = vmx_vmexit_control;
    u32 vmentry_ctl = vmx_vmentry_control;

    vmx_vmcs_enter(v);

    /* VMCS controls. */
    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_control);

    v->arch.hvm_vmx.exec_control = vmx_cpu_based_exec_control;
    if ( d->arch.vtsc )
        v->arch.hvm_vmx.exec_control |= CPU_BASED_RDTSC_EXITING;

    v->arch.hvm_vmx.secondary_exec_control = vmx_secondary_exec_control;

    /* Disable VPID for now: we decide when to enable it on VMENTER. */
    v->arch.hvm_vmx.secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;

    if ( paging_mode_hap(d) )
    {
        v->arch.hvm_vmx.exec_control &= ~(CPU_BASED_INVLPG_EXITING |
                                          CPU_BASED_CR3_LOAD_EXITING |
                                          CPU_BASED_CR3_STORE_EXITING);
    }
    else
    {
        v->arch.hvm_vmx.secondary_exec_control &= 
            ~(SECONDARY_EXEC_ENABLE_EPT | 
              SECONDARY_EXEC_UNRESTRICTED_GUEST |
              SECONDARY_EXEC_ENABLE_INVPCID);
        vmexit_ctl &= ~(VM_EXIT_SAVE_GUEST_PAT |
                        VM_EXIT_LOAD_HOST_PAT);
        vmentry_ctl &= ~VM_ENTRY_LOAD_GUEST_PAT;
    }

    /* Disable Virtualize x2APIC mode by default. */
    v->arch.hvm_vmx.secondary_exec_control &=
        ~SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;

    /* Do not enable Monitor Trap Flag unless start single step debug */
    v->arch.hvm_vmx.exec_control &= ~CPU_BASED_MONITOR_TRAP_FLAG;

    if ( is_pvh_domain(d) )
    {
        /* Disable virtual apics, TPR */
        v->arch.hvm_vmx.secondary_exec_control &=
            ~(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES
              | SECONDARY_EXEC_APIC_REGISTER_VIRT
              | SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_TPR_SHADOW;

        /* In turn, disable posted interrupts. */
        __vmwrite(PIN_BASED_VM_EXEC_CONTROL,
                  vmx_pin_based_exec_control & ~PIN_BASED_POSTED_INTERRUPT);

        /* Unrestricted guest (real mode for EPT) */
        v->arch.hvm_vmx.secondary_exec_control &=
            ~SECONDARY_EXEC_UNRESTRICTED_GUEST;

        /* Start in 64-bit mode. PVH 32bitfixme. */
        vmentry_ctl |= VM_ENTRY_IA32E_MODE;       /* GUEST_EFER.LME/LMA ignored */

        ASSERT(v->arch.hvm_vmx.exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
        ASSERT(v->arch.hvm_vmx.exec_control & CPU_BASED_ACTIVATE_MSR_BITMAP);
        ASSERT(!(v->arch.hvm_vmx.exec_control & CPU_BASED_RDTSC_EXITING));
    }

    vmx_update_cpu_exec_control(v);

    __vmwrite(VM_EXIT_CONTROLS, vmexit_ctl);
    __vmwrite(VM_ENTRY_CONTROLS, vmentry_ctl);

    if ( cpu_has_vmx_ple )
    {
        __vmwrite(PLE_GAP, ple_gap);
        __vmwrite(PLE_WINDOW, ple_window);
    }

    if ( cpu_has_vmx_secondary_exec_control )
        __vmwrite(SECONDARY_VM_EXEC_CONTROL,
                  v->arch.hvm_vmx.secondary_exec_control);

    /* MSR access bitmap. */
    if ( cpu_has_vmx_msr_bitmap )
    {
        unsigned long *msr_bitmap = alloc_xenheap_page();

        if ( msr_bitmap == NULL )
        {
            vmx_vmcs_exit(v);
            return -ENOMEM;
        }

        memset(msr_bitmap, ~0, PAGE_SIZE);
        v->arch.hvm_vmx.msr_bitmap = msr_bitmap;
        __vmwrite(MSR_BITMAP, virt_to_maddr(msr_bitmap));

        vmx_disable_intercept_for_msr(v, MSR_FS_BASE, MSR_TYPE_R | MSR_TYPE_W);
        vmx_disable_intercept_for_msr(v, MSR_GS_BASE, MSR_TYPE_R | MSR_TYPE_W);
        vmx_disable_intercept_for_msr(v, MSR_SHADOW_GS_BASE, MSR_TYPE_R | MSR_TYPE_W);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_CS, MSR_TYPE_R | MSR_TYPE_W);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_ESP, MSR_TYPE_R | MSR_TYPE_W);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_EIP, MSR_TYPE_R | MSR_TYPE_W);
        if ( paging_mode_hap(d) && (!iommu_enabled || iommu_snoop) )
            vmx_disable_intercept_for_msr(v, MSR_IA32_CR_PAT, MSR_TYPE_R | MSR_TYPE_W);
        if ( (vmexit_ctl & VM_EXIT_CLEAR_BNDCFGS) &&
             (vmentry_ctl & VM_ENTRY_LOAD_BNDCFGS) )
            vmx_disable_intercept_for_msr(v, MSR_IA32_BNDCFGS, MSR_TYPE_R | MSR_TYPE_W);
    }

    /* I/O access bitmap. */
    __vmwrite(IO_BITMAP_A, virt_to_maddr((char *)hvm_io_bitmap + 0));
    __vmwrite(IO_BITMAP_B, virt_to_maddr((char *)hvm_io_bitmap + PAGE_SIZE));

    if ( cpu_has_vmx_virtual_intr_delivery )
    {
        unsigned int i;

        /* EOI-exit bitmap */
        bitmap_zero(v->arch.hvm_vmx.eoi_exit_bitmap, NR_VECTORS);
        for ( i = 0; i < ARRAY_SIZE(v->arch.hvm_vmx.eoi_exit_bitmap); ++i )
            __vmwrite(EOI_EXIT_BITMAP(i), 0);

        /* Initialise Guest Interrupt Status (RVI and SVI) to 0 */
        __vmwrite(GUEST_INTR_STATUS, 0);
    }

    if ( cpu_has_vmx_posted_intr_processing )
    {
        __vmwrite(PI_DESC_ADDR, virt_to_maddr(&v->arch.hvm_vmx.pi_desc));
        __vmwrite(POSTED_INTR_NOTIFICATION_VECTOR, posted_intr_vector);
    }

    /* Host data selectors. */
    __vmwrite(HOST_SS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_DS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_ES_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_FS_SELECTOR, 0);
    __vmwrite(HOST_GS_SELECTOR, 0);
    __vmwrite(HOST_FS_BASE, 0);
    __vmwrite(HOST_GS_BASE, 0);

    /* Host control registers. */
    v->arch.hvm_vmx.host_cr0 = read_cr0() | X86_CR0_TS;
    __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);
    __vmwrite(HOST_CR4, mmu_cr4_features);

    /* Host CS:RIP. */
    __vmwrite(HOST_CS_SELECTOR, __HYPERVISOR_CS);
    __vmwrite(HOST_RIP, (unsigned long)vmx_asm_vmexit_handler);

    /* Host SYSENTER CS:RIP. */
    rdmsrl(MSR_IA32_SYSENTER_CS, sysenter_cs);
    __vmwrite(HOST_SYSENTER_CS, sysenter_cs);
    rdmsrl(MSR_IA32_SYSENTER_EIP, sysenter_eip);
    __vmwrite(HOST_SYSENTER_EIP, sysenter_eip);

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
    __vmwrite(GUEST_ES_LIMIT, ~0u);
    __vmwrite(GUEST_SS_LIMIT, ~0u);
    __vmwrite(GUEST_DS_LIMIT, ~0u);
    __vmwrite(GUEST_FS_LIMIT, ~0u);
    __vmwrite(GUEST_GS_LIMIT, ~0u);
    __vmwrite(GUEST_CS_LIMIT, ~0u);

    /* Guest segment AR bytes. */
    __vmwrite(GUEST_ES_AR_BYTES, 0xc093); /* read/write, accessed */
    __vmwrite(GUEST_SS_AR_BYTES, 0xc093);
    __vmwrite(GUEST_DS_AR_BYTES, 0xc093);
    __vmwrite(GUEST_FS_AR_BYTES, 0xc093);
    __vmwrite(GUEST_GS_AR_BYTES, 0xc093);
    if ( is_pvh_domain(d) )
        /* CS.L == 1, exec, read/write, accessed. PVH 32bitfixme. */
        __vmwrite(GUEST_CS_AR_BYTES, 0xa09b);
    else
        __vmwrite(GUEST_CS_AR_BYTES, 0xc09b); /* exec/read, accessed */

    /* Guest IDT. */
    __vmwrite(GUEST_IDTR_BASE, 0);
    __vmwrite(GUEST_IDTR_LIMIT, 0);

    /* Guest GDT. */
    __vmwrite(GUEST_GDTR_BASE, 0);
    __vmwrite(GUEST_GDTR_LIMIT, 0);

    /* Guest LDT. */
    __vmwrite(GUEST_LDTR_AR_BYTES, 0x0082); /* LDT */
    __vmwrite(GUEST_LDTR_SELECTOR, 0);
    __vmwrite(GUEST_LDTR_BASE, 0);
    __vmwrite(GUEST_LDTR_LIMIT, 0);

    /* Guest TSS. */
    __vmwrite(GUEST_TR_AR_BYTES, 0x008b); /* 32-bit TSS (busy) */
    __vmwrite(GUEST_TR_BASE, 0);
    __vmwrite(GUEST_TR_LIMIT, 0xff);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmwrite(GUEST_DR7, 0);
    __vmwrite(VMCS_LINK_POINTER, ~0UL);

    v->arch.hvm_vmx.exception_bitmap = HVM_TRAP_MASK
              | (paging_mode_hap(d) ? 0 : (1U << TRAP_page_fault))
              | (1U << TRAP_no_device);
    vmx_update_exception_bitmap(v);

    /*
     * In HVM domains, this happens on the realmode->paging
     * transition.  Since PVH never goes through this transition, we
     * need to do it at start-of-day.
     */
    if ( is_pvh_domain(d) )
        vmx_update_debug_state(v);

    v->arch.hvm_vcpu.guest_cr[0] = X86_CR0_PE | X86_CR0_ET;

    /* PVH domains always start in paging mode */
    if ( is_pvh_domain(d) )
        v->arch.hvm_vcpu.guest_cr[0] |= X86_CR0_PG;

    hvm_update_guest_cr(v, 0);

    v->arch.hvm_vcpu.guest_cr[4] = is_pvh_domain(d) ? X86_CR4_PAE : 0;
    hvm_update_guest_cr(v, 4);

    if ( cpu_has_vmx_tpr_shadow )
    {
        __vmwrite(VIRTUAL_APIC_PAGE_ADDR,
                  page_to_maddr(vcpu_vlapic(v)->regs_page));
        __vmwrite(TPR_THRESHOLD, 0);
    }

    if ( paging_mode_hap(d) )
    {
        struct p2m_domain *p2m = p2m_get_hostp2m(d);
        struct ept_data *ept = &p2m->ept;

        ept->asr  = pagetable_get_pfn(p2m_get_pagetable(p2m));
        __vmwrite(EPT_POINTER, ept_get_eptp(ept));
    }

    if ( paging_mode_hap(d) )
    {
        u64 host_pat, guest_pat;

        rdmsrl(MSR_IA32_CR_PAT, host_pat);
        guest_pat = MSR_IA32_CR_PAT_RESET;

        __vmwrite(HOST_PAT, host_pat);
        __vmwrite(GUEST_PAT, guest_pat);
    }

    vmx_vmcs_exit(v);

    /* PVH: paging mode is updated by arch_set_info_guest(). */
    if ( is_hvm_vcpu(v) )
    {
        /* will update HOST & GUEST_CR3 as reqd */
        paging_update_paging_modes(v);

        vmx_vlapic_msr_changed(v);
    }

    return 0;
}

int vmx_read_guest_msr(u32 msr, u64 *val)
{
    struct vcpu *curr = current;
    unsigned int i, msr_count = curr->arch.hvm_vmx.msr_count;
    const struct vmx_msr_entry *msr_area = curr->arch.hvm_vmx.msr_area;

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

int vmx_write_guest_msr(u32 msr, u64 val)
{
    struct vcpu *curr = current;
    unsigned int i, msr_count = curr->arch.hvm_vmx.msr_count;
    struct vmx_msr_entry *msr_area = curr->arch.hvm_vmx.msr_area;

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

int vmx_add_guest_msr(u32 msr)
{
    struct vcpu *curr = current;
    unsigned int i, msr_count = curr->arch.hvm_vmx.msr_count;
    struct vmx_msr_entry *msr_area = curr->arch.hvm_vmx.msr_area;

    if ( msr_area == NULL )
    {
        if ( (msr_area = alloc_xenheap_page()) == NULL )
            return -ENOMEM;
        curr->arch.hvm_vmx.msr_area = msr_area;
        __vmwrite(VM_EXIT_MSR_STORE_ADDR, virt_to_maddr(msr_area));
        __vmwrite(VM_ENTRY_MSR_LOAD_ADDR, virt_to_maddr(msr_area));
    }

    for ( i = 0; i < msr_count; i++ )
        if ( msr_area[i].index == msr )
            return 0;

    if ( msr_count == (PAGE_SIZE / sizeof(struct vmx_msr_entry)) )
        return -ENOSPC;

    msr_area[msr_count].index = msr;
    msr_area[msr_count].mbz   = 0;
    msr_area[msr_count].data  = 0;
    curr->arch.hvm_vmx.msr_count = ++msr_count;
    __vmwrite(VM_EXIT_MSR_STORE_COUNT, msr_count);
    __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, msr_count);

    return 0;
}

int vmx_add_host_load_msr(u32 msr)
{
    struct vcpu *curr = current;
    unsigned int i, msr_count = curr->arch.hvm_vmx.host_msr_count;
    struct vmx_msr_entry *msr_area = curr->arch.hvm_vmx.host_msr_area;

    if ( msr_area == NULL )
    {
        if ( (msr_area = alloc_xenheap_page()) == NULL )
            return -ENOMEM;
        curr->arch.hvm_vmx.host_msr_area = msr_area;
        __vmwrite(VM_EXIT_MSR_LOAD_ADDR, virt_to_maddr(msr_area));
    }

    for ( i = 0; i < msr_count; i++ )
        if ( msr_area[i].index == msr )
            return 0;

    if ( msr_count == (PAGE_SIZE / sizeof(struct vmx_msr_entry)) )
        return -ENOSPC;

    msr_area[msr_count].index = msr;
    msr_area[msr_count].mbz   = 0;
    rdmsrl(msr, msr_area[msr_count].data);
    curr->arch.hvm_vmx.host_msr_count = ++msr_count;
    __vmwrite(VM_EXIT_MSR_LOAD_COUNT, msr_count);

    return 0;
}

void vmx_set_eoi_exit_bitmap(struct vcpu *v, u8 vector)
{
    if ( !test_and_set_bit(vector, v->arch.hvm_vmx.eoi_exit_bitmap) )
        set_bit(vector / BITS_PER_LONG,
                &v->arch.hvm_vmx.eoi_exitmap_changed);
}

void vmx_clear_eoi_exit_bitmap(struct vcpu *v, u8 vector)
{
    if ( test_and_clear_bit(vector, v->arch.hvm_vmx.eoi_exit_bitmap) )
        set_bit(vector / BITS_PER_LONG,
                &v->arch.hvm_vmx.eoi_exitmap_changed);
}

int vmx_create_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;
    int rc;

    if ( (arch_vmx->vmcs = vmx_alloc_vmcs()) == NULL )
        return -ENOMEM;

    INIT_LIST_HEAD(&arch_vmx->active_list);
    __vmpclear(virt_to_maddr(arch_vmx->vmcs));
    arch_vmx->active_cpu = -1;
    arch_vmx->launched   = 0;

    if ( (rc = construct_vmcs(v)) != 0 )
    {
        vmx_free_vmcs(arch_vmx->vmcs);
        return rc;
    }

    return 0;
}

void vmx_destroy_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    vmx_clear_vmcs(v);

    vmx_free_vmcs(arch_vmx->vmcs);

    free_xenheap_page(v->arch.hvm_vmx.host_msr_area);
    free_xenheap_page(v->arch.hvm_vmx.msr_area);
    free_xenheap_page(v->arch.hvm_vmx.msr_bitmap);
}

void vm_launch_fail(void)
{
    unsigned long error;

    __vmread(VM_INSTRUCTION_ERROR, &error);
    printk("<vm_launch_fail> error code %lx\n", error);
    domain_crash_synchronous();
}

void vm_resume_fail(void)
{
    unsigned long error;

    __vmread(VM_INSTRUCTION_ERROR, &error);
    printk("<vm_resume_fail> error code %lx\n", error);
    domain_crash_synchronous();
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
        /*
         * For pass-through domain, guest PCI-E device driver may leverage the
         * "Non-Snoop" I/O, and explicitly WBINVD or CLFLUSH to a RAM space.
         * Since migration may occur before WBINVD or CLFLUSH, we need to
         * maintain data consistency either by:
         *  1: flushing cache (wbinvd) when the guest is scheduled out if
         *     there is no wbinvd exit, or
         *  2: execute wbinvd on all dirty pCPUs when guest wbinvd exits.
         * If VT-d engine can force snooping, we don't need to do these.
         */
        if ( has_arch_pdevs(v->domain) && !iommu_snoop
                && !cpu_has_wbinvd_exiting )
        {
            int cpu = v->arch.hvm_vmx.active_cpu;
            if ( cpu != -1 )
                flush_mask(cpumask_of(cpu), FLUSH_CACHE);
        }

        vmx_clear_vmcs(v);
        vmx_load_vmcs(v);
        hvm_migrate_timers(v);
        hvm_migrate_pirqs(v);
        vmx_set_host_env(v);
        /*
         * Both n1 VMCS and n2 VMCS need to update the host environment after 
         * VCPU migration. The environment of current VMCS is updated in place,
         * but the action of another VMCS is deferred till it is switched in.
         */
        v->arch.hvm_vmx.hostenv_migrated = 1;

        hvm_asid_flush_vcpu(v);
    }

    debug_state = v->domain->debugger_attached
                  || v->domain->arch.hvm_domain.params[HVM_PARAM_MEMORY_EVENT_INT3]
                  || v->domain->arch.hvm_domain.params[HVM_PARAM_MEMORY_EVENT_SINGLE_STEP];

    if ( unlikely(v->arch.hvm_vcpu.debug_state_latch != debug_state) )
    {
        v->arch.hvm_vcpu.debug_state_latch = debug_state;
        vmx_update_debug_state(v);
    }

    hvm_do_resume(v);
    reset_stack_and_jump(vmx_asm_do_vmentry);
}

static inline unsigned long vmr(unsigned long field)
{
    unsigned long val;

    return __vmread_safe(field, &val) ? val : 0;
}

static void vmx_dump_sel(char *name, uint32_t selector)
{
    uint32_t sel, attr, limit;
    uint64_t base;
    sel = vmr(selector);
    attr = vmr(selector + (GUEST_ES_AR_BYTES - GUEST_ES_SELECTOR));
    limit = vmr(selector + (GUEST_ES_LIMIT - GUEST_ES_SELECTOR));
    base = vmr(selector + (GUEST_ES_BASE - GUEST_ES_SELECTOR));
    printk("%s: sel=0x%04x, attr=0x%05x, limit=0x%08x, base=0x%016"PRIx64"\n",
           name, sel, attr, limit, base);
}

static void vmx_dump_sel2(char *name, uint32_t lim)
{
    uint32_t limit;
    uint64_t base;
    limit = vmr(lim);
    base = vmr(lim + (GUEST_GDTR_BASE - GUEST_GDTR_LIMIT));
    printk("%s:                           limit=0x%08x, base=0x%016"PRIx64"\n",
           name, limit, base);
}

void vmcs_dump_vcpu(struct vcpu *v)
{
    struct cpu_user_regs *regs = &v->arch.user_regs;
    unsigned long long x;

    if ( v == current )
        regs = guest_cpu_user_regs();

    vmx_vmcs_enter(v);

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
    printk("RSP = 0x%016llx (0x%016llx)  RIP = 0x%016llx (0x%016llx)\n", 
           (unsigned long long)vmr(GUEST_RSP),
           (unsigned long long)regs->esp,
           (unsigned long long)vmr(GUEST_RIP),
           (unsigned long long)regs->eip);
    printk("RFLAGS=0x%016llx (0x%016llx)  DR7 = 0x%016llx\n", 
           (unsigned long long)vmr(GUEST_RFLAGS),
           (unsigned long long)regs->eflags,
           (unsigned long long)vmr(GUEST_DR7));
    printk("Sysenter RSP=%016llx CS:RIP=%04x:%016llx\n",
           (unsigned long long)vmr(GUEST_SYSENTER_ESP),
           (int)vmr(GUEST_SYSENTER_CS),
           (unsigned long long)vmr(GUEST_SYSENTER_EIP));
    vmx_dump_sel("CS", GUEST_CS_SELECTOR);
    vmx_dump_sel("DS", GUEST_DS_SELECTOR);
    vmx_dump_sel("SS", GUEST_SS_SELECTOR);
    vmx_dump_sel("ES", GUEST_ES_SELECTOR);
    vmx_dump_sel("FS", GUEST_FS_SELECTOR);
    vmx_dump_sel("GS", GUEST_GS_SELECTOR);
    vmx_dump_sel2("GDTR", GUEST_GDTR_LIMIT);
    vmx_dump_sel("LDTR", GUEST_LDTR_SELECTOR);
    vmx_dump_sel2("IDTR", GUEST_IDTR_LIMIT);
    vmx_dump_sel("TR", GUEST_TR_SELECTOR);
    printk("Guest PAT = 0x%08x%08x\n",
           (uint32_t)vmr(GUEST_PAT_HIGH), (uint32_t)vmr(GUEST_PAT));
    x  = (unsigned long long)vmr(TSC_OFFSET_HIGH) << 32;
    x |= (uint32_t)vmr(TSC_OFFSET);
    printk("TSC Offset = %016llx\n", x);
    x  = (unsigned long long)vmr(GUEST_IA32_DEBUGCTL_HIGH) << 32;
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
           (unsigned long long)vmr(HOST_SYSENTER_ESP),
           (int)vmr(HOST_SYSENTER_CS),
           (unsigned long long)vmr(HOST_SYSENTER_EIP));
    printk("Host PAT = 0x%08x%08x\n",
           (uint32_t)vmr(HOST_PAT_HIGH), (uint32_t)vmr(HOST_PAT));

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
    printk("EPT pointer = 0x%08x%08x\n",
           (uint32_t)vmr(EPT_POINTER_HIGH), (uint32_t)vmr(EPT_POINTER));
    printk("Virtual processor ID = 0x%04x\n",
           (uint32_t)vmr(VIRTUAL_PROCESSOR_ID));

    vmx_vmcs_exit(v);
}

static void vmcs_dump(unsigned char ch)
{
    struct domain *d;
    struct vcpu *v;
    
    printk("*********** VMCS Areas **************\n");

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        if ( !has_hvm_container_domain(d) )
            continue;
        printk("\n>>> Domain %d <<<\n", d->domain_id);
        for_each_vcpu ( d, v )
        {
            printk("\tVCPU %d\n", v->vcpu_id);
            vmcs_dump_vcpu(v);
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    printk("**************************************\n");
}

static struct keyhandler vmcs_dump_keyhandler = {
    .diagnostic = 1,
    .u.fn = vmcs_dump,
    .desc = "dump Intel's VMCS"
};

void __init setup_vmcs_dump(void)
{
    register_keyhandler('v', &vmcs_dump_keyhandler);
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
