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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/keyhandler.h>
#include <xen/vm_event.h>
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
#include <asm/monitor.h>
#include <asm/shadow.h>
#include <asm/tboot.h>
#include <asm/apic.h>

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

static bool_t __read_mostly opt_pml_enabled = 1;
static s8 __read_mostly opt_ept_ad = -1;

/*
 * The 'ept' parameter controls functionalities that depend on, or impact the
 * EPT mechanism. Optional comma separated value may contain:
 *
 *  pml                 Enable PML
 *  ad                  Use A/D bits
 */
static int __init parse_ept_param(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        bool_t val = !!strncmp(s, "no-", 3);

        if ( !val )
            s += 3;

        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( !strncmp(s, "pml", ss - s) )
            opt_pml_enabled = val;
        else if ( !strncmp(s, "ad", ss - s) )
            opt_ept_ad = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("ept", parse_ept_param);

/* Dynamic (run-time adjusted) execution control flags. */
u32 vmx_pin_based_exec_control __read_mostly;
u32 vmx_cpu_based_exec_control __read_mostly;
u32 vmx_secondary_exec_control __read_mostly;
u32 vmx_vmexit_control __read_mostly;
u32 vmx_vmentry_control __read_mostly;
u64 vmx_ept_vpid_cap __read_mostly;
u64 vmx_vmfunc __read_mostly;
bool_t vmx_virt_exception __read_mostly;

static DEFINE_PER_CPU_READ_MOSTLY(paddr_t, vmxon_region);
static DEFINE_PER_CPU(paddr_t, current_vmcs);
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
    P(cpu_has_vmx_vmfunc, "VM Functions");
    P(cpu_has_vmx_virt_exceptions, "Virtualisation Exceptions");
    P(cpu_has_vmx_pml, "Page Modification Logging");
    P(cpu_has_vmx_tsc_scaling, "TSC Scaling");
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
    u64 _vmx_vmfunc = 0;
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
               SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING |
               SECONDARY_EXEC_ENABLE_RDTSCP |
               SECONDARY_EXEC_PAUSE_LOOP_EXITING |
               SECONDARY_EXEC_ENABLE_INVPCID |
               SECONDARY_EXEC_ENABLE_VM_FUNCTIONS |
               SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS |
               SECONDARY_EXEC_XSAVES |
               SECONDARY_EXEC_TSC_SCALING);
        rdmsrl(MSR_IA32_VMX_MISC, _vmx_misc_cap);
        if ( _vmx_misc_cap & VMX_MISC_VMWRITE_ALL )
            opt |= SECONDARY_EXEC_ENABLE_VMCS_SHADOWING;
        if ( opt_vpid_enabled )
            opt |= SECONDARY_EXEC_ENABLE_VPID;
        if ( opt_unrestricted_guest_enabled )
            opt |= SECONDARY_EXEC_UNRESTRICTED_GUEST;
        if ( opt_pml_enabled )
            opt |= SECONDARY_EXEC_ENABLE_PML;

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

        if ( !opt_ept_ad )
            _vmx_ept_vpid_cap &= ~VMX_EPT_AD_BIT;
        else if ( /* Work around Erratum AVR41 on Avoton processors. */
                  boot_cpu_data.x86 == 6 && boot_cpu_data.x86_model == 0x4d &&
                  opt_ept_ad < 0 )
            _vmx_ept_vpid_cap &= ~VMX_EPT_AD_BIT;

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

        /* EPT A/D bits is required for PML */
        if ( !(_vmx_ept_vpid_cap & VMX_EPT_AD_BIT) )
            _vmx_secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_PML;
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

    /* PML cannot be supported if EPT is not used */
    if ( !(_vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT) )
        _vmx_secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_PML;

    /* Turn off opt_pml_enabled if PML feature is not present */
    if ( !(_vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_PML) )
        opt_pml_enabled = 0;

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
     * delivery" and "acknowledge interrupt on exit" is set. For the latter
     * is a minimal requirement, only check the former, which is optional.
     */
    if ( !(_vmx_secondary_exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) )
        _vmx_pin_based_exec_control &= ~PIN_BASED_POSTED_INTERRUPT;

    if ( iommu_intpost &&
         !(_vmx_pin_based_exec_control & PIN_BASED_POSTED_INTERRUPT) )
    {
        printk("Intel VT-d Posted Interrupt is disabled for CPU-side Posted "
               "Interrupt is not enabled\n");
        iommu_intpost = 0;
    }

    /* The IA32_VMX_VMFUNC MSR exists only when VMFUNC is available */
    if ( _vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_VM_FUNCTIONS )
    {
        rdmsrl(MSR_IA32_VMX_VMFUNC, _vmx_vmfunc);

        /*
         * VMFUNC leaf 0 (EPTP switching) must be supported.
         *
         * Or we just don't use VMFUNC.
         */
        if ( !(_vmx_vmfunc & VMX_VMFUNC_EPTP_SWITCHING) )
            _vmx_secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_VM_FUNCTIONS;
    }

    /* Virtualization exceptions are only enabled if VMFUNC is enabled */
    if ( !(_vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_VM_FUNCTIONS) )
        _vmx_secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS;

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
        vmx_vmfunc                 = _vmx_vmfunc;
        vmx_virt_exception         = !!(_vmx_secondary_exec_control &
                                       SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS);
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
        mismatch |= cap_check(
            "VMFUNC Capability",
            vmx_vmfunc, _vmx_vmfunc);
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

static paddr_t vmx_alloc_vmcs(void)
{
    struct page_info *pg;
    struct vmcs_struct *vmcs;

    if ( (pg = alloc_domheap_page(NULL, 0)) == NULL )
    {
        gdprintk(XENLOG_WARNING, "Failed to allocate VMCS.\n");
        return 0;
    }

    vmcs = __map_domain_page(pg);
    clear_page(vmcs);
    vmcs->vmcs_revision_id = vmcs_revision_id;
    unmap_domain_page(vmcs);

    return page_to_maddr(pg);
}

static void vmx_free_vmcs(paddr_t pa)
{
    free_domheap_page(maddr_to_page(pa));
}

static void __vmx_clear_vmcs(void *info)
{
    struct vcpu *v = info;
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    /* Otherwise we can nest (vmx_cpu_down() vs. vmx_clear_vmcs()). */
    ASSERT(!local_irq_is_enabled());

    if ( arch_vmx->active_cpu == smp_processor_id() )
    {
        __vmpclear(arch_vmx->vmcs_pa);
        if ( arch_vmx->vmcs_shadow_maddr )
            __vmpclear(arch_vmx->vmcs_shadow_maddr);

        arch_vmx->active_cpu = -1;
        arch_vmx->launched   = 0;

        list_del(&arch_vmx->active_list);

        if ( arch_vmx->vmcs_pa == this_cpu(current_vmcs) )
            this_cpu(current_vmcs) = 0;
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

    __vmptrld(v->arch.hvm_vmx.vmcs_pa);
    this_cpu(current_vmcs) = v->arch.hvm_vmx.vmcs_pa;

    local_irq_restore(flags);
}

void vmx_vmcs_reload(struct vcpu *v)
{
    /*
     * As we may be running with interrupts disabled, we can't acquire
     * v->arch.hvm_vmx.vmcs_lock here. However, with interrupts disabled
     * the VMCS can't be taken away from us anymore if we still own it.
     */
    ASSERT(v->is_running || !local_irq_is_enabled());
    if ( v->arch.hvm_vmx.vmcs_pa == this_cpu(current_vmcs) )
        return;

    vmx_load_vmcs(v);
}

int vmx_cpu_up_prepare(unsigned int cpu)
{
    /*
     * If nvmx_cpu_up_prepare() failed, do not return failure and just fallback
     * to legacy mode for vvmcs synchronization.
     */
    if ( nvmx_cpu_up_prepare(cpu) != 0 )
        printk("CPU%d: Could not allocate virtual VMCS buffer.\n", cpu);

    if ( per_cpu(vmxon_region, cpu) )
        return 0;

    per_cpu(vmxon_region, cpu) = vmx_alloc_vmcs();
    if ( per_cpu(vmxon_region, cpu) )
        return 0;

    printk("CPU%d: Could not allocate host VMCS\n", cpu);
    nvmx_cpu_dead(cpu);
    return -ENOMEM;
}

void vmx_cpu_dead(unsigned int cpu)
{
    vmx_free_vmcs(per_cpu(vmxon_region, cpu));
    per_cpu(vmxon_region, cpu) = 0;
    nvmx_cpu_dead(cpu);
    vmx_pi_desc_fixup(cpu);
}

int _vmx_cpu_up(bool bsp)
{
    u32 eax, edx;
    int rc, bios_locked, cpu = smp_processor_id();
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
        return -EINVAL;
    }

    rdmsr(MSR_IA32_FEATURE_CONTROL, eax, edx);

    bios_locked = !!(eax & IA32_FEATURE_CONTROL_LOCK);
    if ( bios_locked )
    {
        if ( !(eax & (tboot_in_measured_env()
                      ? IA32_FEATURE_CONTROL_ENABLE_VMXON_INSIDE_SMX
                      : IA32_FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX)) )
        {
            printk("CPU%d: VMX disabled by BIOS.\n", cpu);
            return -EINVAL;
        }
    }
    else
    {
        eax  = IA32_FEATURE_CONTROL_LOCK;
        eax |= IA32_FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX;
        if ( test_bit(X86_FEATURE_SMX, &boot_cpu_data.x86_capability) )
            eax |= IA32_FEATURE_CONTROL_ENABLE_VMXON_INSIDE_SMX;
        wrmsr(MSR_IA32_FEATURE_CONTROL, eax, 0);
    }

    if ( (rc = vmx_init_vmcs_config()) != 0 )
        return rc;

    INIT_LIST_HEAD(&this_cpu(active_vmcs_list));

    if ( bsp && (rc = vmx_cpu_up_prepare(cpu)) != 0 )
        return rc;

    switch ( __vmxon(this_cpu(vmxon_region)) )
    {
    case -2: /* #UD or #GP */
        if ( bios_locked &&
             test_bit(X86_FEATURE_SMX, &boot_cpu_data.x86_capability) &&
             (!(eax & IA32_FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX) ||
              !(eax & IA32_FEATURE_CONTROL_ENABLE_VMXON_INSIDE_SMX)) )
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

    vmx_pi_per_cpu_init(cpu);

    return 0;
}

int vmx_cpu_up()
{
    return _vmx_cpu_up(false);
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
        return v->arch.hvm_vmx.vmcs_pa == this_cpu(current_vmcs);

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
        if ( is_hvm_vcpu(current) )
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

void vmx_clear_msr_intercept(struct vcpu *v, unsigned int msr,
                             enum vmx_msr_intercept_type type)
{
    struct vmx_msr_bitmap *msr_bitmap = v->arch.hvm_vmx.msr_bitmap;
    struct domain *d = v->domain;

    /* VMX MSR bitmap supported? */
    if ( msr_bitmap == NULL )
        return;

    if ( unlikely(monitored_msr(d, msr)) )
        return;

    if ( msr <= 0x1fff )
    {
        if ( type & VMX_MSR_R )
            clear_bit(msr, msr_bitmap->read_low);
        if ( type & VMX_MSR_W )
            clear_bit(msr, msr_bitmap->write_low);
    }
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
    {
        msr &= 0x1fff;
        if ( type & VMX_MSR_R )
            clear_bit(msr, msr_bitmap->read_high);
        if ( type & VMX_MSR_W )
            clear_bit(msr, msr_bitmap->write_high);
    }
    else
        ASSERT(!"MSR out of range for interception\n");
}

void vmx_set_msr_intercept(struct vcpu *v, unsigned int msr,
                           enum vmx_msr_intercept_type type)
{
    struct vmx_msr_bitmap *msr_bitmap = v->arch.hvm_vmx.msr_bitmap;

    /* VMX MSR bitmap supported? */
    if ( msr_bitmap == NULL )
        return;

    if ( msr <= 0x1fff )
    {
        if ( type & VMX_MSR_R )
            set_bit(msr, msr_bitmap->read_low);
        if ( type & VMX_MSR_W )
            set_bit(msr, msr_bitmap->write_low);
    }
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
    {
        msr &= 0x1fff;
        if ( type & VMX_MSR_R )
            set_bit(msr, msr_bitmap->read_high);
        if ( type & VMX_MSR_W )
            set_bit(msr, msr_bitmap->write_high);
    }
    else
        ASSERT(!"MSR out of range for interception\n");
}

bool vmx_msr_is_intercepted(struct vmx_msr_bitmap *msr_bitmap,
                            unsigned int msr, bool is_write)
{
    if ( msr <= 0x1fff )
        return test_bit(msr, is_write ? msr_bitmap->write_low
                                      : msr_bitmap->read_low);
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
        return test_bit(msr & 0x1fff, is_write ? msr_bitmap->write_high
                                               : msr_bitmap->read_high);
    else
        /* MSRs outside the bitmap ranges are always intercepted. */
        return true;
}


/*
 * Switch VMCS between layer 1 & 2 guest
 */
void vmx_vmcs_switch(paddr_t from, paddr_t to)
{
    struct arch_vmx_struct *vmx = &current->arch.hvm_vmx;
    spin_lock(&vmx->vmcs_lock);

    __vmpclear(from);
    if ( vmx->vmcs_shadow_maddr )
        __vmpclear(vmx->vmcs_shadow_maddr);
    __vmptrld(to);

    vmx->vmcs_pa = to;
    vmx->launched = 0;
    this_cpu(current_vmcs) = to;

    if ( vmx->hostenv_migrated )
    {
        vmx->hostenv_migrated = 0;
        vmx_set_host_env(current);
    }

    spin_unlock(&vmx->vmcs_lock);
}

void virtual_vmcs_enter(const struct vcpu *v)
{
    __vmptrld(v->arch.hvm_vmx.vmcs_shadow_maddr);
}

void virtual_vmcs_exit(const struct vcpu *v)
{
    paddr_t cur = this_cpu(current_vmcs);

    __vmpclear(v->arch.hvm_vmx.vmcs_shadow_maddr);
    if ( cur )
        __vmptrld(cur);
}

u64 virtual_vmcs_vmread(const struct vcpu *v, u32 vmcs_encoding)
{
    u64 res;

    virtual_vmcs_enter(v);
    __vmread(vmcs_encoding, &res);
    virtual_vmcs_exit(v);

    return res;
}

enum vmx_insn_errno virtual_vmcs_vmread_safe(const struct vcpu *v,
                                             u32 vmcs_encoding, u64 *val)
{
    enum vmx_insn_errno ret;

    virtual_vmcs_enter(v);
    ret = vmread_safe(vmcs_encoding, val);
    virtual_vmcs_exit(v);

    return ret;
}

void virtual_vmcs_vmwrite(const struct vcpu *v, u32 vmcs_encoding, u64 val)
{
    virtual_vmcs_enter(v);
    __vmwrite(vmcs_encoding, val);
    virtual_vmcs_exit(v);
}

enum vmx_insn_errno virtual_vmcs_vmwrite_safe(const struct vcpu *v,
                                              u32 vmcs_encoding, u64 val)
{
    enum vmx_insn_errno ret;

    virtual_vmcs_enter(v);
    ret = vmwrite_safe(vmcs_encoding, val);
    virtual_vmcs_exit(v);

    return ret;
}

/*
 * This function is only called in a vCPU's initialization phase,
 * so we can update the posted-interrupt descriptor in non-atomic way.
 */
static void pi_desc_init(struct vcpu *v)
{
    v->arch.hvm_vmx.pi_desc.nv = posted_intr_vector;

    /*
     * Mark NDST as invalid, then we can use this invalid value as a
     * marker to whether update NDST or not in vmx_pi_hooks_assign().
     */
    v->arch.hvm_vmx.pi_desc.ndst = APIC_INVALID_DEST;
}

static int construct_vmcs(struct vcpu *v)
{
    struct domain *d = v->domain;
    u32 vmexit_ctl = vmx_vmexit_control;
    u32 vmentry_ctl = vmx_vmentry_control;

    vmx_vmcs_enter(v);

    /* VMCS controls. */
    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_control);

    v->arch.hvm_vmx.exec_control = vmx_cpu_based_exec_control;
    if ( d->arch.vtsc && !cpu_has_vmx_tsc_scaling )
        v->arch.hvm_vmx.exec_control |= CPU_BASED_RDTSC_EXITING;

    v->arch.hvm_vmx.secondary_exec_control = vmx_secondary_exec_control;

    /*
     * Disable descriptor table exiting: It's controlled by the VM event
     * monitor requesting it.
     */
    v->arch.hvm_vmx.secondary_exec_control &=
        ~SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING;

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

    /* Disable VMFUNC and #VE for now: they may be enabled later by altp2m. */
    v->arch.hvm_vmx.secondary_exec_control &=
        ~(SECONDARY_EXEC_ENABLE_VM_FUNCTIONS |
          SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS);

    if ( !has_vlapic(d) )
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
        struct vmx_msr_bitmap *msr_bitmap = alloc_xenheap_page();

        if ( msr_bitmap == NULL )
        {
            vmx_vmcs_exit(v);
            return -ENOMEM;
        }

        memset(msr_bitmap, ~0, PAGE_SIZE);
        v->arch.hvm_vmx.msr_bitmap = msr_bitmap;
        __vmwrite(MSR_BITMAP, virt_to_maddr(msr_bitmap));

        vmx_clear_msr_intercept(v, MSR_FS_BASE, VMX_MSR_RW);
        vmx_clear_msr_intercept(v, MSR_GS_BASE, VMX_MSR_RW);
        vmx_clear_msr_intercept(v, MSR_SHADOW_GS_BASE, VMX_MSR_RW);
        vmx_clear_msr_intercept(v, MSR_IA32_SYSENTER_CS, VMX_MSR_RW);
        vmx_clear_msr_intercept(v, MSR_IA32_SYSENTER_ESP, VMX_MSR_RW);
        vmx_clear_msr_intercept(v, MSR_IA32_SYSENTER_EIP, VMX_MSR_RW);
        if ( paging_mode_hap(d) && (!iommu_enabled || iommu_snoop) )
            vmx_clear_msr_intercept(v, MSR_IA32_CR_PAT, VMX_MSR_RW);
        if ( (vmexit_ctl & VM_EXIT_CLEAR_BNDCFGS) &&
             (vmentry_ctl & VM_ENTRY_LOAD_BNDCFGS) )
            vmx_clear_msr_intercept(v, MSR_IA32_BNDCFGS, VMX_MSR_RW);
    }

    /* I/O access bitmap. */
    __vmwrite(IO_BITMAP_A, __pa(d->arch.hvm_domain.io_bitmap));
    __vmwrite(IO_BITMAP_B, __pa(d->arch.hvm_domain.io_bitmap) + PAGE_SIZE);

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
        if ( iommu_intpost )
            pi_desc_init(v);

        __vmwrite(PI_DESC_ADDR, virt_to_maddr(&v->arch.hvm_vmx.pi_desc));
        __vmwrite(POSTED_INTR_NOTIFICATION_VECTOR, posted_intr_vector);
    }

    /* Disable PML anyway here as it will only be enabled in log dirty mode */
    v->arch.hvm_vmx.secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_PML;

    /* Host data selectors. */
    __vmwrite(HOST_SS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_DS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_ES_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_FS_SELECTOR, 0);
    __vmwrite(HOST_GS_SELECTOR, 0);
    __vmwrite(HOST_FS_BASE, 0);
    __vmwrite(HOST_GS_BASE, 0);
    __vmwrite(HOST_TR_SELECTOR, TSS_ENTRY << 3);

    /* Host control registers. */
    v->arch.hvm_vmx.host_cr0 = read_cr0() | X86_CR0_TS;
    __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);
    __vmwrite(HOST_CR4, mmu_cr4_features);

    /* Host CS:RIP. */
    __vmwrite(HOST_CS_SELECTOR, __HYPERVISOR_CS);
    __vmwrite(HOST_RIP, (unsigned long)vmx_asm_vmexit_handler);

    /* Host SYSENTER CS:RIP. */
    __vmwrite(HOST_SYSENTER_CS, __HYPERVISOR_CS);
    __vmwrite(HOST_SYSENTER_EIP, (unsigned long)sysenter_entry);

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

    if ( paging_mode_hap(d) )
    {
        struct p2m_domain *p2m = p2m_get_hostp2m(d);
        struct ept_data *ept = &p2m->ept;

        ept->mfn = pagetable_get_pfn(p2m_get_pagetable(p2m));
        __vmwrite(EPT_POINTER, ept->eptp);
    }

    if ( paging_mode_hap(d) )
    {
        u64 host_pat, guest_pat;

        rdmsrl(MSR_IA32_CR_PAT, host_pat);
        guest_pat = MSR_IA32_CR_PAT_RESET;

        __vmwrite(HOST_PAT, host_pat);
        __vmwrite(GUEST_PAT, guest_pat);
    }
    if ( cpu_has_vmx_mpx )
        __vmwrite(GUEST_BNDCFGS, 0);
    if ( cpu_has_vmx_xsaves )
        __vmwrite(XSS_EXIT_BITMAP, 0);

    if ( cpu_has_vmx_tsc_scaling )
        __vmwrite(TSC_MULTIPLIER, d->arch.hvm_domain.tsc_scaling_ratio);

    vmx_vmcs_exit(v);

    /* will update HOST & GUEST_CR3 as reqd */
    paging_update_paging_modes(v);

    vmx_vlapic_msr_changed(v);

    return 0;
}

static int vmx_msr_entry_key_cmp(const void *key, const void *elt)
{
    const u32 *msr = key;
    const struct vmx_msr_entry *entry = elt;

    if ( *msr > entry->index )
        return 1;
    if ( *msr < entry->index )
        return -1;

    return 0;
}

struct vmx_msr_entry *vmx_find_msr(u32 msr, int type)
{
    struct vcpu *curr = current;
    unsigned int msr_count;
    struct vmx_msr_entry *msr_area;

    if ( type == VMX_GUEST_MSR )
    {
        msr_count = curr->arch.hvm_vmx.msr_count;
        msr_area = curr->arch.hvm_vmx.msr_area;
    }
    else
    {
        ASSERT(type == VMX_HOST_MSR);
        msr_count = curr->arch.hvm_vmx.host_msr_count;
        msr_area = curr->arch.hvm_vmx.host_msr_area;
    }

    if ( msr_area == NULL )
        return NULL;

    return bsearch(&msr, msr_area, msr_count, sizeof(struct vmx_msr_entry),
                   vmx_msr_entry_key_cmp);
}

int vmx_read_guest_msr(u32 msr, u64 *val)
{
    struct vmx_msr_entry *ent;

    if ( (ent = vmx_find_msr(msr, VMX_GUEST_MSR)) != NULL )
    {
        *val = ent->data;
        return 0;
    }

    return -ESRCH;
}

int vmx_write_guest_msr(u32 msr, u64 val)
{
    struct vmx_msr_entry *ent;

    if ( (ent = vmx_find_msr(msr, VMX_GUEST_MSR)) != NULL )
    {
        ent->data = val;
        return 0;
    }

    return -ESRCH;
}

int vmx_add_msr(u32 msr, int type)
{
    struct vcpu *curr = current;
    unsigned int idx, *msr_count;
    struct vmx_msr_entry **msr_area, *msr_area_elem;

    if ( type == VMX_GUEST_MSR )
    {
        msr_count = &curr->arch.hvm_vmx.msr_count;
        msr_area = &curr->arch.hvm_vmx.msr_area;
    }
    else
    {
        ASSERT(type == VMX_HOST_MSR);
        msr_count = &curr->arch.hvm_vmx.host_msr_count;
        msr_area = &curr->arch.hvm_vmx.host_msr_area;
    }

    if ( *msr_area == NULL )
    {
        if ( (*msr_area = alloc_xenheap_page()) == NULL )
            return -ENOMEM;

        if ( type == VMX_GUEST_MSR )
        {
            __vmwrite(VM_EXIT_MSR_STORE_ADDR, virt_to_maddr(*msr_area));
            __vmwrite(VM_ENTRY_MSR_LOAD_ADDR, virt_to_maddr(*msr_area));
        }
        else
            __vmwrite(VM_EXIT_MSR_LOAD_ADDR, virt_to_maddr(*msr_area));
    }

    for ( idx = 0; idx < *msr_count && (*msr_area)[idx].index <= msr; idx++ )
        if ( (*msr_area)[idx].index == msr )
            return 0;

    if ( *msr_count == (PAGE_SIZE / sizeof(struct vmx_msr_entry)) )
        return -ENOSPC;

    memmove(*msr_area + idx + 1, *msr_area + idx,
            sizeof(*msr_area_elem) * (*msr_count - idx));

    msr_area_elem = *msr_area + idx;
    msr_area_elem->index = msr;
    msr_area_elem->mbz = 0;

    ++*msr_count;

    if ( type == VMX_GUEST_MSR )
    {
        msr_area_elem->data = 0;
        __vmwrite(VM_EXIT_MSR_STORE_COUNT, *msr_count);
        __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, *msr_count);
    }
    else
    {
        rdmsrl(msr, msr_area_elem->data);
        __vmwrite(VM_EXIT_MSR_LOAD_COUNT, *msr_count);
    }

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

bool_t vmx_vcpu_pml_enabled(const struct vcpu *v)
{
    return !!(v->arch.hvm_vmx.secondary_exec_control &
              SECONDARY_EXEC_ENABLE_PML);
}

int vmx_vcpu_enable_pml(struct vcpu *v)
{
    if ( vmx_vcpu_pml_enabled(v) )
        return 0;

    v->arch.hvm_vmx.pml_pg = v->domain->arch.paging.alloc_page(v->domain);
    if ( !v->arch.hvm_vmx.pml_pg )
        return -ENOMEM;

    vmx_vmcs_enter(v);

    __vmwrite(PML_ADDRESS, page_to_mfn(v->arch.hvm_vmx.pml_pg) << PAGE_SHIFT);
    __vmwrite(GUEST_PML_INDEX, NR_PML_ENTRIES - 1);

    v->arch.hvm_vmx.secondary_exec_control |= SECONDARY_EXEC_ENABLE_PML;

    __vmwrite(SECONDARY_VM_EXEC_CONTROL,
              v->arch.hvm_vmx.secondary_exec_control);

    vmx_vmcs_exit(v);

    return 0;
}

void vmx_vcpu_disable_pml(struct vcpu *v)
{
    if ( !vmx_vcpu_pml_enabled(v) )
        return;

    /* Make sure we don't lose any logged GPAs. */
    vmx_vcpu_flush_pml_buffer(v);

    vmx_vmcs_enter(v);

    v->arch.hvm_vmx.secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_PML;
    __vmwrite(SECONDARY_VM_EXEC_CONTROL,
              v->arch.hvm_vmx.secondary_exec_control);

    vmx_vmcs_exit(v);

    v->domain->arch.paging.free_page(v->domain, v->arch.hvm_vmx.pml_pg);
    v->arch.hvm_vmx.pml_pg = NULL;
}

void vmx_vcpu_flush_pml_buffer(struct vcpu *v)
{
    uint64_t *pml_buf;
    unsigned long pml_idx;

    ASSERT((v == current) || (!vcpu_runnable(v) && !v->is_running));
    ASSERT(vmx_vcpu_pml_enabled(v));

    vmx_vmcs_enter(v);

    __vmread(GUEST_PML_INDEX, &pml_idx);

    /* Do nothing if PML buffer is empty. */
    if ( pml_idx == (NR_PML_ENTRIES - 1) )
        goto out;

    pml_buf = __map_domain_page(v->arch.hvm_vmx.pml_pg);

    /*
     * PML index can be either 2^16-1 (buffer is full), or 0 ~ NR_PML_ENTRIES-1
     * (buffer is not full), and in latter case PML index always points to next
     * available entity.
     */
    if ( pml_idx >= NR_PML_ENTRIES )
        pml_idx = 0;
    else
        pml_idx++;

    for ( ; pml_idx < NR_PML_ENTRIES; pml_idx++ )
    {
        unsigned long gfn = pml_buf[pml_idx] >> PAGE_SHIFT;

        /*
         * Need to change type from log-dirty to normal memory for logged GFN.
         * hap_track_dirty_vram depends on it to work. And we mark all logged
         * GFNs to be dirty, as we cannot be sure whether it's safe to ignore
         * GFNs on which p2m_change_type_one returns failure. The failure cases
         * are very rare, and additional cost is negligible, but a missing mark
         * is extremely difficult to debug.
         */
        p2m_change_type_one(v->domain, gfn, p2m_ram_logdirty, p2m_ram_rw);

        /* HVM guest: pfn == gfn */
        paging_mark_pfn_dirty(v->domain, _pfn(gfn));
    }

    unmap_domain_page(pml_buf);

    /* Reset PML index */
    __vmwrite(GUEST_PML_INDEX, NR_PML_ENTRIES - 1);

 out:
    vmx_vmcs_exit(v);
}

bool_t vmx_domain_pml_enabled(const struct domain *d)
{
    return !!(d->arch.hvm_domain.vmx.status & VMX_DOMAIN_PML_ENABLED);
}

/*
 * This function enables PML for particular domain. It should be called when
 * domain is paused.
 *
 * PML needs to be enabled globally for all vcpus of the domain, as PML buffer
 * and PML index are pre-vcpu, but EPT table is shared by vcpus, therefore
 * enabling PML on partial vcpus won't work.
 */
int vmx_domain_enable_pml(struct domain *d)
{
    struct vcpu *v;
    int rc;

    ASSERT(atomic_read(&d->pause_count));

    if ( vmx_domain_pml_enabled(d) )
        return 0;

    for_each_vcpu ( d, v )
        if ( (rc = vmx_vcpu_enable_pml(v)) != 0 )
            goto error;

    d->arch.hvm_domain.vmx.status |= VMX_DOMAIN_PML_ENABLED;

    return 0;

 error:
    for_each_vcpu ( d, v )
        if ( vmx_vcpu_pml_enabled(v) )
            vmx_vcpu_disable_pml(v);
    return rc;
}

/*
 * Disable PML for particular domain. Called when domain is paused.
 *
 * The same as enabling PML for domain, disabling PML should be done for all
 * vcpus at once.
 */
void vmx_domain_disable_pml(struct domain *d)
{
    struct vcpu *v;

    ASSERT(atomic_read(&d->pause_count));

    if ( !vmx_domain_pml_enabled(d) )
        return;

    for_each_vcpu ( d, v )
        vmx_vcpu_disable_pml(v);

    d->arch.hvm_domain.vmx.status &= ~VMX_DOMAIN_PML_ENABLED;
}

/*
 * Flush PML buffer of all vcpus, and update the logged dirty pages to log-dirty
 * radix tree. Called when domain is paused.
 */
void vmx_domain_flush_pml_buffers(struct domain *d)
{
    struct vcpu *v;

    ASSERT(atomic_read(&d->pause_count));

    if ( !vmx_domain_pml_enabled(d) )
        return;

    for_each_vcpu ( d, v )
        vmx_vcpu_flush_pml_buffer(v);
}

static void vmx_vcpu_update_eptp(struct vcpu *v, u64 eptp)
{
    vmx_vmcs_enter(v);
    __vmwrite(EPT_POINTER, eptp);
    vmx_vmcs_exit(v);
}

/*
 * Update EPTP data to VMCS of all vcpus of the domain. Must be called when
 * domain is paused.
 */
void vmx_domain_update_eptp(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct vcpu *v;

    ASSERT(atomic_read(&d->pause_count));

    for_each_vcpu ( d, v )
        vmx_vcpu_update_eptp(v, p2m->ept.eptp);

    ept_sync_domain(p2m);
}

int vmx_create_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;
    int rc;

    if ( (arch_vmx->vmcs_pa = vmx_alloc_vmcs()) == 0 )
        return -ENOMEM;

    INIT_LIST_HEAD(&arch_vmx->active_list);
    __vmpclear(arch_vmx->vmcs_pa);
    arch_vmx->active_cpu = -1;
    arch_vmx->launched   = 0;

    if ( (rc = construct_vmcs(v)) != 0 )
    {
        vmx_free_vmcs(arch_vmx->vmcs_pa);
        return rc;
    }

    return 0;
}

void vmx_destroy_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    vmx_clear_vmcs(v);

    vmx_free_vmcs(arch_vmx->vmcs_pa);

    free_xenheap_page(v->arch.hvm_vmx.host_msr_area);
    free_xenheap_page(v->arch.hvm_vmx.msr_area);
    free_xenheap_page(v->arch.hvm_vmx.msr_bitmap);
}

void vmx_vmentry_failure(void)
{
    struct vcpu *curr = current;
    unsigned long error;

    __vmread(VM_INSTRUCTION_ERROR, &error);
    gprintk(XENLOG_ERR, "VM%s error: %#lx\n",
            curr->arch.hvm_vmx.launched ? "RESUME" : "LAUNCH", error);

    if ( error == VMX_INSN_INVALID_CONTROL_STATE ||
         error == VMX_INSN_INVALID_HOST_STATE )
        vmcs_dump_vcpu(curr);

    domain_crash_synchronous();
}

void vmx_do_resume(struct vcpu *v)
{
    bool_t debug_state;

    if ( v->arch.hvm_vmx.active_cpu == smp_processor_id() )
        vmx_vmcs_reload(v);
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
                  || v->domain->arch.monitor.software_breakpoint_enabled
                  || v->domain->arch.monitor.singlestep_enabled;

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

    return vmread_safe(field, &val) ? 0 : val;
}

#define vmr16(fld) ({             \
    BUILD_BUG_ON((fld) & 0x6001); \
    (uint16_t)vmr(fld);           \
})

#define vmr32(fld) ({                         \
    BUILD_BUG_ON(((fld) & 0x6001) != 0x4000); \
    (uint32_t)vmr(fld);                       \
})

static void vmx_dump_sel(char *name, uint32_t selector)
{
    uint32_t sel, attr, limit;
    uint64_t base;
    sel = vmr(selector);
    attr = vmr(selector + (GUEST_ES_AR_BYTES - GUEST_ES_SELECTOR));
    limit = vmr(selector + (GUEST_ES_LIMIT - GUEST_ES_SELECTOR));
    base = vmr(selector + (GUEST_ES_BASE - GUEST_ES_SELECTOR));
    printk("%s: %04x %05x %08x %016"PRIx64"\n", name, sel, attr, limit, base);
}

static void vmx_dump_sel2(char *name, uint32_t lim)
{
    uint32_t limit;
    uint64_t base;
    limit = vmr(lim);
    base = vmr(lim + (GUEST_GDTR_BASE - GUEST_GDTR_LIMIT));
    printk("%s:            %08x %016"PRIx64"\n", name, limit, base);
}

void vmcs_dump_vcpu(struct vcpu *v)
{
    struct cpu_user_regs *regs = &v->arch.user_regs;
    uint32_t vmentry_ctl, vmexit_ctl;
    unsigned long cr4;
    uint64_t efer;
    unsigned int i, n;

    if ( v == current )
        regs = guest_cpu_user_regs();

    vmx_vmcs_enter(v);

    vmentry_ctl = vmr32(VM_ENTRY_CONTROLS),
    vmexit_ctl = vmr32(VM_EXIT_CONTROLS);
    cr4 = vmr(GUEST_CR4);
    efer = vmr(GUEST_EFER);

    printk("*** Guest State ***\n");
    printk("CR0: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
           vmr(GUEST_CR0), vmr(CR0_READ_SHADOW), vmr(CR0_GUEST_HOST_MASK));
    printk("CR4: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
           cr4, vmr(CR4_READ_SHADOW), vmr(CR4_GUEST_HOST_MASK));
    printk("CR3 = 0x%016lx\n", vmr(GUEST_CR3));
    if ( (v->arch.hvm_vmx.secondary_exec_control &
          SECONDARY_EXEC_ENABLE_EPT) &&
         (cr4 & X86_CR4_PAE) && !(efer & EFER_LMA) )
    {
        printk("PDPTE0 = 0x%016lx  PDPTE1 = 0x%016lx\n",
               vmr(GUEST_PDPTE(0)), vmr(GUEST_PDPTE(1)));
        printk("PDPTE2 = 0x%016lx  PDPTE3 = 0x%016lx\n",
               vmr(GUEST_PDPTE(2)), vmr(GUEST_PDPTE(3)));
    }
    printk("RSP = 0x%016lx (0x%016lx)  RIP = 0x%016lx (0x%016lx)\n",
           vmr(GUEST_RSP), regs->rsp,
           vmr(GUEST_RIP), regs->rip);
    printk("RFLAGS=0x%08lx (0x%08lx)  DR7 = 0x%016lx\n",
           vmr(GUEST_RFLAGS), regs->rflags,
           vmr(GUEST_DR7));
    printk("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
           vmr(GUEST_SYSENTER_ESP),
           vmr32(GUEST_SYSENTER_CS), vmr(GUEST_SYSENTER_EIP));
    printk("       sel  attr  limit   base\n");
    vmx_dump_sel("  CS", GUEST_CS_SELECTOR);
    vmx_dump_sel("  DS", GUEST_DS_SELECTOR);
    vmx_dump_sel("  SS", GUEST_SS_SELECTOR);
    vmx_dump_sel("  ES", GUEST_ES_SELECTOR);
    vmx_dump_sel("  FS", GUEST_FS_SELECTOR);
    vmx_dump_sel("  GS", GUEST_GS_SELECTOR);
    vmx_dump_sel2("GDTR", GUEST_GDTR_LIMIT);
    vmx_dump_sel("LDTR", GUEST_LDTR_SELECTOR);
    vmx_dump_sel2("IDTR", GUEST_IDTR_LIMIT);
    vmx_dump_sel("  TR", GUEST_TR_SELECTOR);
    if ( (vmexit_ctl & (VM_EXIT_SAVE_GUEST_PAT | VM_EXIT_SAVE_GUEST_EFER)) ||
         (vmentry_ctl & (VM_ENTRY_LOAD_GUEST_PAT | VM_ENTRY_LOAD_GUEST_EFER)) )
        printk("EFER = 0x%016lx  PAT = 0x%016lx\n", efer, vmr(GUEST_PAT));
    printk("PreemptionTimer = 0x%08x  SM Base = 0x%08x\n",
           vmr32(GUEST_PREEMPTION_TIMER), vmr32(GUEST_SMBASE));
    printk("DebugCtl = 0x%016lx  DebugExceptions = 0x%016lx\n",
           vmr(GUEST_IA32_DEBUGCTL), vmr(GUEST_PENDING_DBG_EXCEPTIONS));
    if ( vmentry_ctl & (VM_ENTRY_LOAD_PERF_GLOBAL_CTRL | VM_ENTRY_LOAD_BNDCFGS) )
        printk("PerfGlobCtl = 0x%016lx  BndCfgS = 0x%016lx\n",
               vmr(GUEST_PERF_GLOBAL_CTRL), vmr(GUEST_BNDCFGS));
    printk("Interruptibility = %08x  ActivityState = %08x\n",
           vmr32(GUEST_INTERRUPTIBILITY_INFO), vmr32(GUEST_ACTIVITY_STATE));
    if ( v->arch.hvm_vmx.secondary_exec_control &
         SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY )
        printk("InterruptStatus = %04x\n", vmr16(GUEST_INTR_STATUS));

    printk("*** Host State ***\n");
    printk("RIP = 0x%016lx (%ps)  RSP = 0x%016lx\n",
           vmr(HOST_RIP), (void *)vmr(HOST_RIP), vmr(HOST_RSP));
    printk("CS=%04x SS=%04x DS=%04x ES=%04x FS=%04x GS=%04x TR=%04x\n",
           vmr16(HOST_CS_SELECTOR), vmr16(HOST_SS_SELECTOR),
           vmr16(HOST_DS_SELECTOR), vmr16(HOST_ES_SELECTOR),
           vmr16(HOST_FS_SELECTOR), vmr16(HOST_GS_SELECTOR),
           vmr16(HOST_TR_SELECTOR));
    printk("FSBase=%016lx GSBase=%016lx TRBase=%016lx\n",
           vmr(HOST_FS_BASE), vmr(HOST_GS_BASE), vmr(HOST_TR_BASE));
    printk("GDTBase=%016lx IDTBase=%016lx\n",
           vmr(HOST_GDTR_BASE), vmr(HOST_IDTR_BASE));
    printk("CR0=%016lx CR3=%016lx CR4=%016lx\n",
           vmr(HOST_CR0), vmr(HOST_CR3), vmr(HOST_CR4));
    printk("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
           vmr(HOST_SYSENTER_ESP),
           vmr32(HOST_SYSENTER_CS), vmr(HOST_SYSENTER_EIP));
    if ( vmexit_ctl & (VM_EXIT_LOAD_HOST_PAT | VM_EXIT_LOAD_HOST_EFER) )
        printk("EFER = 0x%016lx  PAT = 0x%016lx\n", vmr(HOST_EFER), vmr(HOST_PAT));
    if ( vmexit_ctl & VM_EXIT_LOAD_PERF_GLOBAL_CTRL )
        printk("PerfGlobCtl = 0x%016lx\n",
               vmr(HOST_PERF_GLOBAL_CTRL));

    printk("*** Control State ***\n");
    printk("PinBased=%08x CPUBased=%08x SecondaryExec=%08x\n",
           vmr32(PIN_BASED_VM_EXEC_CONTROL),
           vmr32(CPU_BASED_VM_EXEC_CONTROL),
           vmr32(SECONDARY_VM_EXEC_CONTROL));
    printk("EntryControls=%08x ExitControls=%08x\n", vmentry_ctl, vmexit_ctl);
    printk("ExceptionBitmap=%08x PFECmask=%08x PFECmatch=%08x\n",
           vmr32(EXCEPTION_BITMAP),
           vmr32(PAGE_FAULT_ERROR_CODE_MASK),
           vmr32(PAGE_FAULT_ERROR_CODE_MATCH));
    printk("VMEntry: intr_info=%08x errcode=%08x ilen=%08x\n",
           vmr32(VM_ENTRY_INTR_INFO),
           vmr32(VM_ENTRY_EXCEPTION_ERROR_CODE),
           vmr32(VM_ENTRY_INSTRUCTION_LEN));
    printk("VMExit: intr_info=%08x errcode=%08x ilen=%08x\n",
           vmr32(VM_EXIT_INTR_INFO),
           vmr32(VM_EXIT_INTR_ERROR_CODE),
           vmr32(VM_EXIT_INSTRUCTION_LEN));
    printk("        reason=%08x qualification=%016lx\n",
           vmr32(VM_EXIT_REASON), vmr(EXIT_QUALIFICATION));
    printk("IDTVectoring: info=%08x errcode=%08x\n",
           vmr32(IDT_VECTORING_INFO), vmr32(IDT_VECTORING_ERROR_CODE));
    printk("TSC Offset = 0x%016lx  TSC Multiplier = 0x%016lx\n",
           vmr(TSC_OFFSET), vmr(TSC_MULTIPLIER));
    if ( (v->arch.hvm_vmx.exec_control & CPU_BASED_TPR_SHADOW) ||
         (vmx_pin_based_exec_control & PIN_BASED_POSTED_INTERRUPT) )
        printk("TPR Threshold = 0x%02x  PostedIntrVec = 0x%02x\n",
               vmr32(TPR_THRESHOLD), vmr16(POSTED_INTR_NOTIFICATION_VECTOR));
    if ( (v->arch.hvm_vmx.secondary_exec_control &
          SECONDARY_EXEC_ENABLE_EPT) )
        printk("EPT pointer = 0x%016lx  EPTP index = 0x%04x\n",
               vmr(EPT_POINTER), vmr16(EPTP_INDEX));
    n = vmr32(CR3_TARGET_COUNT);
    for ( i = 0; i + 1 < n; i += 2 )
        printk("CR3 target%u=%016lx target%u=%016lx\n",
               i, vmr(CR3_TARGET_VALUE(i)),
               i + 1, vmr(CR3_TARGET_VALUE(i + 1)));
    if ( i < n )
        printk("CR3 target%u=%016lx\n", i, vmr(CR3_TARGET_VALUE(i)));
    if ( v->arch.hvm_vmx.secondary_exec_control &
         SECONDARY_EXEC_PAUSE_LOOP_EXITING )
        printk("PLE Gap=%08x Window=%08x\n",
               vmr32(PLE_GAP), vmr32(PLE_WINDOW));
    if ( v->arch.hvm_vmx.secondary_exec_control &
         (SECONDARY_EXEC_ENABLE_VPID | SECONDARY_EXEC_ENABLE_VM_FUNCTIONS) )
        printk("Virtual processor ID = 0x%04x VMfunc controls = %016lx\n",
               vmr16(VIRTUAL_PROCESSOR_ID), vmr(VM_FUNCTION_CONTROL));

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
        if ( !is_hvm_domain(d) )
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

void __init setup_vmcs_dump(void)
{
    register_keyhandler('v', vmcs_dump, "dump VT-x VMCSs", 1);
}

static void __init __maybe_unused build_assertions(void)
{
    struct vmx_msr_bitmap bitmap;

    /* Check vmx_msr_bitmap layoug against hardware expectations. */
    BUILD_BUG_ON(sizeof(bitmap)            != PAGE_SIZE);
    BUILD_BUG_ON(sizeof(bitmap.read_low)   != 1024);
    BUILD_BUG_ON(sizeof(bitmap.read_high)  != 1024);
    BUILD_BUG_ON(sizeof(bitmap.write_low)  != 1024);
    BUILD_BUG_ON(sizeof(bitmap.write_high) != 1024);
    BUILD_BUG_ON(offsetof(struct vmx_msr_bitmap, read_low)   != 0);
    BUILD_BUG_ON(offsetof(struct vmx_msr_bitmap, read_high)  != 1024);
    BUILD_BUG_ON(offsetof(struct vmx_msr_bitmap, write_low)  != 2048);
    BUILD_BUG_ON(offsetof(struct vmx_msr_bitmap, write_high) != 3072);
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
