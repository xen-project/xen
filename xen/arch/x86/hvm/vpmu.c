/*
 * vpmu.c: PMU virtualization for HVM domain.
 *
 * Copyright (c) 2007, Intel Corporation.
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
 * Author: Haitao Shan <haitao.shan@intel.com>
 */
#include <xen/config.h>
#include <xen/sched.h>
#include <xen/xenoprof.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <asm/regs.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/nmi.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/vpmu.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/apic.h>
#include <public/pmu.h>
#include <xsm/xsm.h>

#include <compat/pmu.h>
CHECK_pmu_cntr_pair;
CHECK_pmu_data;
CHECK_pmu_params;

/*
 * "vpmu" :     vpmu generally enabled
 * "vpmu=off" : vpmu generally disabled
 * "vpmu=bts" : vpmu enabled and Intel BTS feature switched on.
 */
static unsigned int __read_mostly opt_vpmu_enabled;
unsigned int __read_mostly vpmu_mode = XENPMU_MODE_OFF;
unsigned int __read_mostly vpmu_features = 0;
static void parse_vpmu_param(char *s);
custom_param("vpmu", parse_vpmu_param);

static DEFINE_SPINLOCK(vpmu_lock);
static unsigned vpmu_count;

static DEFINE_PER_CPU(struct vcpu *, last_vcpu);

static void __init parse_vpmu_param(char *s)
{
    switch ( parse_bool(s) )
    {
    case 0:
        break;
    default:
        if ( !strcmp(s, "bts") )
            vpmu_features |= XENPMU_FEATURE_INTEL_BTS;
        else if ( *s )
        {
            printk("VPMU: unknown flag: %s - vpmu disabled!\n", s);
            break;
        }
        /* fall through */
    case 1:
        /* Default VPMU mode */
        vpmu_mode = XENPMU_MODE_SELF;
        opt_vpmu_enabled = 1;
        break;
    }
}

void vpmu_lvtpc_update(uint32_t val)
{
    struct vpmu_struct *vpmu;

    if ( vpmu_mode == XENPMU_MODE_OFF )
        return;

    vpmu = vcpu_vpmu(current);

    vpmu->hw_lapic_lvtpc = PMU_APIC_VECTOR | (val & APIC_LVT_MASKED);
    apic_write(APIC_LVTPC, vpmu->hw_lapic_lvtpc);
}

int vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content, uint64_t supported)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu_mode == XENPMU_MODE_OFF )
        return 0;

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->do_wrmsr )
        return vpmu->arch_vpmu_ops->do_wrmsr(msr, msr_content, supported);
    return 0;
}

int vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu_mode == XENPMU_MODE_OFF )
    {
        *msr_content = 0;
        return 0;
    }

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->do_rdmsr )
        return vpmu->arch_vpmu_ops->do_rdmsr(msr, msr_content);
    return 0;
}

void vpmu_do_interrupt(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->arch_vpmu_ops )
    {
        struct vlapic *vlapic = vcpu_vlapic(v);
        u32 vlapic_lvtpc;

        if ( !vpmu->arch_vpmu_ops->do_interrupt(regs) ||
             !is_vlapic_lvtpc_enabled(vlapic) )
            return;

        vlapic_lvtpc = vlapic_get_reg(vlapic, APIC_LVTPC);

        switch ( GET_APIC_DELIVERY_MODE(vlapic_lvtpc) )
        {
        case APIC_MODE_FIXED:
            vlapic_set_irq(vlapic, vlapic_lvtpc & APIC_VECTOR_MASK, 0);
            break;
        case APIC_MODE_NMI:
            v->nmi_pending = 1;
            break;
        }
    }
}

void vpmu_do_cpuid(unsigned int input,
                   unsigned int *eax, unsigned int *ebx,
                   unsigned int *ecx, unsigned int *edx)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->do_cpuid )
        vpmu->arch_vpmu_ops->do_cpuid(input, eax, ebx, ecx, edx);
}

static void vpmu_save_force(void *arg)
{
    struct vcpu *v = (struct vcpu *)arg;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
        return;

    vpmu_set(vpmu, VPMU_CONTEXT_SAVE);

    if ( vpmu->arch_vpmu_ops )
        (void)vpmu->arch_vpmu_ops->arch_vpmu_save(v);

    vpmu_reset(vpmu, VPMU_CONTEXT_SAVE);

    per_cpu(last_vcpu, smp_processor_id()) = NULL;
}

void vpmu_save(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    int pcpu = smp_processor_id();

    if ( !vpmu_are_all_set(vpmu, VPMU_CONTEXT_ALLOCATED | VPMU_CONTEXT_LOADED) )
       return;

    vpmu->last_pcpu = pcpu;
    per_cpu(last_vcpu, pcpu) = v;

    if ( vpmu->arch_vpmu_ops )
        if ( vpmu->arch_vpmu_ops->arch_vpmu_save(v) )
            vpmu_reset(vpmu, VPMU_CONTEXT_LOADED);

    apic_write(APIC_LVTPC, PMU_APIC_VECTOR | APIC_LVT_MASKED);
}

void vpmu_load(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    int pcpu = smp_processor_id();
    struct vcpu *prev = NULL;

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
        return;

    /* First time this VCPU is running here */
    if ( vpmu->last_pcpu != pcpu )
    {
        /*
         * Get the context from last pcpu that we ran on. Note that if another
         * VCPU is running there it must have saved this VPCU's context before
         * startig to run (see below).
         * There should be no race since remote pcpu will disable interrupts
         * before saving the context.
         */
        if ( vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
        {
            on_selected_cpus(cpumask_of(vpmu->last_pcpu),
                             vpmu_save_force, (void *)v, 1);
            vpmu_reset(vpmu, VPMU_CONTEXT_LOADED);
        }
    } 

    /* Prevent forced context save from remote CPU */
    local_irq_disable();

    prev = per_cpu(last_vcpu, pcpu);

    if ( prev != v && prev )
    {
        vpmu = vcpu_vpmu(prev);

        /* Someone ran here before us */
        vpmu_save_force(prev);
        vpmu_reset(vpmu, VPMU_CONTEXT_LOADED);

        vpmu = vcpu_vpmu(v);
    }

    local_irq_enable();

    /* Only when PMU is counting, we load PMU context immediately. */
    if ( !vpmu_is_set(vpmu, VPMU_RUNNING) )
        return;

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->arch_vpmu_load )
    {
        apic_write_around(APIC_LVTPC, vpmu->hw_lapic_lvtpc);
        /* Arch code needs to set VPMU_CONTEXT_LOADED */
        vpmu->arch_vpmu_ops->arch_vpmu_load(v);
    }
}

void vpmu_initialise(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    uint8_t vendor = current_cpu_data.x86_vendor;
    int ret;

    BUILD_BUG_ON(sizeof(struct xen_pmu_intel_ctxt) > XENPMU_CTXT_PAD_SZ);
    BUILD_BUG_ON(sizeof(struct xen_pmu_amd_ctxt) > XENPMU_CTXT_PAD_SZ);

    if ( is_pvh_vcpu(v) )
        return;

    ASSERT(!vpmu->flags && !vpmu->context);

    /*
     * Count active VPMUs so that we won't try to change vpmu_mode while
     * they are in use.
     */
    spin_lock(&vpmu_lock);
    vpmu_count++;
    spin_unlock(&vpmu_lock);

    switch ( vendor )
    {
    case X86_VENDOR_AMD:
        ret = svm_vpmu_initialise(v);
        break;

    case X86_VENDOR_INTEL:
        ret = vmx_vpmu_initialise(v);
        break;

    default:
        if ( vpmu_mode != XENPMU_MODE_OFF )
        {
            printk(XENLOG_G_WARNING "VPMU: Unknown CPU vendor %d. "
                   "Disabling VPMU\n", vendor);
            opt_vpmu_enabled = 0;
            vpmu_mode = XENPMU_MODE_OFF;
        }
        return; /* Don't bother restoring vpmu_count, VPMU is off forever */
    }

    if ( ret )
        printk(XENLOG_G_WARNING "VPMU: Initialization failed for %pv\n", v);

    /* Intel needs to initialize VPMU ops even if VPMU is not in use */
    if ( ret || (vpmu_mode == XENPMU_MODE_OFF) )
    {
        spin_lock(&vpmu_lock);
        vpmu_count--;
        spin_unlock(&vpmu_lock);
    }
}

static void vpmu_clear_last(void *arg)
{
    if ( this_cpu(last_vcpu) == arg )
        this_cpu(last_vcpu) = NULL;
}

void vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
        return;

    /*
     * Need to clear last_vcpu in case it points to v.
     * We can check here non-atomically whether it is 'v' since
     * last_vcpu can never become 'v' again at this point.
     * We will test it again in vpmu_clear_last() with interrupts
     * disabled to make sure we don't clear someone else.
     */
    if ( per_cpu(last_vcpu, vpmu->last_pcpu) == v )
        on_selected_cpus(cpumask_of(vpmu->last_pcpu),
                         vpmu_clear_last, v, 1);

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->arch_vpmu_destroy )
        vpmu->arch_vpmu_ops->arch_vpmu_destroy(v);

    spin_lock(&vpmu_lock);
    vpmu_count--;
    spin_unlock(&vpmu_lock);
}

/* Dump some vpmu informations on console. Used in keyhandler dump_domains(). */
void vpmu_dump(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->arch_vpmu_dump )
        vpmu->arch_vpmu_ops->arch_vpmu_dump(v);
}

long do_xenpmu_op(unsigned int op, XEN_GUEST_HANDLE_PARAM(xen_pmu_params_t) arg)
{
    int ret;
    struct xen_pmu_params pmu_params = {.val = 0};

    if ( !opt_vpmu_enabled )
        return -EOPNOTSUPP;

    ret = xsm_pmu_op(XSM_OTHER, current->domain, op);
    if ( ret )
        return ret;

    /* Check major version when parameters are specified */
    switch ( op )
    {
    case XENPMU_mode_set:
    case XENPMU_feature_set:
        if ( copy_from_guest(&pmu_params, arg, 1) )
            return -EFAULT;

        if ( pmu_params.version.maj != XENPMU_VER_MAJ )
            return -EINVAL;
    }

    switch ( op )
    {
    case XENPMU_mode_set:
    {
        if ( (pmu_params.val & ~(XENPMU_MODE_SELF | XENPMU_MODE_HV)) ||
             (hweight64(pmu_params.val) > 1) )
            return -EINVAL;

        /* 32-bit dom0 can only sample itself. */
        if ( is_pv_32bit_vcpu(current) && (pmu_params.val & XENPMU_MODE_HV) )
            return -EINVAL;

        spin_lock(&vpmu_lock);

        /*
         * We can always safely switch between XENPMU_MODE_SELF and
         * XENPMU_MODE_HV while other VPMUs are active.
         */
        if ( (vpmu_count == 0) ||
             ((vpmu_mode ^ pmu_params.val) ==
              (XENPMU_MODE_SELF | XENPMU_MODE_HV)) )
            vpmu_mode = pmu_params.val;
        else if ( vpmu_mode != pmu_params.val )
        {
            printk(XENLOG_WARNING
                   "VPMU: Cannot change mode while active VPMUs exist\n");
            ret = -EBUSY;
        }

        spin_unlock(&vpmu_lock);

        break;
    }

    case XENPMU_mode_get:
        memset(&pmu_params, 0, sizeof(pmu_params));
        pmu_params.val = vpmu_mode;

        pmu_params.version.maj = XENPMU_VER_MAJ;
        pmu_params.version.min = XENPMU_VER_MIN;

        if ( copy_to_guest(arg, &pmu_params, 1) )
            ret = -EFAULT;

        break;

    case XENPMU_feature_set:
        if ( pmu_params.val & ~XENPMU_FEATURE_INTEL_BTS )
            return -EINVAL;

        spin_lock(&vpmu_lock);

        if ( (vpmu_count == 0) || (vpmu_features == pmu_params.val) )
            vpmu_features = pmu_params.val;
        else
        {
            printk(XENLOG_WARNING "VPMU: Cannot change features while"
                                  " active VPMUs exist\n");
            ret = -EBUSY;
        }

        spin_unlock(&vpmu_lock);

        break;

    case XENPMU_feature_get:
        pmu_params.val = vpmu_features;
        if ( copy_field_to_guest(arg, &pmu_params, val) )
            ret = -EFAULT;

        break;

    default:
        ret = -EINVAL;
    }

    return ret;
}

static int __init vpmu_init(void)
{
    int vendor = current_cpu_data.x86_vendor;

    if ( !opt_vpmu_enabled )
    {
        printk(XENLOG_INFO "VPMU: disabled\n");
        return 0;
    }

    /* NMI watchdog uses LVTPC and HW counter */
    if ( opt_watchdog && opt_vpmu_enabled )
    {
        printk(XENLOG_WARNING "NMI watchdog is enabled. Turning VPMU off.\n");
        opt_vpmu_enabled = 0;
        vpmu_mode = XENPMU_MODE_OFF;
        return 0;
    }

    switch ( vendor )
    {
    case X86_VENDOR_AMD:
        if ( amd_vpmu_init() )
           vpmu_mode = XENPMU_MODE_OFF;
        break;
    case X86_VENDOR_INTEL:
        if ( core2_vpmu_init() )
           vpmu_mode = XENPMU_MODE_OFF;
        break;
    default:
        printk(XENLOG_WARNING "VPMU: Unknown CPU vendor: %d. "
               "Turning VPMU off.\n", vendor);
        vpmu_mode = XENPMU_MODE_OFF;
        break;
    }

    if ( vpmu_mode != XENPMU_MODE_OFF )
        printk(XENLOG_INFO "VPMU: version " __stringify(XENPMU_VER_MAJ) "."
               __stringify(XENPMU_VER_MIN) "\n");
    else
        opt_vpmu_enabled = 0;

    return 0;
}
__initcall(vpmu_init);
