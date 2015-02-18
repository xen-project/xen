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

/*
 * "vpmu" :     vpmu generally enabled
 * "vpmu=off" : vpmu generally disabled
 * "vpmu=bts" : vpmu enabled and Intel BTS feature switched on.
 */
static unsigned int __read_mostly opt_vpmu_enabled;
static void parse_vpmu_param(char *s);
custom_param("vpmu", parse_vpmu_param);

static DEFINE_PER_CPU(struct vcpu *, last_vcpu);

static void __init parse_vpmu_param(char *s)
{
    switch ( parse_bool(s) )
    {
    case 0:
        break;
    default:
        if ( !strcmp(s, "bts") )
            opt_vpmu_enabled |= VPMU_BOOT_BTS;
        else if ( *s )
        {
            printk("VPMU: unknown flag: %s - vpmu disabled!\n", s);
            break;
        }
        /* fall through */
    case 1:
        opt_vpmu_enabled |= VPMU_BOOT_ENABLED;
        break;
    }
}

int vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content, uint64_t supported)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->do_wrmsr )
        return vpmu->arch_vpmu_ops->do_wrmsr(msr, msr_content, supported);
    return 0;
}

int vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

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

    if ( vpmu->arch_vpmu_ops )
        (void)vpmu->arch_vpmu_ops->arch_vpmu_save(v);

    vpmu_reset(vpmu, VPMU_CONTEXT_SAVE);

    per_cpu(last_vcpu, smp_processor_id()) = NULL;
}

void vpmu_save(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    int pcpu = smp_processor_id();

    if ( !(vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) &&
           vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED)) )
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
            vpmu_set(vpmu, VPMU_CONTEXT_SAVE);
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
        vpmu_set(vpmu, VPMU_CONTEXT_SAVE);
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

    if ( is_pvh_vcpu(v) )
        return;

    if ( vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
        vpmu_destroy(v);
    vpmu_clear(vpmu);
    vpmu->context = NULL;

    switch ( vendor )
    {
    case X86_VENDOR_AMD:
        if ( svm_vpmu_initialise(v, opt_vpmu_enabled) != 0 )
            opt_vpmu_enabled = 0;
        break;

    case X86_VENDOR_INTEL:
        if ( vmx_vpmu_initialise(v, opt_vpmu_enabled) != 0 )
            opt_vpmu_enabled = 0;
        break;

    default:
        printk("VPMU: Initialization failed. "
               "Unknown CPU vendor %d\n", vendor);
        opt_vpmu_enabled = 0;
        break;
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
}

/* Dump some vpmu informations on console. Used in keyhandler dump_domains(). */
void vpmu_dump(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->arch_vpmu_dump )
        vpmu->arch_vpmu_ops->arch_vpmu_dump(v);
}

static int __init vpmu_init(void)
{
    /* NMI watchdog uses LVTPC and HW counter */
    if ( opt_watchdog && opt_vpmu_enabled )
    {
        printk(XENLOG_WARNING "NMI watchdog is enabled. Turning VPMU off.\n");
        opt_vpmu_enabled = 0;
    }

    return 0;
}
__initcall(vpmu_init);
