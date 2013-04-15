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

int vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->do_wrmsr )
        return vpmu->arch_vpmu_ops->do_wrmsr(msr, msr_content);
    return 0;
}

int vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->do_rdmsr )
        return vpmu->arch_vpmu_ops->do_rdmsr(msr, msr_content);
    return 0;
}

int vpmu_do_interrupt(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->arch_vpmu_ops )
    {
        struct vlapic *vlapic = vcpu_vlapic(v);
        u32 vlapic_lvtpc;
        unsigned char int_vec;

        if ( !vpmu->arch_vpmu_ops->do_interrupt(regs) )
            return 0;

        if ( !is_vlapic_lvtpc_enabled(vlapic) )
            return 1;

        vlapic_lvtpc = vlapic_get_reg(vlapic, APIC_LVTPC);
        int_vec = vlapic_lvtpc & APIC_VECTOR_MASK;

        if ( GET_APIC_DELIVERY_MODE(vlapic_lvtpc) == APIC_MODE_FIXED )
            vlapic_set_irq(vcpu_vlapic(v), int_vec, 0);
        else
            v->nmi_pending = 1;
        return 1;
    }

    return 0;
}

void vpmu_do_cpuid(unsigned int input,
                   unsigned int *eax, unsigned int *ebx,
                   unsigned int *ecx, unsigned int *edx)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->do_cpuid )
        vpmu->arch_vpmu_ops->do_cpuid(input, eax, ebx, ecx, edx);
}

void vpmu_save(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !(vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) &&
           vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED)) )
       return;

    if ( vpmu->arch_vpmu_ops )
        vpmu->arch_vpmu_ops->arch_vpmu_save(v);

    vpmu->hw_lapic_lvtpc = apic_read(APIC_LVTPC);
    apic_write(APIC_LVTPC, PMU_APIC_VECTOR | APIC_LVT_MASKED);

    vpmu_reset(vpmu, VPMU_CONTEXT_LOADED);
}

void vpmu_load(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    /* Only when PMU is counting, we load PMU context immediately. */
    if ( !(vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) &&
           vpmu_is_set(vpmu, VPMU_RUNNING)) )
        return;

    if ( vpmu->arch_vpmu_ops && vpmu->arch_vpmu_ops->arch_vpmu_load )
    {
        apic_write_around(APIC_LVTPC, vpmu->hw_lapic_lvtpc);
        vpmu->arch_vpmu_ops->arch_vpmu_load(v);
    }

    vpmu_set(vpmu, VPMU_CONTEXT_LOADED);
}

void vpmu_initialise(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    uint8_t vendor = current_cpu_data.x86_vendor;

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

void vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

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

