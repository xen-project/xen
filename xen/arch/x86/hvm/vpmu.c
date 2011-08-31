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

static bool_t __read_mostly opt_vpmu_enabled;
boolean_param("vpmu", opt_vpmu_enabled);

int vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops )
        return vpmu->arch_vpmu_ops->do_wrmsr(msr, msr_content);
    return 0;
}

int vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops )
        return vpmu->arch_vpmu_ops->do_rdmsr(msr, msr_content);
    return 0;
}

int vpmu_do_interrupt(struct cpu_user_regs *regs)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops )
        return vpmu->arch_vpmu_ops->do_interrupt(regs);
    return 0;
}

void vpmu_save(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->arch_vpmu_ops )
        vpmu->arch_vpmu_ops->arch_vpmu_save(v);
}

void vpmu_load(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->arch_vpmu_ops )
        vpmu->arch_vpmu_ops->arch_vpmu_load(v);
}

void vpmu_initialise(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    __u8 vendor = current_cpu_data.x86_vendor;
    __u8 family = current_cpu_data.x86;
    __u8 cpu_model = current_cpu_data.x86_model;

    if ( !opt_vpmu_enabled )
        return;

    if ( vpmu->flags & VPMU_CONTEXT_ALLOCATED )
        vpmu_destroy(v);

    switch ( vendor )
    {
    case X86_VENDOR_AMD:
        switch ( family )
        {
        case 0x10:
        case 0x12:
        case 0x14:
        case 0x15:
            vpmu->arch_vpmu_ops = &amd_vpmu_ops;
            break;
        default:
            printk("VPMU: Initialization failed. "
                   "AMD processor family %d has not "
                   "been supported\n", family);
            return;
        }
        break;

    case X86_VENDOR_INTEL:
        if ( family == 6 )
        {
            switch ( cpu_model )
            {
            case 15:
            case 23:
            case 26:
            case 29:
            case 42:
            case 46:
            case 47:
                vpmu->arch_vpmu_ops = &core2_vpmu_ops;
                break;
            }
        }
        if ( vpmu->arch_vpmu_ops == NULL )
            printk("VPMU: Initialization failed. "
                   "Intel processor family %d model %d has not "
                   "been supported\n", family, cpu_model);
        break;

    default:
        printk("VPMU: Initialization failed. "
               "Unknown CPU vendor %d\n", vendor);
        break;
    }

    if ( vpmu->arch_vpmu_ops != NULL )
    {
        vpmu->flags = 0;
        vpmu->context = NULL;
        vpmu->arch_vpmu_ops->arch_vpmu_initialise(v);
    }
}

void vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->arch_vpmu_ops )
        vpmu->arch_vpmu_ops->arch_vpmu_destroy(v);
}

