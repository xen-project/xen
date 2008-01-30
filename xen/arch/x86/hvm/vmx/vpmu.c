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
#include <asm/regs.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <public/sched.h>
#include <public/hvm/save.h>
#include <asm/hvm/vmx/vpmu.h>

int inline vpmu_do_wrmsr(struct cpu_user_regs *regs)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops )
        return vpmu->arch_vpmu_ops->do_wrmsr(regs);
    return 0;
}

int inline vpmu_do_rdmsr(struct cpu_user_regs *regs)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( vpmu->arch_vpmu_ops )
        return vpmu->arch_vpmu_ops->do_rdmsr(regs);
    return 0;
}

int inline vpmu_do_interrupt(struct cpu_user_regs *regs)
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

extern struct arch_vpmu_ops core2_vpmu_ops;
void inline vpmu_initialise(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    /* If it is not a fresh initialization, release all resources
     * before initialise again.
     */
    if ( vpmu->flags & VPMU_CONTEXT_ALLOCATED )
        vpmu_destroy(v);

    if ( current_cpu_data.x86 == 6 )
    {
        switch ( current_cpu_data.x86_model )
        {
        case 15:
        case 23:
            vpmu->arch_vpmu_ops = &core2_vpmu_ops;
            dprintk(XENLOG_INFO,
                   "Core 2 duo CPU detected for guest PMU usage.\n");
            break;
        }
    }

    if ( !vpmu->arch_vpmu_ops )
    {
        dprintk(XENLOG_WARNING, "Unsupport CPU model for guest PMU usage.\n");
        return;
    }

    vpmu->flags = 0;
    vpmu->context = NULL;
    vpmu->arch_vpmu_ops->arch_vpmu_initialise(v);
}

void inline vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->arch_vpmu_ops )
        vpmu->arch_vpmu_ops->arch_vpmu_destroy(v);
}

