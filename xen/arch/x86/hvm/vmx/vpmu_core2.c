/*
 * vpmu_core2.c: CORE 2 specific PMU virtualization for HVM domain.
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
#include <asm/system.h>
#include <asm/regs.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <public/sched.h>
#include <public/hvm/save.h>
#include <asm/hvm/vmx/vpmu.h>
#include <asm/hvm/vmx/vpmu_core2.h>

u32 core2_counters_msr[] =   {
    MSR_CORE_PERF_FIXED_CTR0,
    MSR_CORE_PERF_FIXED_CTR1,
    MSR_CORE_PERF_FIXED_CTR2};

/* Core 2 Non-architectual Performance Control MSRs. */
u32 core2_ctrls_msr[] = {
    MSR_CORE_PERF_FIXED_CTR_CTRL,
    MSR_IA32_PEBS_ENABLE,
    MSR_IA32_DS_AREA};

struct pmumsr core2_counters = {
    3,
    core2_counters_msr
};

struct pmumsr core2_ctrls = {
    3,
    core2_ctrls_msr
};
static int arch_pmc_cnt;

static int core2_get_pmc_count(void)
{
    u32 eax, ebx, ecx, edx;

    if ( arch_pmc_cnt == 0 )
    {
        cpuid(0xa, &eax, &ebx, &ecx, &edx);
        arch_pmc_cnt = (eax & 0xff00) >> 8;
    }

    return arch_pmc_cnt;
}

static int is_core2_vpmu_msr(u32 msr_index, int *type, int *index)
{
    int i;

    for ( i = 0; i < core2_counters.num; i++ )
    {
        if ( core2_counters.msr[i] == msr_index )
        {
            *type = MSR_TYPE_COUNTER;
            *index = i;
            return 1;
        }
    }
    
    for ( i = 0; i < core2_ctrls.num; i++ )
    {
        if ( core2_ctrls.msr[i] == msr_index )
        {
            *type = MSR_TYPE_CTRL;
            *index = i;
            return 1;
        }
    }

    if ( (msr_index == MSR_CORE_PERF_GLOBAL_CTRL) ||
         (msr_index == MSR_CORE_PERF_GLOBAL_STATUS) ||
         (msr_index == MSR_CORE_PERF_GLOBAL_OVF_CTRL) )
    {
        *type = MSR_TYPE_GLOBAL;
        return 1;
    }

    if ( (msr_index >= MSR_IA32_PERFCTR0) &&
         (msr_index < (MSR_IA32_PERFCTR0 + core2_get_pmc_count())) )
    {
        *type = MSR_TYPE_ARCH_COUNTER;
        *index = msr_index - MSR_IA32_PERFCTR0;
        return 1;
    }

    if ( (msr_index >= MSR_P6_EVNTSEL0) &&
         (msr_index < (MSR_P6_EVNTSEL0 + core2_get_pmc_count())) )
    {
        *type = MSR_TYPE_ARCH_CTRL;
        *index = msr_index - MSR_P6_EVNTSEL0;
        return 1;
    }

    return 0;
}

static void core2_vpmu_set_msr_bitmap(unsigned long *msr_bitmap)
{
    int i;

    /* Allow Read/Write PMU Counters MSR Directly. */
    for ( i = 0; i < core2_counters.num; i++ )
    {
        clear_bit(msraddr_to_bitpos(core2_counters.msr[i]), msr_bitmap);
        clear_bit(msraddr_to_bitpos(core2_counters.msr[i]),
                  msr_bitmap + 0x800/BYTES_PER_LONG);
    }
    for ( i = 0; i < core2_get_pmc_count(); i++ )
    {
        clear_bit(msraddr_to_bitpos(MSR_IA32_PERFCTR0+i), msr_bitmap);
        clear_bit(msraddr_to_bitpos(MSR_IA32_PERFCTR0+i),
                  msr_bitmap + 0x800/BYTES_PER_LONG);
    }

    /* Allow Read PMU Non-global Controls Directly. */
    for ( i = 0; i < core2_ctrls.num; i++ )
        clear_bit(msraddr_to_bitpos(core2_ctrls.msr[i]), msr_bitmap);
    for ( i = 0; i < core2_get_pmc_count(); i++ )
        clear_bit(msraddr_to_bitpos(MSR_P6_EVNTSEL0+i), msr_bitmap);
}

static void core2_vpmu_unset_msr_bitmap(unsigned long *msr_bitmap)
{
    int i;

    for ( i = 0; i < core2_counters.num; i++ )
    {
        set_bit(msraddr_to_bitpos(core2_counters.msr[i]), msr_bitmap);
        set_bit(msraddr_to_bitpos(core2_counters.msr[i]),
                msr_bitmap + 0x800/BYTES_PER_LONG);
    }
    for ( i = 0; i < core2_get_pmc_count(); i++ )
    {
        set_bit(msraddr_to_bitpos(MSR_IA32_PERFCTR0+i), msr_bitmap);
        set_bit(msraddr_to_bitpos(MSR_IA32_PERFCTR0+i),
                msr_bitmap + 0x800/BYTES_PER_LONG);
    }
    for ( i = 0; i < core2_ctrls.num; i++ )
        set_bit(msraddr_to_bitpos(core2_ctrls.msr[i]), msr_bitmap);
    for ( i = 0; i < core2_get_pmc_count(); i++ )
        set_bit(msraddr_to_bitpos(MSR_P6_EVNTSEL0+i), msr_bitmap);
}

static inline void __core2_vpmu_save(struct vcpu *v)
{
    int i;
    struct core2_vpmu_context *core2_vpmu_cxt = vcpu_vpmu(v)->context;

    for ( i = 0; i < core2_counters.num; i++ )
        rdmsrl(core2_counters.msr[i], core2_vpmu_cxt->counters[i]);
    for ( i = 0; i < core2_get_pmc_count(); i++ )
        rdmsrl(MSR_IA32_PERFCTR0+i, core2_vpmu_cxt->arch_msr_pair[i].counter);
    core2_vpmu_cxt->hw_lapic_lvtpc = apic_read(APIC_LVTPC);
    apic_write(APIC_LVTPC, PMU_APIC_VECTOR | APIC_LVT_MASKED);
}

static void core2_vpmu_save(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !((vpmu->flags & VPMU_CONTEXT_ALLOCATED) &&
           (vpmu->flags & VPMU_CONTEXT_LOADED)) )
        return;

    __core2_vpmu_save(v);

    /* Unset PMU MSR bitmap to trap lazy load. */
    if ( !(vpmu->flags & VPMU_RUNNING) && cpu_has_vmx_msr_bitmap )
        core2_vpmu_unset_msr_bitmap(v->arch.hvm_vmx.msr_bitmap);

    vpmu->flags &= ~VPMU_CONTEXT_LOADED;
    return;
}

static inline void __core2_vpmu_load(struct vcpu *v)
{
    int i;
    struct core2_vpmu_context *core2_vpmu_cxt = vcpu_vpmu(v)->context;

    for ( i = 0; i < core2_counters.num; i++ )
        wrmsrl(core2_counters.msr[i], core2_vpmu_cxt->counters[i]);
    for ( i = 0; i < core2_get_pmc_count(); i++ )
        wrmsrl(MSR_IA32_PERFCTR0+i, core2_vpmu_cxt->arch_msr_pair[i].counter);

    for ( i = 0; i < core2_ctrls.num; i++ )
        wrmsrl(core2_ctrls.msr[i], core2_vpmu_cxt->ctrls[i]);
    for ( i = 0; i < core2_get_pmc_count(); i++ )
        wrmsrl(MSR_P6_EVNTSEL0+i, core2_vpmu_cxt->arch_msr_pair[i].control);

    apic_write_around(APIC_LVTPC, core2_vpmu_cxt->hw_lapic_lvtpc);
}

static void core2_vpmu_load(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    /* Only when PMU is counting, we load PMU context immediately. */
    if ( !((vpmu->flags & VPMU_CONTEXT_ALLOCATED) &&
           (vpmu->flags & VPMU_RUNNING)) )
        return;
    __core2_vpmu_load(v);
    vpmu->flags |= VPMU_CONTEXT_LOADED;
}

static int core2_vpmu_alloc_resource(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt;
    struct core2_pmu_enable *pmu_enable;

    if ( !acquire_pmu_ownership(PMU_OWNER_HVM) )
        return 0;

    wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 0);
    if ( vmx_add_host_load_msr(MSR_CORE_PERF_GLOBAL_CTRL) )
        return 0;

    if ( vmx_add_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL) )
        return 0;
    vmx_write_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, -1ULL);

    pmu_enable = xmalloc_bytes(sizeof(struct core2_pmu_enable) +
                 (core2_get_pmc_count()-1)*sizeof(char));
    if ( !pmu_enable )
        goto out1;
    memset(pmu_enable, 0, sizeof(struct core2_pmu_enable) +
                 (core2_get_pmc_count()-1)*sizeof(char));

    core2_vpmu_cxt = xmalloc_bytes(sizeof(struct core2_vpmu_context) +
                    (core2_get_pmc_count()-1)*sizeof(struct arch_msr_pair));
    if ( !core2_vpmu_cxt )
        goto out2;
    memset(core2_vpmu_cxt, 0, sizeof(struct core2_vpmu_context) +
                    (core2_get_pmc_count()-1)*sizeof(struct arch_msr_pair));
    core2_vpmu_cxt->pmu_enable = pmu_enable;
    vpmu->context = (void *)core2_vpmu_cxt;

    return 1;
 out2:
    xfree(pmu_enable);
 out1:
    gdprintk(XENLOG_WARNING, "Insufficient memory for PMU, PMU feature is "
             "unavailable on domain %d vcpu %d.\n",
             v->vcpu_id, v->domain->domain_id);
    return 0;
}

static void core2_vpmu_save_msr_context(struct vcpu *v, int type,
                                       int index, u64 msr_data)
{
    struct core2_vpmu_context *core2_vpmu_cxt = vcpu_vpmu(v)->context;

    switch ( type )
    {
    case MSR_TYPE_CTRL:
        core2_vpmu_cxt->ctrls[index] = msr_data;
        break;
    case MSR_TYPE_ARCH_CTRL:
        core2_vpmu_cxt->arch_msr_pair[index].control = msr_data;
        break;
    }
}

static int core2_vpmu_msr_common_check(u32 msr_index, int *type, int *index)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( !is_core2_vpmu_msr(msr_index, type, index) )
        return 0;

    if ( unlikely(!(vpmu->flags & VPMU_CONTEXT_ALLOCATED)) &&
	 (vpmu->context != NULL ||
	  !core2_vpmu_alloc_resource(current)) )
        return 0;
    vpmu->flags |= VPMU_CONTEXT_ALLOCATED;

    /* Do the lazy load staff. */
    if ( !(vpmu->flags & VPMU_CONTEXT_LOADED) )
    {
        __core2_vpmu_load(current);
        vpmu->flags |= VPMU_CONTEXT_LOADED;
        if ( cpu_has_vmx_msr_bitmap )
            core2_vpmu_set_msr_bitmap(current->arch.hvm_vmx.msr_bitmap);
    }
    return 1;
}

static int core2_vpmu_do_wrmsr(struct cpu_user_regs *regs)
{
    u32 ecx = regs->ecx;
    u64 msr_content, global_ctrl, non_global_ctrl;
    char pmu_enable = 0;
    int i, tmp;
    int type = -1, index = -1;
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt = NULL;

    if ( !core2_vpmu_msr_common_check(ecx, &type, &index) )
        return 0;

    msr_content = (u32)regs->eax | ((u64)regs->edx << 32);
    core2_vpmu_cxt = vpmu->context;
    switch ( ecx )
    {
    case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        core2_vpmu_cxt->global_ovf_status &= ~msr_content;
        return 1;
    case MSR_CORE_PERF_GLOBAL_STATUS:
        gdprintk(XENLOG_INFO, "Can not write readonly MSR: "
                 "MSR_PERF_GLOBAL_STATUS(0x38E)!\n");
        vmx_inject_hw_exception(TRAP_gp_fault, 0);
        return 1;
    case MSR_IA32_PEBS_ENABLE:
        if ( msr_content & 1 )
            gdprintk(XENLOG_WARNING, "Guest is trying to enable PEBS, "
                     "which is not supported.\n");
        return 1;
    case MSR_IA32_DS_AREA:
        gdprintk(XENLOG_WARNING, "Guest setting of DTS is ignored.\n");
        return 1;
    case MSR_CORE_PERF_GLOBAL_CTRL:
        global_ctrl = msr_content;
        for ( i = 0; i < core2_get_pmc_count(); i++ )
        {
            rdmsrl(MSR_P6_EVNTSEL0+i, non_global_ctrl);
            core2_vpmu_cxt->pmu_enable->arch_pmc_enable[i] =
                    global_ctrl & (non_global_ctrl >> 22) & 1;
            global_ctrl >>= 1;
        }

        rdmsrl(MSR_CORE_PERF_FIXED_CTR_CTRL, non_global_ctrl);
        global_ctrl = msr_content >> 32;
        for ( i = 0; i < 3; i++ )
        {
            core2_vpmu_cxt->pmu_enable->fixed_ctr_enable[i] =
                (global_ctrl & 1) & ((non_global_ctrl & 0x3)? 1: 0);
            non_global_ctrl >>= 4;
            global_ctrl >>= 1;
        }
        break;
    case MSR_CORE_PERF_FIXED_CTR_CTRL:
        non_global_ctrl = msr_content;
        vmx_read_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, &global_ctrl);
        global_ctrl >>= 32;
        for ( i = 0; i < 3; i++ )
        {
            core2_vpmu_cxt->pmu_enable->fixed_ctr_enable[i] =
                (global_ctrl & 1) & ((non_global_ctrl & 0x3)? 1: 0);
            non_global_ctrl >>= 4;
            global_ctrl >>= 1;
        }
        break;
    default:
        tmp = ecx - MSR_P6_EVNTSEL0;
        vmx_read_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, &global_ctrl);
        if ( tmp >= 0 && tmp < core2_get_pmc_count() )
            core2_vpmu_cxt->pmu_enable->arch_pmc_enable[tmp] =
                (global_ctrl >> tmp) & (msr_content >> 22) & 1;
    }

    for ( i = 0; i < 3; i++ )
        pmu_enable |= core2_vpmu_cxt->pmu_enable->fixed_ctr_enable[i];
    for ( i = 0; i < core2_get_pmc_count(); i++ )
        pmu_enable |= core2_vpmu_cxt->pmu_enable->arch_pmc_enable[i];
    if ( pmu_enable )
        vpmu->flags |= VPMU_RUNNING;
    else
        vpmu->flags &= ~VPMU_RUNNING;

    /* Setup LVTPC in local apic */
    if ( vpmu->flags & VPMU_RUNNING &&
         is_vlapic_lvtpc_enabled(vcpu_vlapic(v)) )
        apic_write_around(APIC_LVTPC, PMU_APIC_VECTOR);
    else
        apic_write_around(APIC_LVTPC, PMU_APIC_VECTOR | APIC_LVT_MASKED);

    core2_vpmu_save_msr_context(v, type, index, msr_content);
    if ( type != MSR_TYPE_GLOBAL )
        wrmsrl(ecx, msr_content);
    else
        vmx_write_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, msr_content);

    return 1;
}

static int core2_vpmu_do_rdmsr(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    int type = -1, index = -1;
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt = NULL;

    if ( !core2_vpmu_msr_common_check(regs->ecx, &type, &index) )
        return 0;

    core2_vpmu_cxt = vpmu->context;
    switch ( regs->ecx )
    {
    case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        break;
    case MSR_CORE_PERF_GLOBAL_STATUS:
        msr_content = core2_vpmu_cxt->global_ovf_status;
        break;
    case MSR_CORE_PERF_GLOBAL_CTRL:
        vmx_read_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, &msr_content);
        break;
    default:
        rdmsrl(regs->ecx, msr_content);
    }

    regs->eax = msr_content & 0xFFFFFFFF;
    regs->edx = msr_content >> 32;
    return 1;
}

static int core2_vpmu_do_interrupt(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    u64 msr_content;
    u32 vlapic_lvtpc;
    unsigned char int_vec;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt = vpmu->context;
    struct vlapic *vlapic = vcpu_vlapic(v);

    rdmsrl(MSR_CORE_PERF_GLOBAL_STATUS, msr_content);
    if ( !msr_content )
        return 0;
    core2_vpmu_cxt->global_ovf_status |= msr_content;
    wrmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, 0xC000000700000003);

    apic_write_around(APIC_LVTPC, apic_read(APIC_LVTPC) & ~APIC_LVT_MASKED);

    if ( !is_vlapic_lvtpc_enabled(vlapic) )
        return 1;

    vlapic_lvtpc = vlapic_get_reg(vlapic, APIC_LVTPC);
    int_vec = vlapic_lvtpc & APIC_VECTOR_MASK;
    vlapic_set_reg(vlapic, APIC_LVTPC, vlapic_lvtpc | APIC_LVT_MASKED);
    if ( GET_APIC_DELIVERY_MODE(vlapic_lvtpc) == APIC_MODE_FIXED )
        vlapic_set_irq(vcpu_vlapic(v), int_vec, 0);
    else
        test_and_set_bool(v->nmi_pending);
    return 1;
}

static void core2_vpmu_initialise(struct vcpu *v)
{
}

static void core2_vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt = vpmu->context;

    if ( !(vpmu->flags & VPMU_CONTEXT_ALLOCATED) )
        return;
    xfree(core2_vpmu_cxt->pmu_enable);
    xfree(vpmu->context);
    if ( cpu_has_vmx_msr_bitmap )
        core2_vpmu_unset_msr_bitmap(v->arch.hvm_vmx.msr_bitmap);
    release_pmu_ownship(PMU_OWNER_HVM);
    vpmu->flags &= ~VPMU_CONTEXT_ALLOCATED;
}

struct arch_vpmu_ops core2_vpmu_ops = {
    .do_wrmsr = core2_vpmu_do_wrmsr,
    .do_rdmsr = core2_vpmu_do_rdmsr,
    .do_interrupt = core2_vpmu_do_interrupt,
    .arch_vpmu_initialise = core2_vpmu_initialise,
    .arch_vpmu_destroy = core2_vpmu_destroy,
    .arch_vpmu_save = core2_vpmu_save,
    .arch_vpmu_load = core2_vpmu_load
};
