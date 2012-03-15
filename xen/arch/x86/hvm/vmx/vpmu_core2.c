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
#include <xen/xenoprof.h>
#include <xen/irq.h>
#include <asm/system.h>
#include <asm/regs.h>
#include <asm/types.h>
#include <asm/apic.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <public/sched.h>
#include <public/hvm/save.h>
#include <asm/hvm/vpmu.h>
#include <asm/hvm/vmx/vpmu_core2.h>

/*
 * QUIRK to workaround an issue on Nehalem processors currently seen
 * on family 6 cpus E5520 (model 26) and X7542 (model 46).
 * The issue leads to endless PMC interrupt loops on the processor.
 * If the interrupt handler is running and a pmc reaches the value 0, this
 * value remains forever and it triggers immediately a new interrupt after
 * finishing the handler.
 * A workaround is to read all flagged counters and if the value is 0 write
 * 1 (or another value != 0) into it.
 * There exist no errata and the real cause of this behaviour is unknown.
 */
bool_t __read_mostly is_pmc_quirk;

static void check_pmc_quirk(void)
{
    u8 family = current_cpu_data.x86;
    u8 cpu_model = current_cpu_data.x86_model;
    is_pmc_quirk = 0;
    if ( family == 6 )
    {
        if ( cpu_model == 47 || cpu_model == 46 || cpu_model == 42 ||
             cpu_model == 26 )
            is_pmc_quirk = 1;
    }
}

static int core2_get_pmc_count(void);
static void handle_pmc_quirk(u64 msr_content)
{
    int num_gen_pmc = core2_get_pmc_count();
    int num_fix_pmc  = 3;
    int i;
    u64 val;

    if ( !is_pmc_quirk )
        return;

    val = msr_content;
    for ( i = 0; i < num_gen_pmc; i++ )
    {
        if ( val & 0x1 )
        {
            u64 cnt;
            rdmsrl(MSR_P6_PERFCTR0 + i, cnt);
            if ( cnt == 0 )
                wrmsrl(MSR_P6_PERFCTR0 + i, 1);
        }
        val >>= 1;
    }
    val = msr_content >> 32;
    for ( i = 0; i < num_fix_pmc; i++ )
    {
        if ( val & 0x1 )
        {
            u64 cnt;
            rdmsrl(MSR_CORE_PERF_FIXED_CTR0 + i, cnt);
            if ( cnt == 0 )
                wrmsrl(MSR_CORE_PERF_FIXED_CTR0 + i, 1);
        }
        val >>= 1;
    }
}

u32 core2_counters_msr[] =   {
    MSR_CORE_PERF_FIXED_CTR0,
    MSR_CORE_PERF_FIXED_CTR1,
    MSR_CORE_PERF_FIXED_CTR2};

/* Core 2 Non-architectual Performance Control MSRs. */
u32 core2_ctrls_msr[] = {
    MSR_CORE_PERF_FIXED_CTR_CTRL,
    MSR_IA32_PEBS_ENABLE,
    MSR_IA32_DS_AREA};

struct pmumsr {
    unsigned int num;
    u32 *msr;
};

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

static u64 core2_calc_intial_glb_ctrl_msr(void)
{
    int arch_pmc_bits = (1 << core2_get_pmc_count()) - 1;
    u64 fix_pmc_bits  = (1 << 3) - 1;
    return ((fix_pmc_bits << 32) | arch_pmc_bits);
}

/* edx bits 5-12: Bit width of fixed-function performance counters  */
static int core2_get_bitwidth_fix_count(void)
{
    u32 eax, ebx, ecx, edx;
    cpuid(0xa, &eax, &ebx, &ecx, &edx);
    return ((edx & 0x1fe0) >> 5);
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

    if ( !(vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) &&
           vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED)) )
        return;

    __core2_vpmu_save(v);

    /* Unset PMU MSR bitmap to trap lazy load. */
    if ( !vpmu_is_set(vpmu, VPMU_RUNNING) && cpu_has_vmx_msr_bitmap )
        core2_vpmu_unset_msr_bitmap(v->arch.hvm_vmx.msr_bitmap);

    vpmu_reset(vpmu, VPMU_CONTEXT_LOADED);
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
    if ( !(vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) &&
           vpmu_is_set(vpmu, VPMU_RUNNING)) )
        return;
    __core2_vpmu_load(v);
    vpmu_set(vpmu, VPMU_CONTEXT_LOADED);
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
    vmx_write_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL,
                 core2_calc_intial_glb_ctrl_msr());

    pmu_enable = xzalloc_bytes(sizeof(struct core2_pmu_enable) +
                               core2_get_pmc_count() - 1);
    if ( !pmu_enable )
        goto out1;

    core2_vpmu_cxt = xzalloc_bytes(sizeof(struct core2_vpmu_context) +
                    (core2_get_pmc_count()-1)*sizeof(struct arch_msr_pair));
    if ( !core2_vpmu_cxt )
        goto out2;
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

    if ( unlikely(!vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED)) &&
	 (vpmu->context != NULL ||
	  !core2_vpmu_alloc_resource(current)) )
        return 0;
    vpmu_set(vpmu, VPMU_CONTEXT_ALLOCATED);

    /* Do the lazy load staff. */
    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
    {
        __core2_vpmu_load(current);
        vpmu_set(vpmu, VPMU_CONTEXT_LOADED);
        if ( cpu_has_vmx_msr_bitmap )
            core2_vpmu_set_msr_bitmap(current->arch.hvm_vmx.msr_bitmap);
    }
    return 1;
}

static int core2_vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content)
{
    u64 global_ctrl, non_global_ctrl;
    char pmu_enable = 0;
    int i, tmp;
    int type = -1, index = -1;
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt = NULL;

    if ( !core2_vpmu_msr_common_check(msr, &type, &index) )
    {
        /* Special handling for BTS */
        if ( msr == MSR_IA32_DEBUGCTLMSR )
        {
            uint64_t supported = IA32_DEBUGCTLMSR_TR | IA32_DEBUGCTLMSR_BTS |
                                 IA32_DEBUGCTLMSR_BTINT;

            if ( cpu_has(&current_cpu_data, X86_FEATURE_DSCPL) )
                supported |= IA32_DEBUGCTLMSR_BTS_OFF_OS |
                             IA32_DEBUGCTLMSR_BTS_OFF_USR;
            if ( msr_content & supported )
            {
                if ( vpmu_is_set(vpmu, VPMU_CPU_HAS_BTS) )
                    return 1;
                gdprintk(XENLOG_WARNING, "Debug Store is not supported on this cpu\n");
                vmx_inject_hw_exception(TRAP_gp_fault, 0);
                return 0;
            }
        }
        return 0;
    }

    core2_vpmu_cxt = vpmu->context;
    switch ( msr )
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
        if ( vpmu_is_set(vpmu, VPMU_CPU_HAS_DS) )
        {
            if ( !is_canonical_address(msr_content) )
            {
                gdprintk(XENLOG_WARNING,
                         "Illegal address for IA32_DS_AREA: %#" PRIx64 "x\n",
                         msr_content);
                vmx_inject_hw_exception(TRAP_gp_fault, 0);
                return 1;
            }
            core2_vpmu_cxt->pmu_enable->ds_area_enable = msr_content ? 1 : 0;
            break;
        }
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
        tmp = msr - MSR_P6_EVNTSEL0;
        vmx_read_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, &global_ctrl);
        if ( tmp >= 0 && tmp < core2_get_pmc_count() )
            core2_vpmu_cxt->pmu_enable->arch_pmc_enable[tmp] =
                (global_ctrl >> tmp) & (msr_content >> 22) & 1;
    }

    for ( i = 0; i < 3; i++ )
        pmu_enable |= core2_vpmu_cxt->pmu_enable->fixed_ctr_enable[i];
    for ( i = 0; i < core2_get_pmc_count(); i++ )
        pmu_enable |= core2_vpmu_cxt->pmu_enable->arch_pmc_enable[i];
    pmu_enable |= core2_vpmu_cxt->pmu_enable->ds_area_enable;
    if ( pmu_enable )
        vpmu_set(vpmu, VPMU_RUNNING);
    else
        vpmu_reset(vpmu, VPMU_RUNNING);

    /* Setup LVTPC in local apic */
    if ( vpmu_is_set(vpmu, VPMU_RUNNING) &&
         is_vlapic_lvtpc_enabled(vcpu_vlapic(v)) )
        apic_write_around(APIC_LVTPC, PMU_APIC_VECTOR);
    else
        apic_write_around(APIC_LVTPC, PMU_APIC_VECTOR | APIC_LVT_MASKED);

    core2_vpmu_save_msr_context(v, type, index, msr_content);
    if ( type != MSR_TYPE_GLOBAL )
    {
        u64 mask;
        int inject_gp = 0;
        switch ( type )
        {
        case MSR_TYPE_ARCH_CTRL:      /* MSR_P6_EVNTSEL[0,...] */
            mask = ~((1ull << 32) - 1);
            if (msr_content & mask)
                inject_gp = 1;
            break;
        case MSR_TYPE_CTRL:           /* IA32_FIXED_CTR_CTRL */
            if  ( msr == MSR_IA32_DS_AREA )
                break;
            /* 4 bits per counter, currently 3 fixed counters implemented. */
            mask = ~((1ull << (3 * 4)) - 1);
            if (msr_content & mask)
                inject_gp = 1;
            break;
        case MSR_TYPE_COUNTER:        /* IA32_FIXED_CTR[0-2] */
            mask = ~((1ull << core2_get_bitwidth_fix_count()) - 1);
            if (msr_content & mask)
                inject_gp = 1;
            break;
        }
        if (inject_gp)
            vmx_inject_hw_exception(TRAP_gp_fault, 0);
        else
            wrmsrl(msr, msr_content);
    }
    else
        vmx_write_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, msr_content);

    return 1;
}

static int core2_vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    int type = -1, index = -1;
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt = NULL;

    if ( core2_vpmu_msr_common_check(msr, &type, &index) )
    {
        core2_vpmu_cxt = vpmu->context;
        switch ( msr )
        {
        case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
            *msr_content = 0;
            break;
        case MSR_CORE_PERF_GLOBAL_STATUS:
            *msr_content = core2_vpmu_cxt->global_ovf_status;
            break;
        case MSR_CORE_PERF_GLOBAL_CTRL:
            vmx_read_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, msr_content);
            break;
        default:
            rdmsrl(msr, *msr_content);
        }
    }
    else
    {
        /* Extension for BTS */
        if ( msr == MSR_IA32_MISC_ENABLE )
        {
            if ( vpmu_is_set(vpmu, VPMU_CPU_HAS_BTS) )
                *msr_content &= ~MSR_IA32_MISC_ENABLE_BTS_UNAVAIL;
        }
        else
            return 0;
    }
    return 1;
}

static void core2_vpmu_do_cpuid(unsigned int input,
                                unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
    if (input == 0x1)
    {
        struct vpmu_struct *vpmu = vcpu_vpmu(current);

        if ( vpmu_is_set(vpmu, VPMU_CPU_HAS_DS) )
        {
            /* Switch on the 'Debug Store' feature in CPUID.EAX[1]:EDX[21] */
            *edx |= cpufeat_mask(X86_FEATURE_DS);
        }
    }
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
    if ( msr_content )
    {
        if ( is_pmc_quirk )
            handle_pmc_quirk(msr_content);
        core2_vpmu_cxt->global_ovf_status |= msr_content;
        msr_content = 0xC000000700000000 | ((1 << core2_get_pmc_count()) - 1);
        wrmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, msr_content);
    }
    else
    {
        /* No PMC overflow but perhaps a Trace Message interrupt. */
        msr_content = __vmread(GUEST_IA32_DEBUGCTL);
        if ( !(msr_content & IA32_DEBUGCTLMSR_TR) )
            return 0;
    }

    apic_write_around(APIC_LVTPC, apic_read(APIC_LVTPC) & ~APIC_LVT_MASKED);

    if ( !is_vlapic_lvtpc_enabled(vlapic) )
        return 1;

    vlapic_lvtpc = vlapic_get_reg(vlapic, APIC_LVTPC);
    int_vec = vlapic_lvtpc & APIC_VECTOR_MASK;
    vlapic_set_reg(vlapic, APIC_LVTPC, vlapic_lvtpc | APIC_LVT_MASKED);
    if ( GET_APIC_DELIVERY_MODE(vlapic_lvtpc) == APIC_MODE_FIXED )
        vlapic_set_irq(vcpu_vlapic(v), int_vec, 0);
    else
        v->nmi_pending = 1;
    return 1;
}

static int core2_vpmu_initialise(struct vcpu *v, unsigned int vpmu_flags)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    u64 msr_content;
    struct cpuinfo_x86 *c = &current_cpu_data;

    if ( !(vpmu_flags & VPMU_BOOT_BTS) )
        goto func_out;
    /* Check the 'Debug Store' feature in the CPUID.EAX[1]:EDX[21] */
    if ( cpu_has(c, X86_FEATURE_DS) )
    {
#ifdef __x86_64__
        if ( !cpu_has(c, X86_FEATURE_DTES64) )
        {
            printk(XENLOG_G_WARNING "CPU doesn't support 64-bit DS Area"
                   " - Debug Store disabled for d%d:v%d\n",
                   v->domain->domain_id, v->vcpu_id);
            goto func_out;
        }
#endif
        vpmu_set(vpmu, VPMU_CPU_HAS_DS);
        rdmsrl(MSR_IA32_MISC_ENABLE, msr_content);
        if ( msr_content & MSR_IA32_MISC_ENABLE_BTS_UNAVAIL )
        {
            /* If BTS_UNAVAIL is set reset the DS feature. */
            vpmu_reset(vpmu, VPMU_CPU_HAS_DS);
            printk(XENLOG_G_WARNING "CPU has set BTS_UNAVAIL"
                   " - Debug Store disabled for d%d:v%d\n",
                   v->domain->domain_id, v->vcpu_id);
        }
        else
        {
            vpmu_set(vpmu, VPMU_CPU_HAS_BTS);
            if ( !cpu_has(c, X86_FEATURE_DSCPL) )
                printk(XENLOG_G_INFO
                       "vpmu: CPU doesn't support CPL-Qualified BTS\n");
            printk("******************************************************\n");
            printk("** WARNING: Emulation of BTS Feature is switched on **\n");
            printk("** Using this processor feature in a virtualized    **\n");
            printk("** environment is not 100%% safe.                   **\n");
            printk("** Setting the DS buffer address with wrong values  **\n");
            printk("** may lead to hypervisor hangs or crashes.         **\n");
            printk("** It is NOT recommended for production use!        **\n");
            printk("******************************************************\n");
        }
    }
func_out:
    check_pmc_quirk();
    return 0;
}

static void core2_vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt = vpmu->context;

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
        return;
    xfree(core2_vpmu_cxt->pmu_enable);
    xfree(vpmu->context);
    if ( cpu_has_vmx_msr_bitmap )
        core2_vpmu_unset_msr_bitmap(v->arch.hvm_vmx.msr_bitmap);
    release_pmu_ownship(PMU_OWNER_HVM);
    vpmu_reset(vpmu, VPMU_CONTEXT_ALLOCATED);
}

struct arch_vpmu_ops core2_vpmu_ops = {
    .do_wrmsr = core2_vpmu_do_wrmsr,
    .do_rdmsr = core2_vpmu_do_rdmsr,
    .do_interrupt = core2_vpmu_do_interrupt,
    .do_cpuid = core2_vpmu_do_cpuid,
    .arch_vpmu_destroy = core2_vpmu_destroy,
    .arch_vpmu_save = core2_vpmu_save,
    .arch_vpmu_load = core2_vpmu_load
};

int vmx_vpmu_initialise(struct vcpu *v, unsigned int vpmu_flags)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    uint8_t family = current_cpu_data.x86;
    uint8_t cpu_model = current_cpu_data.x86_model;
    int ret = 0;

    if ( family == 6 )
    {
        switch ( cpu_model )
        {
        case 15:
        case 23:
        case 26:
        case 29:
        case 42:
        case 45:
        case 46:
        case 47:
        case 58:
            ret = core2_vpmu_initialise(v, vpmu_flags);
            if ( !ret )
                vpmu->arch_vpmu_ops = &core2_vpmu_ops;
            return ret;
        }
    }

    printk("VPMU: Initialization failed. "
           "Intel processor family %d model %d has not "
           "been supported\n", family, cpu_model);
    return -EINVAL;
}

