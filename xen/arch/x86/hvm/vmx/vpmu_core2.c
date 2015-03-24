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
 * See Intel SDM Vol 2a Instruction Set Reference chapter 3 for CPUID
 * instruction.
 * cpuid 0xa - Architectural Performance Monitoring Leaf
 * Register eax
 */
#define PMU_VERSION_SHIFT        0  /* Version ID */
#define PMU_VERSION_BITS         8  /* 8 bits 0..7 */
#define PMU_VERSION_MASK         (((1 << PMU_VERSION_BITS) - 1) << PMU_VERSION_SHIFT)

#define PMU_GENERAL_NR_SHIFT     8  /* Number of general pmu registers */
#define PMU_GENERAL_NR_BITS      8  /* 8 bits 8..15 */
#define PMU_GENERAL_NR_MASK      (((1 << PMU_GENERAL_NR_BITS) - 1) << PMU_GENERAL_NR_SHIFT)

#define PMU_GENERAL_WIDTH_SHIFT 16  /* Width of general pmu registers */
#define PMU_GENERAL_WIDTH_BITS   8  /* 8 bits 16..23 */
#define PMU_GENERAL_WIDTH_MASK  (((1 << PMU_GENERAL_WIDTH_BITS) - 1) << PMU_GENERAL_WIDTH_SHIFT)
/* Register edx */
#define PMU_FIXED_NR_SHIFT       0  /* Number of fixed pmu registers */
#define PMU_FIXED_NR_BITS        5  /* 5 bits 0..4 */
#define PMU_FIXED_NR_MASK        (((1 << PMU_FIXED_NR_BITS) -1) << PMU_FIXED_NR_SHIFT)

#define PMU_FIXED_WIDTH_SHIFT    5  /* Width of fixed pmu registers */
#define PMU_FIXED_WIDTH_BITS     8  /* 8 bits 5..12 */
#define PMU_FIXED_WIDTH_MASK     (((1 << PMU_FIXED_WIDTH_BITS) -1) << PMU_FIXED_WIDTH_SHIFT)

/* Alias registers (0x4c1) for full-width writes to PMCs */
#define MSR_PMC_ALIAS_MASK       (~(MSR_IA32_PERFCTR0 ^ MSR_IA32_A_PERFCTR0))
static bool_t __read_mostly full_width_write;

/*
 * MSR_CORE_PERF_FIXED_CTR_CTRL contains the configuration of all fixed
 * counters. 4 bits for every counter.
 */
#define FIXED_CTR_CTRL_BITS 4
#define FIXED_CTR_CTRL_MASK ((1 << FIXED_CTR_CTRL_BITS) - 1)

#define VPMU_CORE2_MAX_FIXED_PMCS     4
struct core2_vpmu_context {
    u64 fixed_ctrl;
    u64 ds_area;
    u64 pebs_enable;
    u64 global_ovf_status;
    u64 enabled_cntrs;  /* Follows PERF_GLOBAL_CTRL MSR format */
    u64 fix_counters[VPMU_CORE2_MAX_FIXED_PMCS];
    struct arch_msr_pair arch_msr_pair[1];
};

/* Number of general-purpose and fixed performance counters */
static unsigned int __read_mostly arch_pmc_cnt, fixed_pmc_cnt;

/*
 * QUIRK to workaround an issue on various family 6 cpus.
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
    if ( current_cpu_data.x86 == 6 )
        is_pmc_quirk = 1;
    else
        is_pmc_quirk = 0;    
}

static void handle_pmc_quirk(u64 msr_content)
{
    int i;
    u64 val;

    if ( !is_pmc_quirk )
        return;

    val = msr_content;
    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        if ( val & 0x1 )
        {
            u64 cnt;
            rdmsrl(MSR_P6_PERFCTR(i), cnt);
            if ( cnt == 0 )
                wrmsrl(MSR_P6_PERFCTR(i), 1);
        }
        val >>= 1;
    }
    val = msr_content >> 32;
    for ( i = 0; i < fixed_pmc_cnt; i++ )
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

/*
 * Read the number of general counters via CPUID.EAX[0xa].EAX[8..15]
 */
static int core2_get_arch_pmc_count(void)
{
    u32 eax;

    eax = cpuid_eax(0xa);
    return MASK_EXTR(eax, PMU_GENERAL_NR_MASK);
}

/*
 * Read the number of fixed counters via CPUID.EDX[0xa].EDX[0..4]
 */
static int core2_get_fixed_pmc_count(void)
{
    u32 eax;

    eax = cpuid_eax(0xa);
    return MASK_EXTR(eax, PMU_FIXED_NR_MASK);
}

/* edx bits 5-12: Bit width of fixed-function performance counters  */
static int core2_get_bitwidth_fix_count(void)
{
    u32 edx;

    edx = cpuid_edx(0xa);
    return MASK_EXTR(edx, PMU_FIXED_WIDTH_MASK);
}

static int is_core2_vpmu_msr(u32 msr_index, int *type, int *index)
{
    u32 msr_index_pmc;

    switch ( msr_index )
    {
    case MSR_CORE_PERF_FIXED_CTR_CTRL:
    case MSR_IA32_DS_AREA:
    case MSR_IA32_PEBS_ENABLE:
        *type = MSR_TYPE_CTRL;
        return 1;

    case MSR_CORE_PERF_GLOBAL_CTRL:
    case MSR_CORE_PERF_GLOBAL_STATUS:
    case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        *type = MSR_TYPE_GLOBAL;
        return 1;

    default:

        if ( (msr_index >= MSR_CORE_PERF_FIXED_CTR0) &&
             (msr_index < MSR_CORE_PERF_FIXED_CTR0 + fixed_pmc_cnt) )
        {
            *index = msr_index - MSR_CORE_PERF_FIXED_CTR0;
            *type = MSR_TYPE_COUNTER;
            return 1;
        }

        if ( (msr_index >= MSR_P6_EVNTSEL(0)) &&
             (msr_index < MSR_P6_EVNTSEL(arch_pmc_cnt)) )
        {
            *index = msr_index - MSR_P6_EVNTSEL(0);
            *type = MSR_TYPE_ARCH_CTRL;
            return 1;
        }

        msr_index_pmc = msr_index & MSR_PMC_ALIAS_MASK;
        if ( (msr_index_pmc >= MSR_IA32_PERFCTR0) &&
             (msr_index_pmc < (MSR_IA32_PERFCTR0 + arch_pmc_cnt)) )
        {
            *type = MSR_TYPE_ARCH_COUNTER;
            *index = msr_index_pmc - MSR_IA32_PERFCTR0;
            return 1;
        }
        return 0;
    }
}

static void core2_vpmu_set_msr_bitmap(unsigned long *msr_bitmap)
{
    int i;

    /* Allow Read/Write PMU Counters MSR Directly. */
    for ( i = 0; i < fixed_pmc_cnt; i++ )
    {
        clear_bit(msraddr_to_bitpos(MSR_CORE_PERF_FIXED_CTR0 + i), msr_bitmap);
        clear_bit(msraddr_to_bitpos(MSR_CORE_PERF_FIXED_CTR0 + i),
                  msr_bitmap + 0x800/BYTES_PER_LONG);
    }
    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        clear_bit(msraddr_to_bitpos(MSR_IA32_PERFCTR0+i), msr_bitmap);
        clear_bit(msraddr_to_bitpos(MSR_IA32_PERFCTR0+i),
                  msr_bitmap + 0x800/BYTES_PER_LONG);

        if ( full_width_write )
        {
            clear_bit(msraddr_to_bitpos(MSR_IA32_A_PERFCTR0 + i), msr_bitmap);
            clear_bit(msraddr_to_bitpos(MSR_IA32_A_PERFCTR0 + i),
                      msr_bitmap + 0x800/BYTES_PER_LONG);
        }
    }

    /* Allow Read PMU Non-global Controls Directly. */
    for ( i = 0; i < arch_pmc_cnt; i++ )
         clear_bit(msraddr_to_bitpos(MSR_P6_EVNTSEL(i)), msr_bitmap);

    clear_bit(msraddr_to_bitpos(MSR_CORE_PERF_FIXED_CTR_CTRL), msr_bitmap);
    clear_bit(msraddr_to_bitpos(MSR_IA32_PEBS_ENABLE), msr_bitmap);
    clear_bit(msraddr_to_bitpos(MSR_IA32_DS_AREA), msr_bitmap);
}

static void core2_vpmu_unset_msr_bitmap(unsigned long *msr_bitmap)
{
    int i;

    for ( i = 0; i < fixed_pmc_cnt; i++ )
    {
        set_bit(msraddr_to_bitpos(MSR_CORE_PERF_FIXED_CTR0 + i), msr_bitmap);
        set_bit(msraddr_to_bitpos(MSR_CORE_PERF_FIXED_CTR0 + i),
                msr_bitmap + 0x800/BYTES_PER_LONG);
    }
    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        set_bit(msraddr_to_bitpos(MSR_IA32_PERFCTR0 + i), msr_bitmap);
        set_bit(msraddr_to_bitpos(MSR_IA32_PERFCTR0 + i),
                msr_bitmap + 0x800/BYTES_PER_LONG);

        if ( full_width_write )
        {
            set_bit(msraddr_to_bitpos(MSR_IA32_A_PERFCTR0 + i), msr_bitmap);
            set_bit(msraddr_to_bitpos(MSR_IA32_A_PERFCTR0 + i),
                      msr_bitmap + 0x800/BYTES_PER_LONG);
        }
    }

    for ( i = 0; i < arch_pmc_cnt; i++ )
        set_bit(msraddr_to_bitpos(MSR_P6_EVNTSEL(i)), msr_bitmap);

    set_bit(msraddr_to_bitpos(MSR_CORE_PERF_FIXED_CTR_CTRL), msr_bitmap);
    set_bit(msraddr_to_bitpos(MSR_IA32_PEBS_ENABLE), msr_bitmap);
    set_bit(msraddr_to_bitpos(MSR_IA32_DS_AREA), msr_bitmap);
}

static inline void __core2_vpmu_save(struct vcpu *v)
{
    int i;
    struct core2_vpmu_context *core2_vpmu_cxt = vcpu_vpmu(v)->context;

    for ( i = 0; i < fixed_pmc_cnt; i++ )
        rdmsrl(MSR_CORE_PERF_FIXED_CTR0 + i, core2_vpmu_cxt->fix_counters[i]);
    for ( i = 0; i < arch_pmc_cnt; i++ )
        rdmsrl(MSR_IA32_PERFCTR0 + i, core2_vpmu_cxt->arch_msr_pair[i].counter);
}

static int core2_vpmu_save(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !vpmu_are_all_set(vpmu, VPMU_CONTEXT_SAVE | VPMU_CONTEXT_LOADED) )
        return 0;

    __core2_vpmu_save(v);

    /* Unset PMU MSR bitmap to trap lazy load. */
    if ( !vpmu_is_set(vpmu, VPMU_RUNNING) &&
         has_hvm_container_vcpu(v) && cpu_has_vmx_msr_bitmap )
        core2_vpmu_unset_msr_bitmap(v->arch.hvm_vmx.msr_bitmap);

    return 1;
}

static inline void __core2_vpmu_load(struct vcpu *v)
{
    unsigned int i, pmc_start;
    struct core2_vpmu_context *core2_vpmu_cxt = vcpu_vpmu(v)->context;

    for ( i = 0; i < fixed_pmc_cnt; i++ )
        wrmsrl(MSR_CORE_PERF_FIXED_CTR0 + i, core2_vpmu_cxt->fix_counters[i]);

    if ( full_width_write )
        pmc_start = MSR_IA32_A_PERFCTR0;
    else
        pmc_start = MSR_IA32_PERFCTR0;
    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        wrmsrl(pmc_start + i, core2_vpmu_cxt->arch_msr_pair[i].counter);
        wrmsrl(MSR_P6_EVNTSEL(i), core2_vpmu_cxt->arch_msr_pair[i].control);
    }

    wrmsrl(MSR_CORE_PERF_FIXED_CTR_CTRL, core2_vpmu_cxt->fixed_ctrl);
    wrmsrl(MSR_IA32_DS_AREA, core2_vpmu_cxt->ds_area);
    wrmsrl(MSR_IA32_PEBS_ENABLE, core2_vpmu_cxt->pebs_enable);
}

static void core2_vpmu_load(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
        return;

    vpmu_set(vpmu, VPMU_CONTEXT_LOADED);

    __core2_vpmu_load(v);
}

static int core2_vpmu_alloc_resource(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt;

    if ( !acquire_pmu_ownership(PMU_OWNER_HVM) )
        return 0;

    wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 0);
    if ( vmx_add_host_load_msr(MSR_CORE_PERF_GLOBAL_CTRL) )
        goto out_err;

    if ( vmx_add_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL) )
        goto out_err;
    vmx_write_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, 0);

    core2_vpmu_cxt = xzalloc_bytes(sizeof(struct core2_vpmu_context) +
                    (arch_pmc_cnt-1)*sizeof(struct arch_msr_pair));
    if ( !core2_vpmu_cxt )
        goto out_err;

    vpmu->context = (void *)core2_vpmu_cxt;

    vpmu_set(vpmu, VPMU_CONTEXT_ALLOCATED);

    return 1;

out_err:
    release_pmu_ownship(PMU_OWNER_HVM);

    printk("Failed to allocate VPMU resources for domain %u vcpu %u\n",
           v->vcpu_id, v->domain->domain_id);

    return 0;
}

static int core2_vpmu_msr_common_check(u32 msr_index, int *type, int *index)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( !is_core2_vpmu_msr(msr_index, type, index) )
        return 0;

    if ( unlikely(!vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED)) &&
         !core2_vpmu_alloc_resource(current) )
        return 0;

    /* Do the lazy load staff. */
    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
    {
        __core2_vpmu_load(current);
        vpmu_set(vpmu, VPMU_CONTEXT_LOADED);
        if ( has_hvm_container_vcpu(current) &&
             cpu_has_vmx_msr_bitmap )
            core2_vpmu_set_msr_bitmap(current->arch.hvm_vmx.msr_bitmap);
    }
    return 1;
}

static int core2_vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content,
                               uint64_t supported)
{
    u64 global_ctrl;
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
            supported |= IA32_DEBUGCTLMSR_TR | IA32_DEBUGCTLMSR_BTS |
                         IA32_DEBUGCTLMSR_BTINT;

            if ( cpu_has(&current_cpu_data, X86_FEATURE_DSCPL) )
                supported |= IA32_DEBUGCTLMSR_BTS_OFF_OS |
                             IA32_DEBUGCTLMSR_BTS_OFF_USR;
            if ( !(msr_content & ~supported) &&
                 vpmu_is_set(vpmu, VPMU_CPU_HAS_BTS) )
                return 1;
            if ( (msr_content & supported) &&
                 !vpmu_is_set(vpmu, VPMU_CPU_HAS_BTS) )
                printk(XENLOG_G_WARNING
                       "%pv: Debug Store unsupported on this CPU\n",
                       current);
        }
        return 0;
    }

    ASSERT(!supported);

    core2_vpmu_cxt = vpmu->context;
    switch ( msr )
    {
    case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        core2_vpmu_cxt->global_ovf_status &= ~msr_content;
        return 1;
    case MSR_CORE_PERF_GLOBAL_STATUS:
        gdprintk(XENLOG_INFO, "Can not write readonly MSR: "
                 "MSR_PERF_GLOBAL_STATUS(0x38E)!\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return 1;
    case MSR_IA32_PEBS_ENABLE:
        if ( msr_content & 1 )
            gdprintk(XENLOG_WARNING, "Guest is trying to enable PEBS, "
                     "which is not supported.\n");
        core2_vpmu_cxt->pebs_enable = msr_content;
        return 1;
    case MSR_IA32_DS_AREA:
        if ( vpmu_is_set(vpmu, VPMU_CPU_HAS_DS) )
        {
            if ( !is_canonical_address(msr_content) )
            {
                gdprintk(XENLOG_WARNING,
                         "Illegal address for IA32_DS_AREA: %#" PRIx64 "x\n",
                         msr_content);
                hvm_inject_hw_exception(TRAP_gp_fault, 0);
                return 1;
            }
            core2_vpmu_cxt->ds_area = msr_content;
            break;
        }
        gdprintk(XENLOG_WARNING, "Guest setting of DTS is ignored.\n");
        return 1;
    case MSR_CORE_PERF_GLOBAL_CTRL:
        global_ctrl = msr_content;
        break;
    case MSR_CORE_PERF_FIXED_CTR_CTRL:
        vmx_read_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, &global_ctrl);
        core2_vpmu_cxt->enabled_cntrs &=
                ~(((1ULL << VPMU_CORE2_MAX_FIXED_PMCS) - 1) << 32);
        if ( msr_content != 0 )
        {
            u64 val = msr_content;
            for ( i = 0; i < fixed_pmc_cnt; i++ )
            {
                if ( val & 3 )
                    core2_vpmu_cxt->enabled_cntrs |= (1ULL << 32) << i;
                val >>= FIXED_CTR_CTRL_BITS;
            }
        }

        core2_vpmu_cxt->fixed_ctrl = msr_content;
        break;
    default:
        tmp = msr - MSR_P6_EVNTSEL(0);
        if ( tmp >= 0 && tmp < arch_pmc_cnt )
        {
            vmx_read_guest_msr(MSR_CORE_PERF_GLOBAL_CTRL, &global_ctrl);

            if ( msr_content & (1ULL << 22) )
                core2_vpmu_cxt->enabled_cntrs |= 1ULL << tmp;
            else
                core2_vpmu_cxt->enabled_cntrs &= ~(1ULL << tmp);

            core2_vpmu_cxt->arch_msr_pair[tmp].control = msr_content;
        }
    }

    if ( (global_ctrl & core2_vpmu_cxt->enabled_cntrs) ||
         (core2_vpmu_cxt->ds_area != 0)  )
        vpmu_set(vpmu, VPMU_RUNNING);
    else
        vpmu_reset(vpmu, VPMU_RUNNING);

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
            mask = ~((1ull << (fixed_pmc_cnt * FIXED_CTR_CTRL_BITS)) - 1);
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
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
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
            if ( cpu_has(&current_cpu_data, X86_FEATURE_DTES64) )
                *ecx |= cpufeat_mask(X86_FEATURE_DTES64);
            if ( cpu_has(&current_cpu_data, X86_FEATURE_DSCPL) )
                *ecx |= cpufeat_mask(X86_FEATURE_DSCPL);
        }
    }
}

/* Dump vpmu info on console, called in the context of keyhandler 'q'. */
static void core2_vpmu_dump(const struct vcpu *v)
{
    const struct vpmu_struct *vpmu = vcpu_vpmu(v);
    unsigned int i;
    const struct core2_vpmu_context *core2_vpmu_cxt = NULL;
    u64 val;

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
         return;

    if ( !vpmu_is_set(vpmu, VPMU_RUNNING) )
    {
        if ( vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
            printk("    vPMU loaded\n");
        else
            printk("    vPMU allocated\n");
        return;
    }

    printk("    vPMU running\n");
    core2_vpmu_cxt = vpmu->context;

    /* Print the contents of the counter and its configuration msr. */
    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        const struct arch_msr_pair *msr_pair = core2_vpmu_cxt->arch_msr_pair;

        printk("      general_%d: 0x%016lx ctrl: 0x%016lx\n",
               i, msr_pair[i].counter, msr_pair[i].control);
    }
    /*
     * The configuration of the fixed counter is 4 bits each in the
     * MSR_CORE_PERF_FIXED_CTR_CTRL.
     */
    val = core2_vpmu_cxt->fixed_ctrl;
    for ( i = 0; i < fixed_pmc_cnt; i++ )
    {
        printk("      fixed_%d:   0x%016lx ctrl: %#lx\n",
               i, core2_vpmu_cxt->fix_counters[i],
               val & FIXED_CTR_CTRL_MASK);
        val >>= FIXED_CTR_CTRL_BITS;
    }
}

static int core2_vpmu_do_interrupt(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    u64 msr_content;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct core2_vpmu_context *core2_vpmu_cxt = vpmu->context;

    rdmsrl(MSR_CORE_PERF_GLOBAL_STATUS, msr_content);
    if ( msr_content )
    {
        if ( is_pmc_quirk )
            handle_pmc_quirk(msr_content);
        core2_vpmu_cxt->global_ovf_status |= msr_content;
        msr_content = 0xC000000700000000 | ((1 << arch_pmc_cnt) - 1);
        wrmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, msr_content);
    }
    else
    {
        /* No PMC overflow but perhaps a Trace Message interrupt. */
        __vmread(GUEST_IA32_DEBUGCTL, &msr_content);
        if ( !(msr_content & IA32_DEBUGCTLMSR_TR) )
            return 0;
    }

    return 1;
}

static int core2_vpmu_initialise(struct vcpu *v, unsigned int vpmu_flags)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    u64 msr_content;
    static bool_t ds_warned;

    if ( !(vpmu_flags & VPMU_BOOT_BTS) )
        goto func_out;
    /* Check the 'Debug Store' feature in the CPUID.EAX[1]:EDX[21] */
    while ( boot_cpu_has(X86_FEATURE_DS) )
    {
        if ( !boot_cpu_has(X86_FEATURE_DTES64) )
        {
            if ( !ds_warned )
                printk(XENLOG_G_WARNING "CPU doesn't support 64-bit DS Area"
                       " - Debug Store disabled for guests\n");
            break;
        }
        vpmu_set(vpmu, VPMU_CPU_HAS_DS);
        rdmsrl(MSR_IA32_MISC_ENABLE, msr_content);
        if ( msr_content & MSR_IA32_MISC_ENABLE_BTS_UNAVAIL )
        {
            /* If BTS_UNAVAIL is set reset the DS feature. */
            vpmu_reset(vpmu, VPMU_CPU_HAS_DS);
            if ( !ds_warned )
                printk(XENLOG_G_WARNING "CPU has set BTS_UNAVAIL"
                       " - Debug Store disabled for guests\n");
            break;
        }

        vpmu_set(vpmu, VPMU_CPU_HAS_BTS);
        if ( !ds_warned )
        {
            if ( !boot_cpu_has(X86_FEATURE_DSCPL) )
                printk(XENLOG_G_INFO
                       "vpmu: CPU doesn't support CPL-Qualified BTS\n");
            printk("******************************************************\n");
            printk("** WARNING: Emulation of BTS Feature is switched on **\n");
            printk("** Using this processor feature in a virtualized    **\n");
            printk("** environment is not 100%% safe.                    **\n");
            printk("** Setting the DS buffer address with wrong values  **\n");
            printk("** may lead to hypervisor hangs or crashes.         **\n");
            printk("** It is NOT recommended for production use!        **\n");
            printk("******************************************************\n");
        }
        break;
    }
    ds_warned = 1;
 func_out:

    arch_pmc_cnt = core2_get_arch_pmc_count();
    fixed_pmc_cnt = core2_get_fixed_pmc_count();
    if ( fixed_pmc_cnt > VPMU_CORE2_MAX_FIXED_PMCS )
    {
        fixed_pmc_cnt = VPMU_CORE2_MAX_FIXED_PMCS;
        printk(XENLOG_G_WARNING "Limiting number of fixed counters to %d\n",
               fixed_pmc_cnt);
    }

    check_pmc_quirk();
    return 0;
}

static void core2_vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    xfree(vpmu->context);
    if ( has_hvm_container_vcpu(v) && cpu_has_vmx_msr_bitmap )
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
    .arch_vpmu_load = core2_vpmu_load,
    .arch_vpmu_dump = core2_vpmu_dump
};

static void core2_no_vpmu_do_cpuid(unsigned int input,
                                unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
    /*
     * As in this case the vpmu is not enabled reset some bits in the
     * architectural performance monitoring related part.
     */
    if ( input == 0xa )
    {
        *eax &= ~PMU_VERSION_MASK;
        *eax &= ~PMU_GENERAL_NR_MASK;
        *eax &= ~PMU_GENERAL_WIDTH_MASK;

        *edx &= ~PMU_FIXED_NR_MASK;
        *edx &= ~PMU_FIXED_WIDTH_MASK;
    }
}

/*
 * If its a vpmu msr set it to 0.
 */
static int core2_no_vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    int type = -1, index = -1;
    if ( !is_core2_vpmu_msr(msr, &type, &index) )
        return 0;
    *msr_content = 0;
    return 1;
}

/*
 * These functions are used in case vpmu is not enabled.
 */
struct arch_vpmu_ops core2_no_vpmu_ops = {
    .do_rdmsr = core2_no_vpmu_do_rdmsr,
    .do_cpuid = core2_no_vpmu_do_cpuid,
};

int vmx_vpmu_initialise(struct vcpu *v, unsigned int vpmu_flags)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    uint8_t family = current_cpu_data.x86;
    uint8_t cpu_model = current_cpu_data.x86_model;
    int ret = 0;

    vpmu->arch_vpmu_ops = &core2_no_vpmu_ops;
    if ( !vpmu_flags )
        return 0;

    if ( family == 6 )
    {
        u64 caps;

        rdmsrl(MSR_IA32_PERF_CAPABILITIES, caps);
        full_width_write = (caps >> 13) & 1;

        switch ( cpu_model )
        {
        /* Core2: */
        case 0x0f: /* original 65 nm celeron/pentium/core2/xeon, "Merom"/"Conroe" */
        case 0x16: /* single-core 65 nm celeron/core2solo "Merom-L"/"Conroe-L" */
        case 0x17: /* 45 nm celeron/core2/xeon "Penryn"/"Wolfdale" */
        case 0x1d: /* six-core 45 nm xeon "Dunnington" */

        case 0x2a: /* SandyBridge */
        case 0x2d: /* SandyBridge, "Romley-EP" */

        /* Nehalem: */
        case 0x1a: /* 45 nm nehalem, "Bloomfield" */
        case 0x1e: /* 45 nm nehalem, "Lynnfield", "Clarksfield", "Jasper Forest" */
        case 0x2e: /* 45 nm nehalem-ex, "Beckton" */

        /* Westmere: */
        case 0x25: /* 32 nm nehalem, "Clarkdale", "Arrandale" */
        case 0x2c: /* 32 nm nehalem, "Gulftown", "Westmere-EP" */
        case 0x27: /* 32 nm Westmere-EX */

        case 0x3a: /* IvyBridge */
        case 0x3e: /* IvyBridge EP */

        /* Haswell: */
        case 0x3c:
        case 0x3f:
        case 0x45:
        case 0x46:

        /* Broadwell */
        case 0x3d:
        case 0x4f:
        case 0x56:

        /* future: */
        case 0x4e:

        /* next gen Xeon Phi */
        case 0x57:
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

