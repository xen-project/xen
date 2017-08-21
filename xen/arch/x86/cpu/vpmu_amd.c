/*
 * vpmu.c: PMU virtualization for HVM domain.
 *
 * Copyright (c) 2010, Advanced Micro Devices, Inc.
 * Parts of this code are Copyright (c) 2007, Intel Corporation
 *
 * Author: Wei Wang <wei.wang2@amd.com>
 * Tested by: Suravee Suthikulpanit <Suravee.Suthikulpanit@amd.com>
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
 *
 */

#include <xen/xenoprof.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <asm/apic.h>
#include <asm/vpmu.h>
#include <asm/hvm/save.h>
#include <asm/hvm/vlapic.h>
#include <public/pmu.h>

#define MSR_F10H_EVNTSEL_GO_SHIFT   40
#define MSR_F10H_EVNTSEL_EN_SHIFT   22
#define MSR_F10H_COUNTER_LENGTH     48

#define is_guest_mode(msr) ((msr) & (1ULL << MSR_F10H_EVNTSEL_GO_SHIFT))
#define is_pmu_enabled(msr) ((msr) & (1ULL << MSR_F10H_EVNTSEL_EN_SHIFT))
#define set_guest_mode(msr) (msr |= (1ULL << MSR_F10H_EVNTSEL_GO_SHIFT))
#define is_overflowed(msr) (!((msr) & (1ULL << (MSR_F10H_COUNTER_LENGTH-1))))

static unsigned int __read_mostly num_counters;
static const u32 __read_mostly *counters;
static const u32 __read_mostly *ctrls;
static bool_t __read_mostly k7_counters_mirrored;

/* Total size of PMU registers block (copied to/from PV(H) guest) */
static unsigned int __read_mostly regs_sz;

#define F10H_NUM_COUNTERS   4
#define F15H_NUM_COUNTERS   6
#define MAX_NUM_COUNTERS    F15H_NUM_COUNTERS

/* PMU Counter MSRs. */
static const u32 AMD_F10H_COUNTERS[] = {
    MSR_K7_PERFCTR0,
    MSR_K7_PERFCTR1,
    MSR_K7_PERFCTR2,
    MSR_K7_PERFCTR3
};

/* PMU Control MSRs. */
static const u32 AMD_F10H_CTRLS[] = {
    MSR_K7_EVNTSEL0,
    MSR_K7_EVNTSEL1,
    MSR_K7_EVNTSEL2,
    MSR_K7_EVNTSEL3
};

static const u32 AMD_F15H_COUNTERS[] = {
    MSR_AMD_FAM15H_PERFCTR0,
    MSR_AMD_FAM15H_PERFCTR1,
    MSR_AMD_FAM15H_PERFCTR2,
    MSR_AMD_FAM15H_PERFCTR3,
    MSR_AMD_FAM15H_PERFCTR4,
    MSR_AMD_FAM15H_PERFCTR5
};

static const u32 AMD_F15H_CTRLS[] = {
    MSR_AMD_FAM15H_EVNTSEL0,
    MSR_AMD_FAM15H_EVNTSEL1,
    MSR_AMD_FAM15H_EVNTSEL2,
    MSR_AMD_FAM15H_EVNTSEL3,
    MSR_AMD_FAM15H_EVNTSEL4,
    MSR_AMD_FAM15H_EVNTSEL5
};

/* Bits [63:42], [39:36], 21 and 19 are reserved */
#define CTRL_RSVD_MASK ((-1ULL & (~((1ULL << 42) - 1))) | \
                        (0xfULL << 36) | (1ULL << 21) | (1ULL << 19))
static uint64_t __read_mostly ctrl_rsvd[MAX_NUM_COUNTERS];

/* Use private context as a flag for MSR bitmap */
#define msr_bitmap_on(vpmu)    do {                                    \
                                   (vpmu)->priv_context = (void *)-1L; \
                               } while (0)
#define msr_bitmap_off(vpmu)   do {                                    \
                                   (vpmu)->priv_context = NULL;        \
                               } while (0)
#define is_msr_bitmap_on(vpmu) ((vpmu)->priv_context != NULL)

static inline int get_pmu_reg_type(u32 addr, unsigned int *idx)
{
    if ( (addr >= MSR_K7_EVNTSEL0) && (addr <= MSR_K7_EVNTSEL3) )
    {
        *idx = addr - MSR_K7_EVNTSEL0;
        return MSR_TYPE_CTRL;
    }

    if ( (addr >= MSR_K7_PERFCTR0) && (addr <= MSR_K7_PERFCTR3) )
    {
        *idx = addr - MSR_K7_PERFCTR0;
        return MSR_TYPE_COUNTER;
    }

    if ( (addr >= MSR_AMD_FAM15H_EVNTSEL0) &&
         (addr <= MSR_AMD_FAM15H_PERFCTR5 ) )
    {
        *idx = (addr - MSR_AMD_FAM15H_EVNTSEL0) >> 1;
        if (addr & 1)
            return MSR_TYPE_COUNTER;
        else
            return MSR_TYPE_CTRL;
    }

    /* unsupported registers */
    return -1;
}

static inline u32 get_fam15h_addr(u32 addr)
{
    switch ( addr )
    {
    case MSR_K7_PERFCTR0:
        return MSR_AMD_FAM15H_PERFCTR0;
    case MSR_K7_PERFCTR1:
        return MSR_AMD_FAM15H_PERFCTR1;
    case MSR_K7_PERFCTR2:
        return MSR_AMD_FAM15H_PERFCTR2;
    case MSR_K7_PERFCTR3:
        return MSR_AMD_FAM15H_PERFCTR3;
    case MSR_K7_EVNTSEL0:
        return MSR_AMD_FAM15H_EVNTSEL0;
    case MSR_K7_EVNTSEL1:
        return MSR_AMD_FAM15H_EVNTSEL1;
    case MSR_K7_EVNTSEL2:
        return MSR_AMD_FAM15H_EVNTSEL2;
    case MSR_K7_EVNTSEL3:
        return MSR_AMD_FAM15H_EVNTSEL3;
    default:
        break;
    }

    return addr;
}

static void amd_vpmu_init_regs(struct xen_pmu_amd_ctxt *ctxt)
{
    unsigned i;
    uint64_t *ctrl_regs = vpmu_reg_pointer(ctxt, ctrls);

    memset(&ctxt->regs[0], 0, regs_sz);
    for ( i = 0; i < num_counters; i++ )
        ctrl_regs[i] = ctrl_rsvd[i];
}

static void amd_vpmu_set_msr_bitmap(struct vcpu *v)
{
    unsigned int i;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    for ( i = 0; i < num_counters; i++ )
    {
        svm_intercept_msr(v, counters[i], MSR_INTERCEPT_NONE);
        svm_intercept_msr(v, ctrls[i], MSR_INTERCEPT_WRITE);
    }

    msr_bitmap_on(vpmu);
}

static void amd_vpmu_unset_msr_bitmap(struct vcpu *v)
{
    unsigned int i;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    for ( i = 0; i < num_counters; i++ )
    {
        svm_intercept_msr(v, counters[i], MSR_INTERCEPT_RW);
        svm_intercept_msr(v, ctrls[i], MSR_INTERCEPT_RW);
    }

    msr_bitmap_off(vpmu);
}

static int amd_vpmu_do_interrupt(struct cpu_user_regs *regs)
{
    return 1;
}

static inline void context_load(struct vcpu *v)
{
    unsigned int i;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_amd_ctxt *ctxt = vpmu->context;
    uint64_t *counter_regs = vpmu_reg_pointer(ctxt, counters);
    uint64_t *ctrl_regs = vpmu_reg_pointer(ctxt, ctrls);

    for ( i = 0; i < num_counters; i++ )
    {
        wrmsrl(counters[i], counter_regs[i]);
        wrmsrl(ctrls[i], ctrl_regs[i]);
    }
}

static int amd_vpmu_load(struct vcpu *v, bool_t from_guest)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_amd_ctxt *ctxt;
    uint64_t *ctrl_regs;
    unsigned int i;

    vpmu_reset(vpmu, VPMU_FROZEN);

    if ( !from_guest && vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
    {
        ctxt = vpmu->context;
        ctrl_regs = vpmu_reg_pointer(ctxt, ctrls);

        for ( i = 0; i < num_counters; i++ )
            wrmsrl(ctrls[i], ctrl_regs[i]);

        return 0;
    }

    if ( from_guest )
    {
        bool_t is_running = 0;
        struct xen_pmu_amd_ctxt *guest_ctxt = &vpmu->xenpmu_data->pmu.c.amd;

        ASSERT(!has_vlapic(v->domain));

        ctxt = vpmu->context;
        ctrl_regs = vpmu_reg_pointer(ctxt, ctrls);

        memcpy(&ctxt->regs[0], &guest_ctxt->regs[0], regs_sz);

        for ( i = 0; i < num_counters; i++ )
        {
            if ( (ctrl_regs[i] & CTRL_RSVD_MASK) != ctrl_rsvd[i] )
            {
                /*
                 * Not necessary to re-init context since we should never load
                 * it until guest provides valid values. But just to be safe.
                 */
                amd_vpmu_init_regs(ctxt);
                return -EINVAL;
            }

            if ( is_pmu_enabled(ctrl_regs[i]) )
                is_running = 1;
        }

        if ( is_running )
            vpmu_set(vpmu, VPMU_RUNNING);
        else
            vpmu_reset(vpmu, VPMU_RUNNING);
    }

    vpmu_set(vpmu, VPMU_CONTEXT_LOADED);

    context_load(v);

    return 0;
}

static inline void context_save(struct vcpu *v)
{
    unsigned int i;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_amd_ctxt *ctxt = vpmu->context;
    uint64_t *counter_regs = vpmu_reg_pointer(ctxt, counters);

    /* No need to save controls -- they are saved in amd_vpmu_do_wrmsr */
    for ( i = 0; i < num_counters; i++ )
        rdmsrl(counters[i], counter_regs[i]);
}

static int amd_vpmu_save(struct vcpu *v,  bool_t to_guest)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    unsigned int i;

    /* Stop the counters. */
    for ( i = 0; i < num_counters; i++ )
        wrmsrl(ctrls[i], 0);

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_SAVE) )
    {
        vpmu_set(vpmu, VPMU_FROZEN);
        return 0;
    }

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
        return 0;

    context_save(v);

    if ( !vpmu_is_set(vpmu, VPMU_RUNNING) && is_hvm_vcpu(v) &&
         is_msr_bitmap_on(vpmu) )
        amd_vpmu_unset_msr_bitmap(v);

    if ( to_guest )
    {
        struct xen_pmu_amd_ctxt *guest_ctxt, *ctxt;

        ASSERT(!has_vlapic(v->domain));
        ctxt = vpmu->context;
        guest_ctxt = &vpmu->xenpmu_data->pmu.c.amd;
        memcpy(&guest_ctxt->regs[0], &ctxt->regs[0], regs_sz);
    }

    return 1;
}

static void context_update(unsigned int msr, u64 msr_content)
{
    unsigned int i;
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_amd_ctxt *ctxt = vpmu->context;
    uint64_t *counter_regs = vpmu_reg_pointer(ctxt, counters);
    uint64_t *ctrl_regs = vpmu_reg_pointer(ctxt, ctrls);

    if ( k7_counters_mirrored &&
        ((msr >= MSR_K7_EVNTSEL0) && (msr <= MSR_K7_PERFCTR3)) )
    {
        msr = get_fam15h_addr(msr);
    }

    for ( i = 0; i < num_counters; i++ )
    {
       if ( msr == ctrls[i] )
       {
           ctrl_regs[i] = msr_content;
           return;
       }
        else if (msr == counters[i] )
        {
            counter_regs[i] = msr_content;
            return;
        }
    }
}

static int amd_vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content,
                             uint64_t supported)
{
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    unsigned int idx = 0;
    int type = get_pmu_reg_type(msr, &idx);

    ASSERT(!supported);

    if ( (type == MSR_TYPE_CTRL ) &&
         ((msr_content & CTRL_RSVD_MASK) != ctrl_rsvd[idx]) )
        return -EINVAL;

    /* For all counters, enable guest only mode for HVM guest */
    if ( is_hvm_vcpu(v) && (type == MSR_TYPE_CTRL) &&
         !is_guest_mode(msr_content) )
    {
        set_guest_mode(msr_content);
    }

    /* check if the first counter is enabled */
    if ( (type == MSR_TYPE_CTRL) &&
        is_pmu_enabled(msr_content) && !vpmu_is_set(vpmu, VPMU_RUNNING) )
    {
        if ( !acquire_pmu_ownership(PMU_OWNER_HVM) )
            return 0;
        vpmu_set(vpmu, VPMU_RUNNING);

        if ( is_hvm_vcpu(v) && is_msr_bitmap_on(vpmu) )
             amd_vpmu_set_msr_bitmap(v);
    }

    /* stop saving & restore if guest stops first counter */
    if ( (type == MSR_TYPE_CTRL) &&
        (is_pmu_enabled(msr_content) == 0) && vpmu_is_set(vpmu, VPMU_RUNNING) )
    {
        vpmu_reset(vpmu, VPMU_RUNNING);
        if ( is_hvm_vcpu(v) && is_msr_bitmap_on(vpmu) )
             amd_vpmu_unset_msr_bitmap(v);
        release_pmu_ownership(PMU_OWNER_HVM);
    }

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED)
        || vpmu_is_set(vpmu, VPMU_FROZEN) )
    {
        context_load(v);
        vpmu_set(vpmu, VPMU_CONTEXT_LOADED);
        vpmu_reset(vpmu, VPMU_FROZEN);
    }

    /* Update vpmu context immediately */
    context_update(msr, msr_content);

    /* Write to hw counters */
    wrmsrl(msr, msr_content);
    return 0;
}

static int amd_vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED)
        || vpmu_is_set(vpmu, VPMU_FROZEN) )
    {
        context_load(v);
        vpmu_set(vpmu, VPMU_CONTEXT_LOADED);
        vpmu_reset(vpmu, VPMU_FROZEN);
    }

    rdmsrl(msr, *msr_content);

    return 0;
}

static void amd_vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( is_hvm_vcpu(v) && is_msr_bitmap_on(vpmu) )
        amd_vpmu_unset_msr_bitmap(v);

    xfree(vpmu->context);
    vpmu->context = NULL;
    vpmu->priv_context = NULL;

    if ( vpmu_is_set(vpmu, VPMU_RUNNING) )
        release_pmu_ownership(PMU_OWNER_HVM);

    vpmu_clear(vpmu);
}

/* VPMU part of the 'q' keyhandler */
static void amd_vpmu_dump(const struct vcpu *v)
{
    const struct vpmu_struct *vpmu = vcpu_vpmu(v);
    const struct xen_pmu_amd_ctxt *ctxt = vpmu->context;
    const uint64_t *counter_regs = vpmu_reg_pointer(ctxt, counters);
    const uint64_t *ctrl_regs = vpmu_reg_pointer(ctxt, ctrls);
    unsigned int i;

    printk("    VPMU state: 0x%x ", vpmu->flags);
    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
    {
         printk("\n");
         return;
    }

    printk("(");
    if ( vpmu_is_set(vpmu, VPMU_PASSIVE_DOMAIN_ALLOCATED) )
        printk("PASSIVE_DOMAIN_ALLOCATED, ");
    if ( vpmu_is_set(vpmu, VPMU_FROZEN) )
        printk("FROZEN, ");
    if ( vpmu_is_set(vpmu, VPMU_CONTEXT_SAVE) )
        printk("SAVE, ");
    if ( vpmu_is_set(vpmu, VPMU_RUNNING) )
        printk("RUNNING, ");
    if ( vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
        printk("LOADED, ");
    printk("ALLOCATED)\n");

    for ( i = 0; i < num_counters; i++ )
    {
        uint64_t ctrl, cntr;

        rdmsrl(ctrls[i], ctrl);
        rdmsrl(counters[i], cntr);
        printk("      %#x: %#lx (%#lx in HW)    %#x: %#lx (%#lx in HW)\n",
               ctrls[i], ctrl_regs[i], ctrl,
               counters[i], counter_regs[i], cntr);
    }
}

static const struct arch_vpmu_ops amd_vpmu_ops = {
    .do_wrmsr = amd_vpmu_do_wrmsr,
    .do_rdmsr = amd_vpmu_do_rdmsr,
    .do_interrupt = amd_vpmu_do_interrupt,
    .arch_vpmu_destroy = amd_vpmu_destroy,
    .arch_vpmu_save = amd_vpmu_save,
    .arch_vpmu_load = amd_vpmu_load,
    .arch_vpmu_dump = amd_vpmu_dump
};

int svm_vpmu_initialise(struct vcpu *v)
{
    struct xen_pmu_amd_ctxt *ctxt;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu_mode == XENPMU_MODE_OFF )
        return 0;

    if ( !counters )
        return -EINVAL;

    ctxt = xmalloc_bytes(sizeof(*ctxt) + regs_sz);
    if ( !ctxt )
    {
        printk(XENLOG_G_WARNING "Insufficient memory for PMU, "
               " PMU feature is unavailable on domain %d vcpu %d.\n",
               v->vcpu_id, v->domain->domain_id);
        return -ENOMEM;
    }

    ctxt->counters = sizeof(*ctxt);
    ctxt->ctrls = ctxt->counters + sizeof(uint64_t) * num_counters;
    amd_vpmu_init_regs(ctxt);

    vpmu->context = ctxt;
    vpmu->priv_context = NULL;

    if ( !has_vlapic(v->domain) )
    {
        /* Copy register offsets to shared area */
        ASSERT(vpmu->xenpmu_data);
        memcpy(&vpmu->xenpmu_data->pmu.c.amd, ctxt,
               offsetof(struct xen_pmu_amd_ctxt, regs));
    }

    vpmu->arch_vpmu_ops = &amd_vpmu_ops;

    vpmu_set(vpmu, VPMU_CONTEXT_ALLOCATED);
    return 0;
}

int __init amd_vpmu_init(void)
{
    unsigned int i;

    switch ( current_cpu_data.x86 )
    {
    case 0x15:
        num_counters = F15H_NUM_COUNTERS;
        counters = AMD_F15H_COUNTERS;
        ctrls = AMD_F15H_CTRLS;
        k7_counters_mirrored = 1;
        break;
    case 0x10:
    case 0x12:
    case 0x14:
    case 0x16:
        num_counters = F10H_NUM_COUNTERS;
        counters = AMD_F10H_COUNTERS;
        ctrls = AMD_F10H_CTRLS;
        k7_counters_mirrored = 0;
        break;
    default:
        printk(XENLOG_WARNING "VPMU: Unsupported CPU family %#x\n",
               current_cpu_data.x86);
        return -EINVAL;
    }

    if ( sizeof(struct xen_pmu_data) +
         2 * sizeof(uint64_t) * num_counters > PAGE_SIZE )
    {
        printk(XENLOG_WARNING
               "VPMU: Register bank does not fit into VPMU shared page\n");
        counters = ctrls = NULL;
        num_counters = 0;
        return -ENOSPC;
    }

    for ( i = 0; i < num_counters; i++ )
    {
        rdmsrl(ctrls[i], ctrl_rsvd[i]);
        ctrl_rsvd[i] &= CTRL_RSVD_MASK;
    }

    regs_sz = 2 * sizeof(uint64_t) * num_counters;

    return 0;
}

