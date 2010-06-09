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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
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
#include <public/sched.h>
#include <public/hvm/save.h>
#include <asm/hvm/vpmu.h>

#define NUM_COUNTERS 4

#define MSR_F10H_EVNTSEL_GO_SHIFT   40
#define MSR_F10H_EVNTSEL_EN_SHIFT   22
#define MSR_F10H_COUNTER_LENGTH     48

#define is_guest_mode(msr) ((msr) & (1ULL << MSR_F10H_EVNTSEL_GO_SHIFT))
#define is_pmu_enabled(msr) ((msr) & (1ULL << MSR_F10H_EVNTSEL_EN_SHIFT))
#define set_guest_mode(msr) (msr |= (1ULL << MSR_F10H_EVNTSEL_GO_SHIFT))
#define is_overflowed(msr) (!((msr) & (1ULL << (MSR_F10H_COUNTER_LENGTH-1))))

/* PMU Counter MSRs. */
u32 AMD_F10H_COUNTERS[] = {
    MSR_K7_PERFCTR0,
    MSR_K7_PERFCTR1,
    MSR_K7_PERFCTR2,
    MSR_K7_PERFCTR3
};

/* PMU Control MSRs. */
u32 AMD_F10H_CTRLS[] = {
    MSR_K7_EVNTSEL0,
    MSR_K7_EVNTSEL1,
    MSR_K7_EVNTSEL2,
    MSR_K7_EVNTSEL3
};

/* storage for context switching */
struct amd_vpmu_context {
    u64 counters[NUM_COUNTERS];
    u64 ctrls[NUM_COUNTERS];
    u32 hw_lapic_lvtpc;
};

static inline int get_pmu_reg_type(u32 addr)
{
    if ( (addr >= MSR_K7_EVNTSEL0) && (addr <= MSR_K7_EVNTSEL3) )
        return MSR_TYPE_CTRL;

    if ( (addr >= MSR_K7_PERFCTR0) && (addr <= MSR_K7_PERFCTR3) )
        return MSR_TYPE_COUNTER;

    /* unsupported registers */
    return -1;
}


static int amd_vpmu_do_interrupt(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vlapic *vlapic = vcpu_vlapic(v);
    u32 vlapic_lvtpc;
    unsigned char int_vec;

    if ( !is_vlapic_lvtpc_enabled(vlapic) )
        return 0;

    vlapic_lvtpc = vlapic_get_reg(vlapic, APIC_LVTPC);
    int_vec = vlapic_lvtpc & APIC_VECTOR_MASK;

    if ( GET_APIC_DELIVERY_MODE(vlapic_lvtpc) == APIC_MODE_FIXED )
        vlapic_set_irq(vcpu_vlapic(v), int_vec, 0);
    else
        test_and_set_bool(v->nmi_pending);

    return 1;
}

static inline void context_restore(struct vcpu *v)
{
    u64 i;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct amd_vpmu_context *ctxt = vpmu->context;

    for ( i = 0; i < NUM_COUNTERS; i++ )
        wrmsrl(AMD_F10H_CTRLS[i], ctxt->ctrls[i]);

    for ( i = 0; i < NUM_COUNTERS; i++ )
    {
        wrmsrl(AMD_F10H_COUNTERS[i], ctxt->counters[i]);

        /* Force an interrupt to allow guest reset the counter,
        if the value is positive */
        if ( is_overflowed(ctxt->counters[i]) && (ctxt->counters[i] > 0) )
        {
            gdprintk(XENLOG_WARNING, "VPMU: Force a performance counter "
                "overflow interrupt!\n");
            amd_vpmu_do_interrupt(0);
        }
    }
}

static void amd_vpmu_restore(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct amd_vpmu_context *ctxt = vpmu->context;

    if ( !((vpmu->flags & VPMU_CONTEXT_ALLOCATED) &&
           (vpmu->flags & VPMU_RUNNING)) )
        return;

    context_restore(v);
    apic_write(APIC_LVTPC, ctxt->hw_lapic_lvtpc);
}

static inline void context_save(struct vcpu *v)
{
    int i;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct amd_vpmu_context *ctxt = vpmu->context;

    for ( i = 0; i < NUM_COUNTERS; i++ )
        rdmsrl(AMD_F10H_COUNTERS[i], ctxt->counters[i]);

    for ( i = 0; i < NUM_COUNTERS; i++ )
        rdmsrl(AMD_F10H_CTRLS[i], ctxt->ctrls[i]);
}

static void amd_vpmu_save(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct amd_vpmu_context *ctx = vpmu->context;

    if ( !((vpmu->flags & VPMU_CONTEXT_ALLOCATED) &&
           (vpmu->flags & VPMU_RUNNING)) )
        return;

    context_save(v);
    ctx->hw_lapic_lvtpc = apic_read(APIC_LVTPC);
    apic_write(APIC_LVTPC,  ctx->hw_lapic_lvtpc | APIC_LVT_MASKED);
}

static void context_update(unsigned int msr, u64 msr_content)
{
    int i;
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct amd_vpmu_context *ctxt = vpmu->context;

    for ( i = 0; i < NUM_COUNTERS; i++ )
        if ( msr == AMD_F10H_COUNTERS[i] )
            ctxt->counters[i] = msr_content;

    for ( i = 0; i < NUM_COUNTERS; i++ )
        if ( msr == AMD_F10H_CTRLS[i] )
            ctxt->ctrls[i] = msr_content;

    ctxt->hw_lapic_lvtpc = apic_read(APIC_LVTPC);
}

static int amd_vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content)
{
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    /* For all counters, enable guest only mode for HVM guest */
    if ( (get_pmu_reg_type(msr) == MSR_TYPE_CTRL) &&
        !(is_guest_mode(msr_content)) )
    {
        set_guest_mode(msr_content);
    }

    /* check if the first counter is enabled */
    if ( (get_pmu_reg_type(msr) == MSR_TYPE_CTRL) &&
        is_pmu_enabled(msr_content) && !(vpmu->flags & VPMU_RUNNING) )
    {
        if ( !acquire_pmu_ownership(PMU_OWNER_HVM) )
            return 1;
        vpmu->flags |= VPMU_RUNNING;
        apic_write(APIC_LVTPC, PMU_APIC_VECTOR);
    }

    /* stop saving & restore if guest stops first counter */
    if ( (get_pmu_reg_type(msr) == MSR_TYPE_CTRL) && 
        (is_pmu_enabled(msr_content) == 0) && (vpmu->flags & VPMU_RUNNING) )
    {
        apic_write(APIC_LVTPC, PMU_APIC_VECTOR | APIC_LVT_MASKED);
        vpmu->flags &= ~VPMU_RUNNING;
        release_pmu_ownship(PMU_OWNER_HVM);
    }

    /* Update vpmu context immediately */
    context_update(msr, msr_content);

    /* Write to hw counters */
    wrmsrl(msr, msr_content);
    return 1;
}

static int amd_vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    rdmsrl(msr, *msr_content);
    return 1;
}

static void amd_vpmu_initialise(struct vcpu *v)
{
    struct amd_vpmu_context *ctxt = NULL;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu->flags & VPMU_CONTEXT_ALLOCATED )
        return;

    ctxt = xmalloc_bytes(sizeof(struct amd_vpmu_context));

    if ( !ctxt )
    {
        gdprintk(XENLOG_WARNING, "Insufficient memory for PMU, "
            " PMU feature is unavailable on domain %d vcpu %d.\n",
            v->vcpu_id, v->domain->domain_id);
        return;
    }

    memset(ctxt, 0, sizeof(struct amd_vpmu_context));
    vpmu->context = (void *)ctxt;
    vpmu->flags |= VPMU_CONTEXT_ALLOCATED;
}

static void amd_vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !(vpmu->flags & VPMU_CONTEXT_ALLOCATED) )
        return;

    xfree(vpmu->context);
    vpmu->flags &= ~VPMU_CONTEXT_ALLOCATED;

    if ( vpmu->flags & VPMU_RUNNING )
    {
        vpmu->flags &= ~VPMU_RUNNING;
        release_pmu_ownship(PMU_OWNER_HVM);
    }
}

struct arch_vpmu_ops amd_vpmu_ops = {
    .do_wrmsr = amd_vpmu_do_wrmsr,
    .do_rdmsr = amd_vpmu_do_rdmsr,
    .do_interrupt = amd_vpmu_do_interrupt,
    .arch_vpmu_initialise = amd_vpmu_initialise,
    .arch_vpmu_destroy = amd_vpmu_destroy,
    .arch_vpmu_save = amd_vpmu_save,
    .arch_vpmu_load = amd_vpmu_restore
};
