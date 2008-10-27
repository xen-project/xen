/**
 * @file op_model_ppro.h
 * pentium pro / P6 model-specific MSR operations
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 * @author Graydon Hoare
 */

#include <xen/types.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/apic.h>
#include <asm/processor.h>
#include <xen/sched.h>
#include <asm/regs.h>
#include <asm/current.h>
#include <asm/hvm/vmx/vpmu.h>
#include <asm/hvm/vmx/vpmu_core2.h>
 
#include "op_x86_model.h"
#include "op_counter.h"

#define NUM_COUNTERS 2
#define NUM_CONTROLS 2

#define CTR_READ(l,h,msrs,c) do {rdmsr(msrs->counters[(c)].addr, (l), (h));} while (0)
#define CTR_WRITE(l,msrs,c) do {wrmsr(msrs->counters[(c)].addr, -(u32)(l), -1);} while (0)
#define CTR_OVERFLOWED(n) (!((n) & (1U<<31)))

#define CTRL_READ(l,h,msrs,c) do {rdmsr((msrs->controls[(c)].addr), (l), (h));} while (0)
#define CTRL_WRITE(l,h,msrs,c) do {wrmsr((msrs->controls[(c)].addr), (l), (h));} while (0)
#define CTRL_SET_ACTIVE(n) (n |= (1<<22))
#define CTRL_SET_INACTIVE(n) (n &= ~(1<<22))
#define CTRL_CLEAR(x) (x &= (1<<21))
#define CTRL_SET_ENABLE(val) (val |= 1<<20)
#define CTRL_SET_USR(val,u) (val |= ((u & 1) << 16))
#define CTRL_SET_KERN(val,k) (val |= ((k & 1) << 17))
#define CTRL_SET_UM(val, m) (val |= (m << 8))
#define CTRL_SET_EVENT(val, e) (val |= e)
#define IS_ACTIVE(val) (val & (1 << 22) )  
#define IS_ENABLE(val) (val & (1 << 20) )
static unsigned long reset_value[NUM_COUNTERS];
int ppro_has_global_ctrl = 0;
extern int is_passive(struct domain *d);
 
static void ppro_fill_in_addresses(struct op_msrs * const msrs)
{
	msrs->counters[0].addr = MSR_P6_PERFCTR0;
	msrs->counters[1].addr = MSR_P6_PERFCTR1;
	
	msrs->controls[0].addr = MSR_P6_EVNTSEL0;
	msrs->controls[1].addr = MSR_P6_EVNTSEL1;
}


static void ppro_setup_ctrs(struct op_msrs const * const msrs)
{
	unsigned int low, high;
	int i;

	/* clear all counters */
	for (i = 0 ; i < NUM_CONTROLS; ++i) {
		CTRL_READ(low, high, msrs, i);
		CTRL_CLEAR(low);
		CTRL_WRITE(low, high, msrs, i);
	}
	
	/* avoid a false detection of ctr overflows in NMI handler */
	for (i = 0; i < NUM_COUNTERS; ++i) {
		CTR_WRITE(1, msrs, i);
	}

	/* enable active counters */
	for (i = 0; i < NUM_COUNTERS; ++i) {
		if (counter_config[i].enabled) {
			reset_value[i] = counter_config[i].count;

			CTR_WRITE(counter_config[i].count, msrs, i);

			CTRL_READ(low, high, msrs, i);
			CTRL_CLEAR(low);
			CTRL_SET_ENABLE(low);
			CTRL_SET_USR(low, counter_config[i].user);
			CTRL_SET_KERN(low, counter_config[i].kernel);
			CTRL_SET_UM(low, counter_config[i].unit_mask);
			CTRL_SET_EVENT(low, counter_config[i].event);
			CTRL_WRITE(low, high, msrs, i);
		}
	}
}

extern void xenoprof_log_event(struct vcpu *v, struct cpu_user_regs * regs, 
			       unsigned long eip, int mode, int event);
extern int xenoprofile_get_mode(struct vcpu *v,
				struct cpu_user_regs * const regs);
 
static int ppro_check_ctrs(unsigned int const cpu,
                           struct op_msrs const * const msrs,
                           struct cpu_user_regs * const regs)
{
	unsigned int low, high;
	int i;
	int ovf = 0;
	unsigned long eip = regs->eip;
	int mode = xenoprofile_get_mode(current, regs);
	struct arch_msr_pair *msrs_content = vcpu_vpmu(current)->context;

	for (i = 0 ; i < NUM_COUNTERS; ++i) {
		if (!reset_value[i])
			continue;
		CTR_READ(low, high, msrs, i);
		if (CTR_OVERFLOWED(low)) {
			xenoprof_log_event(current, regs, eip, mode, i);
			CTR_WRITE(reset_value[i], msrs, i);
			if ( is_passive(current->domain) && (mode != 2) && 
				(vcpu_vpmu(current)->flags & PASSIVE_DOMAIN_ALLOCATED) ) 
			{
				if ( IS_ACTIVE(msrs_content[i].control) )
				{
					msrs_content[i].counter = (low | (unsigned long)high << 32);
					if ( IS_ENABLE(msrs_content[i].control) )
						ovf = 2;
				}
			}
			if ( !ovf )
				ovf = 1;
		}
	}

	/* Only P6 based Pentium M need to re-unmask the apic vector but it
	 * doesn't hurt other P6 variant */
	apic_write(APIC_LVTPC, apic_read(APIC_LVTPC) & ~APIC_LVT_MASKED);

	return ovf;
}

 
static void ppro_start(struct op_msrs const * const msrs)
{
	unsigned int low,high;
	int i;

	for (i = 0; i < NUM_COUNTERS; ++i) {
		if (reset_value[i]) {
			CTRL_READ(low, high, msrs, i);
			CTRL_SET_ACTIVE(low);
			CTRL_WRITE(low, high, msrs, i);
		}
	}
    /* Global Control MSR is enabled by default when system power on.
     * However, this may not hold true when xenoprof starts to run.
     */
    if ( ppro_has_global_ctrl )
        wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, (1<<NUM_COUNTERS) - 1);
}


static void ppro_stop(struct op_msrs const * const msrs)
{
	unsigned int low,high;
	int i;

	for (i = 0; i < NUM_COUNTERS; ++i) {
		if (!reset_value[i])
			continue;
		CTRL_READ(low, high, msrs, i);
		CTRL_SET_INACTIVE(low);
		CTRL_WRITE(low, high, msrs, i);
	}
    if ( ppro_has_global_ctrl )
        wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 0);
}

static int ppro_is_arch_pmu_msr(u64 msr_index, int *type, int *index)
{
	if ( (msr_index >= MSR_IA32_PERFCTR0) &&
            (msr_index < (MSR_IA32_PERFCTR0 + NUM_COUNTERS)) )
	{
        	*type = MSR_TYPE_ARCH_COUNTER;
		*index = msr_index - MSR_IA32_PERFCTR0;
		return 1;
        }
        if ( (msr_index >= MSR_P6_EVNTSEL0) &&
            (msr_index < (MSR_P6_EVNTSEL0 + NUM_CONTROLS)) )
        {
		*type = MSR_TYPE_ARCH_CTRL;
		*index = msr_index - MSR_P6_EVNTSEL0;
		return 1;
        }

        return 0;
}

static int ppro_allocate_msr(struct vcpu *v)
{
	struct vpmu_struct *vpmu = vcpu_vpmu(v);
	struct arch_msr_pair *msr_content;
	
	msr_content = xmalloc_bytes( sizeof(struct arch_msr_pair) * NUM_COUNTERS );
	if ( !msr_content )
		goto out;
	memset(msr_content, 0, sizeof(struct arch_msr_pair) * NUM_COUNTERS);
	vpmu->context = (void *)msr_content;
	vpmu->flags = 0;
	vpmu->flags |= PASSIVE_DOMAIN_ALLOCATED;
	return 1;
out:
        gdprintk(XENLOG_WARNING, "Insufficient memory for oprofile, oprofile is "
                 "unavailable on domain %d vcpu %d.\n",
                 v->vcpu_id, v->domain->domain_id);
        return 0;	
}

static void ppro_free_msr(struct vcpu *v)
{
	struct vpmu_struct *vpmu = vcpu_vpmu(v);

	xfree(vpmu->context);
	vpmu->flags &= ~PASSIVE_DOMAIN_ALLOCATED;
}

static void ppro_load_msr(struct vcpu *v, int type, int index, u64 *msr_content)
{
	struct arch_msr_pair *msrs = vcpu_vpmu(v)->context;
	switch ( type )
	{
	case MSR_TYPE_ARCH_COUNTER:
		*msr_content = msrs[index].counter;
		break;
	case MSR_TYPE_ARCH_CTRL:
		*msr_content = msrs[index].control;
		break;
	}	
}

static void ppro_save_msr(struct vcpu *v, int type, int index, u64 msr_content)
{
	struct arch_msr_pair *msrs = vcpu_vpmu(v)->context;
	
	switch ( type )
	{
	case MSR_TYPE_ARCH_COUNTER:
		msrs[index].counter = msr_content;
		break;
	case MSR_TYPE_ARCH_CTRL:
		msrs[index].control = msr_content;
		break;
	}	
}

struct op_x86_model_spec const op_ppro_spec = {
	.num_counters = NUM_COUNTERS,
	.num_controls = NUM_CONTROLS,
	.fill_in_addresses = &ppro_fill_in_addresses,
	.setup_ctrs = &ppro_setup_ctrs,
	.check_ctrs = &ppro_check_ctrs,
	.start = &ppro_start,
	.stop = &ppro_stop,
	.is_arch_pmu_msr = &ppro_is_arch_pmu_msr,
	.allocated_msr = &ppro_allocate_msr,
	.free_msr = &ppro_free_msr,
	.load_msr = &ppro_load_msr,
	.save_msr = &ppro_save_msr
};
