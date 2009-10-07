/**
 * @file op_model_athlon.h
 * athlon / K7 model-specific MSR operations
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
#include <asm/hvm/support.h>
 
#include "op_x86_model.h"
#include "op_counter.h"

#define NUM_COUNTERS 4
#define NUM_CONTROLS 4

#define CTR_READ(l,h,msrs,c) do {rdmsr(msrs->counters[(c)].addr, (l), (h));} while (0)
#define CTR_WRITE(l,msrs,c) do {wrmsr(msrs->counters[(c)].addr, -(unsigned int)(l), -1);} while (0)
#define CTR_OVERFLOWED(n) (!((n) & (1U<<31)))

#define CTRL_READ(l,h,msrs,c) do {rdmsr(msrs->controls[(c)].addr, (l), (h));} while (0)
#define CTRL_WRITE(l,h,msrs,c) do {wrmsr(msrs->controls[(c)].addr, (l), (h));} while (0)
#define CTRL_SET_ACTIVE(n) (n |= (1<<22))
#define CTRL_SET_INACTIVE(n) (n &= ~(1<<22))
#define CTRL_CLEAR(lo, hi) (lo &= (1<<21), hi = 0)
#define CTRL_SET_ENABLE(val) (val |= 1<<20)
#define CTRL_SET_USR(val,u) (val |= ((u & 1) << 16))
#define CTRL_SET_KERN(val,k) (val |= ((k & 1) << 17))
#define CTRL_SET_UM(val, m) (val |= ((m & 0xff) << 8))
#define CTRL_SET_EVENT_LOW(val, e) (val |= (e & 0xff))
#define CTRL_SET_EVENT_HIGH(val, e) (val |= ((e >> 8) & 0xf))
#define CTRL_SET_HOST_ONLY(val, h) (val |= ((h & 1) << 9))
#define CTRL_SET_GUEST_ONLY(val, h) (val |= ((h & 1) << 8))

static unsigned long reset_value[NUM_COUNTERS];

extern char svm_stgi_label[];

static void athlon_fill_in_addresses(struct op_msrs * const msrs)
{
	msrs->counters[0].addr = MSR_K7_PERFCTR0;
	msrs->counters[1].addr = MSR_K7_PERFCTR1;
	msrs->counters[2].addr = MSR_K7_PERFCTR2;
	msrs->counters[3].addr = MSR_K7_PERFCTR3;

	msrs->controls[0].addr = MSR_K7_EVNTSEL0;
	msrs->controls[1].addr = MSR_K7_EVNTSEL1;
	msrs->controls[2].addr = MSR_K7_EVNTSEL2;
	msrs->controls[3].addr = MSR_K7_EVNTSEL3;
}

 
static void athlon_setup_ctrs(struct op_msrs const * const msrs)
{
	unsigned int low, high;
	int i;
 
	/* clear all counters */
	for (i = 0 ; i < NUM_CONTROLS; ++i) {
		CTRL_READ(low, high, msrs, i);
		CTRL_CLEAR(low, high);
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
			CTRL_CLEAR(low, high);
			CTRL_SET_ENABLE(low);
			CTRL_SET_USR(low, counter_config[i].user);
			CTRL_SET_KERN(low, counter_config[i].kernel);
			CTRL_SET_UM(low, counter_config[i].unit_mask);
			CTRL_SET_EVENT_LOW(low, counter_config[i].event);
			CTRL_SET_EVENT_HIGH(high, counter_config[i].event);
			CTRL_SET_HOST_ONLY(high, 0);
			CTRL_SET_GUEST_ONLY(high, 0);
			CTRL_WRITE(low, high, msrs, i);
		} else {
			reset_value[i] = 0;
		}
	}
}

static int athlon_check_ctrs(unsigned int const cpu,
			     struct op_msrs const * const msrs,
			     struct cpu_user_regs * const regs)

{
	unsigned int low, high;
	int i;
	int ovf = 0;
	unsigned long eip = regs->eip;
	int mode = 0;
	struct vcpu *v = current;
	struct cpu_user_regs *guest_regs = guest_cpu_user_regs();

	if (!guest_mode(regs) &&
	    (regs->eip == (unsigned long)svm_stgi_label)) {
		/* SVM guest was running when NMI occurred */
		ASSERT(is_hvm_vcpu(v));
		eip = guest_regs->eip;
		mode = xenoprofile_get_mode(v, guest_regs);
	} else {
		eip = regs->eip;
		mode = xenoprofile_get_mode(v, regs);
	}

	for (i = 0 ; i < NUM_COUNTERS; ++i) {
		CTR_READ(low, high, msrs, i);
		if (CTR_OVERFLOWED(low)) {
			xenoprof_log_event(current, regs, eip, mode, i);
			CTR_WRITE(reset_value[i], msrs, i);
			ovf = 1;
		}
	}

	/* See op_model_ppro.c */
	return ovf;
}

 
static void athlon_start(struct op_msrs const * const msrs)
{
	unsigned int low, high;
	int i;
	for (i = 0 ; i < NUM_COUNTERS ; ++i) {
		if (reset_value[i]) {
			CTRL_READ(low, high, msrs, i);
			CTRL_SET_ACTIVE(low);
			CTRL_WRITE(low, high, msrs, i);
		}
	}
}


static void athlon_stop(struct op_msrs const * const msrs)
{
	unsigned int low,high;
	int i;

	/* Subtle: stop on all counters to avoid race with
	 * setting our pm callback */
	for (i = 0 ; i < NUM_COUNTERS ; ++i) {
		CTRL_READ(low, high, msrs, i);
		CTRL_SET_INACTIVE(low);
		CTRL_WRITE(low, high, msrs, i);
	}
}


struct op_x86_model_spec const op_athlon_spec = {
	.num_counters = NUM_COUNTERS,
	.num_controls = NUM_CONTROLS,
	.fill_in_addresses = &athlon_fill_in_addresses,
	.setup_ctrs = &athlon_setup_ctrs,
	.check_ctrs = &athlon_check_ctrs,
	.start = &athlon_start,
	.stop = &athlon_stop
};
