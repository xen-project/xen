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

#define CTR_READ(msr_content,msrs,c) do {rdmsrl(msrs->counters[(c)].addr, (msr_content));} while (0)
#define CTR_WRITE(l,msrs,c) do {wrmsr(msrs->counters[(c)].addr, -(unsigned int)(l), -1);} while (0)
#define CTR_OVERFLOWED(n) (!((n) & (1ULL<<31)))

#define CTRL_READ(msr_content,msrs,c) do {rdmsrl(msrs->controls[(c)].addr, (msr_content));} while (0)
#define CTRL_WRITE(msr_content,msrs,c) do {wrmsrl(msrs->controls[(c)].addr, (msr_content));} while (0)
#define CTRL_SET_ACTIVE(n) (n |= (1ULL<<22))
#define CTRL_SET_INACTIVE(n) (n &= ~(1ULL<<22))
#define CTRL_CLEAR(val) (val &= (1ULL<<21))
#define CTRL_SET_ENABLE(val) (val |= 1ULL<<20)
#define CTRL_SET_USR(val,u) (val |= ((u & 1) << 16))
#define CTRL_SET_KERN(val,k) (val |= ((k & 1) << 17))
#define CTRL_SET_UM(val, m) (val |= ((m & 0xff) << 8))
#define CTRL_SET_EVENT(val, e) (val |= (((e >> 8) & 0xf) | (e & 0xff)))
#define CTRL_SET_HOST_ONLY(val, h) (val |= ((h & 0x1ULL) << 41))
#define CTRL_SET_GUEST_ONLY(val, h) (val |= ((h & 0x1ULL) << 40))

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
	uint64_t msr_content;
	int i;
 
	/* clear all counters */
	for (i = 0 ; i < NUM_CONTROLS; ++i) {
		CTRL_READ(msr_content, msrs, i);
		CTRL_CLEAR(msr_content);
		CTRL_WRITE(msr_content, msrs, i);
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

			CTRL_READ(msr_content, msrs, i);
			CTRL_CLEAR(msr_content);
			CTRL_SET_ENABLE(msr_content);
			CTRL_SET_USR(msr_content, counter_config[i].user);
			CTRL_SET_KERN(msr_content, counter_config[i].kernel);
			CTRL_SET_UM(msr_content, counter_config[i].unit_mask);
			CTRL_SET_EVENT(msr_content, counter_config[i].event);
			CTRL_SET_HOST_ONLY(msr_content, 0);
			CTRL_SET_GUEST_ONLY(msr_content, 0);
			CTRL_WRITE(msr_content, msrs, i);
		} else {
			reset_value[i] = 0;
		}
	}
}

static int athlon_check_ctrs(unsigned int const cpu,
			     struct op_msrs const * const msrs,
			     struct cpu_user_regs * const regs)

{
	uint64_t msr_content;
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
		CTR_READ(msr_content, msrs, i);
		if (CTR_OVERFLOWED(msr_content)) {
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
	uint64_t msr_content;
	int i;
	for (i = 0 ; i < NUM_COUNTERS ; ++i) {
		if (reset_value[i]) {
			CTRL_READ(msr_content, msrs, i);
			CTRL_SET_ACTIVE(msr_content);
			CTRL_WRITE(msr_content, msrs, i);
		}
	}
}


static void athlon_stop(struct op_msrs const * const msrs)
{
	uint64_t msr_content;
	int i;

	/* Subtle: stop on all counters to avoid race with
	 * setting our pm callback */
	for (i = 0 ; i < NUM_COUNTERS ; ++i) {
		CTRL_READ(msr_content, msrs, i);
		CTRL_SET_INACTIVE(msr_content);
		CTRL_WRITE(msr_content, msrs, i);
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
