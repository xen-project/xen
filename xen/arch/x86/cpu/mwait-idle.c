/*
 * mwait_idle.c - native hardware idle loop for modern processors
 *
 * Copyright (c) 2013, Intel Corporation.
 * Len Brown <len.brown@intel.com>
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
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * mwait_idle is a cpuidle driver that loads on specific processors
 * in lieu of the legacy ACPI processor_idle driver.  The intent is to
 * make Linux more efficient on these processors, as mwait_idle knows
 * more than ACPI, as well as make Linux more immune to ACPI BIOS bugs.
 */

/*
 * Design Assumptions
 *
 * All CPUs have same idle states as boot CPU
 *
 * Chipset BM_STS (bus master status) bit is a NOP
 *	for preventing entry into deep C-states
 */

/*
 * Known limitations
 *
 * The driver currently initializes for_each_online_cpu() upon load.
 * It it unaware of subsequent processors hot-added to the system.
 * This means that if you boot with maxcpus=n and later online
 * processors above n, those processors will use C1 only.
 *
 * ACPI has a .suspend hack to turn off deep C-states during suspend
 * to avoid complications with the lapic timer workaround.
 * Have not seen issues with suspend, but may need same workaround here.
 */

/* un-comment DEBUG to enable pr_debug() statements */
#define DEBUG

#include <xen/lib.h>
#include <xen/cpu.h>
#include <xen/init.h>
#include <xen/softirq.h>
#include <xen/trace.h>
#include <asm/cpuidle.h>
#include <asm/hpet.h>
#include <asm/mwait.h>
#include <asm/msr.h>
#include <acpi/cpufreq/cpufreq.h>

#define MWAIT_IDLE_VERSION "0.4"
#undef PREFIX
#define PREFIX "mwait-idle: "

#ifdef DEBUG
# define pr_debug(fmt...) printk(KERN_DEBUG fmt)
#else
# define pr_debug(fmt...)
#endif

static __initdata bool_t no_mwait_idle;
invbool_param("mwait-idle", no_mwait_idle);

static unsigned int mwait_substates;

#define LAPIC_TIMER_ALWAYS_RELIABLE 0xFFFFFFFF
/* Reliable LAPIC Timer States, bit 1 for C1 etc. Default to only C1. */
static unsigned int lapic_timer_reliable_states = (1 << 1);

struct idle_cpu {
	const struct cpuidle_state *state_table;

	/*
	 * Hardware C-state auto-demotion may not always be optimal.
	 * Indicate which enable bits to clear here.
	 */
	unsigned long auto_demotion_disable_flags;
	bool_t byt_auto_demotion_disable_flag;
	bool_t disable_promotion_to_c1e;
};

static const struct idle_cpu *icpu;

static const struct cpuidle_state {
	char		name[16];
	unsigned int	flags;
	unsigned int	exit_latency; /* in US */
	unsigned int	target_residency; /* in US */
} *cpuidle_state_table;

/*
 * Set this flag for states where the HW flushes the TLB for us
 * and so we don't need cross-calls to keep it consistent.
 * If this flag is set, SW flushes the TLB, so even if the
 * HW doesn't do the flushing, this flag is safe to use.
 */
#define CPUIDLE_FLAG_TLB_FLUSHED	0x10000

/*
 * MWAIT takes an 8-bit "hint" in EAX "suggesting"
 * the C-state (top nibble) and sub-state (bottom nibble)
 * 0x00 means "MWAIT(C1)", 0x10 means "MWAIT(C2)" etc.
 *
 * We store the hint at the top of our "flags" for each state.
 */
#define flg2MWAIT(flags) (((flags) >> 24) & 0xFF)
#define MWAIT2flg(eax) ((eax & 0xFF) << 24)
#define MWAIT_HINT2CSTATE(hint) (((hint) >> MWAIT_SUBSTATE_SIZE) & MWAIT_CSTATE_MASK)
#define MWAIT_HINT2SUBSTATE(hint) ((hint) & MWAIT_CSTATE_MASK)

/*
 * States are indexed by the cstate number,
 * which is also the index into the MWAIT hint array.
 * Thus C0 is a dummy.
 */
static const struct cpuidle_state nehalem_cstates[] = {
	{
		.name = "C1-NHM",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 3,
		.target_residency = 6,
	},
	{
		.name = "C1E-NHM",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3-NHM",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 20,
		.target_residency = 80,
	},
	{
		.name = "C6-NHM",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 200,
		.target_residency = 800,
	},
	{}
};

static const struct cpuidle_state snb_cstates[] = {
	{
		.name = "C1-SNB",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E-SNB",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3-SNB",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 80,
		.target_residency = 211,
	},
	{
		.name = "C6-SNB",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 104,
		.target_residency = 345,
	},
	{
		.name = "C7-SNB",
		.flags = MWAIT2flg(0x30) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 109,
		.target_residency = 345,
	},
	{}
};

static const struct cpuidle_state byt_cstates[] = {
	{
		.name = "C1-BYT",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E-BYT",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 15,
		.target_residency = 30,
	},
	{
		.name = "C6N-BYT",
		.flags = MWAIT2flg(0x58) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 40,
		.target_residency = 275,
	},
	{
		.name = "C6S-BYT",
		.flags = MWAIT2flg(0x52) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 140,
		.target_residency = 560,
	},
	{
		.name = "C7-BYT",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 1200,
		.target_residency = 1500,
	},
	{
		.name = "C7S-BYT",
		.flags = MWAIT2flg(0x64) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 10000,
		.target_residency = 20000,
	},
	{}
};

static const struct cpuidle_state ivb_cstates[] = {
	{
		.name = "C1-IVB",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E-IVB",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3-IVB",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 59,
		.target_residency = 156,
	},
	{
		.name = "C6-IVB",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 80,
		.target_residency = 300,
	},
	{
		.name = "C7-IVB",
		.flags = MWAIT2flg(0x30) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 87,
		.target_residency = 300,
	},
	{}
};

static const struct cpuidle_state ivt_cstates[] = {
	{
		.name = "C1-IVT",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E-IVT",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 80,
	},
	{
		.name = "C3-IVT",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 59,
		.target_residency = 156,
	},
	{
		.name = "C6-IVT",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 82,
		.target_residency = 300,
	},
	{}
};

static const struct cpuidle_state ivt_cstates_4s[] = {
	{
		.name = "C1-IVT-4S",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E-IVT-4S",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 250,
	},
	{
		.name = "C3-IVT-4S",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 59,
		.target_residency = 300,
	},
	{
		.name = "C6-IVT-4S",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 84,
		.target_residency = 400,
	},
	{}
};

static const struct cpuidle_state ivt_cstates_8s[] = {
	{
		.name = "C1-IVT-8S",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E-IVT-8S",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 500,
	},
	{
		.name = "C3-IVT-8S",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 59,
		.target_residency = 600,
	},
	{
		.name = "C6-IVT-8S",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 88,
		.target_residency = 700,
	},
	{}
};

static const struct cpuidle_state hsw_cstates[] = {
	{
		.name = "C1-HSW",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E-HSW",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3-HSW",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 33,
		.target_residency = 100,
	},
	{
		.name = "C6-HSW",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 133,
		.target_residency = 400,
	},
	{
		.name = "C7s-HSW",
		.flags = MWAIT2flg(0x32) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 166,
		.target_residency = 500,
	},
 	{
		.name = "C8-HSW",
		.flags = MWAIT2flg(0x40) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 300,
		.target_residency = 900,
	},
	{
		.name = "C9-HSW",
		.flags = MWAIT2flg(0x50) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 600,
		.target_residency = 1800,
	},
	{
		.name = "C10-HSW",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 2600,
		.target_residency = 7700,
	},
	{}
};

static const struct cpuidle_state bdw_cstates[] = {
	{
		.name = "C1-BDW",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E-BDW",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3-BDW",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 40,
		.target_residency = 100,
	},
	{
		.name = "C6-BDW",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 133,
		.target_residency = 400,
	},
	{
		.name = "C7s-BDW",
		.flags = MWAIT2flg(0x32) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 166,
		.target_residency = 500,
	},
	{
		.name = "C8-BDW",
		.flags = MWAIT2flg(0x40) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 300,
		.target_residency = 900,
	},
	{
		.name = "C9-BDW",
		.flags = MWAIT2flg(0x50) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 600,
		.target_residency = 1800,
	},
	{
		.name = "C10-BDW",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 2600,
		.target_residency = 7700,
	},
	{}
};

static const struct cpuidle_state atom_cstates[] = {
	{
		.name = "C1E-ATM",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C2-ATM",
		.flags = MWAIT2flg(0x10),
		.exit_latency = 20,
		.target_residency = 80,
	},
	{
		.name = "C4-ATM",
		.flags = MWAIT2flg(0x30) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 100,
		.target_residency = 400,
	},
	{
		.name = "C6-ATM",
		.flags = MWAIT2flg(0x52) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 140,
		.target_residency = 560,
	},
	{}
};

static const struct cpuidle_state avn_cstates[] = {
	{
		.name = "C1-AVN",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C6-AVN",
		.flags = MWAIT2flg(0x51) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 15,
		.target_residency = 45,
	},
	{}
};

static void mwait_idle(void)
{
	unsigned int cpu = smp_processor_id();
	struct acpi_processor_power *power = processor_powers[cpu];
	struct acpi_processor_cx *cx = NULL;
	unsigned int eax, next_state, cstate;
	u64 before, after;
	u32 exp = 0, pred = 0, irq_traced[4] = { 0 };

	if (max_cstate > 0 && power && !sched_has_urgent_vcpu() &&
	    (next_state = cpuidle_current_governor->select(power)) > 0) {
		do {
			cx = &power->states[next_state];
		} while (cx->type > max_cstate && --next_state);
		if (!next_state)
			cx = NULL;
		menu_get_trace_data(&exp, &pred);
	}
	if (!cx) {
		if (pm_idle_save)
			pm_idle_save();
		else
			safe_halt();
		return;
	}

	cpufreq_dbs_timer_suspend();

	sched_tick_suspend();
	/* sched_tick_suspend() can raise TIMER_SOFTIRQ. Process it now. */
	process_pending_softirqs();

	/* Interrupts must be disabled for C2 and higher transitions. */
	local_irq_disable();

	if (!cpu_is_haltable(cpu)) {
		local_irq_enable();
		sched_tick_resume();
		cpufreq_dbs_timer_resume();
		return;
	}

	power->last_state = cx;
	eax = cx->address;
	cstate = ((eax >> MWAIT_SUBSTATE_SIZE) & MWAIT_CSTATE_MASK) + 1;

#if 0 /* XXX Can we/do we need to do something similar on Xen? */
	/*
	 * leave_mm() to avoid costly and often unnecessary wakeups
	 * for flushing the user TLB's associated with the active mm.
	 */
	if (cpuidle_state_table[].flags & CPUIDLE_FLAG_TLB_FLUSHED)
		leave_mm(cpu);
#endif

	if (!(lapic_timer_reliable_states & (1 << cstate)))
		lapic_timer_off();

	before = cpuidle_get_tick();
	TRACE_4D(TRC_PM_IDLE_ENTRY, cx->type, before, exp, pred);

	if (cpu_is_haltable(cpu))
		mwait_idle_with_hints(eax, MWAIT_ECX_INTERRUPT_BREAK);

	after = cpuidle_get_tick();

	cstate_restore_tsc();
	trace_exit_reason(irq_traced);
	TRACE_6D(TRC_PM_IDLE_EXIT, cx->type, after,
		irq_traced[0], irq_traced[1], irq_traced[2], irq_traced[3]);

	update_idle_stats(power, cx, before, after);
	local_irq_enable();

	if (!(lapic_timer_reliable_states & (1 << cstate)))
		lapic_timer_on();

	/* Now back in C0. */
	power->last_state = &power->states[0];

	sched_tick_resume();
	cpufreq_dbs_timer_resume();

	if ( cpuidle_current_governor->reflect )
		cpuidle_current_governor->reflect(power);
}

static void auto_demotion_disable(void *dummy)
{
	u64 msr_bits;

	rdmsrl(MSR_NHM_SNB_PKG_CST_CFG_CTL, msr_bits);
	msr_bits &= ~(icpu->auto_demotion_disable_flags);
	wrmsrl(MSR_NHM_SNB_PKG_CST_CFG_CTL, msr_bits);
}

static void byt_auto_demotion_disable(void *dummy)
{
	wrmsrl(MSR_CC6_DEMOTION_POLICY_CONFIG, 0);
	wrmsrl(MSR_MC6_DEMOTION_POLICY_CONFIG, 0);
}

static void c1e_promotion_disable(void *dummy)
{
	u64 msr_bits;

	rdmsrl(MSR_IA32_POWER_CTL, msr_bits);
	msr_bits &= ~0x2;
	wrmsrl(MSR_IA32_POWER_CTL, msr_bits);
}

static const struct idle_cpu idle_cpu_nehalem = {
	.state_table = nehalem_cstates,
	.auto_demotion_disable_flags = NHM_C1_AUTO_DEMOTE | NHM_C3_AUTO_DEMOTE,
	.disable_promotion_to_c1e = 1,
};

static const struct idle_cpu idle_cpu_atom = {
	.state_table = atom_cstates,
};

static const struct idle_cpu idle_cpu_lincroft = {
	.state_table = atom_cstates,
	.auto_demotion_disable_flags = ATM_LNC_C6_AUTO_DEMOTE,
};

static const struct idle_cpu idle_cpu_snb = {
	.state_table = snb_cstates,
	.disable_promotion_to_c1e = 1,
};

static const struct idle_cpu idle_cpu_byt = {
	.state_table = byt_cstates,
	.disable_promotion_to_c1e = 1,
	.byt_auto_demotion_disable_flag = 1,
};

static const struct idle_cpu idle_cpu_ivb = {
	.state_table = ivb_cstates,
	.disable_promotion_to_c1e = 1,
};

static const struct idle_cpu idle_cpu_ivt = {
	.state_table = ivt_cstates,
	.disable_promotion_to_c1e = 1,
};

static const struct idle_cpu idle_cpu_hsw = {
	.state_table = hsw_cstates,
	.disable_promotion_to_c1e = 1,
};

static const struct idle_cpu idle_cpu_bdw = {
	.state_table = bdw_cstates,
	.disable_promotion_to_c1e = 1,
};

static const struct idle_cpu idle_cpu_avn = {
	.state_table = avn_cstates,
	.disable_promotion_to_c1e = 1,
};

#define ICPU(model, cpu) { 6, model, &idle_cpu_##cpu }

static struct intel_idle_id {
	unsigned int family, model;
	const struct idle_cpu *data;
} intel_idle_ids[] __initdata = {
	ICPU(0x1a, nehalem),
	ICPU(0x1e, nehalem),
	ICPU(0x1f, nehalem),
	ICPU(0x25, nehalem),
	ICPU(0x2c, nehalem),
	ICPU(0x2e, nehalem),
	ICPU(0x2f, nehalem),
	ICPU(0x1c, atom),
	ICPU(0x26, lincroft),
	ICPU(0x2a, snb),
	ICPU(0x2d, snb),
	ICPU(0x36, atom),
	ICPU(0x37, byt),
	ICPU(0x3a, ivb),
	ICPU(0x3e, ivt),
	ICPU(0x3c, hsw),
	ICPU(0x3f, hsw),
	ICPU(0x45, hsw),
	ICPU(0x46, hsw),
	ICPU(0x4d, avn),
	ICPU(0x3d, bdw),
	ICPU(0x4f, bdw),
	ICPU(0x56, bdw),
	{}
};

/*
 * mwait_idle_state_table_update()
 *
 * Update the default state_table for this CPU-id
 *
 * Currently used to access tuned IVT multi-socket targets
 * Assumption: num_sockets == (max_package_num + 1)
 */
static void __init mwait_idle_state_table_update(void)
{
	/* IVT uses a different table for 1-2, 3-4, and > 4 sockets */
	if (boot_cpu_data.x86_model == 0x3e) { /* IVT */
		unsigned int cpu, max_apicid = boot_cpu_physical_apicid;

		for_each_present_cpu(cpu)
			if (max_apicid < x86_cpu_to_apicid[cpu])
				max_apicid = x86_cpu_to_apicid[cpu];
		switch (apicid_to_socket(max_apicid)) {
		case 0: case 1:
			/* 1 and 2 socket systems use default ivt_cstates */
			break;
		case 2: case 3:
			cpuidle_state_table = ivt_cstates_4s;
			break;
		default:
			cpuidle_state_table = ivt_cstates_8s;
			break;
		}
	}
}

static int __init mwait_idle_probe(void)
{
	unsigned int eax, ebx, ecx;
	const struct intel_idle_id *id;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
	    !boot_cpu_has(X86_FEATURE_MWAIT) ||
	    boot_cpu_data.cpuid_level < CPUID_MWAIT_LEAF)
		return -ENODEV;

	for (id = intel_idle_ids; id->family; ++id)
		if (id->family == boot_cpu_data.x86 &&
		    id->model == boot_cpu_data.x86_model)
			break;
	if (!id->family) {
		pr_debug(PREFIX "does not run on family %d model %d\n",
			 boot_cpu_data.x86, boot_cpu_data.x86_model);
		return -ENODEV;
	}

	cpuid(CPUID_MWAIT_LEAF, &eax, &ebx, &ecx, &mwait_substates);

	if (!(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED) ||
	    !(ecx & CPUID5_ECX_INTERRUPT_BREAK) ||
	    !mwait_substates)
		return -ENODEV;

	if (!max_cstate || no_mwait_idle) {
		pr_debug(PREFIX "disabled\n");
		return -EPERM;
	}

	pr_debug(PREFIX "MWAIT substates: %#x\n", mwait_substates);

	icpu = id->data;
	cpuidle_state_table = icpu->state_table;

	if (boot_cpu_has(X86_FEATURE_ARAT))
		lapic_timer_reliable_states = LAPIC_TIMER_ALWAYS_RELIABLE;

	pr_debug(PREFIX "v" MWAIT_IDLE_VERSION " model %#x\n",
		 boot_cpu_data.x86_model);

	pr_debug(PREFIX "lapic_timer_reliable_states %#x\n",
		 lapic_timer_reliable_states);

	mwait_idle_state_table_update();

	return 0;
}

static int mwait_idle_cpu_init(struct notifier_block *nfb,
			       unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu, cstate;
	struct acpi_processor_power *dev = processor_powers[cpu];

	switch (action) {
	default:
		return NOTIFY_DONE;

	case CPU_UP_PREPARE:
		cpuidle_init_cpu(cpu);
		return NOTIFY_DONE;

	case CPU_ONLINE:
		if (!dev)
			return NOTIFY_DONE;
		break;
	}

	dev->count = 1;

	for (cstate = 0; cpuidle_state_table[cstate].target_residency; ++cstate) {
		unsigned int num_substates, hint, state;
		struct acpi_processor_cx *cx;

		hint = flg2MWAIT(cpuidle_state_table[cstate].flags);
		state = MWAIT_HINT2CSTATE(hint) + 1;

		if (state > max_cstate) {
			printk(PREFIX "max C-state %u reached\n", max_cstate);
			break;
		}

		/* Number of sub-states for this state in CPUID.MWAIT. */
		num_substates = (mwait_substates >> (state * 4))
		                & MWAIT_SUBSTATE_MASK;
		/* If NO sub-states for this state in CPUID, skip it. */
		if (num_substates == 0)
			continue;

		if (dev->count >= ACPI_PROCESSOR_MAX_POWER) {
			printk(PREFIX "max C-state count of %u reached\n",
			       ACPI_PROCESSOR_MAX_POWER);
			break;
		}

		if (state > 2 && !boot_cpu_has(X86_FEATURE_NONSTOP_TSC) &&
		    !pm_idle_save)
			setup_clear_cpu_cap(X86_FEATURE_TSC_RELIABLE);

		cx = dev->states + dev->count;
		cx->type = state;
		cx->address = hint;
		cx->entry_method = ACPI_CSTATE_EM_FFH;
		cx->latency = cpuidle_state_table[cstate].exit_latency;
		cx->target_residency =
			cpuidle_state_table[cstate].target_residency;

		dev->count++;
	}

	if (icpu->auto_demotion_disable_flags)
		on_selected_cpus(cpumask_of(cpu), auto_demotion_disable, NULL, 1);

	if (icpu->byt_auto_demotion_disable_flag)
		on_selected_cpus(cpumask_of(cpu), byt_auto_demotion_disable, NULL, 1);

	if (icpu->disable_promotion_to_c1e)
		on_selected_cpus(cpumask_of(cpu), c1e_promotion_disable, NULL, 1);

	return NOTIFY_DONE;
}

int __init mwait_idle_init(struct notifier_block *nfb)
{
	int err;

	if (pm_idle_save)
		return -ENODEV;

	err = mwait_idle_probe();
	if (!err && !boot_cpu_has(X86_FEATURE_ARAT)) {
		hpet_broadcast_init();
		if (xen_cpuidle < 0 && !hpet_broadcast_is_available())
			err = -ENODEV;
		else if(!lapic_timer_init())
			err = -EINVAL;
		if (err)
			pr_debug(PREFIX "not used (%d)\n", err);
	}
	if (!err) {
		nfb->notifier_call = mwait_idle_cpu_init;
		mwait_idle_cpu_init(nfb, CPU_UP_PREPARE, NULL);

		pm_idle_save = pm_idle;
		pm_idle = mwait_idle;
		dead_idle = acpi_dead_idle;
	}

	return err;
}
