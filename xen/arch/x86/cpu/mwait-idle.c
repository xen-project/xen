/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * mwait_idle.c - native hardware idle loop for modern processors
 *
 * Copyright (c) 2013, Intel Corporation.
 * Len Brown <len.brown@intel.com>
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
 *
 * CPU will flush caches as needed when entering a C-state via MWAIT
 *	(in contrast to entering ACPI C3, in which case the WBINVD
 *	instruction needs to be executed to flush the caches)
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
#include <xen/param.h>
#include <xen/softirq.h>
#include <xen/trace.h>
#include <asm/cpuidle.h>
#include <asm/hpet.h>
#include <asm/intel-family.h>
#include <asm/mwait.h>
#include <asm/msr.h>
#include <asm/spec_ctrl.h>
#include <acpi/cpufreq/cpufreq.h>

#define MWAIT_IDLE_VERSION "0.4.1"
#undef PREFIX
#define PREFIX "mwait-idle: "

#ifdef DEBUG
# define pr_debug(fmt...) printk(KERN_DEBUG fmt)
#else
# define pr_debug(fmt...)
#endif

static __initdata bool opt_mwait_idle = true;
boolean_param("mwait-idle", opt_mwait_idle);

static unsigned int mwait_substates;

/*
 * Some platforms come with mutually exclusive C-states, so that if one is
 * enabled, the other C-states must not be used. Example: C1 and C1E on
 * Sapphire Rapids platform. This parameter allows for selecting the
 * preferred C-states among the groups of mutually exclusive C-states - the
 * selected C-states will be registered, the other C-states from the mutually
 * exclusive group won't be registered. If the platform has no mutually
 * exclusive C-states, this parameter has no effect.
 */
static unsigned int __ro_after_init preferred_states_mask;
static char __initdata preferred_states[64];
string_param("preferred-cstates", preferred_states);

#define LAPIC_TIMER_ALWAYS_RELIABLE 0xFFFFFFFF
/* Reliable LAPIC Timer States, bit 1 for C1 etc. Default to only C1. */
static unsigned int lapic_timer_reliable_states = (1 << 1);

enum c1e_promotion {
	C1E_PROMOTION_PRESERVE,
	C1E_PROMOTION_ENABLE,
	C1E_PROMOTION_DISABLE
};

struct idle_cpu {
	const struct cpuidle_state *state_table;

	/*
	 * Hardware C-state auto-demotion may not always be optimal.
	 * Indicate which enable bits to clear here.
	 */
	unsigned long auto_demotion_disable_flags;
	bool byt_auto_demotion_disable_flag;
	enum c1e_promotion c1e_promotion;
};

static const struct idle_cpu *icpu;

static const struct cpuidle_state {
	char		name[16];
	unsigned int	flags;
	unsigned int	exit_latency; /* in US */
	unsigned int	target_residency; /* in US */
} *cpuidle_state_table;

#define CPUIDLE_FLAG_DISABLED		0x1
/*
 * Enable interrupts before entering the C-state. On some platforms and for
 * some C-states, this may measurably decrease interrupt latency.
 */
#define CPUIDLE_FLAG_IRQ_ENABLE		0x8000
/*
 * Set this flag for states where the HW flushes the TLB for us
 * and so we don't need cross-calls to keep it consistent.
 * If this flag is set, SW flushes the TLB, so even if the
 * HW doesn't do the flushing, this flag is safe to use.
 */
#define CPUIDLE_FLAG_TLB_FLUSHED	0x10000

/*
 * Disable IBRS across idle (when KERNEL_IBRS), is exclusive vs IRQ_ENABLE
 * above.
 */
#define CPUIDLE_FLAG_IBRS		0x20000

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
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 3,
		.target_residency = 6,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 20,
		.target_residency = 80,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 200,
		.target_residency = 800,
	},
	{}
};

static const struct cpuidle_state snb_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 80,
		.target_residency = 211,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 104,
		.target_residency = 345,
	},
	{
		.name = "C7",
		.flags = MWAIT2flg(0x30) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 109,
		.target_residency = 345,
	},
	{}
};

static const struct cpuidle_state byt_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C6N",
		.flags = MWAIT2flg(0x58) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 300,
		.target_residency = 275,
	},
	{
		.name = "C6S",
		.flags = MWAIT2flg(0x52) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 500,
		.target_residency = 560,
	},
	{
		.name = "C7",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 1200,
		.target_residency = 4000,
	},
	{
		.name = "C7S",
		.flags = MWAIT2flg(0x64) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 10000,
		.target_residency = 20000,
	},
	{}
};

static const struct cpuidle_state cht_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C6N",
		.flags = MWAIT2flg(0x58) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 80,
		.target_residency = 275,
	},
	{
		.name = "C6S",
		.flags = MWAIT2flg(0x52) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 200,
		.target_residency = 560,
	},
	{
		.name = "C7",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 1200,
		.target_residency = 4000,
	},
	{
		.name = "C7S",
		.flags = MWAIT2flg(0x64) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 10000,
		.target_residency = 20000,
	},
	{}
};

static const struct cpuidle_state ivb_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 59,
		.target_residency = 156,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 80,
		.target_residency = 300,
	},
	{
		.name = "C7",
		.flags = MWAIT2flg(0x30) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 87,
		.target_residency = 300,
	},
	{}
};

static const struct cpuidle_state ivt_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 80,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 59,
		.target_residency = 156,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 82,
		.target_residency = 300,
	},
	{}
};

static const struct cpuidle_state ivt_cstates_4s[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 250,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 59,
		.target_residency = 300,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 84,
		.target_residency = 400,
	},
	{}
};

static const struct cpuidle_state ivt_cstates_8s[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 500,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 59,
		.target_residency = 600,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 88,
		.target_residency = 700,
	},
	{}
};

static const struct cpuidle_state hsw_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 33,
		.target_residency = 100,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 133,
		.target_residency = 400,
	},
	{
		.name = "C7s",
		.flags = MWAIT2flg(0x32) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 166,
		.target_residency = 500,
	},
 	{
		.name = "C8",
		.flags = MWAIT2flg(0x40) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 300,
		.target_residency = 900,
	},
	{
		.name = "C9",
		.flags = MWAIT2flg(0x50) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 600,
		.target_residency = 1800,
	},
	{
		.name = "C10",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 2600,
		.target_residency = 7700,
	},
	{}
};

static const struct cpuidle_state bdw_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 40,
		.target_residency = 100,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 133,
		.target_residency = 400,
	},
	{
		.name = "C7s",
		.flags = MWAIT2flg(0x32) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 166,
		.target_residency = 500,
	},
	{
		.name = "C8",
		.flags = MWAIT2flg(0x40) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 300,
		.target_residency = 900,
	},
	{
		.name = "C9",
		.flags = MWAIT2flg(0x50) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 600,
		.target_residency = 1800,
	},
	{
		.name = "C10",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 2600,
		.target_residency = 7700,
	},
	{}
};

static struct cpuidle_state __read_mostly skl_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C3",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 70,
		.target_residency = 100,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED | CPUIDLE_FLAG_IBRS,
		.exit_latency = 85,
		.target_residency = 200,
	},
	{
		.name = "C7s",
		.flags = MWAIT2flg(0x33) | CPUIDLE_FLAG_TLB_FLUSHED | CPUIDLE_FLAG_IBRS,
		.exit_latency = 124,
		.target_residency = 800,
	},
	{
		.name = "C8",
		.flags = MWAIT2flg(0x40) | CPUIDLE_FLAG_TLB_FLUSHED | CPUIDLE_FLAG_IBRS,
		.exit_latency = 200,
		.target_residency = 800,
	},
	{
		.name = "C9",
		.flags = MWAIT2flg(0x50) | CPUIDLE_FLAG_TLB_FLUSHED | CPUIDLE_FLAG_IBRS,
		.exit_latency = 480,
		.target_residency = 5000,
	},
	{
		.name = "C10",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED | CPUIDLE_FLAG_IBRS,
		.exit_latency = 890,
		.target_residency = 5000,
	},
	{}
};

static struct cpuidle_state __read_mostly skx_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00) | CPUIDLE_FLAG_IRQ_ENABLE,
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED | CPUIDLE_FLAG_IBRS,
		.exit_latency = 133,
		.target_residency = 600,
	},
	{}
};

static const struct cpuidle_state icx_cstates[] = {
       {
               .name = "C1",
               .flags = MWAIT2flg(0x00) | CPUIDLE_FLAG_IRQ_ENABLE,
               .exit_latency = 1,
               .target_residency = 1,
       },
       {
               .name = "C1E",
               .flags = MWAIT2flg(0x01),
               .exit_latency = 4,
               .target_residency = 4,
       },
       {
               .name = "C6",
               .flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
               .exit_latency = 170,
               .target_residency = 600,
       },
       {}
};

/*
 * On AlderLake C1 has to be disabled if C1E is enabled, and vice versa.
 * C1E is enabled only if "C1E promotion" bit is set in MSR_IA32_POWER_CTL.
 * But in this case there is effectively no C1, because C1 requests are
 * promoted to C1E. If the "C1E promotion" bit is cleared, then both C1
 * and C1E requests end up with C1, so there is effectively no C1E.
 *
 * By default we enable C1E and disable C1 by marking it with
 * 'CPUIDLE_FLAG_DISABLED'.
 */
static struct cpuidle_state __read_mostly adl_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00) | CPUIDLE_FLAG_DISABLED,
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 2,
		.target_residency = 4,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 220,
		.target_residency = 600,
	},
	{
		.name = "C8",
		.flags = MWAIT2flg(0x40) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 280,
		.target_residency = 800,
	},
	{
		.name = "C10",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 680,
		.target_residency = 2000,
	},
	{}
};

static struct cpuidle_state __read_mostly adl_l_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00) | CPUIDLE_FLAG_DISABLED,
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 2,
		.target_residency = 4,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 170,
		.target_residency = 500,
	},
	{
		.name = "C8",
		.flags = MWAIT2flg(0x40) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 200,
		.target_residency = 600,
	},
	{
		.name = "C10",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 230,
		.target_residency = 700,
	},
	{}
};

static struct cpuidle_state __read_mostly spr_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 1,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 2,
		.target_residency = 4,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 290,
		.target_residency = 800,
	},
	{}
};

static const struct cpuidle_state atom_cstates[] = {
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C2",
		.flags = MWAIT2flg(0x10),
		.exit_latency = 20,
		.target_residency = 80,
	},
	{
		.name = "C4",
		.flags = MWAIT2flg(0x30) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 100,
		.target_residency = 400,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x52) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 140,
		.target_residency = 560,
	},
	{}
};

static const struct cpuidle_state tangier_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 4,
	},
	{
		.name = "C4",
		.flags = MWAIT2flg(0x30) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 100,
		.target_residency = 400,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x52) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 140,
		.target_residency = 560,
	},
	{
		.name = "C7",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 1200,
		.target_residency = 4000,
	},
	{
		.name = "C9",
		.flags = MWAIT2flg(0x64) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 10000,
		.target_residency = 20000,
	},
	{}
};

static const struct cpuidle_state avn_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x51) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 15,
		.target_residency = 45,
	},
	{}
};

static struct cpuidle_state __read_mostly bxt_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 133,
		.target_residency = 133,
	},
	{
		.name = "C7s",
		.flags = MWAIT2flg(0x31) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 155,
		.target_residency = 155,
	},
	{
		.name = "C8",
		.flags = MWAIT2flg(0x40) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 1000,
		.target_residency = 1000,
	},
	{
		.name = "C9",
		.flags = MWAIT2flg(0x50) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 2000,
		.target_residency = 2000,
	},
	{
		.name = "C10",
		.flags = MWAIT2flg(0x60) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 10000,
		.target_residency = 10000,
	},
	{}
};

static const struct cpuidle_state dnv_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 10,
		.target_residency = 20,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 50,
		.target_residency = 500,
	},
	{}
};

/*
 * Note, depending on HW and FW revision, SnowRidge SoC may or may not support
 * C6, and this is indicated in the CPUID mwait leaf.
 */
static const struct cpuidle_state snr_cstates[] = {
	{
		.name = "C1",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 2,
		.target_residency = 2,
	},
	{
		.name = "C1E",
		.flags = MWAIT2flg(0x01),
		.exit_latency = 15,
		.target_residency = 25,
	},
	{
		.name = "C6",
		.flags = MWAIT2flg(0x20) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 130,
		.target_residency = 500,
	},
	{}
};

static void cf_check mwait_idle(void)
{
	unsigned int cpu = smp_processor_id();
	struct cpu_info *info = get_cpu_info();
	struct acpi_processor_power *power = processor_powers[cpu];
	struct acpi_processor_cx *cx = NULL;
	unsigned int next_state;
	u64 before, after;
	u32 exp = 0, pred = 0, irq_traced[4] = { 0 };

	if (max_cstate > 0 && power &&
	    (next_state = cpuidle_current_governor->select(power)) > 0) {
		unsigned int max_state = sched_has_urgent_vcpu() ? ACPI_STATE_C1
								 : max_cstate;

		do {
			cx = &power->states[next_state];
		} while ((cx->type > max_state || (cx->type == max_cstate &&
			  MWAIT_HINT2SUBSTATE(cx->address) > max_csubstate)) &&
			 --next_state);
		if (!next_state)
			cx = NULL;
		else if (tb_init_done)
			menu_get_trace_data(&exp, &pred);
	}
	if (!cx) {
		if (pm_idle_save)
			pm_idle_save();
		else
		{
			spec_ctrl_enter_idle(info);
			safe_halt();
			spec_ctrl_exit_idle(info);
		}
		return;
	}

	cpufreq_dbs_timer_suspend();

	rcu_idle_enter(cpu);
	/* rcu_idle_enter() can raise TIMER_SOFTIRQ. Process it now. */
	process_pending_softirqs();

	/* Interrupts must be disabled for C2 and higher transitions. */
	local_irq_disable();

	if (!cpu_is_haltable(cpu)) {
		local_irq_enable();
		rcu_idle_exit(cpu);
		cpufreq_dbs_timer_resume();
		return;
	}

	if ((cx->type >= 3) && errata_c6_workaround())
		cx = power->safe_state;

	if (cx->ibrs_disable) {
		ASSERT(!cx->irq_enable_early);
		spec_ctrl_enter_idle(info);
	}

#if 0 /* XXX Can we/do we need to do something similar on Xen? */
	/*
	 * leave_mm() to avoid costly and often unnecessary wakeups
	 * for flushing the user TLB's associated with the active mm.
	 */
	if (cpuidle_state_table[].flags & CPUIDLE_FLAG_TLB_FLUSHED)
		leave_mm(cpu);
#endif

	if (!(lapic_timer_reliable_states & (1 << cx->type)))
		lapic_timer_off();

	before = alternative_call(cpuidle_get_tick);
	TRACE_TIME(TRC_PM_IDLE_ENTRY, cx->type, before, exp, pred);

	update_last_cx_stat(power, cx, before);

	if (cx->irq_enable_early)
		local_irq_enable();

	mwait_idle_with_hints(cx->address, MWAIT_ECX_INTERRUPT_BREAK);

	local_irq_disable();

	after = alternative_call(cpuidle_get_tick);

	cstate_restore_tsc();
	trace_exit_reason(irq_traced);

	/* Now back in C0. */
	update_idle_stats(power, cx, before, after);

	if (cx->ibrs_disable)
		spec_ctrl_exit_idle(info);

	local_irq_enable();

	TRACE_TIME(TRC_PM_IDLE_EXIT, cx->type, after,
		   irq_traced[0], irq_traced[1], irq_traced[2], irq_traced[3]);

	if (!(lapic_timer_reliable_states & (1 << cx->type)))
		lapic_timer_on();

	rcu_idle_exit(cpu);
	cpufreq_dbs_timer_resume();

	if ( cpuidle_current_governor->reflect )
		cpuidle_current_governor->reflect(power);
}

static void cf_check auto_demotion_disable(void *dummy)
{
	u64 msr_bits;

	rdmsrl(MSR_PKG_CST_CONFIG_CONTROL, msr_bits);
	msr_bits &= ~(icpu->auto_demotion_disable_flags);
	wrmsrl(MSR_PKG_CST_CONFIG_CONTROL, msr_bits);
}

static void cf_check byt_auto_demotion_disable(void *dummy)
{
	wrmsrl(MSR_CC6_DEMOTION_POLICY_CONFIG, 0);
	wrmsrl(MSR_MC6_DEMOTION_POLICY_CONFIG, 0);
}

static void cf_check c1e_promotion_enable(void *dummy)
{
	uint64_t msr_bits;

	rdmsrl(MSR_IA32_POWER_CTL, msr_bits);
	msr_bits |= 0x2;
	wrmsrl(MSR_IA32_POWER_CTL, msr_bits);
}

static void cf_check c1e_promotion_disable(void *dummy)
{
	u64 msr_bits;

	rdmsrl(MSR_IA32_POWER_CTL, msr_bits);
	msr_bits &= ~0x2;
	wrmsrl(MSR_IA32_POWER_CTL, msr_bits);
}

static const struct idle_cpu idle_cpu_nehalem = {
	.state_table = nehalem_cstates,
	.auto_demotion_disable_flags = NHM_C1_AUTO_DEMOTE | NHM_C3_AUTO_DEMOTE,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_atom = {
	.state_table = atom_cstates,
};

static const struct idle_cpu idle_cpu_tangier = {
	.state_table = tangier_cstates,
};

static const struct idle_cpu idle_cpu_lincroft = {
	.state_table = atom_cstates,
	.auto_demotion_disable_flags = ATM_LNC_C6_AUTO_DEMOTE,
};

static const struct idle_cpu idle_cpu_snb = {
	.state_table = snb_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_byt = {
	.state_table = byt_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
	.byt_auto_demotion_disable_flag = true,
};

static const struct idle_cpu idle_cpu_cht = {
	.state_table = cht_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
	.byt_auto_demotion_disable_flag = true,
};

static const struct idle_cpu idle_cpu_ivb = {
	.state_table = ivb_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_ivt = {
	.state_table = ivt_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_hsw = {
	.state_table = hsw_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_bdw = {
	.state_table = bdw_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_skl = {
	.state_table = skl_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_skx = {
	.state_table = skx_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_icx = {
	.state_table = icx_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static struct idle_cpu __read_mostly idle_cpu_adl = {
	.state_table = adl_cstates,
};

static struct idle_cpu __read_mostly idle_cpu_adl_l = {
	.state_table = adl_l_cstates,
};

static struct idle_cpu __read_mostly idle_cpu_spr = {
	.state_table = spr_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_avn = {
	.state_table = avn_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_bxt = {
	.state_table = bxt_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_dnv = {
	.state_table = dnv_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

static const struct idle_cpu idle_cpu_snr = {
	.state_table = snr_cstates,
	.c1e_promotion = C1E_PROMOTION_DISABLE,
};

#define ICPU(model, cpu) \
	{ X86_VENDOR_INTEL, 6, INTEL_FAM6_ ## model, X86_FEATURE_ALWAYS, \
	  &idle_cpu_ ## cpu}

static const struct x86_cpu_id intel_idle_ids[] __initconstrel = {
	ICPU(NEHALEM_EP,		nehalem),
	ICPU(NEHALEM,			nehalem),
	ICPU(NEHALEM_G,			nehalem),
	ICPU(WESTMERE,			nehalem),
	ICPU(WESTMERE_EP,		nehalem),
	ICPU(NEHALEM_EX,		nehalem),
	ICPU(WESTMERE_EX,		nehalem),
	ICPU(ATOM_BONNELL,		atom),
	ICPU(ATOM_BONNELL_MID,		lincroft),
	ICPU(SANDYBRIDGE,		snb),
	ICPU(SANDYBRIDGE_X,		snb),
	ICPU(ATOM_SALTWELL,		atom),
	ICPU(ATOM_SILVERMONT,		byt),
	ICPU(ATOM_SILVERMONT_MID,	tangier),
	ICPU(ATOM_AIRMONT,		cht),
	ICPU(IVYBRIDGE,			ivb),
	ICPU(IVYBRIDGE_X,		ivt),
	ICPU(HASWELL,			hsw),
	ICPU(HASWELL_X,			hsw),
	ICPU(HASWELL_L,			hsw),
	ICPU(HASWELL_G,			hsw),
	ICPU(ATOM_SILVERMONT_D,		avn),
	ICPU(BROADWELL,			bdw),
	ICPU(BROADWELL_G,		bdw),
	ICPU(BROADWELL_X,		bdw),
	ICPU(BROADWELL_D,		bdw),
	ICPU(SKYLAKE_L,			skl),
	ICPU(SKYLAKE,			skl),
	ICPU(KABYLAKE_L,		skl),
	ICPU(KABYLAKE,			skl),
	ICPU(SKYLAKE_X,			skx),
	ICPU(ICELAKE_X,			icx),
	ICPU(ICELAKE_D,			icx),
	ICPU(ALDERLAKE,			adl),
	ICPU(ALDERLAKE_L,		adl_l),
	ICPU(SAPPHIRERAPIDS_X,		spr),
	ICPU(ATOM_GOLDMONT,		bxt),
	ICPU(ATOM_GOLDMONT_PLUS,	bxt),
	ICPU(ATOM_GOLDMONT_D,		dnv),
	ICPU(ATOM_TREMONT_D,		snr),
	{}
};

/*
 * ivt_idle_state_table_update(void)
 *
 * Tune IVT multi-socket targets
 * Assumption: num_sockets == (max_package_num + 1)
 */
static void __init ivt_idle_state_table_update(void)
{
	/* IVT uses a different table for 1-2, 3-4, and > 4 sockets */
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

/*
 * Translate IRTL (Interrupt Response Time Limit) MSR to usec
 */

static const unsigned int __initconst irtl_ns_units[] = {
	1, 32, 1024, 32768, 1048576, 33554432, 0, 0 };

static unsigned long long __init irtl_2_usec(unsigned long long irtl)
{
	unsigned long long ns;

	if (!irtl)
		return 0;

	ns = irtl_ns_units[(irtl >> 10) & 0x7];

	return (irtl & 0x3FF) * ns / 1000;
}
/*
 * bxt_idle_state_table_update(void)
 *
 * On BXT, we trust the IRTL to show the definitive maximum latency
 * We use the same value for target_residency.
 */
static void __init bxt_idle_state_table_update(void)
{
	unsigned long long msr;
	unsigned int usec;

	rdmsrl(MSR_PKGC6_IRTL, msr);
	usec = irtl_2_usec(msr);
	if (usec) {
		bxt_cstates[2].exit_latency = usec;
		bxt_cstates[2].target_residency = usec;
	}

	rdmsrl(MSR_PKGC7_IRTL, msr);
	usec = irtl_2_usec(msr);
	if (usec) {
		bxt_cstates[3].exit_latency = usec;
		bxt_cstates[3].target_residency = usec;
	}

	rdmsrl(MSR_PKGC8_IRTL, msr);
	usec = irtl_2_usec(msr);
	if (usec) {
		bxt_cstates[4].exit_latency = usec;
		bxt_cstates[4].target_residency = usec;
	}

	rdmsrl(MSR_PKGC9_IRTL, msr);
	usec = irtl_2_usec(msr);
	if (usec) {
		bxt_cstates[5].exit_latency = usec;
		bxt_cstates[5].target_residency = usec;
	}

	rdmsrl(MSR_PKGC10_IRTL, msr);
	usec = irtl_2_usec(msr);
	if (usec) {
		bxt_cstates[6].exit_latency = usec;
		bxt_cstates[6].target_residency = usec;
	}
}

/*
 * sklh_idle_state_table_update(void)
 *
 * On SKL-H (model 0x5e) disable C8 and C9 if:
 * C10 is enabled and SGX disabled
 */
static void __init sklh_idle_state_table_update(void)
{
	u64 msr;

	/* if PC10 disabled via cmdline max_cstate=7 or shallower */
	if (max_cstate <= 7)
		return;

	/* if PC10 not present in CPUID.MWAIT.EDX */
	if ((mwait_substates & (MWAIT_CSTATE_MASK << 28)) == 0)
		return;

	rdmsrl(MSR_PKG_CST_CONFIG_CONTROL, msr);

	/* PC10 is not enabled in PKG C-state limit */
	if ((msr & 0xF) != 8)
		return;

	/* if SGX is present */
	if (boot_cpu_has(X86_FEATURE_SGX)) {
		rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);

		/* if SGX is enabled */
		if (msr & IA32_FEATURE_CONTROL_SGX_ENABLE)
			return;
	}

	skl_cstates[5].flags |= CPUIDLE_FLAG_DISABLED;	/* C8-SKL */
	skl_cstates[6].flags |= CPUIDLE_FLAG_DISABLED;	/* C9-SKL */
}

/*
 * skx_idle_state_table_update - Adjust the Sky Lake/Cascade Lake
 * idle states table.
 */
static void __init skx_idle_state_table_update(void)
{
	unsigned long long msr;

	rdmsrl(MSR_PKG_CST_CONFIG_CONTROL, msr);

	/*
	 * 000b: C0/C1 (no package C-state support)
	 * 001b: C2
	 * 010b: C6 (non-retention)
	 * 011b: C6 (retention)
	 * 111b: No Package C state limits.
	 */
	if ((msr & 0x7) < 2) {
		/*
		 * Uses the CC6 + PC0 latency and 3 times of
		 * latency for target_residency if the PC6
		 * is disabled in BIOS. This is consistent
		 * with how intel_idle driver uses _CST
		 * to set the target_residency.
		 */
		skx_cstates[2].exit_latency = 92;
		skx_cstates[2].target_residency = 276;
	}
}

/*
 * adl_idle_state_table_update - Adjust AlderLake idle states table.
 */
static void __init adl_idle_state_table_update(void)
{
	/* Check if user prefers C1 over C1E. */
	if ((preferred_states_mask & BIT(1, U)) &&
	    !(preferred_states_mask & BIT(2, U))) {
		adl_cstates[0].flags &= ~CPUIDLE_FLAG_DISABLED;
		adl_cstates[1].flags |= CPUIDLE_FLAG_DISABLED;
		adl_l_cstates[0].flags &= ~CPUIDLE_FLAG_DISABLED;
		adl_l_cstates[1].flags |= CPUIDLE_FLAG_DISABLED;

		/* Disable C1E by clearing the "C1E promotion" bit. */
		idle_cpu_adl.c1e_promotion = C1E_PROMOTION_DISABLE;
		idle_cpu_adl_l.c1e_promotion = C1E_PROMOTION_DISABLE;
		return;
	}

	/* Make sure C1E is enabled by default */
	idle_cpu_adl.c1e_promotion = C1E_PROMOTION_ENABLE;
	idle_cpu_adl_l.c1e_promotion = C1E_PROMOTION_ENABLE;
}

/*
 * spr_idle_state_table_update - Adjust Sapphire Rapids idle states table.
 */
static void __init spr_idle_state_table_update(void)
{
	uint64_t msr;

	/*
	 * By default, the C6 state assumes the worst-case scenario of package
	 * C6. However, if PC6 is disabled, we update the numbers to match
	 * core C6.
	 */
	rdmsrl(MSR_PKG_CST_CONFIG_CONTROL, msr);

	/* Limit value 2 and above allow for PC6. */
	if ((msr & 0x7) < 2) {
		spr_cstates[2].exit_latency = 190;
		spr_cstates[2].target_residency = 600;
	}
}

/*
 * mwait_idle_state_table_update()
 *
 * Update the default state_table for this CPU-id
 */
static void __init mwait_idle_state_table_update(void)
{
	switch (boot_cpu_data.x86_model) {
	case INTEL_FAM6_IVYBRIDGE_X:
		ivt_idle_state_table_update();
		break;
	case INTEL_FAM6_ATOM_GOLDMONT:
	case INTEL_FAM6_ATOM_GOLDMONT_PLUS:
		bxt_idle_state_table_update();
		break;
	case INTEL_FAM6_SKYLAKE:
		sklh_idle_state_table_update();
		break;
	case INTEL_FAM6_SKYLAKE_X:
		skx_idle_state_table_update();
		break;
	case INTEL_FAM6_SAPPHIRERAPIDS_X:
		spr_idle_state_table_update();
		break;
	case INTEL_FAM6_ALDERLAKE:
	case INTEL_FAM6_ALDERLAKE_L:
		adl_idle_state_table_update();
		break;
	}
}

static int __init mwait_idle_probe(void)
{
	unsigned int eax, ebx, ecx;
	const struct x86_cpu_id *id = x86_match_cpu(intel_idle_ids);
	const char *str;

	if (!id) {
		pr_debug(PREFIX "does not run on family %d model %d\n",
			 boot_cpu_data.x86, boot_cpu_data.x86_model);
		return -ENODEV;
	}

	if (!boot_cpu_has(X86_FEATURE_MONITOR)) {
		pr_debug(PREFIX "Please enable MWAIT in BIOS SETUP\n");
		return -ENODEV;
	}

	if (boot_cpu_data.cpuid_level < CPUID_MWAIT_LEAF)
		return -ENODEV;

	cpuid(CPUID_MWAIT_LEAF, &eax, &ebx, &ecx, &mwait_substates);

	if (!(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED) ||
	    !(ecx & CPUID5_ECX_INTERRUPT_BREAK) ||
	    !mwait_substates)
		return -ENODEV;

	if (!max_cstate || !opt_mwait_idle) {
		pr_debug(PREFIX "disabled\n");
		return -EPERM;
	}

	pr_debug(PREFIX "MWAIT substates: %#x\n", mwait_substates);

	icpu = id->driver_data;
	cpuidle_state_table = icpu->state_table;

	if (boot_cpu_has(X86_FEATURE_ARAT))
		lapic_timer_reliable_states = LAPIC_TIMER_ALWAYS_RELIABLE;

	pr_debug(PREFIX "v" MWAIT_IDLE_VERSION " model %#x\n",
		 boot_cpu_data.x86_model);

	pr_debug(PREFIX "lapic_timer_reliable_states %#x\n",
		 lapic_timer_reliable_states);

	str = preferred_states;
	if (isdigit(str[0]))
		preferred_states_mask = simple_strtoul(str, &str, 0);
	else if (str[0])
	{
		const char *ss;

		do {
			const struct cpuidle_state *state = icpu->state_table;
			unsigned int bit = 1;

			ss = strchr(str, ',');
			if (!ss)
				ss = strchr(str, '\0');

			for (; state->name[0]; ++state) {
				bit <<= 1;
				if (!cmdline_strcmp(str, state->name)) {
					preferred_states_mask |= bit;
					break;
				}
			}
			if (!state->name[0])
				break;

			str = ss + 1;
		} while (*ss);

		str -= str == ss + 1;
	}
	if (str[0])
		printk("unrecognized \"preferred-cstates=%s\"\n", str);

	mwait_idle_state_table_update();

	return 0;
}

static int cf_check mwait_idle_cpu_init(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu, cstate;
	struct acpi_processor_power *dev = processor_powers[cpu];

	switch (action) {
		int rc;

	default:
		return NOTIFY_DONE;

	case CPU_UP_PREPARE:
		rc = cpuidle_init_cpu(cpu);
		dev = processor_powers[cpu];
		if (!rc && cpuidle_current_governor->enable)
			rc = cpuidle_current_governor->enable(dev);
		return notifier_from_errno(rc);

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

		/* if state marked as disabled, skip it */
		if (cpuidle_state_table[cstate].flags &
		    CPUIDLE_FLAG_DISABLED) {
			printk(XENLOG_DEBUG PREFIX "state %s is disabled\n",
			       cpuidle_state_table[cstate].name);
			continue;
		}

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
		if ((cpuidle_state_table[cstate].flags &
		     CPUIDLE_FLAG_IRQ_ENABLE) &&
		    /* cstate_restore_tsc() needs to be a no-op */
		    boot_cpu_has(X86_FEATURE_NONSTOP_TSC))
			cx->irq_enable_early = true;
		if (cpuidle_state_table[cstate].flags & CPUIDLE_FLAG_IBRS)
			cx->ibrs_disable = true;

		dev->count++;
	}

	if (icpu->auto_demotion_disable_flags)
		on_selected_cpus(cpumask_of(cpu), auto_demotion_disable, NULL, 1);

	if (icpu->byt_auto_demotion_disable_flag)
		on_selected_cpus(cpumask_of(cpu), byt_auto_demotion_disable, NULL, 1);

	switch (icpu->c1e_promotion) {
	case C1E_PROMOTION_DISABLE:
		on_selected_cpus(cpumask_of(cpu), c1e_promotion_disable, NULL, 1);
		break;

	case C1E_PROMOTION_ENABLE:
		on_selected_cpus(cpumask_of(cpu), c1e_promotion_enable, NULL, 1);
		break;

	case C1E_PROMOTION_PRESERVE:
		break;
	}

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
		pm_idle_save = pm_idle;
		pm_idle = mwait_idle;
		dead_idle = acpi_dead_idle;
	}

	return err;
}

/* Helper function for HPET. */
bool __init mwait_pc10_supported(void)
{
	unsigned int ecx, edx, dummy;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
	    !cpu_has_monitor ||
	    boot_cpu_data.cpuid_level < CPUID_MWAIT_LEAF)
		return false;

	cpuid(CPUID_MWAIT_LEAF, &dummy, &dummy, &ecx, &edx);

	return (ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED) &&
	       (ecx & CPUID5_ECX_INTERRUPT_BREAK) &&
	       (edx >> 28);
}
