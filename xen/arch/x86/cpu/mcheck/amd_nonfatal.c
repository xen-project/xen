/*
 * MCA implementation for AMD CPUs
 * Copyright (c) 2007 Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */


/* K8 common MCA documentation published at
 *
 * AMD64 Architecture Programmer's Manual Volume 2:
 * System Programming
 * Publication # 24593 Revision: 3.12
 * Issue Date: September 2006
 *
 * URL:
 * http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/24593.pdf
 */

/* The related documentation for K8 Revisions A - E is:
 *
 * BIOS and Kernel Developer's Guide for
 * AMD Athlon 64 and AMD Opteron Processors
 * Publication # 26094 Revision: 3.30
 * Issue Date: February 2006
 *
 * URL:
 * http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/26094.PDF
 */

/* The related documentation for K8 Revisions F - G is:
 *
 * BIOS and Kernel Developer's Guide for
 * AMD NPT Family 0Fh Processors
 * Publication # 32559 Revision: 3.04
 * Issue Date: December 2006
 *
 * URL:
 * http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/32559.pdf
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/smp.h>
#include <xen/timer.h>
#include <xen/event.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"
#include "vmce.h"

static struct timer mce_timer;

#define MCE_PERIOD MILLISECS(10000)
#define MCE_MIN    MILLISECS(2000)
#define MCE_MAX    MILLISECS(30000)

static s_time_t period = MCE_PERIOD;
static int hw_threshold = 0;
static int adjust = 0;
static int variable_period = 1;

/* The polling service routine:
 * Collects information of correctable errors and notifies
 * Dom0 via an event.
 */
static void mce_amd_checkregs(void *info)
{
	mctelem_cookie_t mctc;
	struct mca_summary bs;

	mctc = mcheck_mca_logout(MCA_POLLER, mca_allbanks, &bs, NULL);

	if (bs.errcnt && mctc != NULL) {
		static uint64_t dumpcount = 0;

		/* If Dom0 enabled the VIRQ_MCA event, then notify it.
		 * Otherwise, if dom0 has had plenty of time to register
		 * the virq handler but still hasn't then dump telemetry
		 * to the Xen console.  The call count may be incremented
		 * on multiple cpus at once and is indicative only - just
		 * a simple-minded attempt to avoid spamming the console
		 * for corrected errors in early startup. */

		if (dom0_vmce_enabled()) {
			mctelem_commit(mctc);
			send_global_virq(VIRQ_MCA);
		} else if (++dumpcount >= 10) {
			x86_mcinfo_dump((struct mc_info *)mctelem_dataptr(mctc));
			mctelem_dismiss(mctc);
		} else {
			mctelem_dismiss(mctc);
		}

	} else if (mctc != NULL) {
		mctelem_dismiss(mctc);
	}

	/* adjust is global and all cpus may attempt to increment it without
	 * synchronisation, so they race and the final adjust count
	 * (number of cpus seeing any error) is approximate.  We can
	 * guarantee that if any cpu observes an error that the
	 * adjust count is at least 1. */
	if (bs.errcnt)
		adjust++;
}

/* polling service routine invoker:
 * Adjust poll frequency at runtime. No error means slow polling frequency,
 * an error means higher polling frequency.
 * It uses hw threshold register introduced in AMD K8 RevF to detect
 * multiple correctable errors between two polls. In that case,
 * increase polling frequency higher than normal.
 */
static void mce_amd_work_fn(void *data)
{
	on_each_cpu(mce_amd_checkregs, data, 1);

	if (adjust > 0) {
		if (!dom0_vmce_enabled()) {
			/* Dom0 did not enable VIRQ_MCA, so Xen is reporting. */
			printk("MCE: polling routine found correctable error. "
				" Use mcelog to parse above error output.\n");
		}
	}

	if (hw_threshold) {
		uint64_t value;
		uint32_t counter;

		value = mca_rdmsr(MSR_IA32_MCx_MISC(4));
		/* Only the error counter field is of interest
		 * Bit field is described in AMD K8 BKDG chapter 6.4.5.5
		 */
		counter = (value & 0xFFF00000000ULL) >> 32U;

		/* HW does not count *all* kinds of correctable errors.
		 * Thus it is possible, that the polling routine finds an
		 * correctable error even if the HW reports nothing. */
		if (counter > 0) {
			/* HW reported correctable errors,
			 * the polling routine did not find...
			 */
			if (adjust == 0) {
				printk("CPU counter reports %"PRIu32
					" correctable hardware error%s that %s"
					" not reported by the status MSRs\n",
					counter,
					(counter == 1 ? "" : "s"),
					(counter == 1 ? "was" : "were"));
			}
			/* subtract 1 to not double count the error
			 * from the polling service routine */
			adjust += (counter - 1);

			/* Restart counter */
			/* No interrupt, reset counter value */
			value &= ~(0x60FFF00000000ULL);
			/* Counter enable */
			value |= (1ULL << 51);
			mca_wrmsr(MSR_IA32_MCx_MISC(4), value);
		}
	}

	if (variable_period && adjust > 0) {
		/* Increase polling frequency */
		adjust++; /* adjust == 1 must have an effect */
		period /= adjust;
	} else if (variable_period) {
		/* Decrease polling frequency */
		period *= 2;
	}
	if (variable_period && period > MCE_MAX) {
		/* limit: Poll at least every 30s */
		period = MCE_MAX;
	}
	if (variable_period && period < MCE_MIN) {
		/* limit: Poll every 2s.
		 * When this is reached an uncorrectable error
		 * is expected to happen, if Dom0 does nothing.
		 */
		period = MCE_MIN;
	}

	set_timer(&mce_timer, NOW() + period);
	adjust = 0;
}

void __init amd_nonfatal_mcheck_init(struct cpuinfo_x86 *c)
{
	if (c->x86_vendor != X86_VENDOR_AMD)
		return;

	/* Assume we are on K8 or newer AMD CPU here */

	/* The threshold bitfields in MSR_IA32_MC4_MISC has
	 * been introduced along with the SVME feature bit. */
	if (variable_period && cpu_has(c, X86_FEATURE_SVM)) {
		uint64_t value;

		/* hw threshold registers present */
		hw_threshold = 1;
		rdmsrl(MSR_IA32_MCx_MISC(4), value);

		if (value & (1ULL << 61)) { /* Locked bit */
			/* Locked by BIOS. Not available for use */
			hw_threshold = 0;
		}
		if (!(value & (1ULL << 63))) { /* Valid bit */
			/* No CtrP present */
			hw_threshold = 0;
		} else {
			if (!(value & (1ULL << 62))) { /* Counter Bit */
				/* No counter field present */
				hw_threshold = 0;
			}
		}

		if (hw_threshold) {
			/* No interrupt, reset counter value */
			value &= ~(0x60FFF00000000ULL);
			/* Counter enable */
			value |= (1ULL << 51);
			wrmsrl(MSR_IA32_MCx_MISC(4), value);
			printk(XENLOG_INFO "MCA: Use hw thresholding to adjust polling frequency\n");
		}
	}

	init_timer(&mce_timer, mce_amd_work_fn, NULL, 0);
	set_timer(&mce_timer, NOW() + period);
}
