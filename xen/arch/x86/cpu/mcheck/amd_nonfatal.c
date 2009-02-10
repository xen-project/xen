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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include <xen/config.h>
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
#include "x86_mca.h"

static struct timer mce_timer;

#define MCE_PERIOD MILLISECS(15000)
#define MCE_MIN    MILLISECS(2000)
#define MCE_MAX    MILLISECS(30000)

static s_time_t period = MCE_PERIOD;
static int hw_threshold = 0;
static int adjust = 0;

/* The polling service routine:
 * Collects information of correctable errors and notifies
 * Dom0 via an event.
 */
void mce_amd_checkregs(void *info)
{
	struct vcpu *vcpu = current;
	struct mc_info *mc_data;
	struct mcinfo_global mc_global;
	struct mcinfo_bank mc_info;
	uint64_t status, addrv, miscv;
	unsigned int i;
	unsigned int event_enabled;
	unsigned int cpu_nr;
	int error_found;

	/* We don't need a slot yet. Only allocate one on error. */
	mc_data = NULL;

	cpu_nr = smp_processor_id();
	BUG_ON(cpu_nr != vcpu->processor);
	event_enabled = guest_enabled_event(dom0->vcpu[0], VIRQ_MCA);
	error_found = 0;

	memset(&mc_global, 0, sizeof(mc_global));
	mc_global.common.type = MC_TYPE_GLOBAL;
	mc_global.common.size = sizeof(mc_global);

	mc_global.mc_domid = vcpu->domain->domain_id; /* impacted domain */
	mc_global.mc_vcpuid = vcpu->vcpu_id; /* impacted vcpu */

	x86_mc_get_cpu_info(cpu_nr, &mc_global.mc_socketid,
	    &mc_global.mc_coreid, &mc_global.mc_core_threadid,
	    &mc_global.mc_apicid, NULL, NULL, NULL);

	mc_global.mc_flags |= MC_FLAG_CORRECTABLE;
	rdmsrl(MSR_IA32_MCG_STATUS, mc_global.mc_gstatus);

	for (i = 0; i < nr_mce_banks; i++) {
		struct domain *d;

		rdmsrl(MSR_IA32_MC0_STATUS + i * 4, status);

		if (!(status & MCi_STATUS_VAL))
			continue;

		if (mc_data == NULL) {
			/* Now we need a slot to fill in error telemetry. */
			mc_data = x86_mcinfo_getptr();
			BUG_ON(mc_data == NULL);
			x86_mcinfo_clear(mc_data);
			x86_mcinfo_add(mc_data, &mc_global);
		}

		memset(&mc_info, 0, sizeof(mc_info));
		mc_info.common.type = MC_TYPE_BANK;
		mc_info.common.size = sizeof(mc_info);
		mc_info.mc_bank = i;
		mc_info.mc_status = status;

		/* Increase polling frequency */
		error_found = 1;

		addrv = 0;
		if (status & MCi_STATUS_ADDRV) {
			rdmsrl(MSR_IA32_MC0_ADDR + i * 4, addrv);

			d = maddr_get_owner(addrv);
			if (d != NULL)
				mc_info.mc_domid = d->domain_id;
		}

		miscv = 0;
		if (status & MCi_STATUS_MISCV)
			rdmsrl(MSR_IA32_MC0_MISC + i * 4, miscv);

		mc_info.mc_addr = addrv;
		mc_info.mc_misc = miscv;
		x86_mcinfo_add(mc_data, &mc_info);

		if (mc_callback_bank_extended)
			mc_callback_bank_extended(mc_data, i, status);

		/* clear status */
		wrmsrl(MSR_IA32_MC0_STATUS + i * 4, 0x0ULL);
		wmb();
	}

	if (error_found > 0) {
		/* If Dom0 enabled the VIRQ_MCA event, then ... */
		if (event_enabled)
			/* ... notify it. */
			send_guest_global_virq(dom0, VIRQ_MCA);
		else
			/* ... or dump it */
			x86_mcinfo_dump(mc_data);
	}

	adjust += error_found;
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
	on_each_cpu(mce_amd_checkregs, data, 1, 1);

	if (adjust > 0) {
		if ( !guest_enabled_event(dom0->vcpu[0], VIRQ_MCA) ) {
			/* Dom0 did not enable VIRQ_MCA, so Xen is reporting. */
			printk("MCE: polling routine found correctable error. "
				" Use mcelog to parse above error output.\n");
		}
	}

	if (hw_threshold) {
		uint64_t value;
		uint32_t counter;

		rdmsrl(MSR_IA32_MC4_MISC, value);
		/* Only the error counter field is of interest
		 * Bit field is described in AMD K8 BKDG chapter 6.4.5.5
		 */
		counter = (value & 0xFFF00000000ULL) >> 32U;

		/* HW does not count *all* kinds of correctable errors.
		 * Thus it is possible, that the polling routine finds an
		 * correctable error even if the HW reports nothing.
		 * However, the other way around is not possible (= BUG).
		 */ 
		if (counter > 0) {
			/* HW reported correctable errors,
			 * the polling routine did not find...
			 */
			BUG_ON(adjust == 0);
			/* subtract 1 to not double count the error 
			 * from the polling service routine */ 
			adjust += (counter - 1);

			/* Restart counter */
			/* No interrupt, reset counter value */
			value &= ~(0x60FFF00000000ULL);
			/* Counter enable */
			value |= (1ULL << 51);
			wrmsrl(MSR_IA32_MC4_MISC, value);
			wmb();
		}
	}

	if (adjust > 0) {
		/* Increase polling frequency */
		adjust++; /* adjust == 1 must have an effect */
		period /= adjust;
	} else {
		/* Decrease polling frequency */
		period *= 2;
	}
	if (period > MCE_MAX) {
		/* limit: Poll at least every 30s */
		period = MCE_MAX;
	}
	if (period < MCE_MIN) {
		/* limit: Poll every 2s.
		 * When this is reached an uncorrectable error
		 * is expected to happen, if Dom0 does nothing.
		 */
		period = MCE_MIN;
	}

	set_timer(&mce_timer, NOW() + period);
	adjust = 0;
}

void amd_nonfatal_mcheck_init(struct cpuinfo_x86 *c)
{
	if (c->x86_vendor != X86_VENDOR_AMD)
		return;

	/* Assume we are on K8 or newer AMD CPU here */

	/* The threshold bitfields in MSR_IA32_MC4_MISC has
	 * been introduced along with the SVME feature bit. */
	if (cpu_has(c, X86_FEATURE_SVME)) {
		uint64_t value;

		/* hw threshold registers present */
		hw_threshold = 1;
		rdmsrl(MSR_IA32_MC4_MISC, value);

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
			wrmsrl(MSR_IA32_MC4_MISC, value);
			/* serialize */
			wmb();
			printk(XENLOG_INFO "MCA: Use hw thresholding to adjust polling frequency\n");
		}
	}

	init_timer(&mce_timer, mce_amd_work_fn, NULL, 0);
	set_timer(&mce_timer, NOW() + period);

	return;
}
