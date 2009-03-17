/*
 * MCA implementation for AMD K8 CPUs
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
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>

#include <asm/processor.h>
#include <asm/shared.h>
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"


/* Machine Check Handler for AMD K8 family series */
void k8_machine_check(struct cpu_user_regs *regs, long error_code)
{
	mcheck_cmn_handler(regs, error_code, mca_allbanks);
}

/* AMD K8 machine check */
int amd_k8_mcheck_init(struct cpuinfo_x86 *c)
{
	uint64_t value;
	uint32_t i;
	int cpu_nr;

	/* Check for PPro style MCA; our caller has confirmed MCE support. */
	if (!cpu_has(c, X86_FEATURE_MCA))
		return 0;

	x86_mce_vector_register(k8_machine_check);
	cpu_nr = smp_processor_id();

	rdmsrl(MSR_IA32_MCG_CAP, value);
	if (value & MCG_CTL_P)	/* Control register present ? */
		wrmsrl (MSR_IA32_MCG_CTL, 0xffffffffffffffffULL);
	nr_mce_banks = value & MCG_CAP_COUNT;

	for (i = 0; i < nr_mce_banks; i++) {
		switch (i) {
		case 4: /* Northbridge */
			/* Enable error reporting of all errors */
			wrmsrl(MSR_IA32_MC4_CTL, 0xffffffffffffffffULL);
			wrmsrl(MSR_IA32_MC4_STATUS, 0x0ULL);
			break;

		default:
			/* Enable error reporting of all errors */
			wrmsrl(MSR_IA32_MC0_CTL + 4 * i, 0xffffffffffffffffULL);
			wrmsrl(MSR_IA32_MC0_STATUS + 4 * i, 0x0ULL);
			break;
		}
	}

	set_in_cr4(X86_CR4_MCE);
	printk("CPU%i: AMD K8 machine check reporting enabled.\n", cpu_nr);

	return 1;
}
