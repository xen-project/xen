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
#include "x86_mca.h"


/* Machine Check Handler for AMD K8 family series */
void k8_machine_check(struct cpu_user_regs *regs, long error_code)
{
	struct vcpu *vcpu = current;
	struct domain *curdom;
	struct mc_info *mc_data;
	struct mcinfo_global mc_global;
	struct mcinfo_bank mc_info;
	uint64_t status, addrv, miscv, uc;
	uint32_t i;
	unsigned int cpu_nr;
	uint32_t xen_impacted = 0;
#define DOM_NORMAL	0
#define DOM0_TRAP	1
#define DOMU_TRAP	2
#define DOMU_KILLED	4
	uint32_t dom_state = DOM_NORMAL;

	/* This handler runs as interrupt gate. So IPIs from the
	 * polling service routine are defered until we finished.
	 */

        /* Disable interrupts for the _vcpu_. It may not re-scheduled to
	 * an other physical CPU or the impacted process in the guest
	 * continues running with corrupted data, otherwise. */
        vcpu_schedule_lock_irq(vcpu);

	mc_data = x86_mcinfo_getptr();
	cpu_nr = smp_processor_id();
	curdom = vcpu->domain;

	memset(&mc_global, 0, sizeof(mc_global));
	mc_global.common.type = MC_TYPE_GLOBAL;
	mc_global.common.size = sizeof(mc_global);

	mc_global.mc_domid = curdom->domain_id; /* impacted domain */
	mc_global.mc_coreid = vcpu->processor; /* impacted physical cpu */
	BUG_ON(cpu_nr != vcpu->processor);
	mc_global.mc_core_threadid = 0;
	mc_global.mc_vcpuid = vcpu->vcpu_id; /* impacted vcpu */
#if 0 /* TODO: on which socket is this physical core?
         It's not clear to me how to figure this out. */
	mc_global.mc_socketid = ???;
#endif
	mc_global.mc_flags |= MC_FLAG_UNCORRECTABLE;
	rdmsrl(MSR_IA32_MCG_STATUS, mc_global.mc_gstatus);

	/* Quick check, who is impacted */
	xen_impacted = is_idle_domain(curdom);

	/* Dom0 */
	x86_mcinfo_clear(mc_data);
	x86_mcinfo_add(mc_data, &mc_global);

	for (i = 0; i < nr_mce_banks; i++) {
		struct domain *d;

		rdmsrl(MSR_IA32_MC0_STATUS + 4 * i, status);

		if (!(status & MCi_STATUS_VAL))
			continue;

		/* An error happened in this bank.
		 * This is expected to be an uncorrectable error,
		 * since correctable errors get polled.
		 */
		uc = status & MCi_STATUS_UC;

		memset(&mc_info, 0, sizeof(mc_info));
		mc_info.common.type = MC_TYPE_BANK;
		mc_info.common.size = sizeof(mc_info);
		mc_info.mc_bank = i;
		mc_info.mc_status = status;

		addrv = 0;
		if (status & MCi_STATUS_ADDRV) {
			rdmsrl(MSR_IA32_MC0_ADDR + 4 * i, addrv);
			
			d = maddr_get_owner(addrv);
			if (d != NULL)
				mc_info.mc_domid = d->domain_id;
		}

		miscv = 0;
		if (status & MCi_STATUS_MISCV)
			rdmsrl(MSR_IA32_MC0_MISC + 4 * i, miscv);

		mc_info.mc_addr = addrv;
		mc_info.mc_misc = miscv;

		x86_mcinfo_add(mc_data, &mc_info); /* Dom0 */

		if (mc_callback_bank_extended)
			mc_callback_bank_extended(mc_data, i, status);

		/* clear status */
		wrmsrl(MSR_IA32_MC0_STATUS + 4 * i, 0x0ULL);
		wmb();
		add_taint(TAINT_MACHINE_CHECK);
	}

	status = mc_global.mc_gstatus;

	/* clear MCIP or cpu enters shutdown state
	 * in case another MCE occurs. */
	status &= ~MCG_STATUS_MCIP;
	wrmsrl(MSR_IA32_MCG_STATUS, status);
	wmb();

	/* For the details see the discussion "MCE/MCA concept" on xen-devel.
	 * The thread started here:
	 * http://lists.xensource.com/archives/html/xen-devel/2007-05/msg01015.html
	 */

	/* MCG_STATUS_RIPV: 
	 * When this bit is not set, then the instruction pointer onto the stack
	 * to resume at is not valid. If xen is interrupted, then we panic anyway
	 * right below. Otherwise it is up to the guest to figure out if 
	 * guest kernel or guest userland is affected and should kill either
	 * itself or the affected process.
	 */

	/* MCG_STATUS_EIPV:
	 * Evaluation of EIPV is the job of the guest.
	 */

	if (xen_impacted) {
		/* Now we are going to panic anyway. Allow interrupts, so that
		 * printk on serial console can work. */
		vcpu_schedule_unlock_irq(vcpu);

		/* Uh, that means, machine check exception
		 * inside Xen occured. */
		printk("Machine check exception occured in Xen.\n");

		/* if MCG_STATUS_EIPV indicates, the IP on the stack is related
		 * to the error then it makes sense to print a stack trace.
		 * That can be useful for more detailed error analysis and/or
		 * error case studies to figure out, if we can clear
		 * xen_impacted and kill a DomU instead
		 * (i.e. if a guest only control structure is affected, but then
		 * we must ensure the bad pages are not re-used again).
		 */
		if (status & MCG_STATUS_EIPV) {
			printk("MCE: Instruction Pointer is related to the error. "
				"Therefore, print the execution state.\n");
			show_execution_state(regs);
		}
		x86_mcinfo_dump(mc_data);
		mc_panic("End of MCE. Use mcelog to decode above error codes.\n");
	}

	/* If Dom0 registered a machine check handler, which is only possible
	 * with a PV MCA driver, then ... */
	if ( guest_has_trap_callback(dom0, 0, TRAP_machine_check) ) {
		dom_state = DOM0_TRAP;

		/* ... deliver machine check trap to Dom0. */
		send_guest_trap(dom0, 0, TRAP_machine_check);

		/* Xen may tell Dom0 now to notify the DomU.
		 * But this will happen through a hypercall. */
	} else
		/* Dom0 did not register a machine check handler, but if DomU
		 * did so, then... */
                if ( guest_has_trap_callback(curdom, vcpu->vcpu_id, TRAP_machine_check) ) {
			dom_state = DOMU_TRAP;

			/* ... deliver machine check trap to DomU */
			send_guest_trap(curdom, vcpu->vcpu_id, TRAP_machine_check);
	} else {
		/* hmm... noone feels responsible to handle the error.
		 * So, do a quick check if a DomU is impacted or not.
		 */
		if (curdom == dom0) {
			/* Dom0 is impacted. Since noone can't handle
			 * this error, panic! */
			x86_mcinfo_dump(mc_data);
			mc_panic("MCE occured in Dom0, which it can't handle\n");

			/* UNREACHED */
		} else {
			dom_state = DOMU_KILLED;

			/* Enable interrupts. This basically results in
			 * calling sti on the *physical* cpu. But after
			 * domain_crash() the vcpu pointer is invalid.
			 * Therefore, we must unlock the irqs before killing
			 * it. */
			vcpu_schedule_unlock_irq(vcpu);

			/* DomU is impacted. Kill it and continue. */
			domain_crash(curdom);
		}
	}


	switch (dom_state) {
	case DOM0_TRAP:
	case DOMU_TRAP:
		/* Enable interrupts. */
		vcpu_schedule_unlock_irq(vcpu);

		/* guest softirqs and event callbacks are scheduled
		 * immediately after this handler exits. */
		break;
	case DOMU_KILLED:
		/* Nothing to do here. */
		break;
	default:
		BUG();
	}
}


/* AMD K8 machine check */
void amd_k8_mcheck_init(struct cpuinfo_x86 *c)
{
	uint64_t value;
	uint32_t i;
	int cpu_nr;

	machine_check_vector = k8_machine_check;
	cpu_nr = smp_processor_id();
	wmb();

	rdmsrl(MSR_IA32_MCG_CAP, value);
	if (value & MCG_CTL_P)	/* Control register present ? */
		wrmsrl (MSR_IA32_MCG_CTL, 0xffffffffffffffffULL);
	nr_mce_banks = value & MCG_CAP_COUNT;

	for (i = 0; i < nr_mce_banks; i++) {
		switch (i) {
		case 4: /* Northbridge */
			/* Enable error reporting of all errors,
			 * enable error checking and
			 * disable sync flooding */
			wrmsrl(MSR_IA32_MC4_CTL, 0x02c3c008ffffffffULL);
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
}
