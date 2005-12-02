/*
 * Hypercall implementations
 * 
 * Copyright (C) 2005 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <xen/config.h>
#include <xen/sched.h>

#include <linux/efi.h>	/* FOR EFI_UNIMPLEMENTED */
#include <asm/sal.h>	/* FOR struct ia64_sal_retval */

#include <asm/vcpu.h>
#include <asm/dom_fw.h>
#include <public/memory.h>
#include <public/sched.h>

extern unsigned long translate_domain_mpaddr(unsigned long);

unsigned long idle_when_pending = 0;
unsigned long pal_halt_light_count = 0;

int
ia64_hypercall (struct pt_regs *regs)
{
	struct vcpu *v = (struct domain *) current;
	struct sal_ret_values x;
	unsigned long *tv, *tc;
	int pi;

	switch (regs->r2) {
	    case FW_HYPERCALL_PAL_CALL:
		//printf("*** PAL hypercall: index=%d\n",regs->r28);
		//FIXME: This should call a C routine
#if 0
		// This is very conservative, but avoids a possible
		// (and deadly) freeze in paravirtualized domains due
		// to a yet-to-be-found bug where pending_interruption
		// is zero when it shouldn't be. Since PAL is called
		// in the idle loop, this should resolve it
		VCPU(v,pending_interruption) = 1;
#endif
		if (regs->r28 == PAL_HALT_LIGHT) {
#define SPURIOUS_VECTOR 15
			pi = vcpu_check_pending_interrupts(v);
			if (pi != SPURIOUS_VECTOR) {
				if (!VCPU(v,pending_interruption))
					idle_when_pending++;
				vcpu_pend_unspecified_interrupt(v);
//printf("idle w/int#%d pending!\n",pi);
//this shouldn't happen, but it apparently does quite a bit!  so don't
//allow it to happen... i.e. if a domain has an interrupt pending and
//it tries to halt itself because it thinks it is idle, just return here
//as deliver_pending_interrupt is called on the way out and will deliver it
			}
			else {
				pal_halt_light_count++;
				do_sched_op(SCHEDOP_yield);
			}
			regs->r8 = 0;
			regs->r9 = 0;
			regs->r10 = 0;
			regs->r11 = 0;
		}
		else {
			struct ia64_pal_retval y;

			if (regs->r28 >= PAL_COPY_PAL)
				y = xen_pal_emulator
					(regs->r28, vcpu_get_gr (v, 33),
					 vcpu_get_gr (v, 34),
					 vcpu_get_gr (v, 35));
			else
				y = xen_pal_emulator(regs->r28,regs->r29,
						     regs->r30,regs->r31);
			regs->r8 = y.status; regs->r9 = y.v0;
			regs->r10 = y.v1; regs->r11 = y.v2;
		}
		break;
	    case FW_HYPERCALL_SAL_CALL:
		x = sal_emulator(vcpu_get_gr(v,32),vcpu_get_gr(v,33),
			vcpu_get_gr(v,34),vcpu_get_gr(v,35),
			vcpu_get_gr(v,36),vcpu_get_gr(v,37),
			vcpu_get_gr(v,38),vcpu_get_gr(v,39));
		regs->r8 = x.r8; regs->r9 = x.r9;
		regs->r10 = x.r10; regs->r11 = x.r11;
		break;
	    case FW_HYPERCALL_EFI_RESET_SYSTEM:
		printf("efi.reset_system called ");
		if (current->domain == dom0) {
			printf("(by dom0)\n ");
			(*efi.reset_system)(EFI_RESET_WARM,0,0,NULL);
		}
#ifdef DOMU_AUTO_RESTART
		else {
			reconstruct_domU(current);
			return 0;  // don't increment ip!
		}
#else	
		printf("(not supported for non-0 domain)\n");
		regs->r8 = EFI_UNSUPPORTED;
#endif
		break;
	    case FW_HYPERCALL_EFI_GET_TIME:
		tv = vcpu_get_gr(v,32);
		tc = vcpu_get_gr(v,33);
		//printf("efi_get_time(%p,%p) called...",tv,tc);
		tv = __va(translate_domain_mpaddr(tv));
		if (tc) tc = __va(translate_domain_mpaddr(tc));
		regs->r8 = (*efi.get_time)(tv,tc);
		//printf("and returns %lx\n",regs->r8);
		break;
	    case FW_HYPERCALL_EFI_SET_TIME:
	    case FW_HYPERCALL_EFI_GET_WAKEUP_TIME:
	    case FW_HYPERCALL_EFI_SET_WAKEUP_TIME:
		// FIXME: need fixes in efi.h from 2.6.9
	    case FW_HYPERCALL_EFI_SET_VIRTUAL_ADDRESS_MAP:
		// FIXME: WARNING!! IF THIS EVER GETS IMPLEMENTED
		// SOME OF THE OTHER EFI EMULATIONS WILL CHANGE AS 
		// POINTER ARGUMENTS WILL BE VIRTUAL!!
	    case FW_HYPERCALL_EFI_GET_VARIABLE:
		// FIXME: need fixes in efi.h from 2.6.9
	    case FW_HYPERCALL_EFI_GET_NEXT_VARIABLE:
	    case FW_HYPERCALL_EFI_SET_VARIABLE:
	    case FW_HYPERCALL_EFI_GET_NEXT_HIGH_MONO_COUNT:
		// FIXME: need fixes in efi.h from 2.6.9
		regs->r8 = EFI_UNSUPPORTED;
		break;
	    case 0xffff:
		regs->r8 = dump_privop_counts_to_user(
			vcpu_get_gr(v,32),
			vcpu_get_gr(v,33));
		break;
	    case 0xfffe:
		regs->r8 = zero_privop_counts_to_user(
			vcpu_get_gr(v,32),
			vcpu_get_gr(v,33));
		break;
	    case __HYPERVISOR_dom0_op:
		regs->r8 = do_dom0_op(regs->r14);
		break;

	    case __HYPERVISOR_memory_op:
		/* we don't handle reservations; just return success */
		{
		    struct xen_memory_reservation reservation;
		    void *arg = regs->r15;

		    switch(regs->r14) {
		    case XENMEM_increase_reservation:
		    case XENMEM_decrease_reservation:
			if (copy_from_user(&reservation, arg,
				sizeof(reservation)))
			    regs->r8 = -EFAULT;
			else
			    regs->r8 = reservation.nr_extents;
			break;
		    default:
			regs->r8 = do_memory_op(regs->r14, regs->r15);
			break;
		    }
		}
		break;

	    case __HYPERVISOR_event_channel_op:
		regs->r8 = do_event_channel_op(regs->r14);
		break;

	    case __HYPERVISOR_grant_table_op:
		regs->r8 = do_grant_table_op(regs->r14, regs->r15, regs->r16);
		break;

	    case __HYPERVISOR_console_io:
		regs->r8 = do_console_io(regs->r14, regs->r15, regs->r16);
		break;

	    case __HYPERVISOR_xen_version:
		regs->r8 = do_xen_version(regs->r14, regs->r15);
		break;

	    default:
		printf("unknown hypercall %x\n", regs->r2);
		regs->r8 = (unsigned long)-1;
	}
	return 1;
}
