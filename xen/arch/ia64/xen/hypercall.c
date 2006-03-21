/*
 * Hypercall implementations
 * 
 * Copyright (C) 2005 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/hypercall.h>
#include <xen/multicall.h>
#include <xen/guest_access.h>

#include <linux/efi.h>	/* FOR EFI_UNIMPLEMENTED */
#include <asm/sal.h>	/* FOR struct ia64_sal_retval */

#include <asm/vcpu.h>
#include <asm/dom_fw.h>
#include <public/dom0_ops.h>
#include <public/event_channel.h>
#include <public/memory.h>
#include <public/sched.h>

extern unsigned long translate_domain_mpaddr(unsigned long);
/* FIXME: where these declarations should be there ? */
extern int dump_privop_counts_to_user(char *, int);
extern int zero_privop_counts_to_user(char *, int);

unsigned long idle_when_pending = 0;
unsigned long pal_halt_light_count = 0;

hypercall_t ia64_hypercall_table[] =
	{
	(hypercall_t)do_ni_hypercall,		/* do_set_trap_table */		/*  0 */
	(hypercall_t)do_ni_hypercall,		/* do_mmu_update */
	(hypercall_t)do_ni_hypercall,		/* do_set_gdt */
	(hypercall_t)do_ni_hypercall,		/* do_stack_switch */
	(hypercall_t)do_ni_hypercall,		/* do_set_callbacks */
	(hypercall_t)do_ni_hypercall,		/* do_fpu_taskswitch */		/*  5 */
	(hypercall_t)do_ni_hypercall,		/* do_sched_op */
	(hypercall_t)do_dom0_op,
	(hypercall_t)do_ni_hypercall,		/* do_set_debugreg */
	(hypercall_t)do_ni_hypercall,		/* do_get_debugreg */
	(hypercall_t)do_ni_hypercall,		/* do_update_descriptor */	/* 10 */
	(hypercall_t)do_ni_hypercall,		/* do_ni_hypercall */
	(hypercall_t)do_memory_op,
	(hypercall_t)do_multicall,
	(hypercall_t)do_ni_hypercall,		/* do_update_va_mapping */
	(hypercall_t)do_ni_hypercall,		/* do_set_timer_op */		/* 15 */
	(hypercall_t)do_event_channel_op,
	(hypercall_t)do_xen_version,
	(hypercall_t)do_console_io,
	(hypercall_t)do_ni_hypercall,           /* do_physdev_op */
	(hypercall_t)do_grant_table_op,						/* 20 */
	(hypercall_t)do_ni_hypercall,		/* do_vm_assist */
	(hypercall_t)do_ni_hypercall,		/* do_update_va_mapping_otherdomain */
	(hypercall_t)do_ni_hypercall,		/* (x86 only) */
	(hypercall_t)do_ni_hypercall,		/* do_vcpu_op */
	(hypercall_t)do_ni_hypercall,		/* (x86_64 only) */		/* 25 */
	(hypercall_t)do_ni_hypercall,		/* do_mmuext_op */
	(hypercall_t)do_ni_hypercall,		/* do_acm_op */
	(hypercall_t)do_ni_hypercall,		/* do_nmi_op */
	(hypercall_t)do_ni_hypercall,		/*  */
	(hypercall_t)do_ni_hypercall,		/*  */				/* 30 */
	(hypercall_t)do_ni_hypercall		/*  */
	};

static int
xen_hypercall (struct pt_regs *regs)
{
	switch (regs->r2) {
	    case __HYPERVISOR_dom0_op:
		regs->r8 = do_dom0_op(guest_handle_from_ptr(regs->r14,
							    dom0_op_t));
		break;

	    case __HYPERVISOR_memory_op:
		/* we don't handle reservations; just return success */
		{
		    struct xen_memory_reservation reservation;
		    void *arg = (void *) regs->r15;

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
			regs->r8 = do_memory_op((int) regs->r14, guest_handle_from_ptr(regs->r15, void));
			break;
		    }
		}
		break;

	    case __HYPERVISOR_event_channel_op:
		regs->r8 = do_event_channel_op(guest_handle_from_ptr(regs->r14, evtchn_op_t));
		break;

	    case __HYPERVISOR_grant_table_op:
		regs->r8 = do_grant_table_op((unsigned int) regs->r14, guest_handle_from_ptr(regs->r15, void), (unsigned int) regs->r16);
		break;

	    case __HYPERVISOR_console_io:
		regs->r8 = do_console_io((int) regs->r14, (int) regs->r15, guest_handle_from_ptr(regs->r16, char));
		break;

	    case __HYPERVISOR_xen_version:
		regs->r8 = do_xen_version((int) regs->r14, guest_handle_from_ptr(regs->r15, void));
		break;

	    case __HYPERVISOR_multicall:
		regs->r8 = do_multicall(guest_handle_from_ptr(regs->r14, multicall_entry_t), (unsigned int) regs->r15);
		break;

	    default:
		printf("unknown xen hypercall %lx\n", regs->r2);
		regs->r8 = do_ni_hypercall();
	}
	return 1;
}


static int
fw_hypercall (struct pt_regs *regs)
{
	struct vcpu *v = current;
	struct sal_ret_values x;
	unsigned long *tv, *tc;

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
			int pi;
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
				do_sched_op(SCHEDOP_yield, 0);
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
		else
			domain_shutdown (current->domain, SHUTDOWN_reboot);
		regs->r8 = EFI_UNSUPPORTED;
		break;
	    case FW_HYPERCALL_EFI_GET_TIME:
		tv = (unsigned long *) vcpu_get_gr(v,32);
		tc = (unsigned long *) vcpu_get_gr(v,33);
		//printf("efi_get_time(%p,%p) called...",tv,tc);
		tv = (unsigned long *) __va(translate_domain_mpaddr((unsigned long) tv));
		if (tc) tc = (unsigned long *) __va(translate_domain_mpaddr((unsigned long) tc));
		regs->r8 = (*efi.get_time)((efi_time_t *) tv, (efi_time_cap_t *) tc);
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
	    default:
		printf("unknown ia64 fw hypercall %lx\n", regs->r2);
		regs->r8 = do_ni_hypercall();
	}
	return 1;
}

/* opt_unsafe_hypercall: If true, unsafe debugging hypercalls are allowed.
   These can create security hole.  */
static int opt_unsafe_hypercall = 0;
boolean_param("unsafe_hypercall", opt_unsafe_hypercall);

int
ia64_hypercall (struct pt_regs *regs)
{
	struct vcpu *v = current;
	unsigned long index = regs->r2;
	int privlvl = (regs->cr_ipsr & IA64_PSR_CPL) >> IA64_PSR_CPL0_BIT;

	if (index >= FW_HYPERCALL_FIRST_USER) {
	    /* Note: user hypercalls are not safe, since Xen doesn't
	       check memory access privilege: Xen does not deny reading
	       or writing to kernel memory.  */
	    if (!opt_unsafe_hypercall) {
		printf("user xen/ia64 hypercalls disabled\n");
		regs->r8 = -1;
	    }
	    else switch (index) {
		case 0xffff:
			regs->r8 = dump_privop_counts_to_user(
				(char *) vcpu_get_gr(v,32),
				(int) vcpu_get_gr(v,33));
			break;
		case 0xfffe:
			regs->r8 = zero_privop_counts_to_user(
				(char *) vcpu_get_gr(v,32),
				(int) vcpu_get_gr(v,33));
			break;
		default:
			printf("unknown user xen/ia64 hypercall %lx\n", index);
			regs->r8 = do_ni_hypercall();
	    }
	    return 1;
	}

	/* Hypercalls are only allowed by kernel.
	   Kernel checks memory accesses.  */
	if (privlvl != 2) {
	    /* FIXME: Return a better error value ?
	       Reflection ? Illegal operation ?  */
	    regs->r8 = -1;
	    return 1;
	}

	if (index >= FW_HYPERCALL_FIRST_ARCH)
	    return fw_hypercall (regs);
	else
	    return xen_hypercall (regs);
}
