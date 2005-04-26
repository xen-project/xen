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

extern unsigned long translate_domain_mpaddr(unsigned long);
extern struct ia64_sal_retval pal_emulator_static(UINT64);
extern struct ia64_sal_retval sal_emulator(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);

void fooefi(void) {}

int
ia64_hypercall (struct pt_regs *regs)
{
	struct exec_domain *ed = (struct domain *) current;
	struct ia64_sal_retval x;
	unsigned long *tv, *tc;

	switch (regs->r2) {
	    case FW_HYPERCALL_PAL_CALL:
		//printf("*** PAL hypercall: index=%d\n",regs->r28);
		//FIXME: This should call a C routine
#if 1
		// This is very conservative, but avoids a possible
		// (and deadly) freeze in paravirtualized domains due
		// to a yet-to-be-found bug where pending_interruption
		// is zero when it shouldn't be. Since PAL is called
		// in the idle loop, this should resolve it
		ed->vcpu_info->arch.pending_interruption = 1;
#endif
		x = pal_emulator_static(regs->r28);
		regs->r8 = x.status; regs->r9 = x.v0;
		regs->r10 = x.v1; regs->r11 = x.v2;
		break;
	    case FW_HYPERCALL_SAL_CALL:
		x = sal_emulator(vcpu_get_gr(ed,32),vcpu_get_gr(ed,33),
			vcpu_get_gr(ed,34),vcpu_get_gr(ed,35),
			vcpu_get_gr(ed,36),vcpu_get_gr(ed,37),
			vcpu_get_gr(ed,38),vcpu_get_gr(ed,39));
		regs->r8 = x.status; regs->r9 = x.v0;
		regs->r10 = x.v1; regs->r11 = x.v2;
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
		tv = vcpu_get_gr(ed,32);
		tc = vcpu_get_gr(ed,33);
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
	    case 0xffff: // test dummy hypercall
		regs->r8 = dump_privop_counts_to_user(
			vcpu_get_gr(ed,32),
			vcpu_get_gr(ed,33));
		break;
	    case 0xfffe: // test dummy hypercall
		regs->r8 = zero_privop_counts_to_user(
			vcpu_get_gr(ed,32),
			vcpu_get_gr(ed,33));
		break;
	    case 0xfffd: // test dummy hypercall
		regs->r8 = launch_domainU(
			vcpu_get_gr(ed,32));
		break;
	    case 0xfffc: // test dummy hypercall
		regs->r8 = domU_staging_write_32(
			vcpu_get_gr(ed,32),
			vcpu_get_gr(ed,33),
			vcpu_get_gr(ed,34),
			vcpu_get_gr(ed,35),
			vcpu_get_gr(ed,36));
		break;
	    case 0xfffb: // test dummy hypercall
		regs->r8 = domU_staging_read_8(vcpu_get_gr(ed,32));
		break;
	}
	return 1;
}
