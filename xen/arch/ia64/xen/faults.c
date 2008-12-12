/*
 * Miscellaneous process/domain related routines
 * 
 * Copyright (C) 2004 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <asm/ptrace.h>
#include <xen/delay.h>
#include <xen/perfc.h>
#include <xen/mm.h>

#include <asm/system.h>
#include <asm/processor.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <asm/privop.h>
#include <asm/vcpu.h>
#include <asm/ia64_int.h>
#include <asm/dom_fw.h>
#include <asm/vhpt.h>
#include <asm/debugger.h>
#include <asm/fpswa.h>
#include <asm/bundle.h>
#include <asm/asm-xsi-offsets.h>
#include <asm/shadow.h>
#include <asm/uaccess.h>
#include <asm/p2m_entry.h>

extern void die_if_kernel(char *str, struct pt_regs *regs, long err);
/* FIXME: where these declarations shold be there ? */
extern int ia64_hyperprivop(unsigned long, REGS *);
extern IA64FAULT ia64_hypercall(struct pt_regs *regs);

extern void do_ssc(unsigned long ssc, struct pt_regs *regs);

// should never panic domain... if it does, stack may have been overrun
static void check_bad_nested_interruption(unsigned long isr,
					  struct pt_regs *regs,
					  unsigned long vector)
{
	struct vcpu *v = current;

	if (!(PSCB(v, ipsr) & IA64_PSR_DT)) {
		panic_domain(regs,
		             "psr.dt off, trying to deliver nested dtlb!\n");
	}
	vector &= ~0xf;
	if (vector != IA64_DATA_TLB_VECTOR &&
	    vector != IA64_ALT_DATA_TLB_VECTOR &&
	    vector != IA64_VHPT_TRANS_VECTOR) {
		panic_domain(regs, "psr.ic off, delivering fault=%lx,"
		             "ipsr=%lx,iip=%lx,ifa=%lx,isr=%lx,PSCB.iip=%lx\n",
		             vector, regs->cr_ipsr, regs->cr_iip, PSCB(v, ifa),
		             isr, PSCB(v, iip));
	}
}

static void reflect_interruption(unsigned long isr, struct pt_regs *regs,
				 unsigned long vector)
{
	struct vcpu *v = current;

	if (!PSCB(v, interrupt_collection_enabled))
		check_bad_nested_interruption(isr, regs, vector);
	PSCB(v, unat) = regs->ar_unat;	// not sure if this is really needed?
	PSCB(v, precover_ifs) = regs->cr_ifs;
	PSCB(v, ipsr) = vcpu_get_psr(v);
	vcpu_bsw0(v);
	PSCB(v, isr) = isr;
	PSCB(v, iip) = regs->cr_iip;
	PSCB(v, ifs) = 0;

	regs->cr_iip = ((unsigned long)PSCBX(v, iva) + vector) & ~0xffUL;
	regs->cr_ipsr = (regs->cr_ipsr & ~DELIVER_PSR_CLR) | DELIVER_PSR_SET;
	regs->cr_ipsr = vcpu_pl_adjust(regs->cr_ipsr, IA64_PSR_CPL0_BIT);
	if (PSCB(v, dcr) & IA64_DCR_BE)
		regs->cr_ipsr |= IA64_PSR_BE;
	else
		regs->cr_ipsr &= ~IA64_PSR_BE;
    
	if (PSCB(v, hpsr_dfh))
		regs->cr_ipsr |= IA64_PSR_DFH;  
	PSCB(v, vpsr_dfh) = 0;
	v->vcpu_info->evtchn_upcall_mask = 1;
	PSCB(v, interrupt_collection_enabled) = 0;

	perfc_incra(slow_reflect, vector >> 8);

	debugger_event(vector == IA64_EXTINT_VECTOR ?
		       XEN_IA64_DEBUG_ON_EXTINT : XEN_IA64_DEBUG_ON_EXCEPT);
}

void reflect_event(void)
{
	struct vcpu *v = current;
	struct pt_regs *regs;
	unsigned long isr;

	if (!event_pending(v))
		return;

	/* Sanity check */
	if (is_idle_vcpu(v)) {
		//printk("WARN: invocation to reflect_event in nested xen\n");
		return;
	}

	regs = vcpu_regs(v);

	isr = regs->cr_ipsr & IA64_PSR_RI;

	if (!PSCB(v, interrupt_collection_enabled))
		printk("psr.ic off, delivering event, ipsr=%lx,iip=%lx,"
		       "isr=%lx,viip=0x%lx\n",
		       regs->cr_ipsr, regs->cr_iip, isr, PSCB(v, iip));
	PSCB(v, unat) = regs->ar_unat;	// not sure if this is really needed?
	PSCB(v, precover_ifs) = regs->cr_ifs;
	PSCB(v, ipsr) = vcpu_get_psr(v);
	vcpu_bsw0(v);
	PSCB(v, isr) = isr;
	PSCB(v, iip) = regs->cr_iip;
	PSCB(v, ifs) = 0;

	regs->cr_iip = v->arch.event_callback_ip;
	regs->cr_ipsr = (regs->cr_ipsr & ~DELIVER_PSR_CLR) | DELIVER_PSR_SET;
	regs->cr_ipsr = vcpu_pl_adjust(regs->cr_ipsr, IA64_PSR_CPL0_BIT);
	if (PSCB(v, dcr) & IA64_DCR_BE)
		regs->cr_ipsr |= IA64_PSR_BE;
	else
		regs->cr_ipsr &= ~IA64_PSR_BE;


	if (PSCB(v, hpsr_dfh))
		regs->cr_ipsr |= IA64_PSR_DFH;
	PSCB(v, vpsr_dfh) = 0;
	v->vcpu_info->evtchn_upcall_mask = 1;
	PSCB(v, interrupt_collection_enabled) = 0;

	debugger_event(XEN_IA64_DEBUG_ON_EVENT);
}

static int handle_lazy_cover(struct vcpu *v, struct pt_regs *regs)
{
	if (!PSCB(v, interrupt_collection_enabled)) {
		PSCB(v, ifs) = regs->cr_ifs;
		regs->cr_ifs = 0;
		perfc_incr(lazy_cover);
		return 1;	// retry same instruction with cr.ifs off
	}
	return 0;
}

void ia64_do_page_fault(unsigned long address, unsigned long isr,
                        struct pt_regs *regs, unsigned long itir)
{
	unsigned long iip = regs->cr_iip, iha;
	// FIXME should validate address here
	unsigned long pteval;
	unsigned long is_data = !((isr >> IA64_ISR_X_BIT) & 1UL);
	IA64FAULT fault;
	int is_ptc_l_needed = 0;
	ia64_itir_t _itir = {.itir = itir};

	if ((isr & IA64_ISR_SP)
	    || ((isr & IA64_ISR_NA)
		&& (isr & IA64_ISR_CODE_MASK) == IA64_ISR_CODE_LFETCH)) {
		/*
		 * This fault was due to a speculative load or lfetch.fault,
		 * set the "ed" bit in the psr to ensure forward progress.
		 * (Target register will get a NaT for ld.s, lfetch will be
		 * canceled.)
		 */
		ia64_psr(regs)->ed = 1;
		return;
	}

 again:
	fault = vcpu_translate(current, address, is_data, &pteval,
	                       &itir, &iha);
	if (fault == IA64_NO_FAULT || fault == IA64_USE_TLB) {
		struct p2m_entry entry;
		unsigned long m_pteval;
		m_pteval = translate_domain_pte(pteval, address, itir,
		                                &(_itir.itir), &entry);
		vcpu_itc_no_srlz(current, is_data ? 2 : 1, address,
		                 m_pteval, pteval, _itir.itir, &entry);
		if ((fault == IA64_USE_TLB && !current->arch.dtlb.pte.p) ||
		    p2m_entry_retry(&entry)) {
			/* dtlb has been purged in-between.  This dtlb was
			   matching.  Undo the work.  */
			vcpu_flush_tlb_vhpt_range(address, _itir.ps);

			// the stale entry which we inserted above
			// may remains in tlb cache.
			// we don't purge it now hoping next itc purges it.
			is_ptc_l_needed = 1;
			goto again;
		}
		return;
	}

	if (is_ptc_l_needed)
		vcpu_ptc_l(current, address, _itir.ps);
	if (!guest_mode(regs)) {
		/* The fault occurs inside Xen.  */
		if (!ia64_done_with_exception(regs)) {
			// should never happen.  If it does, region 0 addr may
			// indicate a bad xen pointer
			printk("*** xen_handle_domain_access: exception table"
			       " lookup failed, iip=0x%lx, addr=0x%lx, "
			       "spinning...\n", iip, address);
			panic_domain(regs, "*** xen_handle_domain_access: "
			             "exception table lookup failed, "
			             "iip=0x%lx, addr=0x%lx, spinning...\n",
			             iip, address);
		}
		return;
	}

	if ((isr & IA64_ISR_IR) && handle_lazy_cover(current, regs))
		return;

	if (!PSCB(current, interrupt_collection_enabled)) {
		check_bad_nested_interruption(isr, regs, fault);
		//printk("Delivering NESTED DATA TLB fault\n");
		fault = IA64_DATA_NESTED_TLB_VECTOR;
		regs->cr_iip =
		    ((unsigned long)PSCBX(current, iva) + fault) & ~0xffUL;
		regs->cr_ipsr =
		    (regs->cr_ipsr & ~DELIVER_PSR_CLR) | DELIVER_PSR_SET;
		regs->cr_ipsr = vcpu_pl_adjust(regs->cr_ipsr,
					       IA64_PSR_CPL0_BIT);
		if (PSCB(current, dcr) & IA64_DCR_BE)
			regs->cr_ipsr |= IA64_PSR_BE;
		else
			regs->cr_ipsr &= ~IA64_PSR_BE;


		if (PSCB(current, hpsr_dfh))
			regs->cr_ipsr |= IA64_PSR_DFH;  
		PSCB(current, vpsr_dfh) = 0;
		perfc_incra(slow_reflect, fault >> 8);
		return;
	}

	PSCB(current, itir) = itir;
	PSCB(current, iha) = iha;
	PSCB(current, ifa) = address;
	reflect_interruption(isr, regs, fault);
}

fpswa_interface_t *fpswa_interface = 0;

void __init trap_init(void)
{
	if (ia64_boot_param->fpswa)
		/* FPSWA fixup: make the interface pointer a virtual address */
		fpswa_interface = __va(ia64_boot_param->fpswa);
	else
		printk("No FPSWA supported.\n");
}

static fpswa_ret_t
fp_emulate(int fp_fault, void *bundle, unsigned long *ipsr,
           unsigned long *fpsr, unsigned long *isr, unsigned long *pr,
           unsigned long *ifs, struct pt_regs *regs)
{
	fp_state_t fp_state;
	fpswa_ret_t ret;
	XEN_EFI_RR_DECLARE(rr6, rr7);

	if (!fpswa_interface)
		return (fpswa_ret_t) {-1, 0, 0, 0};

	memset(&fp_state, 0, sizeof(fp_state_t));

	/*
	 * compute fp_state.  only FP registers f6 - f11 are used by the
	 * kernel, so set those bits in the mask and set the low volatile
	 * pointer to point to these registers.
	 */
	fp_state.bitmask_low64 = 0xfc0;	/* bit6..bit11 */

	fp_state.fp_state_low_volatile = (fp_state_low_volatile_t *) &regs->f6;
	/*
	 * unsigned long (*EFI_FPSWA) (
	 *      unsigned long    trap_type,
	 *      void             *Bundle,
	 *      unsigned long    *pipsr,
	 *      unsigned long    *pfsr,
	 *      unsigned long    *pisr,
	 *      unsigned long    *ppreds,
	 *      unsigned long    *pifs,
	 *      void             *fp_state);
	 */
	XEN_EFI_RR_ENTER(rr6, rr7);
	ret = (*fpswa_interface->fpswa) (fp_fault, bundle,
	                                 ipsr, fpsr, isr, pr, ifs, &fp_state);
	XEN_EFI_RR_LEAVE(rr6, rr7);

	return ret;
}

/*
 * Handle floating-point assist faults and traps for domain.
 */
unsigned long
handle_fpu_swa(int fp_fault, struct pt_regs *regs, unsigned long isr)
{
	IA64_BUNDLE bundle;
	unsigned long fault_ip;
	fpswa_ret_t ret;
	unsigned long rc;

	fault_ip = regs->cr_iip;
	/*
	 * When the FP trap occurs, the trapping instruction is completed.
	 * If ipsr.ri == 0, there is the trapping instruction in previous
	 * bundle.
	 */
	if (!fp_fault && (ia64_psr(regs)->ri == 0))
		fault_ip -= 16;

	if (VMX_DOMAIN(current)) {
		rc = __vmx_get_domain_bundle(fault_ip, &bundle);
	} else {
		rc = 0;
		if (vcpu_get_domain_bundle(current, regs, fault_ip,
					   &bundle) == 0)
			rc = IA64_RETRY;
	}
	if (rc == IA64_RETRY) {
		PSCBX(current, fpswa_ret) = (fpswa_ret_t){IA64_RETRY, 0, 0, 0};
		gdprintk(XENLOG_DEBUG,
			 "%s(%s): floating-point bundle at 0x%lx not mapped\n",
			 __FUNCTION__, fp_fault ? "fault" : "trap", fault_ip);
		return IA64_RETRY;
	}

	ret = fp_emulate(fp_fault, &bundle, &regs->cr_ipsr, &regs->ar_fpsr,
	                 &isr, &regs->pr, &regs->cr_ifs, regs);

	if (ret.status) {
		PSCBX(current, fpswa_ret) = ret;
		gdprintk(XENLOG_ERR, "%s(%s): fp_emulate() returned %ld\n",
			 __FUNCTION__, fp_fault ? "fault" : "trap",
			 ret.status);
	}

	return ret.status;
}

void
ia64_fault(unsigned long vector, unsigned long isr, unsigned long ifa,
           unsigned long iim, unsigned long itir, unsigned long arg5,
           unsigned long arg6, unsigned long arg7, unsigned long stack)
{
	struct pt_regs *regs = (struct pt_regs *)&stack;
	unsigned long code;
	static const char *const reason[] = {
		"IA-64 Illegal Operation fault",
		"IA-64 Privileged Operation fault",
		"IA-64 Privileged Register fault",
		"IA-64 Reserved Register/Field fault",
		"Disabled Instruction Set Transition fault",
		"Unknown fault 5", "Unknown fault 6",
		"Unknown fault 7", "Illegal Hazard fault",
		"Unknown fault 9", "Unknown fault 10",
		"Unknown fault 11", "Unknown fault 12",
		"Unknown fault 13", "Unknown fault 14", "Unknown fault 15"
	};

	printk("ia64_fault, vector=0x%lx, ifa=0x%016lx, iip=0x%016lx, "
	       "ipsr=0x%016lx, isr=0x%016lx\n", vector, ifa,
	       regs->cr_iip, regs->cr_ipsr, isr);

	if ((isr & IA64_ISR_NA) &&
	    ((isr & IA64_ISR_CODE_MASK) == IA64_ISR_CODE_LFETCH)) {
		/*
		 * This fault was due to lfetch.fault, set "ed" bit in the
		 * psr to cancel the lfetch.
		 */
		ia64_psr(regs)->ed = 1;
		printk("ia64_fault: handled lfetch.fault\n");
		return;
	}

	switch (vector) {
	case 0:
		printk("VHPT Translation.\n");
		break;

	case 4:
		printk("Alt DTLB.\n");
		break;

	case 6:
		printk("Instruction Key Miss.\n");
		break;

	case 7:
		printk("Data Key Miss.\n");
		break;

	case 8:
		printk("Dirty-bit.\n");
		break;

	case 10:
		/* __domain_get_bundle() may cause fault. */
		if (ia64_done_with_exception(regs))
			return;
		printk("Data Access-bit.\n");
		break;

	case 20:
		printk("Page Not Found.\n");
		break;

	case 21:
		printk("Key Permission.\n");
		break;

	case 22:
		printk("Instruction Access Rights.\n");
		break;

	case 24:	/* General Exception */
		code = (isr >> 4) & 0xf;
		printk("General Exception: %s%s.\n", reason[code],
		       (code == 3) ? ((isr & (1UL << 37)) ? " (RSE access)" :
		                       " (data access)") : "");
		if (code == 8) {
#ifdef CONFIG_IA64_PRINT_HAZARDS
			printk("%s[%d]: possible hazard @ ip=%016lx "
			       "(pr = %016lx)\n", current->comm, current->pid,
			       regs->cr_iip + ia64_psr(regs)->ri, regs->pr);
#endif
			printk("ia64_fault: returning on hazard\n");
			return;
		}
		break;

	case 25:
		printk("Disabled FP-Register.\n");
		break;

	case 26:
		printk("NaT consumption.\n");
		break;

	case 29:
		printk("Debug.\n");
		break;

	case 30:
		printk("Unaligned Reference.\n");
		break;

	case 31:
		printk("Unsupported data reference.\n");
		break;

	case 32:
		printk("Floating-Point Fault.\n");
		break;

	case 33:
		printk("Floating-Point Trap.\n");
		break;

	case 34:
		printk("Lower Privilege Transfer Trap.\n");
		break;

	case 35:
		printk("Taken Branch Trap.\n");
		break;

	case 36:
		printk("Single Step Trap.\n");
		break;

	case 45:
		printk("IA-32 Exception.\n");
		break;

	case 46:
		printk("IA-32 Intercept.\n");
		break;

	case 47:
		printk("IA-32 Interrupt.\n");
		break;

	default:
		printk("Fault %lu\n", vector);
		break;
	}

	show_registers(regs);
	panic("Fault in Xen.\n");
}

/* Also read in hyperprivop.S  */
int first_break = 0;

void
ia64_handle_break(unsigned long ifa, struct pt_regs *regs, unsigned long isr,
                  unsigned long iim)
{
	struct domain *d = current->domain;
	struct vcpu *v = current;
	IA64FAULT vector;

	/* FIXME: don't hardcode constant */
	if ((iim == 0x80001 || iim == 0x80002)
	    && ia64_get_cpl(regs->cr_ipsr) == CONFIG_CPL0_EMUL) {
		do_ssc(vcpu_get_gr(current, 36), regs);
	}
#ifdef CRASH_DEBUG
	else if ((iim == 0 || iim == CDB_BREAK_NUM) && !guest_mode(regs)) {
		if (iim == 0)
			show_registers(regs);
		debugger_trap_fatal(0 /* don't care */ , regs);
		regs_increment_iip(regs);
	}
#endif
	else if (iim == d->arch.breakimm &&
	         ia64_get_cpl(regs->cr_ipsr) == CONFIG_CPL0_EMUL) {
		/* by default, do not continue */
		v->arch.hypercall_continuation = 0;

		if ((vector = ia64_hypercall(regs)) == IA64_NO_FAULT) {
			if (!PSCBX(v, hypercall_continuation))
				vcpu_increment_iip(current);
		} else
			reflect_interruption(isr, regs, vector);
	} else if ((iim - HYPERPRIVOP_START) < HYPERPRIVOP_MAX
		   && ia64_get_cpl(regs->cr_ipsr) == CONFIG_CPL0_EMUL) {
		if (ia64_hyperprivop(iim, regs))
			vcpu_increment_iip(current);
	} else {
		if (iim == 0)
			die_if_kernel("bug check", regs, iim);
		PSCB(v, iim) = iim;
		reflect_interruption(isr, regs, IA64_BREAK_VECTOR);
	}
}

void
ia64_handle_privop(unsigned long ifa, struct pt_regs *regs, unsigned long isr,
                   unsigned long itir)
{
	IA64FAULT vector;

	vector = priv_emulate(current, regs, isr);
	if (vector != IA64_NO_FAULT && vector != IA64_RFI_IN_PROGRESS) {
		// Note: if a path results in a vector to reflect that requires
		// iha/itir (e.g. vcpu_force_data_miss), they must be set there
		/*
		 * IA64_GENEX_VECTOR may contain in the lowest byte an ISR.code
		 * see IA64_ILLOP_FAULT, ...
		 */
		if ((vector & ~0xffUL) == IA64_GENEX_VECTOR) {
			isr = vector & 0xffUL;
			vector = IA64_GENEX_VECTOR;
		}
		reflect_interruption(isr, regs, vector);
	}
}

void
ia64_lazy_load_fpu(struct vcpu *v)
{
	if (PSCB(v, hpsr_dfh)) {
		PSCB(v, hpsr_dfh) = 0;
		PSCB(v, hpsr_mfh) = 1;
		if (__ia64_per_cpu_var(fp_owner) != v)
			__ia64_load_fpu(v->arch._thread.fph);
	}
}

void
ia64_handle_reflection(unsigned long ifa, struct pt_regs *regs,
                       unsigned long isr, unsigned long iim,
                       unsigned long vector)
{
	struct vcpu *v = current;
	unsigned long check_lazy_cover = 0;
	unsigned long psr = regs->cr_ipsr;
	unsigned long status;

	/* Following faults shouldn't be seen from Xen itself */
	BUG_ON(!(psr & IA64_PSR_CPL));

	switch (vector) {
	case 6:
		vector = IA64_INST_KEY_MISS_VECTOR;
		break;
	case 7:
		vector = IA64_DATA_KEY_MISS_VECTOR;
		break;
	case 8:
		vector = IA64_DIRTY_BIT_VECTOR;
		break;
	case 9:
		vector = IA64_INST_ACCESS_BIT_VECTOR;
		break;
	case 10:
		check_lazy_cover = 1;
		vector = IA64_DATA_ACCESS_BIT_VECTOR;
		break;
	case 20:
		check_lazy_cover = 1;
		vector = IA64_PAGE_NOT_PRESENT_VECTOR;
		break;
	case 21:
		vector = IA64_KEY_PERMISSION_VECTOR;
		break;
	case 22:
		vector = IA64_INST_ACCESS_RIGHTS_VECTOR;
		break;
	case 23:
		check_lazy_cover = 1;
		vector = IA64_DATA_ACCESS_RIGHTS_VECTOR;
		break;
	case 24:
		vector = IA64_GENEX_VECTOR;
		break;
	case 25:
		ia64_lazy_load_fpu(v);
		if (!PSCB(v, vpsr_dfh)) {
			regs->cr_ipsr &= ~IA64_PSR_DFH;
			return;
		}
		vector = IA64_DISABLED_FPREG_VECTOR;
		break;
	case 26:
		if (((isr >> 4L) & 0xfL) == 1) {
			/* Fault is due to a register NaT consumption fault. */
			//regs->eml_unat = 0;  FIXME: DO WE NEED THIS??
			vector = IA64_NAT_CONSUMPTION_VECTOR;
			break;
		}
#if 1
		// pass null pointer dereferences through with no error
		// but retain debug output for non-zero ifa
		if (!ifa) {
			vector = IA64_NAT_CONSUMPTION_VECTOR;
			break;
		}
#endif
#ifdef CONFIG_PRIVIFY
		/* Some privified operations are coded using reg+64 instead
		   of reg.  */
		printk("*** NaT fault... attempting to handle as privop\n");
		printk("isr=%016lx, ifa=%016lx, iip=%016lx, ipsr=%016lx\n",
		       isr, ifa, regs->cr_iip, psr);
		//regs->eml_unat = 0;  FIXME: DO WE NEED THIS???
		// certain NaT faults are higher priority than privop faults
		vector = priv_emulate(v, regs, isr);
		if (vector == IA64_NO_FAULT) {
			printk("*** Handled privop masquerading as NaT "
			       "fault\n");
			return;
		}
#endif
		vector = IA64_NAT_CONSUMPTION_VECTOR;
		break;
	case 27:
		//printk("*** Handled speculation vector, itc=%lx!\n",
		//       ia64_get_itc());
		PSCB(current, iim) = iim;
		vector = IA64_SPECULATION_VECTOR;
		break;
	case 29:
		vector = IA64_DEBUG_VECTOR;
		if (debugger_kernel_event(regs, XEN_IA64_DEBUG_ON_KERN_DEBUG))
			return;
		break;
	case 30:
		// FIXME: Should we handle unaligned refs in Xen??
		vector = IA64_UNALIGNED_REF_VECTOR;
		break;
	case 32:
		status = handle_fpu_swa(1, regs, isr);
		if (!status) {
			vcpu_increment_iip(v);
			return;
		}
		vector = IA64_FP_FAULT_VECTOR;
		break;
	case 33:
		status = handle_fpu_swa(0, regs, isr);
		if (!status)
			return;
		vector = IA64_FP_TRAP_VECTOR;
		break;
	case 34:
		if (isr & (1UL << 4))
			printk("ia64_handle_reflection: handling "
			       "unimplemented instruction address %s\n",
			       (isr & (1UL<<32)) ? "fault" : "trap");
		vector = IA64_LOWERPRIV_TRANSFER_TRAP_VECTOR;
		break;
	case 35:
		vector = IA64_TAKEN_BRANCH_TRAP_VECTOR;
		if (debugger_kernel_event(regs, XEN_IA64_DEBUG_ON_KERN_TBRANCH))
			return;
		break;
	case 36:
		vector = IA64_SINGLE_STEP_TRAP_VECTOR;
		if (debugger_kernel_event(regs, XEN_IA64_DEBUG_ON_KERN_SSTEP))
			return;
		break;

	default:
		panic_domain(regs, "ia64_handle_reflection: "
			     "unhandled vector=0x%lx\n", vector);
		return;
	}
	if (check_lazy_cover && (isr & IA64_ISR_IR) &&
	    handle_lazy_cover(v, regs))
		return;
	PSCB(current, ifa) = ifa;
	PSCB(current, itir) = vcpu_get_itir_on_fault(v, ifa);
	reflect_interruption(isr, regs, vector);
}

void
ia64_shadow_fault(unsigned long ifa, unsigned long itir,
                  unsigned long isr, struct pt_regs *regs)
{
	struct vcpu *v = current;
	struct domain *d = current->domain;
	unsigned long gpfn;
	unsigned long pte = 0;
	struct vhpt_lf_entry *vlfe;

	/*
	 * v->arch.vhpt_pg_shift shouldn't be used here.
	 * Currently dirty page logging bitmap is allocated based
	 * on PAGE_SIZE. This is part of xen_domctl_shadow_op ABI.
	 * If we want to log dirty pages in finer grained when
	 * v->arch.vhpt_pg_shift < PAGE_SHIFT, we have to
	 * revise the ABI and update this function and the related
	 * tool stack (live relocation).
	 */
	unsigned long vhpt_pg_shift = PAGE_SHIFT;

	/* There are 2 jobs to do:
	   -  marking the page as dirty (the metaphysical address must be
	      extracted to do that).
	   -  reflecting or not the fault (the virtual Dirty bit must be
	      extracted to decide).
	   Unfortunatly these informations are not immediatly available!
	 */

	/* Extract the metaphysical address.
	   Try to get it from VHPT and M2P as we need the flags.  */
	vlfe = (struct vhpt_lf_entry *)ia64_thash(ifa);
	pte = vlfe->page_flags;
	if (vlfe->ti_tag == ia64_ttag(ifa)) {
		/* The VHPT entry is valid.  */
		gpfn = get_gpfn_from_mfn((pte & _PAGE_PPN_MASK) >>
					 vhpt_pg_shift);
		BUG_ON(gpfn == INVALID_M2P_ENTRY);
	} else {
		unsigned long itir, iha;
		IA64FAULT fault;

		/* The VHPT entry is not valid.  */
		vlfe = NULL;

		/* FIXME: gives a chance to tpa, as the TC was valid.  */

		fault = vcpu_translate(v, ifa, 1, &pte, &itir, &iha);

		/* Try again!  */
		if (fault != IA64_NO_FAULT) {
			/* This will trigger a dtlb miss.  */
			ia64_ptcl(ifa, vhpt_pg_shift << 2);
			return;
		}
		gpfn = ((pte & _PAGE_PPN_MASK) >> vhpt_pg_shift);
		if (pte & _PAGE_D)
			pte |= _PAGE_VIRT_D;
	}

	/* Set the dirty bit in the bitmap.  */
	shadow_mark_page_dirty(d, gpfn);

	/* Update the local TC/VHPT and decides wether or not the fault should
	   be reflected.
	   SMP note: we almost ignore the other processors.  The shadow_bitmap
	   has been atomically updated.  If the dirty fault happen on another
	   processor, it will do its job.
	 */

	if (pte != 0) {
		/* We will know how to handle the fault.  */

		if (pte & _PAGE_VIRT_D) {
			/* Rewrite VHPT entry.
			   There is no race here because only the
			   cpu VHPT owner can write page_flags.  */
			if (vlfe)
				vlfe->page_flags = pte | _PAGE_D;

			/* Purge the TC locally.
			   It will be reloaded from the VHPT iff the
			   VHPT entry is still valid.  */
			ia64_ptcl(ifa, vhpt_pg_shift << 2);

			atomic64_inc(&d->arch.shadow_fault_count);
		} else {
			/* Reflect.
			   In this case there is no need to purge.  */
			ia64_handle_reflection(ifa, regs, isr, 0, 8);
		}
	} else {
		/* We don't know wether or not the fault must be
		   reflected.  The VHPT entry is not valid.  */
		/* FIXME: in metaphysical mode, we could do an ITC now.  */
		ia64_ptcl(ifa, vhpt_pg_shift << 2);
	}
}
