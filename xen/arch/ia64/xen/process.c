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

#include <linux/efi.h>	/* FOR EFI_UNIMPLEMENTED */
#include <asm/sal.h>	/* FOR struct ia64_sal_retval */

#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
//#include <asm/ldt.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <asm/regionreg.h>
#include <asm/privop.h>
#include <asm/vcpu.h>
#include <asm/ia64_int.h>
#include <asm/dom_fw.h>
#include "hpsim_ssc.h"
#include <xen/multicall.h>
#include <asm/debugger.h>

extern void die_if_kernel(char *str, struct pt_regs *regs, long err);
/* FIXME: where these declarations shold be there ? */
extern void load_region_regs(struct vcpu *);
extern void panic_domain(struct pt_regs *, const char *, ...);
extern long platform_is_hp_ski(void);
extern int ia64_hyperprivop(unsigned long, REGS *);
extern int ia64_hypercall(struct pt_regs *regs);
extern void vmx_do_launch(struct vcpu *);

extern unsigned long dom0_start, dom0_size;

#define IA64_PSR_CPL1	(__IA64_UL(1) << IA64_PSR_CPL1_BIT)
// note IA64_PSR_PK removed from following, why is this necessary?
#define	DELIVER_PSR_SET	(IA64_PSR_IC | IA64_PSR_I | \
			IA64_PSR_DT | IA64_PSR_RT | IA64_PSR_CPL1 | \
			IA64_PSR_IT | IA64_PSR_BN)

#define	DELIVER_PSR_CLR	(IA64_PSR_AC | IA64_PSR_DFL | IA64_PSR_DFH | \
			IA64_PSR_SP | IA64_PSR_DI | IA64_PSR_SI |	\
			IA64_PSR_DB | IA64_PSR_LP | IA64_PSR_TB | \
			IA64_PSR_CPL | IA64_PSR_MC | IA64_PSR_IS | \
			IA64_PSR_ID | IA64_PSR_DA | IA64_PSR_DD | \
			IA64_PSR_SS | IA64_PSR_RI | IA64_PSR_ED | IA64_PSR_IA)

#define PSCB(x,y)	VCPU(x,y)
#define PSCBX(x,y)	x->arch.y

extern unsigned long vcpu_verbose;

long do_iopl(domid_t domain, unsigned int new_io_pl)
{
	dummy();
	return 0;
}

#include <xen/sched-if.h>

extern struct schedule_data schedule_data[NR_CPUS];

void schedule_tail(struct vcpu *prev)
{
	context_saved(prev);

	if (VMX_DOMAIN(current)) {
		vmx_do_launch(current);
	} else {
		load_region_regs(current);
		vcpu_load_kernel_regs(current);
	}
}

void tdpfoo(void) { }

// given a domain virtual address, pte and pagesize, extract the metaphysical
// address, convert the pte for a physical address for (possibly different)
// Xen PAGE_SIZE and return modified pte.  (NOTE: TLB insert should use
// PAGE_SIZE!)
unsigned long translate_domain_pte(unsigned long pteval,
	unsigned long address, unsigned long itir)
{
	struct domain *d = current->domain;
	unsigned long mask, pteval2, mpaddr;
	unsigned long lookup_domain_mpa(struct domain *,unsigned long);
	extern struct domain *dom0;
	extern unsigned long dom0_start, dom0_size;

	// FIXME address had better be pre-validated on insert
	mask = ~itir_mask(itir);
	mpaddr = ((pteval & _PAGE_PPN_MASK) & ~mask) | (address & mask);
	if (d == dom0) {
		if (mpaddr < dom0_start || mpaddr >= dom0_start + dom0_size) {
			/*
			printk("translate_domain_pte: out-of-bounds dom0 mpaddr 0x%lx! itc=%lx...\n",
				mpaddr, ia64_get_itc());
			*/
			tdpfoo();
		}
	}
	else if ((mpaddr >> PAGE_SHIFT) > d->max_pages) {
		if ((mpaddr & ~0x1fffL ) != (1L << 40))
		printf("translate_domain_pte: bad mpa=0x%lx (> 0x%lx),vadr=0x%lx,pteval=0x%lx,itir=0x%lx\n",
			mpaddr, (unsigned long) d->max_pages<<PAGE_SHIFT, address, pteval, itir);
		tdpfoo();
	}
	pteval2 = lookup_domain_mpa(d,mpaddr);
	pteval2 &= _PAGE_PPN_MASK; // ignore non-addr bits
	pteval2 |= _PAGE_PL_2; // force PL0->2 (PL3 is unaffected)
	pteval2 = (pteval & ~_PAGE_PPN_MASK) | pteval2;
	return pteval2;
}

// given a current domain metaphysical address, return the physical address
unsigned long translate_domain_mpaddr(unsigned long mpaddr)
{
	extern unsigned long lookup_domain_mpa(struct domain *,unsigned long);
	unsigned long pteval;

	if (current->domain == dom0) {
		if (mpaddr < dom0_start || mpaddr >= dom0_start + dom0_size) {
			printk("translate_domain_mpaddr: out-of-bounds dom0 mpaddr 0x%lx! continuing...\n",
				mpaddr);
			tdpfoo();
		}
	}
	pteval = lookup_domain_mpa(current->domain,mpaddr);
	return ((pteval & _PAGE_PPN_MASK) | (mpaddr & ~PAGE_MASK));
}

unsigned long slow_reflect_count[0x80] = { 0 };
unsigned long fast_reflect_count[0x80] = { 0 };

#define inc_slow_reflect_count(vec) slow_reflect_count[vec>>8]++;

void zero_reflect_counts(void)
{
	int i;
	for (i=0; i<0x80; i++) slow_reflect_count[i] = 0;
	for (i=0; i<0x80; i++) fast_reflect_count[i] = 0;
}

int dump_reflect_counts(char *buf)
{
	int i,j,cnt;
	char *s = buf;

	s += sprintf(s,"Slow reflections by vector:\n");
	for (i = 0, j = 0; i < 0x80; i++) {
		if ( (cnt = slow_reflect_count[i]) != 0 ) {
			s += sprintf(s,"0x%02x00:%10d, ",i,cnt);
			if ((j++ & 3) == 3) s += sprintf(s,"\n");
		}
	}
	if (j & 3) s += sprintf(s,"\n");
	s += sprintf(s,"Fast reflections by vector:\n");
	for (i = 0, j = 0; i < 0x80; i++) {
		if ( (cnt = fast_reflect_count[i]) != 0 ) {
			s += sprintf(s,"0x%02x00:%10d, ",i,cnt);
			if ((j++ & 3) == 3) s += sprintf(s,"\n");
		}
	}
	if (j & 3) s += sprintf(s,"\n");
	return s - buf;
}

// should never panic domain... if it does, stack may have been overrun
void check_bad_nested_interruption(unsigned long isr, struct pt_regs *regs, unsigned long vector)
{
	struct vcpu *v = current;

	if (!(PSCB(v,ipsr) & IA64_PSR_DT)) {
		panic_domain(regs,"psr.dt off, trying to deliver nested dtlb!\n");
	}
	vector &= ~0xf;
	if (vector != IA64_DATA_TLB_VECTOR &&
		vector != IA64_ALT_DATA_TLB_VECTOR &&
		vector != IA64_VHPT_TRANS_VECTOR) {
panic_domain(regs,"psr.ic off, delivering fault=%lx,ipsr=%p,iip=%p,ifa=%p,isr=%p,PSCB.iip=%p\n",
	vector,regs->cr_ipsr,regs->cr_iip,PSCB(v,ifa),isr,PSCB(v,iip));
	}
}

void reflect_interruption(unsigned long isr, struct pt_regs *regs, unsigned long vector)
{
	struct vcpu *v = current;

	if (!PSCB(v,interrupt_collection_enabled))
		check_bad_nested_interruption(isr,regs,vector);
	PSCB(v,unat) = regs->ar_unat;  // not sure if this is really needed?
	PSCB(v,precover_ifs) = regs->cr_ifs;
	vcpu_bsw0(v);
	PSCB(v,ipsr) = vcpu_get_ipsr_int_state(v,regs->cr_ipsr);
	PSCB(v,isr) = isr;
	PSCB(v,iip) = regs->cr_iip;
	PSCB(v,ifs) = 0;
	PSCB(v,incomplete_regframe) = 0;

	regs->cr_iip = ((unsigned long) PSCBX(v,iva) + vector) & ~0xffUL;
	regs->cr_ipsr = (regs->cr_ipsr & ~DELIVER_PSR_CLR) | DELIVER_PSR_SET;
#ifdef CONFIG_SMP
#warning "SMP FIXME: sharedinfo doesn't handle smp yet, need page per vcpu"
#endif
	regs->r31 = (unsigned long) &(((mapped_regs_t *)SHARED_ARCHINFO_ADDR)->ipsr);

	PSCB(v,interrupt_delivery_enabled) = 0;
	PSCB(v,interrupt_collection_enabled) = 0;

	inc_slow_reflect_count(vector);
}

void foodpi(void) {}

unsigned long pending_false_positive = 0;

void reflect_extint(struct pt_regs *regs)
{
	unsigned long isr = regs->cr_ipsr & IA64_PSR_RI;
	struct vcpu *v = current;
	static int first_extint = 1;

	if (first_extint) {
		printf("Delivering first extint to domain: isr=0x%lx, iip=0x%lx\n", isr, regs->cr_iip);
		first_extint = 0;
	}
	if (vcpu_timer_pending_early(v))
printf("*#*#*#* about to deliver early timer to domain %d!!!\n",v->domain->domain_id);
	PSCB(current,itir) = 0;
	reflect_interruption(isr,regs,IA64_EXTINT_VECTOR);
}

// ONLY gets called from ia64_leave_kernel
// ONLY call with interrupts disabled?? (else might miss one?)
// NEVER successful if already reflecting a trap/fault because psr.i==0
void deliver_pending_interrupt(struct pt_regs *regs)
{
	struct domain *d = current->domain;
	struct vcpu *v = current;
	// FIXME: Will this work properly if doing an RFI???
	if (!is_idle_domain(d) && user_mode(regs)) {
		//vcpu_poke_timer(v);
		if (vcpu_deliverable_interrupts(v))
			reflect_extint(regs);
		else if (PSCB(v,pending_interruption))
			++pending_false_positive;
	}
}
unsigned long lazy_cover_count = 0;

int handle_lazy_cover(struct vcpu *v, unsigned long isr, struct pt_regs *regs)
{
	if (!PSCB(v,interrupt_collection_enabled)) {
		PSCB(v,ifs) = regs->cr_ifs;
		PSCB(v,incomplete_regframe) = 1;
		regs->cr_ifs = 0;
		lazy_cover_count++;
		return(1); // retry same instruction with cr.ifs off
	}
	return(0);
}

void ia64_do_page_fault (unsigned long address, unsigned long isr, struct pt_regs *regs, unsigned long itir)
{
	unsigned long iip = regs->cr_iip, iha;
	// FIXME should validate address here
	unsigned long pteval;
	unsigned long is_data = !((isr >> IA64_ISR_X_BIT) & 1UL);
	IA64FAULT fault;

	if ((isr & IA64_ISR_IR) && handle_lazy_cover(current, isr, regs)) return;
	if ((isr & IA64_ISR_SP)
	    || ((isr & IA64_ISR_NA) && (isr & IA64_ISR_CODE_MASK) == IA64_ISR_CODE_LFETCH))
	{
		/*
		 * This fault was due to a speculative load or lfetch.fault, set the "ed"
		 * bit in the psr to ensure forward progress.  (Target register will get a
		 * NaT for ld.s, lfetch will be canceled.)
		 */
		ia64_psr(regs)->ed = 1;
		return;
	}

	fault = vcpu_translate(current,address,is_data,&pteval,&itir,&iha);
	if (fault == IA64_NO_FAULT) {
		pteval = translate_domain_pte(pteval,address,itir);
		vcpu_itc_no_srlz(current,is_data?2:1,address,pteval,-1UL,(itir>>2)&0x3f);
		return;
	}
	if (IS_VMM_ADDRESS(iip)) {
		if (!ia64_done_with_exception(regs)) {
			// should never happen.  If it does, region 0 addr may
			// indicate a bad xen pointer
			printk("*** xen_handle_domain_access: exception table"
			       " lookup failed, iip=0x%lx, addr=0x%lx, spinning...\n",
				iip, address);
			panic_domain(regs,"*** xen_handle_domain_access: exception table"
			       " lookup failed, iip=0x%lx, addr=0x%lx, spinning...\n",
				iip, address);
		}
		return;
	}
	if (!PSCB(current,interrupt_collection_enabled)) {
		check_bad_nested_interruption(isr,regs,fault);
		//printf("Delivering NESTED DATA TLB fault\n");
		fault = IA64_DATA_NESTED_TLB_VECTOR;
		regs->cr_iip = ((unsigned long) PSCBX(current,iva) + fault) & ~0xffUL;
		regs->cr_ipsr = (regs->cr_ipsr & ~DELIVER_PSR_CLR) | DELIVER_PSR_SET;
		// NOTE: nested trap must NOT pass PSCB address
		//regs->r31 = (unsigned long) &PSCB(current);
		inc_slow_reflect_count(fault);
		return;
	}

	PSCB(current,itir) = itir;
	PSCB(current,iha) = iha;
	PSCB(current,ifa) = address;
	reflect_interruption(isr, regs, fault);
}

void
ia64_fault (unsigned long vector, unsigned long isr, unsigned long ifa,
	    unsigned long iim, unsigned long itir, unsigned long arg5,
	    unsigned long arg6, unsigned long arg7, unsigned long stack)
{
	struct pt_regs *regs = (struct pt_regs *) &stack;
	unsigned long code;
	char buf[128];
	static const char * const reason[] = {
		"IA-64 Illegal Operation fault",
		"IA-64 Privileged Operation fault",
		"IA-64 Privileged Register fault",
		"IA-64 Reserved Register/Field fault",
		"Disabled Instruction Set Transition fault",
		"Unknown fault 5", "Unknown fault 6", "Unknown fault 7", "Illegal Hazard fault",
		"Unknown fault 9", "Unknown fault 10", "Unknown fault 11", "Unknown fault 12",
		"Unknown fault 13", "Unknown fault 14", "Unknown fault 15"
	};
#if 0
printf("ia64_fault, vector=0x%p, ifa=%p, iip=%p, ipsr=%p, isr=%p\n",
 vector, ifa, regs->cr_iip, regs->cr_ipsr, isr);
#endif

	if ((isr & IA64_ISR_NA) && ((isr & IA64_ISR_CODE_MASK) == IA64_ISR_CODE_LFETCH)) {
		/*
		 * This fault was due to lfetch.fault, set "ed" bit in the psr to cancel
		 * the lfetch.
		 */
		ia64_psr(regs)->ed = 1;
		printf("ia64_fault: handled lfetch.fault\n");
		return;
	}

	switch (vector) {
	      case 24: /* General Exception */
		code = (isr >> 4) & 0xf;
		sprintf(buf, "General Exception: %s%s", reason[code],
			(code == 3) ? ((isr & (1UL << 37))
				       ? " (RSE access)" : " (data access)") : "");
		if (code == 8) {
# ifdef CONFIG_IA64_PRINT_HAZARDS
			printk("%s[%d]: possible hazard @ ip=%016lx (pr = %016lx)\n",
			       current->comm, current->pid, regs->cr_iip + ia64_psr(regs)->ri,
			       regs->pr);
# endif
			printf("ia64_fault: returning on hazard\n");
			return;
		}
		break;

	      case 25: /* Disabled FP-Register */
		if (isr & 2) {
			//disabled_fph_fault(regs);
			//return;
		}
		sprintf(buf, "Disabled FPL fault---not supposed to happen!");
		break;

	      case 26: /* NaT Consumption */
		if (user_mode(regs)) {
			void *addr;

			if (((isr >> 4) & 0xf) == 2) {
				/* NaT page consumption */
				//sig = SIGSEGV;
				//code = SEGV_ACCERR;
				addr = (void *) ifa;
			} else {
				/* register NaT consumption */
				//sig = SIGILL;
				//code = ILL_ILLOPN;
				addr = (void *) (regs->cr_iip + ia64_psr(regs)->ri);
			}
			//siginfo.si_signo = sig;
			//siginfo.si_code = code;
			//siginfo.si_errno = 0;
			//siginfo.si_addr = addr;
			//siginfo.si_imm = vector;
			//siginfo.si_flags = __ISR_VALID;
			//siginfo.si_isr = isr;
			//force_sig_info(sig, &siginfo, current);
			//return;
		} //else if (ia64_done_with_exception(regs))
			//return;
		sprintf(buf, "NaT consumption");
		break;

	      case 31: /* Unsupported Data Reference */
		if (user_mode(regs)) {
			//siginfo.si_signo = SIGILL;
			//siginfo.si_code = ILL_ILLOPN;
			//siginfo.si_errno = 0;
			//siginfo.si_addr = (void *) (regs->cr_iip + ia64_psr(regs)->ri);
			//siginfo.si_imm = vector;
			//siginfo.si_flags = __ISR_VALID;
			//siginfo.si_isr = isr;
			//force_sig_info(SIGILL, &siginfo, current);
			//return;
		}
		sprintf(buf, "Unsupported data reference");
		break;

	      case 29: /* Debug */
	      case 35: /* Taken Branch Trap */
	      case 36: /* Single Step Trap */
		//if (fsys_mode(current, regs)) {}
		switch (vector) {
		      case 29:
			//siginfo.si_code = TRAP_HWBKPT;
#ifdef CONFIG_ITANIUM
			/*
			 * Erratum 10 (IFA may contain incorrect address) now has
			 * "NoFix" status.  There are no plans for fixing this.
			 */
			if (ia64_psr(regs)->is == 0)
			  ifa = regs->cr_iip;
#endif
			break;
		      case 35: ifa = 0; break;
		      case 36: ifa = 0; break;
		      //case 35: siginfo.si_code = TRAP_BRANCH; ifa = 0; break;
		      //case 36: siginfo.si_code = TRAP_TRACE; ifa = 0; break;
		}
		//siginfo.si_signo = SIGTRAP;
		//siginfo.si_errno = 0;
		//siginfo.si_addr  = (void *) ifa;
		//siginfo.si_imm   = 0;
		//siginfo.si_flags = __ISR_VALID;
		//siginfo.si_isr   = isr;
		//force_sig_info(SIGTRAP, &siginfo, current);
		//return;

	      case 32: /* fp fault */
	      case 33: /* fp trap */
		//result = handle_fpu_swa((vector == 32) ? 1 : 0, regs, isr);
		//if ((result < 0) || (current->thread.flags & IA64_THREAD_FPEMU_SIGFPE)) {
			//siginfo.si_signo = SIGFPE;
			//siginfo.si_errno = 0;
			//siginfo.si_code = FPE_FLTINV;
			//siginfo.si_addr = (void *) (regs->cr_iip + ia64_psr(regs)->ri);
			//siginfo.si_flags = __ISR_VALID;
			//siginfo.si_isr = isr;
			//siginfo.si_imm = 0;
			//force_sig_info(SIGFPE, &siginfo, current);
		//}
		//return;
		sprintf(buf, "FP fault/trap");
		break;

	      case 34:
		if (isr & 0x2) {
			/* Lower-Privilege Transfer Trap */
			/*
			 * Just clear PSR.lp and then return immediately: all the
			 * interesting work (e.g., signal delivery is done in the kernel
			 * exit path).
			 */
			//ia64_psr(regs)->lp = 0;
			//return;
			sprintf(buf, "Lower-Privilege Transfer trap");
		} else {
			/* Unimplemented Instr. Address Trap */
			if (user_mode(regs)) {
				//siginfo.si_signo = SIGILL;
				//siginfo.si_code = ILL_BADIADDR;
				//siginfo.si_errno = 0;
				//siginfo.si_flags = 0;
				//siginfo.si_isr = 0;
				//siginfo.si_imm = 0;
				//siginfo.si_addr = (void *) (regs->cr_iip + ia64_psr(regs)->ri);
				//force_sig_info(SIGILL, &siginfo, current);
				//return;
			}
			sprintf(buf, "Unimplemented Instruction Address fault");
		}
		break;

	      case 45:
		printk(KERN_ERR "Unexpected IA-32 exception (Trap 45)\n");
		printk(KERN_ERR "  iip - 0x%lx, ifa - 0x%lx, isr - 0x%lx\n",
		       regs->cr_iip, ifa, isr);
		//force_sig(SIGSEGV, current);
		break;

	      case 46:
		printk(KERN_ERR "Unexpected IA-32 intercept trap (Trap 46)\n");
		printk(KERN_ERR "  iip - 0x%lx, ifa - 0x%lx, isr - 0x%lx, iim - 0x%lx\n",
		       regs->cr_iip, ifa, isr, iim);
		//force_sig(SIGSEGV, current);
		return;

	      case 47:
		sprintf(buf, "IA-32 Interruption Fault (int 0x%lx)", isr >> 16);
		break;

	      default:
		sprintf(buf, "Fault %lu", vector);
		break;
	}
	//die_if_kernel(buf, regs, error);
printk("ia64_fault: %s: reflecting\n",buf);
PSCB(current,itir) = vcpu_get_itir_on_fault(current,ifa);
PSCB(current,ifa) = ifa;
reflect_interruption(isr,regs,IA64_GENEX_VECTOR);
//while(1);
	//force_sig(SIGILL, current);
}

unsigned long running_on_sim = 0;

void
do_ssc(unsigned long ssc, struct pt_regs *regs)
{
	extern unsigned long lookup_domain_mpa(struct domain *,unsigned long);
	unsigned long arg0, arg1, arg2, arg3, retval;
	char buf[2];
/**/	static int last_fd, last_count;	// FIXME FIXME FIXME
/**/					// BROKEN FOR MULTIPLE DOMAINS & SMP
/**/	struct ssc_disk_stat { int fd; unsigned count;} *stat, last_stat;

	arg0 = vcpu_get_gr(current,32);
	switch(ssc) {
	    case SSC_PUTCHAR:
		buf[0] = arg0;
		buf[1] = '\0';
		printf(buf);
		break;
	    case SSC_GETCHAR:
		retval = ia64_ssc(0,0,0,0,ssc);
		vcpu_set_gr(current,8,retval,0);
		break;
	    case SSC_WAIT_COMPLETION:
		if (arg0) {	// metaphysical address

			arg0 = translate_domain_mpaddr(arg0);
/**/			stat = (struct ssc_disk_stat *)__va(arg0);
///**/			if (stat->fd == last_fd) stat->count = last_count;
/**/			stat->count = last_count;
//if (last_count >= PAGE_SIZE) printf("ssc_wait: stat->fd=%d,last_fd=%d,last_count=%d\n",stat->fd,last_fd,last_count);
///**/			retval = ia64_ssc(arg0,0,0,0,ssc);
/**/			retval = 0;
		}
		else retval = -1L;
		vcpu_set_gr(current,8,retval,0);
		break;
	    case SSC_OPEN:
		arg1 = vcpu_get_gr(current,33);	// access rights
if (!running_on_sim) { printf("SSC_OPEN, not implemented on hardware.  (ignoring...)\n"); arg0 = 0; }
		if (arg0) {	// metaphysical address
			arg0 = translate_domain_mpaddr(arg0);
			retval = ia64_ssc(arg0,arg1,0,0,ssc);
		}
		else retval = -1L;
		vcpu_set_gr(current,8,retval,0);
		break;
	    case SSC_WRITE:
	    case SSC_READ:
//if (ssc == SSC_WRITE) printf("DOING AN SSC_WRITE\n");
		arg1 = vcpu_get_gr(current,33);
		arg2 = vcpu_get_gr(current,34);
		arg3 = vcpu_get_gr(current,35);
		if (arg2) {	// metaphysical address of descriptor
			struct ssc_disk_req *req;
			unsigned long mpaddr;
			long len;

			arg2 = translate_domain_mpaddr(arg2);
			req = (struct ssc_disk_req *) __va(arg2);
			req->len &= 0xffffffffL;	// avoid strange bug
			len = req->len;
/**/			last_fd = arg1;
/**/			last_count = len;
			mpaddr = req->addr;
//if (last_count >= PAGE_SIZE) printf("do_ssc: read fd=%d, addr=%p, len=%lx ",last_fd,mpaddr,len);
			retval = 0;
			if ((mpaddr & PAGE_MASK) != ((mpaddr+len-1) & PAGE_MASK)) {
				// do partial page first
				req->addr = translate_domain_mpaddr(mpaddr);
				req->len = PAGE_SIZE - (req->addr & ~PAGE_MASK);
				len -= req->len; mpaddr += req->len;
				retval = ia64_ssc(arg0,arg1,arg2,arg3,ssc);
				arg3 += req->len; // file offset
/**/				last_stat.fd = last_fd;
/**/				(void)ia64_ssc(__pa(&last_stat),0,0,0,SSC_WAIT_COMPLETION);
//if (last_count >= PAGE_SIZE) printf("ssc(%p,%lx)[part]=%x ",req->addr,req->len,retval);
			}
			if (retval >= 0) while (len > 0) {
				req->addr = translate_domain_mpaddr(mpaddr);
				req->len = (len > PAGE_SIZE) ? PAGE_SIZE : len;
				len -= PAGE_SIZE; mpaddr += PAGE_SIZE;
				retval = ia64_ssc(arg0,arg1,arg2,arg3,ssc);
				arg3 += req->len; // file offset
// TEMP REMOVED AGAIN				arg3 += req->len; // file offset
/**/				last_stat.fd = last_fd;
/**/				(void)ia64_ssc(__pa(&last_stat),0,0,0,SSC_WAIT_COMPLETION);
//if (last_count >= PAGE_SIZE) printf("ssc(%p,%lx)=%x ",req->addr,req->len,retval);
			}
			// set it back to the original value
			req->len = last_count;
		}
		else retval = -1L;
		vcpu_set_gr(current,8,retval,0);
//if (last_count >= PAGE_SIZE) printf("retval=%x\n",retval);
		break;
	    case SSC_CONNECT_INTERRUPT:
		arg1 = vcpu_get_gr(current,33);
		arg2 = vcpu_get_gr(current,34);
		arg3 = vcpu_get_gr(current,35);
		if (!running_on_sim) { printf("SSC_CONNECT_INTERRUPT, not implemented on hardware.  (ignoring...)\n"); break; }
		(void)ia64_ssc(arg0,arg1,arg2,arg3,ssc);
		break;
	    case SSC_NETDEV_PROBE:
		vcpu_set_gr(current,8,-1L,0);
		break;
	    default:
		printf("ia64_handle_break: bad ssc code %lx, iip=0x%lx, b0=0x%lx... spinning\n",
			ssc, regs->cr_iip, regs->b0);
		while(1);
		break;
	}
	vcpu_increment_iip(current);
}

int first_break = 1;

void
ia64_handle_break (unsigned long ifa, struct pt_regs *regs, unsigned long isr, unsigned long iim)
{
	struct domain *d = (struct domain *) current->domain;
	struct vcpu *v = current;
	extern unsigned long running_on_sim;

	if (first_break) {
		if (platform_is_hp_ski()) running_on_sim = 1;
		else running_on_sim = 0;
		first_break = 0;
	}
	if (iim == 0x80001 || iim == 0x80002) {	//FIXME: don't hardcode constant
		if (running_on_sim) do_ssc(vcpu_get_gr(current,36), regs);
		else do_ssc(vcpu_get_gr(current,36), regs);
	} 
#ifdef CRASH_DEBUG
	else if ((iim == 0 || iim == CDB_BREAK_NUM) && !user_mode(regs)) {
		if (iim == 0)
			show_registers(regs);
		debugger_trap_fatal(0 /* don't care */, regs);
	} 
#endif
	else if (iim == d->arch.breakimm) {
		/* by default, do not continue */
		v->arch.hypercall_continuation = 0;

		if (ia64_hypercall(regs) &&
		    !PSCBX(v, hypercall_continuation))
			vcpu_increment_iip(current);
	}
	else if (!PSCB(v,interrupt_collection_enabled)) {
		if (ia64_hyperprivop(iim,regs))
			vcpu_increment_iip(current);
	}
	else {
		if (iim == 0) 
			die_if_kernel("bug check", regs, iim);
		PSCB(v,iim) = iim;
		reflect_interruption(isr,regs,IA64_BREAK_VECTOR);
	}
}

void
ia64_handle_privop (unsigned long ifa, struct pt_regs *regs, unsigned long isr, unsigned long itir)
{
	IA64FAULT vector;

	vector = priv_emulate(current,regs,isr);
	if (vector != IA64_NO_FAULT && vector != IA64_RFI_IN_PROGRESS) {
		// Note: if a path results in a vector to reflect that requires
		// iha/itir (e.g. vcpu_force_data_miss), they must be set there
		reflect_interruption(isr,regs,vector);
	}
}

#define INTR_TYPE_MAX	10
UINT64 int_counts[INTR_TYPE_MAX];

void
ia64_handle_reflection (unsigned long ifa, struct pt_regs *regs, unsigned long isr, unsigned long iim, unsigned long vector)
{
	struct vcpu *v = current;
	unsigned long check_lazy_cover = 0;
	unsigned long psr = regs->cr_ipsr;

	/* Following faults shouldn'g be seen from Xen itself */
	if (!(psr & IA64_PSR_CPL)) BUG();

	switch(vector) {
	    case 8:
		vector = IA64_DIRTY_BIT_VECTOR; break;
	    case 9:
		vector = IA64_INST_ACCESS_BIT_VECTOR; break;
	    case 10:
		check_lazy_cover = 1;
		vector = IA64_DATA_ACCESS_BIT_VECTOR; break;
	    case 20:
		check_lazy_cover = 1;
		vector = IA64_PAGE_NOT_PRESENT_VECTOR; break;
	    case 22:
		vector = IA64_INST_ACCESS_RIGHTS_VECTOR; break;
	    case 23:
		check_lazy_cover = 1;
		vector = IA64_DATA_ACCESS_RIGHTS_VECTOR; break;
	    case 25:
		vector = IA64_DISABLED_FPREG_VECTOR;
		break;
	    case 26:
		if (((isr >> 4L) & 0xfL) == 1) {
			//regs->eml_unat = 0;  FIXME: DO WE NEED THIS??
			printf("ia64_handle_reflection: handling regNaT fault");
			vector = IA64_NAT_CONSUMPTION_VECTOR; break;
		}
#if 1
		// pass null pointer dereferences through with no error
		// but retain debug output for non-zero ifa
		if (!ifa) {
			vector = IA64_NAT_CONSUMPTION_VECTOR; break;
		}
#endif
printf("*** NaT fault... attempting to handle as privop\n");
printf("isr=%016lx, ifa=%016lx, iip=%016lx, ipsr=%016lx\n",
       isr, ifa, regs->cr_iip, psr);
		//regs->eml_unat = 0;  FIXME: DO WE NEED THIS???
		// certain NaT faults are higher priority than privop faults
		vector = priv_emulate(v,regs,isr);
		if (vector == IA64_NO_FAULT) {
printf("*** Handled privop masquerading as NaT fault\n");
			return;
		}
		vector = IA64_NAT_CONSUMPTION_VECTOR; break;
	    case 27:
//printf("*** Handled speculation vector, itc=%lx!\n",ia64_get_itc());
		PSCB(current,iim) = iim;
		vector = IA64_SPECULATION_VECTOR; break;
	    case 30:
		// FIXME: Should we handle unaligned refs in Xen??
		vector = IA64_UNALIGNED_REF_VECTOR; break;
	    case 32:
		printf("ia64_handle_reflection: handling FP fault");
		vector = IA64_FP_FAULT_VECTOR; break;
	    case 33:
		printf("ia64_handle_reflection: handling FP trap");
		vector = IA64_FP_TRAP_VECTOR; break;
	    case 34:
		printf("ia64_handle_reflection: handling lowerpriv trap");
		vector = IA64_LOWERPRIV_TRANSFER_TRAP_VECTOR; break;
	    case 35:
		printf("ia64_handle_reflection: handling taken branch trap");
		vector = IA64_TAKEN_BRANCH_TRAP_VECTOR; break;
	    case 36:
		printf("ia64_handle_reflection: handling single step trap");
		vector = IA64_SINGLE_STEP_TRAP_VECTOR; break;

	    default:
		printf("ia64_handle_reflection: unhandled vector=0x%lx\n",vector);
		while(vector);
		return;
	}
	if (check_lazy_cover && (isr & IA64_ISR_IR) && handle_lazy_cover(v, isr, regs)) return;
	PSCB(current,ifa) = ifa;
	PSCB(current,itir) = vcpu_get_itir_on_fault(v,ifa);
	reflect_interruption(isr,regs,vector);
}

unsigned long __hypercall_create_continuation(
	unsigned int op, unsigned int nr_args, ...)
{
    struct mc_state *mcs = &mc_state[smp_processor_id()];
    struct vcpu *v = current;
    unsigned int i;
    va_list args;

    va_start(args, nr_args);
    if ( test_bit(_MCSF_in_multicall, &mcs->flags) ) {
	panic("PREEMPT happen in multicall\n");	// Not support yet
    } else {
	vcpu_set_gr(v, 2, op, 0);
	for ( i = 0; i < nr_args; i++) {
	    switch (i) {
	    case 0: vcpu_set_gr(v, 14, va_arg(args, unsigned long), 0);
		    break;
	    case 1: vcpu_set_gr(v, 15, va_arg(args, unsigned long), 0);
		    break;
	    case 2: vcpu_set_gr(v, 16, va_arg(args, unsigned long), 0);
		    break;
	    case 3: vcpu_set_gr(v, 17, va_arg(args, unsigned long), 0);
		    break;
	    case 4: vcpu_set_gr(v, 18, va_arg(args, unsigned long), 0);
		    break;
	    default: panic("Too many args for hypercall continuation\n");
		    break;
	    }
	}
    }
    v->arch.hypercall_continuation = 1;
    va_end(args);
    return op;
}

