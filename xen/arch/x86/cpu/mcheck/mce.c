/*
 * mce.c - x86 Machine Check Exception Reporting
 * (c) 2002 Alan Cox <alan@redhat.com>, Dave Jones <davej@codemonkey.org.uk>
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/config.h>
#include <xen/smp.h>
#include <xen/errno.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/cpumask.h>
#include <xen/event.h>
#include <xen/guest_access.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"

int mce_disabled = 0;
unsigned int nr_mce_banks;

EXPORT_SYMBOL_GPL(nr_mce_banks);	/* non-fatal.o */

static void mcinfo_clear(struct mc_info *);

#define	SEG_PL(segsel) ((segsel) & 0x3)

#if 1	/* XXFM switch to 0 for putback */

#define	x86_mcerr(str, err) _x86_mcerr(str, err)

static int _x86_mcerr(const char *msg, int err)
{
	printk("x86_mcerr: %s, returning %d\n",
	    msg != NULL ? msg : "", err);
	return err;
}
#else
#define x86_mcerr(str,err)
#endif

cpu_banks_t mca_allbanks;

/* Handle unconfigured int18 (should never happen) */
static void unexpected_machine_check(struct cpu_user_regs *regs, long error_code)
{
	printk(XENLOG_ERR "CPU#%d: Unexpected int18 (Machine Check).\n",
		smp_processor_id());
}


static x86_mce_vector_t _machine_check_vector = unexpected_machine_check;

void x86_mce_vector_register(x86_mce_vector_t hdlr)
{
	_machine_check_vector = hdlr;
	wmb();
}

/* Call the installed machine check handler for this CPU setup. */

void machine_check_vector(struct cpu_user_regs *regs, long error_code)
{
	_machine_check_vector(regs, error_code);
}

/* Init machine check callback handler
 * It is used to collect additional information provided by newer
 * CPU families/models without the need to duplicate the whole handler.
 * This avoids having many handlers doing almost nearly the same and each
 * with its own tweaks ands bugs. */
static x86_mce_callback_t mc_callback_bank_extended = NULL;

void x86_mce_callback_register(x86_mce_callback_t cbfunc)
{
	mc_callback_bank_extended = cbfunc;
}

/* Utility function to perform MCA bank telemetry readout and to push that
 * telemetry towards an interested dom0 for logging and diagnosis.
 * The caller - #MC handler or MCA poll function - must arrange that we
 * do not migrate cpus. */

/* XXFM Could add overflow counting? */
mctelem_cookie_t mcheck_mca_logout(enum mca_source who, cpu_banks_t bankmask,
    struct mca_summary *sp)
{
	struct vcpu *v = current;
	struct domain *d;
	uint64_t gstatus, status, addr, misc;
	struct mcinfo_global mcg;	/* on stack */
	struct mcinfo_common *mic;
	struct mcinfo_global *mig;	/* on stack */
	mctelem_cookie_t mctc = NULL;
	uint32_t uc = 0, pcc = 0;
	struct mc_info *mci = NULL;
	mctelem_class_t which = MC_URGENT;	/* XXXgcc */
	unsigned int cpu_nr;
	int errcnt = 0;
	int i;
	enum mca_extinfo cbret = MCA_EXTINFO_IGNORED;

	cpu_nr = smp_processor_id();
	BUG_ON(cpu_nr != v->processor);

	rdmsrl(MSR_IA32_MCG_STATUS, gstatus);

	memset(&mcg, 0, sizeof (mcg));
	mcg.common.type = MC_TYPE_GLOBAL;
	mcg.common.size = sizeof (mcg);
	if (v != NULL && ((d = v->domain) != NULL)) {
		mcg.mc_domid = d->domain_id;
		mcg.mc_vcpuid = v->vcpu_id;
	} else {
		mcg.mc_domid = -1;
		mcg.mc_vcpuid = -1;
	}
	mcg.mc_gstatus = gstatus;	/* MCG_STATUS */

	switch (who) {
	case MCA_MCE_HANDLER:
		mcg.mc_flags = MC_FLAG_MCE;
		which = MC_URGENT;
		break;

	case MCA_POLLER:
	case MCA_RESET:
		mcg.mc_flags = MC_FLAG_POLLED;
		which = MC_NONURGENT;
		break;

	case MCA_CMCI_HANDLER:
		mcg.mc_flags = MC_FLAG_CMCI;
		which = MC_NONURGENT;
		break;

	default:
		BUG();
	}

	/* Retrieve detector information */
	x86_mc_get_cpu_info(cpu_nr, &mcg.mc_socketid,
	    &mcg.mc_coreid, &mcg.mc_core_threadid,
	    &mcg.mc_apicid, NULL, NULL, NULL);

	for (i = 0; i < 32 && i < nr_mce_banks; i++) {
		struct mcinfo_bank mcb;		/* on stack */

		/* Skip bank if corresponding bit in bankmask is clear */
		if (!test_bit(i, bankmask))
			continue;

		rdmsrl(MSR_IA32_MC0_STATUS + i * 4, status);
		if (!(status & MCi_STATUS_VAL))
			continue;	/* this bank has no valid telemetry */

		/* If this is the first bank with valid MCA DATA, then
		 * try to reserve an entry from the urgent/nonurgent queue
		 * depending on whethere we are called from an exception or
		 * a poller;  this can fail (for example dom0 may not
		 * yet have consumed past telemetry). */
		if (errcnt == 0) {
			if ((mctc = mctelem_reserve(which)) != NULL) {
				mci = mctelem_dataptr(mctc);
				mcinfo_clear(mci);
			}
		}

		memset(&mcb, 0, sizeof (mcb));
		mcb.common.type = MC_TYPE_BANK;
		mcb.common.size = sizeof (mcb);
		mcb.mc_bank = i;
		mcb.mc_status = status;

		/* form a mask of which banks have logged uncorrected errors */
		if ((status & MCi_STATUS_UC) != 0)
			uc |= (1 << i);

		/* likewise for those with processor context corrupt */
		if ((status & MCi_STATUS_PCC) != 0)
			pcc |= (1 << i);

		addr = misc = 0;

		if (status & MCi_STATUS_ADDRV) {
			rdmsrl(MSR_IA32_MC0_ADDR + 4 * i, addr);
			d = maddr_get_owner(addr);
			if (d != NULL && (who == MCA_POLLER ||
			    who == MCA_CMCI_HANDLER))
				mcb.mc_domid = d->domain_id;
		}

		if (status & MCi_STATUS_MISCV)
			rdmsrl(MSR_IA32_MC0_MISC + 4 * i, misc);

		mcb.mc_addr = addr;
		mcb.mc_misc = misc;

		if (who == MCA_CMCI_HANDLER) {
			rdmsrl(MSR_IA32_MC0_CTL2 + i, mcb.mc_ctrl2);
			rdtscll(mcb.mc_tsc);
		}

		/* Increment the error count;  if this is the first bank
		 * with a valid error then add the global info to the mcinfo. */
		if (errcnt++ == 0 && mci != NULL)
			x86_mcinfo_add(mci, &mcg);

		/* Add the bank data */
		if (mci != NULL)
			x86_mcinfo_add(mci, &mcb);

		if (mc_callback_bank_extended && cbret != MCA_EXTINFO_GLOBAL) {
			cbret = mc_callback_bank_extended(mci, i, status);
		}

		/* Clear status */
		wrmsrl(MSR_IA32_MC0_STATUS + 4 * i, 0x0ULL);
		wmb();
	}

	if (mci != NULL && errcnt > 0) {
		x86_mcinfo_lookup(mic, mci, MC_TYPE_GLOBAL);
		mig = (struct mcinfo_global *)mic;
		if (pcc)
			mcg.mc_flags |= MC_FLAG_UNCORRECTABLE;
		else if (uc)
			mcg.mc_flags |= MC_FLAG_RECOVERABLE;
		else
			mcg.mc_flags |= MC_FLAG_CORRECTABLE;
	}


	if (sp) {
		sp->errcnt = errcnt;
		sp->ripv = (gstatus & MCG_STATUS_RIPV) != 0;
		sp->eipv = (gstatus & MCG_STATUS_EIPV) != 0;
		sp->uc = uc;
		sp->pcc = pcc;
	}

	return mci != NULL ? mctc : NULL;	/* may be NULL */
}

#define DOM_NORMAL	0
#define DOM0_TRAP	1
#define DOMU_TRAP	2
#define DOMU_KILLED	4

/* Shared #MC handler. */
void mcheck_cmn_handler(struct cpu_user_regs *regs, long error_code,
    cpu_banks_t bankmask)
{
	int xen_state_lost, dom0_state_lost, domU_state_lost;
	struct vcpu *v = current;
	struct domain *curdom = v->domain;
	domid_t domid = curdom->domain_id;
	int ctx_xen, ctx_dom0, ctx_domU;
	uint32_t dom_state = DOM_NORMAL;
	mctelem_cookie_t mctc = NULL;
	struct mca_summary bs;
	struct mc_info *mci = NULL;
	int irqlocked = 0;
	uint64_t gstatus;
	int ripv;

	/* This handler runs as interrupt gate. So IPIs from the
	 * polling service routine are defered until we're finished.
	 */

	/* Disable interrupts for the _vcpu_. It may not re-scheduled to
	 * another physical CPU. */
	vcpu_schedule_lock_irq(v);
	irqlocked = 1;

	/* Read global status;  if it does not indicate machine check
	 * in progress then bail as long as we have a valid ip to return to. */
	rdmsrl(MSR_IA32_MCG_STATUS, gstatus);
	ripv = ((gstatus & MCG_STATUS_RIPV) != 0);
	if (!(gstatus & MCG_STATUS_MCIP) && ripv) {
		add_taint(TAINT_MACHINE_CHECK); /* questionable */
		vcpu_schedule_unlock_irq(v);
		irqlocked = 0;
		goto cmn_handler_done;
	}

	/* Go and grab error telemetry.  We must choose whether to commit
	 * for logging or dismiss the cookie that is returned, and must not
	 * reference the cookie after that action.
	 */
	mctc = mcheck_mca_logout(MCA_MCE_HANDLER, bankmask, &bs);
	if (mctc != NULL)
		mci = (struct mc_info *)mctelem_dataptr(mctc);

	/* Clear MCIP or another #MC will enter shutdown state */
	gstatus &= ~MCG_STATUS_MCIP;
	wrmsrl(MSR_IA32_MCG_STATUS, gstatus);
	wmb();

	/* If no valid errors and our stack is intact, we're done */
	if (ripv && bs.errcnt == 0) {
		vcpu_schedule_unlock_irq(v);
		irqlocked = 0;
		goto cmn_handler_done;
	}

	if (bs.uc || bs.pcc)
		add_taint(TAINT_MACHINE_CHECK);

	/* Machine check exceptions will usually be for UC and/or PCC errors,
	 * but it is possible to configure machine check for some classes
	 * of corrected error.
	 *
	 * UC errors could compromise any domain or the hypervisor
	 * itself - for example a cache writeback of modified data that
	 * turned out to be bad could be for data belonging to anyone, not
	 * just the current domain.  In the absence of known data poisoning
	 * to prevent consumption of such bad data in the system we regard
	 * all UC errors as terminal.  It may be possible to attempt some
	 * heuristics based on the address affected, which guests have
	 * mappings to that mfn etc.
	 *
	 * PCC errors apply to the current context.
	 *
	 * If MCG_STATUS indicates !RIPV then even a #MC that is not UC
	 * and not PCC is terminal - the return instruction pointer
	 * pushed onto the stack is bogus.  If the interrupt context is
	 * the hypervisor or dom0 the game is over, otherwise we can
	 * limit the impact to a single domU but only if we trampoline
	 * somewhere safely - we can't return and unwind the stack.
	 * Since there is no trampoline in place we will treat !RIPV
	 * as terminal for any context.
	 */
	ctx_xen = SEG_PL(regs->cs) == 0;
	ctx_dom0 = !ctx_xen && (domid == dom0->domain_id);
	ctx_domU = !ctx_xen && !ctx_dom0;

	xen_state_lost = bs.uc != 0 || (ctx_xen && (bs.pcc || !ripv)) ||
	    !ripv;
	dom0_state_lost = bs.uc != 0 || (ctx_dom0 && (bs.pcc || !ripv));
	domU_state_lost = bs.uc != 0 || (ctx_domU && (bs.pcc || !ripv));

	if (xen_state_lost) {
		/* Now we are going to panic anyway. Allow interrupts, so that
		 * printk on serial console can work. */
		vcpu_schedule_unlock_irq(v);
		irqlocked = 0;

		printk("Terminal machine check exception occured in "
		    "hypervisor context.\n");

		/* If MCG_STATUS_EIPV indicates, the IP on the stack is related
		 * to the error then it makes sense to print a stack trace.
		 * That can be useful for more detailed error analysis and/or
		 * error case studies to figure out, if we can clear
		 * xen_impacted and kill a DomU instead
		 * (i.e. if a guest only control structure is affected, but then
		 * we must ensure the bad pages are not re-used again).
		 */
		if (bs.eipv & MCG_STATUS_EIPV) {
			printk("MCE: Instruction Pointer is related to the "
			    "error, therefore print the execution state.\n");
			show_execution_state(regs);
		}

		/* Commit the telemetry so that panic flow can find it. */
		if (mctc != NULL) {
			x86_mcinfo_dump(mci);
			mctelem_commit(mctc);
		}
		mc_panic("Hypervisor state lost due to machine check "
		    "exception.\n");
		/*NOTREACHED*/
	}

	/*
	 * Xen hypervisor state is intact.  If dom0 state is lost then
	 * give it a chance to decide what to do if it has registered
	 * a handler for this event, otherwise panic.
	 *
	 * XXFM Could add some Solaris dom0 contract kill here?
	 */
	if (dom0_state_lost) {
		if (guest_has_trap_callback(dom0, 0, TRAP_machine_check)) {
			dom_state = DOM0_TRAP;
			send_guest_trap(dom0, 0, TRAP_machine_check);
			/* XXFM case of return with !ripv ??? */
		} else {
			/* Commit telemetry for panic flow. */
			if (mctc != NULL) {
				x86_mcinfo_dump(mci);
				mctelem_commit(mctc);
			}
			mc_panic("Dom0 state lost due to machine check "
			    "exception\n");
			/*NOTREACHED*/
		}
	}

	/*
	 * If a domU has lost state then send it a trap if it has registered
	 * a handler, otherwise crash the domain.
	 * XXFM Revisit this functionality.
	 */
	if (domU_state_lost) {
		if (guest_has_trap_callback(v->domain, v->vcpu_id,
		    TRAP_machine_check)) {
			dom_state = DOMU_TRAP;
			send_guest_trap(curdom, v->vcpu_id,
			    TRAP_machine_check);
		} else {
			dom_state = DOMU_KILLED;
			/* Enable interrupts. This basically results in
			 * calling sti on the *physical* cpu. But after
			 * domain_crash() the vcpu pointer is invalid.
			 * Therefore, we must unlock the irqs before killing
			 * it. */
			vcpu_schedule_unlock_irq(v);
			irqlocked = 0;

			/* DomU is impacted. Kill it and continue. */
			domain_crash(curdom);
		}
	}

	switch (dom_state) {
	case DOM0_TRAP:
	case DOMU_TRAP:
		/* Enable interrupts. */
		vcpu_schedule_unlock_irq(v);
		irqlocked = 0;

		/* guest softirqs and event callbacks are scheduled
		 * immediately after this handler exits. */
		break;
	case DOMU_KILLED:
		/* Nothing to do here. */
		break;

	case DOM_NORMAL:
		vcpu_schedule_unlock_irq(v);
		irqlocked = 0;
		break;
	}

cmn_handler_done:
	BUG_ON(irqlocked);
	BUG_ON(!ripv);

	if (bs.errcnt) {
		/* Not panicing, so forward telemetry to dom0 now if it
		 * is interested. */
		if (guest_enabled_event(dom0->vcpu[0], VIRQ_MCA)) {
			if (mctc != NULL)
				mctelem_commit(mctc);
			send_guest_global_virq(dom0, VIRQ_MCA);
		} else {
			x86_mcinfo_dump(mci);
			if (mctc != NULL)
				mctelem_dismiss(mctc);
		}
	} else if (mctc != NULL) {
		mctelem_dismiss(mctc);
	}
}

static int amd_mcheck_init(struct cpuinfo_x86 *ci)
{
	int rc = 0;

	switch (ci->x86) {
	case 6:
		rc = amd_k7_mcheck_init(ci);
		break;

	case 0xf:
		rc = amd_k8_mcheck_init(ci);
		break;

	case 0x10:
		rc = amd_f10_mcheck_init(ci);
		break;

	default:
		/* Assume that machine check support is available.
		 * The minimum provided support is at least the K8. */
		rc = amd_k8_mcheck_init(ci);
	}

	return rc;
}

/*check the existence of Machine Check*/
int mce_available(struct cpuinfo_x86 *c)
{
	return cpu_has(c, X86_FEATURE_MCE) && cpu_has(c, X86_FEATURE_MCA);
}

/*
 * Check if bank 0 is usable for MCE. It isn't for AMD K7,
 * and Intel P6 family before model 0x1a.
 */
int mce_firstbank(struct cpuinfo_x86 *c)
{
	if (c->x86 == 6) {
		if (c->x86_vendor == X86_VENDOR_AMD)
			return 1;

		if (c->x86_vendor == X86_VENDOR_INTEL && c->x86_model < 0x1a)
			return 1;
	}

	return 0;
}

/* This has to be run for each processor */
void mcheck_init(struct cpuinfo_x86 *c)
{
	int inited = 0, i;

	if (mce_disabled == 1) {
		printk(XENLOG_INFO "MCE support disabled by bootparam\n");
		return;
	}

	for (i = 0; i < MAX_NR_BANKS; i++)
		set_bit(i,mca_allbanks);

	/* Enforce at least MCE support in CPUID information.  Individual
	 * families may also need to enforce a check for MCA support. */
	if (!cpu_has(c, X86_FEATURE_MCE)) {
		printk(XENLOG_INFO "CPU%i: No machine check support available\n",
			smp_processor_id());
		return;
	}

	mctelem_init(sizeof (struct mc_info));

	switch (c->x86_vendor) {
	case X86_VENDOR_AMD:
		inited = amd_mcheck_init(c);
		break;

	case X86_VENDOR_INTEL:
		switch (c->x86) {
		case 5:
#ifndef CONFIG_X86_64
			inited = intel_p5_mcheck_init(c);
#endif
			break;

		case 6:
		case 15:
			inited = intel_mcheck_init(c);
			break;
		}
		break;

#ifndef CONFIG_X86_64
	case X86_VENDOR_CENTAUR:
		if (c->x86==5) {
			inited = winchip_mcheck_init(c);
		}
		break;
#endif

	default:
		break;
	}

	if (!inited)
		printk(XENLOG_INFO "CPU%i: No machine check initialization\n",
		    smp_processor_id());
}


static void __init mcheck_disable(char *str)
{
	mce_disabled = 1;
}

static void __init mcheck_enable(char *str)
{
	mce_disabled = -1;
}

custom_param("nomce", mcheck_disable);
custom_param("mce", mcheck_enable);

static void mcinfo_clear(struct mc_info *mi)
{
	memset(mi, 0, sizeof(struct mc_info));
	x86_mcinfo_nentries(mi) = 0;
}

int x86_mcinfo_add(struct mc_info *mi, void *mcinfo)
{
	int i;
	unsigned long end1, end2;
	struct mcinfo_common *mic, *mic_base, *mic_index;

	mic = (struct mcinfo_common *)mcinfo;
	mic_index = mic_base = x86_mcinfo_first(mi);

	/* go to first free entry */
	for (i = 0; i < x86_mcinfo_nentries(mi); i++) {
		mic_index = x86_mcinfo_next(mic_index);
	}

	/* check if there is enough size */
	end1 = (unsigned long)((uint8_t *)mic_base + sizeof(struct mc_info));
	end2 = (unsigned long)((uint8_t *)mic_index + mic->size);

	if (end1 < end2)
		return x86_mcerr("mcinfo_add: no more sparc", -ENOSPC);

	/* there's enough space. add entry. */
	memcpy(mic_index, mic, mic->size);
	x86_mcinfo_nentries(mi)++;

	return 0;
}

/* Dump machine check information in a format,
 * mcelog can parse. This is used only when
 * Dom0 does not take the notification. */
void x86_mcinfo_dump(struct mc_info *mi)
{
	struct mcinfo_common *mic = NULL;
	struct mcinfo_global *mc_global;
	struct mcinfo_bank *mc_bank;

	/* first print the global info */
	x86_mcinfo_lookup(mic, mi, MC_TYPE_GLOBAL);
	if (mic == NULL)
		return;
	mc_global = (struct mcinfo_global *)mic;
	if (mc_global->mc_flags & MC_FLAG_MCE) {
		printk(XENLOG_WARNING
			"CPU%d: Machine Check Exception: %16"PRIx64"\n",
			mc_global->mc_coreid, mc_global->mc_gstatus);
	} else {
		printk(XENLOG_WARNING "MCE: The hardware reports a non "
			"fatal, correctable incident occured on "
			"CPU %d.\n",
			mc_global->mc_coreid);
	}

	/* then the bank information */
	x86_mcinfo_lookup(mic, mi, MC_TYPE_BANK); /* finds the first entry */
	do {
		if (mic == NULL)
			return;
		if (mic->type != MC_TYPE_BANK)
			goto next;

		mc_bank = (struct mcinfo_bank *)mic;

		printk(XENLOG_WARNING "Bank %d: %16"PRIx64,
			mc_bank->mc_bank,
			mc_bank->mc_status);
		if (mc_bank->mc_status & MCi_STATUS_MISCV)
			printk("[%16"PRIx64"]", mc_bank->mc_misc);
		if (mc_bank->mc_status & MCi_STATUS_ADDRV)
			printk(" at %16"PRIx64, mc_bank->mc_addr);

		printk("\n");
next:
		mic = x86_mcinfo_next(mic); /* next entry */
		if ((mic == NULL) || (mic->size == 0))
			break;
	} while (1);
}

static void do_mc_get_cpu_info(void *v)
{
	int cpu = smp_processor_id();
	int cindex, cpn;
	struct cpuinfo_x86 *c;
	xen_mc_logical_cpu_t *log_cpus, *xcp;
	uint32_t junk, ebx;

	log_cpus = v;
	c = &cpu_data[cpu];
	cindex = 0;
	cpn = cpu - 1;

	/*
	 * Deal with sparse masks, condensed into a contig array.
	 */
	while (cpn >= 0) {
		if (cpu_isset(cpn, cpu_online_map))
			cindex++;
		cpn--;
	}

	xcp = &log_cpus[cindex];
	c = &cpu_data[cpu];
	xcp->mc_cpunr = cpu;
	x86_mc_get_cpu_info(cpu, &xcp->mc_chipid,
	    &xcp->mc_coreid, &xcp->mc_threadid,
	    &xcp->mc_apicid, &xcp->mc_ncores,
	    &xcp->mc_ncores_active, &xcp->mc_nthreads);
	xcp->mc_cpuid_level = c->cpuid_level;
	xcp->mc_family = c->x86;
	xcp->mc_vendor = c->x86_vendor;
	xcp->mc_model = c->x86_model;
	xcp->mc_step = c->x86_mask;
	xcp->mc_cache_size = c->x86_cache_size;
	xcp->mc_cache_alignment = c->x86_cache_alignment;
	memcpy(xcp->mc_vendorid, c->x86_vendor_id, sizeof xcp->mc_vendorid);
	memcpy(xcp->mc_brandid, c->x86_model_id, sizeof xcp->mc_brandid);
	memcpy(xcp->mc_cpu_caps, c->x86_capability, sizeof xcp->mc_cpu_caps);

	/*
	 * This part needs to run on the CPU itself.
	 */
	xcp->mc_nmsrvals = __MC_NMSRS;
	xcp->mc_msrvalues[0].reg = MSR_IA32_MCG_CAP;
	rdmsrl(MSR_IA32_MCG_CAP, xcp->mc_msrvalues[0].value);

	if (c->cpuid_level >= 1) {
		cpuid(1, &junk, &ebx, &junk, &junk);
		xcp->mc_clusterid = (ebx >> 24) & 0xff;
	} else
		xcp->mc_clusterid = hard_smp_processor_id();
}


void x86_mc_get_cpu_info(unsigned cpu, uint32_t *chipid, uint16_t *coreid,
			 uint16_t *threadid, uint32_t *apicid,
			 unsigned *ncores, unsigned *ncores_active,
			 unsigned *nthreads)
{
	struct cpuinfo_x86 *c;

	*apicid = cpu_physical_id(cpu);
	c = &cpu_data[cpu];
	if (c->apicid == BAD_APICID) {
		*chipid = cpu;
		*coreid = 0;
		*threadid = 0;
		if (ncores != NULL)
			*ncores = 1;
		if (ncores_active != NULL)
			*ncores_active = 1;
		if (nthreads != NULL)
			*nthreads = 1;
	} else {
		*chipid = phys_proc_id[cpu];
		if (c->x86_max_cores > 1)
			*coreid = cpu_core_id[cpu];
		else
			*coreid = 0;
		*threadid = c->apicid & ((1 << (c->x86_num_siblings - 1)) - 1);
		if (ncores != NULL)
			*ncores = c->x86_max_cores;
		if (ncores_active != NULL)
			*ncores_active = c->booted_cores;
		if (nthreads != NULL)
			*nthreads = c->x86_num_siblings;
	}
}

#if BITS_PER_LONG == 64

#define	ID2COOKIE(id)	((mctelem_cookie_t)(id))
#define	COOKIE2ID(c) ((uint64_t)(c))

#elif BITS_PER_LONG == 32

#define	ID2COOKIE(id)	((mctelem_cookie_t)(uint32_t)((id) & 0xffffffffU))
#define	COOKIE2ID(c)	((uint64_t)(uint32_t)(c))

#elif defined(BITS_PER_LONG)
#error BITS_PER_LONG has unexpected value
#else
#error BITS_PER_LONG definition absent
#endif

/* Machine Check Architecture Hypercall */
long do_mca(XEN_GUEST_HANDLE(xen_mc_t) u_xen_mc)
{
	long ret = 0;
	struct xen_mc curop, *op = &curop;
	struct vcpu *v = current;
	struct xen_mc_fetch *mc_fetch;
	struct xen_mc_physcpuinfo *mc_physcpuinfo;
	uint32_t flags, cmdflags;
	int nlcpu;
	xen_mc_logical_cpu_t *log_cpus = NULL;
	mctelem_cookie_t mctc;
	mctelem_class_t which;

	if ( copy_from_guest(op, u_xen_mc, 1) )
		return x86_mcerr("do_mca: failed copyin of xen_mc_t", -EFAULT);

	if ( op->interface_version != XEN_MCA_INTERFACE_VERSION )
		return x86_mcerr("do_mca: interface version mismatch", -EACCES);

	switch (op->cmd) {
	case XEN_MC_fetch:
		mc_fetch = &op->u.mc_fetch;
		cmdflags = mc_fetch->flags;

		/* This hypercall is for Dom0 only */
		if (!IS_PRIV(v->domain) )
			return x86_mcerr(NULL, -EPERM);

		switch (cmdflags & (XEN_MC_NONURGENT | XEN_MC_URGENT)) {
		case XEN_MC_NONURGENT:
			which = MC_NONURGENT;
			break;

		case XEN_MC_URGENT:
			which = MC_URGENT;
			break;

		default:
			return x86_mcerr("do_mca fetch: bad cmdflags", -EINVAL);
		}

		flags = XEN_MC_OK;

		if (cmdflags & XEN_MC_ACK) {
			mctelem_cookie_t cookie = ID2COOKIE(mc_fetch->fetch_id);
			mctelem_ack(which, cookie);
		} else {
			if (guest_handle_is_null(mc_fetch->data))
				return x86_mcerr("do_mca fetch: guest buffer "
				    "invalid", -EINVAL);

			if ((mctc = mctelem_consume_oldest_begin(which))) {
				struct mc_info *mcip = mctelem_dataptr(mctc);
				if (copy_to_guest(mc_fetch->data, mcip, 1)) {
					ret = -EFAULT;
					flags |= XEN_MC_FETCHFAILED;
					mc_fetch->fetch_id = 0;
				} else {
					mc_fetch->fetch_id = COOKIE2ID(mctc);
				}
				mctelem_consume_oldest_end(mctc);
			} else {
				/* There is no data */
				flags |= XEN_MC_NODATA;
				mc_fetch->fetch_id = 0;
			}

			mc_fetch->flags = flags;
			if (copy_to_guest(u_xen_mc, op, 1) != 0)
				ret = -EFAULT;
		}

		break;

	case XEN_MC_notifydomain:
		return x86_mcerr("do_mca notify unsupported", -EINVAL);

	case XEN_MC_physcpuinfo:
		if ( !IS_PRIV(v->domain) )
			return x86_mcerr("do_mca cpuinfo", -EPERM);

		mc_physcpuinfo = &op->u.mc_physcpuinfo;
		nlcpu = num_online_cpus();

		if (!guest_handle_is_null(mc_physcpuinfo->info)) {
			if (mc_physcpuinfo->ncpus <= 0)
				return x86_mcerr("do_mca cpuinfo: ncpus <= 0",
				    -EINVAL);
			nlcpu = min(nlcpu, (int)mc_physcpuinfo->ncpus);
			log_cpus = xmalloc_array(xen_mc_logical_cpu_t, nlcpu);
			if (log_cpus == NULL)
				return x86_mcerr("do_mca cpuinfo", -ENOMEM);

			if (on_each_cpu(do_mc_get_cpu_info, log_cpus,
			    1, 1) != 0) {
				xfree(log_cpus);
				return x86_mcerr("do_mca cpuinfo", -EIO);
			}
		}

		mc_physcpuinfo->ncpus = nlcpu;

		if (copy_to_guest(u_xen_mc, op, 1)) {
			if (log_cpus != NULL)
				xfree(log_cpus);
			return x86_mcerr("do_mca cpuinfo", -EFAULT);
		}

		if (!guest_handle_is_null(mc_physcpuinfo->info)) {
			if (copy_to_guest(mc_physcpuinfo->info,
			    log_cpus, nlcpu))
				ret = -EFAULT;
			xfree(log_cpus);
		}
		break;

	default:
		return x86_mcerr("do_mca: bad command", -EINVAL);
	}

	return ret;
}

void mc_panic(char *s)
{
    console_start_sync();
    printk("Fatal machine check: %s\n", s);
    printk("\n"
           "****************************************\n"
           "\n"
           "   The processor has reported a hardware error which cannot\n"
           "   be recovered from.  Xen will now reboot the machine.\n");
    panic("HARDWARE ERROR");
}
