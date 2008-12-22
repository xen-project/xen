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

#include <asm/processor.h> 
#include <asm/system.h>

#include "mce.h"
#include "x86_mca.h"

int mce_disabled = 0;
unsigned int nr_mce_banks;

EXPORT_SYMBOL_GPL(nr_mce_banks);	/* non-fatal.o */

/* XXX For now a fixed array is used. Later this should be changed
 * to a dynamic allocated array with the size calculated in relation
 * to physical cpus present in the machine.
 * The more physical cpus are available, the more entries you need.
 */
#define MAX_MCINFO	20

struct mc_machine_notify {
	struct mc_info mc;
	uint32_t fetch_idx;
	uint32_t valid;
};

struct mc_machine {

	/* Array structure used for collecting machine check error telemetry. */
	struct mc_info mc[MAX_MCINFO];

	/* We handle multiple machine check reports lockless by
	 * iterating through the array using the producer/consumer concept.
	 */
	/* Producer array index to fill with machine check error data.
	 * Index must be increased atomically. */
	uint32_t error_idx;

	/* Consumer array index to fetch machine check error data from.
	 * Index must be increased atomically. */
	uint32_t fetch_idx;

	/* Integer array holding the indeces of the mc array that allows
         * a Dom0 to notify a DomU to re-fetch the same machine check error
         * data. The notification and refetch also uses its own 
	 * producer/consumer mechanism, because Dom0 may decide to not report
	 * every error to the impacted DomU.
	 */
	struct mc_machine_notify notify[MAX_MCINFO];

	/* Array index to get fetch_idx from.
	 * Index must be increased atomically. */
	uint32_t notifyproducer_idx;
	uint32_t notifyconsumer_idx;
};

/* Global variable with machine check information. */
struct mc_machine mc_data;

/* Handle unconfigured int18 (should never happen) */
static void unexpected_machine_check(struct cpu_user_regs *regs, long error_code)
{	
	printk(XENLOG_ERR "CPU#%d: Unexpected int18 (Machine Check).\n",
		smp_processor_id());
}


/* Call the installed machine check handler for this CPU setup. */
void (*machine_check_vector)(struct cpu_user_regs *regs, long error_code) = unexpected_machine_check;

/* Init machine check callback handler
 * It is used to collect additional information provided by newer
 * CPU families/models without the need to duplicate the whole handler.
 * This avoids having many handlers doing almost nearly the same and each
 * with its own tweaks ands bugs. */
int (*mc_callback_bank_extended)(struct mc_info *, uint16_t, uint64_t) = NULL;


static void amd_mcheck_init(struct cpuinfo_x86 *ci)
{

	switch (ci->x86) {
	case 6:
		amd_k7_mcheck_init(ci);
		break;

	case 0xf:
		amd_k8_mcheck_init(ci);
		break;

	case 0x10:
		amd_f10_mcheck_init(ci);
		break;

	default:
		/* Assume that machine check support is available.
		 * The minimum provided support is at least the K8. */
		amd_k8_mcheck_init(ci);
	}
}

/*check the existence of Machine Check*/
int mce_available(struct cpuinfo_x86 *c)
{
	return cpu_has(c, X86_FEATURE_MCE) && cpu_has(c, X86_FEATURE_MCA);
}

/* This has to be run for each processor */
void mcheck_init(struct cpuinfo_x86 *c)
{
	if (mce_disabled == 1) {
		printk(XENLOG_INFO "MCE support disabled by bootparam\n");
		return;
	}

	if (!cpu_has(c, X86_FEATURE_MCE)) {
		printk(XENLOG_INFO "CPU%i: No machine check support available\n",
			smp_processor_id());
		return;
	}

	memset(&mc_data, 0, sizeof(struct mc_machine));

	switch (c->x86_vendor) {
	case X86_VENDOR_AMD:
		amd_mcheck_init(c);
		break;

	case X86_VENDOR_INTEL:
#ifndef CONFIG_X86_64
		if (c->x86==5)
			intel_p5_mcheck_init(c);
#endif
		/*If it is P6 or P4 family, including CORE 2 DUO series*/
		if (c->x86 == 6 || c->x86==15)
		{
			printk(KERN_DEBUG "MCE: Intel newly family MC Init\n");
			intel_mcheck_init(c);
		}
		break;

#ifndef CONFIG_X86_64
	case X86_VENDOR_CENTAUR:
		if (c->x86==5)
			winchip_mcheck_init(c);
		break;
#endif

	default:
		break;
	}
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


#include <xen/guest_access.h>
#include <asm/traps.h>

struct mc_info *x86_mcinfo_getptr(void)
{
	struct mc_info *mi;
	uint32_t entry, next;

	for (;;) {
		entry = mc_data.error_idx;
		smp_rmb();
		next = entry + 1;
		if (cmpxchg(&mc_data.error_idx, entry, next) == entry)
			break;
	}

	mi = &(mc_data.mc[(entry % MAX_MCINFO)]);
	BUG_ON(mc_data.error_idx < mc_data.fetch_idx);

	return mi;
}

static int x86_mcinfo_matches_guest(const struct mc_info *mi,
			const struct domain *d, const struct vcpu *v)
{
	struct mcinfo_common *mic;
	struct mcinfo_global *mig;

	x86_mcinfo_lookup(mic, mi, MC_TYPE_GLOBAL);
	mig = (struct mcinfo_global *)mic;
	if (mig == NULL)
		return 0;

	if (d->domain_id != mig->mc_domid)
		return 0;

	if (v->vcpu_id != mig->mc_vcpuid)
		return 0;

	return 1;
}


#define x86_mcinfo_mcdata(idx) (mc_data.mc[(idx % MAX_MCINFO)])

static struct mc_info *x86_mcinfo_getfetchptr(uint32_t *fetch_idx,
				const struct domain *d, const struct vcpu *v)
{
	struct mc_info *mi;

	/* This function is called from the fetch hypercall with
	 * the mc_lock spinlock held. Thus, no need for locking here.
	 */
	mi = &(x86_mcinfo_mcdata(mc_data.fetch_idx));
	if ((d != dom0) && !x86_mcinfo_matches_guest(mi, d, v)) {
		/* Bogus domU command detected. */
		*fetch_idx = 0;
		return NULL;
	}

	*fetch_idx = mc_data.fetch_idx;
	mc_data.fetch_idx++;
	BUG_ON(mc_data.fetch_idx > mc_data.error_idx);

	return mi;
}


static void x86_mcinfo_marknotified(struct xen_mc_notifydomain *mc_notifydomain)
{
	struct mc_machine_notify *mn;
	struct mcinfo_common *mic = NULL;
	struct mcinfo_global *mig;
	struct domain *d;
	int i;

	/* This function is called from the notifier hypercall with
	 * the mc_notify_lock spinlock held. Thus, no need for locking here.
	 */

	/* First invalidate entries for guests that disappeared after
	 * notification (e.g. shutdown/crash). This step prevents the
	 * notification array from filling up with stalling/leaking entries.
	 */
	for (i = mc_data.notifyconsumer_idx; i < mc_data.notifyproducer_idx; i++) {
		mn = &(mc_data.notify[(i % MAX_MCINFO)]);
		x86_mcinfo_lookup(mic, &mn->mc, MC_TYPE_GLOBAL);
		BUG_ON(mic == NULL);
		mig = (struct mcinfo_global *)mic;
		d = get_domain_by_id(mig->mc_domid);
		if (d == NULL) {
			/* Domain does not exist. */
			mn->valid = 0;
		}
		if ((!mn->valid) && (i == mc_data.notifyconsumer_idx))
			mc_data.notifyconsumer_idx++;
	}

	/* Now put in the error telemetry. Since all error data fetchable
	 * by domUs are uncorrectable errors, they are very important.
	 * So we dump them before overriding them. When a guest takes that long,
	 * then we can assume something bad already happened (crash, hang, etc.)
	 */
	mn = &(mc_data.notify[(mc_data.notifyproducer_idx % MAX_MCINFO)]);

	if (mn->valid) {
		struct mcinfo_common *mic = NULL;
		struct mcinfo_global *mig;

		/* To not loose the information, we dump it. */
		x86_mcinfo_lookup(mic, &mn->mc, MC_TYPE_GLOBAL);
		BUG_ON(mic == NULL);
		mig = (struct mcinfo_global *)mic;
		printk(XENLOG_WARNING "Domain ID %u was notified by Dom0 to "
			"fetch machine check error telemetry. But Domain ID "
			"did not do that in time.\n",
			mig->mc_domid);
		x86_mcinfo_dump(&mn->mc);
	}

	memcpy(&mn->mc, &(x86_mcinfo_mcdata(mc_notifydomain->fetch_idx)),
		sizeof(struct mc_info));
	mn->fetch_idx = mc_notifydomain->fetch_idx;
	mn->valid = 1;

	mc_data.notifyproducer_idx++;

	/* By design there can never be more notifies than machine check errors.
	 * If that ever happens, then we hit a bug. */
	BUG_ON(mc_data.notifyproducer_idx > mc_data.fetch_idx);
	BUG_ON(mc_data.notifyconsumer_idx > mc_data.notifyproducer_idx);
}

static struct mc_info *x86_mcinfo_getnotifiedptr(uint32_t *fetch_idx,
				const struct domain *d, const struct vcpu *v)
{
	struct mc_machine_notify *mn = NULL;
	uint32_t i;
	int found;

	/* This function is called from the fetch hypercall with
	 * the mc_notify_lock spinlock held. Thus, no need for locking here.
	 */

	/* The notifier data is filled in the order guests get notified, but
	 * guests may fetch them in a different order. That's why we need
	 * the game with valid/invalid entries. */
	found = 0;
	for (i = mc_data.notifyconsumer_idx; i < mc_data.notifyproducer_idx; i++) {
		mn = &(mc_data.notify[(i % MAX_MCINFO)]);
		if (!mn->valid) {
			if (i == mc_data.notifyconsumer_idx)
				mc_data.notifyconsumer_idx++;
			continue;
		}
		if (x86_mcinfo_matches_guest(&mn->mc, d, v)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		/* This domain has never been notified. This must be
		 * a bogus domU command. */
		*fetch_idx = 0;
		return NULL;
	}

	BUG_ON(mn == NULL);
	*fetch_idx = mn->fetch_idx;
	mn->valid = 0;

	BUG_ON(mc_data.notifyconsumer_idx > mc_data.notifyproducer_idx);
	return &mn->mc;
}


void x86_mcinfo_clear(struct mc_info *mi)
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
		return -ENOSPC; /* No space. Can't add entry. */

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
	if (mc_global->mc_flags & MC_FLAG_UNCORRECTABLE) {
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



/* Machine Check Architecture Hypercall */
long do_mca(XEN_GUEST_HANDLE(xen_mc_t) u_xen_mc)
{
	long ret = 0;
	struct xen_mc curop, *op = &curop;
	struct vcpu *v = current;
	struct domain *domU;
	struct xen_mc_fetch *mc_fetch;
	struct xen_mc_notifydomain *mc_notifydomain;
	struct mc_info *mi;
	uint32_t flags;
	uint32_t fetch_idx;
        uint16_t vcpuid;
	/* Use a different lock for the notify hypercall in order to allow
	 * a DomU to fetch mc data while Dom0 notifies another DomU. */
	static DEFINE_SPINLOCK(mc_lock);
	static DEFINE_SPINLOCK(mc_notify_lock);

	if ( copy_from_guest(op, u_xen_mc, 1) )
		return -EFAULT;

	if ( op->interface_version != XEN_MCA_INTERFACE_VERSION )
		return -EACCES;

	switch ( op->cmd ) {
	case XEN_MC_fetch:
		/* This hypercall is for any domain */
		mc_fetch = &op->u.mc_fetch;

		switch (mc_fetch->flags) {
		case XEN_MC_CORRECTABLE:
			/* But polling mode is Dom0 only, because
			 * correctable errors are reported to Dom0 only */
			if ( !IS_PRIV(v->domain) )
				return -EPERM;
			break;

		case XEN_MC_TRAP:
			break;
		default:
			return -EFAULT;
		}

		flags = XEN_MC_OK;
		spin_lock(&mc_lock);

		if ( IS_PRIV(v->domain) ) {
			/* this must be Dom0. So a notify hypercall
			 * can't have happened before. */
			mi = x86_mcinfo_getfetchptr(&fetch_idx, dom0, v);
		} else {
			/* Hypercall comes from an unprivileged domain */
			domU = v->domain;
			if (guest_has_trap_callback(dom0, 0, TRAP_machine_check)) {
				/* Dom0 must have notified this DomU before
				 * via the notify hypercall. */
				mi = x86_mcinfo_getnotifiedptr(&fetch_idx, domU, v);
			} else {
				/* Xen notified the DomU. */
				mi = x86_mcinfo_getfetchptr(&fetch_idx, domU, v);
			}
		}

		if (mi) {
			memcpy(&mc_fetch->mc_info, mi,
				sizeof(struct mc_info));
		} else {
			/* There is no data for a bogus DomU command. */
			flags |= XEN_MC_NODATA;
			memset(&mc_fetch->mc_info, 0, sizeof(struct mc_info));
		}

		mc_fetch->flags = flags;
		mc_fetch->fetch_idx = fetch_idx;

		if ( copy_to_guest(u_xen_mc, op, 1) )
			ret = -EFAULT;

		spin_unlock(&mc_lock);
		break;

	case XEN_MC_notifydomain:
		/* This hypercall is for Dom0 only */
		if ( !IS_PRIV(v->domain) )
			return -EPERM;

		spin_lock(&mc_notify_lock);

		mc_notifydomain = &op->u.mc_notifydomain;
		domU = get_domain_by_id(mc_notifydomain->mc_domid);
		vcpuid = mc_notifydomain->mc_vcpuid;

		if ((domU == NULL) || (domU == dom0)) {
			/* It's not possible to notify a non-existent domain
			 * or the dom0. */
			spin_unlock(&mc_notify_lock);
			return -EACCES;
		}

		if (vcpuid >= MAX_VIRT_CPUS) {
			/* It's not possible to notify a vcpu, Xen can't
			 * assign to a domain. */
			spin_unlock(&mc_notify_lock);
			return -EACCES;
		}

		mc_notifydomain->flags = XEN_MC_OK;

		mi = &(x86_mcinfo_mcdata(mc_notifydomain->fetch_idx));
		if (!x86_mcinfo_matches_guest(mi, domU, domU->vcpu[vcpuid])) {
			/* The error telemetry is not for the guest, Dom0
			 * wants to notify. */
			mc_notifydomain->flags |= XEN_MC_NOMATCH;
		} else if ( guest_has_trap_callback(domU, vcpuid,
						TRAP_machine_check) )
		{
			/* Send notification */
			if ( send_guest_trap(domU, vcpuid, TRAP_machine_check) )
				mc_notifydomain->flags |= XEN_MC_NOTDELIVERED;
		} else
			mc_notifydomain->flags |= XEN_MC_CANNOTHANDLE;

#ifdef DEBUG
		/* sanity check - these two flags are mutually exclusive */
		if ((flags & XEN_MC_CANNOTHANDLE) && (flags & XEN_MC_NOTDELIVERED))
			BUG();
#endif

		if ( copy_to_guest(u_xen_mc, op, 1) )
			ret = -EFAULT;

		if (ret == 0) {
			x86_mcinfo_marknotified(mc_notifydomain);
		}

		spin_unlock(&mc_notify_lock);
		break;
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
