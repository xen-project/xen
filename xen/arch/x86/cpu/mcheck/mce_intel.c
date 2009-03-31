#include <xen/init.h>
#include <xen/types.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/delay.h>
#include <xen/smp.h>
#include <asm/processor.h> 
#include <asm/system.h>
#include <asm/msr.h>
#include "mce.h"
#include "x86_mca.h"

DEFINE_PER_CPU(cpu_banks_t, mce_banks_owned);

static int nr_intel_ext_msrs = 0;
static int cmci_support = 0;
static int firstbank;

#ifdef CONFIG_X86_MCE_THERMAL
static void unexpected_thermal_interrupt(struct cpu_user_regs *regs)
{
    printk(KERN_ERR "Thermal: CPU%d: Unexpected LVT TMR interrupt!\n",
                smp_processor_id());
    add_taint(TAINT_MACHINE_CHECK);
}

/* P4/Xeon Thermal transition interrupt handler */
static void intel_thermal_interrupt(struct cpu_user_regs *regs)
{
    u32 l, h;
    unsigned int cpu = smp_processor_id();
    static s_time_t next[NR_CPUS];

    ack_APIC_irq();
    if (NOW() < next[cpu])
        return;

    next[cpu] = NOW() + MILLISECS(5000);
    rdmsr(MSR_IA32_THERM_STATUS, l, h);
    if (l & 0x1) {
        printk(KERN_EMERG "CPU%d: Temperature above threshold\n", cpu);
        printk(KERN_EMERG "CPU%d: Running in modulated clock mode\n",
                cpu);
        add_taint(TAINT_MACHINE_CHECK);
    } else {
        printk(KERN_INFO "CPU%d: Temperature/speed normal\n", cpu);
    }
}

/* Thermal interrupt handler for this CPU setup */
static void (*vendor_thermal_interrupt)(struct cpu_user_regs *regs) 
        = unexpected_thermal_interrupt;

fastcall void smp_thermal_interrupt(struct cpu_user_regs *regs)
{
    irq_enter();
    vendor_thermal_interrupt(regs);
    irq_exit();
}

/* P4/Xeon Thermal regulation detect and init */
static void intel_init_thermal(struct cpuinfo_x86 *c)
{
    u32 l, h;
    int tm2 = 0;
    unsigned int cpu = smp_processor_id();

    /* Thermal monitoring */
    if (!cpu_has(c, X86_FEATURE_ACPI))
        return; /* -ENODEV */

    /* Clock modulation */
    if (!cpu_has(c, X86_FEATURE_ACC))
        return; /* -ENODEV */

    /* first check if its enabled already, in which case there might
     * be some SMM goo which handles it, so we can't even put a handler
     * since it might be delivered via SMI already -zwanem.
     */
    rdmsr (MSR_IA32_MISC_ENABLE, l, h);
    h = apic_read(APIC_LVTTHMR);
    if ((l & (1<<3)) && (h & APIC_DM_SMI)) {
        printk(KERN_DEBUG "CPU%d: Thermal monitoring handled by SMI\n",cpu);
        return; /* -EBUSY */
    }

    if (cpu_has(c, X86_FEATURE_TM2) && (l & (1 << 13)))
        tm2 = 1;

    /* check whether a vector already exists, temporarily masked? */
    if (h & APIC_VECTOR_MASK) {
        printk(KERN_DEBUG "CPU%d: Thermal LVT vector (%#x) already installed\n",
                 cpu, (h & APIC_VECTOR_MASK));
        return; /* -EBUSY */
    }

    /* The temperature transition interrupt handler setup */
    h = THERMAL_APIC_VECTOR;    /* our delivery vector */
    h |= (APIC_DM_FIXED | APIC_LVT_MASKED);  /* we'll mask till we're ready */
    apic_write_around(APIC_LVTTHMR, h);

    rdmsr (MSR_IA32_THERM_INTERRUPT, l, h);
    wrmsr (MSR_IA32_THERM_INTERRUPT, l | 0x03 , h);

    /* ok we're good to go... */
    vendor_thermal_interrupt = intel_thermal_interrupt;

    rdmsr (MSR_IA32_MISC_ENABLE, l, h);
    wrmsr (MSR_IA32_MISC_ENABLE, l | (1<<3), h);

    l = apic_read (APIC_LVTTHMR);
    apic_write_around (APIC_LVTTHMR, l & ~APIC_LVT_MASKED);
    printk (KERN_INFO "CPU%d: Thermal monitoring enabled (%s)\n", 
            cpu, tm2 ? "TM2" : "TM1");
    return;
}
#endif /* CONFIG_X86_MCE_THERMAL */

static inline void intel_get_extended_msr(struct mcinfo_extended *ext, u32 msr)
{
    if ( ext->mc_msrs < ARRAY_SIZE(ext->mc_msr)
         && msr < MSR_IA32_MCG_EAX + nr_intel_ext_msrs ) {
        ext->mc_msr[ext->mc_msrs].reg = msr;
        rdmsrl(msr, ext->mc_msr[ext->mc_msrs].value);
        ++ext->mc_msrs;
    }
}

static enum mca_extinfo
intel_get_extended_msrs(struct mc_info *mci, uint16_t bank, uint64_t status)
{
    struct mcinfo_extended mc_ext;

    if (mci == NULL || nr_intel_ext_msrs == 0 || !(status & MCG_STATUS_EIPV))
        return MCA_EXTINFO_IGNORED;

    /* this function will called when CAP(9).MCG_EXT_P = 1 */
    memset(&mc_ext, 0, sizeof(struct mcinfo_extended));
    mc_ext.common.type = MC_TYPE_EXTENDED;
    mc_ext.common.size = sizeof(mc_ext);

    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_EAX);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_EBX);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_ECX);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_EDX);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_ESI);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_EDI);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_EBP);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_ESP);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_EFLAGS);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_EIP);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_MISC);

#ifdef __x86_64__
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_R8);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_R9);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_R10);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_R11);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_R12);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_R13);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_R14);
    intel_get_extended_msr(&mc_ext, MSR_IA32_MCG_R15);
#endif

    x86_mcinfo_add(mci, &mc_ext);

    return MCA_EXTINFO_GLOBAL;
}

/* Below are for MCE handling */

/* Log worst error severity and offending CPU.,
 * Pick this CPU for further processing in softirq */
static int severity_cpu = -1;
static int worst = 0;

/* Lock of entry@second round scanning in MCE# handler */
static cpumask_t scanned_cpus;
/* Lock for entry@Critical Section in MCE# handler */
static bool_t mce_enter_lock = 0;
/* Record how many CPUs impacted in this MCE# */
static cpumask_t impact_map;

/* Lock of softirq rendezvous entering point */
static cpumask_t mced_cpus;
/*Lock of softirq rendezvous leaving point */
static cpumask_t finished_cpus;
/* Lock for picking one processing CPU */
static bool_t mce_process_lock = 0;

/* Spinlock for vMCE# MSR virtualization data */
static DEFINE_SPINLOCK(mce_locks);

/* Local buffer for holding MCE# data temporarily, sharing between mce
 * handler and softirq handler. Those data will be finally committed
 * for DOM0 Log and coped to per_dom related data for guest vMCE#
 * MSR virtualization.
 * Note: When local buffer is still in processing in softirq, another
 * MCA comes, simply panic.
 */

struct mc_local_t
{
    bool_t in_use;
    mctelem_cookie_t mctc[NR_CPUS];
};
static struct mc_local_t mc_local;

/* This node list records errors impacting a domain. when one
 * MCE# happens, one error bank impacts a domain. This error node
 * will be inserted to the tail of the per_dom data for vMCE# MSR
 * virtualization. When one vMCE# injection is finished processing
 * processed by guest, the corresponding node will be deleted. 
 * This node list is for GUEST vMCE# MSRS virtualization.
 */
static struct bank_entry* alloc_bank_entry(void) {
    struct bank_entry *entry;

    entry = xmalloc(struct bank_entry);
    if (!entry) {
        printk(KERN_ERR "MCE: malloc bank_entry failed\n");
        return NULL;
    }
    memset(entry, 0x0, sizeof(entry));
    INIT_LIST_HEAD(&entry->list);
    return entry;
}

/* Fill error bank info for #vMCE injection and GUEST vMCE#
 * MSR virtualization data
 * 1) Log down how many nr_injections of the impacted.
 * 2) Copy MCE# error bank to impacted DOM node list, 
      for vMCE# MSRs virtualization
*/

static int fill_vmsr_data(int cpu, struct mcinfo_bank *mc_bank, 
        uint64_t gstatus) {
    struct domain *d;
    struct bank_entry *entry;

    /* This error bank impacts one domain, we need to fill domain related
     * data for vMCE MSRs virtualization and vMCE# injection */
    if (mc_bank->mc_domid != (uint16_t)~0) {
        d = get_domain_by_id(mc_bank->mc_domid);

        /* Not impact a valid domain, skip this error of the bank */
        if (!d) {
            printk(KERN_DEBUG "MCE: Not found valid impacted DOM\n");
            return 0;
        }

        entry = alloc_bank_entry();
        entry->mci_status = mc_bank->mc_status;
        entry->mci_addr = mc_bank->mc_addr;
        entry->mci_misc = mc_bank->mc_misc;
        entry->cpu = cpu;
        entry->bank = mc_bank->mc_bank;

        /* New error Node, insert to the tail of the per_dom data */
        list_add_tail(&entry->list, &d->arch.vmca_msrs.impact_header);
        /* Fill MSR global status */
        d->arch.vmca_msrs.mcg_status = gstatus;
        /* New node impact the domain, need another vMCE# injection*/
        d->arch.vmca_msrs.nr_injection++;

        printk(KERN_DEBUG "MCE: Found error @[CPU%d BANK%d "
                "status %"PRIx64" addr %"PRIx64" domid %d]\n ",
                entry->cpu, mc_bank->mc_bank,
                mc_bank->mc_status, mc_bank->mc_addr, mc_bank->mc_domid);
    }
    return 0;
}

static int mce_actions(void) {
    int32_t cpu, ret;
    struct mc_info *local_mi;
    struct mcinfo_common *mic = NULL;
    struct mcinfo_global *mc_global;
    struct mcinfo_bank *mc_bank;

    /* Spinlock is used for exclusive read/write of vMSR virtualization
     * (per_dom vMCE# data)
     */
    spin_lock(&mce_locks);

    /*
     * If softirq is filling this buffer while another MCE# comes,
     * simply panic
     */
    test_and_set_bool(mc_local.in_use);

    for_each_cpu_mask(cpu, impact_map) {
        if (mc_local.mctc[cpu] == NULL) {
            printk(KERN_ERR "MCE: get reserved entry failed\n ");
            ret = -1;
            goto end;
        }
        local_mi = (struct mc_info*)mctelem_dataptr(mc_local.mctc[cpu]);
        x86_mcinfo_lookup(mic, local_mi, MC_TYPE_GLOBAL);
        if (mic == NULL) {
            printk(KERN_ERR "MCE: get local buffer entry failed\n ");
            ret = -1;
            goto end;
        }

        mc_global = (struct mcinfo_global *)mic;

        /* Processing bank information */
        x86_mcinfo_lookup(mic, local_mi, MC_TYPE_BANK);

        for ( ; mic && mic->size; mic = x86_mcinfo_next(mic) ) {
            if (mic->type != MC_TYPE_BANK) {
                continue;
            }
            mc_bank = (struct mcinfo_bank*)mic;
            /* Fill vMCE# injection and vMCE# MSR virtualization related data */
            if (fill_vmsr_data(cpu, mc_bank, mc_global->mc_gstatus) == -1) {
                ret = -1;
                goto end;
            }

            /* TODO: Add recovery actions here, such as page-offline, etc */
        }
    } /* end of impact_map loop */

    ret = 0;

end:

    for_each_cpu_mask(cpu, impact_map) {
        /* This reserved entry is processed, commit it */
        if (mc_local.mctc[cpu] != NULL) {
            mctelem_commit(mc_local.mctc[cpu]);
            printk(KERN_DEBUG "MCE: Commit one URGENT ENTRY\n");
        }
    }

    test_and_clear_bool(mc_local.in_use);
    spin_unlock(&mce_locks);
    return ret;
}

/* Softirq Handler for this MCE# processing */
static void mce_softirq(void)
{
    int cpu = smp_processor_id();
    cpumask_t affinity;

    /* Wait until all cpus entered softirq */
    while ( cpus_weight(mced_cpus) != num_online_cpus() ) {
        cpu_relax();
    }
    /* Not Found worst error on severity_cpu, it's weird */
    if (severity_cpu == -1) {
        printk(KERN_WARNING "MCE: not found severity_cpu!\n");
        mc_panic("MCE: not found severity_cpu!");
        return;
    }
    /* We choose severity_cpu for further processing */
    if (severity_cpu == cpu) {

        /* Step1: Fill DOM0 LOG buffer, vMCE injection buffer and
         * vMCE MSRs virtualization buffer
         */
        if (mce_actions())
            mc_panic("MCE recovery actions or Filling vMCE MSRS "
                     "virtualization data failed!\n");

        /* Step2: Send Log to DOM0 through vIRQ */
        if (dom0 && guest_enabled_event(dom0->vcpu[0], VIRQ_MCA)) {
            printk(KERN_DEBUG "MCE: send MCE# to DOM0 through virq\n");
            send_guest_global_virq(dom0, VIRQ_MCA);
        }

        /* Step3: Inject vMCE to impacted DOM. Currently we cares DOM0 only */
        if (guest_has_trap_callback
               (dom0, 0, TRAP_machine_check) &&
                 !test_and_set_bool(dom0->vcpu[0]->mce_pending)) {
            dom0->vcpu[0]->cpu_affinity_tmp = 
                    dom0->vcpu[0]->cpu_affinity;
            cpus_clear(affinity);
            cpu_set(cpu, affinity);
            printk(KERN_DEBUG "MCE: CPU%d set affinity, old %d\n", cpu,
                dom0->vcpu[0]->processor);
            vcpu_set_affinity(dom0->vcpu[0], &affinity);
            vcpu_kick(dom0->vcpu[0]);
        }

        /* Clean Data */
        test_and_clear_bool(mce_process_lock);
        cpus_clear(impact_map);
        cpus_clear(scanned_cpus);
        worst = 0;
        cpus_clear(mced_cpus);
        memset(&mc_local, 0x0, sizeof(mc_local));
    }

    cpu_set(cpu, finished_cpus);
    wmb();
   /* Leave until all cpus finished recovery actions in softirq */
    while ( cpus_weight(finished_cpus) != num_online_cpus() ) {
        cpu_relax();
    }

    cpus_clear(finished_cpus);
    severity_cpu = -1;
    printk(KERN_DEBUG "CPU%d exit softirq \n", cpu);
}

/* Machine Check owner judge algorithm:
 * When error happens, all cpus serially read its msr banks.
 * The first CPU who fetches the error bank's info will clear
 * this bank. Later readers can't get any infor again.
 * The first CPU is the actual mce_owner
 *
 * For Fatal (pcc=1) error, it might cause machine crash
 * before we're able to log. For avoiding log missing, we adopt two
 * round scanning:
 * Round1: simply scan. If found pcc = 1 or ripv = 0, simply reset.
 * All MCE banks are sticky, when boot up, MCE polling mechanism
 * will help to collect and log those MCE errors.
 * Round2: Do all MCE processing logic as normal.
 */

/* Simple Scan. Panic when found non-recovery errors. Doing this for
 * avoiding LOG missing
 */
static void severity_scan(void)
{
    uint64_t status;
    int32_t i;

    /* TODO: For PCC = 0, we need to have further judge. If it is can't be
     * recovered, we need to RESET for avoiding DOM0 LOG missing
     */
    for ( i = 0; i < nr_mce_banks; i++) {
        mca_rdmsrl(MSR_IA32_MC0_STATUS + 4 * i , status);
        if ( !(status & MCi_STATUS_VAL) )
            continue;
        /* MCE handler only handles UC error */
        if ( !(status & MCi_STATUS_UC) )
            continue;
        if ( !(status & MCi_STATUS_EN) )
            continue;
        /*
         * If this was an injected error, keep going, since the
         * interposed value will be lost at reboot.
         */
        if (status & MCi_STATUS_PCC && intpose_lookup(smp_processor_id(),
          MSR_IA32_MC0_STATUS + 4 * i, NULL) == NULL)
            mc_panic("pcc = 1, cpu unable to continue\n");
    }

    /* TODO: Further judgement for later CPUs here, maybe need MCACOD assistence */
    /* EIPV and RIPV is not a reliable way to judge the error severity */

}


static void intel_machine_check(struct cpu_user_regs * regs, long error_code)
{
    unsigned int cpu = smp_processor_id();
    int32_t severity = 0;
    uint64_t gstatus;
    mctelem_cookie_t mctc = NULL;
    struct mca_summary bs;

    /* First round scanning */
    severity_scan();
    cpu_set(cpu, scanned_cpus);
    while (cpus_weight(scanned_cpus) < num_online_cpus())
        cpu_relax();

    wmb();
    /* All CPUs Finished first round scanning */
    if (mc_local.in_use != 0) {
        mc_panic("MCE: Local buffer is being processed, can't handle new MCE!\n");
        return;
    }

    /* Enter Critical Section */
    while (test_and_set_bool(mce_enter_lock)) {
        udelay (1);
    }

    mctc = mcheck_mca_logout(MCA_MCE_HANDLER, mca_allbanks, &bs);
     /* local data point to the reserved entry, let softirq to
      * process the local data */
    if (!bs.errcnt) {
        if (mctc != NULL)
            mctelem_dismiss(mctc);
        mc_local.mctc[cpu] = NULL;
        cpu_set(cpu, mced_cpus);
        test_and_clear_bool(mce_enter_lock);
        raise_softirq(MACHINE_CHECK_SOFTIRQ);
        return;
    }
    else if ( mctc != NULL) {
        mc_local.mctc[cpu] = mctc;
    }

    if (bs.uc || bs.pcc)
        add_taint(TAINT_MACHINE_CHECK);

    if (bs.pcc) {
        printk(KERN_WARNING "PCC=1 should have caused reset\n");
        severity = 3;
    }
    else if (bs.uc) {
        severity = 2;
    }
    else {
        printk(KERN_WARNING "We should skip Correctable Error\n");
        severity = 1;
    }
    /* This is the offending cpu! */
    cpu_set(cpu, impact_map);

    if ( severity > worst) {
        worst = severity;
        severity_cpu = cpu;
    }
    cpu_set(cpu, mced_cpus);
    test_and_clear_bool(mce_enter_lock);
    wmb();

    /* Wait for all cpus Leave Critical */
    while (cpus_weight(mced_cpus) < num_online_cpus())
        cpu_relax();
    /* Print MCE error */
    x86_mcinfo_dump(mctelem_dataptr(mctc));

    /* Pick one CPU to clear MCIP */
    if (!test_and_set_bool(mce_process_lock)) {
        mca_rdmsrl(MSR_IA32_MCG_STATUS, gstatus);
        mca_wrmsrl(MSR_IA32_MCG_STATUS, gstatus & ~MCG_STATUS_MCIP);

        if (worst >= 3) {
            printk(KERN_WARNING "worst=3 should have caused RESET\n");
            mc_panic("worst=3 should have caused RESET");
        }
        else {
            printk(KERN_DEBUG "MCE: trying to recover\n");
        }
    }
    raise_softirq(MACHINE_CHECK_SOFTIRQ);
}

static DEFINE_SPINLOCK(cmci_discover_lock);
static DEFINE_PER_CPU(cpu_banks_t, no_cmci_banks);

/*
 * Discover bank sharing using the algorithm recommended in the SDM.
 */
static int do_cmci_discover(int i)
{
    unsigned msr = MSR_IA32_MC0_CTL2 + i;
    u64 val;

    rdmsrl(msr, val);
    /* Some other CPU already owns this bank. */
    if (val & CMCI_EN) {
        clear_bit(i, __get_cpu_var(mce_banks_owned));
        goto out;
    }
    wrmsrl(msr, val | CMCI_EN | CMCI_THRESHOLD);
    rdmsrl(msr, val);

    if (!(val & CMCI_EN)) {
        /* This bank does not support CMCI. Polling timer has to handle it. */
        set_bit(i, __get_cpu_var(no_cmci_banks));
        return 0;
    }
    set_bit(i, __get_cpu_var(mce_banks_owned));
out:
    clear_bit(i, __get_cpu_var(no_cmci_banks));
    return 1;
}

static void cmci_discover(void)
{
    unsigned long flags;
    int i;
    mctelem_cookie_t mctc;
    struct mca_summary bs;

    printk(KERN_DEBUG "CMCI: find owner on CPU%d\n", smp_processor_id());

    spin_lock_irqsave(&cmci_discover_lock, flags);

    for (i = 0; i < nr_mce_banks; i++)
        if (!test_bit(i, __get_cpu_var(mce_banks_owned)))
            do_cmci_discover(i);

    spin_unlock_irqrestore(&cmci_discover_lock, flags);

    /* In case CMCI happended when do owner change.
     * If CMCI happened yet not processed immediately,
     * MCi_status (error_count bit 38~52) is not cleared,
     * the CMCI interrupt will never be triggered again.
     */

    mctc = mcheck_mca_logout(
        MCA_CMCI_HANDLER, __get_cpu_var(mce_banks_owned), &bs);

    if (bs.errcnt && mctc != NULL) {
        if (guest_enabled_event(dom0->vcpu[0], VIRQ_MCA)) {
            mctelem_commit(mctc);
            send_guest_global_virq(dom0, VIRQ_MCA);
        } else {
            x86_mcinfo_dump(mctelem_dataptr(mctc));
            mctelem_dismiss(mctc);
        }
    } else if (mctc != NULL)
        mctelem_dismiss(mctc);

    printk(KERN_DEBUG "CMCI: CPU%d owner_map[%lx], no_cmci_map[%lx]\n", 
           smp_processor_id(), 
           *((unsigned long *)__get_cpu_var(mce_banks_owned)), 
           *((unsigned long *)__get_cpu_var(no_cmci_banks)));
}

/*
 * Define an owner for each bank. Banks can be shared between CPUs
 * and to avoid reporting events multiple times always set up one
 * CPU as owner. 
 *
 * The assignment has to be redone when CPUs go offline and
 * any of the owners goes away. Also pollers run in parallel so we
 * have to be careful to update the banks in a way that doesn't
 * lose or duplicate events.
 */

static void mce_set_owner(void)
{
    if (!cmci_support || mce_disabled == 1)
        return;

    cmci_discover();
}

static void __cpu_mcheck_distribute_cmci(void *unused)
{
    cmci_discover();
}

void cpu_mcheck_distribute_cmci(void)
{
    if (cmci_support && !mce_disabled)
        on_each_cpu(__cpu_mcheck_distribute_cmci, NULL, 0, 0);
}

static void clear_cmci(void)
{
    int i;

    if (!cmci_support || mce_disabled == 1)
        return;

    printk(KERN_DEBUG "CMCI: clear_cmci support on CPU%d\n", 
            smp_processor_id());

    for (i = 0; i < nr_mce_banks; i++) {
        unsigned msr = MSR_IA32_MC0_CTL2 + i;
        u64 val;
        if (!test_bit(i, __get_cpu_var(mce_banks_owned)))
            continue;
        rdmsrl(msr, val);
        if (val & (CMCI_EN|CMCI_THRESHOLD_MASK))
            wrmsrl(msr, val & ~(CMCI_EN|CMCI_THRESHOLD_MASK));
        clear_bit(i, __get_cpu_var(mce_banks_owned));
    }
}

void cpu_mcheck_disable(void)
{
    clear_in_cr4(X86_CR4_MCE);

    if (cmci_support && !mce_disabled)
        clear_cmci();
}

static void intel_init_cmci(struct cpuinfo_x86 *c)
{
    u32 l, apic;
    int cpu = smp_processor_id();

    if (!mce_available(c) || !cmci_support) {
        printk(KERN_DEBUG "CMCI: CPU%d has no CMCI support\n", cpu);
        return;
    }

    apic = apic_read(APIC_CMCI);
    if ( apic & APIC_VECTOR_MASK )
    {
        printk(KERN_WARNING "CPU%d CMCI LVT vector (%#x) already installed\n",
            cpu, ( apic & APIC_VECTOR_MASK ));
        return;
    }

    apic = CMCI_APIC_VECTOR;
    apic |= (APIC_DM_FIXED | APIC_LVT_MASKED);
    apic_write_around(APIC_CMCI, apic);

    l = apic_read(APIC_CMCI);
    apic_write_around(APIC_CMCI, l & ~APIC_LVT_MASKED);
}

fastcall void smp_cmci_interrupt(struct cpu_user_regs *regs)
{
    mctelem_cookie_t mctc;
    struct mca_summary bs;

    ack_APIC_irq();
    irq_enter();

    mctc = mcheck_mca_logout(
        MCA_CMCI_HANDLER, __get_cpu_var(mce_banks_owned), &bs);

    if (bs.errcnt && mctc != NULL) {
        if (guest_enabled_event(dom0->vcpu[0], VIRQ_MCA)) {
            mctelem_commit(mctc);
            printk(KERN_DEBUG "CMCI: send CMCI to DOM0 through virq\n");
            send_guest_global_virq(dom0, VIRQ_MCA);
        } else {
            x86_mcinfo_dump(mctelem_dataptr(mctc));
            mctelem_dismiss(mctc);
       }
    } else if (mctc != NULL)
        mctelem_dismiss(mctc);

    irq_exit();
}

void mce_intel_feature_init(struct cpuinfo_x86 *c)
{

#ifdef CONFIG_X86_MCE_THERMAL
    intel_init_thermal(c);
#endif
    intel_init_cmci(c);
}

static uint64_t g_mcg_cap;
static void mce_cap_init(struct cpuinfo_x86 *c)
{
    u32 l, h;

    rdmsr (MSR_IA32_MCG_CAP, l, h);
    /* For Guest vMCE usage */
    g_mcg_cap = ((u64)h << 32 | l) & (~MCG_CMCI_P);

    if ((l & MCG_CMCI_P) && cpu_has_apic)
        cmci_support = 1;

    nr_mce_banks = l & MCG_CAP_COUNT;
    if (nr_mce_banks > MAX_NR_BANKS)
    {
        printk(KERN_WARNING "MCE: exceed max mce banks\n");
        g_mcg_cap = (g_mcg_cap & ~MCG_CAP_COUNT) | MAX_NR_BANKS;
    }
    if (l & MCG_EXT_P)
    {
        nr_intel_ext_msrs = (l >> MCG_EXT_CNT) & 0xff;
        printk (KERN_INFO "CPU%d: Intel Extended MCE MSRs (%d) available\n",
            smp_processor_id(), nr_intel_ext_msrs);
    }
    firstbank = mce_firstbank(c);
}

static void mce_init(void)
{
    u32 l, h;
    int i;
    mctelem_cookie_t mctc;
    struct mca_summary bs;

    clear_in_cr4(X86_CR4_MCE);

    /* log the machine checks left over from the previous reset.
     * This also clears all registers*/

    mctc = mcheck_mca_logout(MCA_RESET, mca_allbanks, &bs);

    /* in the boot up stage, don't inject to DOM0, but print out */
    if (bs.errcnt && mctc != NULL) {
        x86_mcinfo_dump(mctelem_dataptr(mctc));
        mctelem_dismiss(mctc);
    }

    set_in_cr4(X86_CR4_MCE);
    rdmsr (MSR_IA32_MCG_CAP, l, h);
    if (l & MCG_CTL_P) /* Control register present ? */
        wrmsr(MSR_IA32_MCG_CTL, 0xffffffff, 0xffffffff);

    for (i = firstbank; i < nr_mce_banks; i++)
    {
        /* Some banks are shared across cores, use MCi_CTRL to judge whether
         * this bank has been initialized by other cores already. */
        rdmsr(MSR_IA32_MC0_CTL + 4*i, l, h);
        if (!(l | h))
        {
            /* if ctl is 0, this bank is never initialized */
            printk(KERN_DEBUG "mce_init: init bank%d\n", i);
            wrmsr (MSR_IA32_MC0_CTL + 4*i, 0xffffffff, 0xffffffff);
            wrmsr (MSR_IA32_MC0_STATUS + 4*i, 0x0, 0x0);
        }
    }
    if (firstbank) /* if cmci enabled, firstbank = 0 */
        wrmsr (MSR_IA32_MC0_STATUS, 0x0, 0x0);
}

/* p4/p6 family have similar MCA initialization process */
int intel_mcheck_init(struct cpuinfo_x86 *c)
{
    mce_cap_init(c);
    printk (KERN_INFO "Intel machine check reporting enabled on CPU#%d.\n",
            smp_processor_id());

    /* machine check is available */
    x86_mce_vector_register(intel_machine_check);
    x86_mce_callback_register(intel_get_extended_msrs);

    mce_init();
    mce_intel_feature_init(c);
    mce_set_owner();

    open_softirq(MACHINE_CHECK_SOFTIRQ, mce_softirq);
    return 1;
}

/* Guest vMCE# MSRs virtualization ops (rdmsr/wrmsr) */
void intel_mce_init_msr(struct domain *d)
{
    d->arch.vmca_msrs.mcg_status = 0x0;
    d->arch.vmca_msrs.mcg_cap = g_mcg_cap;
    d->arch.vmca_msrs.mcg_ctl = (uint64_t)~0x0;
    d->arch.vmca_msrs.nr_injection = 0;
    memset(d->arch.vmca_msrs.mci_ctl, ~0,
           sizeof(d->arch.vmca_msrs.mci_ctl));
    INIT_LIST_HEAD(&d->arch.vmca_msrs.impact_header);
}

int intel_mce_wrmsr(u32 msr, u64 value)
{
    struct domain *d = current->domain;
    struct bank_entry *entry = NULL;
    unsigned int bank;
    int ret = 1;

    spin_lock(&mce_locks);
    switch(msr)
    {
    case MSR_IA32_MCG_CTL:
        if (value != (u64)~0x0 && value != 0x0) {
            gdprintk(XENLOG_WARNING, "MCE: value written to MCG_CTL"
                     "should be all 0s or 1s\n");
            ret = -1;
            break;
        }
        d->arch.vmca_msrs.mcg_ctl = value;
        break;
    case MSR_IA32_MCG_STATUS:
        d->arch.vmca_msrs.mcg_status = value;
        gdprintk(XENLOG_DEBUG, "MCE: wrmsr MCG_CTL %"PRIx64"\n", value);
        break;
    case MSR_IA32_MCG_CAP:
        gdprintk(XENLOG_WARNING, "MCE: MCG_CAP is read-only\n");
        ret = -1;
        break;
    case MSR_IA32_MC0_CTL2 ... MSR_IA32_MC0_CTL2 + MAX_NR_BANKS - 1:
        gdprintk(XENLOG_WARNING, "We have disabled CMCI capability, "
                 "Guest should not write this MSR!\n");
        break;
    case MSR_IA32_MC0_CTL ... MSR_IA32_MC0_CTL + 4 * MAX_NR_BANKS - 1:
        bank = (msr - MSR_IA32_MC0_CTL) / 4;
        if (bank >= (d->arch.vmca_msrs.mcg_cap & MCG_CAP_COUNT)) {
            gdprintk(XENLOG_WARNING, "MCE: bank %u does not exist\n", bank);
            ret = -1;
            break;
        }
        switch (msr & (MSR_IA32_MC0_CTL | 3))
        {
        case MSR_IA32_MC0_CTL:
            if (value != (u64)~0x0 && value != 0x0) {
                gdprintk(XENLOG_WARNING, "MCE: value written to MC%u_CTL"
                         "should be all 0s or 1s (is %"PRIx64")\n",
                         bank, value);
                ret = -1;
                break;
            }
            d->arch.vmca_msrs.mci_ctl[(msr - MSR_IA32_MC0_CTL)/4] = value;
            break;
        case MSR_IA32_MC0_STATUS:
            /* Give the first entry of the list, it corresponds to current
             * vMCE# injection. When vMCE# is finished processing by the
             * the guest, this node will be deleted.
             * Only error bank is written. Non-error banks simply return.
             */
            if (!list_empty(&d->arch.vmca_msrs.impact_header)) {
                entry = list_entry(d->arch.vmca_msrs.impact_header.next,
                                   struct bank_entry, list);
                if ( entry->bank == bank )
                    entry->mci_status = value;
                gdprintk(XENLOG_DEBUG,
                         "MCE: wr MC%u_STATUS %"PRIx64" in vMCE#\n",
                         bank, value);
            } else
                gdprintk(XENLOG_DEBUG,
                         "MCE: wr MC%u_STATUS %"PRIx64"\n", bank, value);
            break;
        case MSR_IA32_MC0_ADDR:
            gdprintk(XENLOG_WARNING, "MCE: MC%u_ADDR is read-only\n", bank);
            ret = -1;
            break;
        case MSR_IA32_MC0_MISC:
            gdprintk(XENLOG_WARNING, "MCE: MC%u_MISC is read-only\n", bank);
            ret = -1;
            break;
        }
        break;
    default:
        ret = 0;
        break;
    }
    spin_unlock(&mce_locks);
    return ret;
}

int intel_mce_rdmsr(u32 msr, u32 *lo, u32 *hi)
{
    struct domain *d = current->domain;
    int ret = 1;
    unsigned int bank;
    struct bank_entry *entry = NULL;

    *lo = *hi = 0x0;
    spin_lock(&mce_locks);
    switch(msr)
    {
    case MSR_IA32_MCG_STATUS:
        *lo = (u32)d->arch.vmca_msrs.mcg_status;
        *hi = (u32)(d->arch.vmca_msrs.mcg_status >> 32);
        gdprintk(XENLOG_DEBUG, "MCE: rd MCG_STATUS lo %x hi %x\n", *lo, *hi);
        break;
    case MSR_IA32_MCG_CAP:
        *lo = (u32)d->arch.vmca_msrs.mcg_cap;
        *hi = (u32)(d->arch.vmca_msrs.mcg_cap >> 32);
        gdprintk(XENLOG_DEBUG, "MCE: rdmsr MCG_CAP lo %x hi %x\n", *lo, *hi);
        break;
    case MSR_IA32_MCG_CTL:
        *lo = (u32)d->arch.vmca_msrs.mcg_ctl;
        *hi = (u32)(d->arch.vmca_msrs.mcg_ctl >> 32);
        gdprintk(XENLOG_DEBUG, "MCE: rdmsr MCG_CTL lo %x hi %x\n", *lo, *hi);
        break;
    case MSR_IA32_MC0_CTL2 ... MSR_IA32_MC0_CTL2 + MAX_NR_BANKS - 1:
        gdprintk(XENLOG_WARNING, "We have disabled CMCI capability, "
                 "Guest should not read this MSR!\n");
        break;
    case MSR_IA32_MC0_CTL ... MSR_IA32_MC0_CTL + 4 * MAX_NR_BANKS - 1:
        bank = (msr - MSR_IA32_MC0_CTL) / 4;
        if (bank >= (d->arch.vmca_msrs.mcg_cap & MCG_CAP_COUNT)) {
            gdprintk(XENLOG_WARNING, "MCE: bank %u does not exist\n", bank);
            ret = -1;
            break;
        }
        switch (msr & (MSR_IA32_MC0_CTL | 3))
        {
        case MSR_IA32_MC0_CTL:
            *lo = (u32)d->arch.vmca_msrs.mci_ctl[bank];
            *hi = (u32)(d->arch.vmca_msrs.mci_ctl[bank] >> 32);
            gdprintk(XENLOG_DEBUG, "MCE: rd MC%u_CTL lo %x hi %x\n",
                     bank, *lo, *hi);
            break;
        case MSR_IA32_MC0_STATUS:
            /* Only error bank is read. Non-error banks simply return. */
            if (!list_empty(&d->arch.vmca_msrs.impact_header)) {
                entry = list_entry(d->arch.vmca_msrs.impact_header.next,
                                   struct bank_entry, list);
                if (entry->bank == bank) {
                    *lo = entry->mci_status;
                    *hi = entry->mci_status >> 32;
                    gdprintk(XENLOG_DEBUG,
                             "MCE: rd MC%u_STATUS in vmCE# context "
                             "lo %x hi %x\n", bank, *lo, *hi);
                } else
                    entry = NULL;
            }
            if (!entry)
                gdprintk(XENLOG_DEBUG, "MCE: rd MC%u_STATUS\n", bank);
            break;
        case MSR_IA32_MC0_ADDR:
            if (!list_empty(&d->arch.vmca_msrs.impact_header)) {
                entry = list_entry(d->arch.vmca_msrs.impact_header.next,
                                   struct bank_entry, list);
                if (entry->bank == bank) {
                    *lo = entry->mci_addr;
                    *hi = entry->mci_addr >> 32;
                    gdprintk(XENLOG_DEBUG,
                             "MCE: rd MC%u_ADDR in vMCE# context lo %x hi %x\n",
                             bank, *lo, *hi);
                }
            }
            break;
        case MSR_IA32_MC0_MISC:
            if (!list_empty(&d->arch.vmca_msrs.impact_header)) {
                entry = list_entry(d->arch.vmca_msrs.impact_header.next,
                                   struct bank_entry, list);
                if (entry->bank == bank) {
                    *lo = entry->mci_misc;
                    *hi = entry->mci_misc >> 32;
                    gdprintk(XENLOG_DEBUG,
                             "MCE: rd MC%u_MISC in vMCE# context lo %x hi %x\n",
                             bank, *lo, *hi);
                }
            }
            break;
        }
        break;
    default:
        ret = 0;
        break;
    }
    spin_unlock(&mce_locks);
    return ret;
}


