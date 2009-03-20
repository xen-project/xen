#include <xen/init.h>
#include <xen/types.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/kernel.h>
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
    mc_ext.mc_msrs = 10;

    mc_ext.mc_msr[0].reg = MSR_IA32_MCG_EAX;
    rdmsrl(MSR_IA32_MCG_EAX, mc_ext.mc_msr[0].value);
    mc_ext.mc_msr[1].reg = MSR_IA32_MCG_EBX;
    rdmsrl(MSR_IA32_MCG_EBX, mc_ext.mc_msr[1].value);
    mc_ext.mc_msr[2].reg = MSR_IA32_MCG_ECX;
    rdmsrl(MSR_IA32_MCG_ECX, mc_ext.mc_msr[2].value);

    mc_ext.mc_msr[3].reg = MSR_IA32_MCG_EDX;
    rdmsrl(MSR_IA32_MCG_EDX, mc_ext.mc_msr[3].value);
    mc_ext.mc_msr[4].reg = MSR_IA32_MCG_ESI;
    rdmsrl(MSR_IA32_MCG_ESI, mc_ext.mc_msr[4].value);
    mc_ext.mc_msr[5].reg = MSR_IA32_MCG_EDI;
    rdmsrl(MSR_IA32_MCG_EDI, mc_ext.mc_msr[5].value);

    mc_ext.mc_msr[6].reg = MSR_IA32_MCG_EBP;
    rdmsrl(MSR_IA32_MCG_EBP, mc_ext.mc_msr[6].value);
    mc_ext.mc_msr[7].reg = MSR_IA32_MCG_ESP;
    rdmsrl(MSR_IA32_MCG_ESP, mc_ext.mc_msr[7].value);
    mc_ext.mc_msr[8].reg = MSR_IA32_MCG_EFLAGS;
    rdmsrl(MSR_IA32_MCG_EFLAGS, mc_ext.mc_msr[8].value);
    mc_ext.mc_msr[9].reg = MSR_IA32_MCG_EIP;
    rdmsrl(MSR_IA32_MCG_EIP, mc_ext.mc_msr[9].value);

    x86_mcinfo_add(mci, &mc_ext);

    return MCA_EXTINFO_GLOBAL;
}

static void intel_machine_check(struct cpu_user_regs * regs, long error_code)
{
	mcheck_cmn_handler(regs, error_code, mca_allbanks);
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

static void mce_cap_init(struct cpuinfo_x86 *c)
{
    u32 l, h;

    rdmsr (MSR_IA32_MCG_CAP, l, h);
    if ((l & MCG_CMCI_P) && cpu_has_apic)
        cmci_support = 1;

    nr_mce_banks = l & 0xff;
    if (nr_mce_banks > MAX_NR_BANKS)
        printk(KERN_WARNING "MCE: exceed max mce banks\n");
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

    return 1;
}
