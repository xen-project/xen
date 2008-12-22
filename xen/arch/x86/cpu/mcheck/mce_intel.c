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
extern int firstbank;

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
        return;	/* -ENODEV */

    /* Clock modulation */
    if (!cpu_has(c, X86_FEATURE_ACC))
        return;	/* -ENODEV */

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
    h = THERMAL_APIC_VECTOR;		/* our delivery vector */
    h |= (APIC_DM_FIXED | APIC_LVT_MASKED);	/* we'll mask till we're ready */
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

static inline void intel_get_extended_msrs(struct mcinfo_extended *mc_ext)
{
    if (nr_intel_ext_msrs == 0)
        return;

	/*this function will called when CAP(9).MCG_EXT_P = 1*/
    memset(mc_ext, 0, sizeof(struct mcinfo_extended));
    mc_ext->common.type = MC_TYPE_EXTENDED;
    mc_ext->common.size = sizeof(mc_ext);
    mc_ext->mc_msrs = 10;

    mc_ext->mc_msr[0].reg = MSR_IA32_MCG_EAX;
    rdmsrl(MSR_IA32_MCG_EAX, mc_ext->mc_msr[0].value);
    mc_ext->mc_msr[1].reg = MSR_IA32_MCG_EBX;
    rdmsrl(MSR_IA32_MCG_EBX, mc_ext->mc_msr[1].value);
    mc_ext->mc_msr[2].reg = MSR_IA32_MCG_ECX;
    rdmsrl(MSR_IA32_MCG_ECX, mc_ext->mc_msr[2].value);

    mc_ext->mc_msr[3].reg = MSR_IA32_MCG_EDX;
    rdmsrl(MSR_IA32_MCG_EDX, mc_ext->mc_msr[3].value);
    mc_ext->mc_msr[4].reg = MSR_IA32_MCG_ESI;
    rdmsrl(MSR_IA32_MCG_ESI, mc_ext->mc_msr[4].value);
    mc_ext->mc_msr[5].reg = MSR_IA32_MCG_EDI;
    rdmsrl(MSR_IA32_MCG_EDI, mc_ext->mc_msr[5].value);

    mc_ext->mc_msr[6].reg = MSR_IA32_MCG_EBP;
    rdmsrl(MSR_IA32_MCG_EBP, mc_ext->mc_msr[6].value);
    mc_ext->mc_msr[7].reg = MSR_IA32_MCG_ESP;
    rdmsrl(MSR_IA32_MCG_ESP, mc_ext->mc_msr[7].value);
    mc_ext->mc_msr[8].reg = MSR_IA32_MCG_EFLAGS;
    rdmsrl(MSR_IA32_MCG_EFLAGS, mc_ext->mc_msr[8].value);
    mc_ext->mc_msr[9].reg = MSR_IA32_MCG_EIP;
    rdmsrl(MSR_IA32_MCG_EIP, mc_ext->mc_msr[9].value);
}

/* machine_check_poll might be called by following types:
 * 1. called when do mcheck_init.
 * 2. called in cmci interrupt handler
 * 3. called in polling handler
 * It will generate a new mc_info item if found CE/UC errors. DOM0 is the 
 * consumer.
*/
static int machine_check_poll(struct mc_info *mi, int calltype)
{
    int exceptions = (read_cr4() & X86_CR4_MCE);
    int i, nr_unit = 0, uc = 0, pcc = 0;
    uint64_t status, addr;
    struct mcinfo_global mcg;
    struct mcinfo_extended mce;
    unsigned int cpu;
    struct domain *d;

    cpu = smp_processor_id();

    if (!mi) {
        printk(KERN_ERR "mcheck_poll: Failed to get mc_info entry\n");
        return 0;
    }
    x86_mcinfo_clear(mi);

    memset(&mcg, 0, sizeof(mcg));
    mcg.common.type = MC_TYPE_GLOBAL;
    mcg.common.size = sizeof(mcg);
    /*If called from cpu-reset check, don't need to fill them.
     *If called from cmci context, we'll try to fill domid by memory addr
    */
    mcg.mc_domid = -1;
    mcg.mc_vcpuid = -1;
    if (calltype == MC_FLAG_POLLED || calltype == MC_FLAG_RESET)
        mcg.mc_flags = MC_FLAG_POLLED;
    else if (calltype == MC_FLAG_CMCI)
        mcg.mc_flags = MC_FLAG_CMCI;
    mcg.mc_socketid = phys_proc_id[cpu];
    mcg.mc_coreid = cpu_core_id[cpu];
    mcg.mc_apicid = cpu_physical_id(cpu);
    mcg.mc_core_threadid = mcg.mc_apicid & ( 1 << (smp_num_siblings - 1)); 
    rdmsrl(MSR_IA32_MCG_STATUS, mcg.mc_gstatus);

    for ( i = 0; i < nr_mce_banks; i++ ) {
        struct mcinfo_bank mcb;
        /*For CMCI, only owners checks the owned MSRs*/
        if ( !test_bit(i, __get_cpu_var(mce_banks_owned)) &&
			(calltype & MC_FLAG_CMCI) )
            continue;
        rdmsrl(MSR_IA32_MC0_STATUS + 4 * i, status);

        if (! (status & MCi_STATUS_VAL) )
            continue;
        /*
         * Uncorrected events are handled by the exception
         * handler when it is enabled. But when the exception
         * is disabled such as when mcheck_init, log everything.
         */
        if ((status & MCi_STATUS_UC) && exceptions)
            continue;

        if (status & MCi_STATUS_UC)
            uc = 1;
        if (status & MCi_STATUS_PCC)
            pcc = 1;

        memset(&mcb, 0, sizeof(mcb));
        mcb.common.type = MC_TYPE_BANK;
        mcb.common.size = sizeof(mcb);
        mcb.mc_bank = i;
        mcb.mc_status = status;
        if (status & MCi_STATUS_MISCV)
            rdmsrl(MSR_IA32_MC0_MISC + 4 * i, mcb.mc_misc);
        if (status & MCi_STATUS_ADDRV) {
            rdmsrl(MSR_IA32_MC0_ADDR + 4 * i, addr);
            d = maddr_get_owner(addr);
            if ( d && (calltype == MC_FLAG_CMCI || calltype == MC_FLAG_POLLED) )
                mcb.mc_domid = d->domain_id;
        }
        if (cmci_support)
            rdmsrl(MSR_IA32_MC0_CTL2 + i, mcb.mc_ctrl2);
        if (calltype == MC_FLAG_CMCI)
            rdtscll(mcb.mc_tsc);
        x86_mcinfo_add(mi, &mcb);
        nr_unit++;
        add_taint(TAINT_MACHINE_CHECK);
        /*Clear state for this bank */
        wrmsrl(MSR_IA32_MC0_STATUS + 4 * i, 0);
        printk(KERN_DEBUG "mcheck_poll: bank%i CPU%d status[%lx]\n", 
                i, cpu, status);
        printk(KERN_DEBUG "mcheck_poll: CPU%d, SOCKET%d, CORE%d, APICID[%d], "
                "thread[%d]\n", cpu, mcg.mc_socketid, 
                mcg.mc_coreid, mcg.mc_apicid, mcg.mc_core_threadid);
 
    }
    /*if pcc = 1, uc must be 1*/
    if (pcc)
        mcg.mc_flags |= MC_FLAG_UNCORRECTABLE;
    else if (uc)
        mcg.mc_flags |= MC_FLAG_RECOVERABLE;
    else /*correctable*/
        mcg.mc_flags |= MC_FLAG_CORRECTABLE;

    if (nr_unit && nr_intel_ext_msrs && 
                    (mcg.mc_gstatus & MCG_STATUS_EIPV)) {
        intel_get_extended_msrs(&mce);
        x86_mcinfo_add(mi, &mce);
    }
    if (nr_unit) 
        x86_mcinfo_add(mi, &mcg);
    /*Clear global state*/
    return nr_unit;
}

static fastcall void intel_machine_check(struct cpu_user_regs * regs, long error_code)
{
    /* MACHINE CHECK Error handler will be sent in another patch,
     * simply copy old solutions here. This code will be replaced
     * by upcoming machine check patches
     */

    int recover=1;
    u32 alow, ahigh, high, low;
    u32 mcgstl, mcgsth;
    int i;
   
    rdmsr (MSR_IA32_MCG_STATUS, mcgstl, mcgsth);
    if (mcgstl & (1<<0))	/* Recoverable ? */
    	recover=0;
    
    printk (KERN_EMERG "CPU %d: Machine Check Exception: %08x%08x\n",
    	smp_processor_id(), mcgsth, mcgstl);
    
    for (i=0; i<nr_mce_banks; i++) {
    	rdmsr (MSR_IA32_MC0_STATUS+i*4,low, high);
    	if (high & (1<<31)) {
    		if (high & (1<<29))
    			recover |= 1;
    		if (high & (1<<25))
    			recover |= 2;
    		printk (KERN_EMERG "Bank %d: %08x%08x", i, high, low);
    		high &= ~(1<<31);
    		if (high & (1<<27)) {
    			rdmsr (MSR_IA32_MC0_MISC+i*4, alow, ahigh);
    			printk ("[%08x%08x]", ahigh, alow);
    		}
    		if (high & (1<<26)) {
    			rdmsr (MSR_IA32_MC0_ADDR+i*4, alow, ahigh);
    			printk (" at %08x%08x", ahigh, alow);
    		}
    		printk ("\n");
    	}
    }
    
    if (recover & 2)
    	mc_panic ("CPU context corrupt");
    if (recover & 1)
    	mc_panic ("Unable to continue");
    
    printk(KERN_EMERG "Attempting to continue.\n");
    /* 
     * Do not clear the MSR_IA32_MCi_STATUS if the error is not 
     * recoverable/continuable.This will allow BIOS to look at the MSRs
     * for errors if the OS could not log the error.
     */
    for (i=0; i<nr_mce_banks; i++) {
    	u32 msr;
    	msr = MSR_IA32_MC0_STATUS+i*4;
    	rdmsr (msr, low, high);
    	if (high&(1<<31)) {
    		/* Clear it */
    		wrmsr(msr, 0UL, 0UL);
    		/* Serialize */
    		wmb();
    		add_taint(TAINT_MACHINE_CHECK);
    	}
    }
    mcgstl &= ~(1<<2);
    wrmsr (MSR_IA32_MCG_STATUS,mcgstl, mcgsth);
}

extern void (*cpu_down_handler)(int down_cpu);
extern void (*cpu_down_rollback_handler)(int down_cpu);
extern void mce_disable_cpu(void);
static bool_t cmci_clear_lock = 0;
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
     /*
      * This bank does not support CMCI. The polling
      * timer has to handle it. 
      */
    	set_bit(i, __get_cpu_var(no_cmci_banks));
    	return 0;
    }
    set_bit(i, __get_cpu_var(mce_banks_owned));
out:
    clear_bit(i, __get_cpu_var(no_cmci_banks));
    return 1;
}

void cmci_discover(void)
{
    int i;

    printk(KERN_DEBUG "CMCI: find owner on CPU%d\n", smp_processor_id());
    spin_lock(&cmci_discover_lock);
    for (i = 0; i < nr_mce_banks; i++) {
        /*If the cpu is the bank owner, need not re-discover*/
        if (test_bit(i, __get_cpu_var(mce_banks_owned)))
            continue;
        do_cmci_discover(i);
    }
    spin_unlock(&cmci_discover_lock);
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

/*we need to re-set cmci owners when cpu_down fail or cpu_up*/
static void cmci_reenable_cpu(void *h)
{
    if (!mce_available(&current_cpu_data) || mce_disabled == 1)
         return;
    printk(KERN_DEBUG "CMCI: reenable mce on CPU%d\n", smp_processor_id());
    mce_set_owner();
    set_in_cr4(X86_CR4_MCE);
}

/* When take cpu_down, we need to execute the impacted cmci_owner judge algorithm 
 * First, we need to clear the ownership on the dead CPU
 * Then,  other CPUs will check whether to take the bank's ownership from down_cpu
 * CPU0 need not and "never" execute this path
*/
void  __cpu_clear_cmci( int down_cpu)
{
    int cpu = smp_processor_id();

    if (!cmci_support && mce_disabled == 1)
        return;

    if (cpu == 0) {
        printk(KERN_DEBUG "CMCI: CPU0 need not be cleared\n");
        return;
    }

    local_irq_disable();
    if (cpu == down_cpu){
        mce_disable_cpu();
        clear_cmci();
        wmb();
        test_and_set_bool(cmci_clear_lock);
        return;
    }
    while (!cmci_clear_lock)
        cpu_relax();
    if (cpu != down_cpu)
        mce_set_owner();

    test_and_clear_bool(cmci_clear_lock);
    local_irq_enable();

}

void  __cpu_clear_cmci_rollback( int down_cpu)
{
    cpumask_t down_map;
    if (!cmci_support || mce_disabled == 1) 
        return;

    cpus_clear(down_map);
    cpu_set(down_cpu, down_map);
    printk(KERN_ERR "CMCI: cpu_down fail. "
        "Reenable cmci on CPU%d\n", down_cpu);
    on_selected_cpus(down_map, cmci_reenable_cpu, NULL, 1, 1);
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

	/*now clear mask flag*/
    l = apic_read(APIC_CMCI);
    apic_write_around(APIC_CMCI, l & ~APIC_LVT_MASKED);
    cpu_down_handler =  __cpu_clear_cmci;
    cpu_down_rollback_handler = __cpu_clear_cmci_rollback; 
}

fastcall void smp_cmci_interrupt(struct cpu_user_regs *regs)
{
    int nr_unit;
    struct mc_info *mi =  x86_mcinfo_getptr();
    int cpu = smp_processor_id();

    ack_APIC_irq();
    irq_enter();
    printk(KERN_DEBUG "CMCI: cmci_intr happen on CPU%d\n", cpu);
    nr_unit = machine_check_poll(mi, MC_FLAG_CMCI);
    if (nr_unit) {
        x86_mcinfo_dump(mi);
        if (dom0 && guest_enabled_event(dom0->vcpu[0], VIRQ_MCA))
            send_guest_global_virq(dom0, VIRQ_MCA);
    }
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
    /* for most of p6 family, bank 0 is an alias bios MSR.
     * But after model>1a, bank 0 is available*/
    if ( c->x86 == 6 && c->x86_vendor == X86_VENDOR_INTEL
            && c->x86_model < 0x1A)
        firstbank = 1;
    else
        firstbank = 0;
}

static void mce_init(void)
{
    u32 l, h;
    int i, nr_unit;
    struct mc_info *mi =  x86_mcinfo_getptr();
    clear_in_cr4(X86_CR4_MCE);
    /* log the machine checks left over from the previous reset.
     * This also clears all registers*/

    nr_unit = machine_check_poll(mi, MC_FLAG_RESET);
    /*in the boot up stage, not expect inject to DOM0, but go print out
    */
    if (nr_unit > 0)
        x86_mcinfo_dump(mi);

    set_in_cr4(X86_CR4_MCE);
    rdmsr (MSR_IA32_MCG_CAP, l, h);
    if (l & MCG_CTL_P)	/* Control register present ? */
        wrmsr(MSR_IA32_MCG_CTL, 0xffffffff, 0xffffffff);

    for (i = firstbank; i < nr_mce_banks; i++)
    {
        /*Some banks are shared across cores, use MCi_CTRL to judge whether
         * this bank has been initialized by other cores already.*/
        rdmsr(MSR_IA32_MC0_CTL + 4*i, l, h);
        if (!l & !h)
        {
            /*if ctl is 0, this bank is never initialized*/
            printk(KERN_DEBUG "mce_init: init bank%d\n", i);
            wrmsr (MSR_IA32_MC0_CTL + 4*i, 0xffffffff, 0xffffffff);
            wrmsr (MSR_IA32_MC0_STATUS + 4*i, 0x0, 0x0);
       }
    }
    if (firstbank) /*if cmci enabled, firstbank = 0*/
        wrmsr (MSR_IA32_MC0_STATUS, 0x0, 0x0);
}

/*p4/p6 faimily has similar MCA initialization process*/
void intel_mcheck_init(struct cpuinfo_x86 *c)
{
	
	mce_cap_init(c);
	printk (KERN_INFO "Intel machine check reporting enabled on CPU#%d.\n",
		smp_processor_id());
	/* machine check is available */
	machine_check_vector = intel_machine_check;
	mce_init();
	mce_intel_feature_init(c);
	mce_set_owner();
}

/*
 * Periodic polling timer for "silent" machine check errors. If the
 * poller finds an MCE, poll faster. When the poller finds no more 
 * errors, poll slower
*/
static struct timer mce_timer;

#define MCE_PERIOD 4000
#define MCE_MIN    2000
#define MCE_MAX    32000

static u64 period = MCE_PERIOD;
static int adjust = 0;

static void mce_intel_checkregs(void *info)
{
    int nr_unit;
    struct mc_info *mi =  x86_mcinfo_getptr();

    if( !mce_available(&current_cpu_data))
        return;
    nr_unit = machine_check_poll(mi, MC_FLAG_POLLED);
    if (nr_unit)
    {
        x86_mcinfo_dump(mi);
        adjust++;
        if (dom0 && guest_enabled_event(dom0->vcpu[0], VIRQ_MCA))
            send_guest_global_virq(dom0, VIRQ_MCA);
    }
}

static void mce_intel_work_fn(void *data)
{
    on_each_cpu(mce_intel_checkregs, data, 1, 1);
    if (adjust) {
        period = period / (adjust + 1);
        printk(KERN_DEBUG "mcheck_poll: Find error, shorten interval to %ld",
            period);
    }
    else {
        period *= 2;
    }
    if (period > MCE_MAX) 
        period = MCE_MAX;
    if (period < MCE_MIN)
        period = MCE_MIN;
    set_timer(&mce_timer, NOW() + MILLISECS(period));
    adjust = 0;
}

void intel_mcheck_timer(struct cpuinfo_x86 *c)
{
    printk(KERN_DEBUG "mcheck_poll: Init_mcheck_timer\n");
    init_timer(&mce_timer, mce_intel_work_fn, NULL, 0);
    set_timer(&mce_timer, NOW() + MILLISECS(MCE_PERIOD));
}

