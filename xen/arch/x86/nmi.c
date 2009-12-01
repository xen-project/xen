/*
 *  linux/arch/i386/nmi.c
 *
 *  NMI watchdog support on APIC systems
 *
 *  Started by Ingo Molnar <mingo@redhat.com>
 *
 *  Fixes:
 *  Mikael Pettersson : AMD K7 support for local APIC NMI watchdog.
 *  Mikael Pettersson : Power Management for local APIC NMI watchdog.
 *  Mikael Pettersson : Pentium 4 support for local APIC NMI watchdog.
 *  Pavel Machek and
 *  Mikael Pettersson : PM converted to driver model. Disable/enable API.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/time.h>
#include <xen/sched.h>
#include <xen/console.h>
#include <xen/smp.h>
#include <xen/keyhandler.h>
#include <asm/current.h>
#include <asm/mc146818rtc.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/debugger.h>
#include <asm/div64.h>
#include <asm/apic.h>

unsigned int nmi_watchdog = NMI_NONE;
static unsigned int nmi_hz = HZ;
static unsigned int nmi_perfctr_msr;	/* the MSR to reset in NMI handler */
static unsigned int nmi_p4_cccr_val;
static DEFINE_PER_CPU(struct timer, nmi_timer);
static DEFINE_PER_CPU(unsigned int, nmi_timer_ticks);

/*
 * lapic_nmi_owner tracks the ownership of the lapic NMI hardware:
 * - it may be reserved by some other driver, or not
 * - when not reserved by some other driver, it may be used for
 *   the NMI watchdog, or not
 *
 * This is maintained separately from nmi_active because the NMI
 * watchdog may also be driven from the I/O APIC timer.
 */
static DEFINE_SPINLOCK(lapic_nmi_owner_lock);
static unsigned int lapic_nmi_owner;
#define LAPIC_NMI_WATCHDOG	(1<<0)
#define LAPIC_NMI_RESERVED	(1<<1)

/* nmi_active:
 * +1: the lapic NMI watchdog is active, but can be disabled
 *  0: the lapic NMI watchdog has not been set up, and cannot
 *     be enabled
 * -1: the lapic NMI watchdog is disabled, but can be enabled
 */
int nmi_active;

#define K7_EVNTSEL_ENABLE	(1 << 22)
#define K7_EVNTSEL_INT		(1 << 20)
#define K7_EVNTSEL_OS		(1 << 17)
#define K7_EVNTSEL_USR		(1 << 16)
#define K7_EVENT_CYCLES_PROCESSOR_IS_RUNNING	0x76
#define K7_NMI_EVENT		K7_EVENT_CYCLES_PROCESSOR_IS_RUNNING

#define P6_EVNTSEL0_ENABLE	(1 << 22)
#define P6_EVNTSEL_INT		(1 << 20)
#define P6_EVNTSEL_OS		(1 << 17)
#define P6_EVNTSEL_USR		(1 << 16)
#define P6_EVENT_CPU_CLOCKS_NOT_HALTED	 0x79
#define CORE_EVENT_CPU_CLOCKS_NOT_HALTED 0x3c

#define P4_ESCR_EVENT_SELECT(N)	((N)<<25)
#define P4_CCCR_OVF_PMI0	(1<<26)
#define P4_CCCR_OVF_PMI1	(1<<27)
#define P4_CCCR_THRESHOLD(N)	((N)<<20)
#define P4_CCCR_COMPLEMENT	(1<<19)
#define P4_CCCR_COMPARE		(1<<18)
#define P4_CCCR_REQUIRED	(3<<16)
#define P4_CCCR_ESCR_SELECT(N)	((N)<<13)
#define P4_CCCR_ENABLE		(1<<12)
/* 
 * Set up IQ_PERFCTR0 to behave like a clock, by having IQ_CCCR0 filter
 * CRU_ESCR0 (with any non-null event selector) through a complemented
 * max threshold. [IA32-Vol3, Section 14.9.9] 
 */
#define P4_NMI_CRU_ESCR0	P4_ESCR_EVENT_SELECT(0x3F)
#define P4_NMI_IQ_CCCR0	\
    (P4_CCCR_OVF_PMI0|P4_CCCR_THRESHOLD(15)|P4_CCCR_COMPLEMENT| \
     P4_CCCR_COMPARE|P4_CCCR_REQUIRED|P4_CCCR_ESCR_SELECT(4)|P4_CCCR_ENABLE)

int __init check_nmi_watchdog (void)
{
    static unsigned int __initdata prev_nmi_count[NR_CPUS];
    int cpu;
    
    if ( !nmi_watchdog )
        return 0;

    printk("Testing NMI watchdog --- ");

    for ( cpu = 0; cpu < NR_CPUS; cpu++ ) 
        prev_nmi_count[cpu] = nmi_count(cpu);
    local_irq_enable();
    mdelay((10*1000)/nmi_hz); /* wait 10 ticks */

    for ( cpu = 0; cpu < NR_CPUS; cpu++ ) 
    {
        if ( !cpu_isset(cpu, cpu_callin_map) && 
             !cpu_isset(cpu, cpu_online_map) )
            continue;
        if ( nmi_count(cpu) - prev_nmi_count[cpu] <= 5 )
            printk("CPU#%d stuck. ", cpu);
        else
            printk("CPU#%d okay. ", cpu);
    }

    printk("\n");

    /*
     * Now that we know it works we can reduce NMI frequency to
     * something more reasonable; makes a difference in some configs.
     * There's a limit to how slow we can go because writing the perfctr
     * MSRs only sets the low 32 bits, with the top 8 bits sign-extended
     * from those, so it's not possible to set up a delay larger than
     * 2^31 cycles and smaller than (2^40 - 2^31) cycles. 
     * (Intel SDM, section 18.22.2)
     */
    if ( nmi_watchdog == NMI_LOCAL_APIC )
        nmi_hz = max(1ul, cpu_khz >> 20);

    return 0;
}

static void nmi_timer_fn(void *unused)
{
    this_cpu(nmi_timer_ticks)++;
    set_timer(&this_cpu(nmi_timer), NOW() + MILLISECS(1000));
}

static void disable_lapic_nmi_watchdog(void)
{
    if (nmi_active <= 0)
        return;
    switch (boot_cpu_data.x86_vendor) {
    case X86_VENDOR_AMD:
        wrmsr(MSR_K7_EVNTSEL0, 0, 0);
        break;
    case X86_VENDOR_INTEL:
        switch (boot_cpu_data.x86) {
        case 6:
            if (boot_cpu_data.x86_model > 0xd)
                break;

            wrmsr(MSR_P6_EVNTSEL0, 0, 0);
            break;
        case 15:
            if (boot_cpu_data.x86_model > 0x4)
                break;

            wrmsr(MSR_P4_IQ_CCCR0, 0, 0);
            wrmsr(MSR_P4_CRU_ESCR0, 0, 0);
            break;
        }
        break;
    }
    nmi_active = -1;
    /* tell do_nmi() and others that we're not active any more */
    nmi_watchdog = 0;
}

static void enable_lapic_nmi_watchdog(void)
{
    if (nmi_active < 0) {
        nmi_watchdog = NMI_LOCAL_APIC;
        setup_apic_nmi_watchdog();
    }
}

int reserve_lapic_nmi(void)
{
    unsigned int old_owner;

    spin_lock(&lapic_nmi_owner_lock);
    old_owner = lapic_nmi_owner;
    lapic_nmi_owner |= LAPIC_NMI_RESERVED;
    spin_unlock(&lapic_nmi_owner_lock);
    if (old_owner & LAPIC_NMI_RESERVED)
        return -EBUSY;
    if (old_owner & LAPIC_NMI_WATCHDOG)
        disable_lapic_nmi_watchdog();
    return 0;
}

void release_lapic_nmi(void)
{
    unsigned int new_owner;

    spin_lock(&lapic_nmi_owner_lock);
    new_owner = lapic_nmi_owner & ~LAPIC_NMI_RESERVED;
    lapic_nmi_owner = new_owner;
    spin_unlock(&lapic_nmi_owner_lock);
    if (new_owner & LAPIC_NMI_WATCHDOG)
        enable_lapic_nmi_watchdog();
}

#define __pminit __devinit

/*
 * Activate the NMI watchdog via the local APIC.
 * Original code written by Keith Owens.
 */

static void __pminit clear_msr_range(unsigned int base, unsigned int n)
{
    unsigned int i;

    for (i = 0; i < n; i++)
        wrmsr(base+i, 0, 0);
}

static inline void write_watchdog_counter(const char *descr)
{
    u64 count = (u64)cpu_khz * 1000;

    do_div(count, nmi_hz);
    if(descr)
        Dprintk("setting %s to -0x%08Lx\n", descr, count);
    wrmsrl(nmi_perfctr_msr, 0 - count);
}

static void __pminit setup_k7_watchdog(void)
{
    unsigned int evntsel;

    nmi_perfctr_msr = MSR_K7_PERFCTR0;

    clear_msr_range(MSR_K7_EVNTSEL0, 4);
    clear_msr_range(MSR_K7_PERFCTR0, 4);

    evntsel = K7_EVNTSEL_INT
        | K7_EVNTSEL_OS
        | K7_EVNTSEL_USR
        | K7_NMI_EVENT;

    wrmsr(MSR_K7_EVNTSEL0, evntsel, 0);
    write_watchdog_counter("K7_PERFCTR0");
    apic_write(APIC_LVTPC, APIC_DM_NMI);
    evntsel |= K7_EVNTSEL_ENABLE;
    wrmsr(MSR_K7_EVNTSEL0, evntsel, 0);
}

static void __pminit setup_p6_watchdog(unsigned counter)
{
    unsigned int evntsel;

    nmi_perfctr_msr = MSR_P6_PERFCTR0;

    clear_msr_range(MSR_P6_EVNTSEL0, 2);
    clear_msr_range(MSR_P6_PERFCTR0, 2);

    evntsel = P6_EVNTSEL_INT
        | P6_EVNTSEL_OS
        | P6_EVNTSEL_USR
        | counter;

    wrmsr(MSR_P6_EVNTSEL0, evntsel, 0);
    write_watchdog_counter("P6_PERFCTR0");
    apic_write(APIC_LVTPC, APIC_DM_NMI);
    evntsel |= P6_EVNTSEL0_ENABLE;
    wrmsr(MSR_P6_EVNTSEL0, evntsel, 0);
}

static int __pminit setup_p4_watchdog(void)
{
    unsigned int misc_enable, dummy;

    rdmsr(MSR_IA32_MISC_ENABLE, misc_enable, dummy);
    if (!(misc_enable & MSR_IA32_MISC_ENABLE_PERF_AVAIL))
        return 0;

    nmi_perfctr_msr = MSR_P4_IQ_PERFCTR0;
    nmi_p4_cccr_val = P4_NMI_IQ_CCCR0;
    if ( boot_cpu_data.x86_num_siblings == 2 )
        nmi_p4_cccr_val |= P4_CCCR_OVF_PMI1;

    if (!(misc_enable & MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL))
        clear_msr_range(0x3F1, 2);
    /* MSR 0x3F0 seems to have a default value of 0xFC00, but current
       docs doesn't fully define it, so leave it alone for now. */
    if (boot_cpu_data.x86_model >= 0x3) {
        /* MSR_P4_IQ_ESCR0/1 (0x3ba/0x3bb) removed */
        clear_msr_range(0x3A0, 26);
        clear_msr_range(0x3BC, 3);
    } else {
        clear_msr_range(0x3A0, 31);
    }
    clear_msr_range(0x3C0, 6);
    clear_msr_range(0x3C8, 6);
    clear_msr_range(0x3E0, 2);
    clear_msr_range(MSR_P4_BPU_CCCR0, 18);
    clear_msr_range(MSR_P4_BPU_PERFCTR0, 18);
        
    wrmsr(MSR_P4_CRU_ESCR0, P4_NMI_CRU_ESCR0, 0);
    wrmsr(MSR_P4_IQ_CCCR0, P4_NMI_IQ_CCCR0 & ~P4_CCCR_ENABLE, 0);
    write_watchdog_counter("P4_IQ_COUNTER0");
    apic_write(APIC_LVTPC, APIC_DM_NMI);
    wrmsr(MSR_P4_IQ_CCCR0, nmi_p4_cccr_val, 0);
    return 1;
}

void __pminit setup_apic_nmi_watchdog(void)
{
    if (!nmi_watchdog)
        return;

    switch (boot_cpu_data.x86_vendor) {
    case X86_VENDOR_AMD:
        switch (boot_cpu_data.x86) {
        case 6:
        case 15 ... 17:
            setup_k7_watchdog();
            break;
        default:
            return;
        }
        break;
    case X86_VENDOR_INTEL:
        switch (boot_cpu_data.x86) {
        case 6:
            setup_p6_watchdog((boot_cpu_data.x86_model < 14) 
                              ? P6_EVENT_CPU_CLOCKS_NOT_HALTED
                              : CORE_EVENT_CPU_CLOCKS_NOT_HALTED);
            break;
        case 15:
            if (!setup_p4_watchdog())
                return;
            break;
        default:
            return;
        }
        break;
    default:
        return;
    }

    lapic_nmi_owner = LAPIC_NMI_WATCHDOG;
    nmi_active = 1;
}

static DEFINE_PER_CPU(unsigned int, last_irq_sums);
static DEFINE_PER_CPU(unsigned int, alert_counter);

static atomic_t watchdog_disable_count = ATOMIC_INIT(1);

void watchdog_disable(void)
{
    atomic_inc(&watchdog_disable_count);
}

void watchdog_enable(void)
{
    static unsigned long heartbeat_initialised;
    unsigned int cpu;

    if ( !atomic_dec_and_test(&watchdog_disable_count) ||
         test_and_set_bit(0, &heartbeat_initialised) )
        return;

    /*
     * Activate periodic heartbeats. We cannot do this earlier during 
     * setup because the timer infrastructure is not available.
     */
    for_each_online_cpu ( cpu )
    {
        init_timer(&per_cpu(nmi_timer, cpu), nmi_timer_fn, NULL, cpu);
        set_timer(&per_cpu(nmi_timer, cpu), NOW());
    }
}

void nmi_watchdog_tick(struct cpu_user_regs * regs)
{
    unsigned int sum = this_cpu(nmi_timer_ticks);

    if ( (this_cpu(last_irq_sums) == sum) &&
         !atomic_read(&watchdog_disable_count) )
    {
        /*
         * Ayiee, looks like this CPU is stuck ... wait a few IRQs (5 seconds) 
         * before doing the oops ...
         */
        this_cpu(alert_counter)++;
        if ( this_cpu(alert_counter) == 5*nmi_hz )
        {
            console_force_unlock();
            printk("Watchdog timer detects that CPU%d is stuck!\n",
                   smp_processor_id());
            fatal_trap(TRAP_nmi, regs);
        }
    } 
    else 
    {
        this_cpu(last_irq_sums) = sum;
        this_cpu(alert_counter) = 0;
    }

    if ( nmi_perfctr_msr )
    {
        if ( nmi_perfctr_msr == MSR_P4_IQ_PERFCTR0 )
        {
            /*
             * P4 quirks:
             * - An overflown perfctr will assert its interrupt
             *   until the OVF flag in its CCCR is cleared.
             * - LVTPC is masked on interrupt and must be
             *   unmasked by the LVTPC handler.
             */
            wrmsr(MSR_P4_IQ_CCCR0, nmi_p4_cccr_val, 0);
            apic_write(APIC_LVTPC, APIC_DM_NMI);
        }
        else if ( nmi_perfctr_msr == MSR_P6_PERFCTR0 )
        {
            /*
             * Only P6 based Pentium M need to re-unmask the apic vector but
             * it doesn't hurt other P6 variants.
             */
            apic_write(APIC_LVTPC, APIC_DM_NMI);
        }
        write_watchdog_counter(NULL);
    }
}

/*
 * For some reason the destination shorthand for self is not valid
 * when used with the NMI delivery mode. This is documented in Tables
 * 8-3 and 8-4 in IA32 Reference Manual Volume 3. We send the IPI to
 * our own APIC ID explicitly which is valid.
 */
void self_nmi(void) 
{
    u32 id = get_apic_id();
    local_irq_disable();
    apic_wait_icr_idle();
    apic_icr_write(APIC_DM_NMI | APIC_DEST_PHYSICAL, id);
    local_irq_enable();
}

static void do_nmi_trigger(unsigned char key)
{
    printk("Triggering NMI on APIC ID %x\n", get_apic_id());
    self_nmi();
}

static struct keyhandler nmi_trigger_keyhandler = {
    .u.fn = do_nmi_trigger,
    .desc = "trigger an NMI"
};

static void do_nmi_stats(unsigned char key)
{
    int i;
    struct domain *d;
    struct vcpu *v;

    printk("CPU\tNMI\n");
    for_each_possible_cpu ( i )
        printk("%3d\t%3d\n", i, nmi_count(i));

    if ( ((d = dom0) == NULL) || (d->vcpu == NULL) ||
         ((v = d->vcpu[0]) == NULL) )
        return;

    i = v->async_exception_mask & (1 << VCPU_TRAP_NMI);
    if ( v->nmi_pending || i )
        printk("dom0 vpu0: NMI %s%s\n",
               v->nmi_pending ? "pending " : "",
               i ? "masked " : "");
    else
        printk("dom0 vcpu0: NMI neither pending nor masked\n");
}

static struct keyhandler nmi_stats_keyhandler = {
    .diagnostic = 1,
    .u.fn = do_nmi_stats,
    .desc = "NMI statistics"
};

static __init int register_nmi_trigger(void)
{
    register_keyhandler('N', &nmi_trigger_keyhandler);
    register_keyhandler('n', &nmi_stats_keyhandler);
    return 0;
}
__initcall(register_nmi_trigger);
