/*
 *  linux/arch/i386/nmi.c
 *
 *  NMI watchdog support on APIC systems
 *
 *  Started by Ingo Molnar <mingo@redhat.com>
 *
 *  Fixes:
 *  Mikael Pettersson	: AMD K7 support for local APIC NMI watchdog.
 *  Mikael Pettersson	: Power Management for local APIC NMI watchdog.
 *  Mikael Pettersson	: Pentium 4 support for local APIC NMI watchdog.
 *  Keir Fraser         : Pentium 4 Hyperthreading support
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
#include <asm/current.h>
#include <asm/mc146818rtc.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/debugger.h>

unsigned int nmi_watchdog = NMI_NONE;
static unsigned int nmi_hz = HZ;
static unsigned int nmi_perfctr_msr;	/* the MSR to reset in NMI handler */
static unsigned int nmi_p4_cccr_val;
static struct ac_timer nmi_timer[NR_CPUS];
static unsigned int nmi_timer_ticks[NR_CPUS];

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
#define P6_EVENT_CPU_CLOCKS_NOT_HALTED	0x79
#define P6_NMI_EVENT		P6_EVENT_CPU_CLOCKS_NOT_HALTED

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
    unsigned int prev_nmi_count[NR_CPUS];
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

    /* now that we know it works we can reduce NMI frequency to
       something more reasonable; makes a difference in some configs */
    if ( nmi_watchdog == NMI_LOCAL_APIC )
        nmi_hz = 1;

    return 0;
}

static void nmi_timer_fn(void *unused)
{
    int cpu = smp_processor_id();
    nmi_timer_ticks[cpu]++;
    set_ac_timer(&nmi_timer[cpu], NOW() + MILLISECS(1000));
}

static inline void nmi_pm_init(void) { }
#define __pminit	__init

/*
 * Activate the NMI watchdog via the local APIC.
 * Original code written by Keith Owens.
 */

static void __pminit clear_msr_range(unsigned int base, unsigned int n)
{
    unsigned int i;
    for ( i = 0; i < n; i++ )
        wrmsr(base+i, 0, 0);
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
    Dprintk("setting K7_PERFCTR0 to %08lx\n", -(cpu_khz/nmi_hz*1000));
    wrmsr(MSR_K7_PERFCTR0, -(cpu_khz/nmi_hz*1000), -1);
    apic_write(APIC_LVTPC, APIC_DM_NMI);
    evntsel |= K7_EVNTSEL_ENABLE;
    wrmsr(MSR_K7_EVNTSEL0, evntsel, 0);
}

static void __pminit setup_p6_watchdog(void)
{
    unsigned int evntsel;

    nmi_perfctr_msr = MSR_P6_PERFCTR0;

    clear_msr_range(MSR_P6_EVNTSEL0, 2);
    clear_msr_range(MSR_P6_PERFCTR0, 2);

    evntsel = P6_EVNTSEL_INT
        | P6_EVNTSEL_OS
        | P6_EVNTSEL_USR
        | P6_NMI_EVENT;

    wrmsr(MSR_P6_EVNTSEL0, evntsel, 0);
    Dprintk("setting P6_PERFCTR0 to %08lx\n", -(cpu_khz/nmi_hz*1000));
    wrmsr(MSR_P6_PERFCTR0, -(cpu_khz/nmi_hz*1000), 0);
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
    if ( smp_num_siblings == 2 )
        nmi_p4_cccr_val |= P4_CCCR_OVF_PMI1;

    if (!(misc_enable & MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL))
        clear_msr_range(0x3F1, 2);
    /* MSR 0x3F0 seems to have a default value of 0xFC00, but current
       docs doesn't fully define it, so leave it alone for now. */
    clear_msr_range(0x3A0, 31);
    clear_msr_range(0x3C0, 6);
    clear_msr_range(0x3C8, 6);
    clear_msr_range(0x3E0, 2);
    clear_msr_range(MSR_P4_BPU_CCCR0, 18);
    clear_msr_range(MSR_P4_BPU_PERFCTR0, 18);
        
    wrmsr(MSR_P4_CRU_ESCR0, P4_NMI_CRU_ESCR0, 0);
    wrmsr(MSR_P4_IQ_CCCR0, P4_NMI_IQ_CCCR0 & ~P4_CCCR_ENABLE, 0);
    Dprintk("setting P4_IQ_PERFCTR0 to 0x%08lx\n", -(cpu_khz/nmi_hz*1000));
    wrmsr(MSR_P4_IQ_PERFCTR0, -(cpu_khz/nmi_hz*1000), -1);
    apic_write(APIC_LVTPC, APIC_DM_NMI);
    wrmsr(MSR_P4_IQ_CCCR0, nmi_p4_cccr_val, 0);

    return 1;
}

void __pminit setup_apic_nmi_watchdog(void)
{
    int cpu = smp_processor_id();

    if (!nmi_watchdog)
        return;

    switch (boot_cpu_data.x86_vendor) {
    case X86_VENDOR_AMD:
        if (boot_cpu_data.x86 != 6 && boot_cpu_data.x86 != 15)
            return;
        setup_k7_watchdog();
        break;
    case X86_VENDOR_INTEL:
        switch (boot_cpu_data.x86) {
        case 6:
            setup_p6_watchdog();
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

    init_ac_timer(&nmi_timer[cpu], nmi_timer_fn, NULL, cpu);

    nmi_pm_init();
}


static unsigned int
last_irq_sums [NR_CPUS],
    alert_counter [NR_CPUS];

static spinlock_t   watchdog_lock = SPIN_LOCK_UNLOCKED;
static unsigned int watchdog_disable_count = 1;
static unsigned int watchdog_on;

void watchdog_disable(void)
{
    unsigned long flags;

    spin_lock_irqsave(&watchdog_lock, flags);

    if ( watchdog_disable_count++ == 0 )
        watchdog_on = 0;

    spin_unlock_irqrestore(&watchdog_lock, flags);
}

void watchdog_enable(void)
{
    unsigned int  cpu;
    unsigned long flags;

    spin_lock_irqsave(&watchdog_lock, flags);

    if ( --watchdog_disable_count == 0 )
    {
        watchdog_on = 1;
        /*
         * Ensure periodic heartbeats are active. We cannot do this earlier
         * during setup because the timer infrastructure is not available. 
         */
        for_each_online_cpu ( cpu )
            set_ac_timer(&nmi_timer[cpu], NOW());
    }

    spin_unlock_irqrestore(&watchdog_lock, flags);
}

void nmi_watchdog_tick(struct cpu_user_regs * regs)
{
    int sum, cpu = smp_processor_id();

    sum = nmi_timer_ticks[cpu];

    if ( (last_irq_sums[cpu] == sum) && watchdog_on )
    {
        /*
         * Ayiee, looks like this CPU is stuck ... wait a few IRQs (5 seconds) 
         * before doing the oops ...
         */
        alert_counter[cpu]++;
        if ( alert_counter[cpu] == 5*nmi_hz )
        {
            console_force_unlock();
            printk("Watchdog timer detects that CPU%d is stuck!\n", cpu);
            fatal_trap(TRAP_nmi, regs);
        }
    } 
    else 
    {
        last_irq_sums[cpu] = sum;
        alert_counter[cpu] = 0;
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
        wrmsr(nmi_perfctr_msr, -(cpu_khz/nmi_hz*1000), -1);
    }
}
