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

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/time.h>
#include <xen/sched.h>
#include <xen/console.h>
#include <xen/smp.h>
#include <xen/keyhandler.h>
#include <xen/cpu.h>
#include <asm/current.h>
#include <asm/mc146818rtc.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/nmi.h>
#include <asm/debugger.h>
#include <asm/div64.h>
#include <asm/apic.h>

unsigned int nmi_watchdog = NMI_NONE;
static unsigned int nmi_hz = HZ;
static unsigned int nmi_perfctr_msr;	/* the MSR to reset in NMI handler */
static unsigned int nmi_p4_cccr_val;
static unsigned int nmi_p6_event_width;
static DEFINE_PER_CPU(struct timer, nmi_timer);
static DEFINE_PER_CPU(unsigned int, nmi_timer_ticks);

/* opt_watchdog: If true, run a watchdog NMI on each processor. */
bool __initdata opt_watchdog;

/* watchdog_force: If true, process unknown NMIs when running the watchdog. */
bool watchdog_force;

static int __init parse_watchdog(const char *s)
{
    if ( !*s )
    {
        opt_watchdog = true;
        return 0;
    }

    switch ( parse_bool(s, NULL) )
    {
    case 0:
        opt_watchdog = false;
        return 0;
    case 1:
        opt_watchdog = true;
        return 0;
    }

    if ( !strcmp(s, "force") )
        watchdog_force = opt_watchdog = true;
    else
        return -EINVAL;

    return 0;
}
custom_param("watchdog", parse_watchdog);

/* opt_watchdog_timeout: Number of seconds to wait before panic. */
static unsigned int opt_watchdog_timeout = 5;

static int parse_watchdog_timeout(const char *s)
{
    const char *q;

    opt_watchdog_timeout = simple_strtoull(s, &q, 0);
    opt_watchdog = !!opt_watchdog_timeout;

    return *q ? -EINVAL : 0;
}
custom_param("watchdog_timeout", parse_watchdog_timeout);

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
#define K7_EVENT_WIDTH          32

#define P6_EVNTSEL0_ENABLE	(1 << 22)
#define P6_EVNTSEL_INT		(1 << 20)
#define P6_EVNTSEL_OS		(1 << 17)
#define P6_EVNTSEL_USR		(1 << 16)
#define P6_EVENT_CPU_CLOCKS_NOT_HALTED	 0x79
#define CORE_EVENT_CPU_CLOCKS_NOT_HALTED 0x3c
/* Bit width of IA32_PMCx MSRs is reported using CPUID.0AH:EAX[23:16]. */
#define P6_EVENT_WIDTH_MASK	(((1 << 8) - 1) << 16)
#define P6_EVENT_WIDTH_MIN	32

#define P4_ESCR_EVENT_SELECT(N)	((N)<<25)
#define P4_CCCR_OVF_PMI0	(1<<26)
#define P4_CCCR_OVF_PMI1	(1<<27)
#define P4_CCCR_OVF		(1<<31)
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

static void __init wait_for_nmis(void *p)
{
    unsigned int cpu = smp_processor_id();
    unsigned int start_count = nmi_count(cpu);
    unsigned long ticks = 10 * 1000 * cpu_khz / nmi_hz;
    unsigned long s, e;

    s = rdtsc();
    do {
        cpu_relax();
        if ( nmi_count(cpu) >= start_count + 2 )
            break;
        e = rdtsc();
    } while( e - s < ticks );
}

void __init check_nmi_watchdog(void)
{
    static unsigned int __initdata prev_nmi_count[NR_CPUS];
    int cpu;
    bool ok = true;

    if ( nmi_watchdog == NMI_NONE )
        return;

    printk("Testing NMI watchdog on all CPUs:");

    for_each_online_cpu ( cpu )
        prev_nmi_count[cpu] = nmi_count(cpu);

    /*
     * Wait at most 10 ticks for 2 watchdog NMIs on each CPU.
     * Busy-wait on all CPUs: the LAPIC counter that the NMI watchdog
     * uses only runs while the core's not halted
     */
    on_selected_cpus(&cpu_online_map, wait_for_nmis, NULL, 1);

    for_each_online_cpu ( cpu )
    {
        if ( nmi_count(cpu) - prev_nmi_count[cpu] < 2 )
        {
            printk(" %d", cpu);
            ok = false;
        }
    }

    printk(" %s\n", ok ? "ok" : "stuck");

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

    return;
}

static void nmi_timer_fn(void *unused)
{
    this_cpu(nmi_timer_ticks)++;
    set_timer(&this_cpu(nmi_timer), NOW() + MILLISECS(1000));
}

void disable_lapic_nmi_watchdog(void)
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
            wrmsr(MSR_P6_EVNTSEL(0), 0, 0);
            break;
        case 15:
            wrmsr(MSR_P4_IQ_CCCR0, 0, 0);
            wrmsr(MSR_P4_CRU_ESCR0, 0, 0);
            break;
        }
        break;
    }
    nmi_active = -1;
    /* tell do_nmi() and others that we're not active any more */
    nmi_watchdog = NMI_NONE;
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

/*
 * Activate the NMI watchdog via the local APIC.
 * Original code written by Keith Owens.
 */

static void clear_msr_range(unsigned int base, unsigned int n)
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
        Dprintk("setting %s to -%#"PRIx64"\n", descr, count);
    wrmsrl(nmi_perfctr_msr, 0 - count);
}

static void setup_k7_watchdog(void)
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

static void setup_p6_watchdog(unsigned counter)
{
    unsigned int evntsel;

    nmi_perfctr_msr = MSR_P6_PERFCTR(0);

    if ( !nmi_p6_event_width && current_cpu_data.cpuid_level >= 0xa )
        nmi_p6_event_width = MASK_EXTR(cpuid_eax(0xa), P6_EVENT_WIDTH_MASK);
    if ( !nmi_p6_event_width )
        nmi_p6_event_width = P6_EVENT_WIDTH_MIN;

    if ( nmi_p6_event_width < P6_EVENT_WIDTH_MIN ||
         nmi_p6_event_width > BITS_PER_LONG )
        return;

    clear_msr_range(MSR_P6_EVNTSEL(0), 2);
    clear_msr_range(MSR_P6_PERFCTR(0), 2);

    evntsel = P6_EVNTSEL_INT
        | P6_EVNTSEL_OS
        | P6_EVNTSEL_USR
        | counter;

    wrmsr(MSR_P6_EVNTSEL(0), evntsel, 0);
    write_watchdog_counter("P6_PERFCTR0");
    apic_write(APIC_LVTPC, APIC_DM_NMI);
    evntsel |= P6_EVNTSEL0_ENABLE;
    wrmsr(MSR_P6_EVNTSEL(0), evntsel, 0);
}

static int setup_p4_watchdog(void)
{
    uint64_t misc_enable;

    rdmsrl(MSR_IA32_MISC_ENABLE, misc_enable);
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
        
    wrmsrl(MSR_P4_CRU_ESCR0, P4_NMI_CRU_ESCR0);
    wrmsrl(MSR_P4_IQ_CCCR0, P4_NMI_IQ_CCCR0 & ~P4_CCCR_ENABLE);
    write_watchdog_counter("P4_IQ_COUNTER0");
    apic_write(APIC_LVTPC, APIC_DM_NMI);
    wrmsrl(MSR_P4_IQ_CCCR0, nmi_p4_cccr_val);
    return 1;
}

void setup_apic_nmi_watchdog(void)
{
    if ( nmi_watchdog == NMI_NONE )
        return;

    switch (boot_cpu_data.x86_vendor) {
    case X86_VENDOR_AMD:
        switch (boot_cpu_data.x86) {
        case 6:
        case 0xf ... 0x17:
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

static int cpu_nmi_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        init_timer(&per_cpu(nmi_timer, cpu), nmi_timer_fn, NULL, cpu);
        set_timer(&per_cpu(nmi_timer, cpu), NOW());
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        kill_timer(&per_cpu(nmi_timer, cpu));
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nmi_nfb = {
    .notifier_call = cpu_nmi_callback
};

static DEFINE_PER_CPU(unsigned int, last_irq_sums);
static DEFINE_PER_CPU(unsigned int, alert_counter);

static atomic_t watchdog_disable_count = ATOMIC_INIT(1);

void watchdog_disable(void)
{
    atomic_inc(&watchdog_disable_count);
}

void watchdog_enable(void)
{
    atomic_dec(&watchdog_disable_count);
}

bool watchdog_enabled(void)
{
    return !atomic_read(&watchdog_disable_count);
}

int __init watchdog_setup(void)
{
    unsigned int cpu;

    /*
     * Activate periodic heartbeats. We cannot do this earlier during 
     * setup because the timer infrastructure is not available.
     */
    for_each_online_cpu ( cpu )
        cpu_nmi_callback(&cpu_nmi_nfb, CPU_UP_PREPARE, (void *)(long)cpu);
    register_cpu_notifier(&cpu_nmi_nfb);

    watchdog_enable();
    return 0;
}

/* Returns false if this was not a watchdog NMI, true otherwise */
bool nmi_watchdog_tick(const struct cpu_user_regs *regs)
{
    bool watchdog_tick = true;
    unsigned int sum = this_cpu(nmi_timer_ticks);

    if ( (this_cpu(last_irq_sums) == sum) && watchdog_enabled() )
    {
        /*
         * Ayiee, looks like this CPU is stuck ... wait for the timeout
         * before doing the oops ...
         */
        this_cpu(alert_counter)++;
        if ( this_cpu(alert_counter) == opt_watchdog_timeout*nmi_hz )
        {
            console_force_unlock();
            printk("Watchdog timer detects that CPU%d is stuck!\n",
                   smp_processor_id());
            fatal_trap(regs, 1);
        }
    } 
    else 
    {
        this_cpu(last_irq_sums) = sum;
        this_cpu(alert_counter) = 0;
    }

    if ( nmi_perfctr_msr )
    {
        uint64_t msr_content;

        /* Work out if this is a watchdog tick by checking for overflow. */
        if ( nmi_perfctr_msr == MSR_P4_IQ_PERFCTR0 )
        {
            rdmsrl(MSR_P4_IQ_CCCR0, msr_content);
            if ( !(msr_content & P4_CCCR_OVF) )
                watchdog_tick = false;

            /*
             * P4 quirks:
             * - An overflown perfctr will assert its interrupt
             *   until the OVF flag in its CCCR is cleared.
             * - LVTPC is masked on interrupt and must be
             *   unmasked by the LVTPC handler.
             */
            wrmsrl(MSR_P4_IQ_CCCR0, nmi_p4_cccr_val);
            apic_write(APIC_LVTPC, APIC_DM_NMI);
        }
        else if ( nmi_perfctr_msr == MSR_P6_PERFCTR(0) )
        {
            rdmsrl(MSR_P6_PERFCTR(0), msr_content);
            if ( msr_content & (1ULL << (nmi_p6_event_width - 1)) )
                watchdog_tick = false;

            /*
             * Only P6 based Pentium M need to re-unmask the apic vector but
             * it doesn't hurt other P6 variants.
             */
            apic_write(APIC_LVTPC, APIC_DM_NMI);
        }
        else if ( nmi_perfctr_msr == MSR_K7_PERFCTR0 )
        {
            rdmsrl(MSR_K7_PERFCTR0, msr_content);
            if ( msr_content & (1ULL << K7_EVENT_WIDTH) )
                watchdog_tick = false;
        }
        write_watchdog_counter(NULL);
    }

    return watchdog_tick;
}

/*
 * For some reason the destination shorthand for self is not valid
 * when used with the NMI delivery mode. This is documented in Tables
 * 8-3 and 8-4 in IA32 Reference Manual Volume 3. We send the IPI to
 * our own APIC ID explicitly which is valid.
 */
void self_nmi(void)
{
    unsigned long flags;
    u32 id = get_apic_id();
    local_irq_save(flags);
    apic_wait_icr_idle();
    apic_icr_write(APIC_DM_NMI | APIC_DEST_PHYSICAL, id);
    local_irq_restore(flags);
}

static void do_nmi_trigger(unsigned char key)
{
    printk("Triggering NMI on APIC ID %x\n", get_apic_id());
    self_nmi();
}

static void do_nmi_stats(unsigned char key)
{
    int i;
    struct domain *d;
    struct vcpu *v;

    printk("CPU\tNMI\n");
    for_each_online_cpu ( i )
        printk("%3d\t%3d\n", i, nmi_count(i));

    if ( ((d = hardware_domain) == NULL) || (d->vcpu == NULL) ||
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

static __init int register_nmi_trigger(void)
{
    register_keyhandler('N', do_nmi_trigger, "trigger an NMI", 0);
    register_keyhandler('n', do_nmi_stats, "NMI statistics", 1);
    return 0;
}
__initcall(register_nmi_trigger);
