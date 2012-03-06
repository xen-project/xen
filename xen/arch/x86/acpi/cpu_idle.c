/*
 * cpu_idle - xen idle state module derived from Linux 
 *            drivers/acpi/processor_idle.c & 
 *            arch/x86/kernel/acpi/cstate.c
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2004, 2005 Dominik Brodowski <linux@brodo.de>
 *  Copyright (C) 2004  Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
 *                      - Added processor hotplug support
 *  Copyright (C) 2005  Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *                      - Added support for C3 on SMP
 *  Copyright (C) 2007, 2008 Intel Corporation
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/acpi.h>
#include <xen/smp.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <xen/cpuidle.h>
#include <xen/trace.h>
#include <xen/sched-if.h>
#include <xen/irq.h>
#include <asm/cache.h>
#include <asm/io.h>
#include <asm/hpet.h>
#include <asm/processor.h>
#include <xen/pmstat.h>
#include <xen/softirq.h>
#include <public/platform.h>
#include <public/sysctl.h>
#include <acpi/cpufreq/cpufreq.h>
#include <asm/apic.h>
#include <xen/notifier.h>
#include <xen/cpu.h>

/*#define DEBUG_PM_CX*/

#define GET_HW_RES_IN_NS(msr, val) \
    do { rdmsrl(msr, val); val = tsc_ticks2ns(val); } while( 0 )
#define GET_PC2_RES(val)  GET_HW_RES_IN_NS(0x60D, val) /* SNB only */
#define GET_PC3_RES(val)  GET_HW_RES_IN_NS(0x3F8, val)
#define GET_PC6_RES(val)  GET_HW_RES_IN_NS(0x3F9, val)
#define GET_PC7_RES(val)  GET_HW_RES_IN_NS(0x3FA, val)
#define GET_CC3_RES(val)  GET_HW_RES_IN_NS(0x3FC, val)
#define GET_CC6_RES(val)  GET_HW_RES_IN_NS(0x3FD, val)
#define GET_CC7_RES(val)  GET_HW_RES_IN_NS(0x3FE, val) /* SNB only */

static void lapic_timer_nop(void) { }
static void (*lapic_timer_off)(void);
static void (*lapic_timer_on)(void);

static uint64_t (*get_tick)(void);
static uint64_t (*ticks_elapsed)(uint64_t t1, uint64_t t2);
static uint64_t (*tick_to_ns)(uint64_t ticks);
static uint64_t (*ns_to_tick)(uint64_t ticks);

static void (*pm_idle_save) (void) __read_mostly;
unsigned int max_cstate __read_mostly = ACPI_PROCESSOR_MAX_POWER - 1;
integer_param("max_cstate", max_cstate);
static bool_t __read_mostly local_apic_timer_c2_ok;
boolean_param("lapic_timer_c2_ok", local_apic_timer_c2_ok);

static struct acpi_processor_power *__read_mostly processor_powers[NR_CPUS];

struct hw_residencies
{
    uint64_t pc2;
    uint64_t pc3;
    uint64_t pc6;
    uint64_t pc7;
    uint64_t cc3;
    uint64_t cc6;
    uint64_t cc7;
};

static void do_get_hw_residencies(void *arg)
{
    struct cpuinfo_x86 *c = &current_cpu_data;
    struct hw_residencies *hw_res = arg;

    if ( c->x86_vendor != X86_VENDOR_INTEL || c->x86 != 6 )
        return;

    switch ( c->x86_model )
    {
    /* Ivy bridge */
    case 0x3A:
    /* Sandy bridge */
    case 0x2A:
    case 0x2D:
        GET_PC2_RES(hw_res->pc2);
        GET_CC7_RES(hw_res->cc7);
        /* fall through */
    /* Nehalem */
    case 0x1A:
    case 0x1E:
    case 0x1F:
    case 0x2E:
    /* Westmere */
    case 0x25:
    case 0x2C:
    case 0x2F:
        GET_PC3_RES(hw_res->pc3);
        GET_PC6_RES(hw_res->pc6);
        GET_PC7_RES(hw_res->pc7);
        GET_CC3_RES(hw_res->cc3);
        GET_CC6_RES(hw_res->cc6);
        break;
    }
}

static void get_hw_residencies(uint32_t cpu, struct hw_residencies *hw_res)
{
    memset(hw_res, 0, sizeof(*hw_res));

    if ( smp_processor_id() == cpu )
        do_get_hw_residencies(hw_res);
    else
        on_selected_cpus(cpumask_of(cpu), do_get_hw_residencies, hw_res, 1);
}

static void print_hw_residencies(uint32_t cpu)
{
    struct hw_residencies hw_res;

    get_hw_residencies(cpu, &hw_res);

    printk("PC2[%"PRId64"] PC3[%"PRId64"] PC6[%"PRId64"] PC7[%"PRId64"]\n",
           hw_res.pc2, hw_res.pc3, hw_res.pc6, hw_res.pc7);
    printk("CC3[%"PRId64"] CC6[%"PRId64"] CC7[%"PRId64"]\n",
           hw_res.cc3, hw_res.cc6,hw_res.cc7);
}

static char* acpi_cstate_method_name[] =
{
    "NONE",
    "SYSIO",
    "FFH",
    "HALT"
};

static void print_acpi_power(uint32_t cpu, struct acpi_processor_power *power)
{
    uint32_t i, idle_usage = 0;
    uint64_t res, idle_res = 0;

    printk("==cpu%d==\n", cpu);
    printk("active state:\t\tC%d\n",
           power->last_state ? power->last_state->idx : -1);
    printk("max_cstate:\t\tC%d\n", max_cstate);
    printk("states:\n");
    
    for ( i = 1; i < power->count; i++ )
    {
        res = tick_to_ns(power->states[i].time);
        idle_usage += power->states[i].usage;
        idle_res += res;

        printk((power->last_state && power->last_state->idx == i) ?
               "   *" : "    ");
        printk("C%d:\t", i);
        printk("type[C%d] ", power->states[i].type);
        printk("latency[%03d] ", power->states[i].latency);
        printk("usage[%08d] ", power->states[i].usage);
        printk("method[%5s] ", acpi_cstate_method_name[power->states[i].entry_method]);
        printk("duration[%"PRId64"]\n", res);
    }
    printk("    C0:\tusage[%08d] duration[%"PRId64"]\n",
           idle_usage, NOW() - idle_res);

    print_hw_residencies(cpu);
}

static void dump_cx(unsigned char key)
{
    unsigned int cpu;

    printk("'%c' pressed -> printing ACPI Cx structures\n", key);
    for_each_online_cpu ( cpu )
        if (processor_powers[cpu])
            print_acpi_power(cpu, processor_powers[cpu]);
}

static struct keyhandler dump_cx_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_cx,
    .desc = "dump ACPI Cx structures"
};

static int __init cpu_idle_key_init(void)
{
    register_keyhandler('c', &dump_cx_keyhandler);
    return 0;
}
__initcall(cpu_idle_key_init);

static uint64_t get_stime_tick(void) { return (uint64_t)NOW(); }
static uint64_t stime_ticks_elapsed(uint64_t t1, uint64_t t2) { return t2 - t1; }
static uint64_t stime_tick_to_ns(uint64_t ticks) { return ticks; }
static uint64_t ns_to_stime_tick(uint64_t ns) { return ns; }

static uint64_t get_acpi_pm_tick(void) { return (uint64_t)inl(pmtmr_ioport); }
static uint64_t acpi_pm_ticks_elapsed(uint64_t t1, uint64_t t2)
{
    if ( t2 >= t1 )
        return (t2 - t1);
    else if ( !(acpi_gbl_FADT.flags & ACPI_FADT_32BIT_TIMER) )
        return (((0x00FFFFFF - t1) + t2 + 1) & 0x00FFFFFF);
    else
        return ((0xFFFFFFFF - t1) + t2 +1);
}

#define MWAIT_ECX_INTERRUPT_BREAK   (0x1)

/*
 * The bit is set iff cpu use monitor/mwait to enter C state
 * with this flag set, CPU can be waken up from C state
 * by writing to specific memory address, instead of sending an IPI.
 */
static cpumask_t cpuidle_mwait_flags;

void cpuidle_wakeup_mwait(cpumask_t *mask)
{
    cpumask_t target;
    unsigned int cpu;

    cpumask_and(&target, mask, &cpuidle_mwait_flags);

    /* CPU is MWAITing on the cpuidle_mwait_wakeup flag. */
    for_each_cpu(cpu, &target)
        mwait_wakeup(cpu) = 0;

    cpumask_andnot(mask, mask, &target);
}

static void mwait_idle_with_hints(unsigned long eax, unsigned long ecx)
{
    unsigned int cpu = smp_processor_id();
    s_time_t expires = per_cpu(timer_deadline, cpu);

    __monitor((void *)&mwait_wakeup(cpu), 0, 0);
    smp_mb();

    /*
     * Timer deadline passing is the event on which we will be woken via
     * cpuidle_mwait_wakeup. So check it now that the location is armed.
     */
    if ( expires > NOW() || expires == 0 )
    {
        cpumask_set_cpu(cpu, &cpuidle_mwait_flags);
        __mwait(eax, ecx);
        cpumask_clear_cpu(cpu, &cpuidle_mwait_flags);
    }

    if ( expires <= NOW() && expires > 0 )
        raise_softirq(TIMER_SOFTIRQ);
}

static void acpi_processor_ffh_cstate_enter(struct acpi_processor_cx *cx)
{
    mwait_idle_with_hints(cx->address, MWAIT_ECX_INTERRUPT_BREAK);
}

static void acpi_idle_do_entry(struct acpi_processor_cx *cx)
{
    switch ( cx->entry_method )
    {
    case ACPI_CSTATE_EM_FFH:
        /* Call into architectural FFH based C-state */
        acpi_processor_ffh_cstate_enter(cx);
        return;
    case ACPI_CSTATE_EM_SYSIO:
        /* IO port based C-state */
        inb(cx->address);
        /* Dummy wait op - must do something useless after P_LVL2 read
           because chipsets cannot guarantee that STPCLK# signal
           gets asserted in time to freeze execution properly. */
        inl(pmtmr_ioport);
        return;
    case ACPI_CSTATE_EM_HALT:
        safe_halt();
        local_irq_disable();
        return;
    }
}

static int acpi_idle_bm_check(void)
{
    u32 bm_status = 0;

    acpi_get_register(ACPI_BITREG_BUS_MASTER_STATUS, &bm_status);
    if ( bm_status )
        acpi_set_register(ACPI_BITREG_BUS_MASTER_STATUS, 1);
    /*
     * TBD: PIIX4 Erratum #18: Note that BM_STS doesn't always reflect
     * the true state of bus mastering activity; forcing us to
     * manually check the BMIDEA bit of each IDE channel.
     */
    return bm_status;
}

static struct {
    spinlock_t lock;
    unsigned int count;
} c3_cpu_status = { .lock = SPIN_LOCK_UNLOCKED };

static inline void trace_exit_reason(u32 *irq_traced)
{
    if ( unlikely(tb_init_done) )
    {
        int i, curbit;
        u32 irr_status[8] = { 0 };

        /* Get local apic IRR register */
        for ( i = 0; i < 8; i++ )
            irr_status[i] = apic_read(APIC_IRR + (i << 4));
        i = 0;
        curbit = find_first_bit((const unsigned long *)irr_status, 256);
        while ( i < 4 && curbit < 256 )
        {
            irq_traced[i++] = curbit;
            curbit = find_next_bit((const unsigned long *)irr_status, 256, curbit + 1);
        }
    }
}

/* vcpu is urgent if vcpu is polling event channel
 *
 * if urgent vcpu exists, CPU should not enter deep C state
 */
static int sched_has_urgent_vcpu(void)
{
    return atomic_read(&this_cpu(schedule_data).urgent_count);
}

/*
 * "AAJ72. EOI Transaction May Not be Sent if Software Enters Core C6 During 
 * an Interrupt Service Routine"
 * 
 * There was an errata with some Core i7 processors that an EOI transaction 
 * may not be sent if software enters core C6 during an interrupt service 
 * routine. So we don't enter deep Cx state if there is an EOI pending.
 */
bool_t errata_c6_eoi_workaround(void)
{
    static bool_t fix_needed = -1;

    if ( unlikely(fix_needed == -1) )
    {
        int model = boot_cpu_data.x86_model;
        fix_needed = (cpu_has_apic && !directed_eoi_enabled &&
                      (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) &&
                      (boot_cpu_data.x86 == 6) &&
                      ((model == 0x1a) || (model == 0x1e) || (model == 0x1f) ||
                       (model == 0x25) || (model == 0x2c) || (model == 0x2f)));
    }

    return (fix_needed && cpu_has_pending_apic_eoi());
}

static void acpi_processor_idle(void)
{
    struct acpi_processor_power *power = processor_powers[smp_processor_id()];
    struct acpi_processor_cx *cx = NULL;
    int next_state;
    int64_t sleep_ticks = 0;
    uint64_t t1, t2 = 0;
    u32 exp = 0, pred = 0;
    u32 irq_traced[4] = { 0 };

    if ( max_cstate > 0 && power && !sched_has_urgent_vcpu() &&
         (next_state = cpuidle_current_governor->select(power)) > 0 )
    {
        cx = &power->states[next_state];
        if ( power->flags.bm_check && acpi_idle_bm_check()
             && cx->type == ACPI_STATE_C3 )
            cx = power->safe_state;
        if ( cx->idx > max_cstate )
            cx = &power->states[max_cstate];
        menu_get_trace_data(&exp, &pred);
    }
    if ( !cx )
    {
        if ( pm_idle_save )
            pm_idle_save();
        else
            safe_halt();
        return;
    }

    cpufreq_dbs_timer_suspend();

    sched_tick_suspend();
    /* sched_tick_suspend() can raise TIMER_SOFTIRQ. Process it now. */
    process_pending_softirqs();

    /*
     * Interrupts must be disabled during bus mastering calculations and
     * for C2/C3 transitions.
     */
    local_irq_disable();

    if ( !cpu_is_haltable(smp_processor_id()) )
    {
        local_irq_enable();
        sched_tick_resume();
        cpufreq_dbs_timer_resume();
        return;
    }

    if ( (cx->type == ACPI_STATE_C3) && errata_c6_eoi_workaround() )
        cx = power->safe_state;

    power->last_state = cx;

    /*
     * Sleep:
     * ------
     * Invoke the current Cx state to put the processor to sleep.
     */
    switch ( cx->type )
    {
    case ACPI_STATE_C1:
    case ACPI_STATE_C2:
        if ( cx->type == ACPI_STATE_C1 || local_apic_timer_c2_ok )
        {
            /* Get start time (ticks) */
            t1 = get_tick();
            /* Trace cpu idle entry */
            TRACE_4D(TRC_PM_IDLE_ENTRY, cx->idx, t1, exp, pred);
            /* Invoke C2 */
            acpi_idle_do_entry(cx);
            /* Get end time (ticks) */
            t2 = get_tick();
            trace_exit_reason(irq_traced);
            /* Trace cpu idle exit */
            TRACE_6D(TRC_PM_IDLE_EXIT, cx->idx, t2,
                     irq_traced[0], irq_traced[1], irq_traced[2], irq_traced[3]);
            /* Re-enable interrupts */
            local_irq_enable();
            /* Compute time (ticks) that we were actually asleep */
            sleep_ticks = ticks_elapsed(t1, t2);
            break;
        }

    case ACPI_STATE_C3:
        /*
         * Before invoking C3, be aware that TSC/APIC timer may be 
         * stopped by H/W. Without carefully handling of TSC/APIC stop issues,
         * deep C state can't work correctly.
         */
        /* preparing APIC stop */
        lapic_timer_off();

        /* Get start time (ticks) */
        t1 = get_tick();
        /* Trace cpu idle entry */
        TRACE_4D(TRC_PM_IDLE_ENTRY, cx->idx, t1, exp, pred);

        /*
         * disable bus master
         * bm_check implies we need ARB_DIS
         * !bm_check implies we need cache flush
         * bm_control implies whether we can do ARB_DIS
         *
         * That leaves a case where bm_check is set and bm_control is
         * not set. In that case we cannot do much, we enter C3
         * without doing anything.
         */
        if ( power->flags.bm_check && power->flags.bm_control )
        {
            spin_lock(&c3_cpu_status.lock);
            if ( ++c3_cpu_status.count == num_online_cpus() )
            {
                /*
                 * All CPUs are trying to go to C3
                 * Disable bus master arbitration
                 */
                acpi_set_register(ACPI_BITREG_ARB_DISABLE, 1);
            }
            spin_unlock(&c3_cpu_status.lock);
        }
        else if ( !power->flags.bm_check )
        {
            /* SMP with no shared cache... Invalidate cache  */
            ACPI_FLUSH_CPU_CACHE();
        }

        /* Invoke C3 */
        acpi_idle_do_entry(cx);

        if ( power->flags.bm_check && power->flags.bm_control )
        {
            /* Enable bus master arbitration */
            spin_lock(&c3_cpu_status.lock);
            acpi_set_register(ACPI_BITREG_ARB_DISABLE, 0);
            c3_cpu_status.count--;
            spin_unlock(&c3_cpu_status.lock);
        }

        /* Get end time (ticks) */
        t2 = get_tick();

        /* recovering TSC */
        cstate_restore_tsc();
        trace_exit_reason(irq_traced);
        /* Trace cpu idle exit */
        TRACE_6D(TRC_PM_IDLE_EXIT, cx->idx, t2,
                 irq_traced[0], irq_traced[1], irq_traced[2], irq_traced[3]);

        /* Re-enable interrupts */
        local_irq_enable();
        /* recovering APIC */
        lapic_timer_on();
        /* Compute time (ticks) that we were actually asleep */
        sleep_ticks = ticks_elapsed(t1, t2);

        break;

    default:
        local_irq_enable();
        sched_tick_resume();
        cpufreq_dbs_timer_resume();
        return;
    }

    cx->usage++;
    if ( sleep_ticks > 0 )
    {
        power->last_residency = tick_to_ns(sleep_ticks) / 1000UL;
        cx->time += sleep_ticks;
    }

    sched_tick_resume();
    cpufreq_dbs_timer_resume();

    if ( cpuidle_current_governor->reflect )
        cpuidle_current_governor->reflect(power);
}

static void acpi_dead_idle(void)
{
    struct acpi_processor_power *power;
    struct acpi_processor_cx *cx;

    if ( (power = processor_powers[smp_processor_id()]) == NULL )
        goto default_halt;

    if ( (cx = &power->states[power->count-1]) == NULL )
        goto default_halt;

    if ( cx->entry_method == ACPI_CSTATE_EM_FFH )
    {
        void *mwait_ptr = &mwait_wakeup(smp_processor_id());

        /*
         * Cache must be flushed as the last operation before sleeping.
         * Otherwise, CPU may still hold dirty data, breaking cache coherency,
         * leading to strange errors.
         */
        wbinvd();

        while ( 1 )
        {
            /*
             * 1. The CLFLUSH is a workaround for erratum AAI65 for
             * the Xeon 7400 series.  
             * 2. The WBINVD is insufficient due to the spurious-wakeup
             * case where we return around the loop.
             * 3. Unlike wbinvd, clflush is a light weight but not serializing 
             * instruction, hence memory fence is necessary to make sure all 
             * load/store visible before flush cache line.
             */
            mb();
            clflush(mwait_ptr);
            __monitor(mwait_ptr, 0, 0);
            mb();
            __mwait(cx->address, 0);
        }
    }
    else if ( current_cpu_data.x86_vendor == X86_VENDOR_AMD &&
              cx->entry_method == ACPI_CSTATE_EM_SYSIO )
    {
        /* Intel prefers not to use SYSIO */

        /* Avoid references to shared data after the cache flush */
        u32 address = cx->address;
        u32 pmtmr_ioport_local = pmtmr_ioport;

        wbinvd();

        while ( 1 )
        {
            inb(address);
            inl(pmtmr_ioport_local);
        }
    }

default_halt:
    for ( ; ; )
        halt();
}

static int cpuidle_init_cpu(int cpu)
{
    struct acpi_processor_power *acpi_power;

    acpi_power = processor_powers[cpu];
    if ( !acpi_power )
    {
        int i;
        acpi_power = xzalloc(struct acpi_processor_power);
        if ( !acpi_power )
            return -ENOMEM;

        for ( i = 0; i < ACPI_PROCESSOR_MAX_POWER; i++ )
            acpi_power->states[i].idx = i;
     
        acpi_power->states[ACPI_STATE_C1].type = ACPI_STATE_C1;
        acpi_power->states[ACPI_STATE_C1].entry_method = ACPI_CSTATE_EM_HALT;
     
        acpi_power->states[ACPI_STATE_C0].valid = 1;
        acpi_power->states[ACPI_STATE_C1].valid = 1;
     
        acpi_power->count = 2;
        acpi_power->safe_state = &acpi_power->states[ACPI_STATE_C1];
        acpi_power->cpu = cpu;
        processor_powers[cpu] = acpi_power;
    }

    if ( cpu == 0 )
    {
        if ( boot_cpu_has(X86_FEATURE_NONSTOP_TSC) )
        {
            get_tick = get_stime_tick;
            ticks_elapsed = stime_ticks_elapsed;
            tick_to_ns = stime_tick_to_ns;
            ns_to_tick = ns_to_stime_tick;
        }
        else
        {
            get_tick = get_acpi_pm_tick;
            ticks_elapsed = acpi_pm_ticks_elapsed;
            tick_to_ns = acpi_pm_tick_to_ns;
            ns_to_tick = ns_to_acpi_pm_tick;
        }
    }

    return 0;
}

#define MWAIT_SUBSTATE_MASK (0xf)
#define MWAIT_SUBSTATE_SIZE (4)

static int acpi_processor_ffh_cstate_probe(xen_processor_cx_t *cx)
{
    struct cpuinfo_x86 *c = &current_cpu_data;
    unsigned int eax, ebx, ecx, edx;
    unsigned int edx_part;
    unsigned int cstate_type; /* C-state type and not ACPI C-state type */
    unsigned int num_cstate_subtype;
    int ret = 0;
    static unsigned long printed;

    if ( c->cpuid_level < CPUID_MWAIT_LEAF )
    {
        printk(XENLOG_INFO "MWAIT leaf not supported by cpuid\n");
        return -EFAULT;
    }

    cpuid(CPUID_MWAIT_LEAF, &eax, &ebx, &ecx, &edx);
    if ( opt_cpu_info )
        printk(XENLOG_DEBUG "cpuid.MWAIT[eax=%x ebx=%x ecx=%x edx=%x]\n",
               eax, ebx, ecx, edx);

    /* Check whether this particular cx_type (in CST) is supported or not */
    cstate_type = (cx->reg.address >> MWAIT_SUBSTATE_SIZE) + 1;
    edx_part = edx >> (cstate_type * MWAIT_SUBSTATE_SIZE);
    num_cstate_subtype = edx_part & MWAIT_SUBSTATE_MASK;

    if ( num_cstate_subtype < (cx->reg.address & MWAIT_SUBSTATE_MASK) )
        ret = -ERANGE;
    /* mwait ecx extensions INTERRUPT_BREAK should be supported for C2/C3 */
    else if ( !(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED) ||
              !(ecx & CPUID5_ECX_INTERRUPT_BREAK) )
        ret = -ENODEV;
    else if ( opt_cpu_info || cx->type >= BITS_PER_LONG ||
              !test_and_set_bit(cx->type, &printed) )
        printk(XENLOG_INFO "Monitor-Mwait will be used to enter C%d state\n",
               cx->type);
    return ret;
}

/*
 * Initialize bm_flags based on the CPU cache properties
 * On SMP it depends on cache configuration
 * - When cache is not shared among all CPUs, we flush cache
 *   before entering C3.
 * - When cache is shared among all CPUs, we use bm_check
 *   mechanism as in UP case
 *
 * This routine is called only after all the CPUs are online
 */
static void acpi_processor_power_init_bm_check(struct acpi_processor_flags *flags)
{
    struct cpuinfo_x86 *c = &current_cpu_data;

    flags->bm_check = 0;
    if ( num_online_cpus() == 1 )
        flags->bm_check = 1;
    else if ( (c->x86_vendor == X86_VENDOR_INTEL) ||
              ((c->x86_vendor == X86_VENDOR_AMD) && (c->x86 == 0x15)) )
    {
        /*
         * Today all MP CPUs that support C3 share cache.
         * And caches should not be flushed by software while
         * entering C3 type state.
         */
        flags->bm_check = 1;
    }

    /*
     * On all recent platforms, ARB_DISABLE is a nop.
     * So, set bm_control to zero to indicate that ARB_DISABLE
     * is not required while entering C3 type state on
     * P4, Core and beyond CPUs
     */
    if ( c->x86_vendor == X86_VENDOR_INTEL &&
        (c->x86 > 0x6 || (c->x86 == 6 && c->x86_model >= 14)) )
            flags->bm_control = 0;
}

#define VENDOR_INTEL                   (1)
#define NATIVE_CSTATE_BEYOND_HALT      (2)

static int check_cx(struct acpi_processor_power *power, xen_processor_cx_t *cx)
{
    static int bm_check_flag = -1;
    static int bm_control_flag = -1;

    switch ( cx->reg.space_id )
    {
    case ACPI_ADR_SPACE_SYSTEM_IO:
        if ( cx->reg.address == 0 )
            return -EINVAL;
        break;

    case ACPI_ADR_SPACE_FIXED_HARDWARE:
        if ( cx->reg.bit_width != VENDOR_INTEL || 
             cx->reg.bit_offset != NATIVE_CSTATE_BEYOND_HALT )
            return -EINVAL;

        /* assume all logical cpu has the same support for mwait */
        if ( acpi_processor_ffh_cstate_probe(cx) )
            return -EINVAL;
        break;

    default:
        return -ENODEV;
    }

    switch ( cx->type )
    {
    case ACPI_STATE_C2:
        if ( local_apic_timer_c2_ok )
            break;
    case ACPI_STATE_C3:
        if ( boot_cpu_has(X86_FEATURE_ARAT) )
        {
            lapic_timer_off = lapic_timer_nop;
            lapic_timer_on = lapic_timer_nop;
        }
        else if ( hpet_broadcast_is_available() )
        {
            lapic_timer_off = hpet_broadcast_enter;
            lapic_timer_on = hpet_broadcast_exit;
        }
        else if ( pit_broadcast_is_available() )
        {
            lapic_timer_off = pit_broadcast_enter;
            lapic_timer_on = pit_broadcast_exit;
        }
        else
        {
            return -EINVAL;
        }

        /* All the logic here assumes flags.bm_check is same across all CPUs */
        if ( bm_check_flag == -1 )
        {
            /* Determine whether bm_check is needed based on CPU  */
            acpi_processor_power_init_bm_check(&(power->flags));
            bm_check_flag = power->flags.bm_check;
            bm_control_flag = power->flags.bm_control;
        }
        else
        {
            power->flags.bm_check = bm_check_flag;
            power->flags.bm_control = bm_control_flag;
        }

        if ( power->flags.bm_check )
        {
            if ( !power->flags.bm_control )
            {
                if ( power->flags.has_cst != 1 )
                {
                    /* bus mastering control is necessary */
                    ACPI_DEBUG_PRINT((ACPI_DB_INFO,
                        "C3 support requires BM control\n"));
                    return -EINVAL;
                }
                else
                {
                    /* Here we enter C3 without bus mastering */
                    ACPI_DEBUG_PRINT((ACPI_DB_INFO,
                        "C3 support without BM control\n"));
                }
            }
            /*
             * On older chipsets, BM_RLD needs to be set
             * in order for Bus Master activity to wake the
             * system from C3.  Newer chipsets handle DMA
             * during C3 automatically and BM_RLD is a NOP.
             * In either case, the proper way to
             * handle BM_RLD is to set it and leave it set.
             */
            acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 1);
        }
        else
        {
            /*
             * WBINVD should be set in fadt, for C3 state to be
             * supported on when bm_check is not required.
             */
            if ( !(acpi_gbl_FADT.flags & ACPI_FADT_WBINVD) )
            {
                ACPI_DEBUG_PRINT((ACPI_DB_INFO,
                          "Cache invalidation should work properly"
                          " for C3 to be enabled on SMP systems\n"));
                return -EINVAL;
            }
            acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 0);
        }

        break;
    }

    return 0;
}

static unsigned int latency_factor = 2;
integer_param("idle_latency_factor", latency_factor);

static void set_cx(
    struct acpi_processor_power *acpi_power,
    xen_processor_cx_t *xen_cx)
{
    struct acpi_processor_cx *cx;

    if ( check_cx(acpi_power, xen_cx) != 0 )
        return;

    if ( xen_cx->type == ACPI_STATE_C1 )
        cx = &acpi_power->states[1];
    else
        cx = &acpi_power->states[acpi_power->count];

    if ( !cx->valid )
        acpi_power->count++;

    cx->valid    = 1;
    cx->type     = xen_cx->type;
    cx->address  = xen_cx->reg.address;

    switch ( xen_cx->reg.space_id )
    {
    case ACPI_ADR_SPACE_FIXED_HARDWARE:
        if ( xen_cx->reg.bit_width == VENDOR_INTEL &&
             xen_cx->reg.bit_offset == NATIVE_CSTATE_BEYOND_HALT &&
             boot_cpu_has(X86_FEATURE_MWAIT) )
            cx->entry_method = ACPI_CSTATE_EM_FFH;
        else
            cx->entry_method = ACPI_CSTATE_EM_HALT;
        break;
    case ACPI_ADR_SPACE_SYSTEM_IO:
        cx->entry_method = ACPI_CSTATE_EM_SYSIO;
        break;
    default:
        cx->entry_method = ACPI_CSTATE_EM_NONE;
    }

    cx->latency  = xen_cx->latency;
    cx->power    = xen_cx->power;
    
    cx->latency_ticks = ns_to_tick(cx->latency * 1000UL);
    cx->target_residency = cx->latency * latency_factor;
    if ( cx->type == ACPI_STATE_C1 || cx->type == ACPI_STATE_C2 )
        acpi_power->safe_state = cx;
}

int get_cpu_id(u32 acpi_id)
{
    int i;
    u32 apic_id;

    if ( acpi_id >= MAX_MADT_ENTRIES )
        return -1;

    apic_id = x86_acpiid_to_apicid[acpi_id];
    if ( apic_id == BAD_APICID )
        return -1;

    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        if ( apic_id == x86_cpu_to_apicid[i] )
            return i;
    }

    return -1;
}

#ifdef DEBUG_PM_CX
static void print_cx_pminfo(uint32_t cpu, struct xen_processor_power *power)
{
    XEN_GUEST_HANDLE(xen_processor_cx_t) states;
    xen_processor_cx_t  state;
    XEN_GUEST_HANDLE(xen_processor_csd_t) csd;
    xen_processor_csd_t dp;
    uint32_t i;

    printk("cpu%d cx acpi info:\n", cpu);
    printk("\tcount = %d\n", power->count);
    printk("\tflags: bm_cntl[%d], bm_chk[%d], has_cst[%d],\n"
           "\t       pwr_setup_done[%d], bm_rld_set[%d]\n",
           power->flags.bm_control, power->flags.bm_check, power->flags.has_cst,
           power->flags.power_setup_done, power->flags.bm_rld_set);
    
    states = power->states;
    
    for ( i = 0; i < power->count; i++ )
    {
        if ( unlikely(copy_from_guest_offset(&state, states, i, 1)) )
            return;
        
        printk("\tstates[%d]:\n", i);
        printk("\t\treg.space_id = 0x%x\n", state.reg.space_id);
        printk("\t\treg.bit_width = 0x%x\n", state.reg.bit_width);
        printk("\t\treg.bit_offset = 0x%x\n", state.reg.bit_offset);
        printk("\t\treg.access_size = 0x%x\n", state.reg.access_size);
        printk("\t\treg.address = 0x%"PRIx64"\n", state.reg.address);
        printk("\t\ttype    = %d\n", state.type);
        printk("\t\tlatency = %d\n", state.latency);
        printk("\t\tpower   = %d\n", state.power);

        csd = state.dp;
        printk("\t\tdp(@0x%p)\n", csd.p);
        
        if ( csd.p != NULL )
        {
            if ( unlikely(copy_from_guest(&dp, csd, 1)) )
                return;
            printk("\t\t\tdomain = %d\n", dp.domain);
            printk("\t\t\tcoord_type   = %d\n", dp.coord_type);
            printk("\t\t\tnum = %d\n", dp.num);
        }
    }
}
#else
#define print_cx_pminfo(c, p)
#endif

long set_cx_pminfo(uint32_t cpu, struct xen_processor_power *power)
{
    XEN_GUEST_HANDLE(xen_processor_cx_t) states;
    xen_processor_cx_t xen_cx;
    struct acpi_processor_power *acpi_power;
    int cpu_id, i, ret;

    if ( unlikely(!guest_handle_okay(power->states, power->count)) )
        return -EFAULT;

    print_cx_pminfo(cpu, power);

    /* map from acpi_id to cpu_id */
    cpu_id = get_cpu_id(cpu);
    if ( cpu_id == -1 )
    {
        printk(XENLOG_ERR "no cpu_id for acpi_id %d\n", cpu);
        return -EINVAL;
    }

    ret = cpuidle_init_cpu(cpu_id);
    if ( ret < 0 )
        return ret;

    acpi_power = processor_powers[cpu_id];
    acpi_power->flags.bm_check = power->flags.bm_check;
    acpi_power->flags.bm_control = power->flags.bm_control;
    acpi_power->flags.has_cst = power->flags.has_cst;

    states = power->states;
    for ( i = 0; i < power->count; i++ )
    {
        if ( unlikely(copy_from_guest_offset(&xen_cx, states, i, 1)) )
            return -EFAULT;

        set_cx(acpi_power, &xen_cx);
    }

    if ( cpuidle_current_governor->enable &&
         cpuidle_current_governor->enable(acpi_power) )
        return -EFAULT;

    /* FIXME: C-state dependency is not supported by far */

    if ( cpu_id == 0 )
    {
        if ( pm_idle_save == NULL )
        {
            pm_idle_save = pm_idle;
            pm_idle = acpi_processor_idle;
        }

        dead_idle = acpi_dead_idle;
    }
 
    return 0;
}

uint32_t pmstat_get_cx_nr(uint32_t cpuid)
{
    return processor_powers[cpuid] ? processor_powers[cpuid]->count : 0;
}

int pmstat_get_cx_stat(uint32_t cpuid, struct pm_cx_stat *stat)
{
    struct acpi_processor_power *power = processor_powers[cpuid];
    uint64_t usage, res, idle_usage = 0, idle_res = 0;
    int i;
    struct hw_residencies hw_res;

    if ( power == NULL )
    {
        stat->last = 0;
        stat->nr = 0;
        stat->idle_time = 0;
        return 0;
    }

    stat->last = power->last_state ? power->last_state->idx : 0;
    stat->nr = power->count;
    stat->idle_time = get_cpu_idle_time(cpuid);

    /* mimic the stat when detail info hasn't been registered by dom0 */
    if ( pm_idle_save == NULL )
    {
        /* C1 */
        usage = 1;
        res = stat->idle_time;
        if ( copy_to_guest_offset(stat->triggers, 1, &usage, 1) ||
             copy_to_guest_offset(stat->residencies, 1, &res, 1) )
            return -EFAULT;

        /* C0 */
        res = NOW() - res;
        if ( copy_to_guest_offset(stat->triggers, 0, &usage, 1) ||
             copy_to_guest_offset(stat->residencies, 0, &res, 1) )
            return -EFAULT;

        stat->pc2 = 0;
        stat->pc3 = 0;
        stat->pc6 = 0;
        stat->pc7 = 0;
        stat->cc3 = 0;
        stat->cc6 = 0;
        stat->cc7 = 0;
        return 0;
    }

    for ( i = power->count - 1; i >= 0; i-- )
    {
        if ( i != 0 )
        {
            usage = power->states[i].usage;
            res = tick_to_ns(power->states[i].time);
            idle_usage += usage;
            idle_res += res;
        }
        else
        {
            usage = idle_usage;
            res = NOW() - idle_res;
        }
        if ( copy_to_guest_offset(stat->triggers, i, &usage, 1) ||
             copy_to_guest_offset(stat->residencies, i, &res, 1) )
            return -EFAULT;
    }

    get_hw_residencies(cpuid, &hw_res);

    stat->pc2 = hw_res.pc2;
    stat->pc3 = hw_res.pc3;
    stat->pc6 = hw_res.pc6;
    stat->pc7 = hw_res.pc7;
    stat->cc3 = hw_res.cc3;
    stat->cc6 = hw_res.cc6;
    stat->cc7 = hw_res.cc7;

    return 0;
}

int pmstat_reset_cx_stat(uint32_t cpuid)
{
    return 0;
}

void cpuidle_disable_deep_cstate(void)
{
    if ( max_cstate > 1 )
    {
        if ( local_apic_timer_c2_ok )
            max_cstate = 2;
        else
            max_cstate = 1;
    }

    mb();

    hpet_disable_legacy_broadcast();
}

bool_t cpuidle_using_deep_cstate(void)
{
    return xen_cpuidle && max_cstate > (local_apic_timer_c2_ok ? 2 : 1);
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    /* Only hook on CPU_ONLINE because a dead cpu may utilize the info to
     * to enter deep C-state */
    switch ( action )
    {
    case CPU_ONLINE:
        (void)cpuidle_init_cpu(cpu);
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

static int __init cpuidle_presmp_init(void)
{
    void *cpu = (void *)(long)smp_processor_id();
    cpu_callback(&cpu_nfb, CPU_ONLINE, cpu);
    register_cpu_notifier(&cpu_nfb);
    return 0;
}
presmp_initcall(cpuidle_presmp_init);

