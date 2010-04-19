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
#include <asm/cache.h>
#include <asm/io.h>
#include <asm/hpet.h>
#include <asm/processor.h>
#include <xen/pmstat.h>
#include <xen/softirq.h>
#include <public/platform.h>
#include <public/sysctl.h>
#include <acpi/cpufreq/cpufreq.h>

/*#define DEBUG_PM_CX*/

static void lapic_timer_nop(void) { }
static void (*lapic_timer_off)(void);
static void (*lapic_timer_on)(void);

extern void (*pm_idle) (void);
extern void (*dead_idle) (void);
extern void menu_get_trace_data(u32 *expected, u32 *pred);

static void (*pm_idle_save) (void) __read_mostly;
unsigned int max_cstate __read_mostly = ACPI_PROCESSOR_MAX_POWER - 1;
integer_param("max_cstate", max_cstate);
static int local_apic_timer_c2_ok __read_mostly = 0;
boolean_param("lapic_timer_c2_ok", local_apic_timer_c2_ok);

static struct acpi_processor_power *__read_mostly processor_powers[NR_CPUS];

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
        res = acpi_pm_tick_to_ns(power->states[i].time);
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

static inline u32 ticks_elapsed(u32 t1, u32 t2)
{
    if ( t2 >= t1 )
        return (t2 - t1);
    else if ( !(acpi_gbl_FADT.flags & ACPI_FADT_32BIT_TIMER) )
        return (((0x00FFFFFF - t1) + t2) & 0x00FFFFFF);
    else
        return ((0xFFFFFFFF - t1) + t2);
}

static void acpi_safe_halt(void)
{
    smp_mb__after_clear_bit();
    safe_halt();
}

#define MWAIT_ECX_INTERRUPT_BREAK   (0x1)

/*
 * The bit is set iff cpu use monitor/mwait to enter C state
 * with this flag set, CPU can be waken up from C state
 * by writing to specific memory address, instead of sending IPI
 */
static cpumask_t cpuidle_mwait_flags;

void cpuidle_wakeup_mwait(cpumask_t *mask)
{
    cpumask_t target;
    int cpu;

    cpus_and(target, *mask, cpuidle_mwait_flags);

    /* cpu is 'mwait'ing at softirq_pending,
       writing to it will wake up CPU */
    for_each_cpu_mask(cpu, target)
        set_bit(TIMER_SOFTIRQ, &softirq_pending(cpu));

    cpus_andnot(*mask, *mask, cpuidle_mwait_flags);
}

static void mwait_idle_with_hints(unsigned long eax, unsigned long ecx)
{
    int cpu = smp_processor_id();

    __monitor((void *)&softirq_pending(cpu), 0, 0);

    smp_mb();
    if (!softirq_pending(cpu))
    {
        cpu_set(cpu, cpuidle_mwait_flags);

        __mwait(eax, ecx);

        cpu_clear(cpu, cpuidle_mwait_flags);
    }
}

static void acpi_processor_ffh_cstate_enter(struct acpi_processor_cx *cx)
{
    mwait_idle_with_hints(cx->address, MWAIT_ECX_INTERRUPT_BREAK);
}

static void acpi_idle_do_entry(struct acpi_processor_cx *cx)
{
    int unused;

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
        unused = inl(pmtmr_ioport);
        return;
    case ACPI_CSTATE_EM_HALT:
        acpi_safe_halt();
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

static void acpi_processor_idle(void)
{
    struct acpi_processor_power *power = processor_powers[smp_processor_id()];
    struct acpi_processor_cx *cx = NULL;
    int next_state;
    int sleep_ticks = 0;
    u32 t1, t2 = 0;
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
            acpi_safe_halt();
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
            t1 = inl(pmtmr_ioport);
            /* Trace cpu idle entry */
            TRACE_4D(TRC_PM_IDLE_ENTRY, cx->idx, t1, exp, pred);
            /* Invoke C2 */
            acpi_idle_do_entry(cx);
            /* Get end time (ticks) */
            t2 = inl(pmtmr_ioport);
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

        /*
         * Before invoking C3, be aware that TSC/APIC timer may be 
         * stopped by H/W. Without carefully handling of TSC/APIC stop issues,
         * deep C state can't work correctly.
         */
        /* preparing APIC stop */
        lapic_timer_off();

        /* Get start time (ticks) */
        t1 = inl(pmtmr_ioport);
        /* Trace cpu idle entry */
        TRACE_4D(TRC_PM_IDLE_ENTRY, cx->idx, t1, exp, pred);
        /* Invoke C3 */
        acpi_idle_do_entry(cx);
        /* Get end time (ticks) */
        t2 = inl(pmtmr_ioport);

        /* recovering TSC */
        cstate_restore_tsc();
        trace_exit_reason(irq_traced);
        /* Trace cpu idle exit */
        TRACE_6D(TRC_PM_IDLE_EXIT, cx->idx, t2,
                 irq_traced[0], irq_traced[1], irq_traced[2], irq_traced[3]);

        if ( power->flags.bm_check && power->flags.bm_control )
        {
            /* Enable bus master arbitration */
            spin_lock(&c3_cpu_status.lock);
            if ( c3_cpu_status.count-- == num_online_cpus() )
                acpi_set_register(ACPI_BITREG_ARB_DISABLE, 0);
            spin_unlock(&c3_cpu_status.lock);
        }

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
        power->last_residency = acpi_pm_tick_to_ns(sleep_ticks) / 1000UL;
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
    int unused;

    if ( (power = processor_powers[smp_processor_id()]) == NULL )
        goto default_halt;

    if ( (cx = &power->states[power->count-1]) == NULL )
        goto default_halt;

    for ( ; ; )
    {
        if ( !power->flags.bm_check && cx->type == ACPI_STATE_C3 )
            ACPI_FLUSH_CPU_CACHE();

        switch ( cx->entry_method )
        {
            case ACPI_CSTATE_EM_FFH:
                /* Not treat interrupt as break event */
                mwait_idle_with_hints(cx->address, 0);
                break;
            case ACPI_CSTATE_EM_SYSIO:
                inb(cx->address);
                unused = inl(pmtmr_ioport);
                break;
            default:
                goto default_halt;
        }
    }

default_halt:
    for ( ; ; )
        halt();
}

static int init_cx_pminfo(struct acpi_processor_power *acpi_power)
{
    int i;

    memset(acpi_power, 0, sizeof(*acpi_power));

    for ( i = 0; i < ACPI_PROCESSOR_MAX_POWER; i++ )
        acpi_power->states[i].idx = i;

    acpi_power->states[ACPI_STATE_C1].type = ACPI_STATE_C1;
    acpi_power->states[ACPI_STATE_C1].entry_method = ACPI_CSTATE_EM_HALT;

    acpi_power->states[ACPI_STATE_C0].valid = 1;
    acpi_power->states[ACPI_STATE_C1].valid = 1;

    acpi_power->count = 2;
    acpi_power->safe_state = &acpi_power->states[ACPI_STATE_C1];

    return 0;
}

#define CPUID_MWAIT_LEAF (5)
#define CPUID5_ECX_EXTENSIONS_SUPPORTED (0x1)
#define CPUID5_ECX_INTERRUPT_BREAK      (0x2)

#define MWAIT_ECX_INTERRUPT_BREAK       (0x1)

#define MWAIT_SUBSTATE_MASK (0xf)
#define MWAIT_SUBSTATE_SIZE (4)

static int acpi_processor_ffh_cstate_probe(xen_processor_cx_t *cx)
{
    struct cpuinfo_x86 *c = &current_cpu_data;
    unsigned int eax, ebx, ecx, edx;
    unsigned int edx_part;
    unsigned int cstate_type; /* C-state type and not ACPI C-state type */
    unsigned int num_cstate_subtype;

    if ( c->cpuid_level < CPUID_MWAIT_LEAF )
    {
        printk(XENLOG_INFO "MWAIT leaf not supported by cpuid\n");
        return -EFAULT;
    }

    cpuid(CPUID_MWAIT_LEAF, &eax, &ebx, &ecx, &edx);
    printk(XENLOG_DEBUG "cpuid.MWAIT[.eax=%x, .ebx=%x, .ecx=%x, .edx=%x]\n",
           eax, ebx, ecx, edx);

    /* Check whether this particular cx_type (in CST) is supported or not */
    cstate_type = (cx->reg.address >> MWAIT_SUBSTATE_SIZE) + 1;
    edx_part = edx >> (cstate_type * MWAIT_SUBSTATE_SIZE);
    num_cstate_subtype = edx_part & MWAIT_SUBSTATE_MASK;

    if ( num_cstate_subtype < (cx->reg.address & MWAIT_SUBSTATE_MASK) )
        return -EFAULT;

    /* mwait ecx extensions INTERRUPT_BREAK should be supported for C2/C3 */
    if ( !(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED) ||
         !(ecx & CPUID5_ECX_INTERRUPT_BREAK) )
        return -EFAULT;

    printk(XENLOG_INFO "Monitor-Mwait will be used to enter C-%d state\n", cx->type);
    return 0;
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
    else if ( c->x86_vendor == X86_VENDOR_INTEL )
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
             xen_cx->reg.bit_offset == NATIVE_CSTATE_BEYOND_HALT )
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
    
    cx->latency_ticks = ns_to_acpi_pm_tick(cx->latency * 1000UL);
    cx->target_residency = cx->latency * latency_factor;
    if ( cx->type == ACPI_STATE_C1 || cx->type == ACPI_STATE_C2 )
        acpi_power->safe_state = cx;
}

int get_cpu_id(u8 acpi_id)
{
    int i;
    u8 apic_id;

    apic_id = x86_acpiid_to_apicid[acpi_id];
    if ( apic_id == 0xff )
        return -1;

    for ( i = 0; i < NR_CPUS; i++ )
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
    int cpu_id, i;

    if ( unlikely(!guest_handle_okay(power->states, power->count)) )
        return -EFAULT;

    print_cx_pminfo(cpu, power);

    /* map from acpi_id to cpu_id */
    cpu_id = get_cpu_id((u8)cpu);
    if ( cpu_id == -1 )
    {
        printk(XENLOG_ERR "no cpu_id for acpi_id %d\n", cpu);
        return -EFAULT;
    }

    acpi_power = processor_powers[cpu_id];
    if ( !acpi_power )
    {
        acpi_power = xmalloc(struct acpi_processor_power);
        if ( !acpi_power )
            return -ENOMEM;
        memset(acpi_power, 0, sizeof(*acpi_power));
        processor_powers[cpu_id] = acpi_power;
    }

    init_cx_pminfo(acpi_power);

    acpi_power->cpu = cpu_id;
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

    /*print_acpi_power(cpu_id, acpi_power);*/

    if ( cpu_id == 0 && pm_idle_save == NULL )
    {
        pm_idle_save = pm_idle;
        pm_idle = acpi_processor_idle;
    }

    if ( cpu_id == 0 )
    {
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
    const struct acpi_processor_power *power = processor_powers[cpuid];
    uint64_t usage, res, idle_usage = 0, idle_res = 0;
    int i;

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

    for ( i = power->count - 1; i >= 0; i-- )
    {
        if ( i != 0 )
        {
            usage = power->states[i].usage;
            res = acpi_pm_tick_to_ns(power->states[i].time);
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

