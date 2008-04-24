/*
 *	Intel SMP support routines.
 *
 *	(c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *	(c) 1998-99, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *	This code is released under the GNU General Public License version 2 or
 *	later.
 */

#include <xen/config.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/perfc.h>
#include <xen/spinlock.h>
#include <asm/current.h>
#include <asm/smp.h>
#include <asm/mc146818rtc.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>
#include <asm/ipi.h>
#include <asm/hvm/support.h>
#include <mach_apic.h>

/*
 *	Some notes on x86 processor bugs affecting SMP operation:
 *
 *	Pentium, Pentium Pro, II, III (and all CPUs) have bugs.
 *	The Linux implications for SMP are handled as follows:
 *
 *	Pentium III / [Xeon]
 *		None of the E1AP-E3AP errata are visible to the user.
 *
 *	E1AP.	see PII A1AP
 *	E2AP.	see PII A2AP
 *	E3AP.	see PII A3AP
 *
 *	Pentium II / [Xeon]
 *		None of the A1AP-A3AP errata are visible to the user.
 *
 *	A1AP.	see PPro 1AP
 *	A2AP.	see PPro 2AP
 *	A3AP.	see PPro 7AP
 *
 *	Pentium Pro
 *		None of 1AP-9AP errata are visible to the normal user,
 *	except occasional delivery of 'spurious interrupt' as trap #15.
 *	This is very rare and a non-problem.
 *
 *	1AP.	Linux maps APIC as non-cacheable
 *	2AP.	worked around in hardware
 *	3AP.	fixed in C0 and above steppings microcode update.
 *		Linux does not use excessive STARTUP_IPIs.
 *	4AP.	worked around in hardware
 *	5AP.	symmetric IO mode (normal Linux operation) not affected.
 *		'noapic' mode has vector 0xf filled out properly.
 *	6AP.	'noapic' mode might be affected - fixed in later steppings
 *	7AP.	We do not assume writes to the LVT deassering IRQs
 *	8AP.	We do not enable low power mode (deep sleep) during MP bootup
 *	9AP.	We do not use mixed mode
 */

/*
 * The following functions deal with sending IPIs between CPUs.
 */

static inline int __prepare_ICR (unsigned int shortcut, int vector)
{
    return APIC_DM_FIXED | shortcut | vector;
}

static inline int __prepare_ICR2 (unsigned int mask)
{
    return SET_APIC_DEST_FIELD(mask);
}

void apic_wait_icr_idle(void)
{
    while ( apic_read( APIC_ICR ) & APIC_ICR_BUSY )
        cpu_relax();
}

void send_IPI_mask_flat(cpumask_t cpumask, int vector)
{
    unsigned long mask = cpus_addr(cpumask)[0];
    unsigned long cfg;
    unsigned long flags;

    /* An IPI with no target generates a send accept error from P5/P6 APICs. */
    WARN_ON(mask == 0);

    local_irq_save(flags);

    /*
     * Wait for idle.
     */
    apic_wait_icr_idle();

    /*
     * prepare target chip field
     */
    cfg = __prepare_ICR2(mask);
    apic_write_around(APIC_ICR2, cfg);

    /*
     * program the ICR
     */
    cfg = __prepare_ICR(0, vector) | APIC_DEST_LOGICAL;

    /*
     * Send the IPI. The write to APIC_ICR fires this off.
     */
    apic_write_around(APIC_ICR, cfg);
    
    local_irq_restore(flags);
}

void send_IPI_mask_phys(cpumask_t mask, int vector)
{
    unsigned long cfg, flags;
    unsigned int query_cpu;

    local_irq_save(flags);

    for_each_cpu_mask ( query_cpu, mask )
    {
        /*
         * Wait for idle.
         */
        apic_wait_icr_idle();

        /*
         * prepare target chip field
         */
        cfg = __prepare_ICR2(cpu_physical_id(query_cpu));
        apic_write_around(APIC_ICR2, cfg);

        /*
         * program the ICR
         */
        cfg = __prepare_ICR(0, vector) | APIC_DEST_PHYSICAL;

        /*
         * Send the IPI. The write to APIC_ICR fires this off.
         */
        apic_write_around(APIC_ICR, cfg);
    }

    local_irq_restore(flags);
}

static DEFINE_SPINLOCK(flush_lock);
static cpumask_t flush_cpumask;
static const void *flush_va;
static unsigned int flush_flags;

fastcall void smp_invalidate_interrupt(void)
{
    ack_APIC_irq();
    perfc_incr(ipis);
    irq_enter();
    if ( !__sync_lazy_execstate() ||
         (flush_flags & (FLUSH_TLB_GLOBAL | FLUSH_CACHE)) )
        flush_area_local(flush_va, flush_flags);
    cpu_clear(smp_processor_id(), flush_cpumask);
    irq_exit();
}

void flush_area_mask(cpumask_t mask, const void *va, unsigned int flags)
{
    ASSERT(local_irq_is_enabled());

    if ( cpu_isset(smp_processor_id(), mask) )
    {
        flush_area_local(va, flags);
        cpu_clear(smp_processor_id(), mask);
    }

    if ( !cpus_empty(mask) )
    {
        spin_lock(&flush_lock);
        flush_cpumask = mask;
        flush_va      = va;
        flush_flags   = flags;
        send_IPI_mask(mask, INVALIDATE_TLB_VECTOR);
        while ( !cpus_empty(flush_cpumask) )
            cpu_relax();
        spin_unlock(&flush_lock);
    }
}

/* Call with no locks held and interrupts enabled (e.g., softirq context). */
void new_tlbflush_clock_period(void)
{
    cpumask_t allbutself;

    /* Flush everyone else. We definitely flushed just before entry. */
    allbutself = cpu_online_map;
    cpu_clear(smp_processor_id(), allbutself);
    flush_mask(allbutself, FLUSH_TLB);

    /* No need for atomicity: we are the only possible updater. */
    ASSERT(tlbflush_clock == 0);
    tlbflush_clock++;
}

void smp_send_event_check_mask(cpumask_t mask)
{
    cpu_clear(smp_processor_id(), mask);
    if ( !cpus_empty(mask) )
        send_IPI_mask(mask, EVENT_CHECK_VECTOR);
}

/*
 * Structure and data for smp_call_function()/on_selected_cpus().
 */

struct call_data_struct {
    void (*func) (void *info);
    void *info;
    int wait;
    atomic_t started;
    atomic_t finished;
    cpumask_t selected;
};

static DEFINE_SPINLOCK(call_lock);
static struct call_data_struct *call_data;

int smp_call_function(
    void (*func) (void *info),
    void *info,
    int retry,
    int wait)
{
    cpumask_t allbutself = cpu_online_map;
    cpu_clear(smp_processor_id(), allbutself);
    return on_selected_cpus(allbutself, func, info, retry, wait);
}

int on_selected_cpus(
    cpumask_t selected,
    void (*func) (void *info),
    void *info,
    int retry,
    int wait)
{
    struct call_data_struct data;
    unsigned int nr_cpus = cpus_weight(selected);

    ASSERT(local_irq_is_enabled());

    /* Legacy UP system with no APIC to deliver IPIs? */
    if ( unlikely(!cpu_has_apic) )
    {
        ASSERT(num_online_cpus() == 1);
        if ( cpu_isset(0, selected) )
        {
            local_irq_disable();
            func(info);
            local_irq_enable();
        }
        return 0;
    }

    if ( nr_cpus == 0 )
        return 0;

    data.func = func;
    data.info = info;
    data.wait = wait;
    atomic_set(&data.started, 0);
    atomic_set(&data.finished, 0);
    data.selected = selected;

    spin_lock(&call_lock);

    call_data = &data;
    wmb();

    send_IPI_mask(selected, CALL_FUNCTION_VECTOR);

    while ( atomic_read(wait ? &data.finished : &data.started) != nr_cpus )
        cpu_relax();

    spin_unlock(&call_lock);

    return 0;
}

static void __stop_this_cpu(void)
{
    ASSERT(!local_irq_is_enabled());

    disable_local_APIC();

    hvm_cpu_down();

    /*
     * Clear FPU, zapping any pending exceptions. Needed for warm reset with
     * some BIOSes.
     */
    clts();
    asm volatile ( "fninit" );
}

static void stop_this_cpu(void *dummy)
{
    __stop_this_cpu();
    cpu_clear(smp_processor_id(), cpu_online_map);
    for ( ; ; )
        halt();
}

/*
 * Stop all CPUs and turn off local APICs and the IO-APIC, so other OSs see a 
 * clean IRQ state.
 */
void smp_send_stop(void)
{
    int timeout = 10;

    smp_call_function(stop_this_cpu, NULL, 1, 0);

    /* Wait 10ms for all other CPUs to go offline. */
    while ( (num_online_cpus() > 1) && (timeout-- > 0) )
        mdelay(1);

    local_irq_disable();
    __stop_this_cpu();
    disable_IO_APIC();
    local_irq_enable();
}

fastcall void smp_event_check_interrupt(struct cpu_user_regs *regs)
{
    ack_APIC_irq();
    perfc_incr(ipis);
}

fastcall void smp_call_function_interrupt(struct cpu_user_regs *regs)
{
    void (*func)(void *info) = call_data->func;
    void *info = call_data->info;

    ack_APIC_irq();
    perfc_incr(ipis);

    if ( !cpu_isset(smp_processor_id(), call_data->selected) )
        return;

    irq_enter();

    if ( call_data->wait )
    {
        (*func)(info);
        mb();
        atomic_inc(&call_data->finished);
    }
    else
    {
        mb();
        atomic_inc(&call_data->started);
        (*func)(info);
    }

    irq_exit();
}
