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
#include <asm/smp.h>
#include <asm/mc146818rtc.h>
#include <asm/flushtlb.h>
#include <asm/smpboot.h>
#include <asm/hardirq.h>

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
    return APIC_DM_FIXED | shortcut | vector | APIC_DEST_LOGICAL;
}

static inline int __prepare_ICR2 (unsigned int mask)
{
    return SET_APIC_DEST_FIELD(mask);
}

static inline void __send_IPI_shortcut(unsigned int shortcut, int vector)
{
    /*
     * Subtle. In the case of the 'never do double writes' workaround
     * we have to lock out interrupts to be safe.  As we don't care
     * of the value read we use an atomic rmw access to avoid costly
     * cli/sti.  Otherwise we use an even cheaper single atomic write
     * to the APIC.
     */
    unsigned int cfg;

    /*
     * Wait for idle.
     */
    apic_wait_icr_idle();

    /*
     * No need to touch the target chip field
     */
    cfg = __prepare_ICR(shortcut, vector);

    /*
     * Send the IPI. The write to APIC_ICR fires this off.
     */
    apic_write_around(APIC_ICR, cfg);
}

void send_IPI_self(int vector)
{
    __send_IPI_shortcut(APIC_DEST_SELF, vector);
}

static inline void send_IPI_mask(int mask, int vector)
{
    unsigned long cfg;
    unsigned long flags;

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
    cfg = __prepare_ICR(0, vector);

    /*
     * Send the IPI. The write to APIC_ICR fires this off.
     */
    apic_write_around(APIC_ICR, cfg);

    local_irq_restore(flags);
}

static inline void send_IPI_allbutself(int vector)
{
    /*
     * If there are no other CPUs in the system then we get an APIC send error 
     * if we try to broadcast. thus we have to avoid sending IPIs in this case.
     */
    if ( smp_num_cpus <= 1 )
        return;

    __send_IPI_shortcut(APIC_DEST_ALLBUT, vector);
}

static spinlock_t flush_lock = SPIN_LOCK_UNLOCKED;
static unsigned long flush_cpumask, flush_va;

asmlinkage void smp_invalidate_interrupt(void)
{
    ack_APIC_irq();
    perfc_incrc(ipis);
    if ( flush_va == FLUSHVA_ALL )
        local_flush_tlb();
    else
        local_flush_tlb_one(flush_va);
    clear_bit(smp_processor_id(), &flush_cpumask);
}

void __flush_tlb_mask(unsigned long mask, unsigned long va)
{
    ASSERT(local_irq_is_enabled());
    
    if ( mask & (1UL << smp_processor_id()) )
    {
        local_flush_tlb();
        mask &= ~(1UL << smp_processor_id());
    }

    if ( mask != 0 )
    {
        spin_lock(&flush_lock);
        flush_cpumask = mask;
        flush_va      = va;
        send_IPI_mask(mask, INVALIDATE_TLB_VECTOR);
        while ( flush_cpumask != 0 )
            cpu_relax();
        spin_unlock(&flush_lock);
    }
}

/* Call with no locks held and interrupts enabled (e.g., softirq context). */
void new_tlbflush_clock_period(void)
{
    ASSERT(local_irq_is_enabled());
    
    /* Flush everyone else. We definitely flushed just before entry. */
    if ( smp_num_cpus > 1 )
    {
        spin_lock(&flush_lock);
        flush_cpumask  = (1UL << smp_num_cpus) - 1;
        flush_cpumask &= ~(1UL << smp_processor_id());
        flush_va       = FLUSHVA_ALL;
        send_IPI_allbutself(INVALIDATE_TLB_VECTOR);
        while ( flush_cpumask != 0 )
            cpu_relax();
        spin_unlock(&flush_lock);
    }

    /* No need for atomicity: we are the only possible updater. */
    ASSERT(tlbflush_clock == 0);
    tlbflush_clock++;
}

static void flush_tlb_all_pge_ipi(void *info)
{
    local_flush_tlb_pge();
}

void flush_tlb_all_pge(void)
{
    smp_call_function(flush_tlb_all_pge_ipi, 0, 1, 1);
    local_flush_tlb_pge();
}

void smp_send_event_check_mask(unsigned long cpu_mask)
{
    cpu_mask &= ~(1UL << smp_processor_id());
    if ( cpu_mask != 0 )
        send_IPI_mask(cpu_mask, EVENT_CHECK_VECTOR);
}

/*
 * Structure and data for smp_call_function().
 */

struct call_data_struct {
    void (*func) (void *info);
    void *info;
    unsigned long started;
    unsigned long finished;
    int wait;
};

static spinlock_t call_lock = SPIN_LOCK_UNLOCKED;
static struct call_data_struct *call_data;

/*
 * Run a function on all other CPUs.
 *  @func: The function to run. This must be fast and non-blocking.
 *  @info: An arbitrary pointer to pass to the function.
 *  @wait: If true, spin until function has completed on other CPUs.
 *  Returns: 0 on success, else a negative status code.
 */
int smp_call_function(
    void (*func) (void *info), void *info, int unused, int wait)
{
    struct call_data_struct data;
    unsigned long cpuset;

    ASSERT(local_irq_is_enabled());

    cpuset = ((1UL << smp_num_cpus) - 1) & ~(1UL << smp_processor_id());
    if ( cpuset == 0 )
        return 0;

    data.func = func;
    data.info = info;
    data.started = data.finished = 0;
    data.wait = wait;

    spin_lock(&call_lock);

    call_data = &data;
    wmb();

    send_IPI_allbutself(CALL_FUNCTION_VECTOR);

    while ( (wait ? data.finished : data.started) != cpuset )
        cpu_relax();

    spin_unlock(&call_lock);

    return 0;
}

/* Run a function on a subset of CPUs (may include local CPU). */
int smp_subset_call_function(
    void (*func) (void *info), void *info, int wait, unsigned long cpuset)
{
    struct call_data_struct data;

    ASSERT(local_irq_is_enabled());

    if ( cpuset & (1UL << smp_processor_id()) )
    {
        local_irq_disable();
        (*func)(info);
        local_irq_enable();
    }

    cpuset &= ((1UL << smp_num_cpus) - 1) & ~(1UL << smp_processor_id());
    if ( cpuset == 0 )
        return 0;

    data.func = func;
    data.info = info;
    data.started = data.finished = 0;
    data.wait = wait;

    spin_lock(&call_lock);

    call_data = &data;
    wmb();

    send_IPI_mask(cpuset, CALL_FUNCTION_VECTOR);

    while ( (wait ? data.finished : data.started) != cpuset )
        cpu_relax();

    spin_unlock(&call_lock);

    return 0;
}

static void stop_this_cpu (void *dummy)
{
    clear_bit(smp_processor_id(), &cpu_online_map);

    disable_local_APIC();

    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

void smp_send_stop(void)
{
    /* Stop all other CPUs in the system. */
    smp_call_function(stop_this_cpu, NULL, 1, 0);
    smp_num_cpus = 1;

    local_irq_disable();
    disable_local_APIC();
    local_irq_enable();
}

asmlinkage void smp_event_check_interrupt(void)
{
    ack_APIC_irq();
    perfc_incrc(ipis);
}

asmlinkage void smp_call_function_interrupt(void)
{
    void (*func) (void *info) = call_data->func;
    void *info = call_data->info;

    ack_APIC_irq();
    perfc_incrc(ipis);

    if ( call_data->wait )
    {
        (*func)(info);
        mb();
        set_bit(smp_processor_id(), &call_data->finished);
    }
    else
    {
        mb();
        set_bit(smp_processor_id(), &call_data->started);
        (*func)(info);
    }
}
