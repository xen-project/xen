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
#include <asm/smpboot.h>
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

static inline void check_IPI_mask(cpumask_t cpumask)
{
    /*
     * Sanity, and necessary. An IPI with no target generates a send accept
     * error with Pentium and P6 APICs.
     */
    ASSERT(cpus_subset(cpumask, cpu_online_map));
    ASSERT(!cpus_empty(cpumask));
}

void send_IPI_mask_flat(cpumask_t cpumask, int vector)
{
    unsigned long mask = cpus_addr(cpumask)[0];
    unsigned long cfg;
    unsigned long flags;

    check_IPI_mask(cpumask);

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

    check_IPI_mask(mask);

    /*
     * Hack. The clustered APIC addressing mode doesn't allow us to send 
     * to an arbitrary mask, so I do a unicasts to each CPU instead. This 
     * should be modified to do 1 message per cluster ID - mbligh
     */ 

    local_irq_save(flags);

    for_each_cpu_mask( query_cpu, mask )
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
static unsigned long flush_va;

fastcall void smp_invalidate_interrupt(void)
{
    ack_APIC_irq();
    perfc_incrc(ipis);
    irq_enter();
    if ( !__sync_lazy_execstate() )
    {
        if ( flush_va == FLUSHVA_ALL )
            local_flush_tlb();
        else
            local_flush_tlb_one(flush_va);
    }
    cpu_clear(smp_processor_id(), flush_cpumask);
    irq_exit();
}

void __flush_tlb_mask(cpumask_t mask, unsigned long va)
{
    ASSERT(local_irq_is_enabled());
    
    if ( cpu_isset(smp_processor_id(), mask) )
    {
        if ( va == FLUSHVA_ALL )
            local_flush_tlb();
        else
            local_flush_tlb_one(va);
        cpu_clear(smp_processor_id(), mask);
    }

    if ( !cpus_empty(mask) )
    {
        spin_lock(&flush_lock);
        flush_cpumask = mask;
        flush_va      = va;
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
    __flush_tlb_mask(allbutself, FLUSHVA_ALL);

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

static void stop_this_cpu (void *dummy)
{
    cpu_clear(smp_processor_id(), cpu_online_map);

    local_irq_disable();
    disable_local_APIC();
    hvm_disable();

    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

void smp_send_stop(void)
{
    /* Stop all other CPUs in the system. */
    smp_call_function(stop_this_cpu, NULL, 1, 0);

    local_irq_disable();
    disable_local_APIC();
    local_irq_enable();
}

fastcall void smp_event_check_interrupt(struct cpu_user_regs *regs)
{
    ack_APIC_irq();
    perfc_incrc(ipis);
}

fastcall void smp_call_function_interrupt(struct cpu_user_regs *regs)
{
    void (*func)(void *info) = call_data->func;
    void *info = call_data->info;

    ack_APIC_irq();
    perfc_incrc(ipis);

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
