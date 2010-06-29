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
#include <asm/hvm/support.h>
#include <mach_apic.h>

int hard_smp_processor_id(void)
{
    return get_apic_id();
}

int logical_smp_processor_id(void)
{
    return get_logical_apic_id();
}

/*
 * send_IPI_mask(cpumask, vector): sends @vector IPI to CPUs in @cpumask,
 * excluding the local CPU. @cpumask may be empty.
 */

void send_IPI_mask(const cpumask_t *mask, int vector)
{
    genapic->send_IPI_mask(mask, vector);
}

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
    return SET_xAPIC_DEST_FIELD(mask);
}

void apic_wait_icr_idle(void)
{
    if ( x2apic_enabled )
        return;

    while ( apic_read( APIC_ICR ) & APIC_ICR_BUSY )
        cpu_relax();
}

static void __default_send_IPI_shortcut(unsigned int shortcut, int vector,
                                    unsigned int dest)
{
    unsigned int cfg;

    /*
     * Wait for idle.
     */
    apic_wait_icr_idle();

    /*
     * prepare target chip field
     */
    cfg = __prepare_ICR(shortcut, vector) | dest;
    /*
     * Send the IPI. The write to APIC_ICR fires this off.
     */
    apic_write_around(APIC_ICR, cfg);
}

void send_IPI_self_flat(int vector)
{
    __default_send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}

void send_IPI_self_phys(int vector)
{
    __default_send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}

void send_IPI_self_x2apic(int vector)
{
    apic_write(APIC_SELF_IPI, vector);    
}

void send_IPI_mask_flat(const cpumask_t *cpumask, int vector)
{
    unsigned long mask = cpus_addr(*cpumask)[0];
    unsigned long cfg;
    unsigned long flags;

    mask &= cpus_addr(cpu_online_map)[0];
    mask &= ~(1UL << smp_processor_id());
    if ( mask == 0 )
        return;

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

void send_IPI_mask_phys(const cpumask_t *mask, int vector)
{
    unsigned long cfg, flags;
    unsigned int query_cpu;

    local_irq_save(flags);

    for_each_cpu_mask ( query_cpu, *mask )
    {
        if ( !cpu_online(query_cpu) || (query_cpu == smp_processor_id()) )
            continue;

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
    if ( !__sync_local_execstate() ||
         (flush_flags & (FLUSH_TLB_GLOBAL | FLUSH_CACHE)) )
        flush_area_local(flush_va, flush_flags);
    cpu_clear(smp_processor_id(), flush_cpumask);
    irq_exit();
}

void flush_area_mask(const cpumask_t *mask, const void *va, unsigned int flags)
{
    ASSERT(local_irq_is_enabled());

    if ( cpu_isset(smp_processor_id(), *mask) )
        flush_area_local(va, flags);

    if ( !cpus_subset(*mask, *cpumask_of(smp_processor_id())) )
    {
        spin_lock(&flush_lock);
        cpus_and(flush_cpumask, *mask, cpu_online_map);
        cpu_clear(smp_processor_id(), flush_cpumask);
        flush_va      = va;
        flush_flags   = flags;
        send_IPI_mask(&flush_cpumask, INVALIDATE_TLB_VECTOR);
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
    flush_mask(&allbutself, FLUSH_TLB);

    /* No need for atomicity: we are the only possible updater. */
    ASSERT(tlbflush_clock == 0);
    tlbflush_clock++;
}

void smp_send_event_check_mask(const cpumask_t *mask)
{
    send_IPI_mask(mask, EVENT_CHECK_VECTOR);
}

/*
 * Structure and data for smp_call_function()/on_selected_cpus().
 */

static void __smp_call_function_interrupt(void);
static DEFINE_SPINLOCK(call_lock);
static struct call_data_struct {
    void (*func) (void *info);
    void *info;
    int wait;
    atomic_t started;
    atomic_t finished;
    cpumask_t selected;
} call_data;

void smp_call_function(
    void (*func) (void *info),
    void *info,
    int wait)
{
    cpumask_t allbutself = cpu_online_map;
    cpu_clear(smp_processor_id(), allbutself);
    on_selected_cpus(&allbutself, func, info, wait);
}

void on_selected_cpus(
    const cpumask_t *selected,
    void (*func) (void *info),
    void *info,
    int wait)
{
    unsigned int nr_cpus;

    ASSERT(local_irq_is_enabled());

    spin_lock(&call_lock);

    call_data.selected = *selected;

    nr_cpus = cpus_weight(call_data.selected);
    if ( nr_cpus == 0 )
        goto out;

    call_data.func = func;
    call_data.info = info;
    call_data.wait = wait;
    atomic_set(&call_data.started, 0);
    atomic_set(&call_data.finished, 0);

    send_IPI_mask(&call_data.selected, CALL_FUNCTION_VECTOR);

    if ( cpu_isset(smp_processor_id(), call_data.selected) )
    {
        local_irq_disable();
        __smp_call_function_interrupt();
        local_irq_enable();
    }

    while ( atomic_read(wait ? &call_data.finished : &call_data.started)
            != nr_cpus )
        cpu_relax();

 out:
    spin_unlock(&call_lock);
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

    smp_call_function(stop_this_cpu, NULL, 0);

    /* Wait 10ms for all other CPUs to go offline. */
    while ( (num_online_cpus() > 1) && (timeout-- > 0) )
        mdelay(1);

    local_irq_disable();
    __stop_this_cpu();
    disable_IO_APIC();
    local_irq_enable();
}

void smp_send_nmi_allbutself(void)
{
    send_IPI_mask(&cpu_online_map, APIC_DM_NMI);
}

fastcall void smp_event_check_interrupt(struct cpu_user_regs *regs)
{
    struct cpu_user_regs *old_regs = set_irq_regs(regs);
    ack_APIC_irq();
    perfc_incr(ipis);
    set_irq_regs(old_regs);
}

static void __smp_call_function_interrupt(void)
{
    void (*func)(void *info) = call_data.func;
    void *info = call_data.info;

    if ( !cpu_isset(smp_processor_id(), call_data.selected) )
        return;

    irq_enter();

    if ( call_data.wait )
    {
        (*func)(info);
        mb();
        atomic_inc(&call_data.finished);
    }
    else
    {
        mb();
        atomic_inc(&call_data.started);
        (*func)(info);
    }

    irq_exit();
}

fastcall void smp_call_function_interrupt(struct cpu_user_regs *regs)
{
    struct cpu_user_regs *old_regs = set_irq_regs(regs);

    ack_APIC_irq();
    perfc_incr(ipis);
    __smp_call_function_interrupt();
    set_irq_regs(old_regs);
}
