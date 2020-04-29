/*
 *	Intel SMP support routines.
 *
 *	(c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *	(c) 1998-99, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *	This code is released under the GNU General Public License version 2 or
 *	later.
 */

#include <xen/cpu.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/perfc.h>
#include <xen/spinlock.h>
#include <asm/current.h>
#include <asm/guest.h>
#include <asm/smp.h>
#include <asm/mc146818rtc.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>
#include <asm/hpet.h>
#include <asm/hvm/support.h>
#include <irq_vectors.h>
#include <mach_apic.h>

/* Helper functions to prepare APIC register values. */
static unsigned int prepare_ICR(unsigned int shortcut, int vector)
{
    return APIC_DM_FIXED | shortcut | vector;
}

static unsigned int prepare_ICR2(unsigned int mask)
{
    return SET_xAPIC_DEST_FIELD(mask);
}

void apic_wait_icr_idle(void)
{
    if ( x2apic_enabled )
        return;

    while ( apic_read(APIC_ICR) & APIC_ICR_BUSY )
        cpu_relax();
}

/* Helper for sending APIC IPIs using a shorthand. */
static void send_IPI_shortcut(unsigned int shortcut, int vector,
                              unsigned int dest)
{
    unsigned int cfg;

    /* Wait for idle. */
    apic_wait_icr_idle();
    /* Prepare target chip field. */
    cfg = prepare_ICR(shortcut, vector) | dest;
    /* Send the IPI. The write to APIC_ICR fires this off. */
    apic_write(APIC_ICR, cfg);
}

/*
 * send_IPI_mask(cpumask, vector): sends @vector IPI to CPUs in @cpumask,
 * excluding the local CPU. @cpumask may be empty.
 */

void send_IPI_mask(const cpumask_t *mask, int vector)
{
    bool cpus_locked = false;
    cpumask_t *scratch = this_cpu(send_ipi_cpumask);

    if ( in_irq() || in_mce_handler() || in_nmi_handler() )
    {
        /*
         * When in IRQ, NMI or #MC context fallback to the old (and simpler)
         * IPI sending routine, and avoid doing any performance optimizations
         * (like using a shorthand) in order to avoid using the scratch
         * cpumask which cannot be used in interrupt context.
         */
        alternative_vcall(genapic.send_IPI_mask, mask, vector);
        return;
    }

    /*
     * This can only be safely used when no CPU hotplug or unplug operations
     * are taking place, there are no offline CPUs (unless those have been
     * onlined and parked), there are no disabled CPUs and all possible CPUs in
     * the system have been accounted for.
     */
    if ( system_state > SYS_STATE_smp_boot &&
         !unaccounted_cpus && !disabled_cpus &&
         /* NB: get_cpu_maps lock requires enabled interrupts. */
         local_irq_is_enabled() && (cpus_locked = get_cpu_maps()) &&
         (park_offline_cpus ||
          cpumask_equal(&cpu_online_map, &cpu_present_map)) )
        cpumask_or(scratch, mask, cpumask_of(smp_processor_id()));
    else
    {
        if ( cpus_locked )
        {
            put_cpu_maps();
            cpus_locked = false;
        }
        cpumask_clear(scratch);
    }

    if ( cpumask_equal(scratch, &cpu_online_map) )
        send_IPI_shortcut(APIC_DEST_ALLBUT, vector, APIC_DEST_PHYSICAL);
    else
        alternative_vcall(genapic.send_IPI_mask, mask, vector);

    if ( cpus_locked )
        put_cpu_maps();
}

void send_IPI_self(int vector)
{
    alternative_vcall(genapic.send_IPI_self, vector);
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

void send_IPI_self_legacy(uint8_t vector)
{
    send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}

void send_IPI_mask_flat(const cpumask_t *cpumask, int vector)
{
    unsigned long mask = cpumask_bits(cpumask)[0];
    unsigned long cfg;
    unsigned long flags;

    mask &= cpumask_bits(&cpu_online_map)[0];
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
    cfg = prepare_ICR2(mask);
    apic_write(APIC_ICR2, cfg);

    /*
     * program the ICR
     */
    cfg = prepare_ICR(0, vector) | APIC_DEST_LOGICAL;

    /*
     * Send the IPI. The write to APIC_ICR fires this off.
     */
    apic_write(APIC_ICR, cfg);
    
    local_irq_restore(flags);
}

void send_IPI_mask_phys(const cpumask_t *mask, int vector)
{
    unsigned long cfg, flags;
    unsigned int query_cpu;

    local_irq_save(flags);

    for_each_cpu ( query_cpu, mask )
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
        cfg = prepare_ICR2(cpu_physical_id(query_cpu));
        apic_write(APIC_ICR2, cfg);

        /*
         * program the ICR
         */
        cfg = prepare_ICR(0, vector) | APIC_DEST_PHYSICAL;

        /*
         * Send the IPI. The write to APIC_ICR fires this off.
         */
        apic_write(APIC_ICR, cfg);
    }

    local_irq_restore(flags);
}

static DEFINE_SPINLOCK(flush_lock);
static cpumask_t flush_cpumask;
static const void *flush_va;
static unsigned int flush_flags;

void invalidate_interrupt(struct cpu_user_regs *regs)
{
    unsigned int flags = flush_flags;
    ack_APIC_irq();
    perfc_incr(ipis);
    if ( (flags & FLUSH_VCPU_STATE) && __sync_local_execstate() )
        flags &= ~(FLUSH_TLB | FLUSH_TLB_GLOBAL | FLUSH_ROOT_PGTBL);
    if ( flags & ~(FLUSH_VCPU_STATE | FLUSH_ORDER_MASK) )
        flush_area_local(flush_va, flags);
    cpumask_clear_cpu(smp_processor_id(), &flush_cpumask);
}

void flush_area_mask(const cpumask_t *mask, const void *va, unsigned int flags)
{
    unsigned int cpu = smp_processor_id();

    ASSERT(local_irq_is_enabled());

    if ( (flags & ~(FLUSH_VCPU_STATE | FLUSH_ORDER_MASK)) &&
         cpumask_test_cpu(cpu, mask) )
        flags = flush_area_local(va, flags);

    if ( (flags & ~FLUSH_ORDER_MASK) &&
         !cpumask_subset(mask, cpumask_of(cpu)) )
    {
        if ( cpu_has_hypervisor &&
             !(flags & ~(FLUSH_TLB | FLUSH_TLB_GLOBAL | FLUSH_VA_VALID |
                         FLUSH_ORDER_MASK)) &&
             !hypervisor_flush_tlb(mask, va, (flags - 1) & FLUSH_ORDER_MASK) )
            return;

        spin_lock(&flush_lock);
        cpumask_and(&flush_cpumask, mask, &cpu_online_map);
        cpumask_clear_cpu(cpu, &flush_cpumask);
        flush_va      = va;
        flush_flags   = flags;
        send_IPI_mask(&flush_cpumask, INVALIDATE_TLB_VECTOR);
        while ( !cpumask_empty(&flush_cpumask) )
            cpu_relax();
        spin_unlock(&flush_lock);
    }
}

/* Call with no locks held and interrupts enabled (e.g., softirq context). */
void new_tlbflush_clock_period(void)
{
    cpumask_t allbutself;

    /* Flush everyone else. We definitely flushed just before entry. */
    cpumask_andnot(&allbutself, &cpu_online_map,
                   cpumask_of(smp_processor_id()));
    flush_mask(&allbutself, FLUSH_TLB);

    /* No need for atomicity: we are the only possible updater. */
    ASSERT(tlbflush_clock == 0);
    tlbflush_clock++;
}

void smp_send_event_check_mask(const cpumask_t *mask)
{
    send_IPI_mask(mask, EVENT_CHECK_VECTOR);
}

void smp_send_call_function_mask(const cpumask_t *mask)
{
    send_IPI_mask(mask, CALL_FUNCTION_VECTOR);

    if ( cpumask_test_cpu(smp_processor_id(), mask) )
    {
        local_irq_disable();
        smp_call_function_interrupt();
        local_irq_enable();
    }
}

void __stop_this_cpu(void)
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

    cpumask_clear_cpu(smp_processor_id(), &cpu_online_map);
}

static void stop_this_cpu(void *dummy)
{
    __stop_this_cpu();
    for ( ; ; )
        halt();
}

/*
 * Stop all CPUs and turn off local APICs and the IO-APIC, so other OSs see a 
 * clean IRQ state.
 */
void smp_send_stop(void)
{
    unsigned int cpu = smp_processor_id();

    if ( num_online_cpus() > 1 )
    {
        int timeout = 10;

        local_irq_disable();
        fixup_irqs(cpumask_of(cpu), 0);
        local_irq_enable();

        smp_call_function(stop_this_cpu, NULL, 0);

        /* Wait 10ms for all other CPUs to go offline. */
        while ( (num_online_cpus() > 1) && (timeout-- > 0) )
            mdelay(1);
    }

    if ( cpu_online(cpu) )
    {
        local_irq_disable();
        disable_IO_APIC();
        hpet_disable();
        __stop_this_cpu();
        x2apic_enabled = (current_local_apic_mode() == APIC_MODE_X2APIC);
        local_irq_enable();
    }
}

void smp_send_nmi_allbutself(void)
{
    send_IPI_mask(&cpu_online_map, APIC_DM_NMI);
}

void event_check_interrupt(struct cpu_user_regs *regs)
{
    ack_APIC_irq();
    perfc_incr(ipis);
    this_cpu(irq_count)++;
}

void call_function_interrupt(struct cpu_user_regs *regs)
{
    ack_APIC_irq();
    perfc_incr(ipis);
    smp_call_function_interrupt();
}
