/*
 *	Intel SMP support routines.
 *
 *	(c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *	(c) 1998-99, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *	This code is released under the GNU General Public License version 2 or
 *	later.
 */

#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/spinlock.h>
#include <asm/smp.h>
#include <asm/mc146818rtc.h>
#include <asm/flushtlb.h>
#include <asm/smpboot.h>
#include <asm/hardirq.h>

#ifdef CONFIG_SMP

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
 * the following functions deal with sending IPIs between CPUs.
 *
 * We use 'broadcast', CPU->CPU IPIs and self-IPIs too.
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

    __save_flags(flags);
    __cli();

		
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

    __restore_flags(flags);
}

static inline void send_IPI_allbutself(int vector)
{
    /*
     * if there are no other CPUs in the system then
     * we get an APIC send error if we try to broadcast.
     * thus we have to avoid sending IPIs in this case.
     */
    if (!(smp_num_cpus > 1))
        return;

    __send_IPI_shortcut(APIC_DEST_ALLBUT, vector);
}

/*
 * ********* XEN NOTICE **********
 * I've left the following comments lying around as they look liek they might
 * be useful to get multiprocessor guest OSes going. However, I suspect the
 * issues we face will be quite different so I've ripped out all the
 * TLBSTATE logic (I didn't understand it anyway :-). These comments do
 * not apply to Xen, therefore! -- Keir (8th Oct 2003).
 */
/*
 *	Smarter SMP flushing macros. 
 *		c/o Linus Torvalds.
 *
 *	These mean you can really definitely utterly forget about
 *	writing to user space from interrupts. (Its not allowed anyway).
 *
 *	Optimizations Manfred Spraul <manfred@colorfullife.com>
 *
 * The flush IPI assumes that a thread switch happens in this order:
 * [cpu0: the cpu that switches]
 * 1) switch_mm() either 1a) or 1b)
 * 1a) thread switch to a different mm
 * 1a1) clear_bit(cpu, &old_mm.cpu_vm_mask);
 * 	Stop ipi delivery for the old mm. This is not synchronized with
 * 	the other cpus, but smp_invalidate_interrupt ignore flush ipis
 * 	for the wrong mm, and in the worst case we perform a superflous
 * 	tlb flush.
 * 1a2) set cpu_tlbstate to TLBSTATE_OK
 * 	Now the smp_invalidate_interrupt won't call leave_mm if cpu0
 *	was in lazy tlb mode.
 * 1a3) update cpu_tlbstate[].active_mm
 * 	Now cpu0 accepts tlb flushes for the new mm.
 * 1a4) set_bit(cpu, &new_mm.cpu_vm_mask);
 * 	Now the other cpus will send tlb flush ipis.
 * 1a4) change cr3.
 * 1b) thread switch without mm change
 *	cpu_tlbstate[].active_mm is correct, cpu0 already handles
 *	flush ipis.
 * 1b1) set cpu_tlbstate to TLBSTATE_OK
 * 1b2) test_and_set the cpu bit in cpu_vm_mask.
 * 	Atomically set the bit [other cpus will start sending flush ipis],
 * 	and test the bit.
 * 1b3) if the bit was 0: leave_mm was called, flush the tlb.
 * 2) switch %%esp, ie current
 *
 * The interrupt must handle 2 special cases:
 * - cr3 is changed before %%esp, ie. it cannot use current->{active_,}mm.
 * - the cpu performs speculative tlb reads, i.e. even if the cpu only
 *   runs in kernel space, the cpu could load tlb entries for user space
 *   pages.
 *
 * The good news is that cpu_tlbstate is local to each cpu, no
 * write/read ordering problems.
 *
 * TLB flush IPI:
 *
 * 1) Flush the tlb entries if the cpu uses the mm that's being flushed.
 * 2) Leave the mm if we are in the lazy tlb mode.
 */

static spinlock_t flush_lock = SPIN_LOCK_UNLOCKED;
static unsigned long flush_cpumask;

asmlinkage void smp_invalidate_interrupt(void)
{
    ack_APIC_irq();
    perfc_incrc(ipis);
    local_flush_tlb();
    clear_bit(smp_processor_id(), &flush_cpumask);
}

void flush_tlb_mask(unsigned long mask)
{
    ASSERT(!in_irq());
    
    if ( mask & (1 << smp_processor_id()) )
    {
        local_flush_tlb();
        mask &= ~(1 << smp_processor_id());
    }

    if ( mask != 0 )
    {
        /*
         * We are certainly not reentering a flush_lock region on this CPU
         * because we are not in an IRQ context. We can therefore wait for the
         * other guy to release the lock. This is harder than it sounds because
         * local interrupts might be disabled, and he may be waiting for us to
         * execute smp_invalidate_interrupt(). We deal with this possibility by
         * inlining the meat of that function here.
         */
        while ( unlikely(!spin_trylock(&flush_lock)) )
        {
            if ( test_and_clear_bit(smp_processor_id(), &flush_cpumask) )
                local_flush_tlb();
            rep_nop();
        }

        flush_cpumask = mask;
        send_IPI_mask(mask, INVALIDATE_TLB_VECTOR);
        while ( flush_cpumask != 0 )
        {
            rep_nop();
            barrier();
        }

        spin_unlock(&flush_lock);
    }
}

/*
 * NB. Must be called with no locks held and interrupts enabled.
 *     (e.g., softirq context).
 */
void new_tlbflush_clock_period(void)
{
    /* Only the leader gets here. Noone else should tick the clock. */
    ASSERT(((tlbflush_clock+1) & TLBCLOCK_EPOCH_MASK) == 0);

    /* Flush everyone else. We definitely flushed just before entry. */
    if ( smp_num_cpus > 1 )
    {
        spin_lock(&flush_lock);
        flush_cpumask = ((1 << smp_num_cpus) - 1) & ~(1 << smp_processor_id());
        send_IPI_allbutself(INVALIDATE_TLB_VECTOR);
        while ( flush_cpumask != 0 )
        {
            rep_nop();
            barrier();
        }
        spin_unlock(&flush_lock);
    }

    /* No need for atomicity: we are the only possible updater. */
    tlbflush_clock++;

    /* Finally, signal the end of the epoch-change protocol. */
    wmb();
    tlbflush_epoch_changing = 0;

    /* In case we got to the end of the next epoch already. */
    tlb_clocktick();
}

static void flush_tlb_all_pge_ipi(void* info)
{
    __flush_tlb_pge();
}

void flush_tlb_all_pge(void)
{
    smp_call_function (flush_tlb_all_pge_ipi,0,1,1);
    __flush_tlb_pge();
}

void smp_send_event_check_mask(unsigned long cpu_mask)
{
    cpu_mask &= ~(1<<smp_processor_id());
    if ( cpu_mask != 0 )
        send_IPI_mask(cpu_mask, EVENT_CHECK_VECTOR);
}

/*
 * Structure and data for smp_call_function(). This is designed to minimise
 * static memory requirements. It also looks cleaner.
 */
static spinlock_t call_lock = SPIN_LOCK_UNLOCKED;

struct call_data_struct {
    void (*func) (void *info);
    void *info;
    atomic_t started;
    atomic_t finished;
    int wait;
};

static struct call_data_struct * call_data;

/*
 * this function sends a 'generic call function' IPI to all other CPUs
 * in the system.
 */

int smp_call_function (void (*func) (void *info), void *info, int nonatomic,
                       int wait)
/*
 * [SUMMARY] Run a function on all other CPUs.
 * <func> The function to run. This must be fast and non-blocking.
 * <info> An arbitrary pointer to pass to the function.
 * <nonatomic> currently unused.
 * <wait> If true, wait (atomically) until function has completed on other CPUs.
 * [RETURNS] 0 on success, else a negative status code. Does not return until
 * remote CPUs are nearly ready to execute <<func>> or are or have executed.
 *
 * You must not call this function with disabled interrupts or from a
 * hardware interrupt handler, or bottom halfs.
 */
{
    struct call_data_struct data;
    int cpus = smp_num_cpus-1;

    if (!cpus)
        return 0;

    data.func = func;
    data.info = info;
    atomic_set(&data.started, 0);
    data.wait = wait;
    if (wait)
        atomic_set(&data.finished, 0);

    ASSERT(local_irq_is_enabled());

    spin_lock(&call_lock);

    call_data = &data;
    wmb();
    /* Send a message to all other CPUs and wait for them to respond */
    send_IPI_allbutself(CALL_FUNCTION_VECTOR);

    /* Wait for response */
    while (atomic_read(&data.started) != cpus)
        barrier();

    if (wait)
        while (atomic_read(&data.finished) != cpus)
            barrier();

    spin_unlock(&call_lock);

    return 0;
}

static void stop_this_cpu (void * dummy)
{
    /*
     * Remove this CPU:
     */
    clear_bit(smp_processor_id(), &cpu_online_map);
    __cli();
    disable_local_APIC();
    for(;;) __asm__("hlt");
}

/*
 * this function calls the 'stop' function on all other CPUs in the system.
 */

void smp_send_stop(void)
{
    smp_call_function(stop_this_cpu, NULL, 1, 0);
    smp_num_cpus = 1;

    __cli();
    disable_local_APIC();
    __sti();
}

/*
 * Nothing to do, as all the work is done automatically when
 * we return from the interrupt.
 */
asmlinkage void smp_event_check_interrupt(void)
{
    ack_APIC_irq();
    perfc_incrc(ipis);
}

asmlinkage void smp_call_function_interrupt(void)
{
    void (*func) (void *info) = call_data->func;
    void *info = call_data->info;
    int wait = call_data->wait;

    ack_APIC_irq();
    perfc_incrc(ipis);

    /*
     * Notify initiating CPU that I've grabbed the data and am
     * about to execute the function
     */
    mb();
    atomic_inc(&call_data->started);
    /*
     * At this point the info structure may be out of scope unless wait==1
     */
    (*func)(info);
    if (wait) {
        mb();
        atomic_inc(&call_data->finished);
    }
}

#endif /* CONFIG_SMP */
