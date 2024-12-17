/******************************************************************************
 * keyhandler.c
 */

#include <asm/regs.h>
#include <xen/delay.h>
#include <xen/keyhandler.h>
#include <xen/llc-coloring.h>
#include <xen/param.h>
#include <xen/sections.h>
#include <xen/shutdown.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/sched.h>
#include <xen/tasklet.h>
#include <xen/domain.h>
#include <xen/rangeset.h>
#include <xen/compat.h>
#include <xen/ctype.h>
#include <xen/perfc.h>
#include <xen/mm.h>
#include <xen/watchdog.h>
#include <xen/init.h>
#include <asm/div64.h>

static unsigned char keypress_key;
static bool alt_key_handling;

static keyhandler_fn_t cf_check show_handlers, cf_check dump_hwdom_registers,
    cf_check dump_domains, cf_check read_clocks;
static irq_keyhandler_fn_t cf_check do_toggle_alt_key, cf_check dump_registers,
    cf_check reboot_machine, cf_check run_all_keyhandlers;

static struct keyhandler {
    union {
        keyhandler_fn_t *fn;
        irq_keyhandler_fn_t *irq_fn;
    };

    const char *desc;    /* Description for help message.                 */
    bool irq_callback,   /* Call in irq context? if not, tasklet context. */
        diagnostic;      /* Include in 'dump all' handler.                */
} key_table[128] __ro_after_init =
{
#define KEYHANDLER(k, f, desc, diag)            \
    [k] = { { .fn = (f) }, desc, 0, diag }

#define IRQ_KEYHANDLER(k, f, desc, diag)        \
    [k] = { { .irq_fn = (f) }, desc, 1, diag }

    IRQ_KEYHANDLER('A', do_toggle_alt_key, "toggle alternative key handling", 0),
    IRQ_KEYHANDLER('d', dump_registers, "dump registers", 1),
        KEYHANDLER('h', show_handlers, "show this message", 0),
        KEYHANDLER('q', dump_domains, "dump domain (and guest debug) info", 1),
        KEYHANDLER('r', dump_runq, "dump run queues", 1),
    IRQ_KEYHANDLER('R', reboot_machine, "reboot machine", 0),
        KEYHANDLER('t', read_clocks, "display multi-cpu clock info", 1),
        KEYHANDLER('0', dump_hwdom_registers, "dump Dom0 registers", 1),
    IRQ_KEYHANDLER('*', run_all_keyhandlers, "print all diagnostics", 0),

#ifdef CONFIG_PERF_COUNTERS
    KEYHANDLER('p', perfc_printall, "print performance counters", 1),
    KEYHANDLER('P', perfc_reset, "reset performance counters", 0),
#endif

#ifdef CONFIG_DEBUG_LOCK_PROFILE
    KEYHANDLER('l', spinlock_profile_printall, "print lock profile info", 1),
    KEYHANDLER('L', spinlock_profile_reset, "reset lock profile info", 0),
#endif

#undef IRQ_KEYHANDLER
#undef KEYHANDLER
};

static void cf_check keypress_action(void *unused)
{
    handle_keypress(keypress_key, true);
}

static DECLARE_TASKLET(keypress_tasklet, keypress_action, NULL);

void handle_keypress(unsigned char key, bool need_context)
{
    struct keyhandler *h;

    if ( key >= ARRAY_SIZE(key_table) || !(h = &key_table[key])->fn )
        return;

    if ( !in_irq() || h->irq_callback )
    {
        console_start_log_everything();
        h->irq_callback ? h->irq_fn(key, need_context) : h->fn(key);
        console_end_log_everything();
    }
    else
    {
        keypress_key = key;
        tasklet_schedule(&keypress_tasklet);
    }
}

void __init register_keyhandler(unsigned char key, keyhandler_fn_t *fn,
                                const char *desc, bool diagnostic)
{
    BUG_ON(key >= ARRAY_SIZE(key_table)); /* Key in range? */
    ASSERT(!key_table[key].fn);           /* Clobbering something else? */

    key_table[key].fn = fn;
    key_table[key].desc = desc;
    key_table[key].irq_callback = 0;
    key_table[key].diagnostic = diagnostic;
}

void __init register_irq_keyhandler(unsigned char key, irq_keyhandler_fn_t *fn,
                                    const char *desc, bool diagnostic)
{
    BUG_ON(key >= ARRAY_SIZE(key_table)); /* Key in range? */
    ASSERT(!key_table[key].irq_fn);       /* Clobbering something else? */

    key_table[key].irq_fn = fn;
    key_table[key].desc = desc;
    key_table[key].irq_callback = 1;
    key_table[key].diagnostic = diagnostic;
}

static void cf_check show_handlers(unsigned char key)
{
    unsigned int i;

    printk("'%c' pressed -> showing installed handlers\n", key);
    for ( i = 0; i < ARRAY_SIZE(key_table); i++ )
        if ( key_table[i].fn )
            printk(" key '%c' (ascii '%02x') => %s\n",
                   isprint(i) ? i : ' ', i, key_table[i].desc);
}

static cpumask_t dump_execstate_mask;

void cf_check dump_execstate(const struct cpu_user_regs *regs)
{
    unsigned int cpu = smp_processor_id();

    if ( !guest_mode(regs) )
    {
        printk("*** Dumping CPU%u host state: ***\n", cpu);
        show_execution_state(regs);
    }

    if ( !is_idle_vcpu(current) )
    {
        printk("*** Dumping CPU%u guest state (%pv): ***\n",
               smp_processor_id(), current);
        show_execution_state(guest_cpu_user_regs());
        printk("\n");
    }

    cpumask_clear_cpu(cpu, &dump_execstate_mask);
    if ( !alt_key_handling )
        return;

    cpu = cpumask_cycle(cpu, &dump_execstate_mask);
    if ( cpu < nr_cpu_ids )
    {
        smp_send_state_dump(cpu);
        return;
    }

    console_end_sync();
    watchdog_enable();
}

static void cf_check dump_registers(
    unsigned char key, bool need_context)
{
    unsigned int cpu;

    /* We want to get everything out that we possibly can. */
    watchdog_disable();
    console_start_sync();

    printk("'%c' pressed -> dumping registers\n\n", key);

    cpumask_copy(&dump_execstate_mask, &cpu_online_map);

    /* Get local execution state out immediately, in case we get stuck. */
    if ( !need_context )
        dump_execstate(get_irq_regs() ?: guest_cpu_user_regs());
    else
        run_in_exception_handler(dump_execstate);

    /* Alt. handling: remaining CPUs are dumped asynchronously one-by-one. */
    if ( alt_key_handling )
        return;

    /* Normal handling: synchronously dump the remaining CPUs' states. */
    for_each_cpu ( cpu, &dump_execstate_mask )
    {
        smp_send_state_dump(cpu);
        while ( cpumask_test_cpu(cpu, &dump_execstate_mask) )
            cpu_relax();
    }

    console_end_sync();
    watchdog_enable();
}

static DECLARE_TASKLET(dump_hwdom_tasklet, NULL, NULL);

static void cf_check dump_hwdom_action(void *data)
{
    struct vcpu *v = data;

    for ( ; ; )
    {
        vcpu_show_execution_state(v);
        if ( (v = v->next_in_list) == NULL )
            break;
        if ( softirq_pending(smp_processor_id()) )
        {
            dump_hwdom_tasklet.data = v;
            tasklet_schedule_on_cpu(&dump_hwdom_tasklet, v->processor);
            break;
        }
    }
}

static void cf_check dump_hwdom_registers(unsigned char key)
{
    struct vcpu *v;

    if ( hardware_domain == NULL )
        return;

    printk("'%c' pressed -> dumping Dom0's registers\n", key);

    for_each_vcpu ( hardware_domain, v )
    {
        if ( alt_key_handling && softirq_pending(smp_processor_id()) )
        {
            tasklet_kill(&dump_hwdom_tasklet);
            tasklet_init(&dump_hwdom_tasklet, dump_hwdom_action, v);
            tasklet_schedule_on_cpu(&dump_hwdom_tasklet, v->processor);
            return;
        }
        vcpu_show_execution_state(v);
    }
}

static void cf_check reboot_machine(unsigned char key, bool unused)
{
    printk("'%c' pressed -> rebooting machine\n", key);
    machine_restart(0);
}

static void cf_check dump_domains(unsigned char key)
{
    struct domain *d;
    const struct sched_unit *unit;
    struct vcpu   *v;
    s_time_t       now = NOW();

    printk("'%c' pressed -> dumping domain info (now = %"PRI_stime")\n",
           key, now);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        unsigned int i;

        process_pending_softirqs();

        printk("General information for domain %u:\n", d->domain_id);
        printk("    refcnt=%d dying=%d pause_count=%d\n",
               atomic_read(&d->refcnt), d->is_dying,
               atomic_read(&d->pause_count));
        printk("    nr_pages=%u xenheap_pages=%u"
#ifdef CONFIG_MEM_SHARING
               " shared_pages=%u"
#endif
#ifdef CONFIG_MEM_PAGING
               " paged_pages=%u"
#endif
               " dirty_cpus={%*pbl} max_pages=%u\n",
               domain_tot_pages(d), d->xenheap_pages,
#ifdef CONFIG_MEM_SHARING
               atomic_read(&d->shr_pages),
#endif
#ifdef CONFIG_MEM_PAGING
               atomic_read(&d->paged_pages),
#endif
               CPUMASK_PR(d->dirty_cpumask), d->max_pages);
        printk("    handle=%02x%02x%02x%02x-%02x%02x-%02x%02x-"
               "%02x%02x-%02x%02x%02x%02x%02x%02x vm_assist=%08lx\n",
               d->handle[ 0], d->handle[ 1], d->handle[ 2], d->handle[ 3],
               d->handle[ 4], d->handle[ 5], d->handle[ 6], d->handle[ 7],
               d->handle[ 8], d->handle[ 9], d->handle[10], d->handle[11],
               d->handle[12], d->handle[13], d->handle[14], d->handle[15],
               d->vm_assist);
        for ( i = 0 ; i < NR_DOMAIN_WATCHDOG_TIMERS; i++ )
            if ( test_bit(i, &d->watchdog_inuse_map) )
                printk("    watchdog %d expires in %d seconds\n",
                       i, (u32)((d->watchdog_timer[i].expires - NOW()) >> 30));

        arch_dump_domain_info(d);

        domain_dump_llc_colors(d);

        rangeset_domain_printk(d);

        dump_pageframe_info(d);

        printk("NODE affinity for domain %d: [%*pbl]\n",
               d->domain_id, NODEMASK_PR(&d->node_affinity));

        printk("VCPU information and callbacks for domain %u:\n",
               d->domain_id);

        for_each_sched_unit ( d, unit )
        {
            printk("  UNIT%d affinities: hard={%*pbl} soft={%*pbl}\n",
                   unit->unit_id, CPUMASK_PR(unit->cpu_hard_affinity),
                   CPUMASK_PR(unit->cpu_soft_affinity));

            for_each_sched_unit_vcpu ( unit, v )
            {
                if ( !(v->vcpu_id & 0x3f) )
                    process_pending_softirqs();

                printk("    VCPU%d: CPU%d [has=%c] poll=%d "
                       "upcall_pend=%02x upcall_mask=%02x ",
                       v->vcpu_id, v->processor,
                       v->is_running ? 'T':'F', v->poll_evtchn,
                       vcpu_info(v, evtchn_upcall_pending),
                       !vcpu_event_delivery_is_enabled(v));
                if ( vcpu_cpu_dirty(v) )
                    printk("dirty_cpu=%u", read_atomic(&v->dirty_cpu));
                printk("\n");
                printk("    pause_count=%d pause_flags=%lx\n",
                       atomic_read(&v->pause_count), v->pause_flags);
                arch_dump_vcpu_info(v);

                if ( v->periodic_period == 0 )
                    printk("No periodic timer\n");
                else
                    printk("%"PRI_stime" Hz periodic timer (period %"PRI_stime" ms)\n",
                           1000000000 / v->periodic_period,
                           v->periodic_period / 1000000);
            }
        }
    }

    for_each_domain ( d )
    {
        for_each_vcpu ( d, v )
        {
            if ( !(v->vcpu_id & 0x3f) )
                process_pending_softirqs();

            printk("Notifying guest %d:%d (virq %d, port %d)\n",
                   d->domain_id, v->vcpu_id,
                   VIRQ_DEBUG, v->virq_to_evtchn[VIRQ_DEBUG]);
            send_guest_vcpu_virq(v, VIRQ_DEBUG);
        }
    }

#ifdef CONFIG_MEM_SHARING
    arch_dump_shared_mem_info();
#endif

    rcu_read_unlock(&domlist_read_lock);
}

static cpumask_t read_clocks_cpumask;
static DEFINE_PER_CPU(s_time_t, read_clocks_time);
static DEFINE_PER_CPU(u64, read_cycles_time);

static void cf_check read_clocks_slave(void *unused)
{
    unsigned int cpu = smp_processor_id();
    local_irq_disable();
    while ( !cpumask_test_cpu(cpu, &read_clocks_cpumask) )
        cpu_relax();
    per_cpu(read_clocks_time, cpu) = NOW();
    per_cpu(read_cycles_time, cpu) = get_cycles();
    cpumask_clear_cpu(cpu, &read_clocks_cpumask);
    local_irq_enable();
}

static void cf_check read_clocks(unsigned char key)
{
    unsigned int cpu = smp_processor_id(), min_stime_cpu, max_stime_cpu;
    unsigned int min_cycles_cpu, max_cycles_cpu;
    u64 min_stime, max_stime, dif_stime;
    u64 min_cycles, max_cycles, dif_cycles;
    static u64 sumdif_stime = 0, maxdif_stime = 0;
    static u64 sumdif_cycles = 0, maxdif_cycles = 0;
    static u32 count = 0;
    static DEFINE_SPINLOCK(lock);

    spin_lock(&lock);

    smp_call_function(read_clocks_slave, NULL, 0);

    local_irq_disable();
    cpumask_andnot(&read_clocks_cpumask, &cpu_online_map, cpumask_of(cpu));
    per_cpu(read_clocks_time, cpu) = NOW();
    per_cpu(read_cycles_time, cpu) = get_cycles();
    local_irq_enable();

    while ( !cpumask_empty(&read_clocks_cpumask) )
        cpu_relax();

    min_stime_cpu = max_stime_cpu = min_cycles_cpu = max_cycles_cpu = cpu;
    for_each_online_cpu ( cpu )
    {
        if ( per_cpu(read_clocks_time, cpu) <
             per_cpu(read_clocks_time, min_stime_cpu) )
            min_stime_cpu = cpu;
        if ( per_cpu(read_clocks_time, cpu) >
             per_cpu(read_clocks_time, max_stime_cpu) )
            max_stime_cpu = cpu;
        if ( per_cpu(read_cycles_time, cpu) <
             per_cpu(read_cycles_time, min_cycles_cpu) )
            min_cycles_cpu = cpu;
        if ( per_cpu(read_cycles_time, cpu) >
             per_cpu(read_cycles_time, max_cycles_cpu) )
            max_cycles_cpu = cpu;
    }

    min_stime = per_cpu(read_clocks_time, min_stime_cpu);
    max_stime = per_cpu(read_clocks_time, max_stime_cpu);
    min_cycles = per_cpu(read_cycles_time, min_cycles_cpu);
    max_cycles = per_cpu(read_cycles_time, max_cycles_cpu);

    spin_unlock(&lock);

    dif_stime = max_stime - min_stime;
    if ( dif_stime > maxdif_stime )
        maxdif_stime = dif_stime;
    sumdif_stime += dif_stime;
    dif_cycles = max_cycles - min_cycles;
    if ( dif_cycles > maxdif_cycles )
        maxdif_cycles = dif_cycles;
    sumdif_cycles += dif_cycles;
    count++;
    printk("Synced stime skew: max=%"PRIu64"ns avg=%"PRIu64"ns "
           "samples=%"PRIu32" current=%"PRIu64"ns\n",
           maxdif_stime, sumdif_stime/count, count, dif_stime);
    printk("Synced cycles skew: max=%"PRIu64" avg=%"PRIu64" "
           "samples=%"PRIu32" current=%"PRIu64"\n",
           maxdif_cycles, sumdif_cycles/count, count, dif_cycles);
}

static void cf_check run_all_nonirq_keyhandlers(void *unused)
{
    /* Fire all the non-IRQ-context diagnostic keyhandlers */
    struct keyhandler *h;
    int k;

    console_start_log_everything();

    for ( k = 0; k < ARRAY_SIZE(key_table); k++ )
    {
        process_pending_softirqs();
        h = &key_table[k];
        if ( !h->fn || !h->diagnostic || h->irq_callback )
            continue;
        printk("[%c: %s]\n", k, h->desc);
        h->fn(k);
    }

    console_end_log_everything();
}

static DECLARE_TASKLET(run_all_keyhandlers_tasklet,
                       run_all_nonirq_keyhandlers, NULL);

static void cf_check run_all_keyhandlers(unsigned char key, bool need_context)
{
    struct keyhandler *h;
    unsigned int k;

    watchdog_disable();

    printk("'%c' pressed -> firing all diagnostic keyhandlers\n", key);

    /* Fire all the IRQ-context diangostic keyhandlers now */
    for ( k = 0; k < ARRAY_SIZE(key_table); k++ )
    {
        h = &key_table[k];
        if ( !h->irq_fn || !h->diagnostic || !h->irq_callback )
            continue;
        printk("[%c: %s]\n", k, h->desc);
        h->irq_fn(k, need_context);
    }

    watchdog_enable();

    /* Trigger the others from a tasklet in non-IRQ context */
    tasklet_schedule(&run_all_keyhandlers_tasklet);
}

static void cf_check do_toggle_alt_key(unsigned char key, bool unused)
{
    alt_key_handling = !alt_key_handling;
    printk("'%c' pressed -> using %s key handling\n", key,
           alt_key_handling ? "alternative" : "normal");
}

void __init initialize_keytable(void)
{
    if ( num_present_cpus() > 16 )
    {
        alt_key_handling = 1;
        printk(XENLOG_INFO "Defaulting to alternative key handling; "
               "send 'A' to switch to normal mode.\n");
    }
}

#define CRASHACTION_SIZE  32
static char crash_debug_panic[CRASHACTION_SIZE];
string_runtime_param("crash-debug-panic", crash_debug_panic);
static char crash_debug_hwdom[CRASHACTION_SIZE];
string_runtime_param("crash-debug-hwdom", crash_debug_hwdom);
static char crash_debug_watchdog[CRASHACTION_SIZE];
string_runtime_param("crash-debug-watchdog", crash_debug_watchdog);
#ifdef CONFIG_KEXEC
static char crash_debug_kexeccmd[CRASHACTION_SIZE];
string_runtime_param("crash-debug-kexeccmd", crash_debug_kexeccmd);
#else
#define crash_debug_kexeccmd NULL
#endif
static char crash_debug_debugkey[CRASHACTION_SIZE];
string_runtime_param("crash-debug-debugkey", crash_debug_debugkey);

void keyhandler_crash_action(enum crash_reason reason)
{
    static const char *const crash_action[] = {
        [CRASHREASON_PANIC] = crash_debug_panic,
        [CRASHREASON_HWDOM] = crash_debug_hwdom,
        [CRASHREASON_WATCHDOG] = crash_debug_watchdog,
        [CRASHREASON_KEXECCMD] = crash_debug_kexeccmd,
        [CRASHREASON_DEBUGKEY] = crash_debug_debugkey,
    };
    static bool ignore;
    const char *action;

    /* Some handlers are not functional too early. */
    if ( system_state < SYS_STATE_smp_boot )
        return;

    if ( (unsigned int)reason >= ARRAY_SIZE(crash_action) )
        return;
    action = crash_action[reason];
    if ( !action )
        return;

    /* Avoid recursion. */
    if ( ignore )
        return;
    ignore = true;

    while ( *action )
    {
        if ( *action == '+' )
            mdelay(10);
        else
            handle_keypress(*action, true);
        action++;
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
