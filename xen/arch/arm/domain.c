#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/wait.h>
#include <xen/errno.h>

#include <asm/current.h>
#include <asm/regs.h>
#include <asm/p2m.h>
#include <asm/irq.h>

#include "gic.h"

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

static void continue_idle_domain(struct vcpu *v)
{
    reset_stack_and_jump(idle_loop);
}

static void continue_nonidle_domain(struct vcpu *v)
{
    /* check_wakeup_from_wait(); */
    reset_stack_and_jump(return_from_trap);
}

void idle_loop(void)
{
    for ( ; ; )
    {
        /* TODO
           if ( cpu_is_offline(smp_processor_id()) )
           play_dead();
           (*pm_idle)();
           BUG();
        */
        do_tasklet();
        do_softirq();
    }
}

static void ctxt_switch_from(struct vcpu *p)
{

}

static void ctxt_switch_to(struct vcpu *n)
{
    p2m_load_VTTBR(n->domain);
}

static void __context_switch(void)
{
    struct cpu_user_regs *stack_regs = guest_cpu_user_regs();
    unsigned int          cpu = smp_processor_id();
    struct vcpu          *p = per_cpu(curr_vcpu, cpu);
    struct vcpu          *n = current;

    ASSERT(p != n);
    ASSERT(cpumask_empty(n->vcpu_dirty_cpumask));

    if ( !is_idle_vcpu(p) )
    {
        memcpy(&p->arch.user_regs, stack_regs, CTXT_SWITCH_STACK_BYTES);
        ctxt_switch_from(p);
    }

    if ( !is_idle_vcpu(n) )
    {
        memcpy(stack_regs, &n->arch.user_regs, CTXT_SWITCH_STACK_BYTES);
        ctxt_switch_to(n);
    }

    per_cpu(curr_vcpu, cpu) = n;

}

static void schedule_tail(struct vcpu *v)
{
    if ( is_idle_vcpu(v) )
        continue_idle_domain(v);
    else
        continue_nonidle_domain(v);
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    unsigned int cpu = smp_processor_id();

    ASSERT(local_irq_is_enabled());

    printk("context switch %d:%d%s -> %d:%d%s\n",
           prev->domain->domain_id, prev->vcpu_id, is_idle_vcpu(prev) ? " (idle)" : "",
           next->domain->domain_id, next->vcpu_id, is_idle_vcpu(next) ? " (idle)" : "");

    /* TODO
       if (prev != next)
       update_runstate_area(prev);
    */

    local_irq_disable();

    set_current(next);

    if ( (per_cpu(curr_vcpu, cpu) == next) ||
         (is_idle_vcpu(next) && cpu_online(cpu)) )
    {
        local_irq_enable();
    }
    else
    {
        __context_switch();

        /* Re-enable interrupts before restoring state which may fault. */
        local_irq_enable();
    }

    context_saved(prev);

    /* TODO
       if (prev != next)
       update_runstate_area(next);
    */

    schedule_tail(next);
    BUG();

}

void continue_running(struct vcpu *same)
{
    schedule_tail(same);
    BUG();
}

int __sync_local_execstate(void)
{
    unsigned long flags;
    int switch_required;

    local_irq_save(flags);

    switch_required = (this_cpu(curr_vcpu) != current);

    if ( switch_required )
    {
        ASSERT(current == idle_vcpu[smp_processor_id()]);
        __context_switch();
    }

    local_irq_restore(flags);

    return switch_required;
}

void sync_local_execstate(void)
{
    (void)__sync_local_execstate();
}

void startup_cpu_idle_loop(void)
{
        struct vcpu *v = current;

        ASSERT(is_idle_vcpu(v));
        /* TODO
           cpumask_set_cpu(v->processor, v->domain->domain_dirty_cpumask);
           cpumask_set_cpu(v->processor, v->vcpu_dirty_cpumask);
        */

        reset_stack_and_jump(idle_loop);
}

struct domain *alloc_domain_struct(void)
{
    struct domain *d;
    BUILD_BUG_ON(sizeof(*d) > PAGE_SIZE);
    d = alloc_xenheap_pages(0, 0);
    if ( d != NULL )
        clear_page(d);
    return d;
}

void free_domain_struct(struct domain *d)
{
    free_xenheap_page(d);
}

void dump_pageframe_info(struct domain *d)
{

}

struct vcpu *alloc_vcpu_struct(void)
{
    struct vcpu *v;
    BUILD_BUG_ON(sizeof(*v) > PAGE_SIZE);
    v = alloc_xenheap_pages(0, 0);
    if ( v != NULL )
        clear_page(v);
    return v;
}

void free_vcpu_struct(struct vcpu *v)
{
    free_xenheap_page(v);
}

int vcpu_initialise(struct vcpu *v)
{
    int rc = 0;

    return rc;
}

void vcpu_destroy(struct vcpu *v)
{

}

int arch_domain_create(struct domain *d, unsigned int domcr_flags)
{
    int rc;

    d->max_vcpus = 8;

    rc = 0;
fail:
    return rc;
}

void arch_domain_destroy(struct domain *d)
{
    /* p2m_destroy */
    /* domain_vgic_destroy */
}

void arch_dump_domain_info(struct domain *d)
{
}

void arch_dump_vcpu_info(struct vcpu *v)
{
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
