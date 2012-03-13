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
#include "vtimer.h"

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
        if ( cpu_is_offline(smp_processor_id()) )
            stop_cpu();

        local_irq_disable();
        if ( cpu_is_haltable(smp_processor_id()) )
            asm volatile ("dsb; wfi");
        local_irq_enable();

        do_tasklet();
        do_softirq();
    }
}

static void ctxt_switch_from(struct vcpu *p)
{
    context_saved(p);
}

static void ctxt_switch_to(struct vcpu *n)
{
    p2m_load_VTTBR(n->domain);
}

static void schedule_tail(struct vcpu *prev)
{
    /* Re-enable interrupts before restoring state which may fault. */
    local_irq_enable();

    ctxt_switch_from(prev);

    /* TODO
       update_runstate_area(current);
    */
    ctxt_switch_to(current);
}

static void continue_new_vcpu(struct vcpu *prev)
{
    schedule_tail(prev);

    if ( is_idle_vcpu(current) )
        continue_idle_domain(current);
    else
        continue_nonidle_domain(current);
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    ASSERT(local_irq_is_enabled());
    ASSERT(prev != next);
    ASSERT(cpumask_empty(next->vcpu_dirty_cpumask));

    /* TODO
       update_runstate_area(prev);
    */

    local_irq_disable();

    set_current(next);

    prev = __context_switch(prev, next);

    schedule_tail(prev);
}

void continue_running(struct vcpu *same)
{
    /* Nothing to do */
}

void sync_local_execstate(void)
{
    /* Nothing to do -- no lazy switching */
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

    v->arch.stack = alloc_xenheap_pages(STACK_ORDER, MEMF_node(vcpu_to_node(v)));
    if ( v->arch.stack == NULL )
        return -ENOMEM;

    v->arch.cpu_info = (struct cpu_info *)(v->arch.stack
                                           + STACK_SIZE
                                           - sizeof(struct cpu_info));

    memset(&v->arch.saved_context, 0, sizeof(v->arch.saved_context));
    v->arch.saved_context.sp = (uint32_t)v->arch.cpu_info;
    v->arch.saved_context.pc = (uint32_t)continue_new_vcpu;

    if ( (rc = vcpu_vgic_init(v)) != 0 )
        return rc;

    if ( (rc = vcpu_vtimer_init(v)) != 0 )
        return rc;

    return rc;
}

void vcpu_destroy(struct vcpu *v)
{
    free_xenheap_pages(v->arch.stack, STACK_ORDER);
}

int arch_domain_create(struct domain *d, unsigned int domcr_flags)
{
    int rc;

    rc = -ENOMEM;
    if ( (rc = p2m_init(d)) != 0 )
        goto fail;

    d->max_vcpus = 8;

    if ( (rc = domain_vgic_init(d)) != 0 )
        goto fail;

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

long arch_do_vcpu_op(int cmd, struct vcpu *v, XEN_GUEST_HANDLE(void) arg)
{
    return -ENOSYS;
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
