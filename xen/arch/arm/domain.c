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
        reset_stack_and_jump(idle_loop);
    else
        /* check_wakeup_from_wait(); */
        reset_stack_and_jump(return_to_new_vcpu);
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

struct vcpu_guest_context *alloc_vcpu_guest_context(void)
{
    return xmalloc(struct vcpu_guest_context);

}

void free_vcpu_guest_context(struct vcpu_guest_context *vgc)
{
    xfree(vgc);
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

    if ( !is_idle_domain(d) )
    {
        rc = -ENOMEM;
        if ( (d->shared_info = alloc_xenheap_pages(0, 0)) == NULL )
            goto fail;

        clear_page(d->shared_info);
        share_xen_page_with_guest(
                virt_to_page(d->shared_info), d, XENSHARE_writable);

        if ( (rc = p2m_alloc_table(d)) != 0 )
            goto fail;
    }

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

static int is_guest_psr(uint32_t psr)
{
    switch (psr & PSR_MODE_MASK)
    {
    case PSR_MODE_USR:
    case PSR_MODE_FIQ:
    case PSR_MODE_IRQ:
    case PSR_MODE_SVC:
    case PSR_MODE_ABT:
    case PSR_MODE_UND:
    case PSR_MODE_SYS:
        return 1;
    case PSR_MODE_MON:
    case PSR_MODE_HYP:
    default:
        return 0;
    }
}

/*
 * Initialise VCPU state. The context can be supplied by either the
 * toolstack (XEN_DOMCTL_setvcpucontext) or the guest
 * (VCPUOP_initialise) and therefore must be properly validated.
 */
int arch_set_info_guest(
    struct vcpu *v, vcpu_guest_context_u c)
{
    struct cpu_user_regs *regs = &c.nat->user_regs;

    if ( !is_guest_psr(regs->cpsr) )
        return -EINVAL;

    if ( regs->spsr_svc && !is_guest_psr(regs->spsr_svc) )
        return -EINVAL;
    if ( regs->spsr_abt && !is_guest_psr(regs->spsr_abt) )
        return -EINVAL;
    if ( regs->spsr_und && !is_guest_psr(regs->spsr_und) )
        return -EINVAL;
    if ( regs->spsr_irq && !is_guest_psr(regs->spsr_irq) )
        return -EINVAL;
    if ( regs->spsr_fiq && !is_guest_psr(regs->spsr_fiq) )
        return -EINVAL;

    v->arch.cpu_info->guest_cpu_user_regs = *regs;

    /* XXX other state:
     * - SCTLR
     * - TTBR0/1
     * - TTBCR
     */

    clear_bit(_VPF_down, &v->pause_flags);

    return 0;
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

void vcpu_mark_events_pending(struct vcpu *v)
{
    int already_pending = test_and_set_bit(
        0, (unsigned long *)&vcpu_info(v, evtchn_upcall_pending));

    if ( already_pending )
        return;

    vgic_vcpu_inject_irq(v, VGIC_IRQ_EVTCHN_CALLBACK, 1);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
