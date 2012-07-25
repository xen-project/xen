#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/wait.h>
#include <xen/errno.h>
#include <xen/bitops.h>

#include <asm/current.h>
#include <asm/regs.h>
#include <asm/p2m.h>
#include <asm/irq.h>

#include "gic.h"
#include "vtimer.h"
#include "vpl011.h"

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
    /* CP 15 */
    p->arch.csselr = READ_CP32(CSSELR);

    /* Control Registers */
    p->arch.actlr = READ_CP32(ACTLR);
    p->arch.sctlr = READ_CP32(SCTLR);
    p->arch.cpacr = READ_CP32(CPACR);

    p->arch.contextidr = READ_CP32(CONTEXTIDR);
    p->arch.tpidrurw = READ_CP32(TPIDRURW);
    p->arch.tpidruro = READ_CP32(TPIDRURO);
    p->arch.tpidrprw = READ_CP32(TPIDRPRW);

    /* Arch timer */
    p->arch.cntvoff = READ_CP64(CNTVOFF);
    p->arch.cntv_cval = READ_CP64(CNTV_CVAL);
    p->arch.cntv_ctl = READ_CP32(CNTV_CTL);

    /* XXX only save these if ThumbEE e.g. ID_PFR0.THUMB_EE_SUPPORT */
    p->arch.teecr = READ_CP32(TEECR);
    p->arch.teehbr = READ_CP32(TEEHBR);

    p->arch.joscr = READ_CP32(JOSCR);
    p->arch.jmcr = READ_CP32(JMCR);

    isb();

    /* MMU */
    p->arch.vbar = READ_CP32(VBAR);
    p->arch.ttbcr = READ_CP32(TTBCR);
    /* XXX save 64 bit TTBR if guest is LPAE */
    p->arch.ttbr0 = READ_CP32(TTBR0);
    p->arch.ttbr1 = READ_CP32(TTBR1);

    p->arch.dacr = READ_CP32(DACR);
    p->arch.par = READ_CP64(PAR);
    p->arch.mair0 = READ_CP32(MAIR0);
    p->arch.mair1 = READ_CP32(MAIR1);

    /* Fault Status */
    p->arch.dfar = READ_CP32(DFAR);
    p->arch.ifar = READ_CP32(IFAR);
    p->arch.dfsr = READ_CP32(DFSR);
    p->arch.ifsr = READ_CP32(IFSR);
    p->arch.adfsr = READ_CP32(ADFSR);
    p->arch.aifsr = READ_CP32(AIFSR);

    /* XXX MPU */

    /* XXX VFP */

    /* XXX VGIC */
    gic_save_state(p);

    isb();
    context_saved(p);
}

static void ctxt_switch_to(struct vcpu *n)
{
    uint32_t hcr;

    hcr = READ_CP32(HCR);
    WRITE_CP32(hcr & ~HCR_VM, HCR);
    isb();

    p2m_load_VTTBR(n->domain);
    isb();

    /* XXX VGIC */
    gic_restore_state(n);

    /* XXX VFP */

    /* XXX MPU */

    /* Fault Status */
    WRITE_CP32(n->arch.dfar, DFAR);
    WRITE_CP32(n->arch.ifar, IFAR);
    WRITE_CP32(n->arch.dfsr, DFSR);
    WRITE_CP32(n->arch.ifsr, IFSR);
    WRITE_CP32(n->arch.adfsr, ADFSR);
    WRITE_CP32(n->arch.aifsr, AIFSR);

    /* MMU */
    WRITE_CP32(n->arch.vbar, VBAR);
    WRITE_CP32(n->arch.ttbcr, TTBCR);
    /* XXX restore 64 bit TTBR if guest is LPAE */
    WRITE_CP32(n->arch.ttbr0, TTBR0);
    WRITE_CP32(n->arch.ttbr1, TTBR1);

    WRITE_CP32(n->arch.dacr, DACR);
    WRITE_CP64(n->arch.par, PAR);
    WRITE_CP32(n->arch.mair0, MAIR0);
    WRITE_CP32(n->arch.mair1, MAIR1);
    isb();

    /* Arch timer */
    WRITE_CP64(n->arch.cntvoff, CNTVOFF);
    WRITE_CP64(n->arch.cntv_cval, CNTV_CVAL);
    WRITE_CP32(n->arch.cntv_ctl, CNTV_CTL);

    /* Control Registers */
    WRITE_CP32(n->arch.actlr, ACTLR);
    WRITE_CP32(n->arch.sctlr, SCTLR);
    WRITE_CP32(n->arch.cpacr, CPACR);

    WRITE_CP32(n->arch.contextidr, CONTEXTIDR);
    WRITE_CP32(n->arch.tpidrurw, TPIDRURW);
    WRITE_CP32(n->arch.tpidruro, TPIDRURO);
    WRITE_CP32(n->arch.tpidrprw, TPIDRPRW);

    /* XXX only restore these if ThumbEE e.g. ID_PFR0.THUMB_EE_SUPPORT */
    WRITE_CP32(n->arch.teecr, TEECR);
    WRITE_CP32(n->arch.teehbr, TEEHBR);

    WRITE_CP32(n->arch.joscr, JOSCR);
    WRITE_CP32(n->arch.jmcr, JMCR);

    isb();

    /* CP 15 */
    WRITE_CP32(n->arch.csselr, CSSELR);

    isb();

    WRITE_CP32(hcr, HCR);
    isb();
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

void sync_vcpu_execstate(struct vcpu *v)
{
    /* Nothing to do -- no lazy switching */
}

#define next_arg(fmt, args) ({                                              \
    unsigned long __arg;                                                    \
    switch ( *(fmt)++ )                                                     \
    {                                                                       \
    case 'i': __arg = (unsigned long)va_arg(args, unsigned int);  break;    \
    case 'l': __arg = (unsigned long)va_arg(args, unsigned long); break;    \
    case 'h': __arg = (unsigned long)va_arg(args, void *);        break;    \
    default:  __arg = 0; BUG();                                             \
    }                                                                       \
    __arg;                                                                  \
})

void hypercall_cancel_continuation(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct mc_state *mcs = &current->mc_state;

    if ( test_bit(_MCSF_in_multicall, &mcs->flags) )
    {
        __clear_bit(_MCSF_call_preempted, &mcs->flags);
    }
    else
    {
        regs->pc += 4; /* undo re-execute 'hvc #XEN_HYPERCALL_TAG' */
    }
}

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
    struct mc_state *mcs = &current->mc_state;
    struct cpu_user_regs *regs;
    const char *p = format;
    unsigned long arg, rc;
    unsigned int i;
    va_list args;

    /* All hypercalls take at least one argument */
    BUG_ON( !p || *p == '\0' );

    va_start(args, format);

    if ( test_bit(_MCSF_in_multicall, &mcs->flags) )
    {
        BUG(); /* XXX multicalls not implemented yet. */

        __set_bit(_MCSF_call_preempted, &mcs->flags);

        for ( i = 0; *p != '\0'; i++ )
            mcs->call.args[i] = next_arg(p, args);

        /* Return value gets written back to mcs->call.result */
        rc = mcs->call.result;
    }
    else
    {
        regs      = guest_cpu_user_regs();
        regs->r12 = op;

        /* Ensure the hypercall trap instruction is re-executed. */
        regs->pc -= 4;  /* re-execute 'hvc #XEN_HYPERCALL_TAG' */

        for ( i = 0; *p != '\0'; i++ )
        {
            arg = next_arg(p, args);

            switch ( i )
            {
            case 0: regs->r0 = arg; break;
            case 1: regs->r1 = arg; break;
            case 2: regs->r2 = arg; break;
            case 3: regs->r3 = arg; break;
            case 4: regs->r4 = arg; break;
            case 5: regs->r5 = arg; break;
            }
        }

        /* Return value gets written back to r0 */
        rc = regs->r0;
    }

    va_end(args);

    return rc;
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

    /* Idle domains do not need this setup */
    if ( is_idle_domain(d) )
        return 0;

    rc = -ENOMEM;
    if ( (rc = p2m_init(d)) != 0 )
        goto fail;

    if ( (d->shared_info = alloc_xenheap_pages(0, 0)) == NULL )
        goto fail;

    clear_page(d->shared_info);
    share_xen_page_with_guest(
        virt_to_page(d->shared_info), d, XENSHARE_writable);

    if ( (rc = p2m_alloc_table(d)) != 0 )
        goto fail;

    if ( (rc = gicv_setup(d)) != 0 )
        goto fail;

    if ( (rc = domain_vgic_init(d)) != 0 )
        goto fail;

    /* Domain 0 gets a real UART not an emulated one */
    if ( d->domain_id && (rc = domain_uart0_init(d)) != 0 )
        goto fail;

    return 0;

fail:
    d->is_dying = DOMDYING_dead;
    free_xenheap_page(d->shared_info);

    p2m_teardown(d);

    domain_vgic_free(d);
    domain_uart0_free(d);

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
    struct vcpu_guest_context *ctxt = c.nat;
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

    v->arch.sctlr = ctxt->sctlr;
    v->arch.ttbr0 = ctxt->ttbr0;
    v->arch.ttbr1 = ctxt->ttbr1;
    v->arch.ttbcr = ctxt->ttbcr;

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
