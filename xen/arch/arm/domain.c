/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <xen/config.h>
#include <xen/hypercall.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/wait.h>
#include <xen/errno.h>
#include <xen/bitops.h>
#include <xen/grant_table.h>

#include <asm/current.h>
#include <asm/event.h>
#include <asm/regs.h>
#include <asm/p2m.h>
#include <asm/irq.h>
#include <asm/cpufeature.h>

#include <asm/gic.h>
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
        {
            dsb();
            wfi();
        }
        local_irq_enable();

        do_tasklet();
        do_softirq();
    }
}

static void ctxt_switch_from(struct vcpu *p)
{
    /* CP 15 */
    p->arch.csselr = READ_SYSREG(CSSELR_EL1);

    /* Control Registers */
    p->arch.actlr = READ_SYSREG(ACTLR_EL1);
    p->arch.sctlr = READ_SYSREG(SCTLR_EL1);
    p->arch.cpacr = READ_SYSREG(CPACR_EL1);

    p->arch.contextidr = READ_SYSREG(CONTEXTIDR_EL1);
    p->arch.tpidr_el0 = READ_SYSREG(TPIDR_EL0);
    p->arch.tpidrro_el0 = READ_SYSREG(TPIDRRO_EL0);
    p->arch.tpidr_el1 = READ_SYSREG(TPIDR_EL1);

    /* Arch timer */
    virt_timer_save(p);

    if ( is_pv32_domain(p->domain) && cpu_has_thumbee )
    {
        p->arch.teecr = READ_SYSREG32(TEECR32_EL1);
        p->arch.teehbr = READ_SYSREG32(TEEHBR32_EL1);
    }

#ifdef CONFIG_ARM_32
    p->arch.joscr = READ_CP32(JOSCR);
    p->arch.jmcr = READ_CP32(JMCR);
#endif

    isb();

    /* MMU */
    p->arch.vbar = READ_SYSREG(VBAR_EL1);
    p->arch.ttbcr = READ_SYSREG(TCR_EL1);
    p->arch.ttbr0 = READ_SYSREG64(TTBR0_EL1);
    p->arch.ttbr1 = READ_SYSREG64(TTBR1_EL1);
    if ( is_pv32_domain(p->domain) )
        p->arch.dacr = READ_SYSREG(DACR32_EL2);
    p->arch.par = READ_SYSREG64(PAR_EL1);
#if defined(CONFIG_ARM_32)
    p->arch.mair0 = READ_CP32(MAIR0);
    p->arch.mair1 = READ_CP32(MAIR1);
#else
    p->arch.mair = READ_SYSREG64(MAIR_EL1);
#endif

    /* Fault Status */
#if defined(CONFIG_ARM_32)
    p->arch.dfar = READ_CP32(DFAR);
    p->arch.ifar = READ_CP32(IFAR);
    p->arch.dfsr = READ_CP32(DFSR);
#elif defined(CONFIG_ARM_64)
    p->arch.far = READ_SYSREG64(FAR_EL1);
    p->arch.esr = READ_SYSREG64(ESR_EL1);
#endif

    if ( is_pv32_domain(p->domain) )
        p->arch.ifsr  = READ_SYSREG(IFSR32_EL2);
    p->arch.afsr0 = READ_SYSREG(AFSR0_EL1);
    p->arch.afsr1 = READ_SYSREG(AFSR1_EL1);

    /* XXX MPU */

    /* XXX VFP */

    /* VGIC */
    gic_save_state(p);

    isb();
    context_saved(p);
}

static void ctxt_switch_to(struct vcpu *n)
{
    register_t hcr;

    hcr = READ_SYSREG(HCR_EL2);
    WRITE_SYSREG(hcr & ~HCR_VM, HCR_EL2);
    isb();

    p2m_load_VTTBR(n->domain);
    isb();

    WRITE_SYSREG32(n->domain->arch.vpidr, VPIDR_EL2);
    WRITE_SYSREG(n->domain->arch.vmpidr, VMPIDR_EL2);

    /* VGIC */
    gic_restore_state(n);

    /* XXX VFP */

    /* XXX MPU */

    /* Fault Status */
#if defined(CONFIG_ARM_32)
    WRITE_CP32(n->arch.dfar, DFAR);
    WRITE_CP32(n->arch.ifar, IFAR);
    WRITE_CP32(n->arch.dfsr, DFSR);
#elif defined(CONFIG_ARM_64)
    WRITE_SYSREG64(n->arch.far, FAR_EL1);
    WRITE_SYSREG64(n->arch.esr, ESR_EL1);
#endif

    if ( is_pv32_domain(n->domain) )
        WRITE_SYSREG(n->arch.ifsr, IFSR32_EL2);
    WRITE_SYSREG(n->arch.afsr0, AFSR0_EL1);
    WRITE_SYSREG(n->arch.afsr1, AFSR1_EL1);

    /* MMU */
    WRITE_SYSREG(n->arch.vbar, VBAR_EL1);
    WRITE_SYSREG(n->arch.ttbcr, TCR_EL1);
    WRITE_SYSREG64(n->arch.ttbr0, TTBR0_EL1);
    WRITE_SYSREG64(n->arch.ttbr1, TTBR1_EL1);
    if ( is_pv32_domain(n->domain) )
        WRITE_SYSREG(n->arch.dacr, DACR32_EL2);
    WRITE_SYSREG64(n->arch.par, PAR_EL1);
#if defined(CONFIG_ARM_32)
    WRITE_CP32(n->arch.mair0, MAIR0);
    WRITE_CP32(n->arch.mair1, MAIR1);
#elif defined(CONFIG_ARM_64)
    WRITE_SYSREG64(n->arch.mair, MAIR_EL1);
#endif
    isb();

    /* Control Registers */
    WRITE_SYSREG(n->arch.actlr, ACTLR_EL1);
    WRITE_SYSREG(n->arch.sctlr, SCTLR_EL1);
    WRITE_SYSREG(n->arch.cpacr, CPACR_EL1);

    WRITE_SYSREG(n->arch.contextidr, CONTEXTIDR_EL1);
    WRITE_SYSREG(n->arch.tpidr_el0, TPIDR_EL0);
    WRITE_SYSREG(n->arch.tpidrro_el0, TPIDRRO_EL0);
    WRITE_SYSREG(n->arch.tpidr_el1, TPIDR_EL1);

    if ( is_pv32_domain(n->domain) && cpu_has_thumbee )
    {
        WRITE_SYSREG32(n->arch.teecr, TEECR32_EL1);
        WRITE_SYSREG32(n->arch.teehbr, TEEHBR32_EL1);
    }

#ifdef CONFIG_ARM_32
    WRITE_CP32(n->arch.joscr, JOSCR);
    WRITE_CP32(n->arch.jmcr, JMCR);
#endif
    isb();

    /* CP 15 */
    WRITE_SYSREG(n->arch.csselr, CSSELR_EL1);

    isb();

    WRITE_SYSREG(hcr, HCR_EL2);
    isb();

    /* This is could trigger an hardware interrupt from the virtual
     * timer. The interrupt needs to be injected into the guest. */
    virt_timer_restore(n);
}

static void schedule_tail(struct vcpu *prev)
{
    ctxt_switch_from(prev);

    local_irq_enable();

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
    d->arch.grant_table_gpfn = xmalloc_array(xen_pfn_t, max_nr_grant_frames);
    return d;
}

void free_domain_struct(struct domain *d)
{
    xfree(d->arch.grant_table_gpfn);
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
    v->arch.saved_context.sp = (register_t)v->arch.cpu_info;
    v->arch.saved_context.pc = (register_t)continue_new_vcpu;

    /* Idle VCPUs don't need the rest of this setup */
    if ( is_idle_vcpu(v) )
        return rc;

    v->arch.sctlr = SCTLR_BASE;

    if ( (rc = vcpu_vgic_init(v)) != 0 )
        return rc;

    if ( (rc = vcpu_vtimer_init(v)) != 0 )
        return rc;

    return rc;
}

void vcpu_destroy(struct vcpu *v)
{
    vcpu_timer_destroy(v);
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

    /* Default the virtual ID to match the physical */
    d->arch.vpidr = boot_cpu_data.midr.bits;
    d->arch.vmpidr = boot_cpu_data.mpidr.bits;

    clear_page(d->shared_info);
    share_xen_page_with_guest(
        virt_to_page(d->shared_info), d, XENSHARE_writable);

    if ( (rc = p2m_alloc_table(d)) != 0 )
        goto fail;

    if ( (rc = gicv_setup(d)) != 0 )
        goto fail;

    if ( (rc = domain_vgic_init(d)) != 0 )
        goto fail;

    if ( (rc = vcpu_domain_init(d)) != 0 )
        goto fail;

    /* Domain 0 gets a real UART not an emulated one */
    if ( d->domain_id && (rc = domain_uart0_init(d)) != 0 )
        goto fail;

    return 0;

fail:
    d->is_dying = DOMDYING_dead;
    arch_domain_destroy(d);

    return rc;
}

void arch_domain_destroy(struct domain *d)
{
    p2m_teardown(d);
    domain_vgic_free(d);
    domain_uart0_free(d);
    free_xenheap_page(d->shared_info);
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
    struct vcpu_guest_core_regs *regs = &c.nat->user_regs;

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

    vcpu_regs_user_to_hyp(v, regs);

    v->arch.sctlr = ctxt->sctlr;
    v->arch.ttbr0 = ctxt->ttbr0;
    v->arch.ttbr1 = ctxt->ttbr1;
    v->arch.ttbcr = ctxt->ttbcr;

    v->is_initialised = 1;

    if ( ctxt->flags & VGCF_online )
        clear_bit(_VPF_down, &v->pause_flags);
    else
        set_bit(_VPF_down, &v->pause_flags);

    return 0;
}

int arch_vcpu_reset(struct vcpu *v)
{
    vcpu_end_shutdown_deferral(v);
    return 0;
}

static int relinquish_memory(struct domain *d, struct page_list_head *list)
{
    struct page_info *page, *tmp;
    int               ret = 0;

    /* Use a recursive lock, as we may enter 'free_domheap_page'. */
    spin_lock_recursive(&d->page_alloc_lock);

    page_list_for_each_safe( page, tmp, list )
    {
        /* Grab a reference to the page so it won't disappear from under us. */
        if ( unlikely(!get_page(page, d)) )
            /* Couldn't get a reference -- someone is freeing this page. */
            BUG();

        if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
            put_page(page);

        put_page(page);

        if ( hypercall_preempt_check() )
        {
            ret = -EAGAIN;
            goto out;
        }
    }

  out:
    spin_unlock_recursive(&d->page_alloc_lock);
    return ret;
}

int domain_relinquish_resources(struct domain *d)
{
    int ret = 0;

    ret = relinquish_memory(d, &d->xenpage_list);
    if ( ret )
        return ret;

    ret = relinquish_memory(d, &d->page_list);
    if ( ret )
        return ret;

    return ret;
}

void arch_dump_domain_info(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        gic_dump_info(v);
    }
}


long do_arm_vcpu_op(int cmd, int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( cmd )
    {
        case VCPUOP_register_vcpu_info:
            return do_vcpu_op(cmd, vcpuid, arg);
        default:
            return -EINVAL;
    }
}

long arch_do_vcpu_op(int cmd, struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
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
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
