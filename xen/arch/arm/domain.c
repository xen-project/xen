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
#include <xen/bitops.h>
#include <xen/errno.h>
#include <xen/grant_table.h>
#include <xen/hypercall.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/livepatch.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/wait.h>

#include <asm/alternative.h>
#include <asm/cpuerrata.h>
#include <asm/cpufeature.h>
#include <asm/current.h>
#include <asm/event.h>
#include <asm/gic.h>
#include <asm/guest_access.h>
#include <asm/guest_atomics.h>
#include <asm/irq.h>
#include <asm/p2m.h>
#include <asm/platform.h>
#include <asm/procinfo.h>
#include <asm/regs.h>
#include <asm/tee/tee.h>
#include <asm/vfp.h>
#include <asm/vgic.h>
#include <asm/vtimer.h>

#include "vuart.h"

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

static void do_idle(void)
{
    unsigned int cpu = smp_processor_id();

    sched_tick_suspend();
    /* sched_tick_suspend() can raise TIMER_SOFTIRQ. Process it now. */
    process_pending_softirqs();

    local_irq_disable();
    if ( cpu_is_haltable(cpu) )
    {
        dsb(sy);
        wfi();
    }
    local_irq_enable();

    sched_tick_resume();
}

void idle_loop(void)
{
    unsigned int cpu = smp_processor_id();

    for ( ; ; )
    {
        if ( cpu_is_offline(cpu) )
            stop_cpu();

        /* Are we here for running vcpu context tasklets, or for idling? */
        if ( unlikely(tasklet_work_to_do(cpu)) )
            do_tasklet();
        /*
         * Test softirqs twice --- first to see if should even try scrubbing
         * and then, after it is done, whether softirqs became pending
         * while we were scrubbing.
         */
        else if ( !softirq_pending(cpu) && !scrub_free_pages() &&
                  !softirq_pending(cpu) )
            do_idle();

        do_softirq();
        /*
         * We MUST be last (or before dsb, wfi). Otherwise after we get the
         * softirq we would execute dsb,wfi (and sleep) and not patch.
         */
        check_for_livepatch_work();
    }
}

static void ctxt_switch_from(struct vcpu *p)
{
    /* When the idle VCPU is running, Xen will always stay in hypervisor
     * mode. Therefore we don't need to save the context of an idle VCPU.
     */
    if ( is_idle_vcpu(p) )
        return;

    p2m_save_state(p);

    /* CP 15 */
    p->arch.csselr = READ_SYSREG(CSSELR_EL1);

    /* Control Registers */
    p->arch.cpacr = READ_SYSREG(CPACR_EL1);

    p->arch.contextidr = READ_SYSREG(CONTEXTIDR_EL1);
    p->arch.tpidr_el0 = READ_SYSREG(TPIDR_EL0);
    p->arch.tpidrro_el0 = READ_SYSREG(TPIDRRO_EL0);
    p->arch.tpidr_el1 = READ_SYSREG(TPIDR_EL1);

    /* Arch timer */
    p->arch.cntkctl = READ_SYSREG32(CNTKCTL_EL1);
    virt_timer_save(p);

    if ( is_32bit_domain(p->domain) && cpu_has_thumbee )
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
    if ( is_32bit_domain(p->domain) )
        p->arch.dacr = READ_SYSREG(DACR32_EL2);
    p->arch.par = READ_SYSREG64(PAR_EL1);
#if defined(CONFIG_ARM_32)
    p->arch.mair0 = READ_CP32(MAIR0);
    p->arch.mair1 = READ_CP32(MAIR1);
    p->arch.amair0 = READ_CP32(AMAIR0);
    p->arch.amair1 = READ_CP32(AMAIR1);
#else
    p->arch.mair = READ_SYSREG64(MAIR_EL1);
    p->arch.amair = READ_SYSREG64(AMAIR_EL1);
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

    if ( is_32bit_domain(p->domain) )
        p->arch.ifsr  = READ_SYSREG(IFSR32_EL2);
    p->arch.afsr0 = READ_SYSREG(AFSR0_EL1);
    p->arch.afsr1 = READ_SYSREG(AFSR1_EL1);

    /* XXX MPU */

    /* VFP */
    vfp_save_state(p);

    /* VGIC */
    gic_save_state(p);

    isb();
}

static void ctxt_switch_to(struct vcpu *n)
{
    uint32_t vpidr;

    /* When the idle VCPU is running, Xen will always stay in hypervisor
     * mode. Therefore we don't need to restore the context of an idle VCPU.
     */
    if ( is_idle_vcpu(n) )
        return;

    vpidr = READ_SYSREG32(MIDR_EL1);
    WRITE_SYSREG32(vpidr, VPIDR_EL2);
    WRITE_SYSREG(n->arch.vmpidr, VMPIDR_EL2);

    /* VGIC */
    gic_restore_state(n);

    /* VFP */
    vfp_restore_state(n);

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

    if ( is_32bit_domain(n->domain) )
        WRITE_SYSREG(n->arch.ifsr, IFSR32_EL2);
    WRITE_SYSREG(n->arch.afsr0, AFSR0_EL1);
    WRITE_SYSREG(n->arch.afsr1, AFSR1_EL1);

    /* MMU */
    WRITE_SYSREG(n->arch.vbar, VBAR_EL1);
    WRITE_SYSREG(n->arch.ttbcr, TCR_EL1);
    WRITE_SYSREG64(n->arch.ttbr0, TTBR0_EL1);
    WRITE_SYSREG64(n->arch.ttbr1, TTBR1_EL1);

    /*
     * Erratum #852523: DACR32_EL2 must be restored before one of the
     * following sysregs: SCTLR_EL1, TCR_EL1, TTBR0_EL1, TTBR1_EL1 or
     * CONTEXTIDR_EL1.
     */
    if ( is_32bit_domain(n->domain) )
        WRITE_SYSREG(n->arch.dacr, DACR32_EL2);
    WRITE_SYSREG64(n->arch.par, PAR_EL1);
#if defined(CONFIG_ARM_32)
    WRITE_CP32(n->arch.mair0, MAIR0);
    WRITE_CP32(n->arch.mair1, MAIR1);
    WRITE_CP32(n->arch.amair0, AMAIR0);
    WRITE_CP32(n->arch.amair1, AMAIR1);
#elif defined(CONFIG_ARM_64)
    WRITE_SYSREG64(n->arch.mair, MAIR_EL1);
    WRITE_SYSREG64(n->arch.amair, AMAIR_EL1);
#endif
    isb();

    /*
     * ARM64_WORKAROUND_AT_SPECULATE: The P2M should be restored after
     * the stage-1 MMU sysregs have been restored.
     */
    p2m_restore_state(n);

    /* Control Registers */
    WRITE_SYSREG(n->arch.cpacr, CPACR_EL1);

    /*
     * This write to sysreg CONTEXTIDR_EL1 ensures we don't hit erratum
     * #852523. I.e DACR32_EL2 is not correctly synchronized.
     */
    WRITE_SYSREG(n->arch.contextidr, CONTEXTIDR_EL1);
    WRITE_SYSREG(n->arch.tpidr_el0, TPIDR_EL0);
    WRITE_SYSREG(n->arch.tpidrro_el0, TPIDRRO_EL0);
    WRITE_SYSREG(n->arch.tpidr_el1, TPIDR_EL1);

    if ( is_32bit_domain(n->domain) && cpu_has_thumbee )
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

    /* This is could trigger an hardware interrupt from the virtual
     * timer. The interrupt needs to be injected into the guest. */
    WRITE_SYSREG32(n->arch.cntkctl, CNTKCTL_EL1);
    virt_timer_restore(n);
}

/* Update per-VCPU guest runstate shared memory area (if registered). */
static void update_runstate_area(struct vcpu *v)
{
    void __user *guest_handle = NULL;
    struct vcpu_runstate_info runstate;

    if ( guest_handle_is_null(runstate_guest(v)) )
        return;

    memcpy(&runstate, &v->runstate, sizeof(runstate));

    if ( VM_ASSIST(v->domain, runstate_update_flag) )
    {
        guest_handle = &v->runstate_guest.p->state_entry_time + 1;
        guest_handle--;
        runstate.state_entry_time |= XEN_RUNSTATE_UPDATE;
        __raw_copy_to_guest(guest_handle,
                            (void *)(&runstate.state_entry_time + 1) - 1, 1);
        smp_wmb();
    }

    __copy_to_guest(runstate_guest(v), &runstate, 1);

    if ( guest_handle )
    {
        runstate.state_entry_time &= ~XEN_RUNSTATE_UPDATE;
        smp_wmb();
        __raw_copy_to_guest(guest_handle,
                            (void *)(&runstate.state_entry_time + 1) - 1, 1);
    }
}

static void schedule_tail(struct vcpu *prev)
{
    ASSERT(prev != current);

    ctxt_switch_from(prev);

    ctxt_switch_to(current);

    local_irq_enable();

    sched_context_switched(prev, current);

    update_runstate_area(current);

    /* Ensure that the vcpu has an up-to-date time base. */
    update_vcpu_system_time(current);
}

static void continue_new_vcpu(struct vcpu *prev)
{
    current->arch.actlr = READ_SYSREG32(ACTLR_EL1);
    processor_vcpu_initialise(current);

    schedule_tail(prev);

    if ( is_idle_vcpu(current) )
        reset_stack_and_jump(idle_loop);
    else if ( is_32bit_domain(current->domain) )
        /* check_wakeup_from_wait(); */
        reset_stack_and_jump(return_to_new_vcpu32);
    else
        /* check_wakeup_from_wait(); */
        reset_stack_and_jump(return_to_new_vcpu64);
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    ASSERT(local_irq_is_enabled());
    ASSERT(prev != next);
    ASSERT(!vcpu_cpu_dirty(next));

    update_runstate_area(prev);

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

#define NEXT_ARG(fmt, args)                                                 \
({                                                                          \
    unsigned long __arg;                                                    \
    switch ( *(fmt)++ )                                                     \
    {                                                                       \
    case 'i': __arg = (unsigned long)va_arg(args, unsigned int);  break;    \
    case 'l': __arg = (unsigned long)va_arg(args, unsigned long); break;    \
    case 'h': __arg = (unsigned long)va_arg(args, void *);        break;    \
    default:  goto bad_fmt;                                                 \
    }                                                                       \
    __arg;                                                                  \
})

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
    struct mc_state *mcs = &current->mc_state;
    struct cpu_user_regs *regs;
    const char *p = format;
    unsigned long arg, rc;
    unsigned int i;
    va_list args;

    current->hcall_preempted = true;

    va_start(args, format);

    if ( mcs->flags & MCSF_in_multicall )
    {
        for ( i = 0; *p != '\0'; i++ )
            mcs->call.args[i] = NEXT_ARG(p, args);

        /* Return value gets written back to mcs->call.result */
        rc = mcs->call.result;
    }
    else
    {
        regs = guest_cpu_user_regs();

#ifdef CONFIG_ARM_64
        if ( !is_32bit_domain(current->domain) )
        {
            regs->x16 = op;

            for ( i = 0; *p != '\0'; i++ )
            {
                arg = NEXT_ARG(p, args);

                switch ( i )
                {
                case 0: regs->x0 = arg; break;
                case 1: regs->x1 = arg; break;
                case 2: regs->x2 = arg; break;
                case 3: regs->x3 = arg; break;
                case 4: regs->x4 = arg; break;
                case 5: regs->x5 = arg; break;
                }
            }

            /* Return value gets written back to x0 */
            rc = regs->x0;
        }
        else
#endif
        {
            regs->r12 = op;

            for ( i = 0; *p != '\0'; i++ )
            {
                arg = NEXT_ARG(p, args);

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
    }

    va_end(args);

    return rc;

 bad_fmt:
    va_end(args);
    gprintk(XENLOG_ERR, "Bad hypercall continuation format '%c'\n", *p);
    ASSERT_UNREACHABLE();
    domain_crash(current->domain);
    return 0;
}

#undef NEXT_ARG

void startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));
    /* TODO
       cpumask_set_cpu(v->processor, v->domain->dirty_cpumask);
       v->dirty_cpu = v->processor;
    */

    reset_stack_and_jump(idle_loop);
}

struct domain *alloc_domain_struct(void)
{
    struct domain *d;
    BUILD_BUG_ON(sizeof(*d) > PAGE_SIZE);
    d = alloc_xenheap_pages(0, 0);
    if ( d == NULL )
        return NULL;

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

/*
 * The new VGIC has a bigger per-IRQ structure, so we need more than one
 * page on ARM64. Cowardly increase the limit in this case.
 */
#if defined(CONFIG_NEW_VGIC) && defined(CONFIG_ARM_64)
#define MAX_PAGES_PER_VCPU  2
#else
#define MAX_PAGES_PER_VCPU  1
#endif

struct vcpu *alloc_vcpu_struct(const struct domain *d)
{
    struct vcpu *v;

    BUILD_BUG_ON(sizeof(*v) > MAX_PAGES_PER_VCPU * PAGE_SIZE);
    v = alloc_xenheap_pages(get_order_from_bytes(sizeof(*v)), 0);
    if ( v != NULL )
    {
        unsigned int i;

        for ( i = 0; i < DIV_ROUND_UP(sizeof(*v), PAGE_SIZE); i++ )
            clear_page((void *)v + i * PAGE_SIZE);
    }

    return v;
}

void free_vcpu_struct(struct vcpu *v)
{
    free_xenheap_pages(v, get_order_from_bytes(sizeof(*v)));
}

int arch_vcpu_create(struct vcpu *v)
{
    int rc = 0;

    BUILD_BUG_ON( sizeof(struct cpu_info) > STACK_SIZE );

    v->arch.stack = alloc_xenheap_pages(STACK_ORDER, MEMF_node(vcpu_to_node(v)));
    if ( v->arch.stack == NULL )
        return -ENOMEM;

    v->arch.cpu_info = (struct cpu_info *)(v->arch.stack
                                           + STACK_SIZE
                                           - sizeof(struct cpu_info));
    memset(v->arch.cpu_info, 0, sizeof(*v->arch.cpu_info));

    v->arch.saved_context.sp = (register_t)v->arch.cpu_info;
    v->arch.saved_context.pc = (register_t)continue_new_vcpu;

    /* Idle VCPUs don't need the rest of this setup */
    if ( is_idle_vcpu(v) )
        return rc;

    v->arch.sctlr = SCTLR_GUEST_INIT;

    v->arch.vmpidr = MPIDR_SMP | vcpuid_to_vaffinity(v->vcpu_id);

    v->arch.hcr_el2 = get_default_hcr_flags();

    if ( (rc = vcpu_vgic_init(v)) != 0 )
        goto fail;

    if ( (rc = vcpu_vtimer_init(v)) != 0 )
        goto fail;

    /*
     * The workaround 2 (i.e SSBD mitigation) is enabled by default if
     * supported.
     */
    if ( get_ssbd_state() == ARM_SSBD_RUNTIME )
        v->arch.cpu_info->flags |= CPUINFO_WORKAROUND_2_FLAG;

    return rc;

fail:
    arch_vcpu_destroy(v);
    return rc;
}

void arch_vcpu_destroy(struct vcpu *v)
{
    vcpu_timer_destroy(v);
    vcpu_vgic_free(v);
    free_xenheap_pages(v->arch.stack, STACK_ORDER);
}

void vcpu_switch_to_aarch64_mode(struct vcpu *v)
{
    v->arch.hcr_el2 |= HCR_RW;
}

int arch_sanitise_domain_config(struct xen_domctl_createdomain *config)
{
    unsigned int max_vcpus;

    /* HVM and HAP must be set. IOMMU may or may not be */
    if ( (config->flags & ~XEN_DOMCTL_CDF_iommu) !=
         (XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap) )
    {
        dprintk(XENLOG_INFO, "Unsupported configuration %#x\n",
                config->flags);
        return -EINVAL;
    }

    /* The P2M table must always be shared between the CPU and the IOMMU */
    if ( config->iommu_opts & XEN_DOMCTL_IOMMU_no_sharept )
    {
        dprintk(XENLOG_INFO,
                "Unsupported iommu option: XEN_DOMCTL_IOMMU_no_sharept\n");
        return -EINVAL;
    }

    /* Fill in the native GIC version, passed back to the toolstack. */
    if ( config->arch.gic_version == XEN_DOMCTL_CONFIG_GIC_NATIVE )
    {
        switch ( gic_hw_version() )
        {
        case GIC_V2:
            config->arch.gic_version = XEN_DOMCTL_CONFIG_GIC_V2;
            break;

        case GIC_V3:
            config->arch.gic_version = XEN_DOMCTL_CONFIG_GIC_V3;
            break;

        default:
            ASSERT_UNREACHABLE();
            return -EINVAL;
        }
    }

    /* max_vcpus depends on the GIC version, and Xen's compiled limit. */
    max_vcpus = min(vgic_max_vcpus(config->arch.gic_version), MAX_VIRT_CPUS);

    if ( max_vcpus == 0 )
    {
        dprintk(XENLOG_INFO, "Unsupported GIC version\n");
        return -EINVAL;
    }

    if ( config->max_vcpus > max_vcpus )
    {
        dprintk(XENLOG_INFO, "Requested vCPUs (%u) exceeds max (%u)\n",
                config->max_vcpus, max_vcpus);
        return -EINVAL;
    }

    if ( config->arch.tee_type != XEN_DOMCTL_CONFIG_TEE_NONE &&
         config->arch.tee_type != tee_get_type() )
    {
        dprintk(XENLOG_INFO, "Unsupported TEE type\n");
        return -EINVAL;
    }

    return 0;
}

int arch_domain_create(struct domain *d,
                       struct xen_domctl_createdomain *config)
{
    int rc, count = 0;

    BUILD_BUG_ON(GUEST_MAX_VCPUS < MAX_VIRT_CPUS);
    d->arch.relmem = RELMEM_not_started;

    /* Idle domains do not need this setup */
    if ( is_idle_domain(d) )
        return 0;

    ASSERT(config != NULL);

    /* p2m_init relies on some value initialized by the IOMMU subsystem */
    if ( (rc = iommu_domain_init(d, config->iommu_opts)) != 0 )
        goto fail;

    if ( (rc = p2m_init(d)) != 0 )
        goto fail;

    rc = -ENOMEM;
    if ( (d->shared_info = alloc_xenheap_pages(0, 0)) == NULL )
        goto fail;

    clear_page(d->shared_info);
    share_xen_page_with_guest(virt_to_page(d->shared_info), d, SHARE_rw);

    switch ( config->arch.gic_version )
    {
    case XEN_DOMCTL_CONFIG_GIC_V2:
        d->arch.vgic.version = GIC_V2;
        break;

    case XEN_DOMCTL_CONFIG_GIC_V3:
        d->arch.vgic.version = GIC_V3;
        break;

    default:
        BUG();
    }

    if ( (rc = domain_vgic_register(d, &count)) != 0 )
        goto fail;

    if ( (rc = domain_io_init(d, count + MAX_IO_HANDLER)) != 0 )
        goto fail;

    if ( (rc = domain_vgic_init(d, config->arch.nr_spis)) != 0 )
        goto fail;

    if ( (rc = domain_vtimer_init(d, &config->arch)) != 0 )
        goto fail;

    if ( (rc = tee_domain_init(d, config->arch.tee_type)) != 0 )
        goto fail;

    update_domain_wallclock_time(d);

    /*
     * The hardware domain will get a PPI later in
     * arch/arm/domain_build.c  depending on the
     * interrupt map of the hardware.
     */
    if ( !is_hardware_domain(d) )
    {
        d->arch.evtchn_irq = GUEST_EVTCHN_PPI;
        /* At this stage vgic_reserve_virq should never fail */
        if ( !vgic_reserve_virq(d, GUEST_EVTCHN_PPI) )
            BUG();
    }

    /*
     * Virtual UART is only used by linux early printk and decompress code.
     * Only use it for the hardware domain because the linux kernel may not
     * support multi-platform.
     */
    if ( is_hardware_domain(d) && (rc = domain_vuart_init(d)) )
        goto fail;

    return 0;

fail:
    d->is_dying = DOMDYING_dead;
    arch_domain_destroy(d);

    return rc;
}

void arch_domain_destroy(struct domain *d)
{
    /* IOMMU page table is shared with P2M, always call
     * iommu_domain_destroy() before p2m_teardown().
     */
    iommu_domain_destroy(d);
    p2m_teardown(d);
    domain_vgic_free(d);
    domain_vuart_free(d);
    free_xenheap_page(d->shared_info);
#ifdef CONFIG_ACPI
    free_xenheap_pages(d->arch.efi_acpi_table,
                       get_order_from_bytes(d->arch.efi_acpi_len));
#endif
    domain_io_free(d);
}

void arch_domain_shutdown(struct domain *d)
{
}

void arch_domain_pause(struct domain *d)
{
}

void arch_domain_unpause(struct domain *d)
{
}

int arch_domain_soft_reset(struct domain *d)
{
    return -ENOSYS;
}

void arch_domain_creation_finished(struct domain *d)
{
    /*
     * To avoid flushing the whole guest RAM on the first Set/Way, we
     * invalidate the P2M to track what has been accessed.
     *
     * This is only turned when IOMMU is not used or the page-table are
     * not shared because bit[0] (e.g valid bit) unset will result
     * IOMMU fault that could be not fixed-up.
     */
    if ( !iommu_use_hap_pt(d) )
        p2m_invalidate_root(p2m_get_hostp2m(d));
}

static int is_guest_pv32_psr(uint32_t psr)
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


#ifdef CONFIG_ARM_64
static int is_guest_pv64_psr(uint32_t psr)
{
    if ( psr & PSR_MODE_BIT )
        return 0;

    switch (psr & PSR_MODE_MASK)
    {
    case PSR_MODE_EL1h:
    case PSR_MODE_EL1t:
    case PSR_MODE_EL0t:
        return 1;
    case PSR_MODE_EL3h:
    case PSR_MODE_EL3t:
    case PSR_MODE_EL2h:
    case PSR_MODE_EL2t:
    default:
        return 0;
    }
}
#endif

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

    if ( is_32bit_domain(v->domain) )
    {
        if ( !is_guest_pv32_psr(regs->cpsr) )
            return -EINVAL;

        if ( regs->spsr_svc && !is_guest_pv32_psr(regs->spsr_svc) )
            return -EINVAL;
        if ( regs->spsr_abt && !is_guest_pv32_psr(regs->spsr_abt) )
            return -EINVAL;
        if ( regs->spsr_und && !is_guest_pv32_psr(regs->spsr_und) )
            return -EINVAL;
        if ( regs->spsr_irq && !is_guest_pv32_psr(regs->spsr_irq) )
            return -EINVAL;
        if ( regs->spsr_fiq && !is_guest_pv32_psr(regs->spsr_fiq) )
            return -EINVAL;
    }
#ifdef CONFIG_ARM_64
    else
    {
        if ( !is_guest_pv64_psr(regs->cpsr) )
            return -EINVAL;

        if ( regs->spsr_el1 && !is_guest_pv64_psr(regs->spsr_el1) )
            return -EINVAL;
    }
#endif

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

int arch_initialise_vcpu(struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    return default_initialise_vcpu(v, arg);
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
            /*
             * Couldn't get a reference -- someone is freeing this page and
             * has already committed to doing so, so no more to do here.
             *
             * Note that the page must be left on the list, a list_del
             * here will clash with the list_del done by the other
             * party in the race and corrupt the list head.
             */
            continue;

        put_page_alloc_ref(page);
        put_page(page);

        if ( hypercall_preempt_check() )
        {
            ret = -ERESTART;
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

    switch ( d->arch.relmem )
    {
    case RELMEM_not_started:
        ret = iommu_release_dt_devices(d);
        if ( ret )
            return ret;

        /*
         * Release the resources allocated for vpl011 which were
         * allocated via a DOMCTL call XEN_DOMCTL_vuart_op.
         */
        domain_vpl011_deinit(d);

        d->arch.relmem = RELMEM_tee;
        /* Fallthrough */

    case RELMEM_tee:
        ret = tee_relinquish_resources(d);
        if (ret )
            return ret;

        d->arch.relmem = RELMEM_xen;
        /* Fallthrough */

    case RELMEM_xen:
        ret = relinquish_memory(d, &d->xenpage_list);
        if ( ret )
            return ret;

        d->arch.relmem = RELMEM_page;
        /* Fallthrough */

    case RELMEM_page:
        ret = relinquish_memory(d, &d->page_list);
        if ( ret )
            return ret;

        d->arch.relmem = RELMEM_mapping;
        /* Fallthrough */

    case RELMEM_mapping:
        ret = relinquish_p2m_mapping(d);
        if ( ret )
            return ret;

        d->arch.relmem = RELMEM_done;
        /* Fallthrough */

    case RELMEM_done:
        break;

    default:
        BUG();
    }

    return 0;
}

void arch_dump_domain_info(struct domain *d)
{
    p2m_dump_info(d);
}


long do_arm_vcpu_op(int cmd, unsigned int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( cmd )
    {
        case VCPUOP_register_vcpu_info:
        case VCPUOP_register_runstate_memory_area:
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
    gic_dump_info(v);
    gic_dump_vgic_info(v);
}

void vcpu_mark_events_pending(struct vcpu *v)
{
    bool already_pending = guest_test_and_set_bit(v->domain,
        0, (unsigned long *)&vcpu_info(v, evtchn_upcall_pending));

    if ( already_pending )
        return;

    vgic_inject_irq(v->domain, v, v->domain->arch.evtchn_irq, true);
}

void vcpu_update_evtchn_irq(struct vcpu *v)
{
    bool pending = vcpu_info(v, evtchn_upcall_pending);

    vgic_inject_irq(v->domain, v, v->domain->arch.evtchn_irq, pending);
}

/* The ARM spec declares that even if local irqs are masked in
 * the CPSR register, an irq should wake up a cpu from WFI anyway.
 * For this reason we need to check for irqs that need delivery,
 * ignoring the CPSR register, *after* calling SCHEDOP_block to
 * avoid races with vgic_inject_irq.
 */
void vcpu_block_unless_event_pending(struct vcpu *v)
{
    vcpu_block();
    if ( local_events_need_delivery_nomask() )
        vcpu_unblock(current);
}

void vcpu_kick(struct vcpu *vcpu)
{
    bool running = vcpu->is_running;

    vcpu_unblock(vcpu);
    if ( running && vcpu != current )
    {
        perfc_incr(vcpu_kick);
        smp_send_event_check_mask(cpumask_of(vcpu->processor));
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
