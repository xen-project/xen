/******************************************************************************
 * arch/x86/domain.c
 *
 * x86-specific domain handling (e.g., register setup and context switching).
 */

/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <xen/grant_table.h>
#include <xen/iocap.h>
#include <xen/kernel.h>
#include <xen/hypercall.h>
#include <xen/multicall.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/percpu.h>
#include <xen/compat.h>
#include <xen/acpi.h>
#include <xen/pci.h>
#include <xen/paging.h>
#include <xen/cpu.h>
#include <xen/wait.h>
#include <xen/guest_access.h>
#include <xen/livepatch.h>
#include <public/sysctl.h>
#include <public/hvm/hvm_vcpu.h>
#include <asm/altp2m.h>
#include <asm/regs.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/cpuidle.h>
#include <asm/mpspec.h>
#include <asm/ldt.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/viridian.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/spec_ctrl.h>
#include <asm/traps.h>
#include <asm/nmi.h>
#include <asm/mce.h>
#include <asm/amd.h>
#include <xen/numa.h>
#include <xen/iommu.h>
#include <compat/vcpu.h>
#include <asm/psr.h>
#include <asm/pv/domain.h>
#include <asm/pv/mm.h>
#include <asm/spec_ctrl.h>

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

static void default_idle(void);
void (*pm_idle) (void) __read_mostly = default_idle;
void (*dead_idle) (void) __read_mostly = default_dead_idle;

static void default_idle(void)
{
    struct cpu_info *info = get_cpu_info();

    local_irq_disable();
    if ( cpu_is_haltable(smp_processor_id()) )
    {
        spec_ctrl_enter_idle(info);
        safe_halt();
        spec_ctrl_exit_idle(info);
    }
    else
        local_irq_enable();
}

void default_dead_idle(void)
{
    /*
     * When going into S3, without flushing caches modified data may be
     * held by the CPUs spinning here indefinitely, and get discarded by
     * a subsequent INIT.
     */
    spec_ctrl_enter_idle(get_cpu_info());
    wbinvd();
    halt();
    spec_ctrl_exit_idle(get_cpu_info());
}

void play_dead(void)
{
    unsigned int cpu = smp_processor_id();

    local_irq_disable();

    /* Change the NMI handler to a nop (see comment below). */
    _set_gate_lower(&idt_tables[cpu][TRAP_nmi], SYS_DESC_irq_gate, 0,
                    &trap_nop);

    /*
     * NOTE: After cpu_exit_clear, per-cpu variables may no longer accessible,
     * as they may be freed at any time if offline CPUs don't get parked. In
     * this case, heap corruption or #PF can occur (when heap debugging is
     * enabled). For example, even printk() can involve tasklet scheduling,
     * which touches per-cpu vars.
     * 
     * Consider very carefully when adding code to *dead_idle. Most hypervisor
     * subsystems are unsafe to call.
     */
    cpu_exit_clear(cpu);

    for ( ; ; )
        dead_idle();
}

static void idle_loop(void)
{
    unsigned int cpu = smp_processor_id();

    for ( ; ; )
    {
        if ( cpu_is_offline(cpu) )
            play_dead();

        /* Are we here for running vcpu context tasklets, or for idling? */
        if ( unlikely(tasklet_work_to_do(cpu)) )
            do_tasklet();
        /*
         * Test softirqs twice --- first to see if should even try scrubbing
         * and then, after it is done, whether softirqs became pending
         * while we were scrubbing.
         */
        else if ( !softirq_pending(cpu) && !scrub_free_pages()  &&
                    !softirq_pending(cpu) )
            pm_idle();
        do_softirq();
        /*
         * We MUST be last (or before pm_idle). Otherwise after we get the
         * softirq we would execute pm_idle (and sleep) and not patch.
         */
        check_for_livepatch_work();
    }
}

/*
 * Idle loop for siblings in active schedule units.
 * We don't do any standard idle work like tasklets or livepatching.
 */
static void guest_idle_loop(void)
{
    unsigned int cpu = smp_processor_id();

    for ( ; ; )
    {
        ASSERT(!cpu_is_offline(cpu));

        if ( !softirq_pending(cpu) && !scrub_free_pages() &&
             !softirq_pending(cpu))
            sched_guest_idle(pm_idle, cpu);
        do_softirq();
    }
}

void startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));
    cpumask_set_cpu(v->processor, v->domain->dirty_cpumask);
    v->dirty_cpu = v->processor;

    reset_stack_and_jump(idle_loop);
}

static void noreturn continue_idle_domain(struct vcpu *v)
{
    /* Idle vcpus might be attached to non-idle units! */
    if ( !is_idle_domain(v->sched_unit->domain) )
        reset_stack_and_jump_nolp(guest_idle_loop);

    reset_stack_and_jump(idle_loop);
}

void init_hypercall_page(struct domain *d, void *ptr)
{
    memset(ptr, 0xcc, PAGE_SIZE);

    if ( is_hvm_domain(d) )
        hvm_init_hypercall_page(d, ptr);
    else if ( is_pv_64bit_domain(d) )
        pv_ring3_init_hypercall_page(ptr);
    else if ( is_pv_32bit_domain(d) )
        pv_ring1_init_hypercall_page(ptr);
    else
        ASSERT_UNREACHABLE();
}

void dump_pageframe_info(struct domain *d)
{
    struct page_info *page;

    printk("Memory pages belonging to domain %u:\n", d->domain_id);

    if ( d->tot_pages >= 10 && d->is_dying < DOMDYING_dead )
    {
        printk("    DomPage list too long to display\n");
    }
    else
    {
        unsigned long total[MASK_EXTR(PGT_type_mask, PGT_type_mask) + 1] = {};

        spin_lock(&d->page_alloc_lock);
        page_list_for_each ( page, &d->page_list )
        {
            unsigned int index = MASK_EXTR(page->u.inuse.type_info,
                                           PGT_type_mask);

            if ( ++total[index] > 16 )
            {
                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_none:
                case PGT_writable_page:
                    continue;
                }
            }
            printk("    DomPage %p: caf=%08lx, taf=%" PRtype_info "\n",
                   _p(mfn_x(page_to_mfn(page))),
                   page->count_info, page->u.inuse.type_info);
        }
        spin_unlock(&d->page_alloc_lock);
    }

    if ( is_hvm_domain(d) )
        p2m_pod_dump_data(d);

    spin_lock(&d->page_alloc_lock);
    page_list_for_each ( page, &d->xenpage_list )
    {
        printk("    XenPage %p: caf=%08lx, taf=%" PRtype_info "\n",
               _p(mfn_x(page_to_mfn(page))),
               page->count_info, page->u.inuse.type_info);
    }
    spin_unlock(&d->page_alloc_lock);
}

void update_guest_memory_policy(struct vcpu *v,
                                struct guest_memory_policy *policy)
{
    bool old_guest_mode = nestedhvm_is_n2(v);
    bool new_guest_mode = policy->nested_guest_mode;

    /*
     * When 'v' is in the nested guest mode, all guest copy
     * functions/macros which finally call paging_gva_to_gfn()
     * transfer data to/from L2 guest. If the copy is intended for L1
     * guest, we must first clear the nested guest flag (by setting
     * policy->nested_guest_mode to false) before the copy and then
     * restore the nested guest flag (by setting
     * policy->nested_guest_mode to true) after the copy.
     */
    if ( unlikely(old_guest_mode != new_guest_mode) )
    {
        if ( new_guest_mode )
            nestedhvm_vcpu_enter_guestmode(v);
        else
            nestedhvm_vcpu_exit_guestmode(v);
        policy->nested_guest_mode = old_guest_mode;
    }
}

#ifndef CONFIG_BIGMEM
/*
 * The hole may be at or above the 44-bit boundary, so we need to determine
 * the total bit count until reaching 32 significant (not squashed out) bits
 * in PFN representations.
 * Note that the way "bits" gets initialized/updated/bounds-checked guarantees
 * that the function will never return zero, and hence will never be called
 * more than once (which is important due to it being deliberately placed in
 * .init.text).
 */
static unsigned int __init noinline _domain_struct_bits(void)
{
    unsigned int bits = 32 + PAGE_SHIFT;
    unsigned int sig = hweight32(~pfn_hole_mask);
    unsigned int mask = pfn_hole_mask >> 32;

    for ( ; bits < BITS_PER_LONG && sig < 32; ++bits, mask >>= 1 )
        if ( !(mask & 1) )
            ++sig;

    return bits;
}
#endif

struct domain *alloc_domain_struct(void)
{
    struct domain *d;
    unsigned int order = get_order_from_bytes(sizeof(*d));
#ifdef CONFIG_BIGMEM
    const unsigned int bits = 0;
#else
    /*
     * We pack the PDX of the domain structure into a 32-bit field within
     * the page_info structure. Hence the MEMF_bits() restriction.
     */
    static unsigned int __read_mostly bits;

    if ( unlikely(!bits) )
         bits = _domain_struct_bits();
#endif


#ifndef CONFIG_DEBUG_LOCK_PROFILE
    BUILD_BUG_ON(sizeof(*d) > PAGE_SIZE);
#endif
    d = alloc_xenheap_pages(order, MEMF_bits(bits));
    if ( d != NULL )
    {
        unsigned int sz;

        for ( sz = 0; sz < (PAGE_SIZE << order); sz += PAGE_SIZE )
            clear_page((void *)d + sz);
    }
    return d;
}

void free_domain_struct(struct domain *d)
{
    free_xenheap_page(d);
}

struct vcpu *alloc_vcpu_struct(const struct domain *d)
{
    struct vcpu *v;
    /*
     * This structure contains embedded PAE PDPTEs, used when an HVM guest
     * runs on shadow pagetables outside of 64-bit mode. In this case the CPU
     * may require that the shadow CR3 points below 4GB, and hence the whole
     * structure must satisfy this restriction. Thus we specify MEMF_bits(32).
     */
    unsigned int memflags =
        (is_hvm_domain(d) && paging_mode_shadow(d)) ? MEMF_bits(32) : 0;

    BUILD_BUG_ON(sizeof(*v) > PAGE_SIZE);
    v = alloc_xenheap_pages(0, memflags);
    if ( v != NULL )
        clear_page(v);
    return v;
}

void free_vcpu_struct(struct vcpu *v)
{
    free_xenheap_page(v);
}

/* Initialise various registers to their architectural INIT/RESET state. */
void arch_vcpu_regs_init(struct vcpu *v)
{
    memset(&v->arch.user_regs, 0, sizeof(v->arch.user_regs));
    v->arch.user_regs.eflags = X86_EFLAGS_MBS;

    memset(v->arch.dr, 0, sizeof(v->arch.dr));
    v->arch.dr6 = X86_DR6_DEFAULT;
    v->arch.dr7 = X86_DR7_DEFAULT;
}

int arch_vcpu_create(struct vcpu *v)
{
    struct domain *d = v->domain;
    int rc;

    v->arch.flags = TF_kernel_mode;

    rc = mapcache_vcpu_init(v);
    if ( rc )
        return rc;

    if ( !is_idle_domain(d) )
    {
        paging_vcpu_init(v);

        if ( (rc = vcpu_init_fpu(v)) != 0 )
            return rc;

        vmce_init_vcpu(v);

        arch_vcpu_regs_init(v);
    }
    else if ( (rc = xstate_alloc_save_area(v)) != 0 )
        return rc;

    spin_lock_init(&v->arch.vpmu.vpmu_lock);

    if ( is_hvm_domain(d) )
        rc = hvm_vcpu_initialise(v);
    else if ( !is_idle_domain(d) )
        rc = pv_vcpu_initialise(v);
    else
    {
        /* Idle domain */
        v->arch.cr3 = __pa(idle_pg_table);
        rc = 0;
        v->arch.msrs = ZERO_BLOCK_PTR; /* Catch stray misuses */
    }

    if ( rc )
        goto fail;

    if ( !is_idle_domain(v->domain) )
    {
        vpmu_initialise(v);

        if ( (rc = init_vcpu_msr_policy(v)) )
            goto fail;

        cpuid_policy_updated(v);
    }

    return rc;

 fail:
    vcpu_destroy_fpu(v);
    xfree(v->arch.msrs);
    v->arch.msrs = NULL;

    return rc;
}

void arch_vcpu_destroy(struct vcpu *v)
{
    xfree(v->arch.vm_event);
    v->arch.vm_event = NULL;

    vcpu_destroy_fpu(v);

    xfree(v->arch.msrs);
    v->arch.msrs = NULL;

    if ( !is_idle_domain(v->domain) )
        vpmu_destroy(v);

    if ( is_hvm_vcpu(v) )
        hvm_vcpu_destroy(v);
    else
        pv_vcpu_destroy(v);
}

int arch_sanitise_domain_config(struct xen_domctl_createdomain *config)
{
    bool hvm = config->flags & XEN_DOMCTL_CDF_hvm;
    unsigned int max_vcpus;

    if ( hvm ? !hvm_enabled : !IS_ENABLED(CONFIG_PV) )
    {
        dprintk(XENLOG_INFO, "%s support not available\n", hvm ? "HVM" : "PV");
        return -EINVAL;
    }

    max_vcpus = hvm ? HVM_MAX_VCPUS : MAX_VIRT_CPUS;

    if ( config->max_vcpus > max_vcpus )
    {
        dprintk(XENLOG_INFO, "Requested vCPUs (%u) exceeds max (%u)\n",
                config->max_vcpus, max_vcpus);
        return -EINVAL;
    }

    if ( !IS_ENABLED(CONFIG_TBOOT) &&
         (config->flags & XEN_DOMCTL_CDF_s3_integrity) )
    {
        dprintk(XENLOG_INFO, "S3 integrity check not valid without CONFIG_TBOOT\n");
        return -EINVAL;
    }

    if ( (config->flags & XEN_DOMCTL_CDF_hap) && !hvm_hap_supported() )
    {
        dprintk(XENLOG_INFO, "HAP requested but not supported\n");
        return -EINVAL;
    }

    if ( !(config->flags & XEN_DOMCTL_CDF_hvm) )
        /*
         * It is only meaningful for XEN_DOMCTL_CDF_oos_off to be clear
         * for HVM guests.
         */
        config->flags |= XEN_DOMCTL_CDF_oos_off;

    return 0;
}

static bool emulation_flags_ok(const struct domain *d, uint32_t emflags)
{
#ifdef CONFIG_HVM
    /* This doesn't catch !CONFIG_HVM case but it is better than nothing */
    BUILD_BUG_ON(X86_EMU_ALL != XEN_X86_EMU_ALL);
#endif

    if ( is_hvm_domain(d) )
    {
        if ( is_hardware_domain(d) &&
             emflags != (X86_EMU_VPCI | X86_EMU_LAPIC | X86_EMU_IOAPIC) )
            return false;
        if ( !is_hardware_domain(d) &&
             emflags != (X86_EMU_ALL & ~X86_EMU_VPCI) &&
             emflags != X86_EMU_LAPIC )
            return false;
    }
    else if ( emflags != 0 && emflags != X86_EMU_PIT )
    {
        /* PV or classic PVH. */
        return false;
    }

    return true;
}

int arch_domain_create(struct domain *d,
                       struct xen_domctl_createdomain *config)
{
    bool paging_initialised = false;
    uint32_t emflags;
    int rc;

    INIT_PAGE_LIST_HEAD(&d->arch.relmem_list);

    spin_lock_init(&d->arch.e820_lock);
    spin_lock_init(&d->arch.vtsc_lock);

    /* Minimal initialisation for the idle domain. */
    if ( unlikely(is_idle_domain(d)) )
    {
        static const struct arch_csw idle_csw = {
            .from = paravirt_ctxt_switch_from,
            .to   = paravirt_ctxt_switch_to,
            .tail = continue_idle_domain,
        };

        d->arch.ctxt_switch = &idle_csw;

        d->arch.cpuid = ZERO_BLOCK_PTR; /* Catch stray misuses. */
        d->arch.msr = ZERO_BLOCK_PTR;

        return 0;
    }

    if ( !config )
    {
        /* Only IDLE is allowed with no config. */
        ASSERT_UNREACHABLE();
        return -EINVAL;
    }

    if ( d->domain_id && cpu_has_amd_erratum(&boot_cpu_data, AMD_ERRATUM_121) )
    {
        if ( !opt_allow_unsafe )
        {
            printk(XENLOG_G_ERR "Xen does not allow DomU creation on this CPU"
                   " for security reasons.\n");
            return -EPERM;
        }
        printk(XENLOG_G_WARNING
               "Dom%d may compromise security on this CPU.\n",
               d->domain_id);
    }

    emflags = config->arch.emulation_flags;

    if ( is_hardware_domain(d) && is_pv_domain(d) )
        emflags |= XEN_X86_EMU_PIT;

    if ( emflags & ~XEN_X86_EMU_ALL )
    {
        printk(XENLOG_G_ERR "d%d: Invalid emulation bitmap: %#x\n",
               d->domain_id, emflags);
        return -EINVAL;
    }

    if ( !emulation_flags_ok(d, emflags) )
    {
        printk(XENLOG_G_ERR "d%d: Xen does not allow %s domain creation "
               "with the current selection of emulators: %#x\n",
               d->domain_id, is_hvm_domain(d) ? "HVM" : "PV", emflags);
        return -EOPNOTSUPP;
    }
    d->arch.emulation_flags = emflags;

    HYPERVISOR_COMPAT_VIRT_START(d) =
        is_pv_domain(d) ? __HYPERVISOR_COMPAT_VIRT_START : ~0u;

    if ( (rc = paging_domain_init(d)) != 0 )
        goto fail;
    paging_initialised = true;

    if ( (rc = init_domain_cpuid_policy(d)) )
        goto fail;

    if ( (rc = init_domain_msr_policy(d)) )
        goto fail;

    d->arch.ioport_caps =
        rangeset_new(d, "I/O Ports", RANGESETF_prettyprint_hex);
    rc = -ENOMEM;
    if ( d->arch.ioport_caps == NULL )
        goto fail;

    /*
     * The shared_info machine address must fit in a 32-bit field within a
     * 32-bit guest's start_info structure. Hence we specify MEMF_bits(32).
     */
    if ( (d->shared_info = alloc_xenheap_pages(0, MEMF_bits(32))) == NULL )
        goto fail;

    clear_page(d->shared_info);
    share_xen_page_with_guest(virt_to_page(d->shared_info), d, SHARE_rw);

    if ( (rc = init_domain_irq_mapping(d)) != 0 )
        goto fail;

    if ( (rc = iommu_domain_init(d, config->iommu_opts)) != 0 )
        goto fail;

    psr_domain_init(d);

    if ( is_hvm_domain(d) )
    {
        if ( (rc = hvm_domain_initialise(d)) != 0 )
            goto fail;
    }
    else if ( is_pv_domain(d) )
    {
        mapcache_domain_init(d);

        if ( (rc = pv_domain_initialise(d)) != 0 )
            goto fail;
    }
    else
        ASSERT_UNREACHABLE(); /* Not HVM and not PV? */

    if ( (rc = tsc_set_info(d, TSC_MODE_DEFAULT, 0, 0, 0)) != 0 )
    {
        ASSERT_UNREACHABLE();
        goto fail;
    }

    /* PV/PVH guests get an emulated PIT too for video BIOSes to use. */
    pit_init(d, cpu_khz);

    /*
     * If the FPU does not save FCS/FDS then we can always
     * save/restore the 64-bit FIP/FDP and ignore the selectors.
     */
    d->arch.x87_fip_width = cpu_has_fpu_sel ? 0 : 8;

    return 0;

 fail:
    d->is_dying = DOMDYING_dead;
    psr_domain_free(d);
    iommu_domain_destroy(d);
    cleanup_domain_irq_mapping(d);
    free_xenheap_page(d->shared_info);
    xfree(d->arch.cpuid);
    xfree(d->arch.msr);
    if ( paging_initialised )
        paging_final_teardown(d);
    free_perdomain_mappings(d);

    return rc;
}

void arch_domain_destroy(struct domain *d)
{
    if ( is_hvm_domain(d) )
        hvm_domain_destroy(d);

    xfree(d->arch.e820);
    xfree(d->arch.cpuid);
    xfree(d->arch.msr);

    free_domain_pirqs(d);
    if ( !is_idle_domain(d) )
        iommu_domain_destroy(d);

    paging_final_teardown(d);

    if ( is_pv_domain(d) )
        pv_domain_destroy(d);
    free_perdomain_mappings(d);

    free_xenheap_page(d->shared_info);
    cleanup_domain_irq_mapping(d);

    psr_domain_free(d);
}

void arch_domain_shutdown(struct domain *d)
{
    if ( is_viridian_domain(d) )
        viridian_time_domain_freeze(d);
}

void arch_domain_pause(struct domain *d)
{
    if ( is_viridian_domain(d) )
        viridian_time_domain_freeze(d);
}

void arch_domain_unpause(struct domain *d)
{
    if ( is_viridian_domain(d) )
        viridian_time_domain_thaw(d);
}

int arch_domain_soft_reset(struct domain *d)
{
    struct page_info *page = virt_to_page(d->shared_info), *new_page;
    int ret = 0;
    struct domain *owner;
    mfn_t mfn;
    gfn_t gfn;
    p2m_type_t p2mt;
    unsigned int i;

    /* Soft reset is supported for HVM domains only. */
    if ( !is_hvm_domain(d) )
        return -EINVAL;

    spin_lock(&d->event_lock);
    for ( i = 0; i < d->nr_pirqs ; i++ )
    {
        if ( domain_pirq_to_emuirq(d, i) != IRQ_UNBOUND )
        {
            ret = unmap_domain_pirq_emuirq(d, i);
            if ( ret )
                break;
        }
    }
    spin_unlock(&d->event_lock);

    if ( ret )
        return ret;

    /*
     * The shared_info page needs to be replaced with a new page, otherwise we
     * will get a hole if the domain does XENMAPSPACE_shared_info.
     */

    owner = page_get_owner_and_reference(page);
    ASSERT( owner == d );

    mfn = page_to_mfn(page);
    gfn = mfn_to_gfn(d, mfn);

    /*
     * gfn == INVALID_GFN indicates that the shared_info page was never mapped
     * to the domain's address space and there is nothing to replace.
     */
    if ( gfn_eq(gfn, INVALID_GFN) )
        goto exit_put_page;

    if ( !mfn_eq(get_gfn_query(d, gfn_x(gfn), &p2mt), mfn) )
    {
        printk(XENLOG_G_ERR
               "Failed to get %pd's shared_info GFN (%"PRI_gfn")\n",
               d, gfn_x(gfn));
        ret = -EINVAL;
        goto exit_put_gfn;
    }

    new_page = alloc_domheap_page(d, 0);
    if ( !new_page )
    {
        printk(XENLOG_G_ERR
               "Failed to alloc a page to replace %pd's shared_info GFN %"PRI_gfn"\n",
               d, gfn_x(gfn));
        ret = -ENOMEM;
        goto exit_put_gfn;
    }

    ret = guest_physmap_remove_page(d, gfn, mfn, PAGE_ORDER_4K);
    if ( ret )
    {
        printk(XENLOG_G_ERR
               "Failed to remove %pd's shared_info GFN %"PRI_gfn"\n",
               d, gfn_x(gfn));
        free_domheap_page(new_page);
        goto exit_put_gfn;
    }

    ret = guest_physmap_add_page(d, gfn, page_to_mfn(new_page),
                                 PAGE_ORDER_4K);
    if ( ret )
    {
        printk(XENLOG_G_ERR
               "Failed to add a page to replace %pd's shared_info frame %"PRI_gfn"\n",
               d, gfn_x(gfn));
        free_domheap_page(new_page);
    }
 exit_put_gfn:
    put_gfn(d, gfn_x(gfn));
 exit_put_page:
    put_page(page);

    return ret;
}

void arch_domain_creation_finished(struct domain *d)
{
}

#define xen_vcpu_guest_context vcpu_guest_context
#define fpu_ctxt fpu_ctxt.x
CHECK_FIELD_(struct, vcpu_guest_context, fpu_ctxt);
#undef fpu_ctxt
#undef xen_vcpu_guest_context

/* Called by XEN_DOMCTL_setvcpucontext and VCPUOP_initialise. */
int arch_set_info_guest(
    struct vcpu *v, vcpu_guest_context_u c)
{
    struct domain *d = v->domain;
    unsigned int i;
    unsigned long flags;
    bool compat;
#ifdef CONFIG_PV
    mfn_t cr3_mfn;
    struct page_info *cr3_page = NULL;
    int rc = 0;
#endif

    /* The context is a compat-mode one if the target domain is compat-mode;
     * we expect the tools to DTRT even in compat-mode callers. */
    compat = is_pv_32bit_domain(d);

#define c(fld) (compat ? (c.cmp->fld) : (c.nat->fld))
    flags = c(flags);

    if ( is_pv_domain(d) )
    {
        if ( !compat )
        {
            if ( !is_canonical_address(c.nat->user_regs.rip) ||
                 !is_canonical_address(c.nat->user_regs.rsp) ||
                 !is_canonical_address(c.nat->kernel_sp) ||
                 (c.nat->ldt_ents && !is_canonical_address(c.nat->ldt_base)) ||
                 !is_canonical_address(c.nat->fs_base) ||
                 !is_canonical_address(c.nat->gs_base_kernel) ||
                 !is_canonical_address(c.nat->gs_base_user) ||
                 !is_canonical_address(c.nat->event_callback_eip) ||
                 !is_canonical_address(c.nat->syscall_callback_eip) ||
                 !is_canonical_address(c.nat->failsafe_callback_eip) )
                return -EINVAL;

            fixup_guest_stack_selector(d, c.nat->user_regs.ss);
            fixup_guest_stack_selector(d, c.nat->kernel_ss);
            fixup_guest_code_selector(d, c.nat->user_regs.cs);

            for ( i = 0; i < ARRAY_SIZE(c.nat->trap_ctxt); i++ )
            {
                if ( !is_canonical_address(c.nat->trap_ctxt[i].address) )
                    return -EINVAL;
                fixup_guest_code_selector(d, c.nat->trap_ctxt[i].cs);
            }

            if ( !__addr_ok(c.nat->ldt_base) )
                return -EINVAL;
        }
        else
        {
            fixup_guest_stack_selector(d, c.cmp->user_regs.ss);
            fixup_guest_stack_selector(d, c.cmp->kernel_ss);
            fixup_guest_code_selector(d, c.cmp->user_regs.cs);
            fixup_guest_code_selector(d, c.cmp->event_callback_cs);
            fixup_guest_code_selector(d, c.cmp->failsafe_callback_cs);

            for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); i++ )
                fixup_guest_code_selector(d, c.cmp->trap_ctxt[i].cs);
        }

        /* LDT safety checks. */
        if ( ((c(ldt_base) & (PAGE_SIZE - 1)) != 0) ||
             (c(ldt_ents) > 8192) )
            return -EINVAL;
    }

    v->arch.flags |= TF_kernel_mode;
    if ( unlikely(!(flags & VGCF_in_kernel)) &&
         /*
          * TF_kernel_mode is only allowed to be clear for 64-bit PV. See
          * update_cr3(), sh_update_cr3(), sh_walk_guest_tables(), and
          * shadow_one_bit_disable() for why that is.
          */
         !is_hvm_domain(d) && !is_pv_32bit_domain(d) )
        v->arch.flags &= ~TF_kernel_mode;

    v->arch.vgc_flags = flags;

    vcpu_setup_fpu(v, v->arch.xsave_area,
                   flags & VGCF_I387_VALID ? &c.nat->fpu_ctxt : NULL,
                   FCW_DEFAULT);

    if ( !compat )
    {
        memcpy(&v->arch.user_regs, &c.nat->user_regs, sizeof(c.nat->user_regs));
        if ( is_pv_domain(d) )
            memcpy(v->arch.pv.trap_ctxt, c.nat->trap_ctxt,
                   sizeof(c.nat->trap_ctxt));
    }
    else
    {
        XLAT_cpu_user_regs(&v->arch.user_regs, &c.cmp->user_regs);
        if ( is_pv_domain(d) )
        {
            for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); ++i )
                XLAT_trap_info(v->arch.pv.trap_ctxt + i,
                               c.cmp->trap_ctxt + i);
        }
    }

    if ( is_hvm_domain(d) )
    {
        for ( i = 0; i < ARRAY_SIZE(v->arch.dr); ++i )
            v->arch.dr[i] = c(debugreg[i]);
        v->arch.dr6 = c(debugreg[6]);
        v->arch.dr7 = c(debugreg[7]);

        hvm_set_info_guest(v);
        goto out;
    }

#ifdef CONFIG_PV
    /* IOPL privileges are virtualised. */
    v->arch.pv.iopl = v->arch.user_regs.eflags & X86_EFLAGS_IOPL;
    v->arch.user_regs.eflags &= ~X86_EFLAGS_IOPL;

    /* Ensure real hardware interrupts are enabled. */
    v->arch.user_regs.eflags |= X86_EFLAGS_IF;

    if ( !v->is_initialised )
    {
        if ( !compat && !(flags & VGCF_in_kernel) && !c.nat->ctrlreg[1] )
            return -EINVAL;

        v->arch.pv.ldt_base = c(ldt_base);
        v->arch.pv.ldt_ents = c(ldt_ents);
    }
    else
    {
        unsigned long pfn = pagetable_get_pfn(v->arch.guest_table);
        bool fail;

        if ( !compat )
        {
            fail = xen_pfn_to_cr3(pfn) != c.nat->ctrlreg[3];
            if ( pagetable_is_null(v->arch.guest_table_user) )
                fail |= c.nat->ctrlreg[1] || !(flags & VGCF_in_kernel);
            else
            {
                pfn = pagetable_get_pfn(v->arch.guest_table_user);
                fail |= xen_pfn_to_cr3(pfn) != c.nat->ctrlreg[1];
            }
        } else {
            l4_pgentry_t *l4tab = map_domain_page(_mfn(pfn));

            pfn = l4e_get_pfn(*l4tab);
            unmap_domain_page(l4tab);
            fail = compat_pfn_to_cr3(pfn) != c.cmp->ctrlreg[3];
        }

        for ( i = 0; i < ARRAY_SIZE(v->arch.pv.gdt_frames); ++i )
            fail |= v->arch.pv.gdt_frames[i] != c(gdt_frames[i]);
        fail |= v->arch.pv.gdt_ents != c(gdt_ents);

        fail |= v->arch.pv.ldt_base != c(ldt_base);
        fail |= v->arch.pv.ldt_ents != c(ldt_ents);

        if ( fail )
           return -EOPNOTSUPP;
    }

    v->arch.pv.kernel_ss = c(kernel_ss);
    v->arch.pv.kernel_sp = c(kernel_sp);
    for ( i = 0; i < ARRAY_SIZE(v->arch.pv.ctrlreg); ++i )
        v->arch.pv.ctrlreg[i] = c(ctrlreg[i]);

    v->arch.pv.event_callback_eip = c(event_callback_eip);
    v->arch.pv.failsafe_callback_eip = c(failsafe_callback_eip);
    if ( !compat )
    {
        v->arch.pv.syscall_callback_eip = c.nat->syscall_callback_eip;
        /* non-nul selector kills fs_base */
        v->arch.pv.fs_base =
            !(v->arch.user_regs.fs & ~3) ? c.nat->fs_base : 0;
        v->arch.pv.gs_base_kernel = c.nat->gs_base_kernel;
        /* non-nul selector kills gs_base_user */
        v->arch.pv.gs_base_user =
            !(v->arch.user_regs.gs & ~3) ? c.nat->gs_base_user : 0;
    }
    else
    {
        v->arch.pv.event_callback_cs = c(event_callback_cs);
        v->arch.pv.failsafe_callback_cs = c(failsafe_callback_cs);
    }

    /* Only CR0.TS is modifiable by guest or admin. */
    v->arch.pv.ctrlreg[0] &= X86_CR0_TS;
    v->arch.pv.ctrlreg[0] |= read_cr0() & ~X86_CR0_TS;

    v->arch.pv.ctrlreg[4] = pv_fixup_guest_cr4(v, v->arch.pv.ctrlreg[4]);

    memset(v->arch.dr, 0, sizeof(v->arch.dr));
    v->arch.dr6 = X86_DR6_DEFAULT;
    v->arch.dr7 = X86_DR7_DEFAULT;
    v->arch.pv.dr7_emul = 0;

    for ( i = 0; i < ARRAY_SIZE(v->arch.dr); i++ )
        set_debugreg(v, i, c(debugreg[i]));
    set_debugreg(v, 6, c(debugreg[6]));
    set_debugreg(v, 7, c(debugreg[7]));

    if ( v->is_initialised )
        goto out;

    if ( v->vcpu_id == 0 )
    {
        /*
         * In the restore case we need to deal with L4 pages which got
         * initialized with m2p_strict still clear (and which hence lack the
         * correct initial RO_MPT_VIRT_{START,END} L4 entry).
         */
        if ( d != current->domain && !VM_ASSIST(d, m2p_strict) &&
             is_pv_domain(d) && !is_pv_32bit_domain(d) &&
             test_bit(VMASST_TYPE_m2p_strict, &c.nat->vm_assist) &&
             atomic_read(&d->arch.pv.nr_l4_pages) )
        {
            bool done = false;

            spin_lock_recursive(&d->page_alloc_lock);

            for ( i = 0; ; )
            {
                struct page_info *page = page_list_remove_head(&d->page_list);

                if ( page_lock(page) )
                {
                    if ( (page->u.inuse.type_info & PGT_type_mask) ==
                         PGT_l4_page_table )
                        done = !fill_ro_mpt(page_to_mfn(page));

                    page_unlock(page);
                }

                page_list_add_tail(page, &d->page_list);

                if ( done || (!(++i & 0xff) && hypercall_preempt_check()) )
                    break;
            }

            spin_unlock_recursive(&d->page_alloc_lock);

            if ( !done )
                return -ERESTART;
        }

        d->vm_assist = c(vm_assist);
    }

    rc = put_old_guest_table(current);
    if ( rc )
        return rc;

    if ( !compat )
        rc = (int)pv_set_gdt(v, c.nat->gdt_frames, c.nat->gdt_ents);
    else
    {
        unsigned long gdt_frames[ARRAY_SIZE(v->arch.pv.gdt_frames)];
        unsigned int nr_frames = DIV_ROUND_UP(c.cmp->gdt_ents, 512);

        if ( nr_frames > ARRAY_SIZE(v->arch.pv.gdt_frames) )
            return -EINVAL;

        for ( i = 0; i < nr_frames; ++i )
            gdt_frames[i] = c.cmp->gdt_frames[i];

        rc = (int)pv_set_gdt(v, gdt_frames, c.cmp->gdt_ents);
    }
    if ( rc != 0 )
        return rc;

    set_bit(_VPF_in_reset, &v->pause_flags);

    if ( !compat )
        cr3_mfn = _mfn(xen_cr3_to_pfn(c.nat->ctrlreg[3]));
    else
        cr3_mfn = _mfn(compat_cr3_to_pfn(c.cmp->ctrlreg[3]));
    cr3_page = get_page_from_mfn(cr3_mfn, d);

    if ( !cr3_page )
        rc = -EINVAL;
    else if ( paging_mode_refcounts(d) )
        /* nothing */;
    else if ( cr3_page == v->arch.old_guest_table )
    {
        v->arch.old_guest_table = NULL;
        put_page(cr3_page);
    }
    else
    {
        if ( !compat )
            rc = put_old_guest_table(v);
        if ( !rc )
            rc = get_page_type_preemptible(cr3_page,
                                           !compat ? PGT_root_page_table
                                                   : PGT_l3_page_table);
        switch ( rc )
        {
        case -EINTR:
            rc = -ERESTART;
        case -ERESTART:
            break;
        case 0:
            if ( !compat && !VM_ASSIST(d, m2p_strict) &&
                 !paging_mode_refcounts(d) )
                fill_ro_mpt(cr3_mfn);
            break;
        default:
            if ( cr3_page == current->arch.old_guest_table )
                cr3_page = NULL;
            break;
        }
    }
    if ( rc )
        /* handled below */;
    else if ( !compat )
    {
        v->arch.guest_table = pagetable_from_page(cr3_page);
        if ( c.nat->ctrlreg[1] )
        {
            cr3_mfn = _mfn(xen_cr3_to_pfn(c.nat->ctrlreg[1]));
            cr3_page = get_page_from_mfn(cr3_mfn, d);

            if ( !cr3_page )
                rc = -EINVAL;
            else if ( !paging_mode_refcounts(d) )
            {
                rc = get_page_type_preemptible(cr3_page, PGT_root_page_table);
                switch ( rc )
                {
                case -EINTR:
                    rc = -ERESTART;
                    /* Fallthrough */
                case -ERESTART:
                    v->arch.old_guest_ptpg = NULL;
                    v->arch.old_guest_table =
                        pagetable_get_page(v->arch.guest_table);
                    v->arch.guest_table = pagetable_null();
                    break;
                default:
                    if ( cr3_page == current->arch.old_guest_table )
                        cr3_page = NULL;
                    break;
                case 0:
                    if ( VM_ASSIST(d, m2p_strict) )
                        zap_ro_mpt(cr3_mfn);
                    break;
                }
            }
            if ( !rc )
               v->arch.guest_table_user = pagetable_from_page(cr3_page);
        }
    }
    else
    {
        l4_pgentry_t *l4tab;

        l4tab = map_domain_page(pagetable_get_mfn(v->arch.guest_table));
        *l4tab = l4e_from_mfn(page_to_mfn(cr3_page),
            _PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED);
        unmap_domain_page(l4tab);
    }
    if ( rc )
    {
        if ( cr3_page )
            put_page(cr3_page);
        pv_destroy_gdt(v);
        return rc;
    }

    clear_bit(_VPF_in_reset, &v->pause_flags);

    if ( v->vcpu_id == 0 )
        update_domain_wallclock_time(d);

    /* Don't redo final setup */
    v->is_initialised = 1;

    if ( paging_mode_enabled(d) )
        paging_update_paging_modes(v);

    update_cr3(v);
#endif /* CONFIG_PV */

 out:
    if ( flags & VGCF_online )
        clear_bit(_VPF_down, &v->pause_flags);
    else
        set_bit(_VPF_down, &v->pause_flags);
    return 0;
#undef c
}

int arch_initialise_vcpu(struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int rc;

    if ( is_hvm_vcpu(v) )
    {
        struct domain *d = v->domain;
        struct vcpu_hvm_context ctxt;

        if ( copy_from_guest(&ctxt, arg, 1) )
            return -EFAULT;

        domain_lock(d);
        rc = v->is_initialised ? -EEXIST : arch_set_info_hvm_guest(v, &ctxt);
        domain_unlock(d);
    }
    else
        rc = default_initialise_vcpu(v, arg);

    return rc;
}

int arch_vcpu_reset(struct vcpu *v)
{
    if ( is_pv_vcpu(v) )
    {
        pv_destroy_gdt(v);
        return vcpu_destroy_pagetables(v);
    }

    vcpu_end_shutdown_deferral(v);
    return 0;
}

long
arch_do_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc = 0;

    switch ( cmd )
    {
    case VCPUOP_register_vcpu_time_memory_area:
    {
        struct vcpu_register_time_memory_area area;

        rc = -EFAULT;
        if ( copy_from_guest(&area, arg, 1) )
            break;

        if ( !guest_handle_okay(area.addr.h, 1) )
            break;

        rc = 0;
        v->arch.time_info_guest = area.addr.h;

        force_update_vcpu_system_time(v);

        break;
    }

    case VCPUOP_get_physid:
    {
        struct vcpu_get_physid cpu_id;

        rc = -EINVAL;
        if ( !is_hwdom_pinned_vcpu(v) )
            break;

        cpu_id.phys_id =
            (uint64_t)x86_cpu_to_apicid[v->vcpu_id] |
            ((uint64_t)acpi_get_processor_id(v->vcpu_id) << 32);

        rc = -EFAULT;
        if ( copy_to_guest(arg, &cpu_id, 1) )
            break;

        rc = 0;
        break;
    }

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

/*
 * Loading a nul selector does not clear bases and limits on AMD or Hygon
 * CPUs. Be on the safe side and re-initialize both to flat segment values
 * before loading a nul selector.
 */
#define preload_segment(seg, value) do {              \
    if ( !((value) & ~3) &&                           \
         (boot_cpu_data.x86_vendor &                  \
          (X86_VENDOR_AMD | X86_VENDOR_HYGON)) )      \
        asm volatile ( "movl %k0, %%" #seg            \
                       :: "r" (FLAT_USER_DS32) );     \
} while ( false )

#define loadsegment(seg,value) ({               \
    int __r = 1;                                \
    asm volatile (                              \
        "1: movl %k1,%%" #seg "\n2:\n"          \
        ".section .fixup,\"ax\"\n"              \
        "3: xorl %k0,%k0\n"                     \
        "   movl %k0,%%" #seg "\n"              \
        "   jmp 2b\n"                           \
        ".previous\n"                           \
        _ASM_EXTABLE(1b, 3b)                    \
        : "=r" (__r) : "r" (value), "0" (__r) );\
    __r; })

/*
 * save_segments() writes a mask of segments which are dirty (non-zero),
 * allowing load_segments() to avoid some expensive segment loads and
 * MSR writes.
 */
static DEFINE_PER_CPU(unsigned int, dirty_segment_mask);
#define DIRTY_DS           0x01
#define DIRTY_ES           0x02
#define DIRTY_FS           0x04
#define DIRTY_GS           0x08
#define DIRTY_FS_BASE      0x10
#define DIRTY_GS_BASE      0x20

static void load_segments(struct vcpu *n)
{
    struct cpu_user_regs *uregs = &n->arch.user_regs;
    int all_segs_okay = 1;
    unsigned int dirty_segment_mask, cpu = smp_processor_id();
    bool fs_gs_done = false;

    /* Load and clear the dirty segment mask. */
    dirty_segment_mask = per_cpu(dirty_segment_mask, cpu);
    per_cpu(dirty_segment_mask, cpu) = 0;

#ifdef CONFIG_HVM
    if ( cpu_has_svm && !is_pv_32bit_vcpu(n) &&
         !(read_cr4() & X86_CR4_FSGSBASE) && !((uregs->fs | uregs->gs) & ~3) )
    {
        unsigned long gsb = n->arch.flags & TF_kernel_mode
            ? n->arch.pv.gs_base_kernel : n->arch.pv.gs_base_user;
        unsigned long gss = n->arch.flags & TF_kernel_mode
            ? n->arch.pv.gs_base_user : n->arch.pv.gs_base_kernel;

        fs_gs_done = svm_load_segs(n->arch.pv.ldt_ents, LDT_VIRT_START(n),
                                   uregs->fs, n->arch.pv.fs_base,
                                   uregs->gs, gsb, gss);
    }
#endif
    if ( !fs_gs_done )
        load_LDT(n);

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_DS) | uregs->ds) )
    {
        preload_segment(ds, uregs->ds);
        all_segs_okay &= loadsegment(ds, uregs->ds);
    }

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_ES) | uregs->es) )
    {
        preload_segment(es, uregs->es);
        all_segs_okay &= loadsegment(es, uregs->es);
    }

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_FS) | uregs->fs) && !fs_gs_done )
    {
        all_segs_okay &= loadsegment(fs, uregs->fs);
        /* non-nul selector updates fs_base */
        if ( uregs->fs & ~3 )
            dirty_segment_mask &= ~DIRTY_FS_BASE;
    }

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_GS) | uregs->gs) && !fs_gs_done )
    {
        all_segs_okay &= loadsegment(gs, uregs->gs);
        /* non-nul selector updates gs_base_user */
        if ( uregs->gs & ~3 )
            dirty_segment_mask &= ~DIRTY_GS_BASE;
    }

    if ( !fs_gs_done && !is_pv_32bit_vcpu(n) )
    {
        /* This can only be non-zero if selector is NULL. */
        if ( n->arch.pv.fs_base | (dirty_segment_mask & DIRTY_FS_BASE) )
            wrfsbase(n->arch.pv.fs_base);

        /*
         * Most kernels have non-zero GS base, so don't bother testing.
         * (For old AMD hardware this is also a serialising instruction,
         * avoiding erratum #88.)
         */
        wrgsshadow(n->arch.pv.gs_base_kernel);

        /* This can only be non-zero if selector is NULL. */
        if ( n->arch.pv.gs_base_user |
             (dirty_segment_mask & DIRTY_GS_BASE) )
            wrgsbase(n->arch.pv.gs_base_user);

        /* If in kernel mode then switch the GS bases around. */
        if ( (n->arch.flags & TF_kernel_mode) )
            asm volatile ( "swapgs" );
    }

    if ( unlikely(!all_segs_okay) )
    {
        struct pv_vcpu *pv = &n->arch.pv;
        struct cpu_user_regs *regs = guest_cpu_user_regs();
        unsigned long *rsp =
            (unsigned long *)(((n->arch.flags & TF_kernel_mode)
                               ? regs->rsp : pv->kernel_sp) & ~0xf);
        unsigned long cs_and_mask, rflags;

        /* Fold upcall mask and architectural IOPL into RFLAGS.IF. */
        rflags  = regs->rflags & ~(X86_EFLAGS_IF|X86_EFLAGS_IOPL);
        rflags |= !vcpu_info(n, evtchn_upcall_mask) << 9;
        if ( VM_ASSIST(n->domain, architectural_iopl) )
            rflags |= n->arch.pv.iopl;

        if ( is_pv_32bit_vcpu(n) )
        {
            unsigned int *esp = ring_1(regs) ?
                                (unsigned int *)regs->rsp :
                                (unsigned int *)pv->kernel_sp;
            int ret = 0;

            /* CS longword also contains full evtchn_upcall_mask. */
            cs_and_mask = (unsigned short)regs->cs |
                ((unsigned int)vcpu_info(n, evtchn_upcall_mask) << 16);

            if ( !ring_1(regs) )
            {
                ret  = put_user(regs->ss,       esp-1);
                ret |= put_user(regs->esp,      esp-2);
                esp -= 2;
            }

            if ( ret |
                 put_user(rflags,              esp-1) |
                 put_user(cs_and_mask,         esp-2) |
                 put_user(regs->eip,           esp-3) |
                 put_user(uregs->gs,           esp-4) |
                 put_user(uregs->fs,           esp-5) |
                 put_user(uregs->es,           esp-6) |
                 put_user(uregs->ds,           esp-7) )
            {
                gprintk(XENLOG_ERR,
                        "error while creating compat failsafe callback frame\n");
                domain_crash(n->domain);
            }

            if ( n->arch.vgc_flags & VGCF_failsafe_disables_events )
                vcpu_info(n, evtchn_upcall_mask) = 1;

            regs->entry_vector |= TRAP_syscall;
            regs->eflags       &= ~(X86_EFLAGS_VM|X86_EFLAGS_RF|X86_EFLAGS_NT|
                                    X86_EFLAGS_IOPL|X86_EFLAGS_TF);
            regs->ss            = FLAT_COMPAT_KERNEL_SS;
            regs->esp           = (unsigned long)(esp-7);
            regs->cs            = FLAT_COMPAT_KERNEL_CS;
            regs->eip           = pv->failsafe_callback_eip;
            return;
        }

        if ( !(n->arch.flags & TF_kernel_mode) )
            toggle_guest_mode(n);
        else
            regs->cs &= ~3;

        /* CS longword also contains full evtchn_upcall_mask. */
        cs_and_mask = (unsigned long)regs->cs |
            ((unsigned long)vcpu_info(n, evtchn_upcall_mask) << 32);

        if ( put_user(regs->ss,            rsp- 1) |
             put_user(regs->rsp,           rsp- 2) |
             put_user(rflags,              rsp- 3) |
             put_user(cs_and_mask,         rsp- 4) |
             put_user(regs->rip,           rsp- 5) |
             put_user(uregs->gs,           rsp- 6) |
             put_user(uregs->fs,           rsp- 7) |
             put_user(uregs->es,           rsp- 8) |
             put_user(uregs->ds,           rsp- 9) |
             put_user(regs->r11,           rsp-10) |
             put_user(regs->rcx,           rsp-11) )
        {
            gprintk(XENLOG_ERR,
                    "error while creating failsafe callback frame\n");
            domain_crash(n->domain);
        }

        if ( n->arch.vgc_flags & VGCF_failsafe_disables_events )
            vcpu_info(n, evtchn_upcall_mask) = 1;

        regs->entry_vector |= TRAP_syscall;
        regs->rflags       &= ~(X86_EFLAGS_AC|X86_EFLAGS_VM|X86_EFLAGS_RF|
                                X86_EFLAGS_NT|X86_EFLAGS_IOPL|X86_EFLAGS_TF);
        regs->ss            = FLAT_KERNEL_SS;
        regs->rsp           = (unsigned long)(rsp-11);
        regs->cs            = FLAT_KERNEL_CS;
        regs->rip           = pv->failsafe_callback_eip;
    }
}

static void save_segments(struct vcpu *v)
{
    struct cpu_user_regs *regs = &v->arch.user_regs;
    unsigned int dirty_segment_mask = 0;

    regs->ds = read_sreg(ds);
    regs->es = read_sreg(es);
    regs->fs = read_sreg(fs);
    regs->gs = read_sreg(gs);

    /* %fs/%gs bases can only be stale if WR{FS,GS}BASE are usable. */
    if ( (read_cr4() & X86_CR4_FSGSBASE) && !is_pv_32bit_vcpu(v) )
    {
        v->arch.pv.fs_base = __rdfsbase();
        if ( v->arch.flags & TF_kernel_mode )
            v->arch.pv.gs_base_kernel = __rdgsbase();
        else
            v->arch.pv.gs_base_user = __rdgsbase();
    }

    if ( regs->ds )
        dirty_segment_mask |= DIRTY_DS;

    if ( regs->es )
        dirty_segment_mask |= DIRTY_ES;

    if ( regs->fs || is_pv_32bit_vcpu(v) )
    {
        dirty_segment_mask |= DIRTY_FS;
        /* non-nul selector kills fs_base */
        if ( regs->fs & ~3 )
            v->arch.pv.fs_base = 0;
    }
    if ( v->arch.pv.fs_base )
        dirty_segment_mask |= DIRTY_FS_BASE;

    if ( regs->gs || is_pv_32bit_vcpu(v) )
    {
        dirty_segment_mask |= DIRTY_GS;
        /* non-nul selector kills gs_base_user */
        if ( regs->gs & ~3 )
            v->arch.pv.gs_base_user = 0;
    }
    if ( v->arch.flags & TF_kernel_mode ? v->arch.pv.gs_base_kernel
                                        : v->arch.pv.gs_base_user )
        dirty_segment_mask |= DIRTY_GS_BASE;

    this_cpu(dirty_segment_mask) = dirty_segment_mask;
}

void paravirt_ctxt_switch_from(struct vcpu *v)
{
    save_segments(v);

    /*
     * Disable debug breakpoints. We do this aggressively because if we switch
     * to an HVM guest we may load DR0-DR3 with values that can cause #DE
     * inside Xen, before we get a chance to reload DR7, and this cannot always
     * safely be handled.
     */
    if ( unlikely(v->arch.dr7 & DR7_ACTIVE_MASK) )
        write_debugreg(7, 0);
}

void paravirt_ctxt_switch_to(struct vcpu *v)
{
    root_pgentry_t *root_pgt = this_cpu(root_pgt);

    if ( root_pgt )
        root_pgt[root_table_offset(PERDOMAIN_VIRT_START)] =
            l4e_from_page(v->domain->arch.perdomain_l3_pg,
                          __PAGE_HYPERVISOR_RW);

    if ( unlikely(v->arch.dr7 & DR7_ACTIVE_MASK) )
        activate_debugregs(v);

    if ( cpu_has_msr_tsc_aux )
        wrmsr_tsc_aux(v->arch.msrs->tsc_aux);
}

/* Update per-VCPU guest runstate shared memory area (if registered). */
bool update_runstate_area(struct vcpu *v)
{
    bool rc;
    struct guest_memory_policy policy = { .nested_guest_mode = false };
    void __user *guest_handle = NULL;
    struct vcpu_runstate_info runstate;

    if ( guest_handle_is_null(runstate_guest(v)) )
        return true;

    update_guest_memory_policy(v, &policy);

    memcpy(&runstate, &v->runstate, sizeof(runstate));

    if ( VM_ASSIST(v->domain, runstate_update_flag) )
    {
        guest_handle = has_32bit_shinfo(v->domain)
            ? &v->runstate_guest.compat.p->state_entry_time + 1
            : &v->runstate_guest.native.p->state_entry_time + 1;
        guest_handle--;
        runstate.state_entry_time |= XEN_RUNSTATE_UPDATE;
        __raw_copy_to_guest(guest_handle,
                            (void *)(&runstate.state_entry_time + 1) - 1, 1);
        smp_wmb();
    }

    if ( has_32bit_shinfo(v->domain) )
    {
        struct compat_vcpu_runstate_info info;

        XLAT_vcpu_runstate_info(&info, &runstate);
        __copy_to_guest(v->runstate_guest.compat, &info, 1);
        rc = true;
    }
    else
        rc = __copy_to_guest(runstate_guest(v), &runstate, 1) !=
             sizeof(runstate);

    if ( guest_handle )
    {
        runstate.state_entry_time &= ~XEN_RUNSTATE_UPDATE;
        smp_wmb();
        __raw_copy_to_guest(guest_handle,
                            (void *)(&runstate.state_entry_time + 1) - 1, 1);
    }

    update_guest_memory_policy(v, &policy);

    return rc;
}

static void _update_runstate_area(struct vcpu *v)
{
    if ( !update_runstate_area(v) && is_pv_vcpu(v) &&
         !(v->arch.flags & TF_kernel_mode) )
        v->arch.pv.need_update_runstate_area = 1;
}

/*
 * Overview of Xen's GDTs.
 *
 * Xen maintains per-CPU compat and regular GDTs which are both a single page
 * in size.  Some content is specific to each CPU (the TSS, the per-CPU marker
 * for #DF handling, and optionally the LDT).  The compat and regular GDTs
 * differ by the layout and content of the guest accessible selectors.
 *
 * The Xen selectors live from 0xe000 (slot 14 of 16), and need to always
 * appear in this position for interrupt/exception handling to work.
 *
 * A PV guest may specify GDT frames of their own (slots 0 to 13).  Room for a
 * full GDT exists in the per-domain mappings.
 *
 * To schedule a PV vcpu, we point slot 14 of the guest's full GDT at the
 * current CPU's compat or regular (as appropriate) GDT frame.  This is so
 * that the per-CPU parts still work correctly after switching pagetables and
 * loading the guests full GDT into GDTR.
 *
 * To schedule Idle or HVM vcpus, we load a GDT base address which causes the
 * regular per-CPU GDT frame to appear with selectors at the appropriate
 * offset.
 */
static always_inline bool need_full_gdt(const struct domain *d)
{
    return is_pv_domain(d) && !is_idle_domain(d);
}

static void update_xen_slot_in_full_gdt(const struct vcpu *v, unsigned int cpu)
{
    l1e_write(pv_gdt_ptes(v) + FIRST_RESERVED_GDT_PAGE,
              !is_pv_32bit_vcpu(v) ? per_cpu(gdt_l1e, cpu)
                                   : per_cpu(compat_gdt_l1e, cpu));
}

static void load_full_gdt(const struct vcpu *v, unsigned int cpu)
{
    struct desc_ptr gdt_desc = {
        .limit = LAST_RESERVED_GDT_BYTE,
        .base = GDT_VIRT_START(v),
    };

    lgdt(&gdt_desc);

    per_cpu(full_gdt_loaded, cpu) = true;
}

static void load_default_gdt(unsigned int cpu)
{
    struct desc_ptr gdt_desc = {
        .limit = LAST_RESERVED_GDT_BYTE,
        .base  = (unsigned long)(per_cpu(gdt, cpu) - FIRST_RESERVED_GDT_ENTRY),
    };

    lgdt(&gdt_desc);

    per_cpu(full_gdt_loaded, cpu) = false;
}

static void __context_switch(void)
{
    struct cpu_user_regs *stack_regs = guest_cpu_user_regs();
    unsigned int          cpu = smp_processor_id();
    struct vcpu          *p = per_cpu(curr_vcpu, cpu);
    struct vcpu          *n = current;
    struct domain        *pd = p->domain, *nd = n->domain;

    ASSERT(p != n);
    ASSERT(!vcpu_cpu_dirty(n));

    if ( !is_idle_domain(pd) )
    {
        memcpy(&p->arch.user_regs, stack_regs, CTXT_SWITCH_STACK_BYTES);
        vcpu_save_fpu(p);
        pd->arch.ctxt_switch->from(p);
    }

    /*
     * Mark this CPU in next domain's dirty cpumasks before calling
     * ctxt_switch_to(). This avoids a race on things like EPT flushing,
     * which is synchronised on that function.
     */
    if ( pd != nd )
        cpumask_set_cpu(cpu, nd->dirty_cpumask);
    write_atomic(&n->dirty_cpu, cpu);

    if ( !is_idle_domain(nd) )
    {
        memcpy(stack_regs, &n->arch.user_regs, CTXT_SWITCH_STACK_BYTES);
        if ( cpu_has_xsave )
        {
            u64 xcr0 = n->arch.xcr0 ?: XSTATE_FP_SSE;

            if ( xcr0 != get_xcr0() && !set_xcr0(xcr0) )
                BUG();

            if ( cpu_has_xsaves && is_hvm_vcpu(n) )
                set_msr_xss(n->arch.msrs->xss.raw);
        }
        vcpu_restore_fpu_nonlazy(n, false);
        nd->arch.ctxt_switch->to(n);
    }

    psr_ctxt_switch_to(nd);

    if ( need_full_gdt(nd) )
        update_xen_slot_in_full_gdt(n, cpu);

    if ( per_cpu(full_gdt_loaded, cpu) &&
         ((p->vcpu_id != n->vcpu_id) || !need_full_gdt(nd)) )
        load_default_gdt(cpu);

    write_ptbase(n);

#if defined(CONFIG_PV) && defined(CONFIG_HVM)
    /* Prefetch the VMCB if we expect to use it later in the context switch */
    if ( cpu_has_svm && is_pv_domain(nd) && !is_pv_32bit_domain(nd) &&
         !is_idle_domain(nd) && !(read_cr4() & X86_CR4_FSGSBASE) )
        svm_load_segs(0, 0, 0, 0, 0, 0, 0);
#endif

    if ( need_full_gdt(nd) && !per_cpu(full_gdt_loaded, cpu) )
        load_full_gdt(n, cpu);

    if ( pd != nd )
        cpumask_clear_cpu(cpu, pd->dirty_cpumask);
    write_atomic(&p->dirty_cpu, VCPU_CPU_CLEAN);

    per_cpu(curr_vcpu, cpu) = n;
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    unsigned int cpu = smp_processor_id();
    const struct domain *prevd = prev->domain, *nextd = next->domain;
    unsigned int dirty_cpu = next->dirty_cpu;

    ASSERT(prev != next);
    ASSERT(local_irq_is_enabled());

    get_cpu_info()->use_pv_cr3 = false;
    get_cpu_info()->xen_cr3 = 0;

    if ( unlikely(dirty_cpu != cpu) && dirty_cpu != VCPU_CPU_CLEAN )
    {
        /* Remote CPU calls __sync_local_execstate() from flush IPI handler. */
        flush_mask(cpumask_of(dirty_cpu), FLUSH_VCPU_STATE);
    }

    _update_runstate_area(prev);
    vpmu_switch_from(prev);
    np2m_schedule(NP2M_SCHEDLE_OUT);

    if ( is_hvm_domain(prevd) && !list_empty(&prev->arch.hvm.tm_list) )
        pt_save_timer(prev);

    local_irq_disable();

    set_current(next);

    if ( (per_cpu(curr_vcpu, cpu) == next) ||
         (is_idle_domain(nextd) && cpu_online(cpu)) )
    {
        local_irq_enable();
    }
    else
    {
        __context_switch();

        /* Re-enable interrupts before restoring state which may fault. */
        local_irq_enable();

        if ( is_pv_domain(nextd) )
            load_segments(next);

        ctxt_switch_levelling(next);

        if ( opt_ibpb && !is_idle_domain(nextd) )
        {
            static DEFINE_PER_CPU(unsigned int, last);
            unsigned int *last_id = &this_cpu(last);

            /*
             * Squash the domid and vcpu id together for comparison
             * efficiency.  We could in principle stash and compare the struct
             * vcpu pointer, but this risks a false alias if a domain has died
             * and the same 4k page gets reused for a new vcpu.
             */
            unsigned int next_id = (((unsigned int)nextd->domain_id << 16) |
                                    (uint16_t)next->vcpu_id);
            BUILD_BUG_ON(MAX_VIRT_CPUS > 0xffff);

            /*
             * When scheduling from a vcpu, to idle, and back to the same vcpu
             * (which might be common in a lightly loaded system, or when
             * using vcpu pinning), there is no need to issue IBPB, as we are
             * returning to the same security context.
             */
            if ( *last_id != next_id )
            {
                wrmsrl(MSR_PRED_CMD, PRED_CMD_IBPB);
                *last_id = next_id;
            }
        }
    }

    sched_context_switched(prev, next);

    _update_runstate_area(next);
    /* Must be done with interrupts enabled */
    vpmu_switch_to(next);
    np2m_schedule(NP2M_SCHEDLE_IN);

    /* Ensure that the vcpu has an up-to-date time base. */
    update_vcpu_system_time(next);

    /*
     * Schedule tail *should* be a terminal function pointer, but leave a
     * bug frame around just in case it returns, to save going back into the
     * context switching code and leaving a far more subtle crash to diagnose.
     */
    nextd->arch.ctxt_switch->tail(next);
    BUG();
}

void continue_running(struct vcpu *same)
{
    /* See the comment above. */
    same->domain->arch.ctxt_switch->tail(same);
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

void sync_vcpu_execstate(struct vcpu *v)
{
    if ( v->dirty_cpu == smp_processor_id() )
        sync_local_execstate();
    else if ( vcpu_cpu_dirty(v) )
    {
        /* Remote CPU calls __sync_local_execstate() from flush IPI handler. */
        flush_mask(cpumask_of(v->dirty_cpu), FLUSH_VCPU_STATE);
    }
}

static int relinquish_memory(
    struct domain *d, struct page_list_head *list, unsigned long type)
{
    struct page_info  *page;
    unsigned long     x, y;
    int               ret = 0;

    /* Use a recursive lock, as we may enter 'free_domheap_page'. */
    spin_lock_recursive(&d->page_alloc_lock);

    while ( (page = page_list_remove_head(list)) )
    {
        /* Grab a reference to the page so it won't disappear from under us. */
        if ( unlikely(!get_page(page, d)) )
        {
            /* Couldn't get a reference -- someone is freeing this page. */
            page_list_add_tail(page, &d->arch.relmem_list);
            continue;
        }

        if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
            ret = put_page_and_type_preemptible(page);
        switch ( ret )
        {
        case 0:
            break;
        case -ERESTART:
        case -EINTR:
            ret = -ERESTART;
            page_list_add(page, list);
            set_bit(_PGT_pinned, &page->u.inuse.type_info);
            put_page(page);
            goto out;
        default:
            BUG();
        }

        put_page_alloc_ref(page);

        /*
         * Forcibly invalidate top-most, still valid page tables at this point
         * to break circular 'linear page table' references as well as clean up
         * partially validated pages. This is okay because MMU structures are
         * not shared across domains and this domain is now dead. Thus top-most
         * valid tables are not in use so a non-zero count means circular
         * reference or partially validated.
         */
        y = page->u.inuse.type_info;
        for ( ; ; )
        {
            x = y;
            if ( likely((x & PGT_type_mask) != type) ||
                 likely(!(x & (PGT_validated|PGT_partial))) )
                break;

            y = cmpxchg(&page->u.inuse.type_info, x,
                        x & ~(PGT_validated|PGT_partial));
            if ( likely(y == x) )
            {
                /* No need for atomic update of type_info here: noone else updates it. */
                switch ( ret = free_page_type(page, x, 1) )
                {
                case 0:
                    break;
                case -EINTR:
                    page_list_add(page, list);
                    page->u.inuse.type_info |= PGT_validated;
                    if ( x & PGT_partial )
                        put_page(page);
                    put_page(page);
                    ret = -ERESTART;
                    goto out;
                case -ERESTART:
                    page_list_add(page, list);
                    page->u.inuse.type_info |= PGT_partial;
                    if ( x & PGT_partial )
                        put_page(page);
                    goto out;
                default:
                    BUG();
                }
                if ( x & PGT_partial )
                {
                    page->u.inuse.type_info--;
                    put_page(page);
                }
                break;
            }
        }

        /* Put the page on the list and /then/ potentially free it. */
        page_list_add_tail(page, &d->arch.relmem_list);
        put_page(page);

        if ( hypercall_preempt_check() )
        {
            ret = -ERESTART;
            goto out;
        }
    }

    /* list is empty at this point. */
    page_list_move(list, &d->arch.relmem_list);

 out:
    spin_unlock_recursive(&d->page_alloc_lock);
    return ret;
}

int domain_relinquish_resources(struct domain *d)
{
    int ret;
    struct vcpu *v;

    BUG_ON(!cpumask_empty(d->dirty_cpumask));

    /*
     * This hypercall can take minutes of wallclock time to complete.  This
     * logic implements a co-routine, stashing state in struct domain across
     * hypercall continuation boundaries.
     */
    switch ( d->arch.rel_priv )
    {
        /*
         * Record the current progress.  Subsequent hypercall continuations
         * will logically restart work from this point.
         *
         * PROGRESS() markers must not be in the middle of loops.  The loop
         * variable isn't preserved across a continuation.
         *
         * To avoid redundant work, there should be a marker before each
         * function which may return -ERESTART.
         */
#define PROGRESS(x)                                                     \
        d->arch.rel_priv = PROG_ ## x; /* Fallthrough */ case PROG_ ## x

        enum {
            PROG_paging = 1,
            PROG_vcpu_pagetables,
            PROG_shared,
            PROG_xen,
            PROG_l4,
            PROG_l3,
            PROG_l2,
            PROG_done,
        };

    case 0:
        ret = pci_release_devices(d);
        if ( ret )
            return ret;

    PROGRESS(paging):

        /* Tear down paging-assistance stuff. */
        ret = paging_teardown(d);
        if ( ret )
            return ret;

    PROGRESS(vcpu_pagetables):

        /* Drop the in-use references to page-table bases. */
        for_each_vcpu ( d, v )
        {
            ret = vcpu_destroy_pagetables(v);
            if ( ret )
                return ret;
        }

        if ( altp2m_active(d) )
        {
            for_each_vcpu ( d, v )
                altp2m_vcpu_disable_ve(v);
        }

        if ( is_pv_domain(d) )
        {
            for_each_vcpu ( d, v )
            {
                /* Relinquish GDT/LDT mappings. */
                pv_destroy_ldt(v);
                pv_destroy_gdt(v);
            }
        }

        if ( d->arch.pirq_eoi_map != NULL )
        {
            unmap_domain_page_global(d->arch.pirq_eoi_map);
            put_page_and_type(mfn_to_page(_mfn(d->arch.pirq_eoi_map_mfn)));
            d->arch.pirq_eoi_map = NULL;
            d->arch.auto_unmask = 0;
        }

#ifdef CONFIG_MEM_SHARING
    PROGRESS(shared):

        if ( is_hvm_domain(d) )
        {
            /* If the domain has shared pages, relinquish them allowing
             * for preemption. */
            ret = relinquish_shared_pages(d);
            if ( ret )
                return ret;
        }
#endif

        spin_lock(&d->page_alloc_lock);
        page_list_splice(&d->arch.relmem_list, &d->page_list);
        INIT_PAGE_LIST_HEAD(&d->arch.relmem_list);
        spin_unlock(&d->page_alloc_lock);

    PROGRESS(xen):

        ret = relinquish_memory(d, &d->xenpage_list, ~0UL);
        if ( ret )
            return ret;

    PROGRESS(l4):

        ret = relinquish_memory(d, &d->page_list, PGT_l4_page_table);
        if ( ret )
            return ret;

    PROGRESS(l3):

        ret = relinquish_memory(d, &d->page_list, PGT_l3_page_table);
        if ( ret )
            return ret;

    PROGRESS(l2):

        ret = relinquish_memory(d, &d->page_list, PGT_l2_page_table);
        if ( ret )
            return ret;

    PROGRESS(done):
        break;

#undef PROGRESS

    default:
        BUG();
    }

    pit_deinit(d);

    if ( is_hvm_domain(d) )
        hvm_domain_relinquish_resources(d);

    return 0;
}

/*
 * Called during vcpu construction, and each time the toolstack changes the
 * CPUID configuration for the domain.
 */
void cpuid_policy_updated(struct vcpu *v)
{
    if ( is_hvm_vcpu(v) )
        hvm_cpuid_policy_changed(v);
}

void arch_dump_domain_info(struct domain *d)
{
    paging_dump_domain_info(d);
}

void arch_dump_vcpu_info(struct vcpu *v)
{
    paging_dump_vcpu_info(v);

    vpmu_dump(v);
}

void vcpu_kick(struct vcpu *v)
{
    /*
     * NB1. 'pause_flags' and 'processor' must be checked /after/ update of
     * pending flag. These values may fluctuate (after all, we hold no
     * locks) but the key insight is that each change will cause
     * evtchn_upcall_pending to be polled.
     * 
     * NB2. We save the running flag across the unblock to avoid a needless
     * IPI for domains that we IPI'd to unblock.
     */
    bool running = v->is_running;

    vcpu_unblock(v);
    if ( running && (in_irq() || (v != current)) )
        cpu_raise_softirq(v->processor, VCPU_KICK_SOFTIRQ);
}

void vcpu_mark_events_pending(struct vcpu *v)
{
    int already_pending = test_and_set_bit(
        0, (unsigned long *)&vcpu_info(v, evtchn_upcall_pending));

    if ( already_pending )
        return;

    if ( is_hvm_vcpu(v) )
        hvm_assert_evtchn_irq(v);
    else
        vcpu_kick(v);
}

static void vcpu_kick_softirq(void)
{
    /*
     * Nothing to do here: we merely prevent notifiers from racing with checks
     * executed on return to guest context with interrupts enabled. See, for
     * example, xxx_intr_assist() executed on return to HVM guest context.
     */
}

static int __init init_vcpu_kick_softirq(void)
{
    open_softirq(VCPU_KICK_SOFTIRQ, vcpu_kick_softirq);
    return 0;
}
__initcall(init_vcpu_kick_softirq);


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
