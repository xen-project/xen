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
#include <asm/hvm/viridian.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
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

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

static void default_idle(void);
void (*pm_idle) (void) __read_mostly = default_idle;
void (*dead_idle) (void) __read_mostly = default_dead_idle;

static void default_idle(void)
{
    local_irq_disable();
    if ( cpu_is_haltable(smp_processor_id()) )
        safe_halt();
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
    wbinvd();
    for ( ; ; )
        halt();
}

static void play_dead(void)
{
    local_irq_disable();

    /*
     * NOTE: After cpu_exit_clear, per-cpu variables are no longer accessible,
     * as they may be freed at any time. In this case, heap corruption or
     * #PF can occur (when heap debugging is enabled). For example, even
     * printk() can involve tasklet scheduling, which touches per-cpu vars.
     * 
     * Consider very carefully when adding code to *dead_idle. Most hypervisor
     * subsystems are unsafe to call.
     */
    cpu_exit_clear(smp_processor_id());

    (*dead_idle)();
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

void startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));
    cpumask_set_cpu(v->processor, v->domain->domain_dirty_cpumask);
    cpumask_set_cpu(v->processor, v->vcpu_dirty_cpumask);

    reset_stack_and_jump(idle_loop);
}

static void noreturn continue_idle_domain(struct vcpu *v)
{
    reset_stack_and_jump(idle_loop);
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
                   _p(page_to_mfn(page)),
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
               _p(page_to_mfn(page)),
               page->count_info, page->u.inuse.type_info);
    }
    spin_unlock(&d->page_alloc_lock);
}

void update_guest_memory_policy(struct vcpu *v,
                                struct guest_memory_policy *policy)
{
    smap_check_policy_t old_smap_policy = v->arch.smap_check_policy;
    bool old_guest_mode = nestedhvm_is_n2(v);
    bool new_guest_mode = policy->nested_guest_mode;

    v->arch.smap_check_policy = policy->smap_policy;
    policy->smap_policy = old_smap_policy;

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


#ifndef CONFIG_LOCK_PROFILE
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
    lock_profile_deregister_struct(LOCKPROF_TYPE_PERDOM, d);
    free_xenheap_page(d);
}

struct vcpu *alloc_vcpu_struct(void)
{
    struct vcpu *v;
    /*
     * This structure contains embedded PAE PDPTEs, used when an HVM guest
     * runs on shadow pagetables outside of 64-bit mode. In this case the CPU
     * may require that the shadow CR3 points below 4GB, and hence the whole
     * structure must satisfy this restriction. Thus we specify MEMF_bits(32).
     */
    BUILD_BUG_ON(sizeof(*v) > PAGE_SIZE);
    v = alloc_xenheap_pages(0, MEMF_bits(32));
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
        v->arch.msr = ZERO_BLOCK_PTR; /* Catch stray misuses */
    }

    if ( rc )
        goto fail;

    if ( !is_idle_domain(v->domain) )
    {
        vpmu_initialise(v);

        if ( (rc = init_vcpu_msr_policy(v)) )
            goto fail;
    }

    return rc;

 fail:
    vcpu_destroy_fpu(v);
    xfree(v->arch.msr);
    v->arch.msr = NULL;

    return rc;
}

void vcpu_destroy(struct vcpu *v)
{
    xfree(v->arch.vm_event);
    v->arch.vm_event = NULL;

    vcpu_destroy_fpu(v);

    xfree(v->arch.msr);
    v->arch.msr = NULL;

    if ( !is_idle_domain(v->domain) )
        vpmu_destroy(v);

    if ( is_hvm_vcpu(v) )
        hvm_vcpu_destroy(v);
    else
        pv_vcpu_destroy(v);
}

static bool emulation_flags_ok(const struct domain *d, uint32_t emflags)
{

    if ( is_hvm_domain(d) )
    {
        if ( is_hardware_domain(d) &&
             emflags != (XEN_X86_EMU_LAPIC|XEN_X86_EMU_IOAPIC) )
            return false;
        if ( !is_hardware_domain(d) && emflags &&
             emflags != XEN_X86_EMU_ALL && emflags != XEN_X86_EMU_LAPIC )
            return false;
    }
    else if ( emflags != 0 && emflags != XEN_X86_EMU_PIT )
    {
        /* PV or classic PVH. */
        return false;
    }

    return true;
}

int arch_domain_create(struct domain *d, unsigned int domcr_flags,
                       struct xen_arch_domainconfig *config)
{
    bool paging_initialised = false;
    int rc;

    if ( config == NULL && !is_idle_domain(d) )
        return -EINVAL;

    d->arch.s3_integrity = !!(domcr_flags & DOMCRF_s3_integrity);

    INIT_LIST_HEAD(&d->arch.pdev_list);

    d->arch.relmem = RELMEM_not_started;
    INIT_PAGE_LIST_HEAD(&d->arch.relmem_list);

    if ( d->domain_id && !is_idle_domain(d) &&
         cpu_has_amd_erratum(&boot_cpu_data, AMD_ERRATUM_121) )
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

    if ( is_idle_domain(d) )
    {
        d->arch.emulation_flags = 0;
        d->arch.cpuid = ZERO_BLOCK_PTR; /* Catch stray misuses. */
        d->arch.msr = ZERO_BLOCK_PTR;
    }
    else
    {
        uint32_t emflags;

        if ( is_hardware_domain(d) && is_pv_domain(d) )
            config->emulation_flags |= XEN_X86_EMU_PIT;

        emflags = config->emulation_flags;
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
    }

    mapcache_domain_init(d);

    HYPERVISOR_COMPAT_VIRT_START(d) =
        is_pv_domain(d) ? __HYPERVISOR_COMPAT_VIRT_START : ~0u;

    if ( !is_idle_domain(d) )
    {
        /* Need to determine if HAP is enabled before initialising paging */
        if ( is_hvm_domain(d) )
            d->arch.hvm_domain.hap_enabled =
                hvm_funcs.hap_supported && (domcr_flags & DOMCRF_hap);

        if ( (rc = paging_domain_init(d, domcr_flags)) != 0 )
            goto fail;
        paging_initialised = 1;

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
        share_xen_page_with_guest(
            virt_to_page(d->shared_info), d, XENSHARE_writable);

        if ( (rc = init_domain_irq_mapping(d)) != 0 )
            goto fail;

        if ( (rc = iommu_domain_init(d)) != 0 )
            goto fail;
    }
    spin_lock_init(&d->arch.e820_lock);

    psr_domain_init(d);

    if ( is_hvm_domain(d) )
    {
        if ( (rc = hvm_domain_initialise(d, domcr_flags, config)) != 0 )
            goto fail;
    }
    else if ( is_idle_domain(d) )
    {
        static const struct arch_csw idle_csw = {
            .from = paravirt_ctxt_switch_from,
            .to   = paravirt_ctxt_switch_to,
            .tail = continue_idle_domain,
        };

        d->arch.ctxt_switch = &idle_csw;
    }
    else
    {
        if ( (rc = pv_domain_initialise(d, domcr_flags, config)) != 0 )
            goto fail;
    }

    /* initialize default tsc behavior in case tools don't */
    tsc_set_info(d, TSC_MODE_DEFAULT, 0UL, 0, 0);
    spin_lock_init(&d->arch.vtsc_lock);

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
    if ( has_viridian_time_ref_count(d) )
        viridian_time_ref_count_freeze(d);
}

void arch_domain_pause(struct domain *d)
{
    if ( has_viridian_time_ref_count(d) )
        viridian_time_ref_count_freeze(d);
}

void arch_domain_unpause(struct domain *d)
{
    if ( has_viridian_time_ref_count(d) )
        viridian_time_ref_count_thaw(d);
}

int arch_domain_soft_reset(struct domain *d)
{
    struct page_info *page = virt_to_page(d->shared_info), *new_page;
    int ret = 0;
    struct domain *owner;
    unsigned long mfn, gfn;
    p2m_type_t p2mt;
    unsigned int i;

    /* Soft reset is supported for HVM domains only. */
    if ( !is_hvm_domain(d) )
        return -EINVAL;

    hvm_domain_soft_reset(d);

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
    gfn = mfn_to_gmfn(d, mfn);

    /*
     * gfn == INVALID_GFN indicates that the shared_info page was never mapped
     * to the domain's address space and there is nothing to replace.
     */
    if ( gfn == gfn_x(INVALID_GFN) )
        goto exit_put_page;

    if ( mfn_x(get_gfn_query(d, gfn, &p2mt)) != mfn )
    {
        printk(XENLOG_G_ERR "Failed to get Dom%d's shared_info GFN (%lx)\n",
               d->domain_id, gfn);
        ret = -EINVAL;
        goto exit_put_page;
    }

    new_page = alloc_domheap_page(d, 0);
    if ( !new_page )
    {
        printk(XENLOG_G_ERR "Failed to alloc a page to replace"
               " Dom%d's shared_info frame %lx\n", d->domain_id, gfn);
        ret = -ENOMEM;
        goto exit_put_gfn;
    }

    ret = guest_physmap_remove_page(d, _gfn(gfn), _mfn(mfn), PAGE_ORDER_4K);
    if ( ret )
    {
        printk(XENLOG_G_ERR "Failed to remove Dom%d's shared_info frame %lx\n",
               d->domain_id, gfn);
        free_domheap_page(new_page);
        goto exit_put_gfn;
    }

    ret = guest_physmap_add_page(d, _gfn(gfn), _mfn(page_to_mfn(new_page)),
                                 PAGE_ORDER_4K);
    if ( ret )
    {
        printk(XENLOG_G_ERR "Failed to add a page to replace"
               " Dom%d's shared_info frame %lx\n", d->domain_id, gfn);
        free_domheap_page(new_page);
    }
 exit_put_gfn:
    put_gfn(d, gfn);
 exit_put_page:
    put_page(page);

    return ret;
}

/*
 * These are the masks of CR4 bits (subject to hardware availability) which a
 * PV guest may not legitimiately attempt to modify.
 */
static unsigned long __read_mostly pv_cr4_mask, compat_pv_cr4_mask;

static int __init init_pv_cr4_masks(void)
{
    unsigned long common_mask = ~X86_CR4_TSD;

    /*
     * All PV guests may attempt to modify TSD, DE and OSXSAVE.
     */
    if ( cpu_has_de )
        common_mask &= ~X86_CR4_DE;
    if ( cpu_has_xsave )
        common_mask &= ~X86_CR4_OSXSAVE;

    pv_cr4_mask = compat_pv_cr4_mask = common_mask;

    /*
     * 64bit PV guests may attempt to modify FSGSBASE.
     */
    if ( cpu_has_fsgsbase )
        pv_cr4_mask &= ~X86_CR4_FSGSBASE;

    return 0;
}
__initcall(init_pv_cr4_masks);

unsigned long pv_guest_cr4_fixup(const struct vcpu *v, unsigned long guest_cr4)
{
    unsigned long hv_cr4 = real_cr4_to_pv_guest_cr4(read_cr4());
    unsigned long mask = is_pv_32bit_vcpu(v) ? compat_pv_cr4_mask : pv_cr4_mask;

    if ( (guest_cr4 & mask) != (hv_cr4 & mask) )
        printk(XENLOG_G_WARNING
               "d%d attempted to change %pv's CR4 flags %08lx -> %08lx\n",
               current->domain->domain_id, v, hv_cr4, guest_cr4);

    return (hv_cr4 & mask) | (guest_cr4 & ~mask);
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
    unsigned long cr3_gfn;
    struct page_info *cr3_page;
    unsigned long flags, cr4;
    unsigned int i;
    int rc = 0, compat;

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

    v->fpu_initialised = !!(flags & VGCF_I387_VALID);

    v->arch.flags &= ~TF_kernel_mode;
    if ( (flags & VGCF_in_kernel) || is_hvm_domain(d)/*???*/ )
        v->arch.flags |= TF_kernel_mode;

    v->arch.vgc_flags = flags;

    if ( flags & VGCF_I387_VALID )
    {
        memcpy(v->arch.fpu_ctxt, &c.nat->fpu_ctxt, sizeof(c.nat->fpu_ctxt));
        if ( v->arch.xsave_area )
            v->arch.xsave_area->xsave_hdr.xstate_bv = XSTATE_FP_SSE;
    }
    else if ( v->arch.xsave_area )
    {
        v->arch.xsave_area->xsave_hdr.xstate_bv = 0;
        v->arch.xsave_area->fpu_sse.mxcsr = MXCSR_DEFAULT;
    }
    else
    {
        typeof(v->arch.xsave_area->fpu_sse) *fpu_sse = v->arch.fpu_ctxt;

        memset(fpu_sse, 0, sizeof(*fpu_sse));
        fpu_sse->fcw = FCW_DEFAULT;
        fpu_sse->mxcsr = MXCSR_DEFAULT;
    }
    if ( v->arch.xsave_area )
        v->arch.xsave_area->xsave_hdr.xcomp_bv = 0;

    if ( !compat )
    {
        memcpy(&v->arch.user_regs, &c.nat->user_regs, sizeof(c.nat->user_regs));
        if ( is_pv_domain(d) )
            memcpy(v->arch.pv_vcpu.trap_ctxt, c.nat->trap_ctxt,
                   sizeof(c.nat->trap_ctxt));
    }
    else
    {
        XLAT_cpu_user_regs(&v->arch.user_regs, &c.cmp->user_regs);
        if ( is_pv_domain(d) )
        {
            for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); ++i )
                XLAT_trap_info(v->arch.pv_vcpu.trap_ctxt + i,
                               c.cmp->trap_ctxt + i);
        }
    }

    if ( is_hvm_domain(d) )
    {
        for ( i = 0; i < ARRAY_SIZE(v->arch.debugreg); ++i )
            v->arch.debugreg[i] = c(debugreg[i]);

        hvm_set_info_guest(v);
        goto out;
    }

    init_int80_direct_trap(v);

    /* IOPL privileges are virtualised. */
    v->arch.pv_vcpu.iopl = v->arch.user_regs.eflags & X86_EFLAGS_IOPL;
    v->arch.user_regs.eflags &= ~X86_EFLAGS_IOPL;

    /* Ensure real hardware interrupts are enabled. */
    v->arch.user_regs.eflags |= X86_EFLAGS_IF;

    if ( !v->is_initialised )
    {
        if ( !compat && !(flags & VGCF_in_kernel) && !c.nat->ctrlreg[1] )
            return -EINVAL;

        v->arch.pv_vcpu.ldt_base = c(ldt_base);
        v->arch.pv_vcpu.ldt_ents = c(ldt_ents);
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

        for ( i = 0; i < ARRAY_SIZE(v->arch.pv_vcpu.gdt_frames); ++i )
            fail |= v->arch.pv_vcpu.gdt_frames[i] != c(gdt_frames[i]);
        fail |= v->arch.pv_vcpu.gdt_ents != c(gdt_ents);

        fail |= v->arch.pv_vcpu.ldt_base != c(ldt_base);
        fail |= v->arch.pv_vcpu.ldt_ents != c(ldt_ents);

        if ( fail )
           return -EOPNOTSUPP;
    }

    v->arch.pv_vcpu.kernel_ss = c(kernel_ss);
    v->arch.pv_vcpu.kernel_sp = c(kernel_sp);
    for ( i = 0; i < ARRAY_SIZE(v->arch.pv_vcpu.ctrlreg); ++i )
        v->arch.pv_vcpu.ctrlreg[i] = c(ctrlreg[i]);

    v->arch.pv_vcpu.event_callback_eip = c(event_callback_eip);
    v->arch.pv_vcpu.failsafe_callback_eip = c(failsafe_callback_eip);
    if ( !compat )
    {
        v->arch.pv_vcpu.syscall_callback_eip = c.nat->syscall_callback_eip;
        v->arch.pv_vcpu.fs_base = c.nat->fs_base;
        v->arch.pv_vcpu.gs_base_kernel = c.nat->gs_base_kernel;
        v->arch.pv_vcpu.gs_base_user = c.nat->gs_base_user;
    }
    else
    {
        v->arch.pv_vcpu.event_callback_cs = c(event_callback_cs);
        v->arch.pv_vcpu.failsafe_callback_cs = c(failsafe_callback_cs);
    }

    /* Only CR0.TS is modifiable by guest or admin. */
    v->arch.pv_vcpu.ctrlreg[0] &= X86_CR0_TS;
    v->arch.pv_vcpu.ctrlreg[0] |= read_cr0() & ~X86_CR0_TS;

    cr4 = v->arch.pv_vcpu.ctrlreg[4];
    v->arch.pv_vcpu.ctrlreg[4] = cr4 ? pv_guest_cr4_fixup(v, cr4) :
        real_cr4_to_pv_guest_cr4(mmu_cr4_features);

    memset(v->arch.debugreg, 0, sizeof(v->arch.debugreg));
    for ( i = 0; i < 8; i++ )
        (void)set_debugreg(v, i, c(debugreg[i]));

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
             atomic_read(&d->arch.pv_domain.nr_l4_pages) )
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
                        done = !fill_ro_mpt(_mfn(page_to_mfn(page)));

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
        unsigned long gdt_frames[ARRAY_SIZE(v->arch.pv_vcpu.gdt_frames)];
        unsigned int n = (c.cmp->gdt_ents + 511) / 512;

        if ( n > ARRAY_SIZE(v->arch.pv_vcpu.gdt_frames) )
            return -EINVAL;
        for ( i = 0; i < n; ++i )
            gdt_frames[i] = c.cmp->gdt_frames[i];
        rc = (int)pv_set_gdt(v, gdt_frames, c.cmp->gdt_ents);
    }
    if ( rc != 0 )
        return rc;

    set_bit(_VPF_in_reset, &v->pause_flags);

    if ( !compat )
        cr3_gfn = xen_cr3_to_pfn(c.nat->ctrlreg[3]);
    else
        cr3_gfn = compat_cr3_to_pfn(c.cmp->ctrlreg[3]);
    cr3_page = get_page_from_gfn(d, cr3_gfn, NULL, P2M_ALLOC);

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
                fill_ro_mpt(_mfn(cr3_gfn));
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
            cr3_gfn = xen_cr3_to_pfn(c.nat->ctrlreg[1]);
            cr3_page = get_page_from_gfn(d, cr3_gfn, NULL, P2M_ALLOC);

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
                        zap_ro_mpt(_mfn(cr3_gfn));
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
        *l4tab = l4e_from_pfn(page_to_mfn(cr3_page),
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
        if ( !is_pinned_vcpu(v) )
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
 * Loading a nul selector does not clear bases and limits on AMD CPUs. Be on
 * the safe side and re-initialize both to flat segment values before loading
 * a nul selector.
 */
#define preload_segment(seg, value) do {              \
    if ( !((value) & ~3) &&                           \
         boot_cpu_data.x86_vendor == X86_VENDOR_AMD ) \
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
#define DIRTY_GS_BASE_USER 0x20

static void load_segments(struct vcpu *n)
{
    struct cpu_user_regs *uregs = &n->arch.user_regs;
    int all_segs_okay = 1;
    unsigned int dirty_segment_mask, cpu = smp_processor_id();

    /* Load and clear the dirty segment mask. */
    dirty_segment_mask = per_cpu(dirty_segment_mask, cpu);
    per_cpu(dirty_segment_mask, cpu) = 0;

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
    if ( unlikely((dirty_segment_mask & DIRTY_FS) | uregs->fs) )
    {
        all_segs_okay &= loadsegment(fs, uregs->fs);
        /* non-nul selector updates fs_base */
        if ( uregs->fs & ~3 )
            dirty_segment_mask &= ~DIRTY_FS_BASE;
    }

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_GS) | uregs->gs) )
    {
        all_segs_okay &= loadsegment(gs, uregs->gs);
        /* non-nul selector updates gs_base_user */
        if ( uregs->gs & ~3 )
            dirty_segment_mask &= ~DIRTY_GS_BASE_USER;
    }

    if ( !is_pv_32bit_vcpu(n) )
    {
        /* This can only be non-zero if selector is NULL. */
        if ( n->arch.pv_vcpu.fs_base | (dirty_segment_mask & DIRTY_FS_BASE) )
            wrfsbase(n->arch.pv_vcpu.fs_base);

        /* Most kernels have non-zero GS base, so don't bother testing. */
        /* (This is also a serialising instruction, avoiding AMD erratum #88.) */
        wrmsrl(MSR_SHADOW_GS_BASE, n->arch.pv_vcpu.gs_base_kernel);

        /* This can only be non-zero if selector is NULL. */
        if ( n->arch.pv_vcpu.gs_base_user |
             (dirty_segment_mask & DIRTY_GS_BASE_USER) )
            wrgsbase(n->arch.pv_vcpu.gs_base_user);

        /* If in kernel mode then switch the GS bases around. */
        if ( (n->arch.flags & TF_kernel_mode) )
            asm volatile ( "swapgs" );
    }

    if ( unlikely(!all_segs_okay) )
    {
        struct pv_vcpu *pv = &n->arch.pv_vcpu;
        struct cpu_user_regs *regs = guest_cpu_user_regs();
        unsigned long *rsp =
            (unsigned long *)(((n->arch.flags & TF_kernel_mode)
                               ? regs->rsp : pv->kernel_sp) & ~0xf);
        unsigned long cs_and_mask, rflags;

        /* Fold upcall mask and architectural IOPL into RFLAGS.IF. */
        rflags  = regs->rflags & ~(X86_EFLAGS_IF|X86_EFLAGS_IOPL);
        rflags |= !vcpu_info(n, evtchn_upcall_mask) << 9;
        if ( VM_ASSIST(n->domain, architectural_iopl) )
            rflags |= n->arch.pv_vcpu.iopl;

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

    if ( cpu_has_fsgsbase && !is_pv_32bit_vcpu(v) )
    {
        v->arch.pv_vcpu.fs_base = __rdfsbase();
        if ( v->arch.flags & TF_kernel_mode )
            v->arch.pv_vcpu.gs_base_kernel = __rdgsbase();
        else
            v->arch.pv_vcpu.gs_base_user = __rdgsbase();
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
            v->arch.pv_vcpu.fs_base = 0;
    }
    if ( v->arch.pv_vcpu.fs_base )
        dirty_segment_mask |= DIRTY_FS_BASE;

    if ( regs->gs || is_pv_32bit_vcpu(v) )
    {
        dirty_segment_mask |= DIRTY_GS;
        /* non-nul selector kills gs_base_user */
        if ( regs->gs & ~3 )
            v->arch.pv_vcpu.gs_base_user = 0;
    }
    if ( v->arch.flags & TF_kernel_mode ? v->arch.pv_vcpu.gs_base_kernel
                                        : v->arch.pv_vcpu.gs_base_user )
        dirty_segment_mask |= DIRTY_GS_BASE_USER;

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
    if ( unlikely(v->arch.debugreg[7] & DR7_ACTIVE_MASK) )
        write_debugreg(7, 0);
}

void paravirt_ctxt_switch_to(struct vcpu *v)
{
    unsigned long cr4;

    cr4 = pv_guest_cr4_to_real_cr4(v);
    if ( unlikely(cr4 != read_cr4()) )
        write_cr4(cr4);

    if ( unlikely(v->arch.debugreg[7] & DR7_ACTIVE_MASK) )
        activate_debugregs(v);

    if ( (v->domain->arch.tsc_mode ==  TSC_MODE_PVRDTSCP) &&
         boot_cpu_has(X86_FEATURE_RDTSCP) )
        write_rdtscp_aux(v->domain->arch.incarnation);
}

/* Update per-VCPU guest runstate shared memory area (if registered). */
bool update_runstate_area(struct vcpu *v)
{
    bool rc;
    struct guest_memory_policy policy =
        { .smap_policy = SMAP_CHECK_ENABLED, .nested_guest_mode = false };
    void __user *guest_handle = NULL;

    if ( guest_handle_is_null(runstate_guest(v)) )
        return true;

    update_guest_memory_policy(v, &policy);

    if ( VM_ASSIST(v->domain, runstate_update_flag) )
    {
        guest_handle = has_32bit_shinfo(v->domain)
            ? &v->runstate_guest.compat.p->state_entry_time + 1
            : &v->runstate_guest.native.p->state_entry_time + 1;
        guest_handle--;
        v->runstate.state_entry_time |= XEN_RUNSTATE_UPDATE;
        __raw_copy_to_guest(guest_handle,
                            (void *)(&v->runstate.state_entry_time + 1) - 1, 1);
        smp_wmb();
    }

    if ( has_32bit_shinfo(v->domain) )
    {
        struct compat_vcpu_runstate_info info;

        XLAT_vcpu_runstate_info(&info, &v->runstate);
        __copy_to_guest(v->runstate_guest.compat, &info, 1);
        rc = true;
    }
    else
        rc = __copy_to_guest(runstate_guest(v), &v->runstate, 1) !=
             sizeof(v->runstate);

    if ( guest_handle )
    {
        v->runstate.state_entry_time &= ~XEN_RUNSTATE_UPDATE;
        smp_wmb();
        __raw_copy_to_guest(guest_handle,
                            (void *)(&v->runstate.state_entry_time + 1) - 1, 1);
    }

    update_guest_memory_policy(v, &policy);

    return rc;
}

static void _update_runstate_area(struct vcpu *v)
{
    if ( !update_runstate_area(v) && is_pv_vcpu(v) &&
         !(v->arch.flags & TF_kernel_mode) )
        v->arch.pv_vcpu.need_update_runstate_area = 1;
}

static inline bool need_full_gdt(const struct domain *d)
{
    return is_pv_domain(d) && !is_idle_domain(d);
}

static void __context_switch(void)
{
    struct cpu_user_regs *stack_regs = guest_cpu_user_regs();
    unsigned int          cpu = smp_processor_id();
    struct vcpu          *p = per_cpu(curr_vcpu, cpu);
    struct vcpu          *n = current;
    struct domain        *pd = p->domain, *nd = n->domain;
    struct desc_struct   *gdt;
    struct desc_ptr       gdt_desc;

    ASSERT(p != n);
    ASSERT(cpumask_empty(n->vcpu_dirty_cpumask));

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
        cpumask_set_cpu(cpu, nd->domain_dirty_cpumask);
    cpumask_set_cpu(cpu, n->vcpu_dirty_cpumask);

    if ( !is_idle_domain(nd) )
    {
        memcpy(stack_regs, &n->arch.user_regs, CTXT_SWITCH_STACK_BYTES);
        if ( cpu_has_xsave )
        {
            u64 xcr0 = n->arch.xcr0 ?: XSTATE_FP_SSE;

            if ( xcr0 != get_xcr0() && !set_xcr0(xcr0) )
                BUG();

            if ( cpu_has_xsaves && is_hvm_vcpu(n) )
                set_msr_xss(n->arch.hvm_vcpu.msr_xss);
        }
        vcpu_restore_fpu_eager(n);
        nd->arch.ctxt_switch->to(n);
    }

    psr_ctxt_switch_to(nd);

    gdt = !is_pv_32bit_domain(nd) ? per_cpu(gdt_table, cpu) :
                                    per_cpu(compat_gdt_table, cpu);
    if ( need_full_gdt(nd) )
    {
        unsigned long mfn = virt_to_mfn(gdt);
        l1_pgentry_t *pl1e = pv_gdt_ptes(n);
        unsigned int i;

        for ( i = 0; i < NR_RESERVED_GDT_PAGES; i++ )
            l1e_write(pl1e + FIRST_RESERVED_GDT_PAGE + i,
                      l1e_from_pfn(mfn + i, __PAGE_HYPERVISOR_RW));
    }

    if ( need_full_gdt(pd) &&
         ((p->vcpu_id != n->vcpu_id) || !need_full_gdt(nd)) )
    {
        gdt_desc.limit = LAST_RESERVED_GDT_BYTE;
        gdt_desc.base  = (unsigned long)(gdt - FIRST_RESERVED_GDT_ENTRY);
        asm volatile ( "lgdt %0" : : "m" (gdt_desc) );
    }

    write_ptbase(n);

    if ( need_full_gdt(nd) &&
         ((p->vcpu_id != n->vcpu_id) || !need_full_gdt(pd)) )
    {
        gdt_desc.limit = LAST_RESERVED_GDT_BYTE;
        gdt_desc.base = GDT_VIRT_START(n);
        asm volatile ( "lgdt %0" : : "m" (gdt_desc) );
    }

    if ( pd != nd )
        cpumask_clear_cpu(cpu, pd->domain_dirty_cpumask);
    cpumask_clear_cpu(cpu, p->vcpu_dirty_cpumask);

    per_cpu(curr_vcpu, cpu) = n;
}


void context_switch(struct vcpu *prev, struct vcpu *next)
{
    unsigned int cpu = smp_processor_id();
    const struct domain *prevd = prev->domain, *nextd = next->domain;
    cpumask_t dirty_mask;

    ASSERT(local_irq_is_enabled());

    cpumask_copy(&dirty_mask, next->vcpu_dirty_cpumask);
    /* Allow at most one CPU at a time to be dirty. */
    ASSERT(cpumask_weight(&dirty_mask) <= 1);
    if ( unlikely(!cpumask_test_cpu(cpu, &dirty_mask) &&
                  !cpumask_empty(&dirty_mask)) )
    {
        /* Other cpus call __sync_local_execstate from flush ipi handler. */
        flush_tlb_mask(&dirty_mask);
    }

    if ( prev != next )
    {
        _update_runstate_area(prev);
        vpmu_switch_from(prev);
        np2m_schedule(NP2M_SCHEDLE_OUT);
    }

    if ( is_hvm_domain(prevd) && !list_empty(&prev->arch.hvm_vcpu.tm_list) )
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

        if ( is_pv_domain(nextd) &&
             (is_idle_domain(prevd) ||
              is_hvm_domain(prevd) ||
              is_pv_32bit_domain(prevd) != is_pv_32bit_domain(nextd)) )
        {
            uint64_t efer = read_efer();
            if ( !(efer & EFER_SCE) )
                write_efer(efer | EFER_SCE);
        }

        /* Re-enable interrupts before restoring state which may fault. */
        local_irq_enable();

        if ( is_pv_domain(nextd) )
        {
            load_LDT(next);
            load_segments(next);
        }

        ctxt_switch_levelling(next);
    }

    context_saved(prev);

    if ( prev != next )
    {
        _update_runstate_area(next);

        /* Must be done with interrupts enabled */
        vpmu_switch_to(next);
        np2m_schedule(NP2M_SCHEDLE_IN);
    }

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
    if ( cpumask_test_cpu(smp_processor_id(), v->vcpu_dirty_cpumask) )
        sync_local_execstate();

    /* Other cpus call __sync_local_execstate from flush ipi handler. */
    flush_tlb_mask(v->vcpu_dirty_cpumask);
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

        if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
            put_page(page);

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

    BUG_ON(!cpumask_empty(d->domain_dirty_cpumask));

    switch ( d->arch.relmem )
    {
    case RELMEM_not_started:
        ret = pci_release_devices(d);
        if ( ret )
            return ret;

        /* Tear down paging-assistance stuff. */
        ret = paging_teardown(d);
        if ( ret )
            return ret;

        /* Drop the in-use references to page-table bases. */
        for_each_vcpu ( d, v )
        {
            ret = vcpu_destroy_pagetables(v);
            if ( ret )
                return ret;
        }

        if ( is_pv_domain(d) )
        {
            for_each_vcpu ( d, v )
            {
                /*
                 * Relinquish GDT mappings. No need for explicit unmapping of
                 * the LDT as it automatically gets squashed with the guest
                 * mappings.
                 */
                pv_destroy_gdt(v);
            }
        }

        if ( d->arch.pirq_eoi_map != NULL )
        {
            unmap_domain_page_global(d->arch.pirq_eoi_map);
            put_page_and_type(mfn_to_page(d->arch.pirq_eoi_map_mfn));
            d->arch.pirq_eoi_map = NULL;
            d->arch.auto_unmask = 0;
        }

        d->arch.relmem = RELMEM_shared;
        /* fallthrough */

    case RELMEM_shared:

        if ( is_hvm_domain(d) )
        {
            /* If the domain has shared pages, relinquish them allowing
             * for preemption. */
            ret = relinquish_shared_pages(d);
            if ( ret )
                return ret;
        }

        d->arch.relmem = RELMEM_xen;

        spin_lock(&d->page_alloc_lock);
        page_list_splice(&d->arch.relmem_list, &d->page_list);
        INIT_PAGE_LIST_HEAD(&d->arch.relmem_list);
        spin_unlock(&d->page_alloc_lock);

        /* Fallthrough. Relinquish every page of memory. */
    case RELMEM_xen:
        ret = relinquish_memory(d, &d->xenpage_list, ~0UL);
        if ( ret )
            return ret;
        d->arch.relmem = RELMEM_l4;
        /* fallthrough */

    case RELMEM_l4:
        ret = relinquish_memory(d, &d->page_list, PGT_l4_page_table);
        if ( ret )
            return ret;
        d->arch.relmem = RELMEM_l3;
        /* fallthrough */

    case RELMEM_l3:
        ret = relinquish_memory(d, &d->page_list, PGT_l3_page_table);
        if ( ret )
            return ret;
        d->arch.relmem = RELMEM_l2;
        /* fallthrough */

    case RELMEM_l2:
        ret = relinquish_memory(d, &d->page_list, PGT_l2_page_table);
        if ( ret )
            return ret;
        d->arch.relmem = RELMEM_done;
        /* fallthrough */

    case RELMEM_done:
        break;

    default:
        BUG();
    }

    pit_deinit(d);

    if ( is_hvm_domain(d) )
        hvm_domain_relinquish_resources(d);

    return 0;
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
