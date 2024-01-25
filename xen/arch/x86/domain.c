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
#include <public/arch-x86/cpuid.h>
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
#ifdef CONFIG_COMPAT
#include <compat/vcpu.h>
#endif
#include <asm/cpu-policy.h>
#include <asm/psr.h>
#include <asm/pv/domain.h>
#include <asm/pv/mm.h>
#include <asm/spec_ctrl.h>

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

static void cf_check default_idle(void);
void (*pm_idle) (void) __read_mostly = default_idle;
void (*dead_idle) (void) __read_mostly = default_dead_idle;

static void cf_check default_idle(void)
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

void cf_check default_dead_idle(void)
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
    _set_gate_lower(&idt_tables[cpu][X86_EXC_NMI], SYS_DESC_irq_gate, 0,
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

static void noreturn cf_check idle_loop(void)
{
    unsigned int cpu = smp_processor_id();
    /*
     * Idle vcpus might be attached to non-idle units! We don't do any
     * standard idle work like tasklets or livepatching in this case.
     */
    bool guest = !is_idle_domain(current->sched_unit->domain);

    for ( ; ; )
    {
        if ( cpu_is_offline(cpu) )
        {
            ASSERT(!guest);
            play_dead();
        }

        /* Are we here for running vcpu context tasklets, or for idling? */
        if ( !guest && unlikely(tasklet_work_to_do(cpu)) )
        {
            do_tasklet();
            /* Livepatch work is always kicked off via a tasklet. */
            check_for_livepatch_work();
        }
        /*
         * Test softirqs twice --- first to see if should even try scrubbing
         * and then, after it is done, whether softirqs became pending
         * while we were scrubbing.
         */
        else if ( !softirq_pending(cpu) && !scrub_free_pages() &&
                  !softirq_pending(cpu) )
        {
            if ( guest )
                sched_guest_idle(pm_idle, cpu);
            else
                pm_idle();
        }
        do_softirq();
    }
}

void startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));
    cpumask_set_cpu(v->processor, v->domain->dirty_cpumask);
    write_atomic(&v->dirty_cpu, v->processor);

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

    if ( domain_tot_pages(d) >= 10 && d->is_dying < DOMDYING_dead )
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

    page_list_for_each ( page, &d->extra_page_list )
    {
        printk("    ExtraPage %p: caf=%08lx, taf=%" PRtype_info "\n",
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

/*
 * Called during vcpu construction, and each time the toolstack changes the
 * CPU policy configuration for the domain.
 */
static void cpu_policy_updated(struct vcpu *v)
{
    if ( is_hvm_vcpu(v) )
        hvm_cpuid_policy_changed(v);
}

void domain_cpu_policy_changed(struct domain *d)
{
    const struct cpu_policy *p = d->arch.cpu_policy;
    struct vcpu *v;

    if ( is_pv_domain(d) )
    {
        if ( ((levelling_caps & LCAP_1cd) == LCAP_1cd) )
        {
            uint64_t mask = cpuidmask_defaults._1cd;
            uint32_t ecx = p->basic._1c;
            uint32_t edx = p->basic._1d;

            /*
             * Must expose hosts HTT and X2APIC value so a guest using native
             * CPUID can correctly interpret other leaves which cannot be
             * masked.
             */
            if ( cpu_has_x2apic )
                ecx |= cpufeat_mask(X86_FEATURE_X2APIC);
            if ( cpu_has_htt )
                edx |= cpufeat_mask(X86_FEATURE_HTT);

            switch ( boot_cpu_data.x86_vendor )
            {
            case X86_VENDOR_INTEL:
                /*
                 * Intel masking MSRs are documented as AND masks.
                 * Experimentally, they are applied after OSXSAVE and APIC
                 * are fast-forwarded from real hardware state.
                 */
                mask &= ((uint64_t)edx << 32) | ecx;

                if ( ecx & cpufeat_mask(X86_FEATURE_XSAVE) )
                    ecx = cpufeat_mask(X86_FEATURE_OSXSAVE);
                else
                    ecx = 0;
                edx = cpufeat_mask(X86_FEATURE_APIC);

                mask |= ((uint64_t)edx << 32) | ecx;
                break;

            case X86_VENDOR_AMD:
            case X86_VENDOR_HYGON:
                mask &= ((uint64_t)ecx << 32) | edx;

                /*
                 * AMD masking MSRs are documented as overrides.
                 * Experimentally, fast-forwarding of the OSXSAVE and APIC
                 * bits from real hardware state only occurs if the MSR has
                 * the respective bits set.
                 */
                if ( ecx & cpufeat_mask(X86_FEATURE_XSAVE) )
                    ecx = cpufeat_mask(X86_FEATURE_OSXSAVE);
                else
                    ecx = 0;
                edx = cpufeat_mask(X86_FEATURE_APIC);

                /*
                 * If the Hypervisor bit is set in the policy, we can also
                 * forward it into real CPUID.
                 */
                if ( p->basic.hypervisor )
                    ecx |= cpufeat_mask(X86_FEATURE_HYPERVISOR);

                mask |= ((uint64_t)ecx << 32) | edx;
                break;
            }

            d->arch.pv.cpuidmasks->_1cd = mask;
        }

        if ( ((levelling_caps & LCAP_6c) == LCAP_6c) )
        {
            uint64_t mask = cpuidmask_defaults._6c;

            if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
                mask &= (~0ULL << 32) | p->basic.raw[6].c;

            d->arch.pv.cpuidmasks->_6c = mask;
        }

        if ( ((levelling_caps & LCAP_7ab0) == LCAP_7ab0) )
        {
            uint64_t mask = cpuidmask_defaults._7ab0;

            /*
             * Leaf 7[0].eax is max_subleaf, not a feature mask.  Take it
             * wholesale from the policy, but clamp the features in 7[0].ebx
             * per usual.
             */
            if ( boot_cpu_data.x86_vendor &
                 (X86_VENDOR_AMD | X86_VENDOR_HYGON) )
                mask = (((uint64_t)p->feat.max_subleaf << 32) |
                        ((uint32_t)mask & p->feat._7b0));

            d->arch.pv.cpuidmasks->_7ab0 = mask;
        }

        if ( ((levelling_caps & LCAP_Da1) == LCAP_Da1) )
        {
            uint64_t mask = cpuidmask_defaults.Da1;
            uint32_t eax = p->xstate.Da1;

            if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
                mask &= (~0ULL << 32) | eax;

            d->arch.pv.cpuidmasks->Da1 = mask;
        }

        if ( ((levelling_caps & LCAP_e1cd) == LCAP_e1cd) )
        {
            uint64_t mask = cpuidmask_defaults.e1cd;
            uint32_t ecx = p->extd.e1c;
            uint32_t edx = p->extd.e1d;

            /*
             * Must expose hosts CMP_LEGACY value so a guest using native
             * CPUID can correctly interpret other leaves which cannot be
             * masked.
             */
            if ( cpu_has_cmp_legacy )
                ecx |= cpufeat_mask(X86_FEATURE_CMP_LEGACY);

            /*
             * If not emulating AMD or Hygon, clear the duplicated features
             * in e1d.
             */
            if ( !(p->x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON)) )
                edx &= ~CPUID_COMMON_1D_FEATURES;

            switch ( boot_cpu_data.x86_vendor )
            {
            case X86_VENDOR_INTEL:
                mask &= ((uint64_t)edx << 32) | ecx;
                break;

            case X86_VENDOR_AMD:
            case X86_VENDOR_HYGON:
                mask &= ((uint64_t)ecx << 32) | edx;

                /*
                 * Fast-forward bits - Must be set in the masking MSR for
                 * fast-forwarding to occur in hardware.
                 */
                ecx = 0;
                edx = cpufeat_mask(X86_FEATURE_APIC);

                mask |= ((uint64_t)ecx << 32) | edx;
                break;
            }

            d->arch.pv.cpuidmasks->e1cd = mask;
        }
    }

    for_each_vcpu ( d, v )
    {
        cpu_policy_updated(v);

        /* If PMU version is zero then the guest doesn't have VPMU */
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
             p->basic.pmu_version == 0 )
            vpmu_destroy(v);
    }
}

#if !defined(CONFIG_BIGMEM) && defined(CONFIG_PDX_COMPRESSION)
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

    /*
     * Without CONFIG_BIGMEM, we pack the PDX of the domain structure into
     * a 32-bit field within the page_info structure. Hence the MEMF_bits()
     * restriction. With PDX compression in place the number of bits must
     * be calculated at runtime, but it's fixed otherwise.
     *
     * On systems with CONFIG_BIGMEM there's no packing, and so there's no
     * such restriction.
     */
#if defined(CONFIG_BIGMEM) || !defined(CONFIG_PDX_COMPRESSION)
    const unsigned int bits = IS_ENABLED(CONFIG_BIGMEM) ? 0 :
                                                          32 + PAGE_SHIFT;
#else
    static unsigned int __read_mostly bits;

    if ( unlikely(!bits) )
         bits = _domain_struct_bits();
#endif

    BUILD_BUG_ON(sizeof(*d) > PAGE_SIZE);
    d = alloc_xenheap_pages(0, MEMF_bits(bits));
    if ( d != NULL )
        clear_page(d);
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

        if ( (rc = init_vcpu_msr_policy(v)) )
            goto fail;
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

        cpu_policy_updated(v);
    }

    return rc;

 fail:
    paging_vcpu_teardown(v);
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

    if ( is_hvm_vcpu(v) )
        hvm_vcpu_destroy(v);
    else
        pv_vcpu_destroy(v);
}

int arch_sanitise_domain_config(struct xen_domctl_createdomain *config)
{
    bool hvm = config->flags & XEN_DOMCTL_CDF_hvm;
    bool hap = config->flags & XEN_DOMCTL_CDF_hap;
    bool nested_virt = config->flags & XEN_DOMCTL_CDF_nested_virt;
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

    if ( hap && !hvm_hap_supported() )
    {
        dprintk(XENLOG_INFO, "HAP requested but not available\n");
        return -EINVAL;
    }

    if ( !hvm )
        /*
         * It is only meaningful for XEN_DOMCTL_CDF_oos_off to be clear
         * for HVM guests.
         */
        config->flags |= XEN_DOMCTL_CDF_oos_off;

    if ( nested_virt && !hap )
    {
        dprintk(XENLOG_INFO, "Nested virt not supported without HAP\n");
        return -EINVAL;
    }

    if ( config->vmtrace_size )
    {
        unsigned int size = config->vmtrace_size;

        ASSERT(vmtrace_available); /* Checked by common code. */

        /*
         * For now, vmtrace is restricted to HVM guests, and using a
         * power-of-2 buffer between 4k and 64M in size.
         */
        if ( !hvm )
        {
            dprintk(XENLOG_INFO, "vmtrace not supported for PV\n");
            return -EINVAL;
        }

        if ( size < PAGE_SIZE || size > MB(64) || (size & (size - 1)) )
        {
            dprintk(XENLOG_INFO, "Unsupported vmtrace size: %#x\n", size);
            return -EINVAL;
        }
    }

    if ( config->arch.misc_flags & ~XEN_X86_MSR_RELAXED )
    {
        dprintk(XENLOG_INFO, "Invalid arch misc flags %#x\n",
                config->arch.misc_flags);
        return -EINVAL;
    }

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
             /* HVM PIRQ feature is user-selectable. */
             (emflags & ~X86_EMU_USE_PIRQ) !=
             (X86_EMU_ALL & ~(X86_EMU_VPCI | X86_EMU_USE_PIRQ)) &&
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
                       struct xen_domctl_createdomain *config,
                       unsigned int flags)
{
    bool paging_initialised = false;
    uint32_t emflags;
    int rc;

    INIT_PAGE_LIST_HEAD(&d->arch.relmem_list);

    spin_lock_init(&d->arch.e820_lock);

    /* Minimal initialisation for the idle domain. */
    if ( unlikely(is_idle_domain(d)) )
    {
        static const struct arch_csw idle_csw = {
            .from = paravirt_ctxt_switch_from,
            .to   = paravirt_ctxt_switch_to,
            .tail = idle_loop,
        };

        d->arch.ctxt_switch = &idle_csw;

        d->arch.cpu_policy = ZERO_BLOCK_PTR; /* Catch stray misuses. */

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

#ifdef CONFIG_PV32
    HYPERVISOR_COMPAT_VIRT_START(d) =
        is_pv_domain(d) ? __HYPERVISOR_COMPAT_VIRT_START : ~0u;
#endif

    if ( (rc = paging_domain_init(d)) != 0 )
        goto fail;
    paging_initialised = true;

    if ( (rc = init_domain_cpu_policy(d)) )
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
        if ( (rc = hvm_domain_initialise(d, config)) != 0 )
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

    if ( (rc = tsc_set_info(d, XEN_CPUID_TSC_MODE_DEFAULT, 0, 0, 0)) != 0 )
    {
        ASSERT_UNREACHABLE();
        goto fail;
    }

    /* PV/PVH guests get an emulated PIT too for video BIOSes to use. */
    pit_init(d);

    /*
     * If the FPU does not save FCS/FDS then we can always
     * save/restore the 64-bit FIP/FDP and ignore the selectors.
     */
    d->arch.x87_fip_width = cpu_has_fpu_sel ? 0 : 8;

    domain_cpu_policy_changed(d);

    d->arch.msr_relaxed = config->arch.misc_flags & XEN_X86_MSR_RELAXED;

    spec_ctrl_init_domain(d);

    return 0;

 fail:
    d->is_dying = DOMDYING_dead;
    psr_domain_free(d);
    iommu_domain_destroy(d);
    cleanup_domain_irq_mapping(d);
    free_xenheap_page(d->shared_info);
    XFREE(d->arch.cpu_policy);
    if ( paging_initialised )
        paging_final_teardown(d);
    free_perdomain_mappings(d);

    return rc;
}

int arch_domain_teardown(struct domain *d)
{
    return 0;
}

void arch_domain_destroy(struct domain *d)
{
    if ( is_hvm_domain(d) )
        hvm_domain_destroy(d);

    xfree(d->arch.e820);
    XFREE(d->arch.cpu_policy);

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
    struct vcpu *v;
    mfn_t mfn;
    gfn_t gfn;
    p2m_type_t p2mt;
    unsigned int i;

    /* Soft reset is supported for HVM domains only. */
    if ( !is_hvm_domain(d) )
        return -EINVAL;

    write_lock(&d->event_lock);
    for ( i = 0; i < d->nr_pirqs ; i++ )
    {
        if ( domain_pirq_to_emuirq(d, i) != IRQ_UNBOUND )
        {
            ret = unmap_domain_pirq_emuirq(d, i);
            if ( ret )
                break;
        }
    }
    write_unlock(&d->event_lock);

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
        goto exit_put_gfn;
    }

    for_each_vcpu ( d, v )
    {
        set_xen_guest_handle(v->arch.time_info_guest, NULL);
        unmap_guest_area(v, &v->arch.time_guest_area);
    }

 exit_put_gfn:
    put_gfn(d, gfn_x(gfn));
 exit_put_page:
    put_page(page);

    return ret;
}

void arch_domain_creation_finished(struct domain *d)
{
    if ( is_hvm_domain(d) )
        hvm_domain_creation_finished(d);
}

#ifdef CONFIG_COMPAT
#define xen_vcpu_guest_context vcpu_guest_context
#define fpu_ctxt fpu_ctxt.x
CHECK_FIELD_(struct, vcpu_guest_context, fpu_ctxt);
#undef fpu_ctxt
#undef xen_vcpu_guest_context
#endif

/* Called by XEN_DOMCTL_setvcpucontext and VCPUOP_initialise. */
int arch_set_info_guest(
    struct vcpu *v, vcpu_guest_context_u c)
{
    struct domain *d = v->domain;
    const struct cpu_policy *p = d->arch.cpu_policy;
    unsigned int i;
    unsigned long flags;
    bool compat;
#ifdef CONFIG_PV
    mfn_t cr3_mfn;
    struct page_info *cr3_page = NULL;
    unsigned int nr_gdt_frames;
    int rc = 0;
#endif

    /* The context is a compat-mode one if the target domain is compat-mode;
     * we expect the tools to DTRT even in compat-mode callers. */
    compat = is_pv_32bit_domain(d);

#ifdef CONFIG_COMPAT
#define c(fld) (compat ? (c.cmp->fld) : (c.nat->fld))
#else
#define c(fld) (c.nat->fld)
#endif
    flags = c(flags);

    if ( !compat )
    {
        if ( c(debugreg[6]) != (uint32_t)c(debugreg[6]) ||
             c(debugreg[7]) != (uint32_t)c(debugreg[7]) )
            return -EINVAL;
    }

    if ( is_pv_domain(d) )
    {
        for ( i = 0; i < ARRAY_SIZE(v->arch.dr); i++ )
            if ( !breakpoint_addr_ok(c(debugreg[i])) )
                return -EINVAL;
        /*
         * Prior to Xen 4.11, dr5 was used to hold the emulated-only
         * subset of dr7, and dr4 was unused.
         *
         * In Xen 4.11 and later, dr4/5 are written as zero, ignored for
         * backwards compatibility, and dr7 emulation is handled
         * internally.
         */

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
#ifdef CONFIG_COMPAT
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
#endif

        /* LDT safety checks. */
        if ( ((c(ldt_base) & (PAGE_SIZE - 1)) != 0) ||
             (c(ldt_ents) > 8192) )
            return -EINVAL;

        v->arch.pv.vgc_flags = flags;
    }

    v->arch.flags |= TF_kernel_mode;
    if ( unlikely(!(flags & VGCF_in_kernel)) &&
         /*
          * TF_kernel_mode is only allowed to be clear for 64-bit PV. See
          * update_cr3(), sh_update_cr3(), sh_walk_guest_tables(), and
          * shadow_one_bit_disable() for why that is.
          */
         is_pv_64bit_domain(d) )
        v->arch.flags &= ~TF_kernel_mode;

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
#ifdef CONFIG_COMPAT
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
#endif

    if ( v->vcpu_id == 0 && (c(vm_assist) & ~arch_vm_assist_valid_mask(d)) )
        return -EINVAL;

    if ( is_hvm_domain(d) )
    {
        for ( i = 0; i < ARRAY_SIZE(v->arch.dr); ++i )
            v->arch.dr[i] = c(debugreg[i]);
        v->arch.dr6 = x86_adj_dr6_rsvd(p, c(debugreg[6]));
        v->arch.dr7 = x86_adj_dr7_rsvd(p, c(debugreg[7]));

        if ( v->vcpu_id == 0 )
            d->vm_assist = c.nat->vm_assist;

        hvm_set_info_guest(v);
        goto out;
    }

#ifdef CONFIG_PV
    /* IOPL privileges are virtualised. */
    v->arch.pv.iopl = v->arch.user_regs.eflags & X86_EFLAGS_IOPL;
    v->arch.user_regs.eflags &= ~X86_EFLAGS_IOPL;

    /* Ensure real hardware interrupts are enabled. */
    v->arch.user_regs.eflags |= X86_EFLAGS_IF;

    nr_gdt_frames = DIV_ROUND_UP(c(gdt_ents), 512);
    if ( nr_gdt_frames > ARRAY_SIZE(v->arch.pv.gdt_frames) )
        return -EINVAL;

    if ( !v->is_initialised )
    {
        if ( !compat && !(flags & VGCF_in_kernel) && !c.nat->ctrlreg[1] )
            return -EINVAL;

        v->arch.pv.ldt_ents = c(ldt_ents);
        v->arch.pv.ldt_base = v->arch.pv.ldt_ents
                              ? c(ldt_base)
                              : (unsigned long)ZERO_BLOCK_PTR;
    }
    else
    {
        unsigned long pfn = pagetable_get_pfn(v->arch.guest_table);
        bool fail;

#ifdef CONFIG_COMPAT
        if ( compat )
        {
            l4_pgentry_t *l4tab = map_domain_page(_mfn(pfn));

            pfn = l4e_get_pfn(*l4tab);
            unmap_domain_page(l4tab);
            fail = compat_pfn_to_cr3(pfn) != c.cmp->ctrlreg[3];
        }
        else
#endif
        {
            fail = xen_pfn_to_cr3(pfn) != c.nat->ctrlreg[3];
            if ( pagetable_is_null(v->arch.guest_table_user) )
                fail |= c.nat->ctrlreg[1] || !(flags & VGCF_in_kernel);
            else
            {
                pfn = pagetable_get_pfn(v->arch.guest_table_user);
                fail |= xen_pfn_to_cr3(pfn) != c.nat->ctrlreg[1];
            }
        }

        fail |= v->arch.pv.gdt_ents != c(gdt_ents);
        for ( i = 0; !fail && i < nr_gdt_frames; ++i )
            fail = v->arch.pv.gdt_frames[i] != c(gdt_frames[i]);

        fail |= v->arch.pv.ldt_ents != c(ldt_ents);
        if ( v->arch.pv.ldt_ents )
            fail |= v->arch.pv.ldt_base != c(ldt_base);

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
        v->arch.pv.fs_base = c.nat->fs_base;
        v->arch.pv.gs_base_kernel = c.nat->gs_base_kernel;
        v->arch.pv.gs_base_user = c.nat->gs_base_user;
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
             is_pv_64bit_domain(d) &&
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
        rc = pv_set_gdt(v, c.nat->gdt_frames, c.nat->gdt_ents);
#ifdef CONFIG_COMPAT
    else
    {
        unsigned long gdt_frames[ARRAY_SIZE(v->arch.pv.gdt_frames)];

        for ( i = 0; i < nr_gdt_frames; ++i )
            gdt_frames[i] = c.cmp->gdt_frames[i];

        rc = pv_set_gdt(v, gdt_frames, c.cmp->gdt_ents);
    }
#endif
    if ( rc != 0 )
        return rc;

    set_bit(_VPF_in_reset, &v->pause_flags);

#ifdef CONFIG_COMPAT
    if ( compat )
        cr3_mfn = _mfn(compat_cr3_to_pfn(c.cmp->ctrlreg[3]));
    else
#endif
        cr3_mfn = _mfn(xen_cr3_to_pfn(c.nat->ctrlreg[3]));
    cr3_page = get_page_from_mfn(cr3_mfn, d);

    if ( !cr3_page )
        rc = -EINVAL;
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
            if ( !compat && !VM_ASSIST(d, m2p_strict) )
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
            else
            {
                rc = get_page_type_preemptible(cr3_page, PGT_root_page_table);
                switch ( rc )
                {
                case -EINTR:
                    rc = -ERESTART;
                    /* Fallthrough */
                case -ERESTART:
                    /*
                     * NB that we're putting the kernel-mode table
                     * here, which we've already successfully
                     * validated above; hence partial = false;
                     */
                    v->arch.old_guest_ptpg = NULL;
                    v->arch.old_guest_table =
                        pagetable_get_page(v->arch.guest_table);
                    v->arch.old_guest_table_partial = false;
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
    else
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
    v->arch.async_exception_mask = 0;
    memset(v->arch.async_exception_state, 0,
           sizeof(v->arch.async_exception_state));

    if ( is_pv_vcpu(v) )
    {
        pv_destroy_gdt(v);
        return vcpu_destroy_pagetables(v);
    }

    vcpu_end_shutdown_deferral(v);
    return 0;
}

static void cf_check
time_area_populate(void *map, struct vcpu *v)
{
    if ( is_pv_vcpu(v) )
        v->arch.pv.pending_system_time.version = 0;

    force_update_secondary_system_time(v, map);
}

long do_vcpu_op(int cmd, unsigned int vcpuid, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc = 0;
    struct domain *d = current->domain;
    struct vcpu *v;

    if ( (v = domain_vcpu(d, vcpuid)) == NULL )
        return -ENOENT;

    switch ( cmd )
    {
    case VCPUOP_send_nmi:
        if ( !guest_handle_is_null(arg) )
            return -EINVAL;

        if ( !test_and_set_bool(v->arch.nmi_pending) )
            vcpu_kick(v);
        break;

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

    case VCPUOP_register_vcpu_time_phys_area:
    {
        struct vcpu_register_time_memory_area area;

        rc = -ENOSYS;
        if ( 0 /* TODO: Dom's XENFEAT_vcpu_time_phys_area setting */ )
            break;

        rc = -EFAULT;
        if ( copy_from_guest(&area.addr.p, arg, 1) )
            break;

        rc = map_guest_area(v, area.addr.p,
                            sizeof(vcpu_time_info_t),
                            &v->arch.time_guest_area,
                            time_area_populate);
        if ( rc == -ERESTART )
            rc = hypercall_create_continuation(__HYPERVISOR_vcpu_op, "iih",
                                               cmd, vcpuid, arg);

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
        rc = common_vcpu_op(cmd, v, arg);
        break;
    }

    return rc;
}

/*
 * Notes on PV segment handling:
 *  - 32bit: All data from the GDT/LDT.
 *  - 64bit: In addition, 64bit FS/GS/GS_KERN bases.
 *
 * Linux's ABI with userspace expects to preserve the full selector and
 * segment base, even sel != NUL, base != GDT/LDT for 64bit code.  Xen must
 * honour this when context switching, to avoid breaking Linux's ABI.
 *
 * Note: It is impossible to preserve a selector value of 1, 2 or 3, as these
 *       get reset to 0 by an IRET back to guest context.  Code playing with
 *       arcane corners of x86 get to keep all resulting pieces.
 *
 * Therefore, we:
 *  - Load the LDT.
 *  - Load each segment selector.
 *    - Any error loads zero, and triggers a failsafe callback.
 *  - For 64bit, further load the 64bit bases.
 *
 * An optimisation exists on SVM-capable hardware, where we use a VMLOAD
 * instruction to load the LDT and full FS/GS/GS_KERN data in one go.
 *
 * AMD-like CPUs prior to Zen2 do not zero the segment base or limit when
 * loading a NUL selector.  This is a problem in principle when context
 * switching to a 64bit guest, as a NUL FS/GS segment is usable and will pick
 * up the stale base.
 *
 * However, it is not an issue in practice.  NUL segments are unusable for
 * 32bit guests (so any stale base won't be used), and we unconditionally
 * write the full FS/GS bases for 64bit guests.
 */
static void load_segments(struct vcpu *n)
{
    struct cpu_user_regs *uregs = &n->arch.user_regs;
    unsigned long gsb = 0, gss = 0;
    bool compat = is_pv_32bit_vcpu(n);
    bool all_segs_okay = true, fs_gs_done = false;

    /*
     * Attempt to load @seg with selector @val.  On error, clear
     * @all_segs_okay in function scope, and load NUL into @sel.
     */
#define TRY_LOAD_SEG(seg, val)                          \
    asm volatile ( "1: mov %k[_val], %%" #seg "\n\t"    \
                   "2:\n\t"                             \
                   ".section .fixup, \"ax\"\n\t"        \
                   "3: xor %k[ok], %k[ok]\n\t"          \
                   "   mov %k[ok], %%" #seg "\n\t"      \
                   "   jmp 2b\n\t"                      \
                   ".previous\n\t"                      \
                   _ASM_EXTABLE(1b, 3b)                 \
                   : [ok] "+r" (all_segs_okay)          \
                   : [_val] "rm" (val) )

    if ( !compat )
    {
        gsb = n->arch.pv.gs_base_kernel;
        gss = n->arch.pv.gs_base_user;

        /*
         * Figure out which way around gsb/gss want to be.  gsb needs to be
         * the active context, and gss needs to be the inactive context.
         */
        if ( !(n->arch.flags & TF_kernel_mode) )
            SWAP(gsb, gss);

#ifdef CONFIG_HVM
        if ( cpu_has_svm && (uregs->fs | uregs->gs) <= 3 )
            fs_gs_done = svm_load_segs(n->arch.pv.ldt_ents, LDT_VIRT_START(n),
                                       n->arch.pv.fs_base, gsb, gss);
#endif
    }

    if ( !fs_gs_done )
    {
        load_LDT(n);

        TRY_LOAD_SEG(fs, uregs->fs);
        TRY_LOAD_SEG(gs, uregs->gs);
    }

    TRY_LOAD_SEG(ds, uregs->ds);
    TRY_LOAD_SEG(es, uregs->es);

    if ( !fs_gs_done && !compat )
    {
        if ( read_cr4() & X86_CR4_FSGSBASE )
        {
            __wrgsbase(gss);
            __wrfsbase(n->arch.pv.fs_base);
            asm volatile ( "swapgs" );
            __wrgsbase(gsb);
        }
        else
        {
            wrmsrl(MSR_FS_BASE, n->arch.pv.fs_base);
            wrmsrl(MSR_GS_BASE, gsb);
            wrmsrl(MSR_SHADOW_GS_BASE, gss);
        }
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
                ret  = put_guest(regs->ss,  esp - 1);
                ret |= put_guest(regs->esp, esp - 2);
                esp -= 2;
            }

            if ( ret |
                 put_guest(rflags,      esp - 1) |
                 put_guest(cs_and_mask, esp - 2) |
                 put_guest(regs->eip,   esp - 3) |
                 put_guest(uregs->gs,   esp - 4) |
                 put_guest(uregs->fs,   esp - 5) |
                 put_guest(uregs->es,   esp - 6) |
                 put_guest(uregs->ds,   esp - 7) )
                domain_crash(n->domain,
                             "Error creating compat failsafe callback frame\n");

            if ( n->arch.pv.vgc_flags & VGCF_failsafe_disables_events )
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

        if ( put_guest(regs->ss,    rsp -  1) |
             put_guest(regs->rsp,   rsp -  2) |
             put_guest(rflags,      rsp -  3) |
             put_guest(cs_and_mask, rsp -  4) |
             put_guest(regs->rip,   rsp -  5) |
             put_guest(uregs->gs,   rsp -  6) |
             put_guest(uregs->fs,   rsp -  7) |
             put_guest(uregs->es,   rsp -  8) |
             put_guest(uregs->ds,   rsp -  9) |
             put_guest(regs->r11,   rsp - 10) |
             put_guest(regs->rcx,   rsp - 11) )
            domain_crash(n->domain,
                         "Error creating failsafe callback frame\n");

        if ( n->arch.pv.vgc_flags & VGCF_failsafe_disables_events )
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

/*
 * Record all guest segment state.  The guest can load segment selectors
 * without trapping, which will also alter the 64bit FS/GS bases.  Arbitrary
 * changes to bases can also be made with the WR{FS,GS}BASE instructions, when
 * enabled.
 *
 * Guests however cannot use SWAPGS, so there is no mechanism to modify the
 * inactive GS base behind Xen's back.  Therefore, Xen's copy of the inactive
 * GS base is still accurate, and doesn't need reading back from hardware.
 */
static void save_segments(struct vcpu *v)
{
    struct cpu_user_regs *regs = &v->arch.user_regs;

    read_sregs(regs);

    if ( !is_pv_32bit_vcpu(v) )
    {
        unsigned long fs_base, gs_base;

        if ( read_cr4() & X86_CR4_FSGSBASE )
        {
            fs_base = __rdfsbase();
            gs_base = __rdgsbase();
        }
        else
        {
            rdmsrl(MSR_FS_BASE, fs_base);
            rdmsrl(MSR_GS_BASE, gs_base);
        }

        v->arch.pv.fs_base = fs_base;
        if ( v->arch.flags & TF_kernel_mode )
            v->arch.pv.gs_base_kernel = gs_base;
        else
            v->arch.pv.gs_base_user = gs_base;
    }
}

void cf_check paravirt_ctxt_switch_from(struct vcpu *v)
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

void cf_check paravirt_ctxt_switch_to(struct vcpu *v)
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
        ASSERT(read_atomic(&p->dirty_cpu) == cpu);
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
            if ( !set_xcr0(n->arch.xcr0 ?: XSTATE_FP_SSE) )
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
    if ( cpu_has_svm && is_pv_64bit_domain(nd) && !is_idle_domain(nd) )
        svm_load_segs_prefetch();
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
    struct cpu_info *info = get_cpu_info();
    const struct domain *prevd = prev->domain, *nextd = next->domain;
    unsigned int dirty_cpu = read_atomic(&next->dirty_cpu);

    ASSERT(prev != next);
    ASSERT(local_irq_is_enabled());

    info->use_pv_cr3 = false;
    info->xen_cr3 = 0;

    if ( unlikely(dirty_cpu != cpu) && dirty_cpu != VCPU_CPU_CLEAN )
    {
        /* Remote CPU calls __sync_local_execstate() from flush IPI handler. */
        flush_mask(cpumask_of(dirty_cpu), FLUSH_VCPU_STATE);
        ASSERT(!vcpu_cpu_dirty(next));
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

        if ( opt_ibpb_ctxt_switch && !is_idle_domain(nextd) )
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
                spec_ctrl_new_guest_context();
                *last_id = next_id;
            }
        }

        /* Update the top-of-stack block with the new spec_ctrl settings. */
        info->spec_ctrl_flags =
            (info->spec_ctrl_flags       & ~SCF_DOM_MASK) |
            (nextd->arch.spec_ctrl_flags &  SCF_DOM_MASK);
    }

    sched_context_switched(prev, next);

    _update_runstate_area(next);
    /* Must be done with interrupts enabled */
    vpmu_switch_to(next);
    np2m_schedule(NP2M_SCHEDLE_IN);

    /* Ensure that the vcpu has an up-to-date time base. */
    update_vcpu_system_time(next);

    reset_stack_and_jump_ind(nextd->arch.ctxt_switch->tail);
}

void continue_running(struct vcpu *same)
{
    reset_stack_and_jump_ind(same->domain->arch.ctxt_switch->tail);
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
    unsigned int dirty_cpu = read_atomic(&v->dirty_cpu);

    if ( dirty_cpu == smp_processor_id() )
        sync_local_execstate();
    else if ( is_vcpu_dirty_cpu(dirty_cpu) )
    {
        /* Remote CPU calls __sync_local_execstate() from flush IPI handler. */
        flush_mask(cpumask_of(dirty_cpu), FLUSH_VCPU_STATE);
    }
    ASSERT(!is_vcpu_dirty_cpu(dirty_cpu) ||
           read_atomic(&v->dirty_cpu) != dirty_cpu);
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
            /*
             * -EINTR means PGT_validated has been re-set; re-set
             * PGT_pinned again so that it gets picked up next time
             * around.
             *
             * -ERESTART, OTOH, means PGT_partial is set instead.  Put
             * it back on the list, but don't set PGT_pinned; the
             * section below will finish off de-validation.  But we do
             * need to drop the general ref associated with
             * PGT_pinned, since put_page_and_type_preemptible()
             * didn't do it.
             *
             * NB we can do an ASSERT for PGT_validated, since we
             * "own" the type ref; but theoretically, the PGT_partial
             * could be cleared by someone else.
             */
            if ( ret == -EINTR )
            {
                ASSERT(page->u.inuse.type_info & PGT_validated);
                set_bit(_PGT_pinned, &page->u.inuse.type_info);
            }
            else
                put_page(page);

            ret = -ERESTART;

            /* Put the page back on the list and drop the ref we grabbed above */
            page_list_add(page, list);
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
                switch ( ret = devalidate_page(page, x, 1) )
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
                    /*
                     * PGT_partial holds a type ref and a general ref.
                     * If we came in with PGT_partial set, then we 1)
                     * don't need to grab an extra type count, and 2)
                     * do need to drop the extra page ref we grabbed
                     * at the top of the loop.  If we didn't come in
                     * with PGT_partial set, we 1) do need to drab an
                     * extra type count, but 2) can transfer the page
                     * ref we grabbed above to it.
                     *
                     * Note that we must increment type_info before
                     * setting PGT_partial.  Theoretically it should
                     * be safe to drop the page ref before setting
                     * PGT_partial, but do it afterwards just to be
                     * extra safe.
                     */
                    if ( !(x & PGT_partial) )
                        page->u.inuse.type_info++;
                    smp_wmb();
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
            PROG_iommu_pagetables = 1,
            PROG_shared,
            PROG_paging,
            PROG_vcpu_pagetables,
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

    PROGRESS(iommu_pagetables):

        ret = iommu_free_pgtables(d);
        if ( ret )
            return ret;

#ifdef CONFIG_MEM_SHARING
    PROGRESS(shared):

        if ( is_hvm_domain(d) )
        {
            /*
             * If the domain has shared pages, relinquish them allowing
             * for preemption.
             */
            ret = relinquish_shared_pages(d);
            if ( ret )
                return ret;

            /*
             * If the domain is forked, decrement the parent's pause count
             * and release the domain.
             */
            if ( mem_sharing_is_fork(d) )
            {
                struct domain *parent = d->parent;

                d->parent = NULL;
                domain_unpause(parent);
                put_domain(parent);
            }
        }
#endif

    PROGRESS(paging):

        /* Tear down paging-assistance stuff. */
        ret = paging_teardown(d);
        if ( ret )
            return ret;

    PROGRESS(vcpu_pagetables):

        /*
         * Drop the in-use references to page-table bases and clean
         * up vPMU instances.
         */
        for_each_vcpu ( d, v )
        {
            ret = vcpu_destroy_pagetables(v);
            if ( ret )
                return ret;

            unmap_guest_area(v, &v->arch.time_guest_area);

            vpmu_destroy(v);
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

static void cf_check vcpu_kick_softirq(void)
{
    /*
     * Nothing to do here: we merely prevent notifiers from racing with checks
     * executed on return to guest context with interrupts enabled. See, for
     * example, xxx_intr_assist() executed on return to HVM guest context.
     */
}

static int __init cf_check init_vcpu_kick_softirq(void)
{
    open_softirq(VCPU_KICK_SOFTIRQ, vcpu_kick_softirq);
    return 0;
}
__initcall(init_vcpu_kick_softirq);

unsigned int domain_max_paddr_bits(const struct domain *d)
{
    unsigned int bits = paging_mode_hap(d) ? hap_paddr_bits : paddr_bits;

    if ( paging_mode_external(d) )
    {
        if ( !IS_ENABLED(CONFIG_BIGMEM) && paging_mode_shadow(d) )
        {
            /* Shadowed superpages store GFNs in 32-bit page_info fields. */
            bits = min(bits, 32U + PAGE_SHIFT);
        }
        else
        {
            /* Both p2m-ept and p2m-pt only support 4-level page tables. */
            bits = min(bits, 48U);
        }
    }

    return bits;
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
