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

#include <xen/config.h>
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
#include <public/sysctl.h>
#include <asm/regs.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/mpspec.h>
#include <asm/ldt.h>
#include <asm/fixmap.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/traps.h>
#include <asm/nmi.h>
#include <asm/mce.h>
#include <asm/amd.h>
#include <xen/numa.h>
#include <xen/iommu.h>
#ifdef CONFIG_COMPAT
#include <compat/vcpu.h>
#endif

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);
DEFINE_PER_CPU(unsigned long, cr4);

static void default_idle(void);
static void default_dead_idle(void);
void (*pm_idle) (void) __read_mostly = default_idle;
void (*dead_idle) (void) __read_mostly = default_dead_idle;

static void paravirt_ctxt_switch_from(struct vcpu *v);
static void paravirt_ctxt_switch_to(struct vcpu *v);

static void default_idle(void)
{
    local_irq_disable();
    if ( cpu_is_haltable(smp_processor_id()) )
        safe_halt();
    else
        local_irq_enable();
}

static void default_dead_idle(void)
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
    for ( ; ; )
    {
        if ( cpu_is_offline(smp_processor_id()) )
            play_dead();
        (*pm_idle)();
        do_tasklet();
        do_softirq();
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

static void continue_idle_domain(struct vcpu *v)
{
    reset_stack_and_jump(idle_loop);
}

static void continue_nonidle_domain(struct vcpu *v)
{
    check_wakeup_from_wait();
    reset_stack_and_jump(ret_from_intr);
}

void dump_pageframe_info(struct domain *d)
{
    struct page_info *page;

    printk("Memory pages belonging to domain %u:\n", d->domain_id);

    if ( d->tot_pages >= 10 )
    {
        printk("    DomPage list too long to display\n");
    }
    else
    {
        spin_lock(&d->page_alloc_lock);
        page_list_for_each ( page, &d->page_list )
        {
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

struct domain *alloc_domain_struct(void)
{
    struct domain *d;
    /*
     * We pack the PDX of the domain structure into a 32-bit field within
     * the page_info structure. Hence the MEMF_bits() restriction.
     */
    unsigned int bits = 32 + PAGE_SHIFT;

#ifdef __x86_64__
    bits += pfn_pdx_hole_shift;
#endif
    BUILD_BUG_ON(sizeof(*d) > PAGE_SIZE);
    d = alloc_xenheap_pages(0, MEMF_bits(bits));
    if ( d != NULL )
        clear_page(d);
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

static DEFINE_PER_CPU(struct page_info *[
    PFN_UP(sizeof(struct vcpu_guest_context))], vgc_pages);

struct vcpu_guest_context *alloc_vcpu_guest_context(void)
{
    unsigned int i, cpu = smp_processor_id();
    enum fixed_addresses idx = FIX_VGC_BEGIN -
        cpu * PFN_UP(sizeof(struct vcpu_guest_context));

#ifdef __i386__
    BUILD_BUG_ON(sizeof(struct vcpu_guest_context) > PAGE_SIZE);
#endif
    BUG_ON(per_cpu(vgc_pages[0], cpu) != NULL);

    for ( i = 0; i < PFN_UP(sizeof(struct vcpu_guest_context)); ++i )
    {
        struct page_info *pg = alloc_domheap_page(NULL, 0);

        if ( unlikely(pg == NULL) )
        {
            free_vcpu_guest_context(NULL);
            return NULL;
        }
        __set_fixmap(idx - i, page_to_mfn(pg), __PAGE_HYPERVISOR);
        per_cpu(vgc_pages[i], cpu) = pg;
    }
    return (void *)fix_to_virt(idx);
}

void free_vcpu_guest_context(struct vcpu_guest_context *vgc)
{
    unsigned int i, cpu = smp_processor_id();
    enum fixed_addresses idx = FIX_VGC_BEGIN -
        cpu * PFN_UP(sizeof(struct vcpu_guest_context));

    BUG_ON(vgc && vgc != (void *)fix_to_virt(idx));

    for ( i = 0; i < PFN_UP(sizeof(struct vcpu_guest_context)); ++i )
    {
        if ( !per_cpu(vgc_pages[i], cpu) )
            continue;
        __set_fixmap(idx - i, 0, 0);
        free_domheap_page(per_cpu(vgc_pages[i], cpu));
        per_cpu(vgc_pages[i], cpu) = NULL;
    }
}

#ifdef __x86_64__

static int setup_compat_l4(struct vcpu *v)
{
    struct page_info *pg;
    l4_pgentry_t *l4tab;
    int rc;

    pg = alloc_domheap_page(NULL, MEMF_node(vcpu_to_node(v)));
    if ( pg == NULL )
        return -ENOMEM;

    rc = setup_compat_arg_xlat(v);
    if ( rc )
    {
        free_domheap_page(pg);
        return rc;
    }

    /* This page needs to look like a pagetable so that it can be shadowed */
    pg->u.inuse.type_info = PGT_l4_page_table|PGT_validated|1;

    l4tab = page_to_virt(pg);
    copy_page(l4tab, idle_pg_table);
    l4tab[0] = l4e_empty();
    l4tab[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_page(pg, __PAGE_HYPERVISOR);
    l4tab[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_paddr(__pa(v->domain->arch.mm_perdomain_l3),
                       __PAGE_HYPERVISOR);

    v->arch.guest_table = pagetable_from_page(pg);
    v->arch.guest_table_user = v->arch.guest_table;

    return 0;
}

static void release_compat_l4(struct vcpu *v)
{
    free_compat_arg_xlat(v);
    free_domheap_page(pagetable_get_page(v->arch.guest_table));
    v->arch.guest_table = pagetable_null();
    v->arch.guest_table_user = pagetable_null();
}

static inline int may_switch_mode(struct domain *d)
{
    return (!is_hvm_domain(d) && (d->tot_pages == 0));
}

int switch_native(struct domain *d)
{
    unsigned int vcpuid;

    if ( d == NULL )
        return -EINVAL;
    if ( !may_switch_mode(d) )
        return -EACCES;
    if ( !is_pv_32on64_domain(d) )
        return 0;

    d->arch.is_32bit_pv = d->arch.has_32bit_shinfo = 0;

    for ( vcpuid = 0; vcpuid < d->max_vcpus; vcpuid++ )
    {
        if (d->vcpu[vcpuid])
            release_compat_l4(d->vcpu[vcpuid]);
    }

    return 0;
}

int switch_compat(struct domain *d)
{
    unsigned int vcpuid;

    if ( d == NULL )
        return -EINVAL;
    if ( !may_switch_mode(d) )
        return -EACCES;
    if ( is_pv_32on64_domain(d) )
        return 0;

    d->arch.is_32bit_pv = d->arch.has_32bit_shinfo = 1;

    for ( vcpuid = 0; vcpuid < d->max_vcpus; vcpuid++ )
    {
        if ( (d->vcpu[vcpuid] != NULL) &&
             (setup_compat_l4(d->vcpu[vcpuid]) != 0) )
            goto undo_and_fail;
    }

    domain_set_alloc_bitsize(d);

    return 0;

 undo_and_fail:
    d->arch.is_32bit_pv = d->arch.has_32bit_shinfo = 0;
    while ( vcpuid-- != 0 )
    {
        if ( d->vcpu[vcpuid] != NULL )
            release_compat_l4(d->vcpu[vcpuid]);
    }
    return -ENOMEM;
}

#else
#define setup_compat_l4(v) 0
#define release_compat_l4(v) ((void)0)
#endif

static inline bool_t standalone_trap_ctxt(struct vcpu *v)
{
    BUILD_BUG_ON(256 * sizeof(*v->arch.pv_vcpu.trap_ctxt) > PAGE_SIZE);
    return 256 * sizeof(*v->arch.pv_vcpu.trap_ctxt) + sizeof(*v) > PAGE_SIZE;
}

int vcpu_initialise(struct vcpu *v)
{
    struct domain *d = v->domain;
    int rc;

    v->arch.flags = TF_kernel_mode;

#if defined(__i386__)
    mapcache_vcpu_init(v);
#else
    {
        unsigned int idx = perdomain_pt_pgidx(v);
        struct page_info *pg;

        if ( !perdomain_pt_page(d, idx) )
        {
            pg = alloc_domheap_page(NULL, MEMF_node(vcpu_to_node(v)));
            if ( !pg )
                return -ENOMEM;
            clear_page(page_to_virt(pg));
            perdomain_pt_page(d, idx) = pg;
            d->arch.mm_perdomain_l2[l2_table_offset(PERDOMAIN_VIRT_START)+idx]
                = l2e_from_page(pg, __PAGE_HYPERVISOR);
        }
    }
#endif

    pae_l3_cache_init(&v->arch.pae_l3_cache);

    paging_vcpu_init(v);

    v->arch.perdomain_ptes = perdomain_ptes(d, v);

    if ( (rc = vcpu_init_fpu(v)) != 0 )
        return rc;

    vmce_init_vcpu(v);

    v->arch.vcpu_info_mfn = INVALID_MFN;

    if ( is_hvm_domain(d) )
    {
        rc = hvm_vcpu_initialise(v);
        goto done;
    }


    spin_lock_init(&v->arch.pv_vcpu.shadow_ldt_lock);

    if ( !is_idle_domain(d) )
    {
        if ( standalone_trap_ctxt(v) )
        {
            v->arch.pv_vcpu.trap_ctxt = alloc_xenheap_page();
            if ( !v->arch.pv_vcpu.trap_ctxt )
            {
                rc = -ENOMEM;
                goto done;
            }
            clear_page(v->arch.pv_vcpu.trap_ctxt);
        }
        else
            v->arch.pv_vcpu.trap_ctxt = (void *)v + PAGE_SIZE -
                256 * sizeof(*v->arch.pv_vcpu.trap_ctxt);

        /* PV guests by default have a 100Hz ticker. */
        v->periodic_period = MILLISECS(10);

        /* PV guests get an emulated PIT too for video BIOSes to use. */
        if ( v->vcpu_id == 0 )
            pit_init(v, cpu_khz);
    }

    v->arch.schedule_tail = continue_nonidle_domain;
    v->arch.ctxt_switch_from = paravirt_ctxt_switch_from;
    v->arch.ctxt_switch_to   = paravirt_ctxt_switch_to;

    if ( is_idle_domain(d) )
    {
        v->arch.schedule_tail = continue_idle_domain;
        v->arch.cr3           = __pa(idle_pg_table);
    }

    v->arch.pv_vcpu.ctrlreg[4] = real_cr4_to_pv_guest_cr4(mmu_cr4_features);

    rc = is_pv_32on64_vcpu(v) ? setup_compat_l4(v) : 0;
 done:
    if ( rc )
    {
        vcpu_destroy_fpu(v);

        if ( !is_hvm_domain(d) && standalone_trap_ctxt(v) )
            free_xenheap_page(v->arch.pv_vcpu.trap_ctxt);
    }

    return rc;
}

void vcpu_destroy(struct vcpu *v)
{
    if ( is_pv_32on64_vcpu(v) )
        release_compat_l4(v);

    vcpu_destroy_fpu(v);

    if ( is_hvm_vcpu(v) )
        hvm_vcpu_destroy(v);
    else if ( standalone_trap_ctxt(v) )
        free_xenheap_page(v->arch.pv_vcpu.trap_ctxt);
}

int arch_domain_create(struct domain *d, unsigned int domcr_flags)
{
#ifdef __x86_64__
    struct page_info *pg;
#else
    int pdpt_order;
#endif
    int i, paging_initialised = 0;
    int rc = -ENOMEM;

    d->arch.hvm_domain.hap_enabled =
        is_hvm_domain(d) &&
        hvm_funcs.hap_supported &&
        (domcr_flags & DOMCRF_hap);
    d->arch.hvm_domain.mem_sharing_enabled = 0;

    d->arch.s3_integrity = !!(domcr_flags & DOMCRF_s3_integrity);

    INIT_LIST_HEAD(&d->arch.pdev_list);

    d->arch.relmem = RELMEM_not_started;
    INIT_PAGE_LIST_HEAD(&d->arch.relmem_list);

#if defined(__i386__)

    pdpt_order = get_order_from_bytes(PDPT_L1_ENTRIES * sizeof(l1_pgentry_t));
    d->arch.mm_perdomain_pt = alloc_xenheap_pages(pdpt_order, 0);
    if ( d->arch.mm_perdomain_pt == NULL )
        goto fail;
    memset(d->arch.mm_perdomain_pt, 0, PAGE_SIZE << pdpt_order);

    mapcache_domain_init(d);

#else /* __x86_64__ */

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

    BUILD_BUG_ON(PDPT_L2_ENTRIES * sizeof(*d->arch.mm_perdomain_pt_pages)
                 != PAGE_SIZE);
    pg = alloc_domheap_page(NULL, MEMF_node(domain_to_node(d)));
    if ( !pg )
        goto fail;
    d->arch.mm_perdomain_pt_pages = page_to_virt(pg);
    clear_page(d->arch.mm_perdomain_pt_pages);

    pg = alloc_domheap_page(NULL, MEMF_node(domain_to_node(d)));
    if ( pg == NULL )
        goto fail;
    d->arch.mm_perdomain_l2 = page_to_virt(pg);
    clear_page(d->arch.mm_perdomain_l2);

    pg = alloc_domheap_page(NULL, MEMF_node(domain_to_node(d)));
    if ( pg == NULL )
        goto fail;
    d->arch.mm_perdomain_l3 = page_to_virt(pg);
    clear_page(d->arch.mm_perdomain_l3);
    d->arch.mm_perdomain_l3[l3_table_offset(PERDOMAIN_VIRT_START)] =
        l3e_from_page(virt_to_page(d->arch.mm_perdomain_l2),
                            __PAGE_HYPERVISOR);

    HYPERVISOR_COMPAT_VIRT_START(d) =
        is_hvm_domain(d) ? ~0u : __HYPERVISOR_COMPAT_VIRT_START;

#endif /* __x86_64__ */

    if ( (rc = paging_domain_init(d, domcr_flags)) != 0 )
        goto fail;
    paging_initialised = 1;

    if ( !is_idle_domain(d) )
    {
        d->arch.cpuids = xzalloc_array(cpuid_input_t, MAX_CPUID_INPUT);
        rc = -ENOMEM;
        if ( d->arch.cpuids == NULL )
            goto fail;
        for ( i = 0; i < MAX_CPUID_INPUT; i++ )
        {
            d->arch.cpuids[i].input[0] = XEN_CPUID_INPUT_UNUSED;
            d->arch.cpuids[i].input[1] = XEN_CPUID_INPUT_UNUSED;
        }

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

        /* For Guest vMCE MSRs virtualization */
        vmce_init_msr(d);
    }

    if ( is_hvm_domain(d) )
    {
        if ( (rc = hvm_domain_initialise(d)) != 0 )
        {
            iommu_domain_destroy(d);
            goto fail;
        }
    }
    else
    {
        /* 32-bit PV guest by default only if Xen is not 64-bit. */
        d->arch.is_32bit_pv = d->arch.has_32bit_shinfo =
            (CONFIG_PAGING_LEVELS != 4);

        spin_lock_init(&d->arch.pv_domain.e820_lock);
    }

    /* initialize default tsc behavior in case tools don't */
    tsc_set_info(d, TSC_MODE_DEFAULT, 0UL, 0, 0);
    spin_lock_init(&d->arch.vtsc_lock);

    return 0;

 fail:
    d->is_dying = DOMDYING_dead;
    vmce_destroy_msr(d);
    cleanup_domain_irq_mapping(d);
    free_xenheap_page(d->shared_info);
    if ( paging_initialised )
        paging_final_teardown(d);
#ifdef __x86_64__
    if ( d->arch.mm_perdomain_l2 )
        free_domheap_page(virt_to_page(d->arch.mm_perdomain_l2));
    if ( d->arch.mm_perdomain_l3 )
        free_domheap_page(virt_to_page(d->arch.mm_perdomain_l3));
    if ( d->arch.mm_perdomain_pt_pages )
        free_domheap_page(virt_to_page(d->arch.mm_perdomain_pt_pages));
#else
    free_xenheap_pages(d->arch.mm_perdomain_pt, pdpt_order);
#endif
    return rc;
}

void arch_domain_destroy(struct domain *d)
{
#ifdef __x86_64__
    unsigned int i;
#endif

    if ( is_hvm_domain(d) )
        hvm_domain_destroy(d);
    else
        xfree(d->arch.pv_domain.e820);

    vmce_destroy_msr(d);
    free_domain_pirqs(d);
    if ( !is_idle_domain(d) )
        iommu_domain_destroy(d);

    paging_final_teardown(d);

#ifdef __i386__
    free_xenheap_pages(
        d->arch.mm_perdomain_pt,
        get_order_from_bytes(PDPT_L1_ENTRIES * sizeof(l1_pgentry_t)));
#else
    for ( i = 0; i < PDPT_L2_ENTRIES; ++i )
    {
        if ( perdomain_pt_page(d, i) )
            free_domheap_page(perdomain_pt_page(d, i));
    }
    free_domheap_page(virt_to_page(d->arch.mm_perdomain_pt_pages));
    free_domheap_page(virt_to_page(d->arch.mm_perdomain_l2));
    free_domheap_page(virt_to_page(d->arch.mm_perdomain_l3));
#endif

    free_xenheap_page(d->shared_info);
    cleanup_domain_irq_mapping(d);
}

unsigned long pv_guest_cr4_fixup(const struct vcpu *v, unsigned long guest_cr4)
{
    unsigned long hv_cr4_mask, hv_cr4 = real_cr4_to_pv_guest_cr4(read_cr4());

    hv_cr4_mask = ~X86_CR4_TSD;
    if ( cpu_has_de )
        hv_cr4_mask &= ~X86_CR4_DE;
    if ( cpu_has_fsgsbase && !is_pv_32bit_domain(v->domain) )
        hv_cr4_mask &= ~X86_CR4_FSGSBASE;
    if ( cpu_has_xsave )
        hv_cr4_mask &= ~X86_CR4_OSXSAVE;

    if ( (guest_cr4 & hv_cr4_mask) != (hv_cr4 & hv_cr4_mask) )
        gdprintk(XENLOG_WARNING,
                 "Attempt to change CR4 flags %08lx -> %08lx\n",
                 hv_cr4, guest_cr4);

    return (hv_cr4 & hv_cr4_mask) | (guest_cr4 & ~hv_cr4_mask);
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
    unsigned long cr3_gfn;
    struct page_info *cr3_page;
    unsigned long flags, cr4;
    unsigned int i;
    int rc = 0, compat;

    /* The context is a compat-mode one if the target domain is compat-mode;
     * we expect the tools to DTRT even in compat-mode callers. */
    compat = is_pv_32on64_domain(d);

#ifdef CONFIG_COMPAT
#define c(fld) (compat ? (c.cmp->fld) : (c.nat->fld))
#else
#define c(fld) (c.nat->fld)
#endif
    flags = c(flags);

    if ( !is_hvm_vcpu(v) )
    {
        if ( !compat )
        {
#ifdef __x86_64__
            if ( !is_canonical_address(c.nat->user_regs.eip) ||
                 !is_canonical_address(c.nat->event_callback_eip) ||
                 !is_canonical_address(c.nat->syscall_callback_eip) ||
                 !is_canonical_address(c.nat->failsafe_callback_eip) )
                return -EINVAL;
#endif

            fixup_guest_stack_selector(d, c.nat->user_regs.ss);
            fixup_guest_stack_selector(d, c.nat->kernel_ss);
            fixup_guest_code_selector(d, c.nat->user_regs.cs);
#ifdef __i386__
            fixup_guest_code_selector(d, c.nat->event_callback_cs);
            fixup_guest_code_selector(d, c.nat->failsafe_callback_cs);
#endif

            for ( i = 0; i < 256; i++ )
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

            for ( i = 0; i < 256; i++ )
                fixup_guest_code_selector(d, c.cmp->trap_ctxt[i].cs);
        }
#endif

        /* LDT safety checks. */
        if ( ((c(ldt_base) & (PAGE_SIZE - 1)) != 0) ||
             (c(ldt_ents) > 8192) )
            return -EINVAL;
    }

    v->fpu_initialised = !!(flags & VGCF_I387_VALID);

    v->arch.flags &= ~TF_kernel_mode;
    if ( (flags & VGCF_in_kernel) || is_hvm_vcpu(v)/*???*/ )
        v->arch.flags |= TF_kernel_mode;

    v->arch.vgc_flags = flags;

    if ( flags & VGCF_I387_VALID )
        memcpy(v->arch.fpu_ctxt, &c.nat->fpu_ctxt, sizeof(c.nat->fpu_ctxt));

    if ( !compat )
    {
        memcpy(&v->arch.user_regs, &c.nat->user_regs, sizeof(c.nat->user_regs));
        if ( !is_hvm_vcpu(v) )
            memcpy(v->arch.pv_vcpu.trap_ctxt, c.nat->trap_ctxt,
                   sizeof(c.nat->trap_ctxt));
    }
#ifdef CONFIG_COMPAT
    else
    {
        XLAT_cpu_user_regs(&v->arch.user_regs, &c.cmp->user_regs);
        for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); ++i )
            XLAT_trap_info(v->arch.pv_vcpu.trap_ctxt + i,
                           c.cmp->trap_ctxt + i);
    }
#endif

    v->arch.user_regs.eflags |= 2;

    if ( is_hvm_vcpu(v) )
    {
        for ( i = 0; i < ARRAY_SIZE(v->arch.debugreg); ++i )
            v->arch.debugreg[i] = c(debugreg[i]);

        hvm_set_info_guest(v);
        goto out;
    }

    init_int80_direct_trap(v);

    /* IOPL privileges are virtualised. */
    v->arch.pv_vcpu.iopl = (v->arch.user_regs.eflags >> 12) & 3;
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
        bool_t fail;

        if ( !compat )
        {
            fail = xen_pfn_to_cr3(pfn) != c.nat->ctrlreg[3];
#ifdef CONFIG_X86_64
            if ( pagetable_is_null(v->arch.guest_table_user) )
                fail |= c.nat->ctrlreg[1] || !(flags & VGCF_in_kernel);
            else
            {
                pfn = pagetable_get_pfn(v->arch.guest_table_user);
                fail |= xen_pfn_to_cr3(pfn) != c.nat->ctrlreg[1];
            }
        } else {
            l4_pgentry_t *l4tab = __va(pfn_to_paddr(pfn));

            pfn = l4e_get_pfn(*l4tab);
            fail = compat_pfn_to_cr3(pfn) != c.cmp->ctrlreg[3];
#endif
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
#ifdef CONFIG_X86_64
    if ( !compat )
    {
        v->arch.pv_vcpu.syscall_callback_eip = c.nat->syscall_callback_eip;
        v->arch.pv_vcpu.fs_base = c.nat->fs_base;
        v->arch.pv_vcpu.gs_base_kernel = c.nat->gs_base_kernel;
        v->arch.pv_vcpu.gs_base_user = c.nat->gs_base_user;
    }
    else
#endif
    {
        v->arch.pv_vcpu.event_callback_cs = c(event_callback_cs);
        v->arch.pv_vcpu.failsafe_callback_cs = c(failsafe_callback_cs);
    }
    v->arch.pv_vcpu.vm_assist = c(vm_assist);

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
        d->vm_assist = c(vm_assist);

    rc = put_old_guest_table(current);
    if ( rc )
        return rc;

    if ( !compat )
        rc = (int)set_gdt(v, c.nat->gdt_frames, c.nat->gdt_ents);
#ifdef CONFIG_COMPAT
    else
    {
        unsigned long gdt_frames[ARRAY_SIZE(v->arch.pv_vcpu.gdt_frames)];
        unsigned int n = (c.cmp->gdt_ents + 511) / 512;

        if ( n > ARRAY_SIZE(v->arch.pv_vcpu.gdt_frames) )
            return -EINVAL;
        for ( i = 0; i < n; ++i )
            gdt_frames[i] = c.cmp->gdt_frames[i];
        rc = (int)set_gdt(v, gdt_frames, c.cmp->gdt_ents);
    }
#endif
    if ( rc != 0 )
        return rc;

    set_bit(_VPF_in_reset, &v->pause_flags);

    if ( !compat )
        cr3_gfn = xen_cr3_to_pfn(c.nat->ctrlreg[3]);
#ifdef CONFIG_COMPAT
    else
        cr3_gfn = compat_cr3_to_pfn(c.cmp->ctrlreg[3]);
#endif
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
            rc = -EAGAIN;
        case -EAGAIN:
        case 0:
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
#ifdef __x86_64__
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
                    rc = -EAGAIN;
                case -EAGAIN:
                    v->arch.old_guest_table =
                        pagetable_get_page(v->arch.guest_table);
                    v->arch.guest_table = pagetable_null();
                    break;
                default:
                    if ( cr3_page == current->arch.old_guest_table )
                        cr3_page = NULL;
                case 0:
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

        l4tab = __va(pagetable_get_paddr(v->arch.guest_table));
        *l4tab = l4e_from_pfn(page_to_mfn(cr3_page),
            _PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED);
#endif
    }
    if ( rc )
    {
        if ( cr3_page )
            put_page(cr3_page);
        destroy_gdt(v);
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

int arch_vcpu_reset(struct vcpu *v)
{
    if ( !is_hvm_vcpu(v) )
    {
        destroy_gdt(v);
        return vcpu_destroy_pagetables(v);
    }

    vcpu_end_shutdown_deferral(v);
    return 0;
}

/* 
 * Unmap the vcpu info page if the guest decided to place it somewhere
 * else.  This is only used from arch_domain_destroy, so there's no
 * need to do anything clever.
 */
static void
unmap_vcpu_info(struct vcpu *v)
{
    unsigned long mfn;

    if ( v->arch.vcpu_info_mfn == INVALID_MFN )
        return;

    mfn = v->arch.vcpu_info_mfn;
    unmap_domain_page_global(v->vcpu_info);

    v->vcpu_info = &dummy_vcpu_info;
    v->arch.vcpu_info_mfn = INVALID_MFN;

    put_page_and_type(mfn_to_page(mfn));
}

/* 
 * Map a guest page in and point the vcpu_info pointer at it.  This
 * makes sure that the vcpu_info is always pointing at a valid piece
 * of memory, and it sets a pending event to make sure that a pending
 * event doesn't get missed.
 */
static int
map_vcpu_info(struct vcpu *v, unsigned long gfn, unsigned offset)
{
    struct domain *d = v->domain;
    void *mapping;
    vcpu_info_t *new_info;
    struct page_info *page;
    int i;

    if ( offset > (PAGE_SIZE - sizeof(vcpu_info_t)) )
        return -EINVAL;

    if ( v->arch.vcpu_info_mfn != INVALID_MFN )
        return -EINVAL;

    /* Run this command on yourself or on other offline VCPUS. */
    if ( (v != current) && !test_bit(_VPF_down, &v->pause_flags) )
        return -EINVAL;

    page = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
    if ( !page )
        return -EINVAL;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        return -EINVAL;
    }

    mapping = __map_domain_page_global(page);
    if ( mapping == NULL )
    {
        put_page_and_type(page);
        return -ENOMEM;
    }

    new_info = (vcpu_info_t *)(mapping + offset);

    if ( v->vcpu_info == &dummy_vcpu_info )
    {
        memset(new_info, 0, sizeof(*new_info));
        __vcpu_info(v, new_info, evtchn_upcall_mask) = 1;
    }
    else
    {
        memcpy(new_info, v->vcpu_info, sizeof(*new_info));
    }

    v->vcpu_info = new_info;
    v->arch.vcpu_info_mfn = page_to_mfn(page);

    /* Set new vcpu_info pointer /before/ setting pending flags. */
    wmb();

    /*
     * Mark everything as being pending just to make sure nothing gets
     * lost.  The domain will get a spurious event, but it can cope.
     */
    vcpu_info(v, evtchn_upcall_pending) = 1;
    for ( i = 0; i < BITS_PER_EVTCHN_WORD(d); i++ )
        set_bit(i, &vcpu_info(v, evtchn_pending_sel));

    return 0;
}

long
arch_do_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE(void) arg)
{
    long rc = 0;

    switch ( cmd )
    {
    case VCPUOP_register_runstate_memory_area:
    {
        struct vcpu_register_runstate_memory_area area;
        struct vcpu_runstate_info runstate;

        rc = -EFAULT;
        if ( copy_from_guest(&area, arg, 1) )
            break;

        if ( !guest_handle_okay(area.addr.h, 1) )
            break;

        rc = 0;
        runstate_guest(v) = area.addr.h;

        if ( v == current )
        {
            __copy_to_guest(runstate_guest(v), &v->runstate, 1);
        }
        else
        {
            vcpu_runstate_get(v, &runstate);
            __copy_to_guest(runstate_guest(v), &runstate, 1);
        }

        break;
    }

    case VCPUOP_register_vcpu_info:
    {
        struct domain *d = v->domain;
        struct vcpu_register_vcpu_info info;

        rc = -EFAULT;
        if ( copy_from_guest(&info, arg, 1) )
            break;

        domain_lock(d);
        rc = map_vcpu_info(v, info.mfn, info.offset);
        domain_unlock(d);

        break;
    }

    /*
     * XXX Disable for 4.0.0: __update_vcpu_system_time() writes to the given
     * virtual address even when running in another domain's address space.
     */
#if 0
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
#endif

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

#ifdef __x86_64__

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
        all_segs_okay &= loadsegment(ds, uregs->ds);

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_ES) | uregs->es) )
        all_segs_okay &= loadsegment(es, uregs->es);

    /*
     * Either selector != 0 ==> reload.
     * Also reload to reset FS_BASE if it was non-zero.
     */
    if ( unlikely((dirty_segment_mask & (DIRTY_FS | DIRTY_FS_BASE)) |
                  uregs->fs) )
        all_segs_okay &= loadsegment(fs, uregs->fs);

    /*
     * Either selector != 0 ==> reload.
     * Also reload to reset GS_BASE if it was non-zero.
     */
    if ( unlikely((dirty_segment_mask & (DIRTY_GS | DIRTY_GS_BASE_USER)) |
                  uregs->gs) )
    {
        /* Reset GS_BASE with user %gs? */
        if ( (dirty_segment_mask & DIRTY_GS) || !n->arch.pv_vcpu.gs_base_user )
            all_segs_okay &= loadsegment(gs, uregs->gs);
    }

    if ( !is_pv_32on64_domain(n->domain) )
    {
        /* This can only be non-zero if selector is NULL. */
        if ( n->arch.pv_vcpu.fs_base )
            wrmsrl(MSR_FS_BASE, n->arch.pv_vcpu.fs_base);

        /* Most kernels have non-zero GS base, so don't bother testing. */
        /* (This is also a serialising instruction, avoiding AMD erratum #88.) */
        wrmsrl(MSR_SHADOW_GS_BASE, n->arch.pv_vcpu.gs_base_kernel);

        /* This can only be non-zero if selector is NULL. */
        if ( n->arch.pv_vcpu.gs_base_user )
            wrmsrl(MSR_GS_BASE, n->arch.pv_vcpu.gs_base_user);

        /* If in kernel mode then switch the GS bases around. */
        if ( (n->arch.flags & TF_kernel_mode) )
            asm volatile ( "swapgs" );
    }

    if ( unlikely(!all_segs_okay) )
    {
        struct pv_vcpu *pv = &n->arch.pv_vcpu;
        struct cpu_user_regs *regs = guest_cpu_user_regs();
        unsigned long *rsp =
            (n->arch.flags & TF_kernel_mode) ?
            (unsigned long *)regs->rsp :
            (unsigned long *)pv->kernel_sp;
        unsigned long cs_and_mask, rflags;

        if ( is_pv_32on64_domain(n->domain) )
        {
            unsigned int *esp = ring_1(regs) ?
                                (unsigned int *)regs->rsp :
                                (unsigned int *)pv->kernel_sp;
            unsigned int cs_and_mask, eflags;
            int ret = 0;

            /* CS longword also contains full evtchn_upcall_mask. */
            cs_and_mask = (unsigned short)regs->cs |
                ((unsigned int)vcpu_info(n, evtchn_upcall_mask) << 16);
            /* Fold upcall mask into RFLAGS.IF. */
            eflags  = regs->_eflags & ~X86_EFLAGS_IF;
            eflags |= !vcpu_info(n, evtchn_upcall_mask) << 9;

            if ( !ring_1(regs) )
            {
                ret  = put_user(regs->ss,       esp-1);
                ret |= put_user(regs->_esp,     esp-2);
                esp -= 2;
            }

            if ( ret |
                 put_user(eflags,              esp-1) |
                 put_user(cs_and_mask,         esp-2) |
                 put_user(regs->_eip,          esp-3) |
                 put_user(uregs->gs,           esp-4) |
                 put_user(uregs->fs,           esp-5) |
                 put_user(uregs->es,           esp-6) |
                 put_user(uregs->ds,           esp-7) )
            {
                gdprintk(XENLOG_ERR, "Error while creating compat "
                         "failsafe callback frame.\n");
                domain_crash(n->domain);
            }

            if ( test_bit(_VGCF_failsafe_disables_events, &n->arch.vgc_flags) )
                vcpu_info(n, evtchn_upcall_mask) = 1;

            regs->entry_vector  = TRAP_syscall;
            regs->_eflags      &= 0xFFFCBEFFUL;
            regs->ss            = FLAT_COMPAT_KERNEL_SS;
            regs->_esp          = (unsigned long)(esp-7);
            regs->cs            = FLAT_COMPAT_KERNEL_CS;
            regs->_eip          = pv->failsafe_callback_eip;
            return;
        }

        if ( !(n->arch.flags & TF_kernel_mode) )
            toggle_guest_mode(n);
        else
            regs->cs &= ~3;

        /* CS longword also contains full evtchn_upcall_mask. */
        cs_and_mask = (unsigned long)regs->cs |
            ((unsigned long)vcpu_info(n, evtchn_upcall_mask) << 32);

        /* Fold upcall mask into RFLAGS.IF. */
        rflags  = regs->rflags & ~X86_EFLAGS_IF;
        rflags |= !vcpu_info(n, evtchn_upcall_mask) << 9;

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
            gdprintk(XENLOG_ERR, "Error while creating failsafe "
                    "callback frame.\n");
            domain_crash(n->domain);
        }

        if ( test_bit(_VGCF_failsafe_disables_events, &n->arch.vgc_flags) )
            vcpu_info(n, evtchn_upcall_mask) = 1;

        regs->entry_vector  = TRAP_syscall;
        regs->rflags       &= ~(X86_EFLAGS_AC|X86_EFLAGS_VM|X86_EFLAGS_RF|
                                X86_EFLAGS_NT|X86_EFLAGS_TF);
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

    regs->ds = read_segment_register(ds);
    regs->es = read_segment_register(es);
    regs->fs = read_segment_register(fs);
    regs->gs = read_segment_register(gs);

    if ( regs->ds )
        dirty_segment_mask |= DIRTY_DS;

    if ( regs->es )
        dirty_segment_mask |= DIRTY_ES;

    if ( regs->fs || is_pv_32on64_domain(v->domain) )
    {
        dirty_segment_mask |= DIRTY_FS;
        v->arch.pv_vcpu.fs_base = 0; /* != 0 selector kills fs_base */
    }
    else if ( v->arch.pv_vcpu.fs_base )
    {
        dirty_segment_mask |= DIRTY_FS_BASE;
    }

    if ( regs->gs || is_pv_32on64_domain(v->domain) )
    {
        dirty_segment_mask |= DIRTY_GS;
        v->arch.pv_vcpu.gs_base_user = 0; /* != 0 selector kills gs_base_user */
    }
    else if ( v->arch.pv_vcpu.gs_base_user )
    {
        dirty_segment_mask |= DIRTY_GS_BASE_USER;
    }

    this_cpu(dirty_segment_mask) = dirty_segment_mask;
}

#define switch_kernel_stack(v) ((void)0)

#elif defined(__i386__)

#define load_segments(n) ((void)0)
#define save_segments(p) ((void)0)

static inline void switch_kernel_stack(struct vcpu *v)
{
    struct tss_struct *tss = &this_cpu(init_tss);
    tss->esp1 = v->arch.pv_vcpu.kernel_sp;
    tss->ss1  = v->arch.pv_vcpu.kernel_ss;
}

#endif /* __i386__ */

static void paravirt_ctxt_switch_from(struct vcpu *v)
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

static void paravirt_ctxt_switch_to(struct vcpu *v)
{
    unsigned long cr4;

    set_int80_direct_trap(v);
    switch_kernel_stack(v);

    cr4 = pv_guest_cr4_to_real_cr4(v);
    if ( unlikely(cr4 != read_cr4()) )
        write_cr4(cr4);

    if ( unlikely(v->arch.debugreg[7] & DR7_ACTIVE_MASK) )
    {
        write_debugreg(0, v->arch.debugreg[0]);
        write_debugreg(1, v->arch.debugreg[1]);
        write_debugreg(2, v->arch.debugreg[2]);
        write_debugreg(3, v->arch.debugreg[3]);
        write_debugreg(6, v->arch.debugreg[6]);
        write_debugreg(7, v->arch.debugreg[7]);
    }

    if ( (v->domain->arch.tsc_mode ==  TSC_MODE_PVRDTSCP) &&
         boot_cpu_has(X86_FEATURE_RDTSCP) )
        write_rdtscp_aux(v->domain->arch.incarnation);
}

/* Update per-VCPU guest runstate shared memory area (if registered). */
static void update_runstate_area(struct vcpu *v)
{
    if ( guest_handle_is_null(runstate_guest(v)) )
        return;

#ifdef CONFIG_COMPAT
    if ( has_32bit_shinfo(v->domain) )
    {
        struct compat_vcpu_runstate_info info;

        XLAT_vcpu_runstate_info(&info, &v->runstate);
        __copy_to_guest(v->runstate_guest.compat, &info, 1);
        return;
    }
#endif

    __copy_to_guest(runstate_guest(v), &v->runstate, 1);
}

static inline int need_full_gdt(struct vcpu *v)
{
    return (!is_hvm_vcpu(v) && !is_idle_vcpu(v));
}

static void __context_switch(void)
{
    struct cpu_user_regs *stack_regs = guest_cpu_user_regs();
    unsigned int          cpu = smp_processor_id();
    struct vcpu          *p = per_cpu(curr_vcpu, cpu);
    struct vcpu          *n = current;
    struct desc_struct   *gdt;
    struct desc_ptr       gdt_desc;

    ASSERT(p != n);
    ASSERT(cpumask_empty(n->vcpu_dirty_cpumask));

    if ( !is_idle_vcpu(p) )
    {
        memcpy(&p->arch.user_regs, stack_regs, CTXT_SWITCH_STACK_BYTES);
        vcpu_save_fpu(p);
        p->arch.ctxt_switch_from(p);
    }

    /*
     * Mark this CPU in next domain's dirty cpumasks before calling
     * ctxt_switch_to(). This avoids a race on things like EPT flushing,
     * which is synchronised on that function.
     */
    if ( p->domain != n->domain )
        cpumask_set_cpu(cpu, n->domain->domain_dirty_cpumask);
    cpumask_set_cpu(cpu, n->vcpu_dirty_cpumask);

    if ( !is_idle_vcpu(n) )
    {
        memcpy(stack_regs, &n->arch.user_regs, CTXT_SWITCH_STACK_BYTES);
        if ( cpu_has_xsave )
        {
            u64 xcr0 = n->arch.xcr0 ?: XSTATE_FP_SSE;

            if ( xcr0 != get_xcr0() && !set_xcr0(xcr0) )
                BUG();
        }
        vcpu_restore_fpu_eager(n);
        n->arch.ctxt_switch_to(n);
    }

    gdt = !is_pv_32on64_vcpu(n) ? per_cpu(gdt_table, cpu) :
                                  per_cpu(compat_gdt_table, cpu);
    if ( need_full_gdt(n) )
    {
        struct page_info *page = virt_to_page(gdt);
        unsigned int i;
        for ( i = 0; i < NR_RESERVED_GDT_PAGES; i++ )
            l1e_write(n->arch.perdomain_ptes +
                      FIRST_RESERVED_GDT_PAGE + i,
                      l1e_from_page(page + i, __PAGE_HYPERVISOR));
    }

    if ( need_full_gdt(p) &&
         ((p->vcpu_id != n->vcpu_id) || !need_full_gdt(n)) )
    {
        gdt_desc.limit = LAST_RESERVED_GDT_BYTE;
        gdt_desc.base  = (unsigned long)(gdt - FIRST_RESERVED_GDT_ENTRY);
        asm volatile ( "lgdt %0" : : "m" (gdt_desc) );
    }

    write_ptbase(n);

    if ( need_full_gdt(n) &&
         ((p->vcpu_id != n->vcpu_id) || !need_full_gdt(p)) )
    {
        gdt_desc.limit = LAST_RESERVED_GDT_BYTE;
        gdt_desc.base = GDT_VIRT_START(n);
        asm volatile ( "lgdt %0" : : "m" (gdt_desc) );
    }

    if ( p->domain != n->domain )
        cpumask_clear_cpu(cpu, p->domain->domain_dirty_cpumask);
    cpumask_clear_cpu(cpu, p->vcpu_dirty_cpumask);

    per_cpu(curr_vcpu, cpu) = n;
}


void context_switch(struct vcpu *prev, struct vcpu *next)
{
    unsigned int cpu = smp_processor_id();
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

    if (prev != next)
        update_runstate_area(prev);

    if ( is_hvm_vcpu(prev) && !list_empty(&prev->arch.hvm_vcpu.tm_list) )
        pt_save_timer(prev);

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

#ifdef CONFIG_COMPAT
        if ( !is_hvm_vcpu(next) &&
             (is_idle_vcpu(prev) ||
              is_hvm_vcpu(prev) ||
              is_pv_32on64_vcpu(prev) != is_pv_32on64_vcpu(next)) )
        {
            uint64_t efer = read_efer();
            if ( !(efer & EFER_SCE) )
                write_efer(efer | EFER_SCE);
        }
#endif

        /* Re-enable interrupts before restoring state which may fault. */
        local_irq_enable();

        if ( !is_hvm_vcpu(next) )
        {
            load_LDT(next);
            load_segments(next);
        }

        set_cpuid_faulting(!is_hvm_vcpu(next) &&
                           (next->domain->domain_id != 0));
    }

    context_saved(prev);

    if (prev != next)
        update_runstate_area(next);

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

void sync_vcpu_execstate(struct vcpu *v)
{
    if ( cpumask_test_cpu(smp_processor_id(), v->vcpu_dirty_cpumask) )
        sync_local_execstate();

    /* Other cpus call __sync_local_execstate from flush ipi handler. */
    flush_tlb_mask(v->vcpu_dirty_cpumask);
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
        if ( !is_hvm_vcpu(current) )
            regs->eip += 2; /* skip re-execute 'syscall' / 'int $xx' */
        else
            current->arch.hvm_vcpu.hcall_preempted = 0;
    }
}

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
    struct mc_state *mcs = &current->mc_state;
    struct cpu_user_regs *regs;
    const char *p = format;
    unsigned long arg;
    unsigned int i;
    va_list args;

    va_start(args, format);

    if ( test_bit(_MCSF_in_multicall, &mcs->flags) )
    {
        __set_bit(_MCSF_call_preempted, &mcs->flags);

        for ( i = 0; *p != '\0'; i++ )
            mcs->call.args[i] = next_arg(p, args);
        if ( is_pv_32on64_domain(current->domain) )
        {
            for ( ; i < 6; i++ )
                mcs->call.args[i] = 0;
        }
    }
    else
    {
        regs       = guest_cpu_user_regs();
        regs->eax  = op;

        /* Ensure the hypercall trap instruction is re-executed. */
        if ( !is_hvm_vcpu(current) )
            regs->eip -= 2;  /* re-execute 'syscall' / 'int $xx' */
        else
            current->arch.hvm_vcpu.hcall_preempted = 1;

#ifdef __x86_64__
        if ( !is_hvm_vcpu(current) ?
             !is_pv_32on64_vcpu(current) :
             (hvm_guest_x86_mode(current) == 8) )
        {
            for ( i = 0; *p != '\0'; i++ )
            {
                arg = next_arg(p, args);
                switch ( i )
                {
                case 0: regs->rdi = arg; break;
                case 1: regs->rsi = arg; break;
                case 2: regs->rdx = arg; break;
                case 3: regs->r10 = arg; break;
                case 4: regs->r8  = arg; break;
                case 5: regs->r9  = arg; break;
                }
            }
        }
        else
#endif
        {
            if ( supervisor_mode_kernel )
                regs->eip &= ~31; /* re-execute entire hypercall entry stub */

            for ( i = 0; *p != '\0'; i++ )
            {
                arg = next_arg(p, args);
                switch ( i )
                {
                case 0: regs->ebx = arg; break;
                case 1: regs->ecx = arg; break;
                case 2: regs->edx = arg; break;
                case 3: regs->esi = arg; break;
                case 4: regs->edi = arg; break;
                case 5: regs->ebp = arg; break;
                }
            }
        }
    }

    va_end(args);

    return op;
}

#ifdef CONFIG_COMPAT
int hypercall_xlat_continuation(unsigned int *id, unsigned int mask, ...)
{
    int rc = 0;
    struct mc_state *mcs = &current->mc_state;
    struct cpu_user_regs *regs;
    unsigned int i, cval = 0;
    unsigned long nval = 0;
    va_list args;

    BUG_ON(id && *id > 5);
    BUG_ON(id && (mask & (1U << *id)));

    va_start(args, mask);

    if ( test_bit(_MCSF_in_multicall, &mcs->flags) )
    {
        if ( !test_bit(_MCSF_call_preempted, &mcs->flags) )
            return 0;
        for ( i = 0; i < 6; ++i, mask >>= 1 )
        {
            if ( mask & 1 )
            {
                nval = va_arg(args, unsigned long);
                cval = va_arg(args, unsigned int);
                if ( cval == nval )
                    mask &= ~1U;
                else
                    BUG_ON(nval == (unsigned int)nval);
            }
            else if ( id && *id == i )
            {
                *id = mcs->call.args[i];
                id = NULL;
            }
            if ( (mask & 1) && mcs->call.args[i] == nval )
            {
                mcs->call.args[i] = cval;
                ++rc;
            }
            else
                BUG_ON(mcs->call.args[i] != (unsigned int)mcs->call.args[i]);
        }
    }
    else
    {
        regs = guest_cpu_user_regs();
        for ( i = 0; i < 6; ++i, mask >>= 1 )
        {
            unsigned long *reg;

            switch ( i )
            {
            case 0: reg = &regs->ebx; break;
            case 1: reg = &regs->ecx; break;
            case 2: reg = &regs->edx; break;
            case 3: reg = &regs->esi; break;
            case 4: reg = &regs->edi; break;
            case 5: reg = &regs->ebp; break;
            default: BUG(); reg = NULL; break;
            }
            if ( (mask & 1) )
            {
                nval = va_arg(args, unsigned long);
                cval = va_arg(args, unsigned int);
                if ( cval == nval )
                    mask &= ~1U;
                else
                    BUG_ON(nval == (unsigned int)nval);
            }
            else if ( id && *id == i )
            {
                *id = *reg;
                id = NULL;
            }
            if ( (mask & 1) && *reg == nval )
            {
                *reg = cval;
                ++rc;
            }
            else
                BUG_ON(*reg != (unsigned int)*reg);
        }
    }

    va_end(args);

    return rc;
}
#endif

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
        case -EAGAIN:
        case -EINTR:
            ret = -EAGAIN;
            page_list_add(page, list);
            set_bit(_PGT_pinned, &page->u.inuse.type_info);
            put_page(page);
            goto out;
        default:
            BUG();
        }

        clear_superpage_mark(page);

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
                    ret = -EAGAIN;
                    goto out;
                case -EAGAIN:
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
            ret = -EAGAIN;
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
        pci_release_devices(d);

        /* Tear down paging-assistance stuff. */
        paging_teardown(d);

        /* Drop the in-use references to page-table bases. */
        for_each_vcpu ( d, v )
        {
            ret = vcpu_destroy_pagetables(v);
            if ( ret )
                return ret;

            unmap_vcpu_info(v);
        }

        if ( !is_hvm_domain(d) )
        {
            for_each_vcpu ( d, v )
            {
                /*
                 * Relinquish GDT mappings. No need for explicit unmapping of
                 * the LDT as it automatically gets squashed with the guest
                 * mappings.
                 */
                destroy_gdt(v);
            }

            if ( d->arch.pv_domain.pirq_eoi_map != NULL )
            {
                unmap_domain_page_global(d->arch.pv_domain.pirq_eoi_map);
                put_page_and_type(
                    mfn_to_page(d->arch.pv_domain.pirq_eoi_map_mfn));
                d->arch.pv_domain.pirq_eoi_map = NULL;
                d->arch.pv_domain.auto_unmask = 0;
            }
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
        /* Fallthrough. Relinquish every page of memory. */
    case RELMEM_xen:
        ret = relinquish_memory(d, &d->xenpage_list, ~0UL);
        if ( ret )
            return ret;
#if CONFIG_PAGING_LEVELS >= 4
        d->arch.relmem = RELMEM_l4;
        /* fallthrough */

    case RELMEM_l4:
        ret = relinquish_memory(d, &d->page_list, PGT_l4_page_table);
        if ( ret )
            return ret;
#endif
#if CONFIG_PAGING_LEVELS >= 3
        d->arch.relmem = RELMEM_l3;
        /* fallthrough */

    case RELMEM_l3:
        ret = relinquish_memory(d, &d->page_list, PGT_l3_page_table);
        if ( ret )
            return ret;
#endif
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
}

void domain_cpuid(
    struct domain *d,
    unsigned int  input,
    unsigned int  sub_input,
    unsigned int  *eax,
    unsigned int  *ebx,
    unsigned int  *ecx,
    unsigned int  *edx)
{
    cpuid_input_t *cpuid;
    int i;

    for ( i = 0; i < MAX_CPUID_INPUT; i++ )
    {
        cpuid = &d->arch.cpuids[i];

        if ( (cpuid->input[0] == input) &&
             ((cpuid->input[1] == XEN_CPUID_INPUT_UNUSED) ||
              (cpuid->input[1] == sub_input)) )
        {
            *eax = cpuid->eax;
            *ebx = cpuid->ebx;
            *ecx = cpuid->ecx;
            *edx = cpuid->edx;

            /*
             * Do not advertise host's invariant TSC unless the TSC is
             * emulated, or the domain cannot migrate to other hosts.
             */
            if ( (input == 0x80000007) && /* Advanced Power Management */
                 !d->disable_migrate && !d->arch.vtsc )
                *edx &= ~(1u<<8); /* TSC Invariant */

            return;
        }
    }

    *eax = *ebx = *ecx = *edx = 0;
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
    bool_t running = v->is_running;
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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
