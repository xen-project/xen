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
#include <xen/multicall.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/percpu.h>
#include <asm/regs.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/mpspec.h>
#include <asm/ldt.h>
#include <asm/paging.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/msr.h>
#ifdef CONFIG_COMPAT
#include <compat/vcpu.h>
#endif

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

static void paravirt_ctxt_switch_from(struct vcpu *v);
static void paravirt_ctxt_switch_to(struct vcpu *v);

static void vcpu_destroy_pagetables(struct vcpu *v);

static void continue_idle_domain(struct vcpu *v)
{
    reset_stack_and_jump(idle_loop);
}

static void continue_nonidle_domain(struct vcpu *v)
{
    reset_stack_and_jump(ret_from_intr);
}

static void default_idle(void)
{
    local_irq_disable();
    if ( !softirq_pending(smp_processor_id()) )
        safe_halt();
    else
        local_irq_enable();
}

void idle_loop(void)
{
    for ( ; ; )
    {
        page_scrub_schedule_work();
        default_idle();
        do_softirq();
    }
}

void startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));
    cpu_set(smp_processor_id(), v->domain->domain_dirty_cpumask);
    cpu_set(smp_processor_id(), v->vcpu_dirty_cpumask);

    reset_stack_and_jump(idle_loop);
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
        list_for_each_entry ( page, &d->page_list, list )
        {
            printk("    DomPage %p: mfn=%p, caf=%08x, taf=%" PRtype_info "\n",
                   _p(page_to_maddr(page)), _p(page_to_mfn(page)),
                   page->count_info, page->u.inuse.type_info);
        }
    }

    list_for_each_entry ( page, &d->xenpage_list, list )
    {
        printk("    XenPage %p: mfn=%p, caf=%08x, taf=%" PRtype_info "\n",
               _p(page_to_maddr(page)), _p(page_to_mfn(page)),
               page->count_info, page->u.inuse.type_info);
    }
}

struct vcpu *alloc_vcpu_struct(void)
{
    struct vcpu *v;
    if ( (v = xmalloc(struct vcpu)) != NULL )
        memset(v, 0, sizeof(*v));
    return v;
}

void free_vcpu_struct(struct vcpu *v)
{
    xfree(v);
}

#ifdef CONFIG_COMPAT

int setup_arg_xlat_area(struct vcpu *v, l4_pgentry_t *l4tab)
{
    struct domain *d = v->domain;
    unsigned i;
    struct page_info *pg;

    if ( !d->arch.mm_arg_xlat_l3 )
    {
        pg = alloc_domheap_page(NULL);
        if ( !pg )
            return -ENOMEM;
        d->arch.mm_arg_xlat_l3 = clear_page(page_to_virt(pg));
    }

    l4tab[l4_table_offset(COMPAT_ARG_XLAT_VIRT_BASE)] =
        l4e_from_paddr(__pa(d->arch.mm_arg_xlat_l3), __PAGE_HYPERVISOR);

    for ( i = 0; i < COMPAT_ARG_XLAT_PAGES; ++i )
    {
        unsigned long va = COMPAT_ARG_XLAT_VIRT_START(v->vcpu_id) + i * PAGE_SIZE;
        l2_pgentry_t *l2tab;
        l1_pgentry_t *l1tab;

        if ( !l3e_get_intpte(d->arch.mm_arg_xlat_l3[l3_table_offset(va)]) )
        {
            pg = alloc_domheap_page(NULL);
            if ( !pg )
                return -ENOMEM;
            clear_page(page_to_virt(pg));
            d->arch.mm_arg_xlat_l3[l3_table_offset(va)] = l3e_from_page(pg, __PAGE_HYPERVISOR);
        }
        l2tab = l3e_to_l2e(d->arch.mm_arg_xlat_l3[l3_table_offset(va)]);
        if ( !l2e_get_intpte(l2tab[l2_table_offset(va)]) )
        {
            pg = alloc_domheap_page(NULL);
            if ( !pg )
                return -ENOMEM;
            clear_page(page_to_virt(pg));
            l2tab[l2_table_offset(va)] = l2e_from_page(pg, __PAGE_HYPERVISOR);
        }
        l1tab = l2e_to_l1e(l2tab[l2_table_offset(va)]);
        BUG_ON(l1e_get_intpte(l1tab[l1_table_offset(va)]));
        pg = alloc_domheap_page(NULL);
        if ( !pg )
            return -ENOMEM;
        l1tab[l1_table_offset(va)] = l1e_from_page(pg, PAGE_HYPERVISOR);
    }

    return 0;
}

static void release_arg_xlat_area(struct domain *d)
{
    if ( d->arch.mm_arg_xlat_l3 )
    {
        unsigned l3;

        for ( l3 = 0; l3 < L3_PAGETABLE_ENTRIES; ++l3 )
        {
            if ( l3e_get_intpte(d->arch.mm_arg_xlat_l3[l3]) )
            {
                l2_pgentry_t *l2tab = l3e_to_l2e(d->arch.mm_arg_xlat_l3[l3]);
                unsigned l2;

                for ( l2 = 0; l2 < L2_PAGETABLE_ENTRIES; ++l2 )
                {
                    if ( l2e_get_intpte(l2tab[l2]) )
                    {
                        l1_pgentry_t *l1tab = l2e_to_l1e(l2tab[l2]);
                        unsigned l1;

                        for ( l1 = 0; l1 < L1_PAGETABLE_ENTRIES; ++l1 )
                        {
                            if ( l1e_get_intpte(l1tab[l1]) )
                                free_domheap_page(l1e_get_page(l1tab[l1]));
                        }
                        free_domheap_page(l2e_get_page(l2tab[l2]));
                    }
                }
                free_domheap_page(l3e_get_page(d->arch.mm_arg_xlat_l3[l3]));
            }
        }
        free_domheap_page(virt_to_page(d->arch.mm_arg_xlat_l3));
    }
}

static int setup_compat_l4(struct vcpu *v)
{
    struct page_info *pg = alloc_domheap_page(NULL);
    l4_pgentry_t *l4tab;
    int rc;

    if ( !pg )
        return -ENOMEM;
    l4tab = copy_page(page_to_virt(pg), idle_pg_table);
    l4tab[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_page(pg, __PAGE_HYPERVISOR);
    l4tab[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_paddr(__pa(v->domain->arch.mm_perdomain_l3), __PAGE_HYPERVISOR);
    v->arch.guest_table = pagetable_from_page(pg);
    v->arch.guest_table_user = v->arch.guest_table;

    if ( (rc = setup_arg_xlat_area(v, l4tab)) < 0 )
    {
        free_domheap_page(pg);
        return rc;
    }

    return 0;
}

static void release_compat_l4(struct vcpu *v)
{
    free_domheap_page(pagetable_get_page(v->arch.guest_table));
    v->arch.guest_table = pagetable_null();
    v->arch.guest_table_user = pagetable_null();
}

static inline int may_switch_mode(struct domain *d)
{
    return (d->tot_pages == 0);
}

int switch_native(struct domain *d)
{
    l1_pgentry_t gdt_l1e;
    unsigned int vcpuid;

    if ( d == NULL )
        return -EINVAL;
    if ( !may_switch_mode(d) )
        return -EACCES;
    if ( !IS_COMPAT(d) )
        return 0;

    clear_bit(_DOMF_compat, &d->domain_flags);
    release_arg_xlat_area(d);

    /* switch gdt */
    gdt_l1e = l1e_from_page(virt_to_page(gdt_table), PAGE_HYPERVISOR);
    for ( vcpuid = 0; vcpuid < MAX_VIRT_CPUS; vcpuid++ )
    {
        d->arch.mm_perdomain_pt[((vcpuid << GDT_LDT_VCPU_SHIFT) +
                                 FIRST_RESERVED_GDT_PAGE)] = gdt_l1e;
        if (d->vcpu[vcpuid])
            release_compat_l4(d->vcpu[vcpuid]);
    }

    d->arch.physaddr_bitsize = 64;

    return 0;
}

int switch_compat(struct domain *d)
{
    l1_pgentry_t gdt_l1e;
    unsigned int vcpuid;

    if ( d == NULL )
        return -EINVAL;
    if ( compat_disabled )
        return -ENOSYS;
    if ( !may_switch_mode(d) )
        return -EACCES;
    if ( IS_COMPAT(d) )
        return 0;

    set_bit(_DOMF_compat, &d->domain_flags);

    /* switch gdt */
    gdt_l1e = l1e_from_page(virt_to_page(compat_gdt_table), PAGE_HYPERVISOR);
    for ( vcpuid = 0; vcpuid < MAX_VIRT_CPUS; vcpuid++ )
    {
        d->arch.mm_perdomain_pt[((vcpuid << GDT_LDT_VCPU_SHIFT) +
                                 FIRST_RESERVED_GDT_PAGE)] = gdt_l1e;
        if (d->vcpu[vcpuid]
            && setup_compat_l4(d->vcpu[vcpuid]) != 0)
            return -ENOMEM;
    }

    d->arch.physaddr_bitsize =
        fls((1UL << 32) - HYPERVISOR_COMPAT_VIRT_START(d)) - 1
        + (PAGE_SIZE - 2);

    return 0;
}

#else
#define release_arg_xlat_area(d) ((void)0)
#define setup_compat_l4(v) 0
#define release_compat_l4(v) ((void)0)
#endif

int vcpu_initialise(struct vcpu *v)
{
    struct domain *d = v->domain;
    int rc;

    v->arch.flags = TF_kernel_mode;

    pae_l3_cache_init(&v->arch.pae_l3_cache);

    paging_vcpu_init(v);

    if ( is_hvm_domain(d) )
    {
        if ( (rc = hvm_vcpu_initialise(v)) != 0 )
            return rc;
    }
    else
    {
        /* PV guests get an emulated PIT too for video BIOSes to use. */
        if ( !is_idle_domain(d) && (v->vcpu_id == 0) )
            pit_init(v, cpu_khz);

        v->arch.schedule_tail = continue_nonidle_domain;
        v->arch.ctxt_switch_from = paravirt_ctxt_switch_from;
        v->arch.ctxt_switch_to   = paravirt_ctxt_switch_to;

        if ( is_idle_domain(d) )
        {
            v->arch.schedule_tail = continue_idle_domain;
            v->arch.cr3           = __pa(idle_pg_table);
        }
    }

    v->arch.perdomain_ptes =
        d->arch.mm_perdomain_pt + (v->vcpu_id << GDT_LDT_VCPU_SHIFT);

    if ( IS_COMPAT(d) && (rc = setup_compat_l4(v)) != 0 )
        return rc;

    return 0;
}

void vcpu_destroy(struct vcpu *v)
{
    if ( IS_COMPAT(v->domain) )
        release_compat_l4(v);
}

int arch_domain_create(struct domain *d)
{
#ifdef __x86_64__
    struct page_info *pg;
    int i;
#endif
    l1_pgentry_t gdt_l1e;
    int vcpuid, pdpt_order;
    int rc = -ENOMEM;

    pdpt_order = get_order_from_bytes(PDPT_L1_ENTRIES * sizeof(l1_pgentry_t));
    d->arch.mm_perdomain_pt = alloc_xenheap_pages(pdpt_order);
    if ( d->arch.mm_perdomain_pt == NULL )
        goto fail;
    memset(d->arch.mm_perdomain_pt, 0, PAGE_SIZE << pdpt_order);

    /*
     * Map Xen segments into every VCPU's GDT, irrespective of whether every
     * VCPU will actually be used. This avoids an NMI race during context
     * switch: if we take an interrupt after switching CR3 but before switching
     * GDT, and the old VCPU# is invalid in the new domain, we would otherwise
     * try to load CS from an invalid table.
     */
    gdt_l1e = l1e_from_page(virt_to_page(gdt_table), PAGE_HYPERVISOR);
    for ( vcpuid = 0; vcpuid < MAX_VIRT_CPUS; vcpuid++ )
        d->arch.mm_perdomain_pt[((vcpuid << GDT_LDT_VCPU_SHIFT) +
                                 FIRST_RESERVED_GDT_PAGE)] = gdt_l1e;

#if defined(__i386__)

    mapcache_init(d);

#else /* __x86_64__ */

    if ( (pg = alloc_domheap_page(NULL)) == NULL )
        goto fail;
    d->arch.mm_perdomain_l2 = clear_page(page_to_virt(pg));
    for ( i = 0; i < (1 << pdpt_order); i++ )
        d->arch.mm_perdomain_l2[l2_table_offset(PERDOMAIN_VIRT_START)+i] =
            l2e_from_page(virt_to_page(d->arch.mm_perdomain_pt)+i,
                          __PAGE_HYPERVISOR);

    if ( (pg = alloc_domheap_page(NULL)) == NULL )
        goto fail;
    d->arch.mm_perdomain_l3 = clear_page(page_to_virt(pg));
    d->arch.mm_perdomain_l3[l3_table_offset(PERDOMAIN_VIRT_START)] =
        l3e_from_page(virt_to_page(d->arch.mm_perdomain_l2),
                            __PAGE_HYPERVISOR);

#endif /* __x86_64__ */

#ifdef CONFIG_COMPAT
    HYPERVISOR_COMPAT_VIRT_START(d) = __HYPERVISOR_COMPAT_VIRT_START;
#endif

    paging_domain_init(d);

    if ( !is_idle_domain(d) )
    {
        d->arch.ioport_caps = 
            rangeset_new(d, "I/O Ports", RANGESETF_prettyprint_hex);
        if ( d->arch.ioport_caps == NULL )
            goto fail;

        if ( (d->shared_info = alloc_xenheap_page()) == NULL )
            goto fail;

        memset(d->shared_info, 0, PAGE_SIZE);
        share_xen_page_with_guest(
            virt_to_page(d->shared_info), d, XENSHARE_writable);
    }

    return is_hvm_domain(d) ? hvm_domain_initialise(d) : 0;

 fail:
    free_xenheap_page(d->shared_info);
#ifdef __x86_64__
    free_domheap_page(virt_to_page(d->arch.mm_perdomain_l2));
    free_domheap_page(virt_to_page(d->arch.mm_perdomain_l3));
#endif
    free_xenheap_pages(d->arch.mm_perdomain_pt, pdpt_order);
    return rc;
}

void arch_domain_destroy(struct domain *d)
{
    struct vcpu *v;

    if ( is_hvm_domain(d) )
    {
        for_each_vcpu ( d, v )
            hvm_vcpu_destroy(v);
        hvm_domain_destroy(d);
    }

    paging_final_teardown(d);

    free_xenheap_pages(
        d->arch.mm_perdomain_pt,
        get_order_from_bytes(PDPT_L1_ENTRIES * sizeof(l1_pgentry_t)));

#ifdef __x86_64__
    free_domheap_page(virt_to_page(d->arch.mm_perdomain_l2));
    free_domheap_page(virt_to_page(d->arch.mm_perdomain_l3));
#endif

    if ( IS_COMPAT(d) )
        release_arg_xlat_area(d);

    free_xenheap_page(d->shared_info);
}

/* This is called by arch_final_setup_guest and do_boot_vcpu */
int arch_set_info_guest(
    struct vcpu *v, vcpu_guest_context_u c)
{
    struct domain *d = v->domain;
#ifdef CONFIG_COMPAT
#define c(fld) (!IS_COMPAT(d) ? (c.nat->fld) : (c.cmp->fld))
#else
#define c(fld) (c.nat->fld)
#endif
    unsigned long cr3_pfn = INVALID_MFN;
    unsigned long flags = c(flags);
    int i, rc;

    if ( !is_hvm_vcpu(v) )
    {
        if ( !IS_COMPAT(d) )
        {
            fixup_guest_stack_selector(d, c.nat->user_regs.ss);
            fixup_guest_stack_selector(d, c.nat->kernel_ss);
            fixup_guest_code_selector(d, c.nat->user_regs.cs);
#ifdef __i386__
            fixup_guest_code_selector(d, c.nat->event_callback_cs);
            fixup_guest_code_selector(d, c.nat->failsafe_callback_cs);
#endif

            for ( i = 0; i < 256; i++ )
                fixup_guest_code_selector(d, c.nat->trap_ctxt[i].cs);

            /* LDT safety checks. */
            if ( ((c.nat->ldt_base & (PAGE_SIZE-1)) != 0) ||
                 (c.nat->ldt_ents > 8192) ||
                 !array_access_ok(c.nat->ldt_base,
                                  c.nat->ldt_ents,
                                  LDT_ENTRY_SIZE) )
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

            /* LDT safety checks. */
            if ( ((c.cmp->ldt_base & (PAGE_SIZE-1)) != 0) ||
                 (c.cmp->ldt_ents > 8192) ||
                 !compat_array_access_ok(c.cmp->ldt_base,
                                         c.cmp->ldt_ents,
                                         LDT_ENTRY_SIZE) )
                return -EINVAL;
        }
#endif
    }

    clear_bit(_VCPUF_fpu_initialised, &v->vcpu_flags);
    if ( flags & VGCF_I387_VALID )
        set_bit(_VCPUF_fpu_initialised, &v->vcpu_flags);

    v->arch.flags &= ~TF_kernel_mode;
    if ( (flags & VGCF_in_kernel) || is_hvm_vcpu(v)/*???*/ )
        v->arch.flags |= TF_kernel_mode;

    if ( !IS_COMPAT(v->domain) )
        memcpy(&v->arch.guest_context, c.nat, sizeof(*c.nat));
#ifdef CONFIG_COMPAT
    else
    {
        XLAT_vcpu_guest_context(&v->arch.guest_context, c.cmp);
    }
#endif

    /* Only CR0.TS is modifiable by guest or admin. */
    v->arch.guest_context.ctrlreg[0] &= X86_CR0_TS;
    v->arch.guest_context.ctrlreg[0] |= read_cr0() & ~X86_CR0_TS;

    init_int80_direct_trap(v);

    if ( !is_hvm_vcpu(v) )
    {
        /* IOPL privileges are virtualised. */
        v->arch.iopl = (v->arch.guest_context.user_regs.eflags >> 12) & 3;
        v->arch.guest_context.user_regs.eflags &= ~EF_IOPL;

        /* Ensure real hardware interrupts are enabled. */
        v->arch.guest_context.user_regs.eflags |= EF_IE;
    }
    else
    {
        hvm_load_cpu_guest_regs(v, &v->arch.guest_context.user_regs);
    }

    if ( test_bit(_VCPUF_initialised, &v->vcpu_flags) )
        return 0;

    memset(v->arch.guest_context.debugreg, 0,
           sizeof(v->arch.guest_context.debugreg));
    for ( i = 0; i < 8; i++ )
        (void)set_debugreg(v, i, c(debugreg[i]));

    if ( v->vcpu_id == 0 )
        d->vm_assist = c(vm_assist);

    if ( !is_hvm_vcpu(v) )
    {
        if ( !IS_COMPAT(d) )
            rc = (int)set_gdt(v, c.nat->gdt_frames, c.nat->gdt_ents);
#ifdef CONFIG_COMPAT
        else
        {
            unsigned long gdt_frames[ARRAY_SIZE(c.cmp->gdt_frames)];
            unsigned int i, n = (c.cmp->gdt_ents + 511) / 512;

            if ( n > ARRAY_SIZE(c.cmp->gdt_frames) )
                return -EINVAL;
            for ( i = 0; i < n; ++i )
                gdt_frames[i] = c.cmp->gdt_frames[i];
            rc = (int)set_gdt(v, gdt_frames, c.cmp->gdt_ents);
        }
#endif
        if ( rc != 0 )
            return rc;

        if ( !IS_COMPAT(d) )
        {
            cr3_pfn = gmfn_to_mfn(d, xen_cr3_to_pfn(c.nat->ctrlreg[3]));

            if ( paging_mode_refcounts(d)
                 ? !get_page(mfn_to_page(cr3_pfn), d)
                 : !get_page_and_type(mfn_to_page(cr3_pfn), d,
                                      PGT_base_page_table) )
            {
                destroy_gdt(v);
                return -EINVAL;
            }

            v->arch.guest_table = pagetable_from_pfn(cr3_pfn);
        }
#ifdef CONFIG_COMPAT
        else
        {
            l4_pgentry_t *l4tab;

            cr3_pfn = gmfn_to_mfn(d, compat_cr3_to_pfn(c.cmp->ctrlreg[3]));

            if ( paging_mode_refcounts(d)
                 ? !get_page(mfn_to_page(cr3_pfn), d)
                 : !get_page_and_type(mfn_to_page(cr3_pfn), d,
                                    PGT_l3_page_table) )
            {
                destroy_gdt(v);
                return -EINVAL;
            }

            l4tab = __va(pagetable_get_paddr(v->arch.guest_table));
            *l4tab = l4e_from_pfn(cr3_pfn, _PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED);
        }
#endif
    }    

    if ( v->vcpu_id == 0 )
        update_domain_wallclock_time(d);

    /* Don't redo final setup */
    set_bit(_VCPUF_initialised, &v->vcpu_flags);

    if ( paging_mode_enabled(d) )
        paging_update_paging_modes(v);

    update_cr3(v);

    return 0;
#undef c
}

int arch_vcpu_reset(struct vcpu *v)
{
    destroy_gdt(v);
    vcpu_destroy_pagetables(v);
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

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

#ifdef __x86_64__

#define loadsegment(seg,value) ({               \
    int __r = 1;                                \
    __asm__ __volatile__ (                      \
        "1: movl %k1,%%" #seg "\n2:\n"          \
        ".section .fixup,\"ax\"\n"              \
        "3: xorl %k0,%k0\n"                     \
        "   movl %k0,%%" #seg "\n"              \
        "   jmp 2b\n"                           \
        ".previous\n"                           \
        ".section __ex_table,\"a\"\n"           \
        "   .align 8\n"                         \
        "   .quad 1b,3b\n"                      \
        ".previous"                             \
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
    struct vcpu_guest_context *nctxt = &n->arch.guest_context;
    int all_segs_okay = 1;
    unsigned int dirty_segment_mask, cpu = smp_processor_id();

    /* Load and clear the dirty segment mask. */
    dirty_segment_mask = per_cpu(dirty_segment_mask, cpu);
    per_cpu(dirty_segment_mask, cpu) = 0;

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_DS) | nctxt->user_regs.ds) )
        all_segs_okay &= loadsegment(ds, nctxt->user_regs.ds);

    /* Either selector != 0 ==> reload. */
    if ( unlikely((dirty_segment_mask & DIRTY_ES) | nctxt->user_regs.es) )
        all_segs_okay &= loadsegment(es, nctxt->user_regs.es);

    /*
     * Either selector != 0 ==> reload.
     * Also reload to reset FS_BASE if it was non-zero.
     */
    if ( unlikely((dirty_segment_mask & (DIRTY_FS | DIRTY_FS_BASE)) |
                  nctxt->user_regs.fs) )
        all_segs_okay &= loadsegment(fs, nctxt->user_regs.fs);

    /*
     * Either selector != 0 ==> reload.
     * Also reload to reset GS_BASE if it was non-zero.
     */
    if ( unlikely((dirty_segment_mask & (DIRTY_GS | DIRTY_GS_BASE_USER)) |
                  nctxt->user_regs.gs) )
    {
        /* Reset GS_BASE with user %gs? */
        if ( (dirty_segment_mask & DIRTY_GS) || !nctxt->gs_base_user )
            all_segs_okay &= loadsegment(gs, nctxt->user_regs.gs);
    }

    if ( !IS_COMPAT(n->domain) )
    {
        /* This can only be non-zero if selector is NULL. */
        if ( nctxt->fs_base )
            wrmsr(MSR_FS_BASE,
                  nctxt->fs_base,
                  nctxt->fs_base>>32);

        /* Most kernels have non-zero GS base, so don't bother testing. */
        /* (This is also a serialising instruction, avoiding AMD erratum #88.) */
        wrmsr(MSR_SHADOW_GS_BASE,
              nctxt->gs_base_kernel,
              nctxt->gs_base_kernel>>32);

        /* This can only be non-zero if selector is NULL. */
        if ( nctxt->gs_base_user )
            wrmsr(MSR_GS_BASE,
                  nctxt->gs_base_user,
                  nctxt->gs_base_user>>32);

        /* If in kernel mode then switch the GS bases around. */
        if ( (n->arch.flags & TF_kernel_mode) )
            __asm__ __volatile__ ( "swapgs" );
    }

    if ( unlikely(!all_segs_okay) )
    {
        struct cpu_user_regs *regs = guest_cpu_user_regs();
        unsigned long *rsp =
            (n->arch.flags & TF_kernel_mode) ?
            (unsigned long *)regs->rsp :
            (unsigned long *)nctxt->kernel_sp;
        unsigned long cs_and_mask, rflags;

        if ( IS_COMPAT(n->domain) )
        {
            unsigned int *esp = ring_1(regs) ?
                                (unsigned int *)regs->rsp :
                                (unsigned int *)nctxt->kernel_sp;
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
                 put_user(nctxt->user_regs.gs, esp-4) |
                 put_user(nctxt->user_regs.fs, esp-5) |
                 put_user(nctxt->user_regs.es, esp-6) |
                 put_user(nctxt->user_regs.ds, esp-7) )
            {
                gdprintk(XENLOG_ERR, "Error while creating compat "
                         "failsafe callback frame.\n");
                domain_crash(n->domain);
            }

            if ( test_bit(_VGCF_failsafe_disables_events,
                          &n->arch.guest_context.flags) )
                vcpu_info(n, evtchn_upcall_mask) = 1;

            regs->entry_vector  = TRAP_syscall;
            regs->_eflags      &= 0xFFFCBEFFUL;
            regs->ss            = FLAT_COMPAT_KERNEL_SS;
            regs->_esp          = (unsigned long)(esp-7);
            regs->cs            = FLAT_COMPAT_KERNEL_CS;
            regs->_eip          = nctxt->failsafe_callback_eip;
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
             put_user(nctxt->user_regs.gs, rsp- 6) |
             put_user(nctxt->user_regs.fs, rsp- 7) |
             put_user(nctxt->user_regs.es, rsp- 8) |
             put_user(nctxt->user_regs.ds, rsp- 9) |
             put_user(regs->r11,           rsp-10) |
             put_user(regs->rcx,           rsp-11) )
        {
            gdprintk(XENLOG_ERR, "Error while creating failsafe "
                    "callback frame.\n");
            domain_crash(n->domain);
        }

        if ( test_bit(_VGCF_failsafe_disables_events,
                      &n->arch.guest_context.flags) )
            vcpu_info(n, evtchn_upcall_mask) = 1;

        regs->entry_vector  = TRAP_syscall;
        regs->rflags       &= ~(X86_EFLAGS_AC|X86_EFLAGS_VM|X86_EFLAGS_RF|
                                X86_EFLAGS_NT|X86_EFLAGS_TF);
        regs->ss            = FLAT_KERNEL_SS;
        regs->rsp           = (unsigned long)(rsp-11);
        regs->cs            = FLAT_KERNEL_CS;
        regs->rip           = nctxt->failsafe_callback_eip;
    }
}

static void save_segments(struct vcpu *v)
{
    struct vcpu_guest_context *ctxt = &v->arch.guest_context;
    struct cpu_user_regs      *regs = &ctxt->user_regs;
    unsigned int dirty_segment_mask = 0;

    regs->ds = read_segment_register(ds);
    regs->es = read_segment_register(es);
    regs->fs = read_segment_register(fs);
    regs->gs = read_segment_register(gs);

    if ( regs->ds )
        dirty_segment_mask |= DIRTY_DS;

    if ( regs->es )
        dirty_segment_mask |= DIRTY_ES;

    if ( regs->fs || IS_COMPAT(v->domain) )
    {
        dirty_segment_mask |= DIRTY_FS;
        ctxt->fs_base = 0; /* != 0 selector kills fs_base */
    }
    else if ( ctxt->fs_base )
    {
        dirty_segment_mask |= DIRTY_FS_BASE;
    }

    if ( regs->gs || IS_COMPAT(v->domain) )
    {
        dirty_segment_mask |= DIRTY_GS;
        ctxt->gs_base_user = 0; /* != 0 selector kills gs_base_user */
    }
    else if ( ctxt->gs_base_user )
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
    struct tss_struct *tss = &init_tss[smp_processor_id()];
    tss->esp1 = v->arch.guest_context.kernel_sp;
    tss->ss1  = v->arch.guest_context.kernel_ss;
}

#endif /* __i386__ */

static void paravirt_ctxt_switch_from(struct vcpu *v)
{
    save_segments(v);
}

static void paravirt_ctxt_switch_to(struct vcpu *v)
{
    set_int80_direct_trap(v);
    switch_kernel_stack(v);
}

#define loaddebug(_v,_reg) \
    __asm__ __volatile__ ("mov %0,%%db" #_reg : : "r" ((_v)->debugreg[_reg]))

static void __context_switch(void)
{
    struct cpu_user_regs *stack_regs = guest_cpu_user_regs();
    unsigned int          cpu = smp_processor_id();
    struct vcpu          *p = per_cpu(curr_vcpu, cpu);
    struct vcpu          *n = current;

    ASSERT(p != n);
    ASSERT(cpus_empty(n->vcpu_dirty_cpumask));

    if ( !is_idle_vcpu(p) )
    {
        memcpy(&p->arch.guest_context.user_regs,
               stack_regs,
               CTXT_SWITCH_STACK_BYTES);
        unlazy_fpu(p);
        p->arch.ctxt_switch_from(p);
    }

    if ( !is_idle_vcpu(n) )
    {
        memcpy(stack_regs,
               &n->arch.guest_context.user_regs,
               CTXT_SWITCH_STACK_BYTES);

        /* Maybe switch the debug registers. */
        if ( unlikely(n->arch.guest_context.debugreg[7]) )
        {
            loaddebug(&n->arch.guest_context, 0);
            loaddebug(&n->arch.guest_context, 1);
            loaddebug(&n->arch.guest_context, 2);
            loaddebug(&n->arch.guest_context, 3);
            /* no 4 and 5 */
            loaddebug(&n->arch.guest_context, 6);
            loaddebug(&n->arch.guest_context, 7);
        }
        n->arch.ctxt_switch_to(n);
    }

    if ( p->domain != n->domain )
        cpu_set(cpu, n->domain->domain_dirty_cpumask);
    cpu_set(cpu, n->vcpu_dirty_cpumask);

    write_ptbase(n);

    if ( p->vcpu_id != n->vcpu_id )
    {
        char gdt_load[10];
        *(unsigned short *)(&gdt_load[0]) = LAST_RESERVED_GDT_BYTE;
        *(unsigned long  *)(&gdt_load[2]) = GDT_VIRT_START(n);
        __asm__ __volatile__ ( "lgdt %0" : "=m" (gdt_load) );
    }

    if ( p->domain != n->domain )
        cpu_clear(cpu, p->domain->domain_dirty_cpumask);
    cpu_clear(cpu, p->vcpu_dirty_cpumask);

    per_cpu(curr_vcpu, cpu) = n;
}


void context_switch(struct vcpu *prev, struct vcpu *next)
{
    unsigned int cpu = smp_processor_id();
    cpumask_t dirty_mask = next->vcpu_dirty_cpumask;

    ASSERT(local_irq_is_enabled());

    /* Allow at most one CPU at a time to be dirty. */
    ASSERT(cpus_weight(dirty_mask) <= 1);
    if ( unlikely(!cpu_isset(cpu, dirty_mask) && !cpus_empty(dirty_mask)) )
    {
        /* Other cpus call __sync_lazy_execstate from flush ipi handler. */
        if ( !cpus_empty(next->vcpu_dirty_cpumask) )
            flush_tlb_mask(next->vcpu_dirty_cpumask);
    }

    local_irq_disable();

    if ( is_hvm_vcpu(prev) && !list_empty(&prev->arch.hvm_vcpu.tm_list) )
        pt_freeze_time(prev);

    set_current(next);

    if ( (per_cpu(curr_vcpu, cpu) == next) || is_idle_vcpu(next) )
    {
        local_irq_enable();
    }
    else
    {
        __context_switch();

#ifdef CONFIG_COMPAT
        if ( is_idle_vcpu(prev)
             || IS_COMPAT(prev->domain) != IS_COMPAT(next->domain) )
        {
            uint32_t efer_lo, efer_hi;

            local_flush_tlb_one(GDT_VIRT_START(next) + FIRST_RESERVED_GDT_BYTE);

            rdmsr(MSR_EFER, efer_lo, efer_hi);
            if ( !IS_COMPAT(next->domain) == !(efer_lo & EFER_SCE) )
            {
                efer_lo ^= EFER_SCE;
                wrmsr(MSR_EFER, efer_lo, efer_hi);
            }
        }
#endif

        /* Re-enable interrupts before restoring state which may fault. */
        local_irq_enable();

        if ( !is_hvm_vcpu(next) )
        {
            load_LDT(next);
            load_segments(next);
        }
    }

    context_saved(prev);

    /* Update per-VCPU guest runstate shared memory area (if registered). */
    if ( !guest_handle_is_null(runstate_guest(next)) )
    {
        if ( !IS_COMPAT(next->domain) )
            __copy_to_guest(runstate_guest(next), &next->runstate, 1);
#ifdef CONFIG_COMPAT
        else
        {
            struct compat_vcpu_runstate_info info;

            XLAT_vcpu_runstate_info(&info, &next->runstate);
            __copy_to_guest(next->runstate_guest.compat, &info, 1);
        }
#endif
    }

    schedule_tail(next);
    BUG();
}

void continue_running(struct vcpu *same)
{
    schedule_tail(same);
    BUG();
}

int __sync_lazy_execstate(void)
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

void sync_vcpu_execstate(struct vcpu *v)
{
    if ( cpu_isset(smp_processor_id(), v->vcpu_dirty_cpumask) )
        (void)__sync_lazy_execstate();

    /* Other cpus call __sync_lazy_execstate from flush ipi handler. */
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

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
    struct mc_state *mcs = &this_cpu(mc_state);
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
        if ( IS_COMPAT(current->domain) )
        {
            for ( ; i < 6; i++ )
                mcs->call.args[i] = 0;
        }
    }
    else
    {
        regs       = guest_cpu_user_regs();
        regs->eax  = op;
        regs->eip -= 2;  /* re-execute 'syscall' / 'int 0x82' */

#ifdef __x86_64__
        if ( !IS_COMPAT(current->domain) )
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
            if ( supervisor_mode_kernel || is_hvm_vcpu(current) )
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
    struct mc_state *mcs = &this_cpu(mc_state);
    struct cpu_user_regs *regs;
    unsigned int i, cval = 0;
    unsigned long nval = 0;
    va_list args;

    BUG_ON(*id > 5);
    BUG_ON(mask & (1U << *id));

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
                ++rc;
            else
            {
                cval = mcs->call.args[i];
                BUG_ON(mcs->call.args[i] != cval);
            }
            mcs->compat_call.args[i] = cval;
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

static void relinquish_memory(struct domain *d, struct list_head *list)
{
    struct list_head *ent;
    struct page_info  *page;
    unsigned long     x, y;

    /* Use a recursive lock, as we may enter 'free_domheap_page'. */
    spin_lock_recursive(&d->page_alloc_lock);

    ent = list->next;
    while ( ent != list )
    {
        page = list_entry(ent, struct page_info, list);

        /* Grab a reference to the page so it won't disappear from under us. */
        if ( unlikely(!get_page(page, d)) )
        {
            /* Couldn't get a reference -- someone is freeing this page. */
            ent = ent->next;
            continue;
        }

        if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
            put_page_and_type(page);

        if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
            put_page(page);

        /*
         * Forcibly invalidate base page tables at this point to break circular
         * 'linear page table' references. This is okay because MMU structures
         * are not shared across domains and this domain is now dead. Thus base
         * tables are not in use so a non-zero count means circular reference.
         */
        y = page->u.inuse.type_info;
        for ( ; ; )
        {
            x = y;
            if ( likely((x & (PGT_type_mask|PGT_validated)) !=
                        (PGT_base_page_table|PGT_validated)) )
                break;

            y = cmpxchg(&page->u.inuse.type_info, x, x & ~PGT_validated);
            if ( likely(y == x) )
            {
                free_page_type(page, PGT_base_page_table);
                break;
            }
        }

        /* Follow the list chain and /then/ potentially free the page. */
        ent = ent->next;
        put_page(page);
    }

    spin_unlock_recursive(&d->page_alloc_lock);
}

static void vcpu_destroy_pagetables(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned long pfn;

#ifdef CONFIG_COMPAT
    if ( IS_COMPAT(d) )
    {
        if ( is_hvm_vcpu(v) )
            pfn = pagetable_get_pfn(v->arch.guest_table);
        else
            pfn = l4e_get_pfn(*(l4_pgentry_t *)
                              __va(pagetable_get_paddr(v->arch.guest_table)));

        if ( pfn != 0 )
        {
            if ( paging_mode_refcounts(d) )
                put_page(mfn_to_page(pfn));
            else
                put_page_and_type(mfn_to_page(pfn));
        }

        if ( is_hvm_vcpu(v) )
            v->arch.guest_table = pagetable_null();
        else
            l4e_write(
                (l4_pgentry_t *) __va(pagetable_get_paddr(v->arch.guest_table)),
                l4e_empty());

        v->arch.cr3 = 0;
        return;
    }
#endif

    pfn = pagetable_get_pfn(v->arch.guest_table);
    if ( pfn != 0 )
    {
        if ( paging_mode_refcounts(d) )
            put_page(mfn_to_page(pfn));
        else
            put_page_and_type(mfn_to_page(pfn));
#ifdef __x86_64__
        if ( pfn == pagetable_get_pfn(v->arch.guest_table_user) )
            v->arch.guest_table_user = pagetable_null();
#endif
        v->arch.guest_table = pagetable_null();
    }

#ifdef __x86_64__
    /* Drop ref to guest_table_user (from MMUEXT_NEW_USER_BASEPTR) */
    pfn = pagetable_get_pfn(v->arch.guest_table_user);
    if ( pfn != 0 )
    {
        if ( paging_mode_refcounts(d) )
            put_page(mfn_to_page(pfn));
        else
            put_page_and_type(mfn_to_page(pfn));
        v->arch.guest_table_user = pagetable_null();
    }
#endif

    v->arch.cr3 = 0;
}

void domain_relinquish_resources(struct domain *d)
{
    struct vcpu *v;

    BUG_ON(!cpus_empty(d->domain_dirty_cpumask));

    /* Drop the in-use references to page-table bases. */
    for_each_vcpu ( d, v )
        vcpu_destroy_pagetables(v);

    /* Tear down paging-assistance stuff. */
    paging_teardown(d);

    /*
     * Relinquish GDT mappings. No need for explicit unmapping of the LDT as
     * it automatically gets squashed when the guest's mappings go away.
     */
    for_each_vcpu(d, v)
        destroy_gdt(v);

    /* Relinquish every page of memory. */
    relinquish_memory(d, &d->xenpage_list);
    relinquish_memory(d, &d->page_list);

    /* Free page used by xen oprofile buffer */
    free_xenoprof_pages(d);
}

void arch_dump_domain_info(struct domain *d)
{
    paging_dump_domain_info(d);
}

void arch_dump_vcpu_info(struct vcpu *v)
{
    paging_dump_vcpu_info(v);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
