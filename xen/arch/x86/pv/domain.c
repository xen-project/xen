/******************************************************************************
 * arch/x86/pv/domain.c
 *
 * PV domain handling
 */

#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/sched.h>

#include <asm/cpufeature.h>
#include <asm/invpcid.h>
#include <asm/spec_ctrl.h>
#include <asm/pv/domain.h>
#include <asm/shadow.h>

#ifdef CONFIG_PV32
int8_t __read_mostly opt_pv32 = -1;
#endif

static __init int parse_pv(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("32", s, ss)) >= 0 )
        {
#ifdef CONFIG_PV32
            opt_pv32 = val;
#else
            no_config_param("PV32", "pv", s, ss);
#endif
        }
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("pv", parse_pv);

static __read_mostly enum {
    PCID_OFF,
    PCID_ALL,
    PCID_XPTI,
    PCID_NOXPTI
} opt_pcid = PCID_XPTI;

#ifdef CONFIG_HYPFS
static const char opt_pcid_2_string[][7] = {
    [PCID_OFF] = "off",
    [PCID_ALL] = "on",
    [PCID_XPTI] = "xpti",
    [PCID_NOXPTI] = "noxpti",
};

static void __init opt_pcid_init(struct param_hypfs *par)
{
    custom_runtime_set_var(par, opt_pcid_2_string[opt_pcid]);
}
#endif

static int parse_pcid(const char *s);
custom_runtime_param("pcid", parse_pcid, opt_pcid_init);

static int parse_pcid(const char *s)
{
    int rc = 0;

    switch ( parse_bool(s, NULL) )
    {
    case 0:
        opt_pcid = PCID_OFF;
        break;

    case 1:
        opt_pcid = PCID_ALL;
        break;

    default:
        switch ( parse_boolean("xpti", s, NULL) )
        {
        case 0:
            opt_pcid = PCID_NOXPTI;
            break;

        case 1:
            opt_pcid = PCID_XPTI;
            break;

        default:
            rc = -EINVAL;
            break;
        }
        break;
    }

    custom_runtime_set_var(param_2_parfs(parse_pcid),
                           opt_pcid_2_string[opt_pcid]);

    return rc;
}

static void noreturn continue_nonidle_domain(struct vcpu *v)
{
    check_wakeup_from_wait();
    reset_stack_and_jump_nolp(ret_from_intr);
}

static int setup_compat_l4(struct vcpu *v)
{
    struct page_info *pg;
    l4_pgentry_t *l4tab;
    mfn_t mfn;

    pg = alloc_domheap_page(v->domain, MEMF_no_owner | MEMF_no_scrub);
    if ( pg == NULL )
        return -ENOMEM;

    mfn = page_to_mfn(pg);
    l4tab = map_domain_page(mfn);
    clear_page(l4tab);
    init_xen_l4_slots(l4tab, mfn, v->domain, INVALID_MFN, false);
    unmap_domain_page(l4tab);

    /* This page needs to look like a pagetable so that it can be shadowed */
    pg->u.inuse.type_info = PGT_l4_page_table | PGT_validated | 1;

    v->arch.guest_table = pagetable_from_page(pg);
    v->arch.guest_table_user = v->arch.guest_table;

    return 0;
}

static void release_compat_l4(struct vcpu *v)
{
    if ( !pagetable_is_null(v->arch.guest_table) )
        free_domheap_page(pagetable_get_page(v->arch.guest_table));
    v->arch.guest_table = pagetable_null();
    v->arch.guest_table_user = pagetable_null();
}

unsigned long pv_fixup_guest_cr4(const struct vcpu *v, unsigned long cr4)
{
    const struct cpuid_policy *p = v->domain->arch.cpuid;

    /* Discard attempts to set guest controllable bits outside of the policy. */
    cr4 &= ~((p->basic.tsc     ? 0 : X86_CR4_TSD)      |
             (p->basic.de      ? 0 : X86_CR4_DE)       |
             (p->feat.fsgsbase ? 0 : X86_CR4_FSGSBASE) |
             (p->basic.xsave   ? 0 : X86_CR4_OSXSAVE));

    /* Masks expected to be disjoint sets. */
    BUILD_BUG_ON(PV_CR4_GUEST_MASK & PV_CR4_GUEST_VISIBLE_MASK);

    /*
     * A guest sees the policy subset of its own choice of guest controllable
     * bits, and a subset of Xen's choice of certain hardware settings.
     */
    return ((cr4 & PV_CR4_GUEST_MASK) |
            (mmu_cr4_features & PV_CR4_GUEST_VISIBLE_MASK));
}

static int8_t __read_mostly opt_global_pages = -1;
boolean_runtime_param("global-pages", opt_global_pages);

static int __init pge_init(void)
{
    if ( opt_global_pages == -1 )
        opt_global_pages = !cpu_has_hypervisor ||
                           !(boot_cpu_data.x86_vendor &
                             (X86_VENDOR_AMD | X86_VENDOR_HYGON));

    return 0;
}
__initcall(pge_init);

unsigned long pv_make_cr4(const struct vcpu *v)
{
    const struct domain *d = v->domain;
    unsigned long cr4 = mmu_cr4_features &
        ~(X86_CR4_PCIDE | X86_CR4_PGE | X86_CR4_TSD);

    /*
     * PCIDE or PGE depends on the PCID/XPTI settings, but must not both be
     * set, as it impacts the safety of TLB flushing.
     */
    if ( d->arch.pv.pcid )
        cr4 |= X86_CR4_PCIDE;
    else if ( !d->arch.pv.xpti && opt_global_pages )
        cr4 |= X86_CR4_PGE;

    /*
     * TSD is needed if either the guest has elected to use it, or Xen is
     * virtualising the TSC value the guest sees.
     */
    if ( d->arch.vtsc || (v->arch.pv.ctrlreg[4] & X86_CR4_TSD) )
        cr4 |= X86_CR4_TSD;

    /*
     * The {RD,WR}{FS,GS}BASE are only useable in 64bit code segments.  While
     * we must not have CR4.FSGSBASE set behind the back of a 64bit PV kernel,
     * we do leave it set in 32bit PV context to speed up Xen's context switch
     * path.
     */
    if ( !is_pv_32bit_domain(d) && !(v->arch.pv.ctrlreg[4] & X86_CR4_FSGSBASE) )
        cr4 &= ~X86_CR4_FSGSBASE;

    return cr4;
}

int switch_compat(struct domain *d)
{
    struct vcpu *v;
    int rc;

    BUILD_BUG_ON(offsetof(struct shared_info, vcpu_info) != 0);

    if ( !opt_pv32 )
        return -EOPNOTSUPP;
    if ( is_hvm_domain(d) || domain_tot_pages(d) != 0 )
        return -EACCES;
    if ( is_pv_32bit_domain(d) )
        return 0;

    d->arch.has_32bit_shinfo = 1;
    d->arch.pv.is_32bit = true;

    for_each_vcpu( d, v )
    {
        if ( (rc = setup_compat_arg_xlat(v)) ||
             (rc = setup_compat_l4(v)) )
            goto undo_and_fail;
    }

    domain_set_alloc_bitsize(d);
    recalculate_cpuid_policy(d);

    d->arch.x87_fip_width = 4;

    d->arch.pv.xpti = false;
    d->arch.pv.pcid = false;

    return 0;

 undo_and_fail:
    d->arch.pv.is_32bit = d->arch.has_32bit_shinfo = false;
    for_each_vcpu( d, v )
    {
        free_compat_arg_xlat(v);
        release_compat_l4(v);
    }

    return rc;
}

static int pv_create_gdt_ldt_l1tab(struct vcpu *v)
{
    return create_perdomain_mapping(v->domain, GDT_VIRT_START(v),
                                    1U << GDT_LDT_VCPU_SHIFT,
                                    v->domain->arch.pv.gdt_ldt_l1tab,
                                    NULL);
}

static void pv_destroy_gdt_ldt_l1tab(struct vcpu *v)
{
    destroy_perdomain_mapping(v->domain, GDT_VIRT_START(v),
                              1U << GDT_LDT_VCPU_SHIFT);
}

void pv_vcpu_destroy(struct vcpu *v)
{
    if ( is_pv_32bit_vcpu(v) )
    {
        free_compat_arg_xlat(v);
        release_compat_l4(v);
    }

    pv_destroy_gdt_ldt_l1tab(v);
    XFREE(v->arch.pv.trap_ctxt);
}

int pv_vcpu_initialise(struct vcpu *v)
{
    struct domain *d = v->domain;
    int rc;

    ASSERT(!is_idle_domain(d));

    rc = pv_create_gdt_ldt_l1tab(v);
    if ( rc )
        return rc;

    BUILD_BUG_ON(X86_NR_VECTORS * sizeof(*v->arch.pv.trap_ctxt) >
                 PAGE_SIZE);
    v->arch.pv.trap_ctxt = xzalloc_array(struct trap_info, X86_NR_VECTORS);
    if ( !v->arch.pv.trap_ctxt )
    {
        rc = -ENOMEM;
        goto done;
    }

    /* PV guests by default have a 100Hz ticker. */
    v->periodic_period = MILLISECS(10);

    v->arch.pv.ctrlreg[4] = pv_fixup_guest_cr4(v, 0);

    if ( is_pv_32bit_domain(d) )
    {
        if ( (rc = setup_compat_arg_xlat(v)) )
            goto done;

        if ( (rc = setup_compat_l4(v)) )
            goto done;
    }

 done:
    if ( rc )
        pv_vcpu_destroy(v);
    return rc;
}

void pv_domain_destroy(struct domain *d)
{
    pv_l1tf_domain_destroy(d);

    destroy_perdomain_mapping(d, GDT_LDT_VIRT_START,
                              GDT_LDT_MBYTES << (20 - PAGE_SHIFT));

    XFREE(d->arch.pv.cpuidmasks);

    FREE_XENHEAP_PAGE(d->arch.pv.gdt_ldt_l1tab);
}


int pv_domain_initialise(struct domain *d)
{
    static const struct arch_csw pv_csw = {
        .from = paravirt_ctxt_switch_from,
        .to   = paravirt_ctxt_switch_to,
        .tail = continue_nonidle_domain,
    };
    int rc = -ENOMEM;

    pv_l1tf_domain_init(d);

    d->arch.pv.gdt_ldt_l1tab =
        alloc_xenheap_pages(0, MEMF_node(domain_to_node(d)));
    if ( !d->arch.pv.gdt_ldt_l1tab )
        goto fail;
    clear_page(d->arch.pv.gdt_ldt_l1tab);

    if ( levelling_caps & ~LCAP_faulting &&
         (d->arch.pv.cpuidmasks = xmemdup(&cpuidmask_defaults)) == NULL )
        goto fail;

    rc = create_perdomain_mapping(d, GDT_LDT_VIRT_START,
                                  GDT_LDT_MBYTES << (20 - PAGE_SHIFT),
                                  NULL, NULL);
    if ( rc )
        goto fail;

    d->arch.ctxt_switch = &pv_csw;

    d->arch.pv.xpti = is_hardware_domain(d) ? opt_xpti_hwdom : opt_xpti_domu;

    if ( !is_pv_32bit_domain(d) && use_invpcid && cpu_has_pcid )
        switch ( ACCESS_ONCE(opt_pcid) )
        {
        case PCID_OFF:
            break;

        case PCID_ALL:
            d->arch.pv.pcid = true;
            break;

        case PCID_XPTI:
            d->arch.pv.pcid = d->arch.pv.xpti;
            break;

        case PCID_NOXPTI:
            d->arch.pv.pcid = !d->arch.pv.xpti;
            break;

        default:
            ASSERT_UNREACHABLE();
            break;
        }

    return 0;

  fail:
    pv_domain_destroy(d);

    return rc;
}

bool __init xpti_pcid_enabled(void)
{
    return use_invpcid && cpu_has_pcid &&
           (opt_pcid == PCID_ALL || opt_pcid == PCID_XPTI);
}

static void _toggle_guest_pt(struct vcpu *v)
{
    const struct domain *d = v->domain;
    struct cpu_info *cpu_info = get_cpu_info();
    unsigned long cr3;

    v->arch.flags ^= TF_kernel_mode;
    update_cr3(v);
    if ( d->arch.pv.xpti )
    {
        cpu_info->root_pgt_changed = true;
        cpu_info->pv_cr3 = __pa(this_cpu(root_pgt)) |
                           (d->arch.pv.pcid ? get_pcid_bits(v, true) : 0);
    }

    /*
     * Don't flush user global mappings from the TLB. Don't tick TLB clock.
     *
     * In shadow mode, though, update_cr3() may need to be accompanied by a
     * TLB flush (for just the incoming PCID), as the top level page table may
     * have changed behind our backs. To be on the safe side, suppress the
     * no-flush unconditionally in this case. The XPTI CR3 write, if enabled,
     * will then need to be a flushing one too.
     */
    cr3 = v->arch.cr3;
    if ( shadow_mode_enabled(d) )
    {
        cr3 &= ~X86_CR3_NOFLUSH;
        cpu_info->pv_cr3 &= ~X86_CR3_NOFLUSH;
    }
    write_cr3(cr3);

    if ( !(v->arch.flags & TF_kernel_mode) )
        return;

    if ( v->arch.pv.need_update_runstate_area && update_runstate_area(v) )
        v->arch.pv.need_update_runstate_area = 0;

    if ( v->arch.pv.pending_system_time.version &&
         update_secondary_system_time(v, &v->arch.pv.pending_system_time) )
        v->arch.pv.pending_system_time.version = 0;
}

void toggle_guest_mode(struct vcpu *v)
{
    ASSERT(!is_pv_32bit_vcpu(v));

    /* %fs/%gs bases can only be stale if WR{FS,GS}BASE are usable. */
    if ( read_cr4() & X86_CR4_FSGSBASE )
    {
        if ( v->arch.flags & TF_kernel_mode )
            v->arch.pv.gs_base_kernel = __rdgsbase();
        else
            v->arch.pv.gs_base_user = __rdgsbase();
    }
    asm volatile ( "swapgs" );

    _toggle_guest_pt(v);
}

void toggle_guest_pt(struct vcpu *v)
{
    if ( !is_pv_32bit_vcpu(v) )
        _toggle_guest_pt(v);
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
