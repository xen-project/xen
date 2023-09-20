#include <xen/mm.h>
#include <asm/shadow.h>

static int cf_check _toggle_log_dirty(struct domain *d)
{
    ASSERT(is_pv_domain(d));
    return -EOPNOTSUPP;
}

static void cf_check _clean_dirty_bitmap(struct domain *d)
{
    ASSERT(is_pv_domain(d));
}

static void cf_check _update_paging_modes(struct vcpu *v)
{
    ASSERT_UNREACHABLE();
}

int shadow_domain_init(struct domain *d)
{
    /* For HVM set up pointers for safety, then fail. */
    static const struct log_dirty_ops sh_none_ops = {
        .enable  = _toggle_log_dirty,
        .disable = _toggle_log_dirty,
        .clean   = _clean_dirty_bitmap,
    };

    paging_log_dirty_init(d, &sh_none_ops);

    d->arch.paging.update_paging_modes = _update_paging_modes;

    return is_hvm_domain(d) ? -EOPNOTSUPP : 0;
}

static int cf_check _page_fault(
    struct vcpu *v, unsigned long va, struct cpu_user_regs *regs)
{
    ASSERT_UNREACHABLE();
    return 0;
}

static bool cf_check _invlpg(struct vcpu *v, unsigned long linear)
{
    ASSERT_UNREACHABLE();
    return true;
}

#ifdef CONFIG_HVM
static unsigned long cf_check _gva_to_gfn(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long va, uint32_t *pfec)
{
    ASSERT_UNREACHABLE();
    return gfn_x(INVALID_GFN);
}
#endif

static pagetable_t cf_check _update_cr3(struct vcpu *v, bool noflush)
{
    ASSERT_UNREACHABLE();
    return pagetable_null();
}

static const struct paging_mode sh_paging_none = {
    .page_fault                    = _page_fault,
    .invlpg                        = _invlpg,
#ifdef CONFIG_HVM
    .gva_to_gfn                    = _gva_to_gfn,
#endif
    .update_cr3                    = _update_cr3,
};

void shadow_vcpu_init(struct vcpu *v)
{
    ASSERT(is_pv_vcpu(v));
    v->arch.paging.mode = &sh_paging_none;
}
