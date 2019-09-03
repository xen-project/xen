#include <xen/mm.h>
#include <asm/shadow.h>

static int _enable_log_dirty(struct domain *d, bool log_global)
{
    ASSERT(is_pv_domain(d));
    return -EOPNOTSUPP;
}

static int _disable_log_dirty(struct domain *d)
{
    ASSERT(is_pv_domain(d));
    return -EOPNOTSUPP;
}

static void _clean_dirty_bitmap(struct domain *d)
{
    ASSERT(is_pv_domain(d));
}

int shadow_domain_init(struct domain *d)
{
    static const struct log_dirty_ops sh_none_ops = {
        .enable  = _enable_log_dirty,
        .disable = _disable_log_dirty,
        .clean   = _clean_dirty_bitmap,
    };

    paging_log_dirty_init(d, &sh_none_ops);
    return is_pv_domain(d) ? 0 : -EOPNOTSUPP;
}

static int _page_fault(struct vcpu *v, unsigned long va,
                       struct cpu_user_regs *regs)
{
    ASSERT_UNREACHABLE();
    return 0;
}

static bool _invlpg(struct vcpu *v, unsigned long linear)
{
    ASSERT_UNREACHABLE();
    return true;
}

static unsigned long _gva_to_gfn(struct vcpu *v, struct p2m_domain *p2m,
                                 unsigned long va, uint32_t *pfec)
{
    ASSERT_UNREACHABLE();
    return gfn_x(INVALID_GFN);
}

static void _update_cr3(struct vcpu *v, int do_locking, bool noflush)
{
    ASSERT_UNREACHABLE();
}

static void _update_paging_modes(struct vcpu *v)
{
    ASSERT_UNREACHABLE();
}

static int _write_p2m_entry(struct p2m_domain *p2m, unsigned long gfn,
                            l1_pgentry_t *p, l1_pgentry_t new,
                            unsigned int level)
{
    ASSERT_UNREACHABLE();
    return -EOPNOTSUPP;
}

static const struct paging_mode sh_paging_none = {
    .page_fault                    = _page_fault,
    .invlpg                        = _invlpg,
    .gva_to_gfn                    = _gva_to_gfn,
    .update_cr3                    = _update_cr3,
    .update_paging_modes           = _update_paging_modes,
    .write_p2m_entry               = _write_p2m_entry,
};

void shadow_vcpu_init(struct vcpu *v)
{
    ASSERT(is_pv_vcpu(v));
    v->arch.paging.mode = &sh_paging_none;
}
