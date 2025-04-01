
/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/domain.h>
#include <xen/errno.h>
#include <xen/mm-frame.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <asm/p2m.h>

int p2m_set_entry(struct p2m_domain *p2m, gfn_t sgfn, unsigned long nr,
                  mfn_t smfn, p2m_type_t t, p2m_access_t a)
{
    BUG_ON("unimplemented");
    return -EINVAL;
}

mfn_t p2m_get_entry(struct p2m_domain *p2m, gfn_t gfn, p2m_type_t *t,
                    p2m_access_t *a, unsigned int *page_order, bool *valid)
{
    BUG_ON("unimplemented");
    return INVALID_MFN;
}

void p2m_dump_info(struct domain *d)
{
    BUG_ON("unimplemented");
}

int p2m_init(struct domain *d)
{
    BUG_ON("unimplemented");
    return -EINVAL;
}

void p2m_save_state(struct vcpu *p)
{
    BUG_ON("unimplemented");
}

void p2m_restore_state(struct vcpu *n)
{
    BUG_ON("unimplemented");
}

void p2m_final_teardown(struct domain *d)
{
    BUG_ON("unimplemented");
}

bool p2m_resolve_translation_fault(struct domain *d, gfn_t gfn)
{
    BUG_ON("unimplemented");
    return false;
}

void p2m_flush_vm(struct vcpu *v) {}

int relinquish_p2m_mapping(struct domain *d)
{
    return 0;
}

void p2m_domain_creation_finished(struct domain *d) {}

int p2m_teardown(struct domain *d)
{
    return 0;
}

int p2m_teardown_allocation(struct domain *d)
{
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
