
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

static int p2m_alloc_table(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    void *table = alloc_xenheap_pages(P2M_ROOT_ORDER, 0);
    unsigned int i;

    if ( !table )
    {
        printk(XENLOG_G_ERR "%pd: p2m: unable to allocate P2M MPU mapping table\n",
               d);
        return -ENOMEM;
    }

    p2m->root = virt_to_page(table);

    for ( i = 0; i < P2M_ROOT_PAGES; i++ )
        clear_page(table + (i * PAGE_SIZE));

    return 0;
}

int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc = 0;
    unsigned int cpu;

    rwlock_init(&p2m->lock);

    p2m->vmid = INVALID_VMID;
    p2m->max_mapped_gfn = _gfn(0);
    p2m->lowest_mapped_gfn = _gfn(ULONG_MAX);

    p2m->default_access = p2m_access_rwx;
    /* mem_access is NOT supported on MPU system. */
    p2m->mem_access_enabled = false;

    /* Ensure that the type chosen is large enough for MAX_VIRT_CPUS. */
    BUILD_BUG_ON((1 << (sizeof(p2m->last_vcpu_ran[0]) * 8)) < MAX_VIRT_CPUS);
    BUILD_BUG_ON((1 << (sizeof(p2m->last_vcpu_ran[0]) * 8)) < INVALID_VCPU_ID);

    for_each_possible_cpu(cpu)
        p2m->last_vcpu_ran[cpu] = INVALID_VCPU_ID;

    /*
     * "Trivial" initialization is now complete. Set the backpointer so that
     * p2m_teardown() and related functions know to do something.
     */
    p2m->domain = d;

    rc = p2m_alloc_vmid(d);
    if ( rc )
        return rc;

    p2m->vsctlr = ((register_t)p2m->vmid << VSCTLR_VMID_SHIFT);

    return p2m_alloc_table(d);
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
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    /* p2m not actually initialized */
    if ( !p2m->domain )
        return;

    if ( p2m->root )
        free_xenheap_pages(page_to_virt(p2m->root), P2M_ROOT_ORDER);

    p2m->root = NULL;

    p2m_free_vmid(d);

    p2m->domain = NULL;
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
