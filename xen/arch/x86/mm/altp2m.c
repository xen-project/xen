/*
 * Alternate p2m HVM
 * Copyright (c) 2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/hvm/support.h>
#include <asm/hvm/hvm.h>
#include <asm/p2m.h>
#include <asm/altp2m.h>

void
altp2m_vcpu_initialise(struct vcpu *v)
{
    if ( v != current )
        vcpu_pause(v);

    vcpu_altp2m(v).p2midx = 0;
    atomic_inc(&p2m_get_altp2m(v)->active_vcpus);

    altp2m_vcpu_update_p2m(v);

    if ( v != current )
        vcpu_unpause(v);
}

void
altp2m_vcpu_destroy(struct vcpu *v)
{
    struct p2m_domain *p2m;

    if ( v != current )
        vcpu_pause(v);

    if ( (p2m = p2m_get_altp2m(v)) )
        atomic_dec(&p2m->active_vcpus);

    altp2m_vcpu_disable_ve(v);

    vcpu_altp2m(v).p2midx = INVALID_ALTP2M;
    altp2m_vcpu_update_p2m(v);

    if ( v != current )
        vcpu_unpause(v);
}

int altp2m_vcpu_enable_ve(struct vcpu *v, gfn_t gfn)
{
    struct domain *d = v->domain;
    struct altp2mvcpu *a = &vcpu_altp2m(v);
    p2m_type_t p2mt;
    struct page_info *pg;
    int rc;

    /* Early exit path if #VE is already configured. */
    if ( a->veinfo_pg )
        return -EEXIST;

    rc = check_get_page_from_gfn(d, gfn, false, &p2mt, &pg);
    if ( rc )
        return rc;

    /*
     * Looking for a plain piece of guest writeable RAM with isn't a magic
     * frame such as a grant/ioreq/shared_info/etc mapping.  We (ab)use the
     * pageable() predicate for this, due to it having the same properties
     * that we want.
     */
    if ( !p2m_is_pageable(p2mt) || is_special_page(pg) )
    {
        rc = -EINVAL;
        goto err;
    }

    /*
     * Update veinfo_pg, making sure to be safe with concurrent hypercalls.
     * The first caller to make veinfo_pg become non-NULL will program its MFN
     * into the VMCS, so must not be clobbered.  Callers which lose the race
     * back off with -EEXIST.
     */
    if ( cmpxchg(&a->veinfo_pg, NULL, pg) != NULL )
    {
        rc = -EEXIST;
        goto err;
    }

    altp2m_vcpu_update_vmfunc_ve(v);

    return 0;

 err:
    put_page(pg);

    return rc;
}

void altp2m_vcpu_disable_ve(struct vcpu *v)
{
    struct altp2mvcpu *a = &vcpu_altp2m(v);
    struct page_info *pg;

    /*
     * Update veinfo_pg, making sure to be safe with concurrent hypercalls.
     * The winner of this race is responsible to update the VMCS to no longer
     * point at the page, then drop the associated ref.
     */
    if ( (pg = xchg(&a->veinfo_pg, NULL)) )
    {
        altp2m_vcpu_update_vmfunc_ve(v);

        put_page(pg);
    }
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
