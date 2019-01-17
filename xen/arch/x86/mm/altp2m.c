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
    vcpu_altp2m(v).veinfo_gfn = INVALID_GFN;
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
    p2m_type_t p2mt;

    if ( !gfn_eq(vcpu_altp2m(v).veinfo_gfn, INVALID_GFN) ||
         mfn_eq(get_gfn_query_unlocked(v->domain, gfn_x(gfn), &p2mt),
                INVALID_MFN) )
        return -EINVAL;

    vcpu_altp2m(v).veinfo_gfn = gfn;
    altp2m_vcpu_update_vmfunc_ve(v);

    return 0;
}

void altp2m_vcpu_disable_ve(struct vcpu *v)
{
    if ( !gfn_eq(vcpu_altp2m(v).veinfo_gfn, INVALID_GFN) )
    {
        vcpu_altp2m(v).veinfo_gfn = INVALID_GFN;
        altp2m_vcpu_update_vmfunc_ve(v);
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
