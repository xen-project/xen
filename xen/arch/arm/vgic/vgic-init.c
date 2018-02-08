/*
 * Copyright (C) 2015, 2016 ARM Ltd.
 * Imported from Linux ("new" KVM VGIC) and heavily adapted to Xen.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <asm/new_vgic.h>

#include "vgic.h"

/* CREATION */

/**
 * domain_vgic_register: create a virtual GIC
 * @d: domain pointer
 * @mmio_count: pointer to add number of required MMIO regions
 *
 * was: kvm_vgic_create
 */
int domain_vgic_register(struct domain *d, int *mmio_count)
{
    switch ( d->arch.vgic.version )
    {
    case GIC_V2:
        *mmio_count = 1;
        break;
    default:
        BUG();
    }

    if ( d->max_vcpus > domain_max_vcpus(d) )
        return -E2BIG;

    d->arch.vgic.vgic_dist_base = VGIC_ADDR_UNDEF;
    d->arch.vgic.vgic_cpu_base = VGIC_ADDR_UNDEF;
    d->arch.vgic.vgic_redist_base = VGIC_ADDR_UNDEF;

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
