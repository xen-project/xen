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

#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/new_vgic.h>

#include "vgic.h"

/*
 * Initialization rules: there are multiple stages to the vgic
 * initialization, both for the distributor and the CPU interfaces.  The basic
 * idea is that even though the VGIC is not functional or not requested from
 * user space, the critical path of the run loop can still call VGIC functions
 * that just won't do anything, without them having to check additional
 * initialization flags to ensure they don't look at uninitialized data
 * structures.
 *
 * Distributor:
 *
 * - vgic_early_init(): initialization of static data that doesn't
 *   depend on any sizing information or emulation type. No allocation
 *   is allowed there.
 *
 * - vgic_init(): allocation and initialization of the generic data
 *   structures that depend on sizing information (number of CPUs,
 *   number of interrupts). Also initializes the vcpu specific data
 *   structures. Can be executed lazily for GICv2.
 *
 * CPU Interface:
 *
 * - vgic_vcpu_early_init(): initialization of static data that
 *   doesn't depend on any sizing information or emulation type. No
 *   allocation is allowed there.
 */

/**
 * vgic_vcpu_early_init() - Initialize static VGIC VCPU data structures
 * @vcpu: The VCPU whose VGIC data structures whould be initialized
 *
 * Only do initialization, but do not actually enable the VGIC CPU interface
 * yet.
 */
static void vgic_vcpu_early_init(struct vcpu *vcpu)
{
    struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic;
    unsigned int i;

    INIT_LIST_HEAD(&vgic_cpu->ap_list_head);
    spin_lock_init(&vgic_cpu->ap_list_lock);

    /*
     * Enable and configure all SGIs to be edge-triggered and
     * configure all PPIs as level-triggered.
     */
    for ( i = 0; i < VGIC_NR_PRIVATE_IRQS; i++ )
    {
        struct vgic_irq *irq = &vgic_cpu->private_irqs[i];

        INIT_LIST_HEAD(&irq->ap_list);
        spin_lock_init(&irq->irq_lock);
        irq->intid = i;
        irq->vcpu = NULL;
        irq->target_vcpu = vcpu;
        irq->targets = 1U << vcpu->vcpu_id;
        atomic_set(&irq->refcount, 0);
        if ( vgic_irq_is_sgi(i) )
        {
            /* SGIs */
            irq->enabled = 1;
            irq->config = VGIC_CONFIG_EDGE;
        }
        else
        {
            /* PPIs */
            irq->config = VGIC_CONFIG_LEVEL;
        }
    }
}

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

    d->arch.vgic.dbase = VGIC_ADDR_UNDEF;
    d->arch.vgic.cbase = VGIC_ADDR_UNDEF;
    d->arch.vgic.vgic_redist_base = VGIC_ADDR_UNDEF;

    return 0;
}

/* INIT/DESTROY */

/**
 * domain_vgic_init: initialize the dist data structures
 * @d: domain pointer
 * @nr_spis: number of SPIs
 */
int domain_vgic_init(struct domain *d, unsigned int nr_spis)
{
    struct vgic_dist *dist = &d->arch.vgic;
    unsigned int i;
    int ret;

    /* The number of SPIs must be a multiple of 32 per the GIC spec. */
    nr_spis = ROUNDUP(nr_spis, 32);

    /* Limit the number of virtual SPIs supported to (1020 - 32) = 988  */
    if ( nr_spis > (1020 - NR_LOCAL_IRQS) )
        return -EINVAL;

    dist->nr_spis = nr_spis;
    dist->spis = xzalloc_array(struct vgic_irq, nr_spis);
    if ( !dist->spis )
        return  -ENOMEM;

    /*
     * In the following code we do not take the irq struct lock since
     * no other action on irq structs can happen while the VGIC is
     * not initialized yet:
     * If someone wants to inject an interrupt or does a MMIO access, we
     * require prior initialization in case of a virtual GICv3 or trigger
     * initialization when using a virtual GICv2.
     */
    for ( i = 0; i < nr_spis; i++ )
    {
        struct vgic_irq *irq = &dist->spis[i];

        irq->intid = i + VGIC_NR_PRIVATE_IRQS;
        INIT_LIST_HEAD(&irq->ap_list);
        spin_lock_init(&irq->irq_lock);
        irq->vcpu = NULL;
        irq->target_vcpu = NULL;
        atomic_set(&irq->refcount, 0);
        if ( dist->version == GIC_V2 )
            irq->targets = 0;
        else
            irq->mpidr = 0;
    }

    INIT_LIST_HEAD(&dist->lpi_list_head);
    spin_lock_init(&dist->lpi_list_lock);

    if ( dist->version == GIC_V2 )
        ret = vgic_v2_map_resources(d);
    else
        ret = -ENXIO;

    if ( ret )
        return ret;

    /* allocated_irqs() is used by Xen to find available vIRQs */
    d->arch.vgic.allocated_irqs =
        xzalloc_array(unsigned long, BITS_TO_LONGS(vgic_num_irqs(d)));
    if ( !d->arch.vgic.allocated_irqs )
        return -ENOMEM;

    /* vIRQ0-15 (SGIs) are reserved */
    for ( i = 0; i < NR_GIC_SGI; i++ )
        set_bit(i, d->arch.vgic.allocated_irqs);

    return 0;
}

/**
 * vcpu_vgic_init() - Register VCPU-specific KVM iodevs
 * was: kvm_vgic_vcpu_init()
 * Xen: adding vgic_vx_enable() call
 * @vcpu: pointer to the VCPU being created and initialized
 */
int vcpu_vgic_init(struct vcpu *vcpu)
{
    int ret = 0;

    vgic_vcpu_early_init(vcpu);

    if ( gic_hw_version() == GIC_V2 )
        vgic_v2_enable(vcpu);
    else
        ret = -ENXIO;

    return ret;
}

void domain_vgic_free(struct domain *d)
{
    struct vgic_dist *dist = &d->arch.vgic;
        int i, ret;

    for ( i = 0; i < dist->nr_spis; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(d, NULL, 32 + i);

        if ( !irq->hw )
            continue;

        ret = release_guest_irq(d, irq->hwintid);
        if ( ret )
            dprintk(XENLOG_G_WARNING,
                    "d%u: Failed to release virq %u ret = %d\n",
                    d->domain_id, 32 + i, ret);
    }

    dist->ready = false;
    dist->initialized = false;

    xfree(dist->spis);
    xfree(dist->allocated_irqs);
    dist->nr_spis = 0;
}

int vcpu_vgic_free(struct vcpu *vcpu)
{
    struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic;

    INIT_LIST_HEAD(&vgic_cpu->ap_list_head);

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
