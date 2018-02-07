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
#include <asm/bug.h>
#include <asm/new_vgic.h>

#include "vgic.h"

/*
 * Iterate over the VM's list of mapped LPIs to find the one with a
 * matching interrupt ID and return a reference to the IRQ structure.
 *
 * TODO: This is more documentation of how it should be done. A list is
 * not a good data structure for Dom0's LPIs, it merely serves as an
 * example here how to properly do the locking, allocation and refcounting.
 * So lpi_list_head should be replaced with something more appropriate.
 */
static struct vgic_irq *vgic_get_lpi(struct domain *d, uint32_t intid)
{
    struct vgic_dist *dist = &d->arch.vgic;
    struct vgic_irq *irq = NULL;

    spin_lock(&dist->lpi_list_lock);

    list_for_each_entry( irq, &dist->lpi_list_head, lpi_list )
    {
        if ( irq->intid != intid )
            continue;

        /*
         * This increases the refcount, the caller is expected to
         * call vgic_put_irq() later once it's finished with the IRQ.
         */
        vgic_get_irq_kref(irq);
        goto out_unlock;
    }
    irq = NULL;

out_unlock:
    spin_unlock(&dist->lpi_list_lock);

    return irq;
}

/**
 * vgic_get_irq() - obtain a reference to a virtual IRQ
 * @d:        The domain the virtual IRQ belongs to.
 * @vcpu:     For private IRQs (SGIs, PPIs) the virtual CPU this IRQ
 *            is associated with. Will be ignored for SPIs and LPIs.
 * @intid:    The virtual IRQ number.
 *
 * This looks up the virtual interrupt ID to get the corresponding
 * struct vgic_irq. It also increases the refcount, so any caller is expected
 * to call vgic_put_irq() once it's finished with this IRQ.
 *
 * Return: The pointer to the requested struct vgic_irq.
 */
struct vgic_irq *vgic_get_irq(struct domain *d, struct vcpu *vcpu,
                              uint32_t intid)
{
    /* SGIs and PPIs */
    if ( intid <= VGIC_MAX_PRIVATE )
        return &vcpu->arch.vgic.private_irqs[intid];

    /* SPIs */
    if ( intid <= VGIC_MAX_SPI )
        return &d->arch.vgic.spis[intid - VGIC_NR_PRIVATE_IRQS];

    /* LPIs */
    if ( intid >= VGIC_MIN_LPI )
        return vgic_get_lpi(d, intid);

    ASSERT_UNREACHABLE();

    return NULL;
}

/**
 * vgic_put_irq() - drop the reference to a virtual IRQ
 * @d:        The domain the virtual IRQ belongs to.
 * @irq:      The pointer to struct vgic_irq, as obtained from vgic_get_irq().
 *
 * This drops the reference to a virtual IRQ. It decreases the refcount
 * of the pointer, so dynamic IRQs can be freed when no longer needed.
 * This should always be called after a vgic_get_irq(), though the reference
 * can be deliberately held for longer periods, if needed.
 *
 * TODO: A linked list is not a good data structure for LPIs in Dom0.
 * Replace this with proper data structure once we get proper LPI support.
 */
void vgic_put_irq(struct domain *d, struct vgic_irq *irq)
{
    struct vgic_dist *dist = &d->arch.vgic;

    if ( irq->intid < VGIC_MIN_LPI )
        return;

    spin_lock(&dist->lpi_list_lock);
    if ( !atomic_dec_and_test(&irq->refcount) )
    {
        spin_unlock(&dist->lpi_list_lock);
        return;
    };

    list_del(&irq->lpi_list);
    dist->lpi_list_count--;
    spin_unlock(&dist->lpi_list_lock);

    xfree(irq);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
