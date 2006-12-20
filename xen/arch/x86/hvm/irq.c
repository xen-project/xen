/******************************************************************************
 * irq.c
 * 
 * Interrupt distribution and delivery logic.
 * 
 * Copyright (c) 2006, K A Fraser, XenSource Inc.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <asm/hvm/domain.h>

void hvm_pci_intx_assert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi, link, isa_irq;

    ASSERT((device <= 31) && (intx <= 3));

    spin_lock(&hvm_irq->lock);

    if ( __test_and_set_bit(device*4 + intx, &hvm_irq->pci_intx) )
        goto out;

    gsi = hvm_pci_intx_gsi(device, intx);
    if ( hvm_irq->gsi_assert_count[gsi]++ == 0 )
        vioapic_irq_positive_edge(d, gsi);

    link    = hvm_pci_intx_link(device, intx);
    isa_irq = hvm_irq->pci_link_route[link];
    if ( (hvm_irq->pci_link_assert_count[link]++ == 0) && isa_irq &&
         (hvm_irq->gsi_assert_count[isa_irq]++ == 0) )
    {
        vioapic_irq_positive_edge(d, isa_irq);
        vpic_irq_positive_edge(d, isa_irq);
    }

 out:
    spin_unlock(&hvm_irq->lock);
}

void hvm_pci_intx_deassert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi, link, isa_irq;

    ASSERT((device <= 31) && (intx <= 3));

    spin_lock(&hvm_irq->lock);

    if ( !__test_and_clear_bit(device*4 + intx, &hvm_irq->pci_intx) )
        goto out;

    gsi = hvm_pci_intx_gsi(device, intx);
    --hvm_irq->gsi_assert_count[gsi];

    link    = hvm_pci_intx_link(device, intx);
    isa_irq = hvm_irq->pci_link_route[link];
    if ( (--hvm_irq->pci_link_assert_count[link] == 0) && isa_irq &&
         (--hvm_irq->gsi_assert_count[isa_irq] == 0) )
        vpic_irq_negative_edge(d, isa_irq);

 out:
    spin_unlock(&hvm_irq->lock);
}

void hvm_isa_irq_assert(
    struct domain *d, unsigned int isa_irq)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    ASSERT(isa_irq <= 15);

    spin_lock(&hvm_irq->lock);

    if ( !__test_and_set_bit(isa_irq, &hvm_irq->isa_irq) &&
         (hvm_irq->gsi_assert_count[isa_irq]++ == 0) )
    {
        vioapic_irq_positive_edge(d, isa_irq);
        vpic_irq_positive_edge(d, isa_irq);
    }

    spin_unlock(&hvm_irq->lock);
}

void hvm_isa_irq_deassert(
    struct domain *d, unsigned int isa_irq)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    ASSERT(isa_irq <= 15);

    spin_lock(&hvm_irq->lock);

    if ( __test_and_clear_bit(isa_irq, &hvm_irq->isa_irq) &&
         (--hvm_irq->gsi_assert_count[isa_irq] == 0) )
        vpic_irq_negative_edge(d, isa_irq);

    spin_unlock(&hvm_irq->lock);
}

void hvm_set_callback_irq_level(void)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi = hvm_irq->callback_gsi;

    /* Fast lock-free tests. */
    if ( (v->vcpu_id != 0) || (gsi == 0) )
        return;

    spin_lock(&hvm_irq->lock);

    gsi = hvm_irq->callback_gsi;
    if ( gsi == 0 )
        goto out;

    if ( local_events_need_delivery() )
    {
        if ( !__test_and_set_bit(0, &hvm_irq->callback_irq_wire) &&
             (hvm_irq->gsi_assert_count[gsi]++ == 0) )
        {
            vioapic_irq_positive_edge(d, gsi);
            if ( gsi <= 15 )
                vpic_irq_positive_edge(d, gsi);
        }
    }
    else
    {
        if ( __test_and_clear_bit(0, &hvm_irq->callback_irq_wire) &&
             (--hvm_irq->gsi_assert_count[gsi] == 0) )
        {
            if ( gsi <= 15 )
                vpic_irq_negative_edge(d, gsi);
        }
    }

 out:
    spin_unlock(&hvm_irq->lock);
}

void hvm_set_pci_link_route(struct domain *d, u8 link, u8 isa_irq)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    u8 old_isa_irq;

    ASSERT((link <= 3) && (isa_irq <= 15));

    spin_lock(&hvm_irq->lock);

    old_isa_irq = hvm_irq->pci_link_route[link];
    if ( old_isa_irq == isa_irq )
        goto out;
    hvm_irq->pci_link_route[link] = isa_irq;

    if ( hvm_irq->pci_link_assert_count[link] == 0 )
        goto out;

    if ( old_isa_irq && (--hvm_irq->gsi_assert_count[old_isa_irq] == 0) )
        vpic_irq_negative_edge(d, isa_irq);

    if ( isa_irq && (hvm_irq->gsi_assert_count[isa_irq]++ == 0) )
    {
        vioapic_irq_positive_edge(d, isa_irq);
        vpic_irq_positive_edge(d, isa_irq);
    }

 out:
    spin_unlock(&hvm_irq->lock);

    dprintk(XENLOG_G_INFO, "Dom%u PCI link %u changed %u -> %u\n",
            d->domain_id, link, old_isa_irq, isa_irq);
}

void hvm_set_callback_gsi(struct domain *d, unsigned int gsi)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int old_gsi;

    if ( gsi >= ARRAY_SIZE(hvm_irq->gsi_assert_count) )
        gsi = 0;

    spin_lock(&hvm_irq->lock);

    old_gsi = hvm_irq->callback_gsi;
    if ( old_gsi == gsi )
        goto out;
    hvm_irq->callback_gsi = gsi;

    if ( !test_bit(0, &hvm_irq->callback_irq_wire) )
        goto out;

    if ( old_gsi && (--hvm_irq->gsi_assert_count[old_gsi] == 0) )
        if ( old_gsi <= 15 )
            vpic_irq_negative_edge(d, old_gsi);

    if ( gsi && (hvm_irq->gsi_assert_count[gsi]++ == 0) )
    {
        vioapic_irq_positive_edge(d, gsi);
        if ( gsi <= 15 )
            vpic_irq_positive_edge(d, gsi);
    }

 out:
    spin_unlock(&hvm_irq->lock);

    dprintk(XENLOG_G_INFO, "Dom%u callback GSI changed %u -> %u\n",
            d->domain_id, old_gsi, gsi);
}

int cpu_has_pending_irq(struct vcpu *v)
{
    struct hvm_domain *plat = &v->domain->arch.hvm_domain;

    /* APIC */
    if ( vlapic_has_interrupt(v) != -1 )
        return 1;

    /* PIC */
    if ( !vlapic_accept_pic_intr(v) )
        return 0;

    return plat->irq.vpic[0].int_output;
}

int cpu_get_interrupt(struct vcpu *v, int *type)
{
    int vector;

    if ( (vector = cpu_get_apic_interrupt(v, type)) != -1 )
        return vector;

    if ( (v->vcpu_id == 0) &&
         ((vector = cpu_get_pic_interrupt(v, type)) != -1) )
        return vector;

    return -1;
}

int get_intr_vector(struct vcpu* v, int irq, int type)
{
    if ( type == APIC_DM_EXTINT )
        return v->domain->arch.hvm_domain.irq.vpic[irq >> 3].irq_base
                + (irq & 0x7);

    return domain_vioapic(v->domain)->redirtbl[irq].fields.vector;
}

int is_irq_masked(struct vcpu *v, int irq)
{
    if ( is_lvtt(v, irq) )
        return !is_lvtt_enabled(v);

    if ( v->domain->arch.hvm_domain.irq.vpic[irq >> 3].imr & (1 << (irq & 7))
            && domain_vioapic(v->domain)->redirtbl[irq].fields.mask )
        return 1;

    return 0;
}
