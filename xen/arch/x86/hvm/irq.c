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
#include <asm/hvm/support.h>

static void __hvm_pci_intx_assert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi, link, isa_irq;

    ASSERT((device <= 31) && (intx <= 3));

    if ( __test_and_set_bit(device*4 + intx, &hvm_irq->pci_intx.i) )
        return;

    gsi = hvm_pci_intx_gsi(device, intx);
    if ( hvm_irq->gsi_assert_count[gsi]++ == 0 )
        vioapic_irq_positive_edge(d, gsi);

    link    = hvm_pci_intx_link(device, intx);
    isa_irq = hvm_irq->pci_link.route[link];
    if ( (hvm_irq->pci_link_assert_count[link]++ == 0) && isa_irq &&
         (hvm_irq->gsi_assert_count[isa_irq]++ == 0) )
    {
        vioapic_irq_positive_edge(d, isa_irq);
        vpic_irq_positive_edge(d, isa_irq);
    }
}

void hvm_pci_intx_assert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    spin_lock(&d->arch.hvm_domain.irq_lock);
    __hvm_pci_intx_assert(d, device, intx);
    spin_unlock(&d->arch.hvm_domain.irq_lock);
}

static void __hvm_pci_intx_deassert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi, link, isa_irq;

    ASSERT((device <= 31) && (intx <= 3));

    if ( !__test_and_clear_bit(device*4 + intx, &hvm_irq->pci_intx.i) )
        return;

    gsi = hvm_pci_intx_gsi(device, intx);
    --hvm_irq->gsi_assert_count[gsi];

    link    = hvm_pci_intx_link(device, intx);
    isa_irq = hvm_irq->pci_link.route[link];
    if ( (--hvm_irq->pci_link_assert_count[link] == 0) && isa_irq &&
         (--hvm_irq->gsi_assert_count[isa_irq] == 0) )
        vpic_irq_negative_edge(d, isa_irq);
}

void hvm_pci_intx_deassert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    spin_lock(&d->arch.hvm_domain.irq_lock);
    __hvm_pci_intx_deassert(d, device, intx);
    spin_unlock(&d->arch.hvm_domain.irq_lock);
}

void hvm_isa_irq_assert(
    struct domain *d, unsigned int isa_irq)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi = hvm_isa_irq_to_gsi(isa_irq);

    ASSERT(isa_irq <= 15);

    spin_lock(&d->arch.hvm_domain.irq_lock);

    if ( !__test_and_set_bit(isa_irq, &hvm_irq->isa_irq.i) &&
         (hvm_irq->gsi_assert_count[gsi]++ == 0) )
    {
        vioapic_irq_positive_edge(d, gsi);
        vpic_irq_positive_edge(d, isa_irq);
    }

    spin_unlock(&d->arch.hvm_domain.irq_lock);
}

void hvm_isa_irq_deassert(
    struct domain *d, unsigned int isa_irq)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi = hvm_isa_irq_to_gsi(isa_irq);

    ASSERT(isa_irq <= 15);

    spin_lock(&d->arch.hvm_domain.irq_lock);

    if ( __test_and_clear_bit(isa_irq, &hvm_irq->isa_irq.i) &&
         (--hvm_irq->gsi_assert_count[gsi] == 0) )
        vpic_irq_negative_edge(d, isa_irq);

    spin_unlock(&d->arch.hvm_domain.irq_lock);
}

static void hvm_set_callback_irq_level(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi, pdev, pintx, asserted;

    ASSERT(v->vcpu_id == 0);

    spin_lock(&d->arch.hvm_domain.irq_lock);

    /* NB. Do not check the evtchn_upcall_mask. It is not used in HVM mode. */
    asserted = !!vcpu_info(v, evtchn_upcall_pending);
    if ( hvm_irq->callback_via_asserted == asserted )
        goto out;
    hvm_irq->callback_via_asserted = asserted;

    /* Callback status has changed. Update the callback via. */
    switch ( hvm_irq->callback_via_type )
    {
    case HVMIRQ_callback_gsi:
        gsi = hvm_irq->callback_via.gsi;
        if ( asserted && (hvm_irq->gsi_assert_count[gsi]++ == 0) )
        {
            vioapic_irq_positive_edge(d, gsi);
            if ( gsi <= 15 )
                vpic_irq_positive_edge(d, gsi);
        }
        else if ( !asserted && (--hvm_irq->gsi_assert_count[gsi] == 0) )
        {
            if ( gsi <= 15 )
                vpic_irq_negative_edge(d, gsi);
        }
        break;
    case HVMIRQ_callback_pci_intx:
        pdev  = hvm_irq->callback_via.pci.dev;
        pintx = hvm_irq->callback_via.pci.intx;
        if ( asserted )
            __hvm_pci_intx_assert(d, pdev, pintx);
        else
            __hvm_pci_intx_deassert(d, pdev, pintx);
    default:
        break;
    }

 out:
    spin_unlock(&d->arch.hvm_domain.irq_lock);
}

void hvm_maybe_deassert_evtchn_irq(void)
{
    struct domain *d = current->domain;
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    if ( hvm_irq->callback_via_asserted &&
         !vcpu_info(d->vcpu[0], evtchn_upcall_pending) )
        hvm_set_callback_irq_level(d->vcpu[0]);
}

void hvm_assert_evtchn_irq(struct vcpu *v)
{
    if ( v->vcpu_id != 0 )
        return;

    if ( unlikely(in_irq() || !local_irq_is_enabled()) )
    {
        tasklet_schedule(&v->arch.hvm_vcpu.assert_evtchn_irq_tasklet);
        return;
    }

    hvm_set_callback_irq_level(v);
}

void hvm_set_pci_link_route(struct domain *d, u8 link, u8 isa_irq)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    u8 old_isa_irq;
    int i;

    ASSERT((link <= 3) && (isa_irq <= 15));

    spin_lock(&d->arch.hvm_domain.irq_lock);

    old_isa_irq = hvm_irq->pci_link.route[link];
    if ( old_isa_irq == isa_irq )
        goto out;
    hvm_irq->pci_link.route[link] = isa_irq;

    /* PCI pass-through fixup. */
    if ( hvm_irq->dpci )
    {
        if ( old_isa_irq )
            clear_bit(old_isa_irq, &hvm_irq->dpci->isairq_map);

        for ( i = 0; i < NR_LINK; i++ )
            if ( hvm_irq->dpci->link_cnt[i] && hvm_irq->pci_link.route[i] )
                set_bit(hvm_irq->pci_link.route[i],
                        &hvm_irq->dpci->isairq_map);
    }

    if ( hvm_irq->pci_link_assert_count[link] == 0 )
        goto out;

    if ( old_isa_irq && (--hvm_irq->gsi_assert_count[old_isa_irq] == 0) )
        vpic_irq_negative_edge(d, old_isa_irq);

    if ( isa_irq && (hvm_irq->gsi_assert_count[isa_irq]++ == 0) )
    {
        vioapic_irq_positive_edge(d, isa_irq);
        vpic_irq_positive_edge(d, isa_irq);
    }

 out:
    spin_unlock(&d->arch.hvm_domain.irq_lock);

    dprintk(XENLOG_G_INFO, "Dom%u PCI link %u changed %u -> %u\n",
            d->domain_id, link, old_isa_irq, isa_irq);
}

void hvm_set_callback_via(struct domain *d, uint64_t via)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi=0, pdev=0, pintx=0;
    uint8_t via_type;

    via_type = (uint8_t)(via >> 56) + 1;
    if ( ((via_type == HVMIRQ_callback_gsi) && (via == 0)) ||
         (via_type > HVMIRQ_callback_pci_intx) )
        via_type = HVMIRQ_callback_none;

    spin_lock(&d->arch.hvm_domain.irq_lock);

    /* Tear down old callback via. */
    if ( hvm_irq->callback_via_asserted )
    {
        switch ( hvm_irq->callback_via_type )
        {
        case HVMIRQ_callback_gsi:
            gsi = hvm_irq->callback_via.gsi;
            if ( (--hvm_irq->gsi_assert_count[gsi] == 0) && (gsi <= 15) )
                vpic_irq_negative_edge(d, gsi);
            break;
        case HVMIRQ_callback_pci_intx:
            pdev  = hvm_irq->callback_via.pci.dev;
            pintx = hvm_irq->callback_via.pci.intx;
            __hvm_pci_intx_deassert(d, pdev, pintx);
            break;
        default:
            break;
        }
    }

    /* Set up new callback via. */
    switch ( hvm_irq->callback_via_type = via_type )
    {
    case HVMIRQ_callback_gsi:
        gsi = hvm_irq->callback_via.gsi = (uint8_t)via;
        if ( (gsi == 0) || (gsi >= ARRAY_SIZE(hvm_irq->gsi_assert_count)) )
            hvm_irq->callback_via_type = HVMIRQ_callback_none;
        else if ( hvm_irq->callback_via_asserted &&
                  (hvm_irq->gsi_assert_count[gsi]++ == 0) )
        {
            vioapic_irq_positive_edge(d, gsi);
            if ( gsi <= 15 )
                vpic_irq_positive_edge(d, gsi);
        }
        break;
    case HVMIRQ_callback_pci_intx:
        pdev  = hvm_irq->callback_via.pci.dev  = (uint8_t)(via >> 11) & 31;
        pintx = hvm_irq->callback_via.pci.intx = (uint8_t)via & 3;
        if ( hvm_irq->callback_via_asserted )
             __hvm_pci_intx_assert(d, pdev, pintx);
        break;
    default:
        break;
    }

    spin_unlock(&d->arch.hvm_domain.irq_lock);

    dprintk(XENLOG_G_INFO, "Dom%u callback via changed to ", d->domain_id);
    switch ( via_type )
    {
    case HVMIRQ_callback_gsi:
        printk("GSI %u\n", gsi);
        break;
    case HVMIRQ_callback_pci_intx:
        printk("PCI INTx Dev 0x%02x Int%c\n", pdev, 'A' + pintx);
        break;
    default:
        printk("None\n");
        break;
    }
}

struct hvm_intack hvm_vcpu_has_pending_irq(struct vcpu *v)
{
    struct hvm_domain *plat = &v->domain->arch.hvm_domain;
    int vector;

    if ( unlikely(v->nmi_pending) )
        return hvm_intack_nmi;

    if ( unlikely(v->mce_pending) )
        return hvm_intack_mce;

    if ( vlapic_accept_pic_intr(v) && plat->vpic[0].int_output )
        return hvm_intack_pic(0);

    vector = vlapic_has_pending_irq(v);
    if ( vector != -1 )
        return hvm_intack_lapic(vector);

    return hvm_intack_none;
}

struct hvm_intack hvm_vcpu_ack_pending_irq(
    struct vcpu *v, struct hvm_intack intack)
{
    int vector;

    switch ( intack.source )
    {
    case hvm_intsrc_nmi:
        if ( !test_and_clear_bool(v->nmi_pending) )
            intack = hvm_intack_none;
        break;
    case hvm_intsrc_mce:
        if ( !test_and_clear_bool(v->mce_pending) )
            intack = hvm_intack_none;
        break;
    case hvm_intsrc_pic:
        if ( (vector = vpic_ack_pending_irq(v)) == -1 )
            intack = hvm_intack_none;
        else
            intack.vector = (uint8_t)vector;
        break;
    case hvm_intsrc_lapic:
        if ( !vlapic_ack_pending_irq(v, intack.vector) )
            intack = hvm_intack_none;
        break;
    default:
        intack = hvm_intack_none;
        break;
    }

    return intack;
}

int hvm_local_events_need_delivery(struct vcpu *v)
{
    struct hvm_intack intack = hvm_vcpu_has_pending_irq(v);

    if ( likely(intack.source == hvm_intsrc_none) )
        return 0;

    return !hvm_interrupt_blocked(v, intack);
}

#if 0 /* Keep for debugging */
static void irq_dump(struct domain *d)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    int i; 
    printk("PCI 0x%16.16"PRIx64"%16.16"PRIx64
           " ISA 0x%8.8"PRIx32" ROUTE %u %u %u %u\n",
           hvm_irq->pci_intx.pad[0],  hvm_irq->pci_intx.pad[1],
           (uint32_t) hvm_irq->isa_irq.pad[0], 
           hvm_irq->pci_link.route[0], hvm_irq->pci_link.route[1],
           hvm_irq->pci_link.route[2], hvm_irq->pci_link.route[3]);
    for ( i = 0 ; i < VIOAPIC_NUM_PINS; i += 8 )
        printk("GSI  %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8
               " %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8"\n",
               hvm_irq->gsi_assert_count[i+0],
               hvm_irq->gsi_assert_count[i+1],
               hvm_irq->gsi_assert_count[i+2],
               hvm_irq->gsi_assert_count[i+3],
               hvm_irq->gsi_assert_count[i+4],
               hvm_irq->gsi_assert_count[i+5],
               hvm_irq->gsi_assert_count[i+6],
               hvm_irq->gsi_assert_count[i+7]);
    printk("Link %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8"\n",
           hvm_irq->pci_link_assert_count[0],
           hvm_irq->pci_link_assert_count[1],
           hvm_irq->pci_link_assert_count[2],
           hvm_irq->pci_link_assert_count[3]);
    printk("Callback via %i:0x%"PRIx32",%s asserted\n", 
           hvm_irq->callback_via_type, hvm_irq->callback_via.gsi, 
           hvm_irq->callback_via_asserted ? "" : " not");
}
#endif

static int irq_save_pci(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int asserted, pdev, pintx;
    int rc;

    spin_lock(&d->arch.hvm_domain.irq_lock);

    pdev  = hvm_irq->callback_via.pci.dev;
    pintx = hvm_irq->callback_via.pci.intx;
    asserted = (hvm_irq->callback_via_asserted &&
                (hvm_irq->callback_via_type == HVMIRQ_callback_pci_intx));

    /*
     * Deassert virtual interrupt via PCI INTx line. The virtual interrupt
     * status is not save/restored, so the INTx line must be deasserted in
     * the restore context.
     */
    if ( asserted )
        __hvm_pci_intx_deassert(d, pdev, pintx);

    /* Save PCI IRQ lines */
    rc = hvm_save_entry(PCI_IRQ, 0, h, &hvm_irq->pci_intx);

    if ( asserted )
        __hvm_pci_intx_assert(d, pdev, pintx);    

    spin_unlock(&d->arch.hvm_domain.irq_lock);

    return rc;
}

static int irq_save_isa(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    /* Save ISA IRQ lines */
    return ( hvm_save_entry(ISA_IRQ, 0, h, &hvm_irq->isa_irq) );
}

static int irq_save_link(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    /* Save PCI-ISA link state */
    return ( hvm_save_entry(PCI_LINK, 0, h, &hvm_irq->pci_link) );
}

static int irq_load_pci(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    int link, dev, intx, gsi;

    /* Load the PCI IRQ lines */
    if ( hvm_load_entry(PCI_IRQ, h, &hvm_irq->pci_intx) != 0 )
        return -EINVAL;

    /* Clear the PCI link assert counts */
    for ( link = 0; link < 4; link++ )
        hvm_irq->pci_link_assert_count[link] = 0;
    
    /* Clear the GSI link assert counts */
    for ( gsi = 0; gsi < VIOAPIC_NUM_PINS; gsi++ )
        hvm_irq->gsi_assert_count[gsi] = 0;

    /* Recalculate the counts from the IRQ line state */
    for ( dev = 0; dev < 32; dev++ )
        for ( intx = 0; intx < 4; intx++ )
            if ( test_bit(dev*4 + intx, &hvm_irq->pci_intx.i) )
            {
                /* Direct GSI assert */
                gsi = hvm_pci_intx_gsi(dev, intx);
                hvm_irq->gsi_assert_count[gsi]++;
                /* PCI-ISA bridge assert */
                link = hvm_pci_intx_link(dev, intx);
                hvm_irq->pci_link_assert_count[link]++;
            }

    return 0;
}

static int irq_load_isa(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    int irq;

    /* Load the ISA IRQ lines */
    if ( hvm_load_entry(ISA_IRQ, h, &hvm_irq->isa_irq) != 0 )
        return -EINVAL;

    /* Adjust the GSI assert counts for the ISA IRQ line state.
     * This relies on the PCI IRQ state being loaded first. */
    for ( irq = 0; platform_legacy_irq(irq); irq++ )
        if ( test_bit(irq, &hvm_irq->isa_irq.i) )
            hvm_irq->gsi_assert_count[hvm_isa_irq_to_gsi(irq)]++;

    return 0;
}


static int irq_load_link(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    int link, gsi;

    /* Load the PCI-ISA IRQ link routing table */
    if ( hvm_load_entry(PCI_LINK, h, &hvm_irq->pci_link) != 0 )
        return -EINVAL;

    /* Sanity check */
    for ( link = 0; link < 4; link++ )
        if ( hvm_irq->pci_link.route[link] > 15 )
        {
            gdprintk(XENLOG_ERR, 
                     "HVM restore: PCI-ISA link %u out of range (%u)\n",
                     link, hvm_irq->pci_link.route[link]);
            return -EINVAL;
        }

    /* Adjust the GSI assert counts for the link outputs.
     * This relies on the PCI and ISA IRQ state being loaded first */
    for ( link = 0; link < 4; link++ )
    {
        if ( hvm_irq->pci_link_assert_count[link] != 0 )
        {
            gsi = hvm_irq->pci_link.route[link];
            if ( gsi != 0 )
                hvm_irq->gsi_assert_count[gsi]++;
        }
    }

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(PCI_IRQ, irq_save_pci, irq_load_pci,
                          1, HVMSR_PER_DOM);
HVM_REGISTER_SAVE_RESTORE(ISA_IRQ, irq_save_isa, irq_load_isa, 
                          1, HVMSR_PER_DOM);
HVM_REGISTER_SAVE_RESTORE(PCI_LINK, irq_save_link, irq_load_link,
                          1, HVMSR_PER_DOM);
