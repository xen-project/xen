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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/types.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/keyhandler.h>
#include <asm/hvm/domain.h>
#include <asm/hvm/support.h>
#include <asm/msi.h>

bool hvm_domain_use_pirq(const struct domain *d, const struct pirq *pirq)
{
    return is_hvm_domain(d) && pirq && pirq->arch.hvm.emuirq != IRQ_UNBOUND;
}

/* Must be called with hvm_domain->irq_lock hold */
static void assert_gsi(struct domain *d, unsigned ioapic_gsi)
{
    struct pirq *pirq =
        pirq_info(d, domain_emuirq_to_pirq(d, ioapic_gsi));

    if ( hvm_domain_use_pirq(d, pirq) )
    {
        send_guest_pirq(d, pirq);
        return;
    }
    vioapic_irq_positive_edge(d, ioapic_gsi);
}

int hvm_ioapic_assert(struct domain *d, unsigned int gsi, bool level)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    int vector;

    if ( gsi >= hvm_irq->nr_gsis )
    {
        ASSERT_UNREACHABLE();
        return -1;
    }

    spin_lock(&d->arch.hvm.irq_lock);
    if ( !level || hvm_irq->gsi_assert_count[gsi]++ == 0 )
        assert_gsi(d, gsi);
    vector = vioapic_get_vector(d, gsi);
    spin_unlock(&d->arch.hvm.irq_lock);

    return vector;
}

void hvm_ioapic_deassert(struct domain *d, unsigned int gsi)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);

    if ( gsi >= hvm_irq->nr_gsis )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    spin_lock(&d->arch.hvm.irq_lock);
    hvm_irq->gsi_assert_count[gsi]--;
    spin_unlock(&d->arch.hvm.irq_lock);
}

static void assert_irq(struct domain *d, unsigned ioapic_gsi, unsigned pic_irq)
{
    assert_gsi(d, ioapic_gsi);
    vpic_irq_positive_edge(d, pic_irq);
}

/* Must be called with hvm_domain->irq_lock hold */
static void deassert_irq(struct domain *d, unsigned isa_irq)
{
    struct pirq *pirq =
        pirq_info(d, domain_emuirq_to_pirq(d, isa_irq));

    if ( !hvm_domain_use_pirq(d, pirq) )
        vpic_irq_negative_edge(d, isa_irq);
}

static void __hvm_pci_intx_assert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    unsigned int gsi, link, isa_irq;

    ASSERT((device <= 31) && (intx <= 3));

    if ( __test_and_set_bit(device*4 + intx, &hvm_irq->pci_intx.i) )
        return;

    gsi = hvm_pci_intx_gsi(device, intx);
    if ( gsi >= hvm_irq->nr_gsis )
    {
        ASSERT_UNREACHABLE();
        return;
    }
    if ( hvm_irq->gsi_assert_count[gsi]++ == 0 )
        assert_gsi(d, gsi);

    link    = hvm_pci_intx_link(device, intx);
    isa_irq = hvm_irq->pci_link.route[link];
    if ( (hvm_irq->pci_link_assert_count[link]++ == 0) && isa_irq &&
         (hvm_irq->gsi_assert_count[isa_irq]++ == 0) )
        assert_irq(d, isa_irq, isa_irq);
}

void hvm_pci_intx_assert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    spin_lock(&d->arch.hvm.irq_lock);
    __hvm_pci_intx_assert(d, device, intx);
    spin_unlock(&d->arch.hvm.irq_lock);
}

static void __hvm_pci_intx_deassert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    unsigned int gsi, link, isa_irq;

    ASSERT((device <= 31) && (intx <= 3));

    if ( !__test_and_clear_bit(device*4 + intx, &hvm_irq->pci_intx.i) )
        return;

    gsi = hvm_pci_intx_gsi(device, intx);
    if ( gsi >= hvm_irq->nr_gsis )
    {
        ASSERT_UNREACHABLE();
        return;
    }
    --hvm_irq->gsi_assert_count[gsi];

    link    = hvm_pci_intx_link(device, intx);
    isa_irq = hvm_irq->pci_link.route[link];
    if ( (--hvm_irq->pci_link_assert_count[link] == 0) && isa_irq &&
         (--hvm_irq->gsi_assert_count[isa_irq] == 0) )
        deassert_irq(d, isa_irq);
}

void hvm_pci_intx_deassert(
    struct domain *d, unsigned int device, unsigned int intx)
{
    spin_lock(&d->arch.hvm.irq_lock);
    __hvm_pci_intx_deassert(d, device, intx);
    spin_unlock(&d->arch.hvm.irq_lock);
}

void hvm_gsi_assert(struct domain *d, unsigned int gsi)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);

    if ( gsi >= hvm_irq->nr_gsis )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    /*
     * __hvm_pci_intx_{de}assert uses a bitfield in pci_intx.i to track the
     * status of each interrupt line, and Xen does the routing and GSI
     * assertion based on that. The value of the pci_intx.i bitmap prevents the
     * same line from triggering multiple times. As we don't use that bitmap
     * for the hardware domain, Xen needs to rely on gsi_assert_count in order
     * to know if the GSI is pending or not.
     */
    spin_lock(&d->arch.hvm.irq_lock);
    if ( !hvm_irq->gsi_assert_count[gsi] )
    {
        hvm_irq->gsi_assert_count[gsi] = 1;
        assert_gsi(d, gsi);
    }
    spin_unlock(&d->arch.hvm.irq_lock);
}

void hvm_gsi_deassert(struct domain *d, unsigned int gsi)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);

    if ( gsi >= hvm_irq->nr_gsis )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    spin_lock(&d->arch.hvm.irq_lock);
    hvm_irq->gsi_assert_count[gsi] = 0;
    spin_unlock(&d->arch.hvm.irq_lock);
}

int hvm_isa_irq_assert(struct domain *d, unsigned int isa_irq,
                       int (*get_vector)(const struct domain *d,
                                         unsigned int gsi))
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    unsigned int gsi = hvm_isa_irq_to_gsi(isa_irq);
    int vector = -1;

    ASSERT(isa_irq <= 15);

    spin_lock(&d->arch.hvm.irq_lock);

    if ( !__test_and_set_bit(isa_irq, &hvm_irq->isa_irq.i) &&
         (hvm_irq->gsi_assert_count[gsi]++ == 0) )
        assert_irq(d, gsi, isa_irq);

    if ( get_vector )
        vector = get_vector(d, gsi);

    spin_unlock(&d->arch.hvm.irq_lock);

    return vector;
}

void hvm_isa_irq_deassert(
    struct domain *d, unsigned int isa_irq)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    unsigned int gsi = hvm_isa_irq_to_gsi(isa_irq);

    ASSERT(isa_irq <= 15);

    spin_lock(&d->arch.hvm.irq_lock);

    if ( __test_and_clear_bit(isa_irq, &hvm_irq->isa_irq.i) &&
         (--hvm_irq->gsi_assert_count[gsi] == 0) )
        deassert_irq(d, isa_irq);

    spin_unlock(&d->arch.hvm.irq_lock);
}

static void hvm_set_callback_irq_level(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    unsigned int gsi, pdev, pintx, asserted;

    ASSERT(v->vcpu_id == 0);

    spin_lock(&d->arch.hvm.irq_lock);

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
    spin_unlock(&d->arch.hvm.irq_lock);
}

void hvm_maybe_deassert_evtchn_irq(void)
{
    struct domain *d = current->domain;
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);

    if ( hvm_irq->callback_via_asserted &&
         !vcpu_info(d->vcpu[0], evtchn_upcall_pending) )
        hvm_set_callback_irq_level(d->vcpu[0]);
}

void hvm_assert_evtchn_irq(struct vcpu *v)
{
    if ( unlikely(in_irq() || !local_irq_is_enabled()) )
    {
        tasklet_schedule(&v->arch.hvm.assert_evtchn_irq_tasklet);
        return;
    }

    if ( v->arch.hvm.evtchn_upcall_vector != 0 )
    {
        uint8_t vector = v->arch.hvm.evtchn_upcall_vector;

        vlapic_set_irq(vcpu_vlapic(v), vector, 0);
    }
    else if ( is_hvm_pv_evtchn_vcpu(v) )
        vcpu_kick(v);
    else if ( v->vcpu_id == 0 )
        hvm_set_callback_irq_level(v);
}

int hvm_set_pci_link_route(struct domain *d, u8 link, u8 isa_irq)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    u8 old_isa_irq;
    int i;

    if ( (link > 3) || (isa_irq > 15) )
        return -EINVAL;

    spin_lock(&d->arch.hvm.irq_lock);

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
    spin_unlock(&d->arch.hvm.irq_lock);

    dprintk(XENLOG_G_INFO, "Dom%u PCI link %u changed %u -> %u\n",
            d->domain_id, link, old_isa_irq, isa_irq);

    return 0;
}

int hvm_inject_msi(struct domain *d, uint64_t addr, uint32_t data)
{
    uint32_t tmp = (uint32_t) addr;
    uint8_t  dest = (tmp & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
    uint8_t  dest_mode = !!(tmp & MSI_ADDR_DESTMODE_MASK);
    uint8_t  delivery_mode = (data & MSI_DATA_DELIVERY_MODE_MASK)
        >> MSI_DATA_DELIVERY_MODE_SHIFT;
    uint8_t trig_mode = (data & MSI_DATA_TRIGGER_MASK)
        >> MSI_DATA_TRIGGER_SHIFT;
    uint8_t vector = data & MSI_DATA_VECTOR_MASK;

    if ( !vector )
    {
        int pirq = ((addr >> 32) & 0xffffff00) | dest;

        if ( pirq > 0 )
        {
            struct pirq *info = pirq_info(d, pirq);

            /* if it is the first time, allocate the pirq */
            if ( !info || info->arch.hvm.emuirq == IRQ_UNBOUND )
            {
                int rc;

                spin_lock(&d->event_lock);
                rc = map_domain_emuirq_pirq(d, pirq, IRQ_MSI_EMU);
                spin_unlock(&d->event_lock);
                if ( rc )
                    return rc;
                info = pirq_info(d, pirq);
                if ( !info )
                    return -EBUSY;
            }
            else if ( info->arch.hvm.emuirq != IRQ_MSI_EMU )
                return -EINVAL;
            send_guest_pirq(d, info);
            return 0;
        }
        return -ERANGE;
    }

    return vmsi_deliver(d, vector, dest, dest_mode, delivery_mode, trig_mode);
}

void hvm_set_callback_via(struct domain *d, uint64_t via)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    unsigned int gsi=0, pdev=0, pintx=0;
    uint8_t via_type;
    struct vcpu *v;

    via_type = (uint8_t)MASK_EXTR(via, HVM_PARAM_CALLBACK_IRQ_TYPE_MASK) + 1;
    if ( ((via_type == HVMIRQ_callback_gsi) && (via == 0)) ||
         (via_type > HVMIRQ_callback_vector) )
        via_type = HVMIRQ_callback_none;

    if ( via_type != HVMIRQ_callback_vector &&
         (!has_vlapic(d) || !has_vioapic(d) || !has_vpic(d)) )
        return;

    spin_lock(&d->arch.hvm.irq_lock);

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
        if ( (gsi == 0) || (gsi >= hvm_irq->nr_gsis) )
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
    case HVMIRQ_callback_vector:
        hvm_irq->callback_via.vector = (uint8_t)via;
        break;
    default:
        break;
    }

    spin_unlock(&d->arch.hvm.irq_lock);

    for_each_vcpu ( d, v )
        if ( is_vcpu_online(v) )
            hvm_assert_evtchn_irq(v);

#ifndef NDEBUG
    printk(XENLOG_G_INFO "Dom%u callback via changed to ", d->domain_id);
    switch ( via_type )
    {
    case HVMIRQ_callback_gsi:
        printk("GSI %u\n", gsi);
        break;
    case HVMIRQ_callback_pci_intx:
        printk("PCI INTx Dev 0x%02x Int%c\n", pdev, 'A' + pintx);
        break;
    case HVMIRQ_callback_vector:
        printk("Direct Vector 0x%02x\n", (uint8_t)via);
        break;
    default:
        printk("None\n");
        break;
    }
#endif
}

struct hvm_intack hvm_vcpu_has_pending_irq(struct vcpu *v)
{
    struct hvm_domain *plat = &v->domain->arch.hvm;
    int vector;

    /*
     * Always call vlapic_sync_pir_to_irr so that PIR is synced into IRR when
     * using posted interrupts. Note this is also done by
     * vlapic_has_pending_irq but depending on which interrupts are pending
     * hvm_vcpu_has_pending_irq will return early without calling
     * vlapic_has_pending_irq.
     */
    vlapic_sync_pir_to_irr(v);

    if ( unlikely(v->nmi_pending) )
        return hvm_intack_nmi;

    if ( unlikely(v->mce_pending) )
        return hvm_intack_mce;

    if ( (plat->irq->callback_via_type == HVMIRQ_callback_vector)
         && vcpu_info(v, evtchn_upcall_pending) )
        return hvm_intack_vector(plat->irq->callback_via.vector);

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
        if ( !vlapic_ack_pending_irq(v, intack.vector, 0) )
            intack = hvm_intack_none;
        break;
    case hvm_intsrc_vector:
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

static void irq_dump(struct domain *d)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    int i; 
    printk("Domain %d:\n", d->domain_id);
    printk("PCI 0x%16.16"PRIx64"%16.16"PRIx64
           " ISA 0x%8.8"PRIx32" ROUTE %u %u %u %u\n",
           hvm_irq->pci_intx.pad[0],  hvm_irq->pci_intx.pad[1],
           (uint32_t) hvm_irq->isa_irq.pad[0], 
           hvm_irq->pci_link.route[0], hvm_irq->pci_link.route[1],
           hvm_irq->pci_link.route[2], hvm_irq->pci_link.route[3]);
    for ( i = 0; i < hvm_irq->nr_gsis && i + 8 <= hvm_irq->nr_gsis; i += 8 )
        printk("GSI [%x - %x] %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8
               " %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8"\n",
               i, i+7,
               hvm_irq->gsi_assert_count[i+0],
               hvm_irq->gsi_assert_count[i+1],
               hvm_irq->gsi_assert_count[i+2],
               hvm_irq->gsi_assert_count[i+3],
               hvm_irq->gsi_assert_count[i+4],
               hvm_irq->gsi_assert_count[i+5],
               hvm_irq->gsi_assert_count[i+6],
               hvm_irq->gsi_assert_count[i+7]);
    if ( i != hvm_irq->nr_gsis )
    {
        printk("GSI [%x - %x]", i, hvm_irq->nr_gsis - 1);
        for ( ; i < hvm_irq->nr_gsis; i++)
            printk(" %2"PRIu8, hvm_irq->gsi_assert_count[i]);
        printk("\n");
    }
    printk("Link %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8" %2.2"PRIu8"\n",
           hvm_irq->pci_link_assert_count[0],
           hvm_irq->pci_link_assert_count[1],
           hvm_irq->pci_link_assert_count[2],
           hvm_irq->pci_link_assert_count[3]);
    printk("Callback via %i:%#"PRIx32",%s asserted\n",
           hvm_irq->callback_via_type, hvm_irq->callback_via.gsi, 
           hvm_irq->callback_via_asserted ? "" : " not");
}

static void dump_irq_info(unsigned char key)
{
    struct domain *d;

    printk("'%c' pressed -> dumping HVM irq info\n", key);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
        if ( is_hvm_domain(d) )
            irq_dump(d);

    rcu_read_unlock(&domlist_read_lock);
}

static int __init dump_irq_info_key_init(void)
{
    register_keyhandler('I', dump_irq_info, "dump HVM irq info", 1);
    return 0;
}
__initcall(dump_irq_info_key_init);

static int irq_save_pci(struct vcpu *v, hvm_domain_context_t *h)
{
    struct domain *d = v->domain;
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    unsigned int asserted, pdev, pintx;
    int rc;

    spin_lock(&d->arch.hvm.irq_lock);

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

    spin_unlock(&d->arch.hvm.irq_lock);

    return rc;
}

static int irq_save_isa(struct vcpu *v, hvm_domain_context_t *h)
{
    const struct domain *d = v->domain;
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);

    /* Save ISA IRQ lines */
    return ( hvm_save_entry(ISA_IRQ, 0, h, &hvm_irq->isa_irq) );
}

static int irq_save_link(struct vcpu *v, hvm_domain_context_t *h)
{
    const struct domain *d = v->domain;
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);

    /* Save PCI-ISA link state */
    return ( hvm_save_entry(PCI_LINK, 0, h, &hvm_irq->pci_link) );
}

static int irq_load_pci(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    int link, dev, intx, gsi;

    /* Load the PCI IRQ lines */
    if ( hvm_load_entry(PCI_IRQ, h, &hvm_irq->pci_intx) != 0 )
        return -EINVAL;

    /* Clear the PCI link assert counts */
    for ( link = 0; link < 4; link++ )
        hvm_irq->pci_link_assert_count[link] = 0;
    
    /* Clear the GSI link assert counts */
    for ( gsi = 0; gsi < hvm_irq->nr_gsis; gsi++ )
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
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
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
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
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
