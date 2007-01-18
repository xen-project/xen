/*
 *  Copyright (C) 2001  MandrakeSoft S.A.
 *
 *    MandrakeSoft S.A.
 *    43, rue d'Aboukir
 *    75002 Paris - France
 *    http://www.linux-mandrake.com/
 *    http://www.mandrakesoft.com/
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *  Yunhong Jiang <yunhong.jiang@intel.com>
 *  Ported to xen by using virtual IRQ line.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/io.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/support.h>
#include <asm/current.h>
#include <asm/event.h>

/* HACK: Route IRQ0 only to VCPU0 to prevent time jumps. */
#define IRQ0_SPECIAL_ROUTING 1

#if defined(__ia64__)
#define opt_hvm_debug_level opt_vmx_debug_level
#endif

static void vioapic_deliver(struct vioapic *vioapic, int irq);

static unsigned long vioapic_read_indirect(struct vioapic *vioapic,
                                           unsigned long addr,
                                           unsigned long length)
{
    unsigned long result = 0;

    switch ( vioapic->ioregsel )
    {
    case VIOAPIC_REG_VERSION:
        result = ((((VIOAPIC_NUM_PINS-1) & 0xff) << 16)
                  | (VIOAPIC_VERSION_ID & 0xff));
        break;

#if !VIOAPIC_IS_IOSAPIC
    case VIOAPIC_REG_APIC_ID:
    case VIOAPIC_REG_ARB_ID:
        result = ((vioapic->id & 0xf) << 24);
        break;
#endif

    default:
    {
        uint32_t redir_index = (vioapic->ioregsel - 0x10) >> 1;
        uint64_t redir_content;

        if ( redir_index >= VIOAPIC_NUM_PINS )
        {
            gdprintk(XENLOG_WARNING, "apic_mem_readl:undefined ioregsel %x\n",
                     vioapic->ioregsel);
            break;
        }

        redir_content = vioapic->redirtbl[redir_index].bits;
        result = (vioapic->ioregsel & 0x1)?
            (redir_content >> 32) & 0xffffffff :
            redir_content & 0xffffffff;
        break;
    }
    }

    return result;
}

static unsigned long vioapic_read(struct vcpu *v,
                                  unsigned long addr,
                                  unsigned long length)
{
    struct vioapic *vioapic = domain_vioapic(v->domain);
    uint32_t result;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "vioapic_read addr %lx\n", addr);

    addr &= 0xff;

    switch ( addr )
    {
    case VIOAPIC_REG_SELECT:
        result = vioapic->ioregsel;
        break;

    case VIOAPIC_REG_WINDOW:
        result = vioapic_read_indirect(vioapic, addr, length);
        break;

    default:
        result = 0;
        break;
    }

    return result;
}

static void vioapic_write_redirent(
    struct vioapic *vioapic, unsigned int idx, int top_word, uint32_t val)
{
    struct domain *d = vioapic_domain(vioapic);
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    union vioapic_redir_entry *pent, ent;

    spin_lock(&hvm_irq->lock);

    pent = &vioapic->redirtbl[idx];
    ent  = *pent;

    if ( top_word )
    {
        /* Contains only the dest_id. */
        ent.bits = (uint32_t)ent.bits | ((uint64_t)val << 32);
    }
    else
    {
        /* Remote IRR and Delivery Status are read-only. */
        ent.bits = ((ent.bits >> 32) << 32) | val;
        ent.fields.delivery_status = 0;
        ent.fields.remote_irr = pent->fields.remote_irr;
    }

    *pent = ent;

    if ( (ent.fields.trig_mode == VIOAPIC_LEVEL_TRIG) &&
         !ent.fields.mask &&
         !ent.fields.remote_irr &&
         hvm_irq->gsi_assert_count[idx] )
    {
        pent->fields.remote_irr = 1;
        vioapic_deliver(vioapic, idx);
    }

    spin_unlock(&hvm_irq->lock);
}

static void vioapic_write_indirect(
    struct vioapic *vioapic, unsigned long addr,
    unsigned long length, unsigned long val)
{
    switch ( vioapic->ioregsel )
    {
    case VIOAPIC_REG_VERSION:
        /* Writes are ignored. */
        break;

#if !VIOAPIC_IS_IOSAPIC
    case VIOAPIC_REG_APIC_ID:
        vioapic->id = (val >> 24) & 0xf;
        break;

    case VIOAPIC_REG_ARB_ID:
        break;
#endif

    default:
    {
        uint32_t redir_index = (vioapic->ioregsel - 0x10) >> 1;

        HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "vioapic_write_indirect "
                    "change redir index %x val %lx\n",
                    redir_index, val);

        if ( redir_index >= VIOAPIC_NUM_PINS )
        {
            gdprintk(XENLOG_WARNING, "vioapic_write_indirect "
                     "error register %x\n", vioapic->ioregsel);
            break;
        }

        vioapic_write_redirent(
            vioapic, redir_index, vioapic->ioregsel&1, val);
        break;
    }
    }
}

static void vioapic_write(struct vcpu *v,
                          unsigned long addr,
                          unsigned long length,
                          unsigned long val)
{
    struct vioapic *vioapic = domain_vioapic(v->domain);

    addr &= 0xff;

    switch ( addr )
    {
    case VIOAPIC_REG_SELECT:
        vioapic->ioregsel = val;
        break;

    case VIOAPIC_REG_WINDOW:
        vioapic_write_indirect(vioapic, addr, length, val);
        break;

#if VIOAPIC_IS_IOSAPIC
    case VIOAPIC_REG_EOI:
        vioapic_update_EOI(v->domain, val);
        break;
#endif

    default:
        break;
    }
}

static int vioapic_range(struct vcpu *v, unsigned long addr)
{
    struct vioapic *vioapic = domain_vioapic(v->domain);

    return ((addr >= vioapic->base_address &&
             (addr < vioapic->base_address + VIOAPIC_MEM_LENGTH)));
}

struct hvm_mmio_handler vioapic_mmio_handler = {
    .check_handler = vioapic_range,
    .read_handler = vioapic_read,
    .write_handler = vioapic_write
};

static void ioapic_inj_irq(
    struct vioapic *vioapic,
    struct vlapic *target,
    uint8_t vector,
    uint8_t trig_mode,
    uint8_t delivery_mode)
{
    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_inj_irq "
                "irq %d trig %d delive mode %d\n",
                vector, trig_mode, delivery_mode);

    switch ( delivery_mode )
    {
    case dest_Fixed:
    case dest_LowestPrio:
        if ( vlapic_set_irq(target, vector, trig_mode) )
            vcpu_kick(vlapic_vcpu(target));
        break;
    default:
        gdprintk(XENLOG_WARNING, "error delivery mode %d\n", delivery_mode);
        break;
    }
}

static uint32_t ioapic_get_delivery_bitmask(
    struct vioapic *vioapic, uint16_t dest, uint8_t dest_mode)
{
    uint32_t mask = 0;
    struct vcpu *v;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask "
                "dest %d dest_mode %d\n", dest, dest_mode);

    if ( dest_mode == 0 ) /* Physical mode. */
    {
        if ( dest == 0xFF ) /* Broadcast. */
        {
            for_each_vcpu ( vioapic_domain(vioapic), v )
                mask |= 1 << v->vcpu_id;
            goto out;
        }

        for_each_vcpu ( vioapic_domain(vioapic), v )
        {
            if ( VLAPIC_ID(vcpu_vlapic(v)) == dest )
            {
                mask = 1 << v->vcpu_id;
                break;
            }
        }
    }
    else if ( dest != 0 ) /* Logical mode, MDA non-zero. */
    {
        for_each_vcpu ( vioapic_domain(vioapic), v )
            if ( vlapic_match_logical_addr(vcpu_vlapic(v), dest) )
                mask |= 1 << v->vcpu_id;
    }

 out:
    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask mask %x\n",
                mask);
    return mask;
}

static inline int pit_channel0_enabled(void)
{
    PITState *pit = &current->domain->arch.hvm_domain.pl_time.vpit;
    struct periodic_time *pt = &pit->channels[0].pt;
    return pt->enabled;
}

static void vioapic_deliver(struct vioapic *vioapic, int irq)
{
    uint16_t dest = vioapic->redirtbl[irq].fields.dest_id;
    uint8_t dest_mode = vioapic->redirtbl[irq].fields.dest_mode;
    uint8_t delivery_mode = vioapic->redirtbl[irq].fields.delivery_mode;
    uint8_t vector = vioapic->redirtbl[irq].fields.vector;
    uint8_t trig_mode = vioapic->redirtbl[irq].fields.trig_mode;
    uint32_t deliver_bitmask;
    struct vlapic *target;
    struct vcpu *v;

    ASSERT(spin_is_locked(&vioapic_domain(vioapic)->arch.hvm_domain.irq.lock));

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC,
                "dest=%x dest_mode=%x delivery_mode=%x "
                "vector=%x trig_mode=%x\n",
                dest, dest_mode, delivery_mode, vector, trig_mode);

    deliver_bitmask = ioapic_get_delivery_bitmask(vioapic, dest, dest_mode);
    if ( !deliver_bitmask )
    {
        HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic deliver "
                    "no target on destination\n");
        return;
    }

    switch ( delivery_mode )
    {
    case dest_LowestPrio:
    {
#ifdef IRQ0_SPECIAL_ROUTING
        /* Force round-robin to pick VCPU 0 */
        if ( (irq == hvm_isa_irq_to_gsi(0)) && pit_channel0_enabled() )
        {
            v = vioapic_domain(vioapic)->vcpu[0];
            target = v ? vcpu_vlapic(v) : NULL;
        }
        else
#endif
            target = apic_round_robin(vioapic_domain(vioapic),
                                      vector, deliver_bitmask);
        if ( target != NULL )
        {
            ioapic_inj_irq(vioapic, target, vector, trig_mode, delivery_mode);
        }
        else
        {
            HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "null round robin: "
                        "mask=%x vector=%x delivery_mode=%x\n",
                        deliver_bitmask, vector, dest_LowestPrio);
        }
        break;
    }

    case dest_Fixed:
    case dest_ExtINT:
    {
        uint8_t bit;
        for ( bit = 0; deliver_bitmask != 0; bit++ )
        {
            if ( !(deliver_bitmask & (1 << bit)) )
                continue;
            deliver_bitmask &= ~(1 << bit);
#ifdef IRQ0_SPECIAL_ROUTING
            /* Do not deliver timer interrupts to VCPU != 0 */
            if ( (irq == hvm_isa_irq_to_gsi(0)) && pit_channel0_enabled() )
                v = vioapic_domain(vioapic)->vcpu[0];
            else
#endif
                v = vioapic_domain(vioapic)->vcpu[bit];
            if ( v != NULL )
            {
                target = vcpu_vlapic(v);
                ioapic_inj_irq(vioapic, target, vector,
                               trig_mode, delivery_mode);
            }
        }
        break;
    }

    case dest_SMI:
    case dest_NMI:
    case dest_INIT:
    case dest__reserved_2:
    default:
        gdprintk(XENLOG_WARNING, "Unsupported delivery mode %d\n",
                 delivery_mode);
        break;
    }
}

void vioapic_irq_positive_edge(struct domain *d, unsigned int irq)
{
    struct vioapic *vioapic = domain_vioapic(d);
    union vioapic_redir_entry *ent;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_irq_positive_edge irq %x", irq);

    ASSERT(irq < VIOAPIC_NUM_PINS);
    ASSERT(spin_is_locked(&d->arch.hvm_domain.irq.lock));

    ent = &vioapic->redirtbl[irq];
    if ( ent->fields.mask )
        return;

    if ( ent->fields.trig_mode == VIOAPIC_EDGE_TRIG )
    {
        vioapic_deliver(vioapic, irq);
    }
    else if ( !ent->fields.remote_irr )
    {
        ent->fields.remote_irr = 1;
        vioapic_deliver(vioapic, irq);
    }
}

static int get_eoi_gsi(struct vioapic *vioapic, int vector)
{
    int i;

    for ( i = 0; i < VIOAPIC_NUM_PINS; i++ )
        if ( vioapic->redirtbl[i].fields.vector == vector )
            return i;

    return -1;
}

void vioapic_update_EOI(struct domain *d, int vector)
{
    struct vioapic *vioapic = domain_vioapic(d);
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    union vioapic_redir_entry *ent;
    int gsi;

    spin_lock(&hvm_irq->lock);

    if ( (gsi = get_eoi_gsi(vioapic, vector)) == -1 )
    {
        gdprintk(XENLOG_WARNING, "Can't find redir item for %d EOI\n", vector);
        goto out;
    }

    ent = &vioapic->redirtbl[gsi];

    ent->fields.remote_irr = 0;
    if ( (ent->fields.trig_mode == VIOAPIC_LEVEL_TRIG) &&
         !ent->fields.mask &&
         hvm_irq->gsi_assert_count[gsi] )
    {
        ent->fields.remote_irr = 1;
        vioapic_deliver(vioapic, gsi);
    }

 out:
    spin_unlock(&hvm_irq->lock);
}

#ifdef HVM_DEBUG_SUSPEND
static void ioapic_info(struct vioapic *s)
{
    int i;
    printk("*****ioapic state:*****\n");
    printk("ioapic 0x%x.\n", s->ioregsel);
    printk("ioapic 0x%x.\n", s->id);
    printk("ioapic 0x%lx.\n", s->base_address);
    for (i = 0; i < VIOAPIC_NUM_PINS; i++) {
        printk("ioapic redirtbl[%d]:0x%"PRIx64"\n", i, s->redirtbl[i].bits);
    }

}
static void hvmirq_info(struct hvm_irq *hvm_irq)
{
    int i;
    printk("*****hvmirq state:*****\n");
    for (i = 0; i < BITS_TO_LONGS(32*4); i++)
        printk("hvmirq pci_intx[%d]:0x%lx.\n", i, hvm_irq->pci_intx[i]);

    for (i = 0; i < BITS_TO_LONGS(16); i++)
        printk("hvmirq isa_irq[%d]:0x%lx.\n", i, hvm_irq->isa_irq[i]);

    for (i = 0; i < BITS_TO_LONGS(1); i++)
        printk("hvmirq callback_irq_wire[%d]:0x%lx.\n", i, hvm_irq->callback_irq_wire[i]);

    printk("hvmirq callback_via_type:0x%x.\n", hvm_irq->callback_via_type);
    printk("hvmirq callback_via:0x%x.\n", hvm_irq->callback_via.gsi);
    

    for (i = 0; i < 4; i++)
        printk("hvmirq pci_link_route[%d]:0x%"PRIx8".\n", i, hvm_irq->pci_link_route[i]);

    for (i = 0; i < 4; i++)
        printk("hvmirq pci_link_assert_count[%d]:0x%"PRIx8".\n", i, hvm_irq->pci_link_assert_count[i]);

    for (i = 0; i < VIOAPIC_NUM_PINS; i++)
        printk("hvmirq gsi_assert_count[%d]:0x%"PRIx8".\n", i, hvm_irq->gsi_assert_count[i]);

    printk("hvmirq round_robin_prev_vcpu:0x%"PRIx8".\n", hvm_irq->round_robin_prev_vcpu);
}
#else
static void ioapic_info(struct vioapic *s)
{
}
static void hvmirq_info(struct hvm_irq *hvm_irq)
{
}
#endif

static void ioapic_save(hvm_domain_context_t *h, void *opaque)
{
    int i;
    struct domain *d = opaque;
    struct vioapic *s = domain_vioapic(d);
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    ioapic_info(s);
    hvmirq_info(hvm_irq);

    /* save iopaic state*/
    hvm_put_32u(h, s->ioregsel);
    hvm_put_32u(h, s->id);
    hvm_put_64u(h, s->base_address);
    for (i = 0; i < VIOAPIC_NUM_PINS; i++) {
        hvm_put_64u(h, s->redirtbl[i].bits);
    }

    /* save hvm irq state */
    hvm_put_buffer(h, (char*)hvm_irq->pci_intx, 16);
    hvm_put_buffer(h, (char*)hvm_irq->isa_irq, 2);
    hvm_put_32u(h, hvm_irq->callback_via_asserted);
    hvm_put_32u(h, hvm_irq->callback_via_type);
    hvm_put_32u(h, hvm_irq->callback_via.gsi);

    for (i = 0; i < 4; i++)
        hvm_put_8u(h, hvm_irq->pci_link_route[i]);

    for (i = 0; i < 4; i++)
        hvm_put_8u(h, hvm_irq->pci_link_assert_count[i]);

    for (i = 0; i < VIOAPIC_NUM_PINS; i++)
        hvm_put_8u(h, hvm_irq->gsi_assert_count[i]);

    hvm_put_8u(h, hvm_irq->round_robin_prev_vcpu);

}

static int ioapic_load(hvm_domain_context_t *h, void *opaque, int version_id)
{
    int i;
    struct domain *d = opaque;
    struct vioapic *s = domain_vioapic(d);
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    
    if (version_id != 1)
        return -EINVAL;

    /* restore ioapic state */
    s->ioregsel = hvm_get_32u(h);
    s->id = hvm_get_32u(h);
    s->base_address = hvm_get_64u(h);
    for (i = 0; i < VIOAPIC_NUM_PINS; i++) {
        s->redirtbl[i].bits = hvm_get_64u(h);
    }

    /* restore irq state */
    hvm_get_buffer(h, (char*)hvm_irq->pci_intx, 16);
    hvm_get_buffer(h, (char*)hvm_irq->isa_irq, 2);
    hvm_irq->callback_via_asserted = hvm_get_32u(h);
    hvm_irq->callback_via_type = hvm_get_32u(h);
    hvm_irq->callback_via.gsi = hvm_get_32u(h);

    for (i = 0; i < 4; i++)
        hvm_irq->pci_link_route[i] = hvm_get_8u(h);

    for (i = 0; i < 4; i++)
        hvm_irq->pci_link_assert_count[i] = hvm_get_8u(h);

    for (i = 0; i < VIOAPIC_NUM_PINS; i++)
        hvm_irq->gsi_assert_count[i] = hvm_get_8u(h);

    hvm_irq->round_robin_prev_vcpu = hvm_get_8u(h);

    ioapic_info(s);
    hvmirq_info(hvm_irq);

    return 0;
}

void vioapic_init(struct domain *d)
{
    struct vioapic *vioapic = domain_vioapic(d);
    int i;

    hvm_register_savevm(d, "xen_hvm_ioapic", 0, 1, ioapic_save, ioapic_load, d);

    memset(vioapic, 0, sizeof(*vioapic));
    for ( i = 0; i < VIOAPIC_NUM_PINS; i++ )
        vioapic->redirtbl[i].fields.mask = 1;
    vioapic->base_address = VIOAPIC_DEFAULT_BASE_ADDRESS;
}
