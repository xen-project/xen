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
 *  License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 *  Yunhong Jiang <yunhong.jiang@intel.com>
 *  Ported to xen by using virtual IRQ line.
 */

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
#include <asm/io_apic.h>

/* HACK: Route IRQ0 only to VCPU0 to prevent time jumps. */
#define IRQ0_SPECIAL_ROUTING 1

static void vioapic_deliver(struct hvm_vioapic *vioapic, unsigned int irq);

static struct hvm_vioapic *addr_vioapic(const struct domain *d,
                                        unsigned long addr)
{
    unsigned int i;

    for ( i = 0; i < d->arch.hvm_domain.nr_vioapics; i++ )
    {
        struct hvm_vioapic *vioapic = domain_vioapic(d, i);

        if ( addr >= vioapic->base_address &&
             addr < vioapic->base_address + VIOAPIC_MEM_LENGTH )
            return vioapic;
    }

    return NULL;
}

static struct hvm_vioapic *gsi_vioapic(const struct domain *d,
                                       unsigned int gsi, unsigned int *pin)
{
    unsigned int i;

    for ( i = 0; i < d->arch.hvm_domain.nr_vioapics; i++ )
    {
        struct hvm_vioapic *vioapic = domain_vioapic(d, i);

        if ( gsi >= vioapic->base_gsi &&
             gsi < vioapic->base_gsi + vioapic->nr_pins )
        {
            *pin = gsi - vioapic->base_gsi;
            return vioapic;
        }
    }

    return NULL;
}

static uint32_t vioapic_read_indirect(const struct hvm_vioapic *vioapic)
{
    uint32_t result = 0;

    switch ( vioapic->ioregsel )
    {
    case VIOAPIC_REG_VERSION:
        result = ((union IO_APIC_reg_01){
                  .bits = { .version = VIOAPIC_VERSION_ID,
                            .entries = vioapic->nr_pins - 1 }
                  }).raw;
        break;

    case VIOAPIC_REG_APIC_ID:
        /*
         * Using union IO_APIC_reg_02 for the ID register too, as
         * union IO_APIC_reg_00's ID field is 8 bits wide for some reason.
         */
    case VIOAPIC_REG_ARB_ID:
        result = ((union IO_APIC_reg_02){
                  .bits = { .arbitration = vioapic->id }
                  }).raw;
        break;

    default:
    {
        uint32_t redir_index = (vioapic->ioregsel - VIOAPIC_REG_RTE0) >> 1;
        uint64_t redir_content;

        if ( redir_index >= vioapic->nr_pins )
        {
            gdprintk(XENLOG_WARNING, "apic_mem_readl:undefined ioregsel %x\n",
                     vioapic->ioregsel);
            break;
        }

        redir_content = vioapic->redirtbl[redir_index].bits;
        result = (vioapic->ioregsel & 1) ? (redir_content >> 32)
                                         : redir_content;
        break;
    }
    }

    return result;
}

static int vioapic_read(
    struct vcpu *v, unsigned long addr,
    unsigned int length, unsigned long *pval)
{
    const struct hvm_vioapic *vioapic;
    uint32_t result;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "addr %lx", addr);

    vioapic = addr_vioapic(v->domain, addr);
    ASSERT(vioapic);

    switch ( addr & 0xff )
    {
    case VIOAPIC_REG_SELECT:
        result = vioapic->ioregsel;
        break;

    case VIOAPIC_REG_WINDOW:
        result = vioapic_read_indirect(vioapic);
        break;

    default:
        result = 0;
        break;
    }

    *pval = result;
    return X86EMUL_OKAY;
}

static int vioapic_hwdom_map_gsi(unsigned int gsi, unsigned int trig,
                                 unsigned int pol)
{
    struct domain *currd = current->domain;
    struct xen_domctl_bind_pt_irq pt_irq_bind = {
        .irq_type = PT_IRQ_TYPE_PCI,
        .machine_irq = gsi,
    };
    int ret, pirq = gsi;

    ASSERT(is_hardware_domain(currd));

    /* Interrupt has been unmasked, bind it now. */
    ret = mp_register_gsi(gsi, trig, pol);
    if ( ret == -EEXIST )
        return 0;
    if ( ret )
    {
        gprintk(XENLOG_WARNING, "vioapic: error registering GSI %u: %d\n",
                 gsi, ret);
        return ret;
    }

    ret = allocate_and_map_gsi_pirq(currd, pirq, &pirq);
    if ( ret )
    {
        gprintk(XENLOG_WARNING, "vioapic: error mapping GSI %u: %d\n",
                 gsi, ret);
        return ret;
    }

    pcidevs_lock();
    ret = pt_irq_create_bind(currd, &pt_irq_bind);
    if ( ret )
    {
        gprintk(XENLOG_WARNING, "vioapic: error binding GSI %u: %d\n",
                gsi, ret);
        spin_lock(&currd->event_lock);
        unmap_domain_pirq(currd, pirq);
        spin_unlock(&currd->event_lock);
    }
    pcidevs_unlock();

    return ret;
}

static void vioapic_write_redirent(
    struct hvm_vioapic *vioapic, unsigned int idx,
    int top_word, uint32_t val)
{
    struct domain *d = vioapic_domain(vioapic);
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    union vioapic_redir_entry *pent, ent;
    int unmasked = 0;
    unsigned int gsi = vioapic->base_gsi + idx;

    spin_lock(&d->arch.hvm_domain.irq_lock);

    pent = &vioapic->redirtbl[idx];
    ent  = *pent;

    if ( top_word )
    {
        /* Contains only the dest_id. */
        ent.bits = (uint32_t)ent.bits | ((uint64_t)val << 32);
    }
    else
    {
        unmasked = ent.fields.mask;
        /* Remote IRR and Delivery Status are read-only. */
        ent.bits = ((ent.bits >> 32) << 32) | val;
        ent.fields.delivery_status = 0;
        ent.fields.remote_irr = pent->fields.remote_irr;
        unmasked = unmasked && !ent.fields.mask;
    }

    *pent = ent;

    if ( is_hardware_domain(d) && unmasked )
    {
        int ret;

        ret = vioapic_hwdom_map_gsi(gsi, ent.fields.trig_mode,
                                    ent.fields.polarity);
        if ( ret )
        {
            /* Mask the entry again. */
            pent->fields.mask = 1;
            unmasked = 0;
        }
    }

    if ( gsi == 0 )
    {
        vlapic_adjust_i8259_target(d);
    }
    else if ( ent.fields.trig_mode == VIOAPIC_EDGE_TRIG )
        pent->fields.remote_irr = 0;
    else if ( !ent.fields.mask &&
              !ent.fields.remote_irr &&
              hvm_irq->gsi_assert_count[idx] )
    {
        pent->fields.remote_irr = 1;
        vioapic_deliver(vioapic, idx);
    }

    spin_unlock(&d->arch.hvm_domain.irq_lock);

    if ( gsi == 0 || unmasked )
        pt_may_unmask_irq(d, NULL);
}

static void vioapic_write_indirect(
    struct hvm_vioapic *vioapic, uint32_t val)
{
    switch ( vioapic->ioregsel )
    {
    case VIOAPIC_REG_VERSION:
        /* Writes are ignored. */
        break;

    case VIOAPIC_REG_APIC_ID:
        /*
         * Presumably because we emulate an Intel IOAPIC which only has a
         * 4 bit ID field (compared to 8 for AMD), using union IO_APIC_reg_02
         * for the ID register (union IO_APIC_reg_00's ID field is 8 bits).
         */
        vioapic->id = ((union IO_APIC_reg_02){ .raw = val }).bits.arbitration;
        break;

    case VIOAPIC_REG_ARB_ID:
        break;

    default:
    {
        uint32_t redir_index = (vioapic->ioregsel - VIOAPIC_REG_RTE0) >> 1;

        HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "rte[%02x].%s = %08x",
                    redir_index, vioapic->ioregsel & 1 ? "hi" : "lo", val);

        if ( redir_index >= vioapic->nr_pins )
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

static int vioapic_write(
    struct vcpu *v, unsigned long addr,
    unsigned int length, unsigned long val)
{
    struct hvm_vioapic *vioapic;

    vioapic = addr_vioapic(v->domain, addr);
    ASSERT(vioapic);

    switch ( addr & 0xff )
    {
    case VIOAPIC_REG_SELECT:
        vioapic->ioregsel = val;
        break;

    case VIOAPIC_REG_WINDOW:
        vioapic_write_indirect(vioapic, val);
        break;

#if VIOAPIC_VERSION_ID >= 0x20
    case VIOAPIC_REG_EOI:
        vioapic_update_EOI(v->domain, val);
        break;
#endif

    default:
        break;
    }

    return X86EMUL_OKAY;
}

static int vioapic_range(struct vcpu *v, unsigned long addr)
{
    return !!addr_vioapic(v->domain, addr);
}

static const struct hvm_mmio_ops vioapic_mmio_ops = {
    .check = vioapic_range,
    .read = vioapic_read,
    .write = vioapic_write
};

static void ioapic_inj_irq(
    struct hvm_vioapic *vioapic,
    struct vlapic *target,
    uint8_t vector,
    uint8_t trig_mode,
    uint8_t delivery_mode)
{
    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "irq %d trig %d deliv %d",
                vector, trig_mode, delivery_mode);

    ASSERT((delivery_mode == dest_Fixed) ||
           (delivery_mode == dest_LowestPrio));

    vlapic_set_irq(target, vector, trig_mode);
}

static inline int pit_channel0_enabled(void)
{
    return pt_active(&current->domain->arch.vpit.pt0);
}

static void vioapic_deliver(struct hvm_vioapic *vioapic, unsigned int pin)
{
    uint16_t dest = vioapic->redirtbl[pin].fields.dest_id;
    uint8_t dest_mode = vioapic->redirtbl[pin].fields.dest_mode;
    uint8_t delivery_mode = vioapic->redirtbl[pin].fields.delivery_mode;
    uint8_t vector = vioapic->redirtbl[pin].fields.vector;
    uint8_t trig_mode = vioapic->redirtbl[pin].fields.trig_mode;
    struct domain *d = vioapic_domain(vioapic);
    struct vlapic *target;
    struct vcpu *v;
    unsigned int irq = vioapic->base_gsi + pin;

    ASSERT(spin_is_locked(&d->arch.hvm_domain.irq_lock));

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC,
                "dest=%x dest_mode=%x delivery_mode=%x "
                "vector=%x trig_mode=%x",
                dest, dest_mode, delivery_mode, vector, trig_mode);

    switch ( delivery_mode )
    {
    case dest_LowestPrio:
    {
#ifdef IRQ0_SPECIAL_ROUTING
        /* Force round-robin to pick VCPU 0 */
        if ( (irq == hvm_isa_irq_to_gsi(0)) && pit_channel0_enabled() )
        {
            v = d->vcpu ? d->vcpu[0] : NULL;
            target = v ? vcpu_vlapic(v) : NULL;
        }
        else
#endif
            target = vlapic_lowest_prio(d, NULL, 0, dest, dest_mode);
        if ( target != NULL )
        {
            ioapic_inj_irq(vioapic, target, vector, trig_mode, delivery_mode);
        }
        else
        {
            HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "null round robin: "
                        "vector=%x delivery_mode=%x",
                        vector, dest_LowestPrio);
        }
        break;
    }

    case dest_Fixed:
    {
#ifdef IRQ0_SPECIAL_ROUTING
        /* Do not deliver timer interrupts to VCPU != 0 */
        if ( (irq == hvm_isa_irq_to_gsi(0)) && pit_channel0_enabled() )
        {
            if ( (v = d->vcpu ? d->vcpu[0] : NULL) != NULL )
                ioapic_inj_irq(vioapic, vcpu_vlapic(v), vector,
                               trig_mode, delivery_mode);
        }
        else
#endif
        {
            for_each_vcpu ( d, v )
                if ( vlapic_match_dest(vcpu_vlapic(v), NULL,
                                       0, dest, dest_mode) )
                    ioapic_inj_irq(vioapic, vcpu_vlapic(v), vector,
                                   trig_mode, delivery_mode);
        }
        break;
    }

    case dest_NMI:
    {
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL,
                                   0, dest, dest_mode) &&
                 !test_and_set_bool(v->nmi_pending) )
                vcpu_kick(v);
        break;
    }

    default:
        gdprintk(XENLOG_WARNING, "Unsupported delivery mode %d\n",
                 delivery_mode);
        break;
    }
}

void vioapic_irq_positive_edge(struct domain *d, unsigned int irq)
{
    unsigned int pin;
    struct hvm_vioapic *vioapic = gsi_vioapic(d, irq, &pin);
    union vioapic_redir_entry *ent;

    if ( !vioapic )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "irq %x", irq);

    ASSERT(pin < vioapic->nr_pins);
    ASSERT(spin_is_locked(&d->arch.hvm_domain.irq_lock));

    ent = &vioapic->redirtbl[pin];
    if ( ent->fields.mask )
        return;

    if ( ent->fields.trig_mode == VIOAPIC_EDGE_TRIG )
    {
        vioapic_deliver(vioapic, pin);
    }
    else if ( !ent->fields.remote_irr )
    {
        ent->fields.remote_irr = 1;
        vioapic_deliver(vioapic, pin);
    }
}

void vioapic_update_EOI(struct domain *d, u8 vector)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    union vioapic_redir_entry *ent;
    unsigned int i;

    ASSERT(has_vioapic(d));

    spin_lock(&d->arch.hvm_domain.irq_lock);

    for ( i = 0; i < d->arch.hvm_domain.nr_vioapics; i++ )
    {
        struct hvm_vioapic *vioapic = domain_vioapic(d, i);
        unsigned int pin;

        for ( pin = 0; pin < vioapic->nr_pins; pin++ )
        {
            ent = &vioapic->redirtbl[pin];
            if ( ent->fields.vector != vector )
                continue;

            ent->fields.remote_irr = 0;

            if ( iommu_enabled )
            {
                spin_unlock(&d->arch.hvm_domain.irq_lock);
                hvm_dpci_eoi(d, vioapic->base_gsi + pin, ent);
                spin_lock(&d->arch.hvm_domain.irq_lock);
            }

            if ( (ent->fields.trig_mode == VIOAPIC_LEVEL_TRIG) &&
                 !ent->fields.mask &&
                 hvm_irq->gsi_assert_count[vioapic->base_gsi + pin] )
            {
                ent->fields.remote_irr = 1;
                vioapic_deliver(vioapic, pin);
            }
        }
    }

    spin_unlock(&d->arch.hvm_domain.irq_lock);
}

int vioapic_get_mask(const struct domain *d, unsigned int gsi)
{
    unsigned int pin;
    const struct hvm_vioapic *vioapic = gsi_vioapic(d, gsi, &pin);

    if ( !vioapic )
        return -EINVAL;

    return vioapic->redirtbl[pin].fields.mask;
}

int vioapic_get_vector(const struct domain *d, unsigned int gsi)
{
    unsigned int pin;
    const struct hvm_vioapic *vioapic = gsi_vioapic(d, gsi, &pin);

    if ( !vioapic )
        return -EINVAL;

    return vioapic->redirtbl[pin].fields.vector;
}

int vioapic_get_trigger_mode(const struct domain *d, unsigned int gsi)
{
    unsigned int pin;
    const struct hvm_vioapic *vioapic = gsi_vioapic(d, gsi, &pin);

    if ( !vioapic )
        return -EINVAL;

    return vioapic->redirtbl[pin].fields.trig_mode;
}

static int ioapic_save(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_vioapic *s;

    if ( !has_vioapic(d) )
        return 0;

    s = domain_vioapic(d, 0);

    if ( s->nr_pins != ARRAY_SIZE(s->domU.redirtbl) ||
         d->arch.hvm_domain.nr_vioapics != 1 )
        return -EOPNOTSUPP;

    return hvm_save_entry(IOAPIC, 0, h, &s->domU);
}

static int ioapic_load(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_vioapic *s;

    if ( !has_vioapic(d) )
        return -ENODEV;

    s = domain_vioapic(d, 0);

    if ( s->nr_pins != ARRAY_SIZE(s->domU.redirtbl) ||
         d->arch.hvm_domain.nr_vioapics != 1 )
        return -EOPNOTSUPP;

    return hvm_load_entry(IOAPIC, h, &s->domU);
}

HVM_REGISTER_SAVE_RESTORE(IOAPIC, ioapic_save, ioapic_load, 1, HVMSR_PER_DOM);

void vioapic_reset(struct domain *d)
{
    unsigned int i;

    if ( !has_vioapic(d) )
    {
        ASSERT(!d->arch.hvm_domain.nr_vioapics);
        return;
    }

    for ( i = 0; i < d->arch.hvm_domain.nr_vioapics; i++ )
    {
        struct hvm_vioapic *vioapic = domain_vioapic(d, i);
        unsigned int nr_pins = vioapic->nr_pins, base_gsi = vioapic->base_gsi;
        unsigned int pin;

        memset(vioapic, 0, hvm_vioapic_size(nr_pins));
        for ( pin = 0; pin < nr_pins; pin++ )
            vioapic->redirtbl[pin].fields.mask = 1;

        if ( !is_hardware_domain(d) )
        {
            ASSERT(!i && !base_gsi);
            vioapic->base_address = VIOAPIC_DEFAULT_BASE_ADDRESS;
            vioapic->id = 0;
        }
        else
        {
            vioapic->base_address = mp_ioapics[i].mpc_apicaddr;
            vioapic->id = mp_ioapics[i].mpc_apicid;
        }
        vioapic->base_gsi = base_gsi;
        vioapic->nr_pins = nr_pins;
        vioapic->domain = d;
    }
}

static void vioapic_free(const struct domain *d, unsigned int nr_vioapics)
{
    unsigned int i;

    for ( i = 0; i < nr_vioapics; i++)
        xfree(domain_vioapic(d, i));
    xfree(d->arch.hvm_domain.vioapic);
}

int vioapic_init(struct domain *d)
{
    unsigned int i, nr_vioapics, nr_gsis = 0;

    if ( !has_vioapic(d) )
    {
        ASSERT(!d->arch.hvm_domain.nr_vioapics);
        return 0;
    }

    nr_vioapics = is_hardware_domain(d) ? nr_ioapics : 1;

    if ( (d->arch.hvm_domain.vioapic == NULL) &&
         ((d->arch.hvm_domain.vioapic =
           xzalloc_array(struct hvm_vioapic *, nr_vioapics)) == NULL) )
        return -ENOMEM;

    for ( i = 0; i < nr_vioapics; i++ )
    {
        unsigned int nr_pins, base_gsi;

        if ( is_hardware_domain(d) )
        {
            nr_pins = nr_ioapic_entries[i];
            base_gsi = io_apic_gsi_base(i);
        }
        else
        {
            nr_pins = ARRAY_SIZE(domain_vioapic(d, 0)->domU.redirtbl);
            base_gsi = 0;
        }

        if ( (domain_vioapic(d, i) =
              xmalloc_bytes(hvm_vioapic_size(nr_pins))) == NULL )
        {
            vioapic_free(d, nr_vioapics);
            return -ENOMEM;
        }
        domain_vioapic(d, i)->nr_pins = nr_pins;
        domain_vioapic(d, i)->base_gsi = base_gsi;
        nr_gsis = max(nr_gsis, base_gsi + nr_pins);
    }

    /*
     * NB: hvm_domain_irq(d)->nr_gsis is actually the highest GSI + 1, but
     * there might be holes in this range (ie: GSIs that don't belong to any
     * vIO APIC).
     */
    ASSERT(hvm_domain_irq(d)->nr_gsis >= nr_gsis);

    d->arch.hvm_domain.nr_vioapics = nr_vioapics;
    vioapic_reset(d);

    register_mmio_handler(d, &vioapic_mmio_ops);

    return 0;
}

void vioapic_deinit(struct domain *d)
{
    if ( !has_vioapic(d) )
    {
        ASSERT(!d->arch.hvm_domain.nr_vioapics);
        return;
    }

    vioapic_free(d, d->arch.hvm_domain.nr_vioapics);
}
