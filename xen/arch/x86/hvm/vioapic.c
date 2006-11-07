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
#include <asm/hvm/support.h>
#include <asm/current.h>
#include <asm/event.h>

/* HACK: Route IRQ0 only to VCPU0 to prevent time jumps. */
#define IRQ0_SPECIAL_ROUTING 1
#ifdef IRQ0_SPECIAL_ROUTING
static int redir_warning_done = 0; 
#endif

#if defined(__ia64__)
#define opt_hvm_debug_level opt_vmx_debug_level
#endif

#ifdef HVM_DOMAIN_SAVE_RESTORE
void ioapic_save(QEMUFile* f, void* opaque)
{
    printk("no implementation for ioapic_save\n");
}

int ioapic_load(QEMUFile* f, void* opaque, int version_id)
{
    printk("no implementation for ioapic_load\n");
    return 0;
}
#endif

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

static void vioapic_update_imr(struct vioapic *vioapic, int index)
{
    if ( vioapic->redirtbl[index].fields.mask )
        set_bit(index, &vioapic->imr);
    else
        clear_bit(index, &vioapic->imr);
}


static void vioapic_write_indirect(struct vioapic *vioapic,
                                   unsigned long addr,
                                   unsigned long length,
                                   unsigned long val)
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
        uint64_t redir_content;

        HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "vioapic_write_indirect "
                    "change redir index %x val %lx\n",
                    redir_index, val);

        if ( redir_index >= VIOAPIC_NUM_PINS )
        {
            gdprintk(XENLOG_WARNING, "vioapic_write_indirect "
                     "error register %x\n", vioapic->ioregsel);
            break;
        }

        redir_content = vioapic->redirtbl[redir_index].bits;

        if ( vioapic->ioregsel & 0x1 )
        {
#ifdef IRQ0_SPECIAL_ROUTING
            if ( !redir_warning_done && (redir_index == 0) &&
                 ((val >> 24) != 0) )
            {
                /*
                 * Cannot yet handle delivering PIT interrupts to any VCPU != 
                 * 0. Needs proper fixing, but for now simply spit a warning 
                 * that we're going to ignore the target in practice and always
                 * deliver to VCPU 0.
                 */
                printk("IO-APIC: PIT (IRQ0) redirect to VCPU %lx "
                       "will be ignored.\n", val >> 24); 
                redir_warning_done = 1;
            }
#endif
            redir_content = (((uint64_t)val & 0xffffffff) << 32) |
                (redir_content & 0xffffffff);
        }
        else
        {
            redir_content = ((redir_content >> 32) << 32) |
                (val & 0xffffffff);
        }
        vioapic->redirtbl[redir_index].bits = redir_content;
        vioapic_update_imr(vioapic, redir_index);
        break;
    }
    } /* switch */
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

static void vioapic_reset(struct vioapic *vioapic)
{
    int i;

    memset(vioapic, 0, sizeof(*vioapic));

    for ( i = 0; i < VIOAPIC_NUM_PINS; i++ )
    {
        vioapic->redirtbl[i].fields.mask = 0x1;
        vioapic_update_imr(vioapic, i);
    }
}

static int ioapic_inj_irq(struct vioapic *vioapic,
                          struct vlapic * target,
                          uint8_t vector,
                          uint8_t trig_mode,
                          uint8_t delivery_mode)
{
    int result = 0;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_inj_irq "
                "irq %d trig %d delive mode %d\n",
                vector, trig_mode, delivery_mode);

    switch ( delivery_mode )
    {
    case dest_Fixed:
    case dest_LowestPrio:
        if ( vlapic_set_irq(target, vector, trig_mode) && (trig_mode == 1) )
            gdprintk(XENLOG_WARNING, "level interrupt before cleared\n");
        result = 1;
        break;
    default:
        gdprintk(XENLOG_WARNING, "error delivery mode %d\n", delivery_mode);
        break;
    }

    return result;
}

#ifndef __ia64__
static int ioapic_match_logical_addr(
    struct vioapic *vioapic, int number, uint8_t dest)
{
    int result = 0;
    uint32_t logical_dest;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_match_logical_addr "
                "number %i dest %x\n",
                number, dest);

    logical_dest = vlapic_get_reg(vioapic->lapic_info[number], APIC_LDR);

    switch ( vlapic_get_reg(vioapic->lapic_info[number], APIC_DFR) )
    {
    case APIC_DFR_FLAT:
        result = ((dest & GET_APIC_LOGICAL_ID(logical_dest)) != 0);
        break;
    case APIC_DFR_CLUSTER:
        /* Should we support flat cluster mode ?*/
        if ( (GET_APIC_LOGICAL_ID(logical_dest) >> 4
              == ((dest >> 0x4) & 0xf)) &&
             (logical_dest & (dest  & 0xf)) )
            result = 1;
        break;
    default:
        gdprintk(XENLOG_WARNING, "error DFR value for %x lapic\n", number);
        break;
    }

    return result;
}
#else
extern int ioapic_match_logical_addr(
    struct vioapic *vioapic, int number, uint8_t dest);
#endif

static uint32_t ioapic_get_delivery_bitmask(struct vioapic *vioapic,
                                            uint16_t dest,
                                            uint8_t dest_mode,
                                            uint8_t vector,
                                            uint8_t delivery_mode)
{
    uint32_t mask = 0;
    int i;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask "
                "dest %d dest_mode %d "
                "vector %d del_mode %d, lapic_count %d\n",
                dest, dest_mode, vector, delivery_mode, vioapic->lapic_count);

    if ( dest_mode == 0 )
    {
        /* Physical mode. */
        for ( i = 0; i < vioapic->lapic_count; i++ )
        {
            if ( VLAPIC_ID(vioapic->lapic_info[i]) == dest )
            {
                mask = 1 << i;
                break;
            }
        }

        /* Broadcast. */
        if ( dest == 0xFF )
        {
            for ( i = 0; i < vioapic->lapic_count; i++ )
                mask |= ( 1 << i );
        }
    }
    else
    {
        /* Logical destination. Call match_logical_addr for each APIC. */
        if ( dest != 0 )
        {
            for ( i = 0; i < vioapic->lapic_count; i++ )
            {
                if ( vioapic->lapic_info[i] &&
                     ioapic_match_logical_addr(vioapic, i, dest) )
                    mask |= (1<<i);
            }
        }
    }

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask "
                "mask %x\n", mask);

    return mask;
}

static void ioapic_deliver(struct vioapic *vioapic, int irq)
{
    uint16_t dest = vioapic->redirtbl[irq].fields.dest_id;
    uint8_t dest_mode = vioapic->redirtbl[irq].fields.dest_mode;
    uint8_t delivery_mode = vioapic->redirtbl[irq].fields.delivery_mode;
    uint8_t vector = vioapic->redirtbl[irq].fields.vector;
    uint8_t trig_mode = vioapic->redirtbl[irq].fields.trig_mode;
    uint32_t deliver_bitmask;
    struct vlapic *target;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC,
                "dest=%x dest_mode=%x delivery_mode=%x "
                "vector=%x trig_mode=%x\n",
                dest, dest_mode, delivery_mode, vector, trig_mode);

    deliver_bitmask = ioapic_get_delivery_bitmask(
        vioapic, dest, dest_mode, vector, delivery_mode);
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
        if ( irq == 0 )
            target = vioapic->lapic_info[0];
        else
#endif
            target = apic_round_robin(vioapic_domain(vioapic), dest_mode,
                                      vector, deliver_bitmask);
        if ( target != NULL )
        {
            ioapic_inj_irq(vioapic, target, vector, trig_mode, delivery_mode);
            vcpu_kick(vlapic_vcpu(target));
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
        for ( bit = 0; bit < vioapic->lapic_count; bit++ )
        {
            if ( !(deliver_bitmask & (1 << bit)) )
                continue;
#ifdef IRQ0_SPECIAL_ROUTING
            /* Do not deliver timer interrupts to VCPU != 0 */
            if ( (irq == 0) && (bit != 0) )
                target = vioapic->lapic_info[0];
            else
#endif
                target = vioapic->lapic_info[bit];
            if ( target != NULL )
            {
                ioapic_inj_irq(vioapic, target, vector,
                               trig_mode, delivery_mode);
                vcpu_kick(vlapic_vcpu(target));
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

static int ioapic_get_highest_irq(struct vioapic *vioapic)
{
    uint32_t irqs = vioapic->irr | vioapic->irr_xen;
    irqs &= ~vioapic->isr & ~vioapic->imr;
    return fls(irqs) - 1;
}

static void service_ioapic(struct vioapic *vioapic)
{
    int irq;

    while ( (irq = ioapic_get_highest_irq(vioapic)) != -1 )
    {
        HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "service_ioapic highest irq %x\n", irq);

        if ( !test_bit(irq, &vioapic->imr) )
            ioapic_deliver(vioapic, irq);

        if ( vioapic->redirtbl[irq].fields.trig_mode == VIOAPIC_LEVEL_TRIG )
            vioapic->isr |= (1 << irq);

        vioapic->irr     &= ~(1 << irq);
        vioapic->irr_xen &= ~(1 << irq);
    }
}

void vioapic_set_xen_irq(struct domain *d, int irq, int level)
{
    struct vioapic *vioapic = domain_vioapic(d);

    if ( vioapic->redirtbl[irq].fields.mask )
        return;

    if ( vioapic->redirtbl[irq].fields.trig_mode == VIOAPIC_EDGE_TRIG )
        gdprintk(XENLOG_WARNING, "Forcing edge triggered APIC irq %d?\n", irq);

    if ( level )
        vioapic->irr_xen |= 1 << irq;
    else
        vioapic->irr_xen &= ~(1 << irq);
}

void vioapic_set_irq(struct domain *d, int irq, int level)
{
    struct vioapic *vioapic = domain_vioapic(d);

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_set_irq "
                "irq %x level %x\n", irq, level);

    if ( (irq < 0) || (irq >= VIOAPIC_NUM_PINS) )
        return;

    if ( vioapic->redirtbl[irq].fields.mask )
        return;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "vioapic_set_irq entry %x "
                "vector %x delivery_mode %x dest_mode %x delivery_status %x "
                "polarity %x remote_irr %x trig_mode %x mask %x dest_id %x\n",
                irq,
                vioapic->redirtbl[irq].fields.vector,
                vioapic->redirtbl[irq].fields.delivery_mode,
                vioapic->redirtbl[irq].fields.dest_mode,
                vioapic->redirtbl[irq].fields.delivery_status,
                vioapic->redirtbl[irq].fields.polarity,
                vioapic->redirtbl[irq].fields.remote_irr,
                vioapic->redirtbl[irq].fields.trig_mode,
                vioapic->redirtbl[irq].fields.mask,
                vioapic->redirtbl[irq].fields.dest_id);

    if ( (irq >= 0) && (irq < VIOAPIC_NUM_PINS) )
    {
        uint32_t bit = 1 << irq;
        if ( vioapic->redirtbl[irq].fields.trig_mode == VIOAPIC_LEVEL_TRIG )
        {
            if ( level )
                vioapic->irr |= bit;
            else
                vioapic->irr &= ~bit;
        }
        else
        {
            if ( level )
                /* XXX No irr clear for edge interrupt */
                vioapic->irr |= bit;
        }
    }

    service_ioapic(vioapic);
}

/* XXX If level interrupt, use vector->irq table for performance */
static int get_redir_num(struct vioapic *vioapic, int vector)
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
    int redir_num;

    if ( (redir_num = get_redir_num(vioapic, vector)) == -1 )
    {
        gdprintk(XENLOG_WARNING, "Can't find redir item for %d EOI\n", vector);
        return;
    }

    if ( !test_and_clear_bit(redir_num, &vioapic->isr) )
    {
        gdprintk(XENLOG_WARNING, "redir %d not set for %d EOI\n",
                 redir_num, vector);
        return;
    }
}

int vioapic_add_lapic(struct vlapic *vlapic, struct vcpu *v)
{
    struct vioapic *vioapic = domain_vioapic(v->domain);

    if ( v->vcpu_id != vioapic->lapic_count )
    {
        gdprintk(XENLOG_ERR, "vioapic_add_lapic "
                 "cpu_id not match vcpu_id %x lapic_count %x\n",
                 v->vcpu_id, vioapic->lapic_count);
        domain_crash_synchronous();
    }

    /* Update count later for race condition on interrupt. */
    vioapic->lapic_info[vioapic->lapic_count] = vlapic;
    wmb();
    vioapic->lapic_count++;

    return vioapic->lapic_count;
}

void vioapic_init(struct domain *d)
{
    struct vioapic *vioapic = domain_vioapic(d);

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "vioapic_init\n");

    vioapic_reset(vioapic);

    vioapic->base_address = VIOAPIC_DEFAULT_BASE_ADDRESS;
}
