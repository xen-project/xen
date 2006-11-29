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
#include <asm/vlsapic.h>
#include <asm/viosapic.h>
#include <asm/current.h>
#include <asm/event.h>

static void viosapic_deliver(struct viosapic *viosapic, int irq)
{
    uint16_t dest = viosapic->redirtbl[irq].dest_id;
    uint8_t delivery_mode = viosapic->redirtbl[irq].delivery_mode;
    uint8_t vector = viosapic->redirtbl[irq].vector;
    struct vcpu *v;

    switch ( delivery_mode )
    {
    // don't support interrupt direct currently
    case SAPIC_FIXED:
    case SAPIC_LOWEST_PRIORITY:
    {
        v = vlsapic_lid_to_vcpu(viosapic_domain(viosapic), dest);
        vlsapic_set_irq(v, vector);
        vcpu_kick(v);
        break;
    }
    case SAPIC_PMI:
    case SAPIC_NMI:
    case SAPIC_INIT:
    case SAPIC_EXTINT:
    default:
        gdprintk(XENLOG_WARNING, "Unsupported delivery mode %d\n",
                 delivery_mode);
        break;
    }
}


static int iosapic_get_highest_irq(struct viosapic *viosapic)
{
    uint32_t irqs = viosapic->irr | viosapic->irr_xen;
    irqs &= ~viosapic->isr & ~viosapic->imr;
    return fls(irqs) - 1;
}


/* XXX If level interrupt, use vector->irq table for performance */
static int get_redir_num(struct viosapic *viosapic, int vector)
{
    int i;

    for ( i = 0; i < VIOSAPIC_NUM_PINS; i++ )
        if ( viosapic->redirtbl[i].vector == vector )
            return i;

    return -1;
}


static void service_iosapic(struct viosapic *viosapic)
{
    int irq;

    while ( (irq = iosapic_get_highest_irq(viosapic)) != -1 )
    {
        if ( !test_bit(irq, &viosapic->imr) )
            viosapic_deliver(viosapic, irq);

        if ( viosapic->redirtbl[irq].trig_mode == SAPIC_LEVEL )
            viosapic->isr |= (1 << irq);

        viosapic->irr &= ~(1 << irq);
        viosapic->irr_xen &= ~(1 << irq);
    }
}


static void viosapic_update_EOI(struct viosapic *viosapic, int vector)
{
    int redir_num;

    if ( (redir_num = get_redir_num(viosapic, vector)) == -1 )
    {
        gdprintk(XENLOG_WARNING, "Can't find redir item for %d EOI\n", vector);
        return;
    }

    if ( !test_and_clear_bit(redir_num, &viosapic->isr) )
    {
        gdprintk(XENLOG_WARNING, "redir %d not set for %d EOI\n",
                 redir_num, vector);
        return;
    }
    service_iosapic(viosapic);
}


static unsigned long viosapic_read_indirect(struct viosapic *viosapic,
                                            unsigned long addr,
                                            unsigned long length)
{
    unsigned long result = 0;

    switch ( viosapic->ioregsel )
    {
    case VIOSAPIC_VERSION:
        result = ((((VIOSAPIC_NUM_PINS - 1) & 0xff) << 16)
                  | (VIOSAPIC_VERSION_ID & 0xff));
        break;

    default:
    {
        uint32_t redir_index = (viosapic->ioregsel - 0x10) >> 1;
        uint64_t redir_content;

        if ( redir_index >= VIOSAPIC_NUM_PINS )
        {
            gdprintk(XENLOG_WARNING, "viosapic_read_indirect:undefined "
                     "ioregsel %x\n", viosapic->ioregsel);
            break;
        }

        redir_content = viosapic->redirtbl[redir_index].bits;
        result = (viosapic->ioregsel & 0x1) ?
                 (redir_content >> 32) & 0xffffffff :
                 redir_content & 0xffffffff;
        break;
    }
    }

    return result;
}


unsigned long viosapic_read(struct vcpu *v,
                            unsigned long addr,
                            unsigned long length)
{
    struct viosapic *viosapic = vcpu_viosapic(v);
    uint32_t result;

    addr &= 0xff;

    switch ( addr )
    {
    case VIOSAPIC_REG_SELECT:
        result = viosapic->ioregsel;
        break;

    case VIOSAPIC_WINDOW:
        result = viosapic_read_indirect(viosapic, addr, length);
        break;

    default:
        result = 0;
        break;
    }

    return result;
}


static inline void viosapic_update_imr(struct viosapic *viosapic, int index)
{
    if ( viosapic->redirtbl[index].mask )
        set_bit(index, &viosapic->imr);
    else
        clear_bit(index, &viosapic->imr);
}


static void viosapic_write_indirect(struct viosapic *viosapic,
                                    unsigned long addr,
                                    unsigned long length,
                                    unsigned long val)
{
    switch ( viosapic->ioregsel )
    {
    case VIOSAPIC_VERSION:
        /* Writes are ignored. */
        break;

    default:
    {
        uint32_t redir_index = (viosapic->ioregsel - 0x10) >> 1;
        uint64_t redir_content;

        if ( redir_index >= VIOSAPIC_NUM_PINS )
        {
            gdprintk(XENLOG_WARNING, "viosapic_write_indirect "
                     "error register %x\n", viosapic->ioregsel);
            break;
        }

        redir_content = viosapic->redirtbl[redir_index].bits;

        if ( viosapic->ioregsel & 0x1 )
        {
            redir_content = (((uint64_t)val & 0xffffffff) << 32) |
                            (redir_content & 0xffffffff);
        }
        else
        {
            redir_content = ((redir_content >> 32) << 32) |
                            (val & 0xffffffff);
        }
        viosapic->redirtbl[redir_index].bits = redir_content;
        viosapic_update_imr(viosapic, redir_index);
        break;
    }
    } /* switch */
}


void viosapic_write(struct vcpu *v,
                      unsigned long addr,
                      unsigned long length,
                      unsigned long val)
{
    struct viosapic *viosapic = vcpu_viosapic(v);

    addr &= 0xff;

    switch ( addr )
    {
    case VIOSAPIC_REG_SELECT:
        viosapic->ioregsel = val;
        break;

    case VIOSAPIC_WINDOW:
        viosapic_write_indirect(viosapic, addr, length, val);
        break;

    case VIOSAPIC_EOI:
        viosapic_update_EOI(viosapic, val);
        break;

    default:
        break;
    }
}


static void viosapic_reset(struct viosapic *viosapic)
{
    int i;

    memset(viosapic, 0, sizeof(*viosapic));

    for ( i = 0; i < VIOSAPIC_NUM_PINS; i++ )
    {
        viosapic->redirtbl[i].mask = 0x1;
        viosapic_update_imr(viosapic, i);
    }
    spin_lock_init(&viosapic->lock);
}


// this is used by VBD/VNIF to inject interrupt for VTI-domain
void viosapic_set_xen_irq(struct domain *d, int irq, int level)
{
    struct viosapic *viosapic = domain_viosapic(d);

    spin_lock(&viosapic->lock);
    if ( viosapic->redirtbl[irq].mask )
        goto out;

    if ( viosapic->redirtbl[irq].trig_mode == SAPIC_EDGE)
        gdprintk(XENLOG_WARNING, "Forcing edge triggered APIC irq %d?\n", irq);

    if ( level )
        viosapic->irr_xen |= 1 << irq;
    else
        viosapic->irr_xen &= ~(1 << irq);

    service_iosapic(viosapic);
out:
    spin_unlock(&viosapic->lock);
}


void viosapic_set_irq(struct domain *d, int irq, int level)
{
    struct viosapic *viosapic = domain_viosapic(d);
    uint32_t bit;

    spin_lock(&viosapic->lock);
    if ( (irq < 0) || (irq >= VIOSAPIC_NUM_PINS) )
        goto out;

    if ( viosapic->redirtbl[irq].mask )
        goto out;

    bit = 1 << irq;
    if ( viosapic->redirtbl[irq].trig_mode == SAPIC_LEVEL )
    {
        if ( level )
            viosapic->irr |= bit;
        else
            viosapic->irr &= ~bit;
    }
    else
    {
        if ( level )
            /* XXX No irr clear for edge interrupt */
            viosapic->irr |= bit;
    }

    service_iosapic(viosapic);
out:    
    spin_unlock(&viosapic->lock);
}


void viosapic_init(struct domain *d)
{
    struct viosapic *viosapic = domain_viosapic(d);

    viosapic_reset(viosapic);

    viosapic->base_address = VIOSAPIC_DEFAULT_BASE_ADDRESS;
}
