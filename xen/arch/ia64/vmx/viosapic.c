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
 * 
 *  Copyright (C) 2007 VA Linux Systems Japan K.K.
 *  Isaku Yamahata <yamahata at valinux co jp>
 *  SMP support
 *  xen save/restore support
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <public/hvm/ioreq.h>
#include <asm/vlsapic.h>
#include <asm/viosapic.h>
#include <asm/current.h>
#include <asm/event.h>
#include <asm/hvm/support.h>
#include <public/hvm/save.h>

static void viosapic_deliver(struct viosapic *viosapic, int irq)
{
    uint16_t dest = viosapic->redirtbl[irq].fields.dest_id;
    uint8_t delivery_mode = viosapic->redirtbl[irq].fields.delivery_mode;
    uint8_t vector = viosapic->redirtbl[irq].fields.vector;

    ASSERT(spin_is_locked(&viosapic->lock));

    if (vlsapic_deliver_int(viosapic_domain (viosapic),
                            dest, delivery_mode, vector) < 0)
        gdprintk(XENLOG_WARNING,
                 "viosapic: can't deliver int %u to %u (dm=%u)\n",
                 vector, dest, delivery_mode);
}


static int iosapic_get_highest_irq(struct viosapic *viosapic)
{
    uint64_t irqs = viosapic->irr & ~viosapic->isr ;
   
    if (irqs)
        return ia64_fls(irqs);

    return -1;
}


/* XXX If level interrupt, use vector->irq table for performance */
static int get_redir_num(struct viosapic *viosapic, int vector)
{
    int i;

    ASSERT(spin_is_locked(&viosapic->lock));
    for ( i = 0; i < VIOSAPIC_NUM_PINS; i++ )
        if ( viosapic->redirtbl[i].fields.vector == vector )
            return i;

    return -1;
}


static void service_iosapic(struct viosapic *viosapic)
{
    int irq;

    while ( (irq = iosapic_get_highest_irq(viosapic)) != -1 )
    {
        if ( viosapic->redirtbl[irq].fields.trig_mode == SAPIC_LEVEL )
            viosapic->isr |= (1UL << irq);

        viosapic_deliver(viosapic, irq);

        viosapic->irr &= ~(1UL << irq);
    }
}


static void viosapic_update_EOI(struct viosapic *viosapic, int vector)
{
    int redir_num;

    spin_lock(&viosapic->lock);
    if ( (redir_num = get_redir_num(viosapic, vector)) == -1 )
    {
        spin_unlock(&viosapic->lock);
        gdprintk(XENLOG_WARNING, "Can't find redir item for %d EOI\n", vector);
        return;
    }

    if ( !test_and_clear_bit(redir_num, &viosapic->isr) )
    {
        spin_unlock(&viosapic->lock);
        if ( viosapic->redirtbl[redir_num].fields.trig_mode == SAPIC_LEVEL )
            gdprintk(XENLOG_WARNING, "redir %d not set for %d EOI\n",
                     redir_num, vector);
        return;
    }
    if ( iommu_enabled )
    {
        spin_unlock(&viosapic->lock);
        hvm_dpci_eoi(current->domain, redir_num, &viosapic->redirtbl[redir_num]);
        spin_lock(&viosapic->lock);
    }

    service_iosapic(viosapic);
    spin_unlock(&viosapic->lock);
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
        /* ioregsel might be written at the same time. copy it before use. */
        uint32_t ioregsel = viosapic->ioregsel;
        uint32_t redir_index;
        uint64_t redir_content;

        redir_index = (ioregsel - 0x10) >> 1;
        if ( redir_index >= VIOSAPIC_NUM_PINS )
        {
            gdprintk(XENLOG_WARNING, "viosapic_read_indirect:undefined "
                     "ioregsel %x\n", ioregsel);
            break;
        }

        redir_content = viosapic->redirtbl[redir_index].bits;
        result = (ioregsel & 0x1) ?
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
        /* ioregsel might be written at the same time. copy it before use. */
        uint32_t ioregsel = viosapic->ioregsel;
        uint32_t redir_index;
        uint64_t redir_content;

        redir_index = (ioregsel - 0x10) >> 1;
        if ( redir_index >= VIOSAPIC_NUM_PINS )
        {
            gdprintk(XENLOG_WARNING, "viosapic_write_indirect "
                     "error register %x\n", viosapic->ioregsel);
            break;
        }

        spin_lock(&viosapic->lock);
        redir_content = viosapic->redirtbl[redir_index].bits;

        if ( ioregsel & 0x1 )
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
        spin_unlock(&viosapic->lock);
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
        viosapic->redirtbl[i].fields.mask = 0x1;
    }
    spin_lock_init(&viosapic->lock);
}

void viosapic_set_irq(struct domain *d, int irq, int level)
{
    struct viosapic *viosapic = domain_viosapic(d);
    uint64_t bit;

    spin_lock(&viosapic->lock);
    if ( (irq < 0) || (irq >= VIOSAPIC_NUM_PINS) )
        goto out;

    if ( viosapic->redirtbl[irq].fields.mask )
        goto out;

    bit = 1UL << irq;
    if ( viosapic->redirtbl[irq].fields.trig_mode == SAPIC_LEVEL )
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

void viosapic_set_pci_irq(struct domain *d, int device, int intx, int level)
{
    int irq;
    irq = hvm_pci_intx_gsi(device, intx);

    viosapic_set_irq(d, irq, level);
}

void viosapic_init(struct domain *d)
{
    struct viosapic *viosapic = domain_viosapic(d);

    viosapic_reset(viosapic);

    viosapic->lowest_vcpu = NULL;
    
    viosapic->base_address = VIOSAPIC_DEFAULT_BASE_ADDRESS;
}

#define VIOSAPIC_INVALID_VCPU_ID (-1UL)
static int viosapic_save(struct domain *d, hvm_domain_context_t *h)
{
    struct viosapic *viosapic = domain_viosapic(d);
    struct hvm_hw_ia64_viosapic viosapic_save;
    int i;

    memset(&viosapic_save, 0, sizeof(viosapic_save));
    
    spin_lock(&viosapic->lock);
    viosapic_save.irr = viosapic->irr;
    viosapic_save.isr = viosapic->isr;
    viosapic_save.ioregsel = viosapic->ioregsel;
    if (viosapic->lowest_vcpu != NULL)
        viosapic_save.lowest_vcpu_id = viosapic->lowest_vcpu->vcpu_id;
    else
        viosapic_save.lowest_vcpu_id = VIOSAPIC_INVALID_VCPU_ID;
    viosapic_save.base_address = viosapic->base_address;

    for (i = 0; i < VIOSAPIC_NUM_PINS; i++)
        viosapic_save.redirtbl[i] = viosapic->redirtbl[i];
    spin_unlock(&viosapic->lock);

    return hvm_save_entry(VIOSAPIC, 0, h, &viosapic_save);
}

static int viosapic_load(struct domain *d, hvm_domain_context_t *h)
{
    struct viosapic *viosapic = domain_viosapic(d);
    struct hvm_hw_ia64_viosapic viosapic_load;
    struct vcpu *lowest_vcpu;
    int i;

    if (hvm_load_entry(VIOSAPIC, h, &viosapic_load))
        return -EINVAL;

    lowest_vcpu = NULL;
    if (viosapic_load.lowest_vcpu_id < d->max_vcpus)
        lowest_vcpu = d->vcpu[viosapic_load.lowest_vcpu_id];
    else if (viosapic_load.lowest_vcpu_id != VIOSAPIC_INVALID_VCPU_ID)
        return -EINVAL;

    if (viosapic_load.base_address != VIOSAPIC_DEFAULT_BASE_ADDRESS)
        return -EINVAL;

    spin_lock(&viosapic->lock);
    viosapic->irr = viosapic_load.irr;
    viosapic->isr = viosapic_load.isr;
    viosapic->ioregsel = viosapic_load.ioregsel;

    viosapic->lowest_vcpu = lowest_vcpu;

    viosapic->base_address = viosapic_load.base_address;

    for (i = 0; i < VIOSAPIC_NUM_PINS; i++)
        viosapic->redirtbl[i] = viosapic_load.redirtbl[i];

    service_iosapic(viosapic);//XXX
    spin_unlock(&viosapic->lock);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(VIOSAPIC, viosapic_save, viosapic_load,
                          1, HVMSR_PER_DOM);
