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
 * Support for virtual MSI logic
 * Will be merged it with virtual IOAPIC logic, since most is the same
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

static uint32_t vmsi_get_delivery_bitmask(
    struct domain *d, uint16_t dest, uint8_t dest_mode)
{
    uint32_t mask = 0;
    struct vcpu *v;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask "
                "dest %d dest_mode %d\n", dest, dest_mode);

    if ( dest_mode == 0 ) /* Physical mode. */
    {
        if ( dest == 0xFF ) /* Broadcast. */
        {
            for_each_vcpu ( d, v )
                mask |= 1 << v->vcpu_id;
            goto out;
        }

        for_each_vcpu ( d, v )
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
        for_each_vcpu ( d, v )
            if ( vlapic_match_logical_addr(vcpu_vlapic(v), dest) )
                mask |= 1 << v->vcpu_id;
    }

 out:
    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask mask %x\n",
                mask);
    return mask;
}

static void vmsi_inj_irq(
    struct domain *d,
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

#define VMSI_DEST_ID_MASK 0xff
#define VMSI_RH_MASK      0x100
#define VMSI_DM_MASK      0x200
#define VMSI_DELIV_MASK   0x7000
#define VMSI_TRIG_MODE    0x8000

#define GFLAGS_SHIFT_DEST_ID        0
#define GFLAGS_SHIFT_RH             8
#define GFLAGS_SHIFT_DM             9
#define GLFAGS_SHIFT_DELIV_MODE     12
#define GLFAGS_SHIFT_TRG_MODE       15

int vmsi_deliver(struct domain *d, int pirq)
{
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    uint32_t flags = hvm_irq_dpci->mirq[pirq].gmsi.gflags;
    int vector = hvm_irq_dpci->mirq[pirq].gmsi.gvec;
    uint16_t dest = (flags & VMSI_DEST_ID_MASK) >> GFLAGS_SHIFT_DEST_ID;
    uint8_t dest_mode = (flags & VMSI_DM_MASK) >> GFLAGS_SHIFT_DM;
    uint8_t delivery_mode = (flags & VMSI_DELIV_MASK) >> GLFAGS_SHIFT_DELIV_MODE;
    uint8_t trig_mode = (flags & VMSI_TRIG_MODE) >> GLFAGS_SHIFT_TRG_MODE;
    uint32_t deliver_bitmask;
    struct vlapic *target;
    struct vcpu *v;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC,
                "msi: dest=%x dest_mode=%x delivery_mode=%x "
                "vector=%x trig_mode=%x\n",
                dest, dest_mode, delivery_mode, vector, trig_mode);

    if ( !( hvm_irq_dpci->mirq[pirq].flags & HVM_IRQ_DPCI_GUEST_MSI ) )
    {
        gdprintk(XENLOG_WARNING, "pirq %x not msi \n", pirq);
        return 0;
    }

    deliver_bitmask = vmsi_get_delivery_bitmask(d, dest, dest_mode);
    if ( !deliver_bitmask )
    {
        HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic deliver "
                    "no target on destination\n");
        return 0;
    }

    switch ( delivery_mode )
    {
    case dest_LowestPrio:
    {
        target = apic_lowest_prio(d, deliver_bitmask);
        if ( target != NULL )
            vmsi_inj_irq(d, target, vector, trig_mode, delivery_mode);
        else
            HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "null round robin: "
                        "mask=%x vector=%x delivery_mode=%x\n",
                        deliver_bitmask, vector, dest_LowestPrio);
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
            v = d->vcpu[bit];
            if ( v != NULL )
            {
                target = vcpu_vlapic(v);
                vmsi_inj_irq(d, target, vector, trig_mode, delivery_mode);
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
    return 1;
}

