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
*/

/*
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

/* HACK: Route IRQ0 only to VCPU0 to prevent time jumps. */
#define IRQ0_SPECIAL_ROUTING 1

#if defined(__ia64__)
#define opt_hvm_debug_level opt_vmx_debug_level
#endif

static void ioapic_enable(hvm_vioapic_t *s, uint8_t enable)
{
    if (enable)
        s->flags |= IOAPIC_ENABLE_FLAG;
    else
        s->flags &= ~IOAPIC_ENABLE_FLAG;
}

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

static unsigned long hvm_vioapic_read_indirect(struct hvm_vioapic *s,
                                              unsigned long addr,
                                              unsigned long length)
{
    unsigned long result = 0;

    ASSERT(s);

    switch (s->ioregsel) {
    case IOAPIC_REG_VERSION:
        result = ((((IOAPIC_NUM_PINS-1) & 0xff) << 16)
                  | (IOAPIC_VERSION_ID & 0xff));
        break;

#ifndef __ia64__
    case IOAPIC_REG_APIC_ID:
        result = ((s->id & 0xf) << 24);
        break;

    case IOAPIC_REG_ARB_ID:
        /* XXX how arb_id used on p4? */
        result = ((s->arb_id & 0xf) << 24);
        break;
#endif

    default:
        {
            uint32_t redir_index = 0;
            uint64_t redir_content = 0;

            redir_index = (s->ioregsel - 0x10) >> 1;

            if (redir_index >= 0 && redir_index < IOAPIC_NUM_PINS) {
                redir_content = s->redirtbl[redir_index].value;

                result = (s->ioregsel & 0x1)?
                           (redir_content >> 32) & 0xffffffff :
                           redir_content & 0xffffffff;
            } else {
                printk("apic_mem_readl:undefined ioregsel %x\n",
                        s->ioregsel);
                domain_crash_synchronous();
            }
            break;
        }
    } /* switch */

    return result;
}

static unsigned long hvm_vioapic_read(struct vcpu *v,
                                     unsigned long addr,
                                     unsigned long length)
{
    struct hvm_vioapic *s = &(v->domain->arch.hvm_domain.vioapic);
    uint32_t    result = 0;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "hvm_vioapic_read addr %lx\n", addr);

    ASSERT(s);

    addr &= 0xff;

    switch (addr) {
    case IOAPIC_REG_SELECT:
        result = s->ioregsel;
        break;

    case IOAPIC_REG_WINDOW:
        result = hvm_vioapic_read_indirect(s, addr, length);
        break;

    default:
          break;
    }

    return result;
}

static void hvm_vioapic_update_imr(struct hvm_vioapic *s, int index)
{
   if (s->redirtbl[index].RedirForm.mask)
       set_bit(index, &s->imr);
   else
       clear_bit(index, &s->imr);
}

static void hvm_vioapic_write_indirect(struct hvm_vioapic *s,
                                      unsigned long addr,
                                      unsigned long length,
                                      unsigned long val)
{
    switch (s->ioregsel) {
    case IOAPIC_REG_VERSION:
        printk("hvm_vioapic_write_indirect: version register read only\n");
        break;

#ifndef __ia64__
    case IOAPIC_REG_APIC_ID:
        s->id = (val >> 24) & 0xf;
        break;

    case IOAPIC_REG_ARB_ID:
        s->arb_id = val;
        break;
#endif

    default:
        {
            uint32_t redir_index = 0;

            HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "hvm_vioapic_write_indirect "
              "change redir index %x val %lx\n",
              redir_index, val);

            redir_index = (s->ioregsel - 0x10) >> 1;

            if (redir_index >= 0 && redir_index < IOAPIC_NUM_PINS) {
                uint64_t redir_content;

                redir_content = s->redirtbl[redir_index].value;

                if (s->ioregsel & 0x1)
                    redir_content = (((uint64_t)val & 0xffffffff) << 32) |
                                    (redir_content & 0xffffffff);
                else
                    redir_content = ((redir_content >> 32) << 32) |
                                    (val & 0xffffffff);
                s->redirtbl[redir_index].value = redir_content;
                hvm_vioapic_update_imr(s, redir_index);
            } else  {
                printk("hvm_vioapic_write_indirect "
                  "error register %x\n", s->ioregsel);
            }
            break;
        }
    } /* switch */
}

static void hvm_vioapic_write(struct vcpu *v,
                             unsigned long addr,
                             unsigned long length,
                             unsigned long val)
{
    hvm_vioapic_t *s = &(v->domain->arch.hvm_domain.vioapic);

    ASSERT(s);

    addr &= 0xff;

    switch (addr) {
    case IOAPIC_REG_SELECT:
        s->ioregsel = val;
        break;

    case IOAPIC_REG_WINDOW:
        hvm_vioapic_write_indirect(s, addr, length, val);
        break;

#ifdef __ia64__
    case IOAPIC_REG_EOI:
        ioapic_update_EOI(v->domain, val);
        break;
#endif

    default:
        break;
    }
}

static int hvm_vioapic_range(struct vcpu *v, unsigned long addr)
{
    hvm_vioapic_t *s = &(v->domain->arch.hvm_domain.vioapic);

    if ((s->flags & IOAPIC_ENABLE_FLAG) &&
        (addr >= s->base_address &&
        (addr < s->base_address + IOAPIC_MEM_LENGTH)))
        return 1;
    else
        return 0;
}

struct hvm_mmio_handler vioapic_mmio_handler = {
    .check_handler = hvm_vioapic_range,
    .read_handler = hvm_vioapic_read,
    .write_handler = hvm_vioapic_write
};

static void hvm_vioapic_reset(hvm_vioapic_t *s)
{
    int i;

    memset(s, 0, sizeof(hvm_vioapic_t));

    for (i = 0; i < IOAPIC_NUM_PINS; i++) {
        s->redirtbl[i].RedirForm.mask = 0x1;
        hvm_vioapic_update_imr(s, i);
    }
}

static void ioapic_update_config(hvm_vioapic_t *s,
                                 unsigned long address,
                                 uint8_t enable)
{
    ASSERT(s);

    ioapic_enable(s, enable);

    if (address != s->base_address)
        s->base_address = address;
}

static int ioapic_inj_irq(hvm_vioapic_t *s,
                          struct vlapic * target,
                          uint8_t vector,
                          uint8_t trig_mode,
                          uint8_t delivery_mode)
{
    int result = 0;

    ASSERT(s && target);

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_inj_irq "
      "irq %d trig %d delive mode %d\n",
      vector, trig_mode, delivery_mode);

    switch (delivery_mode) {
    case dest_Fixed:
    case dest_LowestPrio:
        if (vlapic_set_irq(target, vector, trig_mode) && (trig_mode == 1))
            printk("<ioapic_inj_irq> level interrupt happen before cleared\n");
        result = 1;
        break;
    default:
        printk("<ioapic_inj_irq> error delivery mode %d\n",
                delivery_mode);
        break;
   }

   return result;
}

#ifndef __ia64__
static int ioapic_match_logical_addr(hvm_vioapic_t *s, int number, uint8_t dest)
{
    int result = 0;
    uint32_t logical_dest = vlapic_get_reg(s->lapic_info[number], APIC_LDR);

    ASSERT(s && s->lapic_info[number]);

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_match_logical_addr "
      "number %i dest %x\n",
      number, dest);

    switch (vlapic_get_reg(s->lapic_info[number], APIC_DFR))
    {
    case APIC_DFR_FLAT:
        result =
          (dest & GET_APIC_LOGICAL_ID(logical_dest)) != 0;
        break;
    case APIC_DFR_CLUSTER:
        /* Should we support flat cluster mode ?*/
        if ( (GET_APIC_LOGICAL_ID(logical_dest) >> 4
               == ((dest >> 0x4) & 0xf)) &&
             (logical_dest & (dest  & 0xf)) )
            result = 1;
        break;
    default:
        printk("error DFR value for %x local apic\n", number);
        break;
    }

    return result;
}
#else
extern int ioapic_match_logical_addr(hvm_vioapic_t *s, int number, uint8_t dest);
#endif

static uint32_t ioapic_get_delivery_bitmask(hvm_vioapic_t *s,
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
      dest, dest_mode, vector, delivery_mode, s->lapic_count);

    ASSERT(s);

    if ( dest_mode == 0 )
    {
        /* Physical mode. */
        for ( i = 0; i < s->lapic_count; i++ )
        {
            if ( VLAPIC_ID(s->lapic_info[i]) == dest )
            {
                mask = 1 << i;
                break;
            }
        }

        /* Broadcast. */
        if ( dest == 0xFF )
        {
            for ( i = 0; i < s->lapic_count; i++ )
                mask |= ( 1 << i );
        }
    }
    else
    {
        /* Logical destination. Call match_logical_addr for each APIC. */
        if ( dest != 0 )
        {
            for ( i = 0; i < s->lapic_count; i++ )
            {
                if ( s->lapic_info[i] &&
                     ioapic_match_logical_addr(s, i, dest) )
                    mask |= (1<<i);
            }
        }
    }

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask "
      "mask %x\n", mask);

    return mask;
}

static void ioapic_deliver(hvm_vioapic_t *s, int irqno)
{
    uint16_t dest = s->redirtbl[irqno].RedirForm.dest_id;
    uint8_t dest_mode = s->redirtbl[irqno].RedirForm.destmode;
    uint8_t delivery_mode = s->redirtbl[irqno].RedirForm.deliver_mode;
    uint8_t vector = s->redirtbl[irqno].RedirForm.vector;
    uint8_t trig_mode = s->redirtbl[irqno].RedirForm.trigmod;
    uint32_t deliver_bitmask;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC,
      "dest %x dest_mode %x delivery_mode %x vector %x trig_mode %x\n",
      dest, dest_mode, delivery_mode, vector, trig_mode);

    deliver_bitmask = ioapic_get_delivery_bitmask(
        s, dest, dest_mode, vector, delivery_mode);

    if (!deliver_bitmask) {
        HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic deliver "
          "no target on destination\n");

        return;
    }

    switch (delivery_mode) {
    case dest_LowestPrio:
    {
        struct vlapic* target;

#ifdef IRQ0_SPECIAL_ROUTING
        if (irqno == 0)
            target = s->lapic_info[0];
        else
#endif
            target = apic_round_robin(s->domain, dest_mode,
                                      vector, deliver_bitmask);
        if (target)
            ioapic_inj_irq(s, target, vector, trig_mode, delivery_mode);
        else
            HVM_DBG_LOG(DBG_LEVEL_IOAPIC,
              "null round robin mask %x vector %x delivery_mode %x\n",
              deliver_bitmask, vector, dest_LowestPrio);
        break;
    }

    case dest_Fixed:
    case dest_ExtINT:
    {
        uint8_t bit;
        for (bit = 0; bit < s->lapic_count; bit++) {
            if (deliver_bitmask & (1 << bit)) {
#ifdef IRQ0_SPECIAL_ROUTING
                if ( (irqno == 0) && (bit !=0) )
                {
                    printk("PIT irq to bit %x\n", bit);
                    domain_crash_synchronous();
                }
#endif
                if (s->lapic_info[bit]) {
                    ioapic_inj_irq(s, s->lapic_info[bit],
                                vector, trig_mode, delivery_mode);
                }
            }
        }
        break;
    }

    case dest_SMI:
    case dest_NMI:
    case dest_INIT:
    case dest__reserved_2:
    default:
        printk("Not support delivey mode %d\n", delivery_mode);
        break;
    }
}

static int ioapic_get_highest_irq(hvm_vioapic_t *s)
{
    uint32_t irqs = (s->irr | s->irr_xen) & ~s->isr & ~s->imr;
    return fls(irqs) - 1;
}

static void service_ioapic(hvm_vioapic_t *s)
{
    int irqno;

    while ((irqno = ioapic_get_highest_irq(s)) != -1) {

        HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "service_ioapic "
          "highest irqno %x\n", irqno);

        if (!test_bit(irqno, &s->imr)) {
            ioapic_deliver(s, irqno);
        }

        if (s->redirtbl[irqno].RedirForm.trigmod == IOAPIC_LEVEL_TRIGGER) {
            s->isr |= (1 << irqno);
        }

        s->irr &= ~(1 << irqno);
	s->irr_xen &= ~(1 << irqno);
    }
}

void hvm_vioapic_do_irqs(struct domain *d, uint16_t irqs)
{
    hvm_vioapic_t *s = &(d->arch.hvm_domain.vioapic);

    if (!hvm_apic_support(d))
        return;

    s->irr |= irqs & ~s->imr;
    service_ioapic(s);
}

void hvm_vioapic_do_irqs_clear(struct domain *d, uint16_t irqs)
{
    hvm_vioapic_t *s = &(d->arch.hvm_domain.vioapic);

    if (!hvm_apic_support(d))
        return;

    s->irr &= ~irqs;
    service_ioapic(s);
}

void hvm_vioapic_set_xen_irq(struct domain *d, int irq, int level)
{
    hvm_vioapic_t *s = &d->arch.hvm_domain.vioapic;

    if (!hvm_apic_support(d) || !IOAPICEnabled(s) ||
	s->redirtbl[irq].RedirForm.mask)
        return;

    if (s->redirtbl[irq].RedirForm.trigmod != IOAPIC_LEVEL_TRIGGER) {
	DPRINTK("Forcing edge triggered APIC irq %d?\n", irq);
	domain_crash(d);
    }

    if (level)
	s->irr_xen |= 1 << irq;
    else
	s->irr_xen &= ~(1 << irq);
}

void hvm_vioapic_set_irq(struct domain *d, int irq, int level)
{
    hvm_vioapic_t *s = &(d->arch.hvm_domain.vioapic);

    if (!hvm_apic_support(d))
        return ;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_set_irq "
      "irq %x level %x\n", irq, level);

    if (irq < 0 || irq >= IOAPIC_NUM_PINS) {
        printk("ioapic_set_irq irq %x is illegal\n", irq);
        domain_crash_synchronous();
    }

    if (!IOAPICEnabled(s) || s->redirtbl[irq].RedirForm.mask)
        return;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "hvm_vioapic_set_irq entry %x "
      "vector %x deliver_mod %x destmode %x delivestatus %x "
      "polarity %x remote_irr %x trigmod %x mask %x dest_id %x\n",
      irq,
      s->redirtbl[irq].RedirForm.vector,
      s->redirtbl[irq].RedirForm.deliver_mode,
      s->redirtbl[irq].RedirForm.destmode,
      s->redirtbl[irq].RedirForm.delivestatus,
      s->redirtbl[irq].RedirForm.polarity,
      s->redirtbl[irq].RedirForm.remoteirr,
      s->redirtbl[irq].RedirForm.trigmod,
      s->redirtbl[irq].RedirForm.mask,
      s->redirtbl[irq].RedirForm.dest_id);

    if (irq >= 0 && irq < IOAPIC_NUM_PINS) {
        uint32_t bit = 1 << irq;
        if (s->redirtbl[irq].RedirForm.trigmod == IOAPIC_LEVEL_TRIGGER) {
            if (level)
                s->irr |= bit;
            else
                s->irr &= ~bit;
        } else {
            if (level)
                /* XXX No irr clear for edge interrupt */
                s->irr |= bit;
        }
    }

    service_ioapic(s);
}

/* XXX If level interrupt, use vector->irq table for performance */
static int get_redir_num(hvm_vioapic_t *s, int vector)
{
    int i = 0;

    ASSERT(s);

    for(i = 0; i < IOAPIC_NUM_PINS; i++) {
        if (s->redirtbl[i].RedirForm.vector == vector)
            return i;
    }

    return -1;
}

void ioapic_update_EOI(struct domain *d, int vector)
{
    hvm_vioapic_t *s = &(d->arch.hvm_domain.vioapic);
    int redir_num;

    if ((redir_num = get_redir_num(s, vector)) == -1) {
        printk("Can't find redir item for %d EOI \n", vector);
        return;
    }

    if (!test_and_clear_bit(redir_num, &s->isr)) {
        printk("redir %d not set for %d  EOI\n", redir_num, vector);
        return;
    }
}

int hvm_vioapic_add_lapic(struct vlapic *vlapic, struct vcpu *v)
{
    hvm_vioapic_t *s = &(v->domain->arch.hvm_domain.vioapic);

    if (v->vcpu_id != s->lapic_count) {
        printk("hvm_vioapic_add_lapic "
           "cpu_id not match vcpu_id %x lapic_count %x\n",
           v->vcpu_id, s->lapic_count);
        domain_crash_synchronous();
    }

    /* update count later for race condition on interrupt */
    s->lapic_info[s->lapic_count] = vlapic;
    s->lapic_count ++;

    return s->lapic_count;
}

hvm_vioapic_t * hvm_vioapic_init(struct domain *d)
{
    int i = 0;
    hvm_vioapic_t *s = &(d->arch.hvm_domain.vioapic);

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "hvm_vioapic_init\n");

    hvm_vioapic_reset(s);

    s->domain = d;

    for (i = 0; i < MAX_LAPIC_NUM; i++)
        s->lapic_info[i] = NULL;

    /* Remove after GFW ready */
    ioapic_update_config(s, IOAPIC_DEFAULT_BASE_ADDRESS, 1);

    return s;
}
