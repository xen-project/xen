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

#include <asm/vmx_vioapic.h>
#include <asm/vmx_platform.h>

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <public/io/ioreq.h>
#include <asm/vmx.h>
#include <public/io/vmx_vpic.h>
#include <asm/current.h>

static void ioapic_enable(vmx_vioapic_t *s, uint8_t enable)
{
    if (enable)
        s->flags |= IOAPIC_ENABLE_FLAG;
    else
        s->flags &= ~IOAPIC_ENABLE_FLAG;
}

static void ioapic_dump_redir(vmx_vioapic_t *s, uint8_t entry)
{
    ASSERT(s);

    RedirStatus redir = s->redirtbl[entry];

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_dump_redir "
      "entry %x vector %x deliver_mod %x destmode %x delivestatus %x "
      "polarity %x remote_irr %x trigmod %x mask %x dest_id %x\n",
      entry, redir.RedirForm.vector, redir.RedirForm.deliver_mode,
      redir.RedirForm.destmode, redir.RedirForm.delivestatus,
      redir.RedirForm.polarity, redir.RedirForm.remoteirr,
      redir.RedirForm.trigmod, redir.RedirForm.mask,
      redir.RedirForm.dest_id);
}

#ifdef VMX_DOMAIN_SAVE_RESTORE
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

static unsigned long vmx_vioapic_read_indirect(struct vmx_vioapic *s,
                                              unsigned long addr,
                                              unsigned long length)
{
    unsigned long result = 0;

    ASSERT(s);

    switch (s->ioregsel) {
    case IOAPIC_REG_VERSION:
        result = ((((IOAPIC_NUM_PINS-1) & 0xff) << 16)
                  | (IOAPIC_VERSION_ID & 0x0f));
        break;

#ifndef __ia64__
    case IOAPIC_REG_APIC_ID:
        result = ((s->id & 0xf) << 24);
        break;

    case IOAPIC_REG_ARB_ID:
        /* XXX how arb_id used on p4? */
        result = ((s->id & 0xf) << 24);
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
                printk("upic_mem_readl:undefined ioregsel %x\n",
                        s->ioregsel);
                domain_crash_synchronous();
            }
            break;
        }
    } /* switch */

    return result;
}

static unsigned long vmx_vioapic_read(struct vcpu *v,
                                     unsigned long addr,
                                     unsigned long length)
{
    struct vmx_vioapic *s = &(v->domain->arch.vmx_platform.vmx_vioapic);
    uint32_t    result = 0;

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "vmx_vioapic_read addr %lx\n", addr);

    ASSERT(s);

    addr &= 0xff;

    switch (addr) {
    case IOAPIC_REG_SELECT:
        result = s->ioregsel;
        break;

    case IOAPIC_REG_WINDOW:
        result = vmx_vioapic_read_indirect(s, addr, length);
        break;

    default:
          break;
    }

    return result;
}

static void vmx_vioapic_update_imr(struct vmx_vioapic *s, int index)
{
   if (s->redirtbl[index].RedirForm.mask)
       set_bit(index, &s->imr);
   else
       clear_bit(index, &s->imr);
}

static void vmx_vioapic_write_indirect(struct vmx_vioapic *s,
                                      unsigned long addr,
                                      unsigned long length,
                                      unsigned long val)
{
    switch (s->ioregsel) {
    case IOAPIC_REG_VERSION:
        printk("vmx_vioapic_write_indirect: version register read only\n");
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

            VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "vmx_vioapic_write_indirect "
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
                vmx_vioapic_update_imr(s, redir_index);
            } else  {
                printk("vmx_vioapic_write_indirect "
                  "error register %x\n", s->ioregsel);
            }
            break;
        }
    } /* switch */
}

static void vmx_vioapic_write(struct vcpu *v,
                             unsigned long addr,
                             unsigned long length,
                             unsigned long val)
{
    vmx_vioapic_t *s = &(v->domain->arch.vmx_platform.vmx_vioapic);

    ASSERT(s);

    addr &= 0xff;

    switch (addr) {
    case IOAPIC_REG_SELECT:
        s->ioregsel = val;
        break;

    case IOAPIC_REG_WINDOW:
        vmx_vioapic_write_indirect(s, addr, length, val);
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

static int vmx_vioapic_range(struct vcpu *v, unsigned long addr)
{
    vmx_vioapic_t *s = &(v->domain->arch.vmx_platform.vmx_vioapic);

    if ((s->flags & IOAPIC_ENABLE_FLAG) &&
        (addr >= s->base_address &&
        (addr <= s->base_address + IOAPIC_MEM_LENGTH)))
        return 1;
    else
        return 0;
}

struct vmx_mmio_handler vioapic_mmio_handler = {
    .check_handler = vmx_vioapic_range,
    .read_handler = vmx_vioapic_read,
    .write_handler = vmx_vioapic_write
};

static void vmx_vioapic_reset(vmx_vioapic_t *s)
{
    int i;

    memset(s, 0, sizeof(vmx_vioapic_t));

    for (i = 0; i < IOAPIC_NUM_PINS; i++) {
        s->redirtbl[i].RedirForm.mask = 0x1;
        vmx_vioapic_update_imr(s, i);
    }
}

static void ioapic_update_config(vmx_vioapic_t *s,
                                 unsigned long address,
                                 uint8_t enable)
{
    ASSERT(s);

    ioapic_enable(s, enable);

    if (address != s->base_address)
        s->base_address = address;
}

static int ioapic_inj_irq(vmx_vioapic_t *s,
                          struct vlapic * target,
                          uint8_t vector,
                          uint8_t trig_mode,
                          uint8_t delivery_mode)
{
    int result = 0;

    ASSERT(s && target);

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_inj_irq "
      "irq %d trig %d delive mode %d\n",
      vector, trig_mode, delivery_mode);

    switch (delivery_mode) {
    case VLAPIC_DELIV_MODE_FIXED:
    case VLAPIC_DELIV_MODE_LPRI:
        if (test_and_set_bit(vector, &VLAPIC_IRR(target)) && trig_mode == 1) {
            /* the level interrupt should not happen before it is cleard */
            printk("<ioapic_inj_irq> level interrupt happen before cleard\n");
        }
#ifndef __ia64__
        if (trig_mode)
            test_and_set_bit(vector, &target->tmr[0]);
#endif
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
static int ioapic_match_logical_addr(vmx_vioapic_t *s, int number, uint8_t dest)
{
    int result = 0;

    ASSERT(s && s->lapic_info[number]);

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_match_logical_addr "
      "number %i dest %x\n",
      number, dest);

    switch (((s->lapic_info[number]->dest_format >> 28) & 0xf)) {
    case 0xf:
        result =
          (dest & ((s->lapic_info[number]->logical_dest >> 24) & 0xff)) != 0;
        break;
    case 0x0:
        /* Should we support flat cluster mode ?*/
        if ( ((s->lapic_info[number]->logical_dest >> 28)
               == ((dest >> 0x4) & 0xf)) &&
             (((s->lapic_info[number]->logical_dest >> 24) & 0xf)
               & (dest  & 0xf)) )
            result = 1;
        break;
    default:
        printk("error DFR value for %x local apic\n", number);
        break;
    }

    return result;
}
#else
extern int ioapic_match_logical_addr(vmx_vioapic_t *s, int number, uint8_t dest);
#endif

static uint32_t ioapic_get_delivery_bitmask(vmx_vioapic_t *s,
                                            uint16_t dest,
                                            uint8_t dest_mode,
                                            uint8_t vector,
                                            uint8_t delivery_mode)
{
    uint32_t mask = 0;
    int i;

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask "
      "dest %d dest_mode %d "
      "vector %d del_mode %d, lapic_count %d\n",
      dest, dest_mode, vector, delivery_mode, s->lapic_count);

    ASSERT(s);

    if (dest_mode == 0) { /* Physical mode */
        for (i = 0; i < s->lapic_count; i++) {
            if (VLAPIC_ID(s->lapic_info[i]) == dest) {
                mask = 1 << i;
                break;
            }
        }
    } else {
        /* logical destination. call match_logical_addr for each APIC. */
        if (dest != 0) {
            for (i=0; i< s->lapic_count; i++) {
                if ( s->lapic_info[i] &&
                     ioapic_match_logical_addr(s, i, dest) ) {
                    mask |= (1<<i);
                }
            }
        }
    }

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_get_delivery_bitmask "
      "mask %x\n", mask);

    return mask;
}

static void ioapic_deliver(vmx_vioapic_t *s, int irqno)
{
    uint16_t dest = s->redirtbl[irqno].RedirForm.dest_id;
    uint8_t dest_mode = s->redirtbl[irqno].RedirForm.destmode;
    uint8_t delivery_mode = s->redirtbl[irqno].RedirForm.deliver_mode;
    uint8_t vector = s->redirtbl[irqno].RedirForm.vector;
    uint8_t trig_mode = s->redirtbl[irqno].RedirForm.trigmod;
    uint32_t deliver_bitmask;

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "IOAPIC deliver: "
      "dest %x dest_mode %x delivery_mode %x vector %x trig_mode %x\n",
      dest, dest_mode, delivery_mode, vector, trig_mode);

    deliver_bitmask =
      ioapic_get_delivery_bitmask(s, dest, dest_mode, vector, delivery_mode);

    if (!deliver_bitmask) {
        VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic deliver "
          "no target on destination\n");

        return;
    }

    switch (delivery_mode) {
    case VLAPIC_DELIV_MODE_LPRI:
    {
        struct vlapic* target;

        target = apic_round_robin(
                s->domain, dest_mode, vector, deliver_bitmask);
        if (target)
            ioapic_inj_irq(s, target, vector, trig_mode, delivery_mode);
        else{
            VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic deliver "
              "null round robin mask %x vector %x delivery_mode %x\n",
              deliver_bitmask, vector, deliver_bitmask);
        }
        break;
    }

    case VLAPIC_DELIV_MODE_FIXED:
    case VLAPIC_DELIV_MODE_EXT:
    {
        uint8_t bit;
        for (bit = 0; bit < s->lapic_count; bit++) {
            if (deliver_bitmask & (1 << bit)) {
                if (s->lapic_info[bit]) {
                    ioapic_inj_irq(s, s->lapic_info[bit],
                                vector, trig_mode, delivery_mode);
                }
            }
        }
        break;
    }

    case VLAPIC_DELIV_MODE_SMI:
    case VLAPIC_DELIV_MODE_NMI:
    case VLAPIC_DELIV_MODE_INIT:
    case VLAPIC_DELIV_MODE_STARTUP:
    default:
        printk("Not support delivey mode %d\n", delivery_mode);
        break;
    }
}

static int ioapic_get_highest_irq(vmx_vioapic_t *s)
{
    uint32_t irqs;

    ASSERT(s);

    irqs = s->irr & ~s->isr & ~s->imr;
    return __fls(irqs);
}


static void service_ioapic(vmx_vioapic_t *s)
{
    int irqno;

    while ((irqno = ioapic_get_highest_irq(s)) != -1) {

        VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "service_ioapic "
          "highest irqno %x\n", irqno);

        if (!test_bit(irqno, &s->imr)) {
            ioapic_deliver(s, irqno);
        }

        if (s->redirtbl[irqno].RedirForm.trigmod == IOAPIC_LEVEL_TRIGGER) {
            s->isr |= (1 << irqno);
        }

        s->irr &= ~(1 << irqno);
    }
}

void vmx_vioapic_do_irqs(struct domain *d, uint16_t irqs)
{
    vmx_vioapic_t *s = &(d->arch.vmx_platform.vmx_vioapic);

    if (!vmx_apic_support(d))
        return;

    s->irr |= irqs & ~s->imr;
    service_ioapic(s);
}

void vmx_vioapic_do_irqs_clear(struct domain *d, uint16_t irqs)
{
    vmx_vioapic_t *s = &(d->arch.vmx_platform.vmx_vioapic);

    if (!vmx_apic_support(d))
        return;

    s->irr &= ~irqs;
    service_ioapic(s);
}

void vmx_vioapic_set_irq(struct domain *d, int irq, int level)
{
    vmx_vioapic_t *s = &(d->arch.vmx_platform.vmx_vioapic);

    if (!vmx_apic_support(d))
        return ;

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "ioapic_set_irq "
      "irq %x level %x\n", irq, level);

    if (irq < 0 || irq >= IOAPIC_NUM_PINS) {
        printk("ioapic_set_irq irq %x is illegal\n", irq);
        domain_crash_synchronous();
    }

    if (!IOAPICEnabled(s) || s->redirtbl[irq].RedirForm.mask)
        return;

    ioapic_dump_redir(s, irq);

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
static int get_redir_num(vmx_vioapic_t *s, int vector)
{
    int i = 0;

    ASSERT(s);

    for(i = 0; i < IOAPIC_NUM_PINS - 1; i++) {
        if (s->redirtbl[i].RedirForm.vector == vector)
            return i;
    }

    return -1;
}

void ioapic_update_EOI(struct domain *d, int vector)
{
    vmx_vioapic_t *s = &(d->arch.vmx_platform.vmx_vioapic);
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

int vmx_vioapic_add_lapic(struct vlapic *vlapic, struct vcpu *v)
{
    vmx_vioapic_t *s = &(v->domain->arch.vmx_platform.vmx_vioapic);

    if (v->vcpu_id != s->lapic_count) {
        printk("vmx_vioapic_add_lapic "
           "cpu_id not match vcpu_id %x lapic_count %x\n",
           v->vcpu_id, s->lapic_count);
        domain_crash_synchronous();
    }

    /* update count later for race condition on interrupt */
    s->lapic_info[s->lapic_count] = vlapic;
    s->lapic_count ++;

    return s->lapic_count;
}

vmx_vioapic_t * vmx_vioapic_init(struct domain *d)
{
    int i = 0;
    vmx_vioapic_t *s = &(d->arch.vmx_platform.vmx_vioapic);

    VMX_DBG_LOG(DBG_LEVEL_IOAPIC, "vmx_vioapic_init\n");

    vmx_vioapic_reset(s);

    s->domain = d;

    for (i = 0; i < MAX_LAPIC_NUM; i++)
        s->lapic_info[i] = NULL;

    /* Remove after GFW ready */
    ioapic_update_config(s, IOAPIC_DEFAULT_BASE_ADDRESS, 1);

    return s;
}
