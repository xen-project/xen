/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/event.h>
#include <xen/irq.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#include <asm/mpic.h>
#include "mpic_init.h"
#include "exceptions.h"

#undef DEBUG
#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
#else
#define DBG(fmt...)
#endif

int vector_irq[NR_VECTORS] __read_mostly = { [0 ... NR_VECTORS - 1] = -1};

unsigned long io_apic_irqs;
int ioapic_ack_new = 1;

static struct hw_interrupt_type *hc_irq;

/* deliver_ee: called with interrupts off when resuming every vcpu */
void deliver_ee(struct cpu_user_regs *regs)
{
    const ulong srr_mask = ~(MSR_IR | MSR_DR | MSR_FE0 | MSR_FE1 | MSR_EE |
                             MSR_RI |
                             MSR_BE | MSR_FP | MSR_PMM | MSR_PR | MSR_SE);

    BUG_ON(mfmsr() & MSR_EE);
    BUG_ON(regs->msr & MSR_HV);

    if (!local_events_need_delivery())
        return;

    /* XXX OS error: EE was set but RI was not. We could trigger a machine
     * check, or kill the domain... for now just crash Xen so we notice. */
    BUG_ON(!(regs->msr & MSR_RI));

    regs->srr0 = regs->pc;
    /* zero SRR1[33:36] and SRR1[42:47] */
    regs->srr1 = regs->msr & ~0x00000000783f0000;
    regs->pc = 0x500;
    regs->msr &= srr_mask;
    regs->msr |= MSR_SF | MSR_ME;

    DBG("<HV: pc=0x%lx, msr=0x%lx\n", regs->pc, regs->msr);
}

void do_external(struct cpu_user_regs *regs)
{
    int vec;
    static unsigned spur_count;

    BUG_ON(!(regs->msr & MSR_EE));
    BUG_ON(mfmsr() & MSR_EE);

    vec = xen_mpic_get_irq(regs);

    if (irq_desc[vec].status & IRQ_PER_CPU) {
        /* x86 do_IRQ does not respect the per cpu flag.  */
        irq_desc_t *desc = &irq_desc[vec];
        regs->entry_vector = vec;
        desc->handler->ack(vec);
        desc->action->handler(vector_to_irq(vec), desc->action->dev_id, regs);
        desc->handler->end(vec);
    } else if (vec != -1) {
        DBG("EE:0x%lx isrc: %d\n", regs->msr, vec);
        regs->entry_vector = vec;
        do_IRQ(regs);

        BUG_ON(mfmsr() & MSR_EE);
        spur_count = 0;
    } else {
        ++spur_count;
        if (spur_count > 100)
            panic("Too many (%d) spurrious interrupts in a row\n"
                  "  Known problem, please halt and let machine idle/cool "
                  "  then reboot\n",
                  100);
    }
}

static int xen_local_irq(unsigned int irq)
{
    irq_desc_t *desc;
    unsigned int vector;

    vector = irq_to_vector(irq);
    desc = &irq_desc[vector];

    return !(desc->status & IRQ_GUEST);
}

static unsigned int xen_startup_irq(unsigned int irq)
{
    DBG("%s(%d)\n", __func__, irq);
    if (xen_local_irq(irq)) {
        return hc_irq->startup(irq);
    }
    return 0;
}

static void xen_shutdown_irq(unsigned int irq)
{
    DBG("%s(%d)\n", __func__, irq);
    if (xen_local_irq(irq)) {
        hc_irq->shutdown(irq);
    }
}

static void xen_enable_irq(unsigned int irq)
{
    DBG("%s(%d)\n", __func__, irq);
    if (xen_local_irq(irq)) {
        hc_irq->enable(irq);
    }
}

static void xen_disable_irq(unsigned int irq)
{
    DBG("%s(%d)\n", __func__, irq);
    if (xen_local_irq(irq)) {
        hc_irq->disable(irq);
    }
}
    
static void xen_ack_irq(unsigned int irq)
{
    DBG("%s(%d)\n", __func__, irq);
    if (xen_local_irq(irq)) {
        if (hc_irq->ack) hc_irq->ack(irq);
    }
}

static void xen_end_irq(unsigned int irq)
{
    DBG("%s(%d)\n", __func__, irq);
    if (xen_local_irq(irq)) {
        hc_irq->end(irq);
    }
}

static void xen_set_affinity(unsigned int irq, cpumask_t mask)
{
    DBG("%s(%d)\n", __func__, irq);
    if (xen_local_irq(irq)) {
        if (hc_irq->set_affinity) hc_irq->set_affinity(irq, mask);
    }
}

static struct hw_interrupt_type xen_irq = {
    .startup = xen_startup_irq,
    .enable = xen_enable_irq,
    .disable = xen_disable_irq,
    .shutdown = xen_shutdown_irq,
    .ack = xen_ack_irq,
    .end = xen_end_irq,
    .set_affinity = xen_set_affinity,
};

void init_IRQ(void)
{
    hc_irq = xen_mpic_init(&xen_irq);
}

void ack_APIC_irq(void)
{
    panic("%s: EOI the whole MPIC?\n", __func__);
}

void ack_bad_irq(unsigned int irq)
{
    printk("unexpected IRQ trap at vector %02x\n", irq);
    /*
     * Currently unexpected vectors happen only on SMP and APIC.
     * We _must_ ack these because every local APIC has only N
     * irq slots per priority level, and a 'hanging, unacked' IRQ
     * holds up an irq slot - in excessive cases (when multiple
     * unexpected vectors occur) that might lock up the APIC
     * completely.
     */
    ack_APIC_irq();
}

extern void dump_ioapic_irq_info(void);
void dump_ioapic_irq_info(void)
{
    printk("%s: can't dump yet\n", __func__);
}

/* irq_vectors is indexed by the sum of all RTEs in all I/O APICs. */
u8 irq_vector[NR_IRQ_VECTORS] __read_mostly = { FIRST_DEVICE_VECTOR , 0 };
int assign_irq_vector(int irq)
{
    static int current_vector = FIRST_DEVICE_VECTOR, offset = 0;

    BUG_ON(irq >= NR_IRQ_VECTORS);
    if (irq != AUTO_ASSIGN && IO_APIC_VECTOR(irq) > 0)
        return IO_APIC_VECTOR(irq);
next:
    current_vector += 8;

    /* Skip the hypercall vector. */
    if (current_vector == HYPERCALL_VECTOR)
        goto next;

    /* Skip the Linux/BSD fast-trap vector. */
    if (current_vector == FAST_TRAP)
        goto next;

    if (current_vector >= FIRST_SYSTEM_VECTOR) {
        offset++;
        if (!(offset%8))
            return -ENOSPC;
        current_vector = FIRST_DEVICE_VECTOR + offset;
    }

    vector_irq[current_vector] = irq;
    if (irq != AUTO_ASSIGN)
        IO_APIC_VECTOR(irq) = current_vector;

    return current_vector;
}

int ioapic_guest_read(unsigned long physbase, unsigned int reg, u32 *pval)
{
    BUG_ON(pval != pval);

    return 0;
}

int ioapic_guest_write(unsigned long physbase, unsigned int reg, u32 val)
{
    BUG_ON(val != val);
    return 0;
}

void send_IPI_mask(cpumask_t mask, int vector)
{
    unsigned int cpus;
    int const bits = 8 * sizeof(cpus);

    switch(vector) {
    case CALL_FUNCTION_VECTOR:
    case EVENT_CHECK_VECTOR:
        break;
    default:
        BUG();
        return;
    }

    BUG_ON(NR_CPUS > bits);
    BUG_ON(fls(mask.bits[0]) > bits);

    cpus = mask.bits[0];
    mpic_send_ipi(vector, cpus);
}
