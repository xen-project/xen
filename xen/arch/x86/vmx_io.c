/*
 * vmx_io.c: handling I/O, interrupts related VMX entry/exit 
 * Copyright (c) 2004, Intel Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */
#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>

#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/vmx.h>
#include <asm/vmx_vmcs.h>
#include <xen/event.h>
#include <public/io/ioreq.h>

extern long do_block();

void vmx_io_assist(struct exec_domain *ed) 
{
    vcpu_iodata_t *vio;
    ioreq_t *p;
    struct domain *d = ed->domain;
    execution_context_t *ec = get_execution_context();
    unsigned long old_eax;
    unsigned long eflags;
    int dir;

    /* clear the pending event */
    ed->vcpu_info->evtchn_upcall_pending = 0;
    /* clear the pending bit for port 2 */
    clear_bit(IOPACKET_PORT>>5, &ed->vcpu_info->evtchn_pending_sel);
    clear_bit(IOPACKET_PORT, &d->shared_info->evtchn_pending[0]);

    vio = (vcpu_iodata_t *) ed->thread.arch_vmx.vmx_platform.shared_page_va;
    if (vio == 0) {
        VMX_DBG_LOG(DBG_LEVEL_1, 
                    "bad shared page: %lx\n", (unsigned long) vio);
        domain_crash();
    }
    p = &vio->vp_ioreq;
    /* clear IO wait VMX flag */
    if (test_bit(ARCH_VMX_IO_WAIT, &ed->thread.arch_vmx.flags)) {
        if (p->state != STATE_IORESP_READY) {
            printk("got a false I/O reponse\n");
            do_block();
        } else {
            p->state = STATE_INVALID;
        }
        clear_bit(ARCH_VMX_IO_WAIT, &ed->thread.arch_vmx.flags);
    } else {
        return;
    }

    __vmread(GUEST_EFLAGS, &eflags);
    dir = (eflags & X86_EFLAGS_DF);

    if (p->dir == IOREQ_WRITE) {
        if (p->pdata_valid) {
            if (!dir)
                ec->esi += p->count * p->size;
            else
                ec->esi -= p->count * p->size;
            ec->ecx -= p->count;
        }
        return;
    } else {
        if (p->pdata_valid) {
            if (!dir)
                ec->edi += p->count * p->size;
            else
                ec->edi -= p->count * p->size;
            ec->ecx -= p->count;
            return;
        }
    }

    old_eax = ec->eax;

    switch(p->size) {
    case 1:
        ec->eax = (old_eax & 0xffffff00) | (p->u.data & 0xff);
        break;
    case 2:
        ec->eax = (old_eax & 0xffff0000) | (p->u.data & 0xffff);
        break;
    case 4:
        ec->eax = (p->u.data & 0xffffffff);
        break;
    default:
        BUG();
    }
}

static inline int __fls(unsigned long word)
{
    int bit;

    __asm__("bsrl %1,%0"
            :"=r" (bit)
            :"rm" (word));
    return word ? bit : -1;
}


/* Simple minded Local APIC priority implementation. Fix later */
static __inline__ int find_highest_irq(unsigned long *pintr)
{
    if (pintr[7])
        return __fls(pintr[7]) + (256-32*1);
    if (pintr[6])
        return __fls(pintr[6]) + (256-32*2);
    if (pintr[5])
        return __fls(pintr[5]) + (256-32*3);
    if (pintr[4])
        return __fls(pintr[4]) + (256-32*4);
    if (pintr[3])
        return __fls(pintr[3]) + (256-32*5);
    if (pintr[2])
        return __fls(pintr[2]) + (256-32*6);
    if (pintr[1])
        return __fls(pintr[1]) + (256-32*7);
    return __fls(pintr[0]);
}

/*
 * Return 0-255 for pending irq.
 *        -1 when no pending.
 */
static inline int find_highest_pending_irq(struct exec_domain *d)
{
    vcpu_iodata_t *vio;

    vio = (vcpu_iodata_t *) d->thread.arch_vmx.vmx_platform.shared_page_va;
    if (vio == 0) {
        VMX_DBG_LOG(DBG_LEVEL_1, 
                    "bad shared page: %lx\n", (unsigned long) vio);
        domain_crash();
    }
        
    return find_highest_irq(&vio->vp_intr[0]);
}

static inline void clear_highest_bit(struct exec_domain *d, int vector)
{
    vcpu_iodata_t *vio;

    vio = (vcpu_iodata_t *) d->thread.arch_vmx.vmx_platform.shared_page_va;
    if (vio == 0) {
        VMX_DBG_LOG(DBG_LEVEL_1, 
                    "bad shared page: %lx\n", (unsigned long) vio);
        domain_crash();
    }
        
    clear_bit(vector, &vio->vp_intr[0]);
}

static inline int irq_masked(unsigned long eflags)
{
    return ((eflags & X86_EFLAGS_IF) == 0);
}

void vmx_intr_assist(struct exec_domain *d) 
{
    int highest_vector = find_highest_pending_irq(d);
    unsigned long intr_fields, eflags;

    if (highest_vector == -1)
        return;

    __vmread(VM_ENTRY_INTR_INFO_FIELD, &intr_fields);
    if (intr_fields & INTR_INFO_VALID_MASK) {
        VMX_DBG_LOG(DBG_LEVEL_1, "vmx_intr_assist: intr_fields: %lx\n", 
                    intr_fields);
        return;
    }

    __vmread(GUEST_EFLAGS, &eflags);
    if (irq_masked(eflags)) {
        VMX_DBG_LOG(DBG_LEVEL_1, "guesting pending: %x, eflags: %lx\n", 
                    highest_vector, eflags);
        return;
    }
        
    clear_highest_bit(d, highest_vector); 
    intr_fields = (INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR | highest_vector);
    __vmwrite(VM_ENTRY_INTR_INFO_FIELD, intr_fields);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);

    return;
}

void vmx_do_resume(struct exec_domain *d) 
{
    __vmwrite(HOST_CR3, pagetable_val(d->mm.monitor_table));
    __vmwrite(GUEST_CR3, pagetable_val(d->mm.shadow_table));
    __vmwrite(HOST_ESP, (unsigned long) get_stack_top());

    if (event_pending(d)) {
        if (test_bit(IOPACKET_PORT, &d->domain->shared_info->evtchn_pending[0])) 
            vmx_io_assist(d);

        else if (test_bit(ARCH_VMX_IO_WAIT, &d->thread.arch_vmx.flags)) {
            printk("got an event while blocked on I/O\n");
            do_block();
        }
                
        /* Assumption: device model will not inject an interrupt
         * while an ioreq_t is pending i.e. the response and 
         * interrupt can come together. But an interrupt without 
         * a response to ioreq_t is not ok.
         */
    }
    if (!test_bit(ARCH_VMX_IO_WAIT, &d->thread.arch_vmx.flags))
        vmx_intr_assist(d);
}
