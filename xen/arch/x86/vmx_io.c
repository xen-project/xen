/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
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
#include <asm/vmx_platform.h>
#include <asm/vmx_virpit.h>

#ifdef CONFIG_VMX

extern long do_block();
  
#if defined (__i386__)
static void load_xen_regs(struct xen_regs *regs)
{ 
    /*
     * Write the guest register value into VMCS
     */
    __vmwrite(GUEST_SS_SELECTOR, regs->ss);
    __vmwrite(GUEST_ESP, regs->esp);
    __vmwrite(GUEST_EFLAGS, regs->eflags);
    __vmwrite(GUEST_CS_SELECTOR, regs->cs);
    __vmwrite(GUEST_EIP, regs->eip);
}

static void set_reg_value (int size, int index, int seg, struct xen_regs *regs, long value)
{
    switch (size) {
    case BYTE:
        switch (index) {
        case 0:
            regs->eax &= 0xFFFFFF00;
            regs->eax |= (value & 0xFF);
            break;
        case 1:
            regs->ecx &= 0xFFFFFF00;
            regs->ecx |= (value & 0xFF);
            break;
        case 2:
            regs->edx &= 0xFFFFFF00;
            regs->edx |= (value & 0xFF);
            break;
        case 3:
            regs->ebx &= 0xFFFFFF00;
            regs->ebx |= (value & 0xFF);
            break;
        case 4:
            regs->eax &= 0xFFFF00FF;
            regs->eax |= ((value & 0xFF) << 8);
            break;
        case 5:
            regs->ecx &= 0xFFFF00FF;
            regs->ecx |= ((value & 0xFF) << 8);
            break;
        case 6:
            regs->edx &= 0xFFFF00FF;
            regs->edx |= ((value & 0xFF) << 8);
            break;
        case 7:
            regs->ebx &= 0xFFFF00FF;
            regs->ebx |= ((value & 0xFF) << 8);
            break;
        default:
            printk("size:%x, index:%x are invalid!\n", size, index);
            break;

        }
        break;
    case WORD:
        switch (index) {
        case 0:
            regs->eax &= 0xFFFF0000;
            regs->eax |= (value & 0xFFFF);
            break;
        case 1:
            regs->ecx &= 0xFFFF0000;
            regs->ecx |= (value & 0xFFFF);
            break;
        case 2:
            regs->edx &= 0xFFFF0000;
            regs->edx |= (value & 0xFFFF);
            break;
        case 3:
            regs->ebx &= 0xFFFF0000;
            regs->ebx |= (value & 0xFFFF);
            break;
        case 4:
            regs->esp &= 0xFFFF0000;
            regs->esp |= (value & 0xFFFF);
            break;

        case 5:
            regs->ebp &= 0xFFFF0000;
            regs->ebp |= (value & 0xFFFF);
            break;
        case 6:
            regs->esi &= 0xFFFF0000;
            regs->esi |= (value & 0xFFFF);
            break;
        case 7:
            regs->edi &= 0xFFFF0000;
            regs->edi |= (value & 0xFFFF);
            break;
        default:
            printk("size:%x, index:%x are invalid!\n", size, index);
            break;
        }
        break;
    case LONG:
        switch (index) {
        case 0:
            regs->eax = value;
            break;
        case 1:
            regs->ecx = value;
            break;
        case 2:
            regs->edx = value;
            break;
        case 3:
            regs->ebx = value;
            break;
        case 4:
            regs->esp = value;
            break;
        case 5:
            regs->ebp = value;
            break;
        case 6:
            regs->esi = value;
            break;
        case 7:
            regs->edi = value;
            break;
        default:
            printk("size:%x, index:%x are invalid!\n", size, index);
            break;
        }
        break;
    default:
        printk("size:%x, index:%x are invalid!\n", size, index);
        break;
    }
}
#endif

void vmx_io_assist(struct exec_domain *ed) 
{
    vcpu_iodata_t *vio;
    ioreq_t *p;
    struct domain *d = ed->domain;
    execution_context_t *ec = get_execution_context();
    unsigned long old_eax;
    int sign;
    struct mi_per_cpu_info *mpci_p;
    struct xen_regs *inst_decoder_regs;

    mpci_p = &ed->arch.arch_vmx.vmx_platform.mpci;
    inst_decoder_regs = mpci_p->inst_decoder_regs;

    /* clear the pending event */
    ed->vcpu_info->evtchn_upcall_pending = 0;
    /* clear the pending bit for port 2 */
    clear_bit(IOPACKET_PORT>>5, &ed->vcpu_info->evtchn_pending_sel);
    clear_bit(IOPACKET_PORT, &d->shared_info->evtchn_pending[0]);

    vio = (vcpu_iodata_t *) ed->arch.arch_vmx.vmx_platform.shared_page_va;
    if (vio == 0) {
        VMX_DBG_LOG(DBG_LEVEL_1, 
                    "bad shared page: %lx\n", (unsigned long) vio);
        domain_crash();
    }
    p = &vio->vp_ioreq;

    if (p->state == STATE_IORESP_HOOK){
        vmx_hooks_assist(ed);
    }

    /* clear IO wait VMX flag */
    if (test_bit(ARCH_VMX_IO_WAIT, &ed->arch.arch_vmx.flags)) {
        if (p->state != STATE_IORESP_READY) {
            printk("got a false I/O reponse\n");
            do_block();
        } else {
            p->state = STATE_INVALID;
        }
        clear_bit(ARCH_VMX_IO_WAIT, &ed->arch.arch_vmx.flags);
    } else {
        return;
    }

    sign = (p->df) ? -1 : 1;
    if (p->port_mm) {
        if (p->pdata_valid) {
            ec->esi += sign * p->count * p->size;
            ec->edi += sign * p->count * p->size;
        } else {
            if (p->dir == IOREQ_WRITE) {
                return;
            }
            int size = -1, index = -1;

            size = operand_size(ed->arch.arch_vmx.vmx_platform.mpci.mmio_target);
            index = operand_index(ed->arch.arch_vmx.vmx_platform.mpci.mmio_target);

            if (ed->arch.arch_vmx.vmx_platform.mpci.mmio_target & WZEROEXTEND) {
                p->u.data = p->u.data & 0xffff;
            }        
            set_reg_value(size, index, 0, (struct xen_regs *)ec, p->u.data);

        }
        load_xen_regs((struct xen_regs *)ec);
        return;
    }

    if (p->dir == IOREQ_WRITE) {
        if (p->pdata_valid) {
            ec->esi += sign * p->count * p->size;
            ec->ecx -= p->count;
        }
        return;
    } else {
        if (p->pdata_valid) {
            ec->edi += sign * p->count * p->size;
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

    vio = (vcpu_iodata_t *) d->arch.arch_vmx.vmx_platform.shared_page_va;
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

    vio = (vcpu_iodata_t *) d->arch.arch_vmx.vmx_platform.shared_page_va;
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
    struct vmx_virpit_t *vpit = &(d->arch.arch_vmx.vmx_platform.vmx_pit);

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
        
    if (vpit->pending_intr_nr && highest_vector == vpit->vector)
        vpit->pending_intr_nr--;
    else
        clear_highest_bit(d, highest_vector); 

    intr_fields = (INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR | highest_vector);
    __vmwrite(VM_ENTRY_INTR_INFO_FIELD, intr_fields);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);

    if (highest_vector == vpit->vector)
        vpit->inject_point = NOW();

    return;
}

void vmx_do_resume(struct exec_domain *d) 
{
    __vmwrite(HOST_CR3, pagetable_val(d->arch.monitor_table));
    __vmwrite(GUEST_CR3, pagetable_val(d->arch.shadow_table));
    __vmwrite(HOST_ESP, (unsigned long) get_stack_top());

    if (event_pending(d)) {
        if (test_bit(IOPACKET_PORT, &d->domain->shared_info->evtchn_pending[0])) 
            vmx_io_assist(d);

        else if (test_bit(ARCH_VMX_IO_WAIT, &d->arch.arch_vmx.flags)) {
            printk("got an event while blocked on I/O\n");
            do_block();
        }
                
        /* Assumption: device model will not inject an interrupt
         * while an ioreq_t is pending i.e. the response and 
         * interrupt can come together. But an interrupt without 
         * a response to ioreq_t is not ok.
         */
    }
    if (!test_bit(ARCH_VMX_IO_WAIT, &d->arch.arch_vmx.flags))
        vmx_intr_assist(d);
}

#endif /* CONFIG_VMX */
