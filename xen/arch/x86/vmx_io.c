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
#include <xen/trace.h>

#include <asm/current.h>
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
#if defined (__i386__)
static void load_cpu_user_regs(struct cpu_user_regs *regs)
{ 
    /*
     * Write the guest register value into VMCS
     */
    __vmwrite(GUEST_SS_SELECTOR, regs->ss);
    __vmwrite(GUEST_RSP, regs->esp);
    __vmwrite(GUEST_RFLAGS, regs->eflags);
    __vmwrite(GUEST_CS_SELECTOR, regs->cs);
    __vmwrite(GUEST_RIP, regs->eip);
}

static void set_reg_value (int size, int index, int seg, struct cpu_user_regs *regs, long value)
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
#else
static void load_cpu_user_regs(struct cpu_user_regs *regs)
{ 
	/* XXX: TBD */
	return;
}
static void set_reg_value (int size, int index, int seg, struct cpu_user_regs *regs, long value)
{
	/* XXX: TBD */
	return;
}
#endif

void vmx_io_assist(struct vcpu *v) 
{
    vcpu_iodata_t *vio;
    ioreq_t *p;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    unsigned long old_eax;
    int sign;
    struct mi_per_cpu_info *mpci_p;
    struct cpu_user_regs *inst_decoder_regs;

    mpci_p = &v->arch.arch_vmx.vmx_platform.mpci;
    inst_decoder_regs = mpci_p->inst_decoder_regs;

    vio = (vcpu_iodata_t *) v->arch.arch_vmx.vmx_platform.shared_page_va;
    if (vio == 0) {
        VMX_DBG_LOG(DBG_LEVEL_1, 
                    "bad shared page: %lx", (unsigned long) vio);
        domain_crash_synchronous();
    }
    p = &vio->vp_ioreq;

    if (p->state == STATE_IORESP_HOOK){
        vmx_hooks_assist(v);
    }

    /* clear IO wait VMX flag */
    if (test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags)) {
        if (p->state != STATE_IORESP_READY) {
                /* An interrupt send event raced us */
                return;
        } else {
            p->state = STATE_INVALID;
        }
        clear_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags);
    } else {
        return;
    }

    sign = (p->df) ? -1 : 1;
    if (p->port_mm) {
        if (p->pdata_valid) {
            regs->esi += sign * p->count * p->size;
            regs->edi += sign * p->count * p->size;
        } else {
            if (p->dir == IOREQ_WRITE) {
                return;
            }
            int size = -1, index = -1;

            size = operand_size(v->arch.arch_vmx.vmx_platform.mpci.mmio_target);
            index = operand_index(v->arch.arch_vmx.vmx_platform.mpci.mmio_target);

            if (v->arch.arch_vmx.vmx_platform.mpci.mmio_target & WZEROEXTEND) {
                p->u.data = p->u.data & 0xffff;
            }        
            set_reg_value(size, index, 0, regs, p->u.data);

        }
        load_cpu_user_regs(regs);
        return;
    }

    if (p->dir == IOREQ_WRITE) {
        if (p->pdata_valid) {
            regs->esi += sign * p->count * p->size;
            regs->ecx -= p->count;
        }
        return;
    } else {
        if (p->pdata_valid) {
            regs->edi += sign * p->count * p->size;
            regs->ecx -= p->count;
            return;
        }
    }

    old_eax = regs->eax;

    switch(p->size) {
    case 1:
        regs->eax = (old_eax & 0xffffff00) | (p->u.data & 0xff);
        break;
    case 2:
        regs->eax = (old_eax & 0xffff0000) | (p->u.data & 0xffff);
        break;
    case 4:
        regs->eax = (p->u.data & 0xffffffff);
        break;
    default:
        BUG();
    }
}

int vmx_clear_pending_io_event(struct vcpu *v) 
{
    struct domain *d = v->domain;

    /* evtchn_pending is shared by other event channels in 0-31 range */
    if (!d->shared_info->evtchn_pending[IOPACKET_PORT>>5])
        clear_bit(IOPACKET_PORT>>5, &v->vcpu_info->evtchn_pending_sel);

    /* Note: VMX domains may need upcalls as well */
    if (!v->vcpu_info->evtchn_pending_sel) 
        clear_bit(0, &v->vcpu_info->evtchn_upcall_pending);

    /* clear the pending bit for IOPACKET_PORT */
    return test_and_clear_bit(IOPACKET_PORT, 
                              &d->shared_info->evtchn_pending[0]);
}

/* Because we've cleared the pending events first, we need to guarantee that
 * all events to be handled by xen for VMX domains are taken care of here.
 *
 * interrupts are guaranteed to be checked before resuming guest. 
 * VMX upcalls have been already arranged for if necessary. 
 */
void vmx_check_events(struct vcpu *d) 
{
    /* clear the event *before* checking for work. This should avoid 
       the set-and-check races */
    if (vmx_clear_pending_io_event(current))
        vmx_io_assist(d);
}

/* On exit from vmx_wait_io, we're guaranteed to have a I/O response from 
   the device model */
void vmx_wait_io()
{
    extern void do_block();

    do {
        if(!test_bit(IOPACKET_PORT, 
            &current->domain->shared_info->evtchn_pending[0]))
            do_block();
        vmx_check_events(current);
        if (!test_bit(ARCH_VMX_IO_WAIT, &current->arch.arch_vmx.flags))
            break;
        /* Events other than IOPACKET_PORT might have woken us up. In that
           case, safely go back to sleep. */
        clear_bit(IOPACKET_PORT>>5, &current->vcpu_info->evtchn_pending_sel);
        clear_bit(0, &current->vcpu_info->evtchn_upcall_pending);
    } while(1);
}

#if defined(__i386__) || defined(__x86_64__)
static inline int __fls(u32 word)
{
    int bit;

    __asm__("bsrl %1,%0"
            :"=r" (bit)
            :"rm" (word));
    return word ? bit : -1;
}
#else
#define __fls(x) 	generic_fls(x)
static __inline__ int generic_fls(u32 x)
{
    int r = 31;

    if (!x)
        return -1;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}
#endif

/* Simple minded Local APIC priority implementation. Fix later */
static __inline__ int find_highest_irq(u32 *pintr)
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
static inline int find_highest_pending_irq(struct vcpu *d)
{
    vcpu_iodata_t *vio;

    vio = (vcpu_iodata_t *) d->arch.arch_vmx.vmx_platform.shared_page_va;
    if (vio == 0) {
        VMX_DBG_LOG(DBG_LEVEL_1, 
                    "bad shared page: %lx", (unsigned long) vio);
        domain_crash_synchronous();
    }
        
    return find_highest_irq((unsigned int *)&vio->vp_intr[0]);
}

static inline void clear_highest_bit(struct vcpu *d, int vector)
{
    vcpu_iodata_t *vio;

    vio = (vcpu_iodata_t *) d->arch.arch_vmx.vmx_platform.shared_page_va;
    if (vio == 0) {
        VMX_DBG_LOG(DBG_LEVEL_1, 
                    "bad shared page: %lx", (unsigned long) vio);
        domain_crash_synchronous();
    }
        
    clear_bit(vector, &vio->vp_intr[0]);
}

static inline int irq_masked(unsigned long eflags)
{
    return ((eflags & X86_EFLAGS_IF) == 0);
}

void vmx_intr_assist(struct vcpu *d) 
{
    int highest_vector = find_highest_pending_irq(d);
    unsigned long intr_fields, eflags;
    struct vmx_virpit_t *vpit = &(d->arch.arch_vmx.vmx_platform.vmx_pit);

    if (highest_vector == -1)
        return;

    __vmread(VM_ENTRY_INTR_INFO_FIELD, &intr_fields);
    if (intr_fields & INTR_INFO_VALID_MASK) {
        VMX_DBG_LOG(DBG_LEVEL_1, "vmx_intr_assist: intr_fields: %lx",
                    intr_fields);
        return;
    }

    __vmread(GUEST_RFLAGS, &eflags);
    if (irq_masked(eflags)) {
        VMX_DBG_LOG(DBG_LEVEL_1, "guesting pending: %x, eflags: %lx",
                    highest_vector, eflags);
        return;
    }
        
    if (vpit->pending_intr_nr && highest_vector == vpit->vector)
        vpit->pending_intr_nr--;
    else
        clear_highest_bit(d, highest_vector); 

    /* close the window between guest PIT initialization and sti */
    if (highest_vector == vpit->vector && !vpit->first_injected){
        vpit->first_injected = 1;
        vpit->pending_intr_nr = 0;
    }

    intr_fields = (INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR | highest_vector);
    __vmwrite(VM_ENTRY_INTR_INFO_FIELD, intr_fields);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);

    TRACE_3D(TRC_VMX_INT, d->domain->domain_id, highest_vector, 0);
    if (highest_vector == vpit->vector)
        vpit->inject_point = NOW();

    return;
}

void vmx_do_resume(struct vcpu *d) 
{
    vmx_stts();
    if ( vmx_paging_enabled(d) )
        __vmwrite(GUEST_CR3, pagetable_get_paddr(d->arch.shadow_table));
    else
        // paging is not enabled in the guest
        __vmwrite(GUEST_CR3, pagetable_get_paddr(d->domain->arch.phys_table));

    __vmwrite(HOST_CR3, pagetable_get_paddr(d->arch.monitor_table));
    __vmwrite(HOST_RSP, (unsigned long)get_stack_bottom());

    if (event_pending(d)) {
        vmx_check_events(d);

        if (test_bit(ARCH_VMX_IO_WAIT, &d->arch.arch_vmx.flags))
            vmx_wait_io();
    }

    /* We can't resume the guest if we're waiting on I/O */
    ASSERT(!test_bit(ARCH_VMX_IO_WAIT, &d->arch.arch_vmx.flags));

    /* We always check for interrupts before resuming guest */
    vmx_intr_assist(d);
}

#endif /* CONFIG_VMX */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
