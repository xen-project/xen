/*
 * io.c: handling I/O, interrupts related VMX entry/exit
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
#include <xen/event.h>

#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <public/hvm/ioreq.h>

#define BSP_CPU(v)    (!(v->vcpu_id))

void vmx_set_tsc_shift(struct vcpu *v, struct hvm_virpit *vpit)
{
    u64   drift;

    if ( vpit->first_injected )
        drift = vpit->period_cycles * vpit->pending_intr_nr;
    else 
        drift = 0;
    vpit->shift = v->arch.hvm_vmx.tsc_offset - drift;
    __vmwrite(TSC_OFFSET, vpit->shift);

#if defined (__i386__)
    __vmwrite(TSC_OFFSET_HIGH, ((vpit->shift)>> 32));
#endif
}

static inline void
interrupt_post_injection(struct vcpu * v, int vector, int type)
{
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);

    if ( is_pit_irq(v, vector, type) ) {
        if ( !vpit->first_injected ) {
            vpit->pending_intr_nr = 0;
            vpit->scheduled = NOW() + vpit->period;
            set_timer(&vpit->pit_timer, vpit->scheduled);
            vpit->first_injected = 1;
        } else {
            vpit->pending_intr_nr--;
        }
        vpit->inject_point = NOW();
        vmx_set_tsc_shift (v, vpit);
    }

    switch(type)
    {
    case VLAPIC_DELIV_MODE_EXT:
        break;

    default:
        vlapic_post_injection(v, vector, type);
        break;
    }
}

static inline void
enable_irq_window(unsigned long cpu_exec_control)
{
    if (!(cpu_exec_control & CPU_BASED_VIRTUAL_INTR_PENDING)) {
        cpu_exec_control |= CPU_BASED_VIRTUAL_INTR_PENDING;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL, cpu_exec_control);
    }
}

static inline void
disable_irq_window(unsigned long cpu_exec_control)
{
    if ( cpu_exec_control & CPU_BASED_VIRTUAL_INTR_PENDING ) {
        cpu_exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL, cpu_exec_control);
    }
}

asmlinkage void vmx_intr_assist(void)
{
    int intr_type = 0;
    int highest_vector;
    unsigned long intr_fields, eflags, interruptibility, cpu_exec_control;
    struct vcpu *v = current;
    struct hvm_domain *plat=&v->domain->arch.hvm_domain;
    struct hvm_virpit *vpit = &plat->vpit;
    struct hvm_virpic *pic= &plat->vpic;

    hvm_pic_assist(v);
    __vmread_vcpu(v, CPU_BASED_VM_EXEC_CONTROL, &cpu_exec_control);
    if ( vpit->pending_intr_nr ) {
        pic_set_irq(pic, 0, 0);
        pic_set_irq(pic, 0, 1);
    }

    __vmread(VM_ENTRY_INTR_INFO_FIELD, &intr_fields);

    if (intr_fields & INTR_INFO_VALID_MASK) {
        enable_irq_window(cpu_exec_control);
        HVM_DBG_LOG(DBG_LEVEL_1, "vmx_intr_assist: intr_fields: %lx",
                    intr_fields);
        return;
    }

    __vmread(GUEST_INTERRUPTIBILITY_INFO, &interruptibility);

    if (interruptibility) {
        enable_irq_window(cpu_exec_control);
        HVM_DBG_LOG(DBG_LEVEL_1, "interruptibility: %lx",interruptibility);
        return;
    }

    __vmread(GUEST_RFLAGS, &eflags);
    if (irq_masked(eflags)) {
        enable_irq_window(cpu_exec_control);
        return;
    }

    highest_vector = cpu_get_interrupt(v, &intr_type); 

    if (highest_vector == -1) {
        disable_irq_window(cpu_exec_control);
        return;
    }

    switch (intr_type) {
    case VLAPIC_DELIV_MODE_EXT:
    case VLAPIC_DELIV_MODE_FIXED:
    case VLAPIC_DELIV_MODE_LPRI:
        vmx_inject_extint(v, highest_vector, VMX_INVALID_ERROR_CODE);
        TRACE_3D(TRC_VMX_INT, v->domain->domain_id, highest_vector, 0);
        break;
    case VLAPIC_DELIV_MODE_SMI:
    case VLAPIC_DELIV_MODE_NMI:
    case VLAPIC_DELIV_MODE_INIT:
    case VLAPIC_DELIV_MODE_STARTUP:
    default:
        printk("Unsupported interrupt type\n");
        BUG();
        break;
    }

    interrupt_post_injection(v, highest_vector, intr_type);
    return;
}

void vmx_do_resume(struct vcpu *v)
{
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);

    vmx_stts();

    if ( event_pending(v) ||
         test_bit(ARCH_HVM_IO_WAIT, &v->arch.hvm_vcpu.ioflags) )
        hvm_wait_io();

    /* pick up the elapsed PIT ticks and re-enable pit_timer */
    if ( vpit->first_injected )
        pickup_deactive_ticks(vpit);
    vmx_set_tsc_shift(v, vpit);

    /* We can't resume the guest if we're waiting on I/O */
    ASSERT(!test_bit(ARCH_HVM_IO_WAIT, &v->arch.hvm_vcpu.ioflags));
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
