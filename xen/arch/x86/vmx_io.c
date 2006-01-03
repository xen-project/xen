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
#include <xen/event.h>

#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/vmx.h>
#include <asm/vmx_vmcs.h>
#include <asm/vmx_platform.h>
#include <asm/vmx_vpit.h>
#include <asm/apic.h>
#include <asm/shadow.h>
#include <asm/vmx_vpic.h>
#include <asm/vmx_vlapic.h>
#include <public/hvm/ioreq.h>

#ifdef CONFIG_VMX
#if defined (__i386__)
void load_cpu_user_regs(struct cpu_user_regs *regs)
{
    /*
     * Write the guest register value into VMCS
     */
    __vmwrite(GUEST_SS_SELECTOR, regs->ss);
    __vmwrite(GUEST_RSP, regs->esp);

    __vmwrite(GUEST_RFLAGS, regs->eflags);
    if (regs->eflags & EF_TF)
        __vm_set_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);
    else
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);

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
            printk("Error: size:%x, index:%x are invalid!\n", size, index);
            domain_crash_synchronous();
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
            printk("Error: size:%x, index:%x are invalid!\n", size, index);
            domain_crash_synchronous();
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
            printk("Error: size:%x, index:%x are invalid!\n", size, index);
            domain_crash_synchronous();
            break;
        }
        break;
    default:
        printk("Error: size:%x, index:%x are invalid!\n", size, index);
        domain_crash_synchronous();
        break;
    }
}
#else
void load_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmwrite(GUEST_SS_SELECTOR, regs->ss);
    __vmwrite(GUEST_RSP, regs->rsp);

    __vmwrite(GUEST_RFLAGS, regs->rflags);
    if (regs->rflags & EF_TF)
        __vm_set_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);
    else
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);

    __vmwrite(GUEST_CS_SELECTOR, regs->cs);
    __vmwrite(GUEST_RIP, regs->rip);
}

static inline void __set_reg_value(unsigned long *reg, int size, long value)
{
    switch (size) {
    case BYTE_64:
        *reg &= ~0xFF;
        *reg |= (value & 0xFF);
        break;
    case WORD:
        *reg &= ~0xFFFF;
        *reg |= (value & 0xFFFF);
        break;
    case LONG:
        *reg &= ~0xFFFFFFFF;
        *reg |= (value & 0xFFFFFFFF);
        break;
    case QUAD:
        *reg = value;
        break;
    default:
        printk("Error: <__set_reg_value>: size:%x is invalid\n", size);
        domain_crash_synchronous();
    }
}

static void set_reg_value (int size, int index, int seg, struct cpu_user_regs *regs, long value)
{
    if (size == BYTE) {
        switch (index) {
        case 0:
            regs->rax &= ~0xFF;
            regs->rax |= (value & 0xFF);
            break;
        case 1:
            regs->rcx &= ~0xFF;
            regs->rcx |= (value & 0xFF);
            break;
        case 2:
            regs->rdx &= ~0xFF;
            regs->rdx |= (value & 0xFF);
            break;
        case 3:
            regs->rbx &= ~0xFF;
            regs->rbx |= (value & 0xFF);
            break;
        case 4:
            regs->rax &= 0xFFFFFFFFFFFF00FF;
            regs->rax |= ((value & 0xFF) << 8);
            break;
        case 5:
            regs->rcx &= 0xFFFFFFFFFFFF00FF;
            regs->rcx |= ((value & 0xFF) << 8);
            break;
        case 6:
            regs->rdx &= 0xFFFFFFFFFFFF00FF;
            regs->rdx |= ((value & 0xFF) << 8);
            break;
        case 7:
            regs->rbx &= 0xFFFFFFFFFFFF00FF;
            regs->rbx |= ((value & 0xFF) << 8);
            break;
        default:
            printk("Error: size:%x, index:%x are invalid!\n", size, index);
            domain_crash_synchronous();
            break;
        }
        return;
    }

    switch (index) {
    case 0:
        __set_reg_value(&regs->rax, size, value);
        break;
    case 1:
        __set_reg_value(&regs->rcx, size, value);
        break;
    case 2:
        __set_reg_value(&regs->rdx, size, value);
        break;
    case 3:
        __set_reg_value(&regs->rbx, size, value);
        break;
    case 4:
        __set_reg_value(&regs->rsp, size, value);
        break;
    case 5:
        __set_reg_value(&regs->rbp, size, value);
        break;
    case 6:
        __set_reg_value(&regs->rsi, size, value);
        break;
    case 7:
        __set_reg_value(&regs->rdi, size, value);
        break;
    case 8:
        __set_reg_value(&regs->r8, size, value);
        break;
    case 9:
        __set_reg_value(&regs->r9, size, value);
        break;
    case 10:
        __set_reg_value(&regs->r10, size, value);
        break;
    case 11:
        __set_reg_value(&regs->r11, size, value);
        break;
    case 12:
        __set_reg_value(&regs->r12, size, value);
        break;
    case 13:
        __set_reg_value(&regs->r13, size, value);
        break;
    case 14:
        __set_reg_value(&regs->r14, size, value);
        break;
    case 15:
        __set_reg_value(&regs->r15, size, value);
        break;
    default:
        printk("Error: <set_reg_value> Invalid index\n");
        domain_crash_synchronous();
    }
    return;
}
#endif

extern long get_reg_value(int size, int index, int seg, struct cpu_user_regs *regs);

static inline void set_eflags_CF(int size, unsigned long v1,
                                 unsigned long v2, struct cpu_user_regs *regs)
{
    unsigned long mask = (1 << (8 * size)) - 1;

    if ((v1 & mask) > (v2 & mask))
        regs->eflags |= X86_EFLAGS_CF;
    else
        regs->eflags &= ~X86_EFLAGS_CF;
}

static inline void set_eflags_OF(int size, unsigned long v1,
                                 unsigned long v2, unsigned long v3, struct cpu_user_regs *regs)
{
    if ((v3 ^ v2) & (v3 ^ v1) & (1 << ((8 * size) - 1)))
        regs->eflags |= X86_EFLAGS_OF;
}

static inline void set_eflags_AF(int size, unsigned long v1,
                                 unsigned long v2, unsigned long v3, struct cpu_user_regs *regs)
{
    if ((v1 ^ v2 ^ v3) & 0x10)
        regs->eflags |= X86_EFLAGS_AF;
}

static inline void set_eflags_ZF(int size, unsigned long v1,
                                 struct cpu_user_regs *regs)
{
    unsigned long mask = (1 << (8 * size)) - 1;

    if ((v1 & mask) == 0)
        regs->eflags |= X86_EFLAGS_ZF;
}

static inline void set_eflags_SF(int size, unsigned long v1,
                                 struct cpu_user_regs *regs)
{
    if (v1 & (1 << ((8 * size) - 1)))
        regs->eflags |= X86_EFLAGS_SF;
}

static char parity_table[256] = {
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

static inline void set_eflags_PF(int size, unsigned long v1,
                                 struct cpu_user_regs *regs)
{
    if (parity_table[v1 & 0xFF])
        regs->eflags |= X86_EFLAGS_PF;
}

static void vmx_pio_assist(struct cpu_user_regs *regs, ioreq_t *p,
                           struct mmio_op *mmio_opp)
{
    unsigned long old_eax;
    int sign = p->df ? -1 : 1;

    if (p->dir == IOREQ_WRITE) {
        if (p->pdata_valid) {
            regs->esi += sign * p->count * p->size;
            if (mmio_opp->flags & REPZ)
                regs->ecx -= p->count;
        }
    } else {
        if (mmio_opp->flags & OVERLAP) {
            unsigned long addr;

            regs->edi += sign * p->count * p->size;
            if (mmio_opp->flags & REPZ)
                regs->ecx -= p->count;

            addr = regs->edi;
            if (sign > 0)
                addr -= p->size;
            vmx_copy(&p->u.data, addr, p->size, VMX_COPY_OUT);
        } else if (p->pdata_valid) {
            regs->edi += sign * p->count * p->size;
            if (mmio_opp->flags & REPZ)
                regs->ecx -= p->count;
        } else {
            old_eax = regs->eax;
            switch (p->size) {
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
                printk("Error: %s unknown port size\n", __FUNCTION__);
                domain_crash_synchronous();
            }
        }
    }
}

static void vmx_mmio_assist(struct cpu_user_regs *regs, ioreq_t *p,
                            struct mmio_op *mmio_opp)
{
    int sign = p->df ? -1 : 1;
    int size = -1, index = -1;
    unsigned long value = 0, diff = 0;
    unsigned long src, dst;

    src = mmio_opp->operand[0];
    dst = mmio_opp->operand[1];
    size = operand_size(src);

    switch (mmio_opp->instr) {
    case INSTR_MOV:
        if (dst & REGISTER) {
            index = operand_index(dst);
            set_reg_value(size, index, 0, regs, p->u.data);
        }
        break;

    case INSTR_MOVZX:
        if (dst & REGISTER) {
            switch (size) {
            case BYTE:
                p->u.data &= 0xFFULL;
                break;

            case WORD:
                p->u.data &= 0xFFFFULL;
                break;

            case LONG:
                p->u.data &= 0xFFFFFFFFULL;
                break;

            default:
                printk("Impossible source operand size of movzx instr: %d\n", size);
                domain_crash_synchronous();
            }
            index = operand_index(dst);
            set_reg_value(operand_size(dst), index, 0, regs, p->u.data);
        }
        break;

    case INSTR_MOVSX:
        if (dst & REGISTER) {
            switch (size) {
            case BYTE:
                p->u.data &= 0xFFULL;
                if ( p->u.data & 0x80ULL )
                    p->u.data |= 0xFFFFFFFFFFFFFF00ULL;
                break;

            case WORD:
                p->u.data &= 0xFFFFULL;
                if ( p->u.data & 0x8000ULL )
                    p->u.data |= 0xFFFFFFFFFFFF0000ULL;
                break;

            case LONG:
                p->u.data &= 0xFFFFFFFFULL;
                if ( p->u.data & 0x80000000ULL )
                    p->u.data |= 0xFFFFFFFF00000000ULL;
                break;

            default:
                printk("Impossible source operand size of movsx instr: %d\n", size);
                domain_crash_synchronous();
            }
            index = operand_index(dst);
            set_reg_value(operand_size(dst), index, 0, regs, p->u.data);
        }
        break;

    case INSTR_MOVS:
        sign = p->df ? -1 : 1;
        regs->esi += sign * p->count * p->size;
        regs->edi += sign * p->count * p->size;

        if ((mmio_opp->flags & OVERLAP) && p->dir == IOREQ_READ) {
            unsigned long addr = regs->edi;

            if (sign > 0)
                addr -= p->size;
            vmx_copy(&p->u.data, addr, p->size, VMX_COPY_OUT);
        }

        if (mmio_opp->flags & REPZ)
            regs->ecx -= p->count;
        break;

    case INSTR_STOS:
        sign = p->df ? -1 : 1;
        regs->edi += sign * p->count * p->size;
        if (mmio_opp->flags & REPZ)
            regs->ecx -= p->count;
        break;

    case INSTR_AND:
        if (src & REGISTER) {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->u.data & value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->u.data & value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->u.data & value;
            set_reg_value(size, index, 0, regs, diff);
        }

        /*
         * The OF and CF flags are cleared; the SF, ZF, and PF
         * flags are set according to the result. The state of
         * the AF flag is undefined.
         */
        regs->eflags &= ~(X86_EFLAGS_CF|X86_EFLAGS_PF|
                          X86_EFLAGS_ZF|X86_EFLAGS_SF|X86_EFLAGS_OF);
        set_eflags_ZF(size, diff, regs);
        set_eflags_SF(size, diff, regs);
        set_eflags_PF(size, diff, regs);
        break;

    case INSTR_OR:
        if (src & REGISTER) {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->u.data | value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->u.data | value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->u.data | value;
            set_reg_value(size, index, 0, regs, diff);
        }

        /*
         * The OF and CF flags are cleared; the SF, ZF, and PF
         * flags are set according to the result. The state of
         * the AF flag is undefined.
         */
        regs->eflags &= ~(X86_EFLAGS_CF|X86_EFLAGS_PF|
                          X86_EFLAGS_ZF|X86_EFLAGS_SF|X86_EFLAGS_OF);
        set_eflags_ZF(size, diff, regs);
        set_eflags_SF(size, diff, regs);
        set_eflags_PF(size, diff, regs);
        break;

    case INSTR_XOR:
        if (src & REGISTER) {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->u.data ^ value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->u.data ^ value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->u.data ^ value;
            set_reg_value(size, index, 0, regs, diff);
        }

        /*
         * The OF and CF flags are cleared; the SF, ZF, and PF
         * flags are set according to the result. The state of
         * the AF flag is undefined.
         */
        regs->eflags &= ~(X86_EFLAGS_CF|X86_EFLAGS_PF|
                          X86_EFLAGS_ZF|X86_EFLAGS_SF|X86_EFLAGS_OF);
        set_eflags_ZF(size, diff, regs);
        set_eflags_SF(size, diff, regs);
        set_eflags_PF(size, diff, regs);
        break;

    case INSTR_CMP:
        if (src & REGISTER) {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->u.data - value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->u.data - value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = value - (unsigned long) p->u.data;
        }

        /*
         * The CF, OF, SF, ZF, AF, and PF flags are set according
         * to the result
         */
        regs->eflags &= ~(X86_EFLAGS_CF|X86_EFLAGS_PF|X86_EFLAGS_AF|
                          X86_EFLAGS_ZF|X86_EFLAGS_SF|X86_EFLAGS_OF);
        set_eflags_CF(size, value, (unsigned long) p->u.data, regs);
        set_eflags_OF(size, diff, value, (unsigned long) p->u.data, regs);
        set_eflags_AF(size, diff, value, (unsigned long) p->u.data, regs);
        set_eflags_ZF(size, diff, regs);
        set_eflags_SF(size, diff, regs);
        set_eflags_PF(size, diff, regs);
        break;

    case INSTR_TEST:
        if (src & REGISTER) {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
        }
        diff = (unsigned long) p->u.data & value;

        /*
         * Sets the SF, ZF, and PF status flags. CF and OF are set to 0
         */
        regs->eflags &= ~(X86_EFLAGS_CF|X86_EFLAGS_PF|
                          X86_EFLAGS_ZF|X86_EFLAGS_SF|X86_EFLAGS_OF);
        set_eflags_ZF(size, diff, regs);
        set_eflags_SF(size, diff, regs);
        set_eflags_PF(size, diff, regs);
        break;

    case INSTR_BT:
        index = operand_index(src);
        value = get_reg_value(size, index, 0, regs);

        if (p->u.data & (1 << (value & ((1 << 5) - 1))))
            regs->eflags |= X86_EFLAGS_CF;
        else
            regs->eflags &= ~X86_EFLAGS_CF;

        break;
    }

    load_cpu_user_regs(regs);
}

void vmx_io_assist(struct vcpu *v)
{
    vcpu_iodata_t *vio;
    ioreq_t *p;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct mmio_op *mmio_opp;
    struct cpu_user_regs *inst_decoder_regs;

    mmio_opp = &v->arch.arch_vmx.mmio_op;
    inst_decoder_regs = mmio_opp->inst_decoder_regs;

    vio = get_vio(v->domain, v->vcpu_id);

    if (vio == 0) {
        VMX_DBG_LOG(DBG_LEVEL_1,
                    "bad shared page: %lx", (unsigned long) vio);
        printf("bad shared page: %lx\n", (unsigned long) vio);
        domain_crash_synchronous();
    }

    p = &vio->vp_ioreq;
    if (p->state == STATE_IORESP_HOOK)
        vmx_hooks_assist(v);

    /* clear IO wait VMX flag */
    if (test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags)) {
        if (p->state == STATE_IORESP_READY) {
            p->state = STATE_INVALID;
            clear_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags);

            if (p->type == IOREQ_TYPE_PIO)
                vmx_pio_assist(regs, p, mmio_opp);
            else
                vmx_mmio_assist(regs, p, mmio_opp);
        }
        /* else an interrupt send event raced us */
    }
}

int vmx_clear_pending_io_event(struct vcpu *v)
{
    struct domain *d = v->domain;
    int port = iopacket_port(d);

    /* evtchn_pending_sel bit is shared by other event channels. */
    if (!d->shared_info->evtchn_pending[port/BITS_PER_LONG])
        clear_bit(port/BITS_PER_LONG, &v->vcpu_info->evtchn_pending_sel);

    /* Note: VMX domains may need upcalls as well. */
    if (!v->vcpu_info->evtchn_pending_sel)
        clear_bit(0, &v->vcpu_info->evtchn_upcall_pending);

    /* Clear the pending bit for port. */
    return test_and_clear_bit(port, &d->shared_info->evtchn_pending[0]);
}

/* Because we've cleared the pending events first, we need to guarantee that
 * all events to be handled by xen for VMX domains are taken care of here.
 *
 * interrupts are guaranteed to be checked before resuming guest.
 * VMX upcalls have been already arranged for if necessary.
 */
void vmx_check_events(struct vcpu *v)
{
    /* clear the event *before* checking for work. This should avoid
       the set-and-check races */
    if (vmx_clear_pending_io_event(v))
        vmx_io_assist(v);
}

/* On exit from vmx_wait_io, we're guaranteed to have a I/O response from
   the device model */
void vmx_wait_io()
{
    extern void do_block();
    int port = iopacket_port(current->domain);

    do {
        if (!test_bit(port, &current->domain->shared_info->evtchn_pending[0]))
            do_block();

        vmx_check_events(current);
        if (!test_bit(ARCH_VMX_IO_WAIT, &current->arch.arch_vmx.flags))
            break;
        /* Events other than IOPACKET_PORT might have woken us up. In that
           case, safely go back to sleep. */
        clear_bit(port/BITS_PER_LONG, &current->vcpu_info->evtchn_pending_sel);
        clear_bit(0, &current->vcpu_info->evtchn_upcall_pending);
    } while(1);
}

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

void set_tsc_shift(struct vcpu *v,struct vmx_virpit *vpit)
{
    u64   drift;

    if ( vpit->first_injected )
        drift = vpit->period_cycles * vpit->pending_intr_nr;
    else 
        drift = 0;
    vpit->shift = v->arch.arch_vmx.tsc_offset - drift;
    __vmwrite(TSC_OFFSET, vpit->shift);

#if defined (__i386__)
    __vmwrite(TSC_OFFSET_HIGH, ((vpit->shift)>> 32));
#endif
}

#define BSP_CPU(v)    (!(v->vcpu_id))
static inline void
interrupt_post_injection(struct vcpu * v, int vector, int type)
{
    struct vmx_virpit *vpit = &(v->domain->arch.vmx_platform.vmx_pit);

    if ( is_pit_irq(v, vector, type) ) {
        if ( !vpit->first_injected ) {
            vpit->pending_intr_nr = 0;
            vpit->scheduled = NOW() + vpit->period;
            set_ac_timer(&vpit->pit_timer, vpit->scheduled);
            vpit->first_injected = 1;
        } else {
            vpit->pending_intr_nr--;
        }
        vpit->inject_point = NOW();
        set_tsc_shift (v, vpit);
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

static inline int irq_masked(unsigned long eflags)
{
    return ((eflags & X86_EFLAGS_IF) == 0);
}

void pic_irq_request(int *interrupt_request, int level)
{
    if (level)
        *interrupt_request = 1;
    else
        *interrupt_request = 0;
}

void vmx_pic_assist(struct vcpu *v)
{
    global_iodata_t *spg;
    u16   *virq_line, irqs;
    struct vmx_virpic *pic = &v->domain->arch.vmx_platform.vmx_pic;
    
    spg = &get_sp(v->domain)->sp_global;
    virq_line  = &spg->pic_clear_irr;
    if ( *virq_line ) {
        do {
            irqs = *(volatile u16*)virq_line;
        } while ( (u16)cmpxchg(virq_line,irqs, 0) != irqs );
        do_pic_irqs_clear(pic, irqs);
    }
    virq_line  = &spg->pic_irr;
    if ( *virq_line ) {
        do {
            irqs = *(volatile u16*)virq_line;
        } while ( (u16)cmpxchg(virq_line,irqs, 0) != irqs );
        do_pic_irqs(pic, irqs);
    }

}

int cpu_get_interrupt(struct vcpu *v, int *type)
{
    int intno;
    struct vmx_virpic *s = &v->domain->arch.vmx_platform.vmx_pic;

    if ( (intno = cpu_get_apic_interrupt(v, type)) != -1 ) {
        /* set irq request if a PIC irq is still pending */
        /* XXX: improve that */
        pic_update_irq(s);
        return intno;
    }
    /* read the irq from the PIC */
    if ( (intno = cpu_get_pic_interrupt(v, type)) != -1 )
        return intno;

    return -1;
}

asmlinkage void vmx_intr_assist(void)
{
    int intr_type = 0;
    int highest_vector;
    unsigned long intr_fields, eflags, interruptibility, cpu_exec_control;
    struct vcpu *v = current;
    struct vmx_platform *plat=&v->domain->arch.vmx_platform;
    struct vmx_virpit *vpit = &plat->vmx_pit;
    struct vmx_virpic *pic= &plat->vmx_pic;

    vmx_pic_assist(v);
    __vmread_vcpu(v, CPU_BASED_VM_EXEC_CONTROL, &cpu_exec_control);
    if ( vpit->pending_intr_nr ) {
        pic_set_irq(pic, 0, 0);
        pic_set_irq(pic, 0, 1);
    }

    __vmread(VM_ENTRY_INTR_INFO_FIELD, &intr_fields);

    if (intr_fields & INTR_INFO_VALID_MASK) {
        enable_irq_window(cpu_exec_control);
        VMX_DBG_LOG(DBG_LEVEL_1, "vmx_intr_assist: intr_fields: %lx",
                    intr_fields);
        return;
    }

    __vmread(GUEST_INTERRUPTIBILITY_INFO, &interruptibility);

    if (interruptibility) {
        enable_irq_window(cpu_exec_control);
        VMX_DBG_LOG(DBG_LEVEL_1, "interruptibility: %lx",interruptibility);
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
    struct vmx_virpit *vpit = &(v->domain->arch.vmx_platform.vmx_pit);
    vmx_stts();

    if (event_pending(v)) {
        vmx_check_events(v);

        if (test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags))
            vmx_wait_io();
    }
    /* pick up the elapsed PIT ticks and re-enable pit_timer */
    if ( vpit->first_injected ) {
        pickup_deactive_ticks(vpit);
    }
    set_tsc_shift(v,vpit);

    /* We can't resume the guest if we're waiting on I/O */
    ASSERT(!test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags));
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
