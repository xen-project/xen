/*
 * io.c: Handling I/O and interrupts.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
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
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/event.h>

#include <xen/hypercall.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>

#include <public/sched.h>
#include <public/hvm/ioreq.h>

#if defined (__i386__)
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
            goto crash;
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
            goto crash;
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
            goto crash;
        }
        break;
    default:
    crash:
        gdprintk(XENLOG_ERR, "size:%x, index:%x are invalid!\n", size, index);
        domain_crash_synchronous();
    }
}
#else
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
        gdprintk(XENLOG_ERR, "size:%x is invalid\n", size);
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
            gdprintk(XENLOG_ERR, "size:%x, index:%x are invalid!\n",
                     size, index);
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
        gdprintk(XENLOG_ERR, "Invalid index\n");
        domain_crash_synchronous();
    }
    return;
}
#endif

extern long get_reg_value(int size, int index, int seg, struct cpu_user_regs *regs);

static inline void set_eflags_CF(int size, unsigned long v1,
                                 unsigned long v2, struct cpu_user_regs *regs)
{
    unsigned long mask;
    
    ASSERT((size <= sizeof(mask)) && (size > 0));

    mask = ~0UL >> (8 * (sizeof(mask) - size));

    if ((v1 & mask) > (v2 & mask))
        regs->eflags |= X86_EFLAGS_CF;
    else
        regs->eflags &= ~X86_EFLAGS_CF;
}

static inline void set_eflags_OF(int size, unsigned long v1,
                                 unsigned long v2, unsigned long v3, struct cpu_user_regs *regs)
{
    unsigned long mask;

    ASSERT((size <= sizeof(mask)) && (size > 0));

    mask = ~0UL >> (8 * (sizeof(mask) - size));
    
    if ((v3 ^ v2) & (v3 ^ v1) & mask)
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
    unsigned long mask;
    
    ASSERT((size <= sizeof(mask)) && (size > 0));

    mask = ~0UL >> (8 * (sizeof(mask) - size));

    if ((v1 & mask) == 0)
        regs->eflags |= X86_EFLAGS_ZF;
}

static inline void set_eflags_SF(int size, unsigned long v1,
                                 struct cpu_user_regs *regs)
{
    unsigned long mask;
    
    ASSERT((size <= sizeof(mask)) && (size > 0));

    mask = ~0UL >> (8 * (sizeof(mask) - size));

    if (v1 & mask)
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

static void hvm_pio_assist(struct cpu_user_regs *regs, ioreq_t *p,
                           struct hvm_io_op *pio_opp)
{
    unsigned long old_eax;
    int sign = p->df ? -1 : 1;

    if ( p->data_is_ptr || (pio_opp->flags & OVERLAP) )
    {
        if ( pio_opp->flags & REPZ )
            regs->ecx -= p->count;

        if ( p->dir == IOREQ_READ )
        {
            if ( pio_opp->flags & OVERLAP )
            {
                unsigned long addr = pio_opp->addr;
                if ( hvm_paging_enabled(current) )
                {
                    int rv = hvm_copy_to_guest_virt(addr, &p->data, p->size);
                    if ( rv != 0 ) 
                    {
                        /* Failed on the page-spanning copy.  Inject PF into
                         * the guest for the address where we failed. */
                        addr += p->size - rv;
                        gdprintk(XENLOG_DEBUG, "Pagefault writing non-io side "
                                 "of a page-spanning PIO: va=%#lx\n", addr);
                        hvm_inject_exception(TRAP_page_fault, 
                                             PFEC_write_access, addr);
                        return;
                    }
                }
                else
                    (void)hvm_copy_to_guest_phys(addr, &p->data, p->size);
            }
            regs->edi += sign * p->count * p->size;
        }
        else /* p->dir == IOREQ_WRITE */
        {
            ASSERT(p->dir == IOREQ_WRITE);
            regs->esi += sign * p->count * p->size;
        }
    }
    else if ( p->dir == IOREQ_READ )
    {
        old_eax = regs->eax;
        switch ( p->size )
        {
        case 1:
            regs->eax = (old_eax & 0xffffff00) | (p->data & 0xff);
            break;
        case 2:
            regs->eax = (old_eax & 0xffff0000) | (p->data & 0xffff);
            break;
        case 4:
            regs->eax = (p->data & 0xffffffff);
            break;
        default:
            printk("Error: %s unknown port size\n", __FUNCTION__);
            domain_crash_synchronous();
        }
    }
}

static void hvm_mmio_assist(struct cpu_user_regs *regs, ioreq_t *p,
                            struct hvm_io_op *mmio_opp)
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
            set_reg_value(size, index, 0, regs, p->data);
        }
        break;

    case INSTR_MOVZX:
        if (dst & REGISTER) {
            switch (size) {
            case BYTE:
                p->data &= 0xFFULL;
                break;

            case WORD:
                p->data &= 0xFFFFULL;
                break;

            case LONG:
                p->data &= 0xFFFFFFFFULL;
                break;

            default:
                printk("Impossible source operand size of movzx instr: %d\n", size);
                domain_crash_synchronous();
            }
            index = operand_index(dst);
            set_reg_value(operand_size(dst), index, 0, regs, p->data);
        }
        break;

    case INSTR_MOVSX:
        if (dst & REGISTER) {
            switch (size) {
            case BYTE:
                p->data &= 0xFFULL;
                if ( p->data & 0x80ULL )
                    p->data |= 0xFFFFFFFFFFFFFF00ULL;
                break;

            case WORD:
                p->data &= 0xFFFFULL;
                if ( p->data & 0x8000ULL )
                    p->data |= 0xFFFFFFFFFFFF0000ULL;
                break;

            case LONG:
                p->data &= 0xFFFFFFFFULL;
                if ( p->data & 0x80000000ULL )
                    p->data |= 0xFFFFFFFF00000000ULL;
                break;

            default:
                printk("Impossible source operand size of movsx instr: %d\n", size);
                domain_crash_synchronous();
            }
            index = operand_index(dst);
            set_reg_value(operand_size(dst), index, 0, regs, p->data);
        }
        break;

    case INSTR_MOVS:
        sign = p->df ? -1 : 1;

        if (mmio_opp->flags & REPZ)
            regs->ecx -= p->count;

        if ((mmio_opp->flags & OVERLAP) && p->dir == IOREQ_READ) {
            unsigned long addr = mmio_opp->addr;

            if (hvm_paging_enabled(current))
            {
                int rv = hvm_copy_to_guest_virt(addr, &p->data, p->size);
                if ( rv != 0 ) 
                {
                    /* Failed on the page-spanning copy.  Inject PF into
                     * the guest for the address where we failed. */
                    addr += p->size - rv;
                    gdprintk(XENLOG_DEBUG, "Pagefault writing non-io side of "
                             "a page-spanning MMIO: va=%#lx\n", addr);
                    hvm_inject_exception(TRAP_page_fault, 
                                         PFEC_write_access, addr);
                    return;
                }
            }
            else
                (void)hvm_copy_to_guest_phys(addr, &p->data, p->size);
        }

        regs->esi += sign * p->count * p->size;
        regs->edi += sign * p->count * p->size;

        break;

    case INSTR_STOS:
        sign = p->df ? -1 : 1;
        regs->edi += sign * p->count * p->size;
        if (mmio_opp->flags & REPZ)
            regs->ecx -= p->count;
        break;

    case INSTR_LODS:
        set_reg_value(size, 0, 0, regs, p->data);
        sign = p->df ? -1 : 1;
        regs->esi += sign * p->count * p->size;
        if (mmio_opp->flags & REPZ)
            regs->ecx -= p->count;
        break;

    case INSTR_AND:
        if (src & REGISTER) {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->data & value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->data & value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->data & value;
            set_reg_value(size, index, 0, regs, diff);
        }
        break;

    case INSTR_ADD:
        if (src & REGISTER) {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->data + value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->data + value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->data + value;
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
            diff = (unsigned long) p->data | value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->data | value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->data | value;
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
            diff = (unsigned long) p->data ^ value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->data ^ value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->data ^ value;
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
    case INSTR_SUB:
        if (src & REGISTER) {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
            diff = (unsigned long) p->data - value;
        } else if (src & IMMEDIATE) {
            value = mmio_opp->immediate;
            diff = (unsigned long) p->data - value;
        } else if (src & MEMORY) {
            index = operand_index(dst);
            value = get_reg_value(size, index, 0, regs);
            diff = value - (unsigned long) p->data;
            if ( mmio_opp->instr == INSTR_SUB )
                set_reg_value(size, index, 0, regs, diff);
        }

        /*
         * The CF, OF, SF, ZF, AF, and PF flags are set according
         * to the result
         */
        regs->eflags &= ~(X86_EFLAGS_CF|X86_EFLAGS_PF|X86_EFLAGS_AF|
                          X86_EFLAGS_ZF|X86_EFLAGS_SF|X86_EFLAGS_OF);
        set_eflags_CF(size, value, (unsigned long) p->data, regs);
        set_eflags_OF(size, diff, value, (unsigned long) p->data, regs);
        set_eflags_AF(size, diff, value, (unsigned long) p->data, regs);
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
        diff = (unsigned long) p->data & value;

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
        if ( src & REGISTER )
        {
            index = operand_index(src);
            value = get_reg_value(size, index, 0, regs);
        }
        else if ( src & IMMEDIATE )
            value = mmio_opp->immediate;
        if (p->data & (1 << (value & ((1 << 5) - 1))))
            regs->eflags |= X86_EFLAGS_CF;
        else
            regs->eflags &= ~X86_EFLAGS_CF;

        break;

    case INSTR_XCHG:
        if (src & REGISTER) {
            index = operand_index(src);
            set_reg_value(size, index, 0, regs, p->data);
        } else {
            index = operand_index(dst);
            set_reg_value(size, index, 0, regs, p->data);
        }
        break;

    case INSTR_PUSH:
        mmio_opp->addr += hvm_get_segment_base(current, x86_seg_ss);
        { 
            unsigned long addr = mmio_opp->addr;
            int rv = hvm_copy_to_guest_virt(addr, &p->data, size);
            if ( rv != 0 ) 
            {
                addr += p->size - rv;
                gdprintk(XENLOG_DEBUG, "Pagefault emulating PUSH from MMIO: "
                         "va=%#lx\n", addr);
                hvm_inject_exception(TRAP_page_fault, PFEC_write_access, addr);
                return;
            }
        }
        break;
    }
}

void hvm_io_assist(struct vcpu *v)
{
    vcpu_iodata_t *vio;
    ioreq_t *p;
    struct cpu_user_regs *regs;
    struct hvm_io_op *io_opp;
    unsigned long gmfn;

    io_opp = &v->arch.hvm_vcpu.io_op;
    regs   = &io_opp->io_context;
    vio    = get_vio(v->domain, v->vcpu_id);

    p = &vio->vp_ioreq;
    if ( p->state != STATE_IORESP_READY )
    {
        gdprintk(XENLOG_ERR, "Unexpected HVM iorequest state %d.\n", p->state);
        domain_crash_synchronous();
    }

    rmb(); /* see IORESP_READY /then/ read contents of ioreq */

    p->state = STATE_IOREQ_NONE;

    if ( p->type == IOREQ_TYPE_PIO )
        hvm_pio_assist(regs, p, io_opp);
    else
        hvm_mmio_assist(regs, p, io_opp);

    /* Copy register changes back into current guest state. */
    hvm_load_cpu_guest_regs(v, regs);
    memcpy(guest_cpu_user_regs(), regs, HVM_CONTEXT_STACK_BYTES);

    /* Has memory been dirtied? */
    if ( p->dir == IOREQ_READ && p->data_is_ptr ) 
    {
        gmfn = get_mfn_from_gpfn(paging_gva_to_gfn(v, p->data));
        mark_dirty(v->domain, gmfn);
    }
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
