/*
 * x86-specific gdb stub routines
 * based on x86 cdb(xen/arch/x86/cdb.c), but Extensively modified.
 * 
 * Copyright (C) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan. K.K.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
#include <asm/debugger.h>

u16
gdb_arch_signal_num(struct cpu_user_regs *regs, unsigned long cookie)
{
    return 5;   /* TRAP signal.  see include/gdb/signals.h */
}

/*
 * Use __copy_*_user to make us page-fault safe, but not otherwise restrict
 * our access to the full virtual address space.
 */
unsigned int
gdb_arch_copy_from_user(void *dest, const void *src, unsigned len)
{
    return __copy_from_user(dest, src, len);
}

unsigned int 
gdb_arch_copy_to_user(void *dest, const void *src, unsigned len)
{
    return __copy_to_user(dest, src, len);
}

void
gdb_arch_print_state(struct cpu_user_regs *regs)
{
    /* XXX */
}

void
gdb_arch_enter(struct cpu_user_regs *regs)
{
    /* nothing */
}

void
gdb_arch_exit(struct cpu_user_regs *regs)
{
    /* nothing */
}

void 
gdb_arch_resume(struct cpu_user_regs *regs,
                unsigned long addr, unsigned long type,
                struct gdb_context *ctx)
{
    if ( addr != -1UL )
        regs->eip = addr;

    regs->eflags &= ~X86_EFLAGS_TF;

    /* Set eflags.RF to ensure we do not re-enter. */
    regs->eflags |= X86_EFLAGS_RF;

    /* Set the trap flag if we are single stepping. */
    if ( type == GDB_STEP )
        regs->eflags |= X86_EFLAGS_TF;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * End:
 */
