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
    /* XXX */
    return 1;
}

void 
gdb_arch_read_reg_array(struct cpu_user_regs *regs, struct gdb_context *ctx)
{
#define GDB_REG(r) gdb_write_to_packet_hex(r, sizeof(r), ctx);
    GDB_REG(regs->eax);
    GDB_REG(regs->ecx);
    GDB_REG(regs->edx);
    GDB_REG(regs->ebx);
    GDB_REG(regs->esp);
    GDB_REG(regs->ebp);
    GDB_REG(regs->esi);
    GDB_REG(regs->edi);
    GDB_REG(regs->eip);
    GDB_REG(regs->eflags);
#undef GDB_REG
#define GDB_SEG_REG(s)  gdb_write_to_packet_hex(s, sizeof(u32), ctx);
    /* sizeof(segment) = 16bit */
    /* but gdb requires its return value as 32bit value */
    GDB_SEG_REG(regs->cs);
    GDB_SEG_REG(regs->ss);
    GDB_SEG_REG(regs->ds);
    GDB_SEG_REG(regs->es);
    GDB_SEG_REG(regs->fs);
    GDB_SEG_REG(regs->gs);
#undef GDB_SEG_REG
    gdb_send_packet(ctx);
}

void 
gdb_arch_write_reg_array(struct cpu_user_regs *regs, const char* buf,
                         struct gdb_context *ctx)
{
    /* XXX TODO */
    gdb_send_reply("E02", ctx);
}

void 
gdb_arch_read_reg(unsigned long regnum, struct cpu_user_regs *regs,
                  struct gdb_context *ctx)
{
    gdb_send_reply("", ctx);
}

/* Like copy_from_user, but safe to call with interrupts disabled.
   Trust me, and don't look behind the curtain. */
unsigned int
gdb_arch_copy_from_user(void *dest, const void *src, unsigned len)
{
    return copy_from_user(dest, src, len);
}

unsigned int 
gdb_arch_copy_to_user(void *dest, const void *src, unsigned len)
{
    return copy_to_user(dest, src, len);
}

void 
gdb_arch_resume(struct cpu_user_regs *regs,
                unsigned long addr, unsigned long type,
                struct gdb_context *ctx)
{
    /* XXX */
    if (type == GDB_STEP) {
        gdb_send_reply("S01", ctx);
    }
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * End:
 */
