/*
 * x86_64 -specific gdb stub routines
 * 
 * Copyright (C) 2007 Dan Doucette   ddoucette@teradici.com
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

#define GDB_REG64(r) gdb_write_to_packet_hex(r, sizeof(u64), ctx)
#define GDB_REG32(r)  gdb_write_to_packet_hex(r, sizeof(u32), ctx)

void 
gdb_arch_read_reg_array(struct cpu_user_regs *regs, struct gdb_context *ctx)
{
    GDB_REG64(regs->rax);
    GDB_REG64(regs->rbx);
    GDB_REG64(regs->rcx);
    GDB_REG64(regs->rdx);
    GDB_REG64(regs->rsi);
    GDB_REG64(regs->rdi);
    GDB_REG64(regs->rbp);
    GDB_REG64(regs->rsp);

    GDB_REG64(regs->r8);
    GDB_REG64(regs->r9);
    GDB_REG64(regs->r10);
    GDB_REG64(regs->r11);
    GDB_REG64(regs->r12);
    GDB_REG64(regs->r13);
    GDB_REG64(regs->r14);
    GDB_REG64(regs->r15);

    GDB_REG64(regs->rip);
    GDB_REG32(regs->eflags);

    GDB_REG32(regs->cs);
    GDB_REG32(regs->ss);
    GDB_REG32(regs->ds);
    GDB_REG32(regs->es);
    GDB_REG32(regs->fs);
    GDB_REG32(regs->gs);

    gdb_send_packet(ctx);
}

void 
gdb_arch_write_reg_array(struct cpu_user_regs *regs, const char* buf,
                         struct gdb_context *ctx)
{
    gdb_send_reply("", ctx);
}

void 
gdb_arch_read_reg(unsigned long regnum, struct cpu_user_regs *regs,
                  struct gdb_context *ctx)
{
    switch (regnum)
    {
        case 0: GDB_REG64(regs->rax); break;
        case 1: GDB_REG64(regs->rbx); break;
        case 2: GDB_REG64(regs->rcx); break;
        case 3: GDB_REG64(regs->rdx); break;
        case 4: GDB_REG64(regs->rsi); break;
        case 5: GDB_REG64(regs->rdi); break;
        case 6: GDB_REG64(regs->rbp); break;
        case 7: GDB_REG64(regs->rsp); break;

        case 8: GDB_REG64(regs->r8); break;
        case 9: GDB_REG64(regs->r9); break;
        case 10: GDB_REG64(regs->r10); break;
        case 11: GDB_REG64(regs->r11); break;
        case 12: GDB_REG64(regs->r12); break;
        case 13: GDB_REG64(regs->r13); break;
        case 14: GDB_REG64(regs->r14); break;
        case 15: GDB_REG64(regs->r15); break;

        case 16: GDB_REG64(regs->rip); break;
        case 17: GDB_REG32(regs->rflags); break;
        case 18: GDB_REG32(regs->cs); break;
        case 19: GDB_REG32(regs->ss); break;
        case 20: GDB_REG32(regs->ds); break;
        case 21: GDB_REG32(regs->es); break;
        case 22: GDB_REG32(regs->fs); break;
        case 23: GDB_REG32(regs->gs); break;
        default:
            GDB_REG64(0xbaadf00ddeadbeef);
            break;
    }
    gdb_send_packet(ctx);
}

void 
gdb_arch_write_reg(unsigned long regnum, unsigned long val, 
                    struct cpu_user_regs *regs, struct gdb_context *ctx)
{
    switch (regnum)
    {
        case 0: regs->rax = val; break;
        case 1: regs->rbx = val; break;
        case 2: regs->rcx = val; break;
        case 3: regs->rdx = val; break;
        case 4: regs->rsi = val; break;
        case 5: regs->rdi = val; break;
        case 6: regs->rbp = val; break;
        case 7: regs->rsp = val; break;

        case 8: regs->r8 = val; break;
        case 9: regs->r9 = val; break;
        case 10: regs->r10 = val; break;
        case 11: regs->r11 = val; break;
        case 12: regs->r12 = val; break;
        case 13: regs->r13 = val; break;
        case 14: regs->r14 = val; break;
        case 15: regs->r15 = val; break;

        case 16: regs->rip = val; break;
        case 17: regs->rflags = (u32)val; break;
        case 18: regs->cs = (u16)val; break;
        case 19: regs->ss = (u16)val; break;
        case 20: regs->ds = (u16)val; break;
        case 21: regs->es = (u16)val; break;
        case 22: regs->fs = (u16)val; break;
        case 23: regs->gs = (u16)val; break;
        default:
            break;
    }
    gdb_send_reply("OK", ctx);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * End:
 */
