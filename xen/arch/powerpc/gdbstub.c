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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/gdbstub.h>
#include <public/xen.h>
#include <asm/msr.h>
#include <asm/bitops.h>
#include <asm/cache.h>
#include <asm/debugger.h>
#include <asm/processor.h>

asm(".globl trap_instruction\n"
        "trap_instruction:\n"
        "trap\n");
extern u32 trap_instruction[];

static unsigned int dec_entry;
static unsigned int hdec_entry;

static inline ulong
gdb_ppc_0x700(struct cpu_user_regs *state)
{
    ulong instr;

    switch (state->msr & MSR_TRAP_BITS) {
        case MSR_TRAP_FE:
            return SIGFPE;
        case MSR_TRAP_IOP:
        case MSR_TRAP_PRIV:
            return SIGILL;
        case MSR_TRAP:
            instr = *((u32 *)state->pc);

            /* if this was a hardcoded trap in the source, step past it */
            if (instr == *trap_instruction) {
                state->pc += sizeof (u32);
            }
            return SIGTRAP;
    }
    return SIGBUS;
}

u16 gdb_arch_signal_num(struct cpu_user_regs *regs, unsigned long cookie)
{
    /* exception type identifies, trap or bad address */
    switch (cookie) {
        case 0x200: /* Machine Check */
            return SIGTERM;
        case 0x300: /* DSI */
        case 0x380: /* Data SLB */
        case 0x400: /* ISI */
        case 0x480: /* Instruction SLB */
            return SIGSEGV;
        case 0x600: /* Alignment SLB */
            return SIGBUS;
        case 0x700: /* Program */
            return gdb_ppc_0x700(regs);
        case 0x800: /* Float */
            return SIGFPE;
        case 0x900: /* Decrementer */
            return SIGALRM; /* is this right? */
        case 0xd00: /* TRAP */
            return SIGTRAP;
        case 0xe00: /* FP */
            return SIGFPE;
    }
    return SIGBUS;
}

void
gdb_arch_resume(struct cpu_user_regs *regs,
                unsigned long addr, unsigned long type,
                struct gdb_context *ctx)
{
    if (addr != ~((ulong)0)) {
        regs->pc = addr;
    }

    if (type == GDB_CONTINUE) {
        regs->msr &= ~MSR_SE;
    } else {
        regs->msr |= MSR_SE;
    }
}

void 
gdb_arch_read_reg(unsigned long regnum, struct cpu_user_regs *regs,
                  struct gdb_context *ctx)
{
    unimplemented();
    gdb_send_reply("", ctx);
}

void
gdb_arch_read_reg_array(struct cpu_user_regs *state, struct gdb_context *ctx)
{
    ulong i = 0;

    for (i = 0; i < 32; ++i) {
        gdb_write_to_packet_hex(state->gprs[i], sizeof(state->gprs[i]), ctx);
    }
    /* Avoid floating point for now */
    for (i = 0; i < 32; ++i) {
        gdb_write_to_packet_hex(0, sizeof(u64), ctx);
    }
    gdb_write_to_packet_hex(state->pc, sizeof (state->pc), ctx);
    gdb_write_to_packet_hex(state->msr, sizeof (state->msr), ctx);
    gdb_write_to_packet_hex(state->cr, sizeof (state->cr), ctx);
    gdb_write_to_packet_hex(state->lr, sizeof (state->lr), ctx);
    gdb_write_to_packet_hex(state->ctr, sizeof (state->ctr), ctx);
    gdb_write_to_packet_hex(state->xer, sizeof (u32), ctx);
    gdb_write_to_packet_hex(0, sizeof(u32), ctx); /* fpscr */
    gdb_send_packet(ctx);
}

void 
gdb_arch_write_reg(unsigned long regnum, unsigned long val, 
                    struct cpu_user_regs *regs, struct gdb_context *ctx)
{
    unimplemented();
    gdb_send_reply("", ctx);
}
 
void
gdb_arch_write_reg_array(struct cpu_user_regs *regs, const char *buf,
                         struct gdb_context *ctx)
{
    ulong i;

    for (i = 0; i < 32; ++i) {
        regs->gprs[i] = str2ulong(buf, sizeof (ulong));
        buf += sizeof (regs->gprs[0]) * 2;
    }
    /* Avoid floating point for now */
    for (i = 0; i < 32; ++i) {
        buf += sizeof (u64) * 2;
    }

    regs->pc = str2ulong(buf, sizeof (regs->pc));
    buf += sizeof (regs->pc) * 2;
    regs->msr = str2ulong(buf, sizeof (regs->msr));
    buf += sizeof (regs->msr) * 2;
    regs->cr = str2ulong(buf, sizeof (regs->cr));
    buf += sizeof (regs->cr) * 2;
    regs->lr = str2ulong(buf, sizeof (regs->lr));
    buf += sizeof (regs->lr) * 2;
    regs->ctr = str2ulong(buf, sizeof (regs->ctr));
    buf += sizeof (regs->ctr) * 2;
    regs->xer = str2ulong(buf, sizeof (u32));
    buf += sizeof (u32) * 2;
}

unsigned int
gdb_arch_copy_from_user(void *dest, const void *src, unsigned len)
{
    memcpy(dest, src, len);
    return 0;
}

unsigned int
gdb_arch_copy_to_user(void *dest, const void *src, unsigned len)
{
    memcpy(dest, src, len);
    synchronize_caches((ulong)dest, len);
    return 0;
}

void
gdb_arch_print_state(struct cpu_user_regs *state)
{
    int i = 0;
    printk("PC: 0x%016lx MSR: 0x%016lx\n", state->pc, state->msr);
    printk("LR: 0x%016lx CTR: 0x%016lx\n", state->lr, state->ctr);
    /* XXX
       printk("DAR: 0x%016lx DSISR: 0x%016lx\n", state->dar, state->dsisr);
       */
    printk("CR: 0x%08x XER: 0x%016lx\n", state->cr, state->xer);
    for (; i < 32; i+=4) {
        printk("%02d: 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n",
                i, state->gprs[i], state->gprs[i+1],
                state->gprs[i+2], state->gprs[i+3]);
    }
}

void
gdb_arch_enter(struct cpu_user_regs *state)
{
    dec_entry = mfdec();
    hdec_entry = mfhdec();
}

void
gdb_arch_exit(struct cpu_user_regs *state)
{
    mtdec(dec_entry);
    mthdec(hdec_entry);
}
