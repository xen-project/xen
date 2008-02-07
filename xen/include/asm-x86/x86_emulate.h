/******************************************************************************
 * x86_emulate.h
 * 
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 * 
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __X86_EMULATE_H__
#define __X86_EMULATE_H__

struct x86_emulate_ctxt;

/* Comprehensive enumeration of x86 segment registers. */
enum x86_segment {
    /* General purpose. */
    x86_seg_cs,
    x86_seg_ss,
    x86_seg_ds,
    x86_seg_es,
    x86_seg_fs,
    x86_seg_gs,
    /* System. */
    x86_seg_tr,
    x86_seg_ldtr,
    x86_seg_gdtr,
    x86_seg_idtr,
    /*
     * Dummy: used to emulate direct processor accesses to management
     * structures (TSS, GDT, LDT, IDT, etc.) which use linear addressing
     * (no segment component) and bypass usual segment- and page-level
     * protection checks.
     */
    x86_seg_none
};

#define is_x86_user_segment(seg) ((unsigned)(seg) <= x86_seg_gs)

/* 
 * Attribute for segment selector. This is a copy of bit 40:47 & 52:55 of the
 * segment descriptor. It happens to match the format of an AMD SVM VMCB.
 */
typedef union segment_attributes {
    u16 bytes;
    struct
    {
        u16 type:4;    /* 0;  Bit 40-43 */
        u16 s:   1;    /* 4;  Bit 44 */
        u16 dpl: 2;    /* 5;  Bit 45-46 */
        u16 p:   1;    /* 7;  Bit 47 */
        u16 avl: 1;    /* 8;  Bit 52 */
        u16 l:   1;    /* 9;  Bit 53 */
        u16 db:  1;    /* 10; Bit 54 */
        u16 g:   1;    /* 11; Bit 55 */
    } fields;
} __attribute__ ((packed)) segment_attributes_t;

/*
 * Full state of a segment register (visible and hidden portions).
 * Again, this happens to match the format of an AMD SVM VMCB.
 */
struct segment_register {
    u16        sel;
    segment_attributes_t attr;
    u32        limit;
    u64        base;
} __attribute__ ((packed));

/*
 * Return codes from state-accessor functions and from x86_emulate().
 */
 /* Completed successfully. State modified appropriately. */
#define X86EMUL_OKAY           0
 /* Unhandleable access or emulation. No state modified. */
#define X86EMUL_UNHANDLEABLE   1
 /* Exception raised and requires delivery. */
#define X86EMUL_EXCEPTION      2
 /* Retry the emulation for some reason. No state modified. */
#define X86EMUL_RETRY          3
 /* (cmpxchg accessor): CMPXCHG failed. Maps to X86EMUL_RETRY in caller. */
#define X86EMUL_CMPXCHG_FAILED 3

/*
 * These operations represent the instruction emulator's interface to memory.
 * 
 * NOTES:
 *  1. If the access fails (cannot emulate, or a standard access faults) then
 *     it is up to the memop to propagate the fault to the guest VM via
 *     some out-of-band mechanism, unknown to the emulator. The memop signals
 *     failure by returning X86EMUL_EXCEPTION to the emulator, which will
 *     then immediately bail.
 *  2. Valid access sizes are 1, 2, 4 and 8 bytes. On x86/32 systems only
 *     cmpxchg8b_emulated need support 8-byte accesses.
 *  3. The emulator cannot handle 64-bit mode emulation on an x86/32 system.
 */
struct x86_emulate_ops
{
    /*
     * All functions:
     *  @ctxt:  [IN ] Emulation context info as passed to the emulator.
     * All memory-access functions:
     *  @seg:   [IN ] Segment being dereferenced (specified as x86_seg_??).
     *  @offset:[IN ] Offset within segment.
     * Read functions:
     *  @val:   [OUT] Value read, zero-extended to 'ulong'.
     * Write functions:
     *  @val:   [IN ] Value to write (low-order bytes used as req'd).
     * Variable-length access functions:
     *  @bytes: [IN ] Number of bytes to read or write.
     */

    /* read: Emulate a memory read. */
    int (*read)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long *val,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * insn_fetch: Emulate fetch from instruction byte stream.
     *  Parameters are same as for 'read'. @seg is always x86_seg_cs.
     */
    int (*insn_fetch)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long *val,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /* write: Emulate a memory write. */
    int (*write)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long val,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * cmpxchg: Emulate an atomic (LOCKed) CMPXCHG operation.
     *  @old:   [IN ] Value expected to be current at @addr.
     *  @new:   [IN ] Value to write to @addr.
     */
    int (*cmpxchg)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long old,
        unsigned long new,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * cmpxchg8b: Emulate an atomic (LOCKed) CMPXCHG8B operation.
     *  @old:   [IN ] Value expected to be current at @addr.
     *  @new:   [IN ] Value to write to @addr.
     * NOTES:
     *  1. This function is only ever called when emulating a real CMPXCHG8B.
     *  2. This function is *never* called on x86/64 systems.
     *  2. Not defining this function (i.e., specifying NULL) is equivalent
     *     to defining a function that always returns X86EMUL_UNHANDLEABLE.
     */
    int (*cmpxchg8b)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long old_lo,
        unsigned long old_hi,
        unsigned long new_lo,
        unsigned long new_hi,
        struct x86_emulate_ctxt *ctxt);

    /*
     * rep_ins: Emulate INS: <src_port> -> <dst_seg:dst_offset>.
     *  @bytes_per_rep: [IN ] Bytes transferred per repetition.
     *  @reps:  [IN ] Maximum repetitions to be emulated.
     *          [OUT] Number of repetitions actually emulated.
     */
    int (*rep_ins)(
        uint16_t src_port,
        enum x86_segment dst_seg,
        unsigned long dst_offset,
        unsigned int bytes_per_rep,
        unsigned long *reps,
        struct x86_emulate_ctxt *ctxt);

    /*
     * rep_outs: Emulate OUTS: <src_seg:src_offset> -> <dst_port>.
     *  @bytes_per_rep: [IN ] Bytes transferred per repetition.
     *  @reps:  [IN ] Maximum repetitions to be emulated.
     *          [OUT] Number of repetitions actually emulated.
     */
    int (*rep_outs)(
        enum x86_segment src_seg,
        unsigned long src_offset,
        uint16_t dst_port,
        unsigned int bytes_per_rep,
        unsigned long *reps,
        struct x86_emulate_ctxt *ctxt);

    /*
     * rep_movs: Emulate MOVS: <src_seg:src_offset> -> <dst_seg:dst_offset>.
     *  @bytes_per_rep: [IN ] Bytes transferred per repetition.
     *  @reps:  [IN ] Maximum repetitions to be emulated.
     *          [OUT] Number of repetitions actually emulated.
     */
    int (*rep_movs)(
        enum x86_segment src_seg,
        unsigned long src_offset,
        enum x86_segment dst_seg,
        unsigned long dst_offset,
        unsigned int bytes_per_rep,
        unsigned long *reps,
        struct x86_emulate_ctxt *ctxt);

    /*
     * read_segment: Emulate a read of full context of a segment register.
     *  @reg:   [OUT] Contents of segment register (visible and hidden state).
     */
    int (*read_segment)(
        enum x86_segment seg,
        struct segment_register *reg,
        struct x86_emulate_ctxt *ctxt);

    /*
     * write_segment: Emulate a read of full context of a segment register.
     *  @reg:   [OUT] Contents of segment register (visible and hidden state).
     */
    int (*write_segment)(
        enum x86_segment seg,
        struct segment_register *reg,
        struct x86_emulate_ctxt *ctxt);

    /*
     * read_io: Read from I/O port(s).
     *  @port:  [IN ] Base port for access.
     */
    int (*read_io)(
        unsigned int port,
        unsigned int bytes,
        unsigned long *val,
        struct x86_emulate_ctxt *ctxt);

    /*
     * write_io: Write to I/O port(s).
     *  @port:  [IN ] Base port for access.
     */
    int (*write_io)(
        unsigned int port,
        unsigned int bytes,
        unsigned long val,
        struct x86_emulate_ctxt *ctxt);

    /*
     * read_cr: Read from control register.
     *  @reg:   [IN ] Register to read (0-15).
     */
    int (*read_cr)(
        unsigned int reg,
        unsigned long *val,
        struct x86_emulate_ctxt *ctxt);

    /*
     * write_cr: Write to control register.
     *  @reg:   [IN ] Register to write (0-15).
     */
    int (*write_cr)(
        unsigned int reg,
        unsigned long val,
        struct x86_emulate_ctxt *ctxt);

    /*
     * read_dr: Read from debug register.
     *  @reg:   [IN ] Register to read (0-15).
     */
    int (*read_dr)(
        unsigned int reg,
        unsigned long *val,
        struct x86_emulate_ctxt *ctxt);

    /*
     * write_dr: Write to debug register.
     *  @reg:   [IN ] Register to write (0-15).
     */
    int (*write_dr)(
        unsigned int reg,
        unsigned long val,
        struct x86_emulate_ctxt *ctxt);

    /*
     * read_msr: Read from model-specific register.
     *  @reg:   [IN ] Register to read.
     */
    int (*read_msr)(
        unsigned long reg,
        uint64_t *val,
        struct x86_emulate_ctxt *ctxt);

    /*
     * write_dr: Write to model-specific register.
     *  @reg:   [IN ] Register to write.
     */
    int (*write_msr)(
        unsigned long reg,
        uint64_t val,
        struct x86_emulate_ctxt *ctxt);

    /* write_rflags: Modify privileged bits in RFLAGS. */
    int (*write_rflags)(
        unsigned long val,
        struct x86_emulate_ctxt *ctxt);

    /* wbinvd: Write-back and invalidate cache contents. */
    int (*wbinvd)(
        struct x86_emulate_ctxt *ctxt);

    /* cpuid: Emulate CPUID via given set of EAX-EDX inputs/outputs. */
    int (*cpuid)(
        unsigned int *eax,
        unsigned int *ebx,
        unsigned int *ecx,
        unsigned int *edx,
        struct x86_emulate_ctxt *ctxt);

    /* hlt: Emulate HLT. */
    int (*hlt)(
        struct x86_emulate_ctxt *ctxt);

    /* inject_hw_exception */
    int (*inject_hw_exception)(
        uint8_t vector,
        uint16_t error_code,
        struct x86_emulate_ctxt *ctxt);

    /* inject_sw_interrupt */
    int (*inject_sw_interrupt)(
        uint8_t vector,
        uint8_t insn_len,
        struct x86_emulate_ctxt *ctxt);

    /* load_fpu_ctxt: Load emulated environment's FPU state onto processor. */
    void (*load_fpu_ctxt)(
        struct x86_emulate_ctxt *ctxt);
};

struct cpu_user_regs;

struct x86_emulate_ctxt
{
    /* Register state before/after emulation. */
    struct cpu_user_regs *regs;

    /* Default address size in current execution mode (16, 32, or 64). */
    unsigned int addr_size;

    /* Stack pointer width in bits (16, 32 or 64). */
    unsigned int sp_size;
};

/*
 * x86_emulate: Emulate an instruction.
 * Returns -1 on failure, 0 on success.
 */
int
x86_emulate(
    struct x86_emulate_ctxt *ctxt,
    struct x86_emulate_ops  *ops);

/*
 * Given the 'reg' portion of a ModRM byte, and a register block, return a
 * pointer into the block that addresses the relevant register.
 * @highbyte_regs specifies whether to decode AH,CH,DH,BH.
 */
void *
decode_register(
    uint8_t modrm_reg, struct cpu_user_regs *regs, int highbyte_regs);

#endif /* __X86_EMULATE_H__ */
