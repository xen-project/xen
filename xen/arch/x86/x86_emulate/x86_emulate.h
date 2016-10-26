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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __X86_EMULATE_H__
#define __X86_EMULATE_H__

#define MAX_INST_LEN 15

struct x86_emulate_ctxt;

/* Comprehensive enumeration of x86 segment registers. */
enum x86_segment {
    /* General purpose.  Matches the SReg3 encoding in opcode/ModRM bytes. */
    x86_seg_es,
    x86_seg_cs,
    x86_seg_ss,
    x86_seg_ds,
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

/* Classification of the types of software generated interrupts/exceptions. */
enum x86_swint_type {
    x86_swint_icebp, /* 0xf1 */
    x86_swint_int3,  /* 0xcc */
    x86_swint_into,  /* 0xce */
    x86_swint_int,   /* 0xcd $n */
};

/* How much help is required with software event injection? */
enum x86_swint_emulation {
    x86_swint_emulate_none, /* Hardware supports all software injection properly */
    x86_swint_emulate_icebp,/* Help needed with `icebp` (0xf1) */
    x86_swint_emulate_all,  /* Help needed with all software events */
};

/* 
 * Attribute for segment selector. This is a copy of bit 40:47 & 52:55 of the
 * segment descriptor. It happens to match the format of an AMD SVM VMCB.
 */
typedef union __attribute__((__packed__)) segment_attributes {
    uint16_t bytes;
    struct
    {
        uint16_t type:4;    /* 0;  Bit 40-43 */
        uint16_t s:   1;    /* 4;  Bit 44 */
        uint16_t dpl: 2;    /* 5;  Bit 45-46 */
        uint16_t p:   1;    /* 7;  Bit 47 */
        uint16_t avl: 1;    /* 8;  Bit 52 */
        uint16_t l:   1;    /* 9;  Bit 53 */
        uint16_t db:  1;    /* 10; Bit 54 */
        uint16_t g:   1;    /* 11; Bit 55 */
        uint16_t pad: 4;
    } fields;
} segment_attributes_t;

/*
 * Full state of a segment register (visible and hidden portions).
 * Again, this happens to match the format of an AMD SVM VMCB.
 */
struct __attribute__((__packed__)) segment_register {
    uint16_t   sel;
    segment_attributes_t attr;
    uint32_t   limit;
    uint64_t   base;
};

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

/* FPU sub-types which may be requested via ->get_fpu(). */
enum x86_emulate_fpu_type {
    X86EMUL_FPU_fpu, /* Standard FPU coprocessor instruction set */
    X86EMUL_FPU_wait, /* WAIT/FWAIT instruction */
    X86EMUL_FPU_mmx, /* MMX instruction set (%mm0-%mm7) */
    X86EMUL_FPU_xmm, /* SSE instruction set (%xmm0-%xmm7/15) */
    X86EMUL_FPU_ymm  /* AVX/XOP instruction set (%ymm0-%ymm7/15) */
};

/*
 * These operations represent the instruction emulator's interface to memory,
 * I/O ports, privileged state... pretty much everything other than GPRs.
 * 
 * NOTES:
 *  1. If the access fails (cannot emulate, or a standard access faults) then
 *     it is up to the memop to propagate the fault to the guest VM via
 *     some out-of-band mechanism, unknown to the emulator. The memop signals
 *     failure by returning X86EMUL_EXCEPTION to the emulator, which will
 *     then immediately bail.
 *  2. The emulator cannot handle 64-bit mode emulation on an x86/32 system.
 */
struct x86_emulate_ops
{
    /*
     * All functions:
     *  @ctxt:  [IN ] Emulation context info as passed to the emulator.
     * All memory-access functions:
     *  @seg:   [IN ] Segment being dereferenced (specified as x86_seg_??).
     *  @offset:[IN ] Offset within segment.
     *  @p_data:[IN ] Pointer to i/o data buffer (length is @bytes)
     * Read functions:
     *  @val:   [OUT] Value read, zero-extended to 'ulong'.
     * Write functions:
     *  @val:   [IN ] Value to write (low-order bytes used as req'd).
     * Variable-length access functions:
     *  @bytes: [IN ] Number of bytes to read or write. Valid access sizes are
     *                1, 2, 4 and 8 (x86/64 only) bytes, unless otherwise
     *                stated.
     */

    /*
     * read: Emulate a memory read.
     *  @bytes: Access length (0 < @bytes < 4096).
     */
    int (*read)(
        enum x86_segment seg,
        unsigned long offset,
        void *p_data,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * insn_fetch: Emulate fetch from instruction byte stream.
     *  Parameters are same as for 'read'. @seg is always x86_seg_cs.
     */
    int (*insn_fetch)(
        enum x86_segment seg,
        unsigned long offset,
        void *p_data,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * write: Emulate a memory write.
     *  @bytes: Access length (0 < @bytes < 4096).
     */
    int (*write)(
        enum x86_segment seg,
        unsigned long offset,
        void *p_data,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * cmpxchg: Emulate an atomic (LOCKed) CMPXCHG operation.
     *  @p_old: [IN ] Pointer to value expected to be current at @addr.
     *  @p_new: [IN ] Pointer to value to write to @addr.
     *  @bytes: [IN ] Operation size (up to 8 (x86/32) or 16 (x86/64) bytes).
     */
    int (*cmpxchg)(
        enum x86_segment seg,
        unsigned long offset,
        void *p_old,
        void *p_new,
        unsigned int bytes,
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
     * rep_stos: Emulate STOS: <*p_data> -> <seg:offset>.
     *  @bytes_per_rep: [IN ] Bytes transferred per repetition.
     *  @reps:  [IN ] Maximum repetitions to be emulated.
     *          [OUT] Number of repetitions actually emulated.
     */
    int (*rep_stos)(
        void *p_data,
        enum x86_segment seg,
        unsigned long offset,
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
        unsigned int reg,
        uint64_t *val,
        struct x86_emulate_ctxt *ctxt);

    /*
     * write_dr: Write to model-specific register.
     *  @reg:   [IN ] Register to write.
     */
    int (*write_msr)(
        unsigned int reg,
        uint64_t val,
        struct x86_emulate_ctxt *ctxt);

    /* wbinvd: Write-back and invalidate cache contents. */
    int (*wbinvd)(
        struct x86_emulate_ctxt *ctxt);

    /*
     * cpuid: Emulate CPUID via given set of EAX-EDX inputs/outputs.
     *
     * May return X86EMUL_EXCEPTION, which causes the emulator to inject
     * #GP[0].  Used to implement CPUID faulting.
     */
    int (*cpuid)(
        unsigned int *eax,
        unsigned int *ebx,
        unsigned int *ecx,
        unsigned int *edx,
        struct x86_emulate_ctxt *ctxt);

    /* inject_hw_exception */
    int (*inject_hw_exception)(
        uint8_t vector,
        int32_t error_code,
        struct x86_emulate_ctxt *ctxt);

    /* inject_sw_interrupt */
    int (*inject_sw_interrupt)(
        enum x86_swint_type type,
        uint8_t vector,
        uint8_t insn_len,
        struct x86_emulate_ctxt *ctxt);

    /*
     * get_fpu: Load emulated environment's FPU state onto processor.
     *  @exn_callback: On any FPU or SIMD exception, pass control to
     *                 (*exception_callback)(exception_callback_arg, regs).
     */
    int (*get_fpu)(
        void (*exception_callback)(void *, struct cpu_user_regs *),
        void *exception_callback_arg,
        enum x86_emulate_fpu_type type,
        struct x86_emulate_ctxt *ctxt);

    /*
     * put_fpu: Relinquish the FPU. Unhook from FPU/SIMD exception handlers.
     *  The handler, if installed, must be prepared to get called without
     *  the get_fpu one having got called before!
     */
    void (*put_fpu)(
        struct x86_emulate_ctxt *ctxt);

    /* invlpg: Invalidate paging structures which map addressed byte. */
    int (*invlpg)(
        enum x86_segment seg,
        unsigned long offset,
        struct x86_emulate_ctxt *ctxt);

    /* vmfunc: Emulate VMFUNC via given set of EAX ECX inputs */
    int (*vmfunc)(
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

    /* Canonical opcode (see below). */
    unsigned int opcode;

    /* Software event injection support. */
    enum x86_swint_emulation swint_emulate;

    /* Set this if writes may have side effects. */
    uint8_t force_writeback;

    /* Retirement state, set by the emulator (valid only on X86EMUL_OKAY). */
    union {
        struct {
            uint8_t hlt:1;          /* Instruction HLTed. */
            uint8_t mov_ss:1;       /* Instruction sets MOV-SS irq shadow. */
            uint8_t sti:1;          /* Instruction sets STI irq shadow. */
        } flags;
        uint8_t byte;
    } retire;

    /* Caller data that can be used by x86_emulate_ops' routines. */
    void *data;
};

/*
 * Encode opcode extensions in the following way:
 *     0x0xxxx for one byte opcodes
 *    0x0fxxxx for 0f-prefixed opcodes (or their VEX/EVEX equivalents)
 *  0x0f38xxxx for 0f38-prefixed opcodes (or their VEX/EVEX equivalents)
 *  0x0f3axxxx for 0f3a-prefixed opcodes (or their VEX/EVEX equivalents)
 *  0x8f08xxxx for 8f/8-prefixed XOP opcodes
 *  0x8f09xxxx for 8f/9-prefixed XOP opcodes
 *  0x8f0axxxx for 8f/a-prefixed XOP opcodes
 * The low byte represents the base opcode withing the resepctive space,
 * and some of bits 8..15 are used for encoding further information (see
 * below).
 * Hence no separate #define-s get added.
 */
#define X86EMUL_OPC_EXT_MASK         0xffff0000
#define X86EMUL_OPC(ext, byte)       ((uint8_t)(byte) | \
                                      MASK_INSR((ext), X86EMUL_OPC_EXT_MASK))
/*
 * This includes the 66, F3, and F2 prefixes (see also below)
 * as well as VEX/EVEX:
 */
#define X86EMUL_OPC_MASK             (0x000000ff | X86EMUL_OPC_PFX_MASK | \
                                     X86EMUL_OPC_ENCODING_MASK)

/*
 * Note that prefixes 66, F2, and F3 get encoded only when semantically
 * meaningful, to reduce the complexity of interpreting this representation.
 */
#define X86EMUL_OPC_PFX_MASK         0x00000300
# define X86EMUL_OPC_66(ext, byte)   (X86EMUL_OPC(ext, byte) | 0x00000100)
# define X86EMUL_OPC_F3(ext, byte)   (X86EMUL_OPC(ext, byte) | 0x00000200)
# define X86EMUL_OPC_F2(ext, byte)   (X86EMUL_OPC(ext, byte) | 0x00000300)

#define X86EMUL_OPC_ENCODING_MASK    0x00003000
#define X86EMUL_OPC_LEGACY_          0x00000000
#define X86EMUL_OPC_VEX_             0x00001000
# define X86EMUL_OPC_VEX(ext, byte) \
    (X86EMUL_OPC(ext, byte) | X86EMUL_OPC_VEX_)
# define X86EMUL_OPC_VEX_66(ext, byte) \
    (X86EMUL_OPC_66(ext, byte) | X86EMUL_OPC_VEX_)
# define X86EMUL_OPC_VEX_F3(ext, byte) \
    (X86EMUL_OPC_F3(ext, byte) | X86EMUL_OPC_VEX_)
# define X86EMUL_OPC_VEX_F2(ext, byte) \
    (X86EMUL_OPC_F2(ext, byte) | X86EMUL_OPC_VEX_)
#define X86EMUL_OPC_EVEX_            0x00002000
# define X86EMUL_OPC_EVEX(ext, byte) \
    (X86EMUL_OPC(ext, byte) | X86EMUL_OPC_EVEX_)
# define X86EMUL_OPC_EVEX_66(ext, byte) \
    (X86EMUL_OPC_66(ext, byte) | X86EMUL_OPC_EVEX_)
# define X86EMUL_OPC_EVEX_F3(ext, byte) \
    (X86EMUL_OPC_F3(ext, byte) | X86EMUL_OPC_EVEX_)
# define X86EMUL_OPC_EVEX_F2(ext, byte) \
    (X86EMUL_OPC_F2(ext, byte) | X86EMUL_OPC_EVEX_)

struct x86_emulate_stub {
    union {
        void (*func)(void);
        uintptr_t addr;
    };
#ifdef __XEN__
    void *ptr;
#else
    /* Room for one insn and a (single byte) RET. */
    uint8_t buf[MAX_INST_LEN + 1];
#endif
};

/*
 * x86_emulate: Emulate an instruction.
 * Returns -1 on failure, 0 on success.
 */
int
x86_emulate(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops);

/*
 * Given the 'reg' portion of a ModRM byte, and a register block, return a
 * pointer into the block that addresses the relevant register.
 * @highbyte_regs specifies whether to decode AH,CH,DH,BH.
 */
void *
decode_register(
    uint8_t modrm_reg, struct cpu_user_regs *regs, int highbyte_regs);

/* Unhandleable read, write or instruction fetch */
int
x86emul_unhandleable_rw(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt);

#ifdef __XEN__

struct x86_emulate_state *
x86_decode_insn(
    struct x86_emulate_ctxt *ctxt,
    int (*insn_fetch)(
        enum x86_segment seg, unsigned long offset,
        void *p_data, unsigned int bytes,
        struct x86_emulate_ctxt *ctxt));

int
x86_insn_modrm(const struct x86_emulate_state *state,
               unsigned int *rm, unsigned int *reg);
unsigned int
x86_insn_length(const struct x86_emulate_state *state,
                const struct x86_emulate_ctxt *ctxt);

#ifdef NDEBUG
static inline void x86_emulate_free_state(struct x86_emulate_state *state) {}
#else
void x86_emulate_free_state(struct x86_emulate_state *state);
#endif

#endif

#endif /* __X86_EMULATE_H__ */
