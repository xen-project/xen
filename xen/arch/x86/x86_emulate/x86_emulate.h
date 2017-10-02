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

/*
 * Comprehensive enumeration of x86 segment registers.  Various bits of code
 * rely on this order (general purpose before system, tr at the beginning of
 * system).
 */
enum x86_segment {
    /* General purpose.  Matches the SReg3 encoding in opcode/ModRM bytes. */
    x86_seg_es,
    x86_seg_cs,
    x86_seg_ss,
    x86_seg_ds,
    x86_seg_fs,
    x86_seg_gs,
    /* System: Valid to use for implicit table references. */
    x86_seg_tr,
    x86_seg_ldtr,
    x86_seg_gdtr,
    x86_seg_idtr,
    /* No Segment: For accesses which are already linear. */
    x86_seg_none
};

static inline bool is_x86_user_segment(enum x86_segment seg)
{
    unsigned int idx = seg;

    return idx <= x86_seg_gs;
}
static inline bool is_x86_system_segment(enum x86_segment seg)
{
    return seg >= x86_seg_tr && seg < x86_seg_none;
}

/*
 * x86 event types. This enumeration is valid for:
 *  Intel VMX: {VM_ENTRY,VM_EXIT,IDT_VECTORING}_INTR_INFO[10:8]
 *  AMD SVM: eventinj[10:8] and exitintinfo[10:8] (types 0-4 only)
 */
enum x86_event_type {
    X86_EVENTTYPE_EXT_INTR,         /* External interrupt */
    X86_EVENTTYPE_NMI = 2,          /* NMI */
    X86_EVENTTYPE_HW_EXCEPTION,     /* Hardware exception */
    X86_EVENTTYPE_SW_INTERRUPT,     /* Software interrupt (CD nn) */
    X86_EVENTTYPE_PRI_SW_EXCEPTION, /* ICEBP (F1) */
    X86_EVENTTYPE_SW_EXCEPTION,     /* INT3 (CC), INTO (CE) */
};
#define X86_EVENT_NO_EC (-1)        /* No error code. */

struct x86_event {
    int16_t       vector;
    uint8_t       type;         /* X86_EVENTTYPE_* */
    uint8_t       insn_len;     /* Instruction length */
    int32_t       error_code;   /* X86_EVENT_NO_EC if n/a */
    unsigned long cr2;          /* Only for TRAP_page_fault h/w exception */
};

/*
 * Full state of a segment register (visible and hidden portions).
 * Chosen to match the format of an AMD SVM VMCB.
 */
struct segment_register {
    uint16_t   sel;
    union {
        uint16_t attr;
        struct {
            uint16_t type:4;
            uint16_t s:   1;
            uint16_t dpl: 2;
            uint16_t p:   1;
            uint16_t avl: 1;
            uint16_t l:   1;
            uint16_t db:  1;
            uint16_t g:   1;
            uint16_t pad: 4;
        };
    };
    uint32_t   limit;
    uint64_t   base;
};

struct x86_emul_fpu_aux {
    unsigned long ip, dp;
    uint16_t cs, ds;
    unsigned int op:11;
    unsigned int dval:1;
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
 /*
  * Operation fully done by one of the hooks:
  * - validate(): operation completed (except common insn retire logic)
  * - read_segment(x86_seg_tr, ...): bypass I/O bitmap access
  * - read_io() / write_io(): bypass GPR update (non-string insns only)
  * Undefined behavior when used anywhere else.
  */
#define X86EMUL_DONE           4
 /*
  * Current instruction is not implemented by the emulator.
  * This value should only be returned by the core emulator when a valid
  * opcode is found but the execution logic for that instruction is missing.
  * It should NOT be returned by any of the x86_emulate_ops callbacks.
  */
#define X86EMUL_UNIMPLEMENTED  5
 /*
  * The current instruction's opcode is not valid.
  * If this error code is returned by a function, an #UD trap should be
  * raised by the final consumer of it.
  *
  * TODO: For the moment X86EMUL_UNRECOGNIZED and X86EMUL_UNIMPLEMENTED
  * can be used interchangeably therefore raising an #UD trap is not
  * strictly expected for now.
 */
#define X86EMUL_UNRECOGNIZED   X86EMUL_UNIMPLEMENTED

/* FPU sub-types which may be requested via ->get_fpu(). */
enum x86_emulate_fpu_type {
    X86EMUL_FPU_fpu, /* Standard FPU coprocessor instruction set */
    X86EMUL_FPU_wait, /* WAIT/FWAIT instruction */
    X86EMUL_FPU_mmx, /* MMX instruction set (%mm0-%mm7) */
    X86EMUL_FPU_xmm, /* SSE instruction set (%xmm0-%xmm7/15) */
    X86EMUL_FPU_ymm, /* AVX/XOP instruction set (%ymm0-%ymm7/15) */
    /* This sentinel will never be passed to ->get_fpu(). */
    X86EMUL_FPU_none
};

struct cpuid_leaf
{
    uint32_t a, b, c, d;
};

struct x86_emulate_state;

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
     *  Except for @bytes, all parameters are the same as for 'read'.
     *  @bytes: Access length (0 <= @bytes < 16, with zero meaning
     *  "validate address only").
     *  @seg is always x86_seg_cs.
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
     * validate: Post-decode, pre-emulate hook to allow caller controlled
     * filtering.
     */
    int (*validate)(
        const struct x86_emulate_state *state,
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
        const struct segment_register *reg,
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

    /* cpuid: Emulate CPUID via given set of EAX-EDX inputs/outputs. */
    int (*cpuid)(
        uint32_t leaf,
        uint32_t subleaf,
        struct cpuid_leaf *res,
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
     * @backout: Undo updates to the specified register file (can, besides
     *           X86EMUL_FPU_none, only be X86EMUL_FPU_fpu at present);
     * @aux: Packaged up FIP/FDP/FOP values to load into FPU.
     */
    void (*put_fpu)(
        struct x86_emulate_ctxt *ctxt,
        enum x86_emulate_fpu_type backout,
        const struct x86_emul_fpu_aux *aux);

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
    /*
     * Input-only state:
     */

    /* CPU vendor (X86_VENDOR_UNKNOWN for "don't care") */
    unsigned char vendor;

    /* Set this if writes may have side effects. */
    bool force_writeback;

    /* Caller data that can be used by x86_emulate_ops' routines. */
    void *data;

    /*
     * Input/output state:
     */

    /* Register state before/after emulation. */
    struct cpu_user_regs *regs;

    /* Default address size in current execution mode (16, 32, or 64). */
    unsigned int addr_size;

    /* Stack pointer width in bits (16, 32 or 64). */
    unsigned int sp_size;

    /* Long mode active? */
    bool lma;

    /*
     * Output-only state:
     */

    /* Canonical opcode (see below) (valid only on X86EMUL_OKAY). */
    unsigned int opcode;

    /* Retirement state, set by the emulator (valid only on X86EMUL_OKAY). */
    union {
        uint8_t raw;
        struct {
            bool hlt:1;          /* Instruction HLTed. */
            bool mov_ss:1;       /* Instruction sets MOV-SS irq shadow. */
            bool sti:1;          /* Instruction sets STI irq shadow. */
            bool unblock_nmi:1;  /* Instruction clears NMI blocking. */
            bool singlestep:1;   /* Singlestepping was active. */
        };
    } retire;

    bool event_pending;
    struct x86_event event;
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

#define X86EMUL_OPC_XOP(ext, byte)    X86EMUL_OPC(0x8f##ext, byte)
#define X86EMUL_OPC_XOP_66(ext, byte) X86EMUL_OPC_66(0x8f##ext, byte)
#define X86EMUL_OPC_XOP_F3(ext, byte) X86EMUL_OPC_F3(0x8f##ext, byte)
#define X86EMUL_OPC_XOP_F2(ext, byte) X86EMUL_OPC_F2(0x8f##ext, byte)

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
 * Returns X86EMUL_* constants.
 */
int
x86_emulate(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops);

#ifndef NDEBUG
/*
 * In debug builds, wrap x86_emulate() with some assertions about its expected
 * behaviour.
 */
int x86_emulate_wrapper(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops);
#define x86_emulate x86_emulate_wrapper
#endif

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

unsigned int
x86_insn_opsize(const struct x86_emulate_state *state);
int
x86_insn_modrm(const struct x86_emulate_state *state,
               unsigned int *rm, unsigned int *reg);
unsigned long
x86_insn_operand_ea(const struct x86_emulate_state *state,
                    enum x86_segment *seg);
unsigned long
x86_insn_immediate(const struct x86_emulate_state *state,
                   unsigned int nr);
unsigned int
x86_insn_length(const struct x86_emulate_state *state,
                const struct x86_emulate_ctxt *ctxt);
bool
x86_insn_is_mem_access(const struct x86_emulate_state *state,
                       const struct x86_emulate_ctxt *ctxt);
bool
x86_insn_is_mem_write(const struct x86_emulate_state *state,
                      const struct x86_emulate_ctxt *ctxt);
bool
x86_insn_is_portio(const struct x86_emulate_state *state,
                   const struct x86_emulate_ctxt *ctxt);
bool
x86_insn_is_cr_access(const struct x86_emulate_state *state,
                      const struct x86_emulate_ctxt *ctxt);

#ifdef NDEBUG
static inline void x86_emulate_free_state(struct x86_emulate_state *state) {}
#else
void x86_emulate_free_state(struct x86_emulate_state *state);
#endif

#endif

static inline void x86_emul_hw_exception(
    unsigned int vector, int error_code, struct x86_emulate_ctxt *ctxt)
{
    ASSERT(!ctxt->event_pending);

    ctxt->event.vector = vector;
    ctxt->event.type = X86_EVENTTYPE_HW_EXCEPTION;
    ctxt->event.error_code = error_code;

    ctxt->event_pending = true;
}

static inline void x86_emul_pagefault(
    int error_code, unsigned long cr2, struct x86_emulate_ctxt *ctxt)
{
    ASSERT(!ctxt->event_pending);

    ctxt->event.vector = 14; /* TRAP_page_fault */
    ctxt->event.type = X86_EVENTTYPE_HW_EXCEPTION;
    ctxt->event.error_code = error_code;
    ctxt->event.cr2 = cr2;

    ctxt->event_pending = true;
}

static inline void x86_emul_reset_event(struct x86_emulate_ctxt *ctxt)
{
    ctxt->event_pending = false;
    ctxt->event = (struct x86_event){};
}

#endif /* __X86_EMULATE_H__ */
