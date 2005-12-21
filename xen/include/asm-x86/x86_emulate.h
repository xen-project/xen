/******************************************************************************
 * x86_emulate.h
 * 
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 * 
 * Copyright (c) 2005 Keir Fraser
 */

#ifndef __X86_EMULATE_H__
#define __X86_EMULATE_H__

/*
 * x86_mem_emulator:
 * 
 * These operations represent the instruction emulator's interface to memory.
 * There are two categories of operation: those that act on ordinary memory
 * regions (*_std), and those that act on memory regions known to require
 * special treatment or emulation (*_emulated).
 * 
 * The emulator assumes that an instruction accesses only one 'emulated memory'
 * location, and that this is one of its data operands. Instruction fetches and
 * stack operations are assumed never to access emulated memory. The emulator
 * automatically deduces which operand of a string-move operation is accessing
 * emulated memory, and requires that the other operand accesses normal memory.
 * 
 * NOTES:
 *  1. The emulator isn't very smart about emulated vs. standard memory.
 *     'Emulated memory' access addresses should be checked for sanity.
 *     'Normal memory' accesses may fault, and the caller must arrange to
 *     detect and handle reentrancy into the emulator via recursive faults.
 *     Accesses may be unaligned and may cross page boundaries.
 *  2. If the access fails (cannot emulate, or a standard access faults) then
 *     it is up to the memop to propagate the fault to the guest VM via
 *     some out-of-band mechanism, unknown to the emulator. The memop signals
 *     failure by returning X86EMUL_PROPAGATE_FAULT to the emulator, which will
 *     then immediately bail.
 *  3. Valid access sizes are 1, 2, 4 and 8 bytes. On x86/32 systems only
 *     cmpxchg8b_emulated need support 8-byte accesses.
 */
/* Access completed successfully: continue emulation as normal. */
#define X86EMUL_CONTINUE        0
/* Access is unhandleable: bail from emulation and return error to caller. */
#define X86EMUL_UNHANDLEABLE    1
/* Terminate emulation but return success to the caller. */
#define X86EMUL_PROPAGATE_FAULT 2 /* propagate a generated fault to guest */
#define X86EMUL_RETRY_INSTR     2 /* retry the instruction for some reason */
#define X86EMUL_CMPXCHG_FAILED  2 /* cmpxchg did not see expected value */
struct x86_mem_emulator
{
    /*
     * read_std: Read bytes of standard (non-emulated/special) memory.
     *           Used for instruction fetch, stack operations, and others.
     *  @addr:  [IN ] Linear address from which to read.
     *  @val:   [OUT] Value read from memory, zero-extended to 'u_long'.
     *  @bytes: [IN ] Number of bytes to read from memory.
     */
    int (*read_std)(
        unsigned long addr,
        unsigned long *val,
        unsigned int bytes);

    /*
     * write_std: Write bytes of standard (non-emulated/special) memory.
     *            Used for stack operations, and others.
     *  @addr:  [IN ] Linear address to which to write.
     *  @val:   [IN ] Value to write to memory (low-order bytes used as req'd).
     *  @bytes: [IN ] Number of bytes to write to memory.
     */
    int (*write_std)(
        unsigned long addr,
        unsigned long val,
        unsigned int bytes);

    /*
     * read_emulated: Read bytes from emulated/special memory area.
     *  @addr:  [IN ] Linear address from which to read.
     *  @val:   [OUT] Value read from memory, zero-extended to 'u_long'.
     *  @bytes: [IN ] Number of bytes to read from memory.
     */
    int (*read_emulated)(
        unsigned long addr,
        unsigned long *val,
        unsigned int bytes);

    /*
     * write_emulated: Read bytes from emulated/special memory area.
     *  @addr:  [IN ] Linear address to which to write.
     *  @val:   [IN ] Value to write to memory (low-order bytes used as req'd).
     *  @bytes: [IN ] Number of bytes to write to memory.
     */
    int (*write_emulated)(
        unsigned long addr,
        unsigned long val,
        unsigned int bytes);

    /*
     * cmpxchg_emulated: Emulate an atomic (LOCKed) CMPXCHG operation on an
     *                   emulated/special memory area.
     *  @addr:  [IN ] Linear address to access.
     *  @old:   [IN ] Value expected to be current at @addr.
     *  @new:   [IN ] Value to write to @addr.
     *  @bytes: [IN ] Number of bytes to access using CMPXCHG.
     */
    int (*cmpxchg_emulated)(
        unsigned long addr,
        unsigned long old,
        unsigned long new,
        unsigned int bytes);

    /*
     * cmpxchg_emulated: Emulate an atomic (LOCKed) CMPXCHG8B operation on an
     *                   emulated/special memory area.
     *  @addr:  [IN ] Linear address to access.
     *  @old:   [IN ] Value expected to be current at @addr.
     *  @new:   [IN ] Value to write to @addr.
     * NOTES:
     *  1. This function is only ever called when emulating a real CMPXCHG8B.
     *  2. This function is *never* called on x86/64 systems.
     *  2. Not defining this function (i.e., specifying NULL) is equivalent
     *     to defining a function that always returns X86EMUL_UNHANDLEABLE.
     */
    int (*cmpxchg8b_emulated)(
        unsigned long addr,
        unsigned long old_lo,
        unsigned long old_hi,
        unsigned long new_lo,
        unsigned long new_hi);
};

/* Standard reader/writer functions that callers may wish to use. */
extern int
x86_emulate_read_std(
    unsigned long addr,
    unsigned long *val,
    unsigned int bytes);
extern int
x86_emulate_write_std(
    unsigned long addr,
    unsigned long val,
    unsigned int bytes);

struct cpu_user_regs;

/*
 * x86_emulate_memop: Emulate an instruction that faulted attempting to
 *                    read/write a 'special' memory area.
 *  @regs: Register state at time of fault.
 *  @cr2:  Linear faulting address.
 *  @ops:  Interface to access special memory.
 *  @mode: Current execution mode, represented by the default size of memory
 *         addresses, in bytes. Valid values are 2, 4 and 8 (x86/64 only).
 */
extern int
x86_emulate_memop(
    struct cpu_user_regs *regs,
    unsigned long cr2,
    struct x86_mem_emulator *ops,
    int mode);

/*
 * Given the 'reg' portion of a ModRM byte, and a register block, return a
 * pointer into the block that addresses the relevant register.
 * @highbyte_regs specifies whether to decode AH,CH,DH,BH.
 */
extern void *
decode_register(
    uint8_t modrm_reg, struct cpu_user_regs *regs, int highbyte_regs);

#endif /* __X86_EMULATE_H__ */
