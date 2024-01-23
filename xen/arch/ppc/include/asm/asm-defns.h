/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_PPC_ASM_DEFNS_H
#define _ASM_PPC_ASM_DEFNS_H

#include <asm/asm-offsets.h>
#include <xen/linkage.h>

/*
 * Load a 64-bit immediate value into the specified GPR.
 */
#define LOAD_IMM64(reg, val)                                                 \
    lis reg, (val) @highest;                                                 \
    ori reg, reg, (val) @higher;                                             \
    rldicr reg, reg, 32, 31;                                                 \
    oris reg, reg, (val) @h;                                                 \
    ori reg, reg, (val) @l;

#define LOAD_IMM32(reg, val)                                                 \
    lis reg, (val) @h;                                                       \
    ori reg, reg, (val) @l;                                                  \

/*
 * Load the address of a symbol from the TOC into the specified GPR.
 */
#define LOAD_REG_ADDR(reg,name)                                              \
    addis reg, %r2, name@toc@ha;                                             \
    addi  reg, reg, name@toc@l

/*
 * Declare a global assembly function with a proper TOC setup prologue
 */
#define _GLOBAL_TOC(name)                                                   \
    .balign 4;                                                              \
    .type name, @function;                                                  \
    .globl name;                                                            \
name:                                                                       \
0:  addis %r2, %r12, (.TOC.-0b)@ha;                                         \
    addi  %r2, %r2, (.TOC.-0b)@l;                                           \
    .localentry name, .-name

/*
 * Depending on how we were booted, the CPU could be running in either
 * Little Endian or Big Endian mode. The following trampoline from Linux
 * cleverly uses an instruction that encodes to a NOP if the CPU's
 * endianness matches the assumption of the assembler (LE, in our case)
 * or a branch to code that performs the endian switch in the other case.
 */
#define FIXUP_ENDIAN                                                           \
    tdi 0, 0, 0x48;   /* Reverse endian of b . + 8          */                 \
    b . + 44;         /* Skip trampoline if endian is good  */                 \
    .long 0xa600607d; /* mfmsr r11                          */                 \
    .long 0x01006b69; /* xori r11,r11,1                     */                 \
    .long 0x00004039; /* li r10,0                           */                 \
    .long 0x6401417d; /* mtmsrd r10,1                       */                 \
    .long 0x05009f42; /* bcl 20,31,$+4                      */                 \
    .long 0xa602487d; /* mflr r10                           */                 \
    .long 0x14004a39; /* addi r10,r10,20                    */                 \
    .long 0xa6035a7d; /* mtsrr0 r10                         */                 \
    .long 0xa6037b7d; /* mtsrr1 r11                         */                 \
    .long 0x2400004c  /* rfid                               */

/* Taken from Linux kernel source (arch/powerpc/boot/crt0.S) */
.macro OP_REGS op, width, start, end, base, offset
	.Lreg=\start
	.rept (\end - \start + 1)
	\op	.Lreg,\offset+\width*.Lreg(\base)
	.Lreg=.Lreg+1
	.endr
.endm

#define SAVE_GPRS(start, end, base) OP_REGS std, 8, start, end, base, 0
#define REST_GPRS(start, end, base) OP_REGS ld, 8, start, end, base, 0
#define SAVE_GPR(n, base)           SAVE_GPRS(n, n, base)
#define REST_GPR(n, base)           REST_GPRS(n, n, base)
#define SAVE_NVGPRS(base)           SAVE_GPRS(14, 31, base)
#define REST_NVGPRS(base)           REST_GPRS(14, 31, base)

#endif /* _ASM_PPC_ASM_DEFNS_H */
