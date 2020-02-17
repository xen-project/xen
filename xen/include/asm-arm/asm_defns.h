#ifndef __ARM_ASM_DEFNS_H__
#define __ARM_ASM_DEFNS_H__

#ifndef COMPILE_OFFSETS
/* NB. Auto-generated from arch/.../asm-offsets.c */
#include <asm/asm-offsets.h>
#endif
#include <asm/processor.h>

/* Macros for generic assembly code */
#if defined(CONFIG_ARM_32)
# define __OP32
# define ASM_REG(index) asm("r" # index)
#elif defined(CONFIG_ARM_64)
# define __OP32 "w"
/*
 * Clang < 8.0 doesn't support register alllocation using the syntax rN.
 * See https://reviews.llvm.org/rL328829.
 */
# define ASM_REG(index) asm("x" # index)
#else
# error "unknown ARM variant"
#endif

#define RODATA_STR(label, msg)                  \
.pushsection .rodata.str, "aMS", %progbits, 1 ; \
label:  .asciz msg;                             \
.popsection

#define ASM_INT(label, val)                 \
    .p2align 2;                             \
label: .long (val);                         \
    .size label, . - label;                 \
    .type label, %object

#endif /* __ARM_ASM_DEFNS_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
