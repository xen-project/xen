#ifndef __ASM_ARM_ARM32_MACROS_H
#define __ASM_ARM_ARM32_MACROS_H

.macro ret
        mov     pc, lr
.endm

/*
 * Move an immediate constant into a 32-bit register using movw/movt
 * instructions.
 */
.macro mov_w reg, word
        movw  \reg, #:lower16:\word
        movt  \reg, #:upper16:\word
.endm

/*
 * Pseudo-op for PC relative adr <reg>, <symbol> where <symbol> is
 * within the range +/- 4GB of the PC.
 *
 * @dst: destination register
 * @sym: name of the symbol
 */
.macro adr_l, dst, sym
        mov_w \dst, \sym - .Lpc\@
        .set  .Lpc\@, .+ 8          /* PC bias */
        add   \dst, \dst, pc
.endm

#ifdef CONFIG_EARLY_PRINTK
/*
 * Macro to print a string to the UART, if there is one.
 *
 * Clobbers r0 - r3
 */
#define PRINT(_s)           \
        mov   r3, lr       ;\
        adr_l r0, 98f      ;\
        bl    asm_puts     ;\
        mov   lr, r3       ;\
        RODATA_STR(98, _s)

/*
 * Macro to print the value of register \rb
 *
 * Clobbers r0 - r4
 */
.macro print_reg rb
        mov   r0, \rb
        mov   r4, lr
        bl    asm_putn
        mov   lr, r4
.endm

#else /* CONFIG_EARLY_PRINTK */
#define PRINT(s)

.macro print_reg rb
.endm

#endif /* !CONFIG_EARLY_PRINTK */

#endif /* __ASM_ARM_ARM32_MACROS_H */
