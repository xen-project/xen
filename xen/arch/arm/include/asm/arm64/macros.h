#ifndef __ASM_ARM_ARM64_MACROS_H
#define __ASM_ARM_ARM64_MACROS_H

    /*
     * @dst: Result of get_cpu_info()
     */
    .macro  adr_cpu_info, dst
    add     \dst, sp, #STACK_SIZE
    and     \dst, \dst, #~(STACK_SIZE - 1)
    sub     \dst, \dst, #CPUINFO_sizeof
    .endm

    /*
     * @dst: Result of READ_ONCE(per_cpu(sym, smp_processor_id()))
     * @sym: The name of the per-cpu variable
     * @tmp: scratch register
     */
    .macro  ldr_this_cpu, dst, sym, tmp
    ldr     \dst, =per_cpu__\sym
    mrs     \tmp, tpidr_el2
    ldr     \dst, [\dst, \tmp]
    .endm

    .macro  ret
        /* ret opcode */
        .inst 0xd65f03c0
        sb
    .endm

    /* clearbhb instruction clearing the branch history */
    .macro clearbhb
        hint    #22
    .endm

#ifdef CONFIG_EARLY_PRINTK
/*
 * Macros to print a string to the UART, if there is one.
 *
 * There are multiple flavors:
 *  - PRINT_SECT(section, string): The @string will be located in @section
 *  - PRINT(): The string will be located in .rodata.str.
 *  - PRINT_ID(): This will create the string in .rodata.idmap which
 *    will always be accessible. This is used when:
 *      - Xen is running on the identity mapping because not all of Xen is mapped
 *      - Running with the MMU-off on secondary CPUs as Xen may not be
 *        physically contiguous in memory (e.g. in the case of cache
 *        coloring).
 *
 * Clobbers x0 - x3
 */
#define PRINT_SECT(section, string)         \
        mov   x3, lr                       ;\
        adr_l x0, 98f                      ;\
        bl    asm_puts                     ;\
        mov   lr, x3                       ;\
        RODATA_SECT(section, 98, string)

#define PRINT(string) PRINT_SECT(.rodata.str, string)
#define PRINT_ID(string) PRINT_SECT(.rodata.idmap, string)

/*
 * Macro to print the value of register \xb
 *
 * Clobbers x0 - x4
 */
.macro print_reg xb
        mov   x0, \xb
        mov   x4, lr
        bl    asm_putn
        mov   lr, x4
.endm

#else /* CONFIG_EARLY_PRINTK */
#define PRINT(s)
#define PRINT_ID(s)

.macro print_reg xb
.endm

#endif /* !CONFIG_EARLY_PRINTK */

/*
 * Pseudo-op for PC relative adr <reg>, <symbol> where <symbol> is
 * within the range +/- 4GB of the PC.
 *
 * @dst: destination register (64 bit wide)
 * @sym: name of the symbol
 */
.macro  adr_l, dst, sym
        adrp \dst, \sym
        add  \dst, \dst, :lo12:\sym
.endm

/*
 * Register aliases.
 */
lr      .req    x30             /* link register */

#endif /* __ASM_ARM_ARM64_MACROS_H */

