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

/*
 * Register aliases.
 */
lr      .req    x30             /* link register */

#endif /* __ASM_ARM_ARM64_MACROS_H */

