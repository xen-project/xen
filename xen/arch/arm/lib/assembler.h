#ifndef __ARCH_ARM_LIB_ASSEMBLER_H__
#define __ARCH_ARM_LIB_ASSEMBLER_H__

/* From Linux arch/arm/include/asm/assembler.h */
/*
 * Data preload for architectures that support it
 */
#define PLD(code...)    code

/*
 * This can be used to enable code to cacheline align the destination
 * pointer when bulk writing to memory.  Experiments on StrongARM and
 * XScale didn't show this a worthwhile thing to do when the cache is not
 * set to write-allocate (this would need further testing on XScale when WA
 * is used).
 *
 * On Feroceon there is much to gain however, regardless of cache mode.
 */
#ifdef CONFIG_CPU_FEROCEON /* Not in Xen... */
#define CALGN(code...) code
#else
#define CALGN(code...)
#endif

// No Thumb, hence:
#define W(instr)        instr
#define ARM(instr...)   instr
#define THUMB(instr...)

#ifdef CONFIG_ARM_UNWIND
#define UNWIND(code...)         code
#else
#define UNWIND(code...)
#endif

#define pull            lsl
#define push            lsr
#define get_byte_0      lsr #24
#define get_byte_1      lsr #16
#define get_byte_2      lsr #8
#define get_byte_3      lsl #0
#define put_byte_0      lsl #24
#define put_byte_1      lsl #16
#define put_byte_2      lsl #8
#define put_byte_3      lsl #0

#define smp_dmb dmb

#endif /*  __ARCH_ARM_LIB_ASSEMBLER_H__ */
