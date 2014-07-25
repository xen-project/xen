#ifndef __ASM_ASSEMBLER_H__
#define __ASM_ASSEMBLER_H__

#ifndef __ASSEMBLY__
#error "Only include this from assembly code"
#endif

/* Only LE support so far */
#define CPU_BE(x...)
#define CPU_LE(x...) x

#endif /* __ASM_ASSEMBLER_H__ */
