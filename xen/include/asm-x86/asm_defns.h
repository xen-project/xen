
#ifndef __X86_ASM_DEFNS_H__
#define __X86_ASM_DEFNS_H__

/* NB. Auto-generated from arch/.../asm-offsets.c */
#include <asm/asm-offsets.h>
#include <asm/processor.h>

#ifdef __x86_64__
#include <asm/x86_64/asm_defns.h>
#else
#include <asm/x86_32/asm_defns.h>
#endif

#ifdef __ASSEMBLY__

#define UNLIKELY_START(cond, tag) \
        j##cond .Lunlikely.tag;   \
        .subsection 1;            \
        .Lunlikely.tag:

#define UNLIKELY_END(tag)         \
        jmp .Llikely.tag;         \
        .subsection 0;            \
        .Llikely.tag:

#endif

#endif /* __X86_ASM_DEFNS_H__ */
