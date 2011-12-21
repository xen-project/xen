
#ifndef __X86_ASM_DEFNS_H__
#define __X86_ASM_DEFNS_H__

#ifndef COMPILE_OFFSETS
/* NB. Auto-generated from arch/.../asm-offsets.c */
#include <asm/asm-offsets.h>
#endif
#include <asm/processor.h>

#ifndef __ASSEMBLY__
void ret_from_intr(void);
#endif

#ifdef __x86_64__
#include <asm/x86_64/asm_defns.h>
#else
#include <asm/x86_32/asm_defns.h>
#endif

/* Exception table entry */
#ifdef __ASSEMBLY__
# define _ASM__EXTABLE(sfx, from, to)             \
    .section .ex_table##sfx, "a" ;                \
    .balign 4 ;                                   \
    .long _ASM_EX(from), _ASM_EX(to) ;            \
    .previous
#else
# define _ASM__EXTABLE(sfx, from, to)             \
    " .section .ex_table" #sfx ",\"a\"\n"         \
    " .balign 4\n"                                \
    " .long " _ASM_EX(from) ", " _ASM_EX(to) "\n" \
    " .previous\n"
#endif

#define _ASM_EXTABLE(from, to)     _ASM__EXTABLE(, from, to)
#define _ASM_PRE_EXTABLE(from, to) _ASM__EXTABLE(.pre, from, to)

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
