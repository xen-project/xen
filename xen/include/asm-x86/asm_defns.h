
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

#include <asm/x86_64/asm_defns.h>

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
        .Ldispatch.tag:           \
        j##cond .Lunlikely.tag;   \
        .subsection 1;            \
        .Lunlikely.tag:

#define UNLIKELY_DISPATCH_LABEL(tag) \
        .Ldispatch.tag

#define UNLIKELY_DONE(cond, tag)  \
        j##cond .Llikely.tag

#define __UNLIKELY_END(tag)       \
        .subsection 0;            \
        .Llikely.tag:

#define UNLIKELY_END(tag)         \
        UNLIKELY_DONE(mp, tag);   \
        __UNLIKELY_END(tag)

#define STACK_CPUINFO_FIELD(field) (STACK_SIZE-CPUINFO_sizeof+CPUINFO_##field)
#define GET_STACK_BASE(reg)                       \
        movq $~(STACK_SIZE-1),reg;                \
        andq %rsp,reg

#define GET_CPUINFO_FIELD(field, reg)             \
        GET_STACK_BASE(reg);                      \
        addq $STACK_CPUINFO_FIELD(field),reg

#define __GET_CURRENT(reg)                        \
        movq STACK_CPUINFO_FIELD(current_vcpu)(reg),reg
#define GET_CURRENT(reg)                          \
        GET_STACK_BASE(reg);                      \
        __GET_CURRENT(reg)

#ifndef NDEBUG
#define ASSERT_NOT_IN_ATOMIC                                             \
    sti; /* sometimes called with interrupts disabled: safe to enable */ \
    call ASSERT_NOT_IN_ATOMIC
#else
#define ASSERT_NOT_IN_ATOMIC
#endif

#else

#ifdef __clang__ /* clang's builtin assember can't do .subsection */

#define UNLIKELY_START_SECTION ".pushsection .fixup,\"ax\""
#define UNLIKELY_END_SECTION   ".popsection"

#else

#define UNLIKELY_START_SECTION ".subsection 1"
#define UNLIKELY_END_SECTION   ".subsection 0"

#endif

#define UNLIKELY_START(cond, tag)          \
        "j" #cond " .Lunlikely%=.tag;\n\t" \
        UNLIKELY_START_SECTION "\n"        \
        ".Lunlikely%=.tag:"

#define UNLIKELY_END(tag)                  \
        "jmp .Llikely%=.tag;\n\t"          \
        UNLIKELY_END_SECTION "\n"          \
        ".Llikely%=.tag:"

#endif

#endif /* __X86_ASM_DEFNS_H__ */
