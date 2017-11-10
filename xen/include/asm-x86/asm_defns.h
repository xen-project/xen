
#ifndef __X86_ASM_DEFNS_H__
#define __X86_ASM_DEFNS_H__

#ifndef COMPILE_OFFSETS
/* NB. Auto-generated from arch/.../asm-offsets.c */
#include <asm/asm-offsets.h>
#endif
#include <asm/bug.h>
#include <asm/processor.h>
#include <asm/percpu.h>
#include <xen/stringify.h>
#include <asm/cpufeature.h>
#include <asm/alternative.h>

#ifndef __ASSEMBLY__
void ret_from_intr(void);
#endif

#ifdef CONFIG_FRAME_POINTER
/* Indicate special exception stack frame by inverting the frame pointer. */
#define SETUP_EXCEPTION_FRAME_POINTER(offs)     \
        leaq  offs(%rsp),%rbp;                  \
        notq  %rbp
#else
#define SETUP_EXCEPTION_FRAME_POINTER(offs)
#endif

#ifndef NDEBUG
#define ASSERT_INTERRUPT_STATUS(x, msg)         \
        pushf;                                  \
        testb $X86_EFLAGS_IF>>8,1(%rsp);        \
        j##x  1f;                               \
        ASSERT_FAILED(msg);                     \
1:      addq  $8,%rsp;
#else
#define ASSERT_INTERRUPT_STATUS(x, msg)
#endif

#define ASSERT_INTERRUPTS_ENABLED \
    ASSERT_INTERRUPT_STATUS(nz, "INTERRUPTS ENABLED")
#define ASSERT_INTERRUPTS_DISABLED \
    ASSERT_INTERRUPT_STATUS(z, "INTERRUPTS DISABLED")

/*
 * This flag is set in an exception frame when registers R12-R15 did not get
 * saved.
 */
#define _TRAP_regs_partial 16
#define TRAP_regs_partial  (1 << _TRAP_regs_partial)
/*
 * This flag gets set in an exception frame when registers R12-R15 possibly
 * get modified from their originally saved values and hence need to be
 * restored even if the normal call flow would restore register values.
 *
 * The flag being set implies _TRAP_regs_partial to be unset. Restoring
 * R12-R15 thus is
 * - required when this flag is set,
 * - safe when _TRAP_regs_partial is unset.
 */
#define _TRAP_regs_dirty   17
#define TRAP_regs_dirty    (1 << _TRAP_regs_dirty)

#define mark_regs_dirty(r) ({ \
        struct cpu_user_regs *r__ = (r); \
        ASSERT(!((r__)->entry_vector & TRAP_regs_partial)); \
        r__->entry_vector |= TRAP_regs_dirty; \
})

#ifdef __ASSEMBLY__
# define _ASM_EX(p) p-.
#else
# define _ASM_EX(p) #p "-."
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

#ifdef HAVE_GAS_QUOTED_SYM
#define SUBSECTION_LBL(tag)                        \
        .ifndef .L.tag;                            \
        .equ .L.tag, 1;                            \
        .equ __stringify(__OBJECT_LABEL__.tag), .; \
        .endif
#else
#define SUBSECTION_LBL(tag)                        \
        .ifndef __OBJECT_LABEL__.tag;              \
        __OBJECT_LABEL__.tag:;                     \
        .endif
#endif

#define UNLIKELY_START(cond, tag) \
        .Ldispatch.tag:           \
        j##cond .Lunlikely.tag;   \
        .subsection 1;            \
        SUBSECTION_LBL(unlikely); \
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

#define STACK_CPUINFO_FIELD(field) (1 - CPUINFO_sizeof + CPUINFO_##field)
#define GET_STACK_END(reg)                        \
        movl $STACK_SIZE-1, %e##reg;              \
        orq  %rsp, %r##reg

#define GET_CPUINFO_FIELD(field, reg)             \
        GET_STACK_END(reg);                       \
        addq $STACK_CPUINFO_FIELD(field), %r##reg

#define __GET_CURRENT(reg)                        \
        movq STACK_CPUINFO_FIELD(current_vcpu)(%r##reg), %r##reg
#define GET_CURRENT(reg)                          \
        GET_STACK_END(reg);                       \
        __GET_CURRENT(reg)

#ifndef NDEBUG
#define ASSERT_NOT_IN_ATOMIC                                             \
    sti; /* sometimes called with interrupts disabled: safe to enable */ \
    call ASSERT_NOT_IN_ATOMIC
#else
#define ASSERT_NOT_IN_ATOMIC
#endif

#define CPUINFO_FEATURE_OFFSET(feature)           \
    (CPUINFO_features + (cpufeat_word(feature) * 4))

#else

#ifdef HAVE_GAS_QUOTED_SYM
#define SUBSECTION_LBL(tag)                                          \
        ".ifndef .L." #tag "\n\t"                                    \
        ".equ .L." #tag ", 1\n\t"                                    \
        ".equ \"" __stringify(__OBJECT_LABEL__) "." #tag "\", .\n\t" \
        ".endif"
#else
#define SUBSECTION_LBL(tag)                                          \
        ".ifndef " __stringify(__OBJECT_LABEL__) "." #tag "\n\t"     \
        __stringify(__OBJECT_LABEL__) "." #tag ":\n\t"               \
        ".endif"
#endif

#ifdef __clang__ /* clang's builtin assember can't do .subsection */

#define UNLIKELY_START_SECTION ".pushsection .text.unlikely,\"ax\""
#define UNLIKELY_END_SECTION   ".popsection"

#else

#define UNLIKELY_START_SECTION ".subsection 1"
#define UNLIKELY_END_SECTION   ".subsection 0"

#endif

#define UNLIKELY_START(cond, tag)                   \
        "j" #cond " .Lunlikely." #tag ".%=;\n\t"   \
        UNLIKELY_START_SECTION "\n\t"               \
        SUBSECTION_LBL(unlikely) "\n"               \
        ".Lunlikely." #tag ".%=:"

#define UNLIKELY_END(tag)                  \
        "jmp .Llikely." #tag ".%=;\n\t"    \
        UNLIKELY_END_SECTION "\n"          \
        ".Llikely." #tag ".%=:"

#endif

/* "Raw" instruction opcodes */
#define __ASM_CLAC      .byte 0x0f,0x01,0xca
#define __ASM_STAC      .byte 0x0f,0x01,0xcb

#ifdef __ASSEMBLY__
#define ASM_AC(op)                                                     \
        661: ASM_NOP3;                                                 \
        .pushsection .altinstr_replacement, "ax";                      \
        662: __ASM_##op;                                               \
        .popsection;                                                   \
        .pushsection .altinstructions, "a";                            \
        altinstruction_entry 661b, 661b, X86_FEATURE_ALWAYS, 3, 0;     \
        altinstruction_entry 661b, 662b, X86_FEATURE_XEN_SMAP, 3, 3;       \
        .popsection

#define ASM_STAC ASM_AC(STAC)
#define ASM_CLAC ASM_AC(CLAC)

#define CR4_PV32_RESTORE                                           \
        667: ASM_NOP5;                                             \
        .pushsection .altinstr_replacement, "ax";                  \
        668: call cr4_pv32_restore;                                \
        .section .altinstructions, "a";                            \
        altinstruction_entry 667b, 667b, X86_FEATURE_ALWAYS, 5, 0; \
        altinstruction_entry 667b, 668b, X86_FEATURE_XEN_SMEP, 5, 5;   \
        altinstruction_entry 667b, 668b, X86_FEATURE_XEN_SMAP, 5, 5;   \
        .popsection

#else
static always_inline void clac(void)
{
    /* Note: a barrier is implicit in alternative() */
    alternative(ASM_NOP3, __stringify(__ASM_CLAC), X86_FEATURE_XEN_SMAP);
}

static always_inline void stac(void)
{
    /* Note: a barrier is implicit in alternative() */
    alternative(ASM_NOP3, __stringify(__ASM_STAC), X86_FEATURE_XEN_SMAP);
}
#endif

#ifdef __ASSEMBLY__
.macro SAVE_ALL op
.ifeqs "\op", "CLAC"
        ASM_CLAC
.else
.ifeqs "\op", "STAC"
        ASM_STAC
.else
.ifnb \op
        .err
.endif
.endif
.endif
        addq  $-(UREGS_error_code-UREGS_r15), %rsp
        cld
        movq  %rdi,UREGS_rdi(%rsp)
        movq  %rsi,UREGS_rsi(%rsp)
        movq  %rdx,UREGS_rdx(%rsp)
        movq  %rcx,UREGS_rcx(%rsp)
        movq  %rax,UREGS_rax(%rsp)
        movq  %r8,UREGS_r8(%rsp)
        movq  %r9,UREGS_r9(%rsp)
        movq  %r10,UREGS_r10(%rsp)
        movq  %r11,UREGS_r11(%rsp)
        movq  %rbx,UREGS_rbx(%rsp)
        movq  %rbp,UREGS_rbp(%rsp)
        SETUP_EXCEPTION_FRAME_POINTER(UREGS_rbp)
        movq  %r12,UREGS_r12(%rsp)
        movq  %r13,UREGS_r13(%rsp)
        movq  %r14,UREGS_r14(%rsp)
        movq  %r15,UREGS_r15(%rsp)
.endm

/*
 * Save all registers not preserved by C code or used in entry/exit code. Mark
 * the frame as partial.
 *
 * @type: exception type
 * @compat: R8-R15 don't need saving, and the frame nevertheless is complete
 */
.macro SAVE_VOLATILE type compat=0
.if \compat
        movl  $\type,UREGS_entry_vector-UREGS_error_code(%rsp)
.else
        movl  $\type|TRAP_regs_partial,\
              UREGS_entry_vector-UREGS_error_code(%rsp)
.endif
        addq  $-(UREGS_error_code-UREGS_r15),%rsp
        cld
        movq  %rdi,UREGS_rdi(%rsp)
        movq  %rsi,UREGS_rsi(%rsp)
        movq  %rdx,UREGS_rdx(%rsp)
        movq  %rcx,UREGS_rcx(%rsp)
        movq  %rax,UREGS_rax(%rsp)
.if !\compat
        movq  %r8,UREGS_r8(%rsp)
        movq  %r9,UREGS_r9(%rsp)
        movq  %r10,UREGS_r10(%rsp)
        movq  %r11,UREGS_r11(%rsp)
.endif
        movq  %rbx,UREGS_rbx(%rsp)
        movq  %rbp,UREGS_rbp(%rsp)
        SETUP_EXCEPTION_FRAME_POINTER(UREGS_rbp)
.endm

/*
 * Complete a frame potentially only partially saved.
 */
.macro SAVE_PRESERVED
        btrl  $_TRAP_regs_partial,UREGS_entry_vector(%rsp)
        jnc   987f
        movq  %r12,UREGS_r12(%rsp)
        movq  %r13,UREGS_r13(%rsp)
        movq  %r14,UREGS_r14(%rsp)
        movq  %r15,UREGS_r15(%rsp)
987:
.endm

#define LOAD_ONE_REG(reg, compat) \
.if !(compat); \
        movq  UREGS_r##reg(%rsp),%r##reg; \
.else; \
        movl  UREGS_r##reg(%rsp),%e##reg; \
.endif

/*
 * Restore all previously saved registers.
 *
 * @adj: extra stack pointer adjustment to be folded into the adjustment done
 *       anyway at the end of the macro
 * @compat: R8-R15 don't need reloading, but they are clobbered for added
 *          safety against information leaks.
 */
.macro RESTORE_ALL adj=0 compat=0
.if !\compat
        testl $TRAP_regs_dirty,UREGS_entry_vector(%rsp)
        movq  UREGS_r11(%rsp),%r11
        movq  UREGS_r10(%rsp),%r10
        movq  UREGS_r9(%rsp),%r9
        movq  UREGS_r8(%rsp),%r8
.else
        xor %r11, %r11
        xor %r10, %r10
        xor %r9, %r9
        xor %r8, %r8
.endif
        LOAD_ONE_REG(ax, \compat)
        LOAD_ONE_REG(cx, \compat)
        LOAD_ONE_REG(dx, \compat)
        LOAD_ONE_REG(si, \compat)
        LOAD_ONE_REG(di, \compat)
.if !\compat
        jz    987f
        movq  UREGS_r15(%rsp),%r15
        movq  UREGS_r14(%rsp),%r14
        movq  UREGS_r13(%rsp),%r13
        movq  UREGS_r12(%rsp),%r12
#ifndef NDEBUG
        .subsection 1
987:    testl $TRAP_regs_partial,UREGS_entry_vector(%rsp)
        jnz   987f
        cmpq  UREGS_r15(%rsp),%r15
        jne   789f
        cmpq  UREGS_r14(%rsp),%r14
        jne   789f
        cmpq  UREGS_r13(%rsp),%r13
        jne   789f
        cmpq  UREGS_r12(%rsp),%r12
        je    987f
789:    BUG   /* Corruption of partial register state. */
        .subsection 0
#endif
.else
        xor %r15, %r15
        xor %r14, %r14
        xor %r13, %r13
        xor %r12, %r12
.endif
987:
        LOAD_ONE_REG(bp, \compat)
        LOAD_ONE_REG(bx, \compat)
        subq  $-(UREGS_error_code-UREGS_r15+\adj), %rsp
.endm

#endif

#ifdef CONFIG_PERF_COUNTERS
#define PERFC_INCR(_name,_idx,_cur)             \
        pushq _cur;                             \
        movslq VCPU_processor(_cur),_cur;       \
        pushq %rdx;                             \
        leaq __per_cpu_offset(%rip),%rdx;       \
        movq (%rdx,_cur,8),_cur;                \
        leaq per_cpu__perfcounters(%rip),%rdx;  \
        addq %rdx,_cur;                         \
        popq %rdx;                              \
        incl ASM_PERFC_##_name*4(_cur,_idx,4);  \
        popq _cur
#else
#define PERFC_INCR(_name,_idx,_cur)
#endif

/* Work around AMD erratum #88 */
#define safe_swapgs                             \
        "mfence; swapgs;"

#ifdef __sun__
#define REX64_PREFIX "rex64\\"
#elif defined(__clang__)
#define REX64_PREFIX ".byte 0x48; "
#else
#define REX64_PREFIX "rex64/"
#endif

#define ELFNOTE(name, type, desc)           \
    .pushsection .note.name, "a", @note   ; \
    .p2align 2                            ; \
    .long 2f - 1f       /* namesz */      ; \
    .long 4f - 3f       /* descsz */      ; \
    .long type          /* type   */      ; \
1:  .asciz #name        /* name   */      ; \
2:  .p2align 2                            ; \
3:  desc                /* desc   */      ; \
4:  .p2align 2                            ; \
    .popsection

#endif /* __X86_ASM_DEFNS_H__ */
