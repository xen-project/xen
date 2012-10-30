#ifndef __X86_64_ASM_DEFNS_H__
#define __X86_64_ASM_DEFNS_H__

#include <asm/percpu.h>

#ifdef CONFIG_FRAME_POINTER
/* Indicate special exception stack frame by inverting the frame pointer. */
#define SETUP_EXCEPTION_FRAME_POINTER(offs)     \
        leaq  offs(%rsp),%rbp;                  \
        notq  %rbp
#else
#define SETUP_EXCEPTION_FRAME_POINTER(offs)
#endif

#ifndef NDEBUG
#define ASSERT_INTERRUPT_STATUS(x)              \
        pushf;                                  \
        testb $X86_EFLAGS_IF>>8,1(%rsp);        \
        j##x  1f;                               \
        ud2a;                                   \
1:      addq  $8,%rsp;
#else
#define ASSERT_INTERRUPT_STATUS(x)
#endif

#define ASSERT_INTERRUPTS_ENABLED  ASSERT_INTERRUPT_STATUS(nz)
#define ASSERT_INTERRUPTS_DISABLED ASSERT_INTERRUPT_STATUS(z)

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

#define SAVE_ALL                                \
        addq  $-(UREGS_error_code-UREGS_r15), %rsp; \
        cld;                                    \
        movq  %rdi,UREGS_rdi(%rsp);             \
        movq  %rsi,UREGS_rsi(%rsp);             \
        movq  %rdx,UREGS_rdx(%rsp);             \
        movq  %rcx,UREGS_rcx(%rsp);             \
        movq  %rax,UREGS_rax(%rsp);             \
        movq  %r8,UREGS_r8(%rsp);               \
        movq  %r9,UREGS_r9(%rsp);               \
        movq  %r10,UREGS_r10(%rsp);             \
        movq  %r11,UREGS_r11(%rsp);             \
        movq  %rbx,UREGS_rbx(%rsp);             \
        movq  %rbp,UREGS_rbp(%rsp);             \
        SETUP_EXCEPTION_FRAME_POINTER(UREGS_rbp); \
        movq  %r12,UREGS_r12(%rsp);             \
        movq  %r13,UREGS_r13(%rsp);             \
        movq  %r14,UREGS_r14(%rsp);             \
        movq  %r15,UREGS_r15(%rsp);             \

#ifdef __ASSEMBLY__

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

/*
 * Reload registers not preserved by C code from frame.
 *
 * @compat: R8-R11 don't need reloading
 *
 * For the way it is used in RESTORE_ALL, this macro must preserve EFLAGS.ZF.
 */
.macro LOAD_C_CLOBBERED compat=0
.if !\compat
        movq  UREGS_r11(%rsp),%r11
        movq  UREGS_r10(%rsp),%r10
        movq  UREGS_r9(%rsp),%r9
        movq  UREGS_r8(%rsp),%r8
.endif
        movq  UREGS_rax(%rsp),%rax
        movq  UREGS_rcx(%rsp),%rcx
        movq  UREGS_rdx(%rsp),%rdx
        movq  UREGS_rsi(%rsp),%rsi
        movq  UREGS_rdi(%rsp),%rdi
.endm

/*
 * Restore all previously saved registers.
 *
 * @adj: extra stack pointer adjustment to be folded into the adjustment done
 *       anyway at the end of the macro
 * @compat: R8-R15 don't need reloading
 */
.macro RESTORE_ALL adj=0 compat=0
.if !\compat
        testl $TRAP_regs_dirty,UREGS_entry_vector(%rsp)
.endif
        LOAD_C_CLOBBERED \compat
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
789:    ud2
        .subsection 0
#endif
.endif
987:    movq  UREGS_rbp(%rsp),%rbp
        movq  UREGS_rbx(%rsp),%rbx
        subq  $-(UREGS_error_code-UREGS_r15+\adj), %rsp
.endm

#endif

#ifdef PERF_COUNTERS
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

#define BUILD_COMMON_IRQ()                      \
__asm__(                                        \
    "\n" __ALIGN_STR"\n"                        \
    "common_interrupt:\n\t"                     \
    STR(SAVE_ALL) "\n\t"                        \
    "movq %rsp,%rdi\n\t"                        \
    "callq " STR(do_IRQ) "\n\t"                 \
    "jmp ret_from_intr\n");

#define BUILD_IRQ(nr)                           \
    "pushq $0\n\t"                              \
    "movl $"#nr",4(%rsp)\n\t"                   \
    "jmp common_interrupt"

#ifdef __ASSEMBLY__
# define _ASM_EX(p) p-.
#else
# define _ASM_EX(p) #p "-."
#endif

#endif /* __X86_64_ASM_DEFNS_H__ */
