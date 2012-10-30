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
.macro LOAD_C_CLOBBERED
        movq  UREGS_r11(%rsp),%r11
        movq  UREGS_r10(%rsp),%r10
        movq  UREGS_r9(%rsp),%r9
        movq  UREGS_r8(%rsp),%r8
        movq  UREGS_rax(%rsp),%rax
        movq  UREGS_rcx(%rsp),%rcx
        movq  UREGS_rdx(%rsp),%rdx
        movq  UREGS_rsi(%rsp),%rsi
        movq  UREGS_rdi(%rsp),%rdi
.endm

.macro RESTORE_ALL adj=0
        movq  UREGS_r15(%rsp),%r15
        movq  UREGS_r14(%rsp),%r14
        movq  UREGS_r13(%rsp),%r13
        movq  UREGS_r12(%rsp),%r12
        movq  UREGS_rbp(%rsp),%rbp
        movq  UREGS_rbx(%rsp),%rbx
        LOAD_C_CLOBBERED
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
