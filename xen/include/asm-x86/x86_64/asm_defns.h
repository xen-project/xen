#ifndef __X86_64_ASM_DEFNS_H__
#define __X86_64_ASM_DEFNS_H__

#include <asm/percpu.h>

#ifdef CONFIG_FRAME_POINTER
/* Indicate special exception stack frame by inverting the frame pointer. */
#define SETUP_EXCEPTION_FRAME_POINTER           \
        movq  %rsp,%rbp;                        \
        notq  %rbp
#else
#define SETUP_EXCEPTION_FRAME_POINTER
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
        cld;                                    \
        pushq %rdi;                             \
        pushq %rsi;                             \
        pushq %rdx;                             \
        pushq %rcx;                             \
        pushq %rax;                             \
        pushq %r8;                              \
        pushq %r9;                              \
        pushq %r10;                             \
        pushq %r11;                             \
        pushq %rbx;                             \
        pushq %rbp;                             \
        SETUP_EXCEPTION_FRAME_POINTER;          \
        pushq %r12;                             \
        pushq %r13;                             \
        pushq %r14;                             \
        pushq %r15;

#define RESTORE_ALL                             \
        popq  %r15;                             \
        popq  %r14;                             \
        popq  %r13;                             \
        popq  %r12;                             \
        popq  %rbp;                             \
        popq  %rbx;                             \
        popq  %r11;                             \
        popq  %r10;                             \
        popq  %r9;                              \
        popq  %r8;                              \
        popq  %rax;                             \
        popq  %rcx;                             \
        popq  %rdx;                             \
        popq  %rsi;                             \
        popq  %rdi;

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
    STR(SAVE_ALL)                               \
    "movq %rsp,%rdi\n\t"                        \
    "callq " STR(do_IRQ) "\n\t"                 \
    "jmp ret_from_intr\n");

#define IRQ_NAME2(nr) nr##_interrupt(void)
#define IRQ_NAME(nr) IRQ_NAME2(IRQ##nr)

#define BUILD_IRQ(nr)                           \
void IRQ_NAME(nr);                   \
__asm__(                                        \
"\n"__ALIGN_STR"\n"                             \
STR(IRQ) #nr "_interrupt:\n\t"                  \
    "pushq $0\n\t"                              \
    "movl $"#nr",4(%rsp)\n\t"                   \
    "jmp common_interrupt");

#define GET_CPUINFO_FIELD(field,reg)                    \
        movq $~(STACK_SIZE-1),reg;                      \
        andq %rsp,reg;                                  \
        orq  $(STACK_SIZE-CPUINFO_sizeof+field),reg;
#define GET_CURRENT(reg)                                \
        GET_CPUINFO_FIELD(CPUINFO_current_vcpu,reg)     \
        movq (reg),reg;

#ifdef __ASSEMBLY__
# define _ASM_EX(p) p-.
#else
# define _ASM_EX(p) #p "-."
#endif

#endif /* __X86_64_ASM_DEFNS_H__ */
