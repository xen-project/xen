#ifndef __X86_64_ASM_DEFNS_H__
#define __X86_64_ASM_DEFNS_H__

/* Maybe auto-generate the following two cases (quoted vs. unquoted). */
#ifndef __ASSEMBLY__

#define SAVE_ALL \
        "cld;" \
        "pushq %rdi;" \
        "pushq %rsi;" \
        "pushq %rdx;" \
        "pushq %rcx;" \
        "pushq %rax;" \
        "pushq %r8;" \
        "pushq %r9;" \
        "pushq %r10;" \
        "pushq %r11;" \
        "pushq %rbx;" \
        "pushq %rbp;" \
        "pushq %r12;" \
        "pushq %r13;" \
        "pushq %r14;" \
        "pushq %r15;"

#define RESTORE_ALL \
        "popq  %r15;" \
        "popq  %r14;" \
        "popq  %r13;" \
        "popq  %r12;" \
        "popq  %rbp;" \
        "popq  %rbx;" \
        "popq  %r11;" \
        "popq  %r10;" \
        "popq  %r9;" \
        "popq  %r8;" \
        "popq  %rax;" \
        "popq  %rcx;" \
        "popq  %rdx;" \
        "popq  %rsi;" \
        "popq  %rdi;"

#else

#define SAVE_ALL \
        cld; \
        pushq %rdi; \
        pushq %rsi; \
        pushq %rdx; \
        pushq %rcx; \
        pushq %rax; \
        pushq %r8; \
        pushq %r9; \
        pushq %r10; \
        pushq %r11; \
        pushq %rbx; \
        pushq %rbp; \
        pushq %r12; \
        pushq %r13; \
        pushq %r14; \
        pushq %r15;

#define RESTORE_ALL \
        popq  %r15; \
        popq  %r14; \
        popq  %r13; \
        popq  %r12; \
        popq  %rbp; \
        popq  %rbx; \
        popq  %r11; \
        popq  %r10; \
        popq  %r9; \
        popq  %r8; \
        popq  %rax; \
        popq  %rcx; \
        popq  %rdx; \
        popq  %rsi; \
        popq  %rdi;

#ifdef PERF_COUNTERS
#define PERFC_INCR(_name,_idx) \
    pushq %rdx; \
    leaq SYMBOL_NAME(perfcounters)+_name(%rip),%rdx; \
    lock incl (%rdx,_idx,4); \
    popq %rdx;
#else
#define PERFC_INCR(_name,_idx)
#endif

#endif

#define BUILD_SMP_INTERRUPT(x,v) XBUILD_SMP_INTERRUPT(x,v)
#define XBUILD_SMP_INTERRUPT(x,v)\
asmlinkage void x(void); \
__asm__( \
    "\n"__ALIGN_STR"\n" \
    SYMBOL_NAME_STR(x) ":\n\t" \
    "pushq $0\n\t" \
    "movl $"#v",4(%rsp)\n\t" \
    SAVE_ALL \
    "callq "SYMBOL_NAME_STR(smp_##x)"\n\t" \
    "jmp ret_from_intr\n");

#define BUILD_SMP_TIMER_INTERRUPT(x,v) XBUILD_SMP_TIMER_INTERRUPT(x,v)
#define XBUILD_SMP_TIMER_INTERRUPT(x,v) \
asmlinkage void x(struct xen_regs * regs); \
__asm__( \
"\n"__ALIGN_STR"\n" \
SYMBOL_NAME_STR(x) ":\n\t" \
    "pushq $0\n\t" \
    "movl $"#v",4(%rsp)\n\t" \
    SAVE_ALL \
    "movq %rsp,%rdi\n\t" \
    "callq "SYMBOL_NAME_STR(smp_##x)"\n\t" \
    "jmp ret_from_intr\n");

#define BUILD_COMMON_IRQ() \
__asm__( \
    "\n" __ALIGN_STR"\n" \
    "common_interrupt:\n\t" \
    SAVE_ALL \
    "movq %rsp,%rdi\n\t" \
    "callq " SYMBOL_NAME_STR(do_IRQ) "\n\t" \
    "jmp ret_from_intr\n");

#define IRQ_NAME2(nr) nr##_interrupt(void)
#define IRQ_NAME(nr) IRQ_NAME2(IRQ##nr)

#define BUILD_IRQ(nr) \
asmlinkage void IRQ_NAME(nr); \
__asm__( \
"\n"__ALIGN_STR"\n" \
SYMBOL_NAME_STR(IRQ) #nr "_interrupt:\n\t" \
    "pushq $0\n\t" \
    "movl $"#nr",4(%rsp)\n\t" \
    "jmp common_interrupt");

#endif /* __X86_64_ASM_DEFNS_H__ */
