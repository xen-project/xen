#ifndef __X86_32_ASM_DEFNS_H__
#define __X86_32_ASM_DEFNS_H__

/* Maybe auto-generate the following two cases (quoted vs. unquoted). */
#ifndef __ASSEMBLY__

#define __SAVE_ALL_PRE \
        "cld;" \
        "pushl %eax;" \
        "pushl %ebp;" \
        "pushl %edi;" \
        "pushl %esi;" \
        "pushl %edx;" \
        "pushl %ecx;" \
        "pushl %ebx;" \
        "testl $"STR(X86_EFLAGS_VM)","STR(XREGS_eflags)"(%esp);" \
        "jz 2f;" \
        "call setup_vm86_frame;" \
        "jmp 3f;" \
        "2:testb $3,"STR(XREGS_cs)"(%esp);" \
        "jz 1f;" \
        "movl %ds,"STR(XREGS_ds)"(%esp);" \
        "movl %es,"STR(XREGS_es)"(%esp);" \
        "movl %fs,"STR(XREGS_fs)"(%esp);" \
        "movl %gs,"STR(XREGS_gs)"(%esp);" \
        "3:"

#define SAVE_ALL_NOSEGREGS(_reg) \
        __SAVE_ALL_PRE \
        "1:"

#define SET_XEN_SEGMENTS(_reg) \
        "movl $("STR(__HYPERVISOR_DS)"),%e"STR(_reg)"x;" \
        "movl %e"STR(_reg)"x,%ds;" \
        "movl %e"STR(_reg)"x,%es;"

#define SAVE_ALL(_reg) \
        __SAVE_ALL_PRE \
        SET_XEN_SEGMENTS(_reg) \
        "1:"

#else

#define __SAVE_ALL_PRE \
        cld; \
        pushl %eax; \
        pushl %ebp; \
        pushl %edi; \
        pushl %esi; \
        pushl %edx; \
        pushl %ecx; \
        pushl %ebx; \
        testl $X86_EFLAGS_VM,XREGS_eflags(%esp); \
        jz 2f; \
        call setup_vm86_frame; \
        jmp 3f; \
        2:testb $3,XREGS_cs(%esp); \
        jz 1f; \
        movl %ds,XREGS_ds(%esp); \
        movl %es,XREGS_es(%esp); \
        movl %fs,XREGS_fs(%esp); \
        movl %gs,XREGS_gs(%esp); \
        3:

#define SAVE_ALL_NOSEGREGS(_reg) \
        __SAVE_ALL_PRE \
        1:

#define SET_XEN_SEGMENTS(_reg) \
        movl $(__HYPERVISOR_DS),%e ## _reg ## x; \
        movl %e ## _reg ## x,%ds; \
        movl %e ## _reg ## x,%es;

#define SAVE_ALL(_reg) \
        __SAVE_ALL_PRE \
        SET_XEN_SEGMENTS(_reg) \
        1:

#endif

#define BUILD_SMP_INTERRUPT(x,v) XBUILD_SMP_INTERRUPT(x,v)
#define XBUILD_SMP_INTERRUPT(x,v)\
asmlinkage void x(void); \
__asm__( \
    "\n"__ALIGN_STR"\n" \
    SYMBOL_NAME_STR(x) ":\n\t" \
    "pushl $"#v"<<16\n\t" \
    SAVE_ALL(a) \
    "call "SYMBOL_NAME_STR(smp_##x)"\n\t" \
    "jmp ret_from_intr\n");

#define BUILD_SMP_TIMER_INTERRUPT(x,v) XBUILD_SMP_TIMER_INTERRUPT(x,v)
#define XBUILD_SMP_TIMER_INTERRUPT(x,v) \
asmlinkage void x(struct xen_regs * regs); \
__asm__( \
"\n"__ALIGN_STR"\n" \
SYMBOL_NAME_STR(x) ":\n\t" \
    "pushl $"#v"<<16\n\t" \
    SAVE_ALL(a) \
    "movl %esp,%eax\n\t" \
    "pushl %eax\n\t" \
    "call "SYMBOL_NAME_STR(smp_##x)"\n\t" \
    "addl $4,%esp\n\t" \
    "jmp ret_from_intr\n");

#define BUILD_COMMON_IRQ() \
__asm__( \
    "\n" __ALIGN_STR"\n" \
    "common_interrupt:\n\t" \
    SAVE_ALL(a) \
    "movl %esp,%eax\n\t" \
    "pushl %eax\n\t" \
    "call " SYMBOL_NAME_STR(do_IRQ) "\n\t" \
    "addl $4,%esp\n\t" \
    "jmp ret_from_intr\n");

#define IRQ_NAME2(nr) nr##_interrupt(void)
#define IRQ_NAME(nr) IRQ_NAME2(IRQ##nr)

#define BUILD_IRQ(nr) \
asmlinkage void IRQ_NAME(nr); \
__asm__( \
"\n"__ALIGN_STR"\n" \
SYMBOL_NAME_STR(IRQ) #nr "_interrupt:\n\t" \
    "pushl $"#nr"<<16\n\t" \
    "jmp common_interrupt");

#endif /* __X86_32_ASM_DEFNS_H__ */
