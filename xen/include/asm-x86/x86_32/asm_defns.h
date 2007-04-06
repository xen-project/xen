#ifndef __X86_32_ASM_DEFNS_H__
#define __X86_32_ASM_DEFNS_H__

#include <asm/percpu.h>

#ifndef NDEBUG
/* Indicate special exception stack frame by inverting the frame pointer. */
#define SETUP_EXCEPTION_FRAME_POINTER           \
        movl  %esp,%ebp;                        \
        notl  %ebp
#define ASSERT_INTERRUPT_STATUS(x)              \
        pushf;                                  \
        testb $X86_EFLAGS_IF>>8,1(%esp);        \
        j##x  1f;                               \
        ud2a;                                   \
1:      addl  $4,%esp;
#else
#define SETUP_EXCEPTION_FRAME_POINTER
#define ASSERT_INTERRUPT_STATUS(x)
#endif

#define ASSERT_INTERRUPTS_ENABLED  ASSERT_INTERRUPT_STATUS(nz)
#define ASSERT_INTERRUPTS_DISABLED ASSERT_INTERRUPT_STATUS(z)

#define __SAVE_ALL_PRE                                  \
        cld;                                            \
        pushl %eax;                                     \
        pushl %ebp;                                     \
        SETUP_EXCEPTION_FRAME_POINTER;                  \
        pushl %edi;                                     \
        pushl %esi;                                     \
        pushl %edx;                                     \
        pushl %ecx;                                     \
        pushl %ebx;                                     \
        testl $(X86_EFLAGS_VM),UREGS_eflags(%esp);      \
        jz 2f;                                          \
        call setup_vm86_frame;                          \
        jmp 3f;                                         \
        2:testb $3,UREGS_cs(%esp);                      \
        jz 1f;                                          \
        mov %ds,UREGS_ds(%esp);                         \
        mov %es,UREGS_es(%esp);                         \
        mov %fs,UREGS_fs(%esp);                         \
        mov %gs,UREGS_gs(%esp);                         \
        3:

#define SAVE_ALL_NOSEGREGS(_reg)                \
        __SAVE_ALL_PRE                          \
        1:

#define SET_XEN_SEGMENTS(_reg)                          \
        movl $(__HYPERVISOR_DS),%e ## _reg ## x;        \
        mov %e ## _reg ## x,%ds;                        \
        mov %e ## _reg ## x,%es;

#define SAVE_ALL(_reg)                          \
        __SAVE_ALL_PRE                          \
        SET_XEN_SEGMENTS(_reg)                  \
        1:

#ifdef PERF_COUNTERS
#define PERFC_INCR(_name,_idx,_cur)                     \
        pushl _cur;                                     \
        movl VCPU_processor(_cur),_cur;                 \
        shll $PERCPU_SHIFT,_cur;                        \
        incl per_cpu__perfcounters+_name*4(_cur,_idx,4);\
        popl _cur
#else
#define PERFC_INCR(_name,_idx,_cur)
#endif

#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
#define FIXUP_RING0_GUEST_STACK                         \
        testl $2,8(%esp);                               \
        jnz 1f; /* rings 2 & 3 permitted */             \
        testl $1,8(%esp);                               \
        jz 2f;                                          \
        ud2; /* ring 1 should not be used */            \
        2:cmpl $(__HYPERVISOR_VIRT_START),%esp;         \
        jge 1f;                                         \
        call fixup_ring0_guest_stack;                   \
        1:
#else
#define FIXUP_RING0_GUEST_STACK
#endif

#define BUILD_SMP_INTERRUPT(x,v) XBUILD_SMP_INTERRUPT(x,v)
#define XBUILD_SMP_INTERRUPT(x,v)               \
asmlinkage void x(void);                        \
__asm__(                                        \
    "\n"__ALIGN_STR"\n"                         \
    ".globl " STR(x) "\n\t"                     \
    STR(x) ":\n\t"                              \
    "pushl $"#v"<<16\n\t"                       \
    STR(FIXUP_RING0_GUEST_STACK)                \
    STR(SAVE_ALL(a))                            \
    "movl %esp,%eax\n\t"                        \
    "pushl %eax\n\t"                            \
    "call "STR(smp_##x)"\n\t"                   \
    "addl $4,%esp\n\t"                          \
    "jmp ret_from_intr\n");

#define BUILD_COMMON_IRQ()                      \
__asm__(                                        \
    "\n" __ALIGN_STR"\n"                        \
    "common_interrupt:\n\t"                     \
    STR(FIXUP_RING0_GUEST_STACK)                \
    STR(SAVE_ALL(a))                            \
    "movl %esp,%eax\n\t"                        \
    "pushl %eax\n\t"                            \
    "call " STR(do_IRQ) "\n\t"                  \
    "addl $4,%esp\n\t"                          \
    "jmp ret_from_intr\n");

#define IRQ_NAME2(nr) nr##_interrupt(void)
#define IRQ_NAME(nr) IRQ_NAME2(IRQ##nr)

#define BUILD_IRQ(nr)                           \
asmlinkage void IRQ_NAME(nr);                   \
__asm__(                                        \
"\n"__ALIGN_STR"\n"                             \
STR(IRQ) #nr "_interrupt:\n\t"                  \
    "pushl $"#nr"<<16\n\t"                      \
    "jmp common_interrupt");

#endif /* __X86_32_ASM_DEFNS_H__ */
