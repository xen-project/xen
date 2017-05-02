/******************************************************************************
 * asm-x86/multicall.h
 */

#ifndef __ASM_X86_MULTICALL_H__
#define __ASM_X86_MULTICALL_H__

#include <xen/errno.h>

enum mc_disposition {
    mc_continue,
    mc_exit,
    mc_preempt,
};

#define multicall_ret(call)                                  \
    (unlikely((call)->op == __HYPERVISOR_iret)               \
     ? mc_exit                                               \
       : likely(guest_kernel_mode(current,                   \
                                  guest_cpu_user_regs()))    \
         ? mc_continue : mc_preempt)

#define do_multicall_call(_call)                             \
    ({                                                       \
        __asm__ __volatile__ (                               \
            "    movq  %c1(%0),%%rax; "                      \
            "    leaq  hypercall_table(%%rip),%%rdi; "       \
            "    cmpq  $("STR(NR_hypercalls)"),%%rax; "      \
            "    jae   2f; "                                 \
            "    movq  (%%rdi,%%rax,8),%%rax; "              \
            "    movq  %c2+0*%c3(%0),%%rdi; "                \
            "    movq  %c2+1*%c3(%0),%%rsi; "                \
            "    movq  %c2+2*%c3(%0),%%rdx; "                \
            "    movq  %c2+3*%c3(%0),%%rcx; "                \
            "    movq  %c2+4*%c3(%0),%%r8; "                 \
            "    movq  %c2+5*%c3(%0),%%r9; "                 \
            "    callq *%%rax; "                             \
            "1:  movq  %%rax,%c4(%0)\n"                      \
            ".section .fixup,\"ax\"\n"                       \
            "2:  movq  $-"STR(ENOSYS)",%%rax\n"              \
            "    jmp   1b\n"                                 \
            ".previous\n"                                    \
            :                                                \
            : "b" (_call),                                   \
              "i" (offsetof(__typeof__(*_call), op)),        \
              "i" (offsetof(__typeof__(*_call), args)),      \
              "i" (sizeof(*(_call)->args)),                  \
              "i" (offsetof(__typeof__(*_call), result))     \
              /* all the caller-saves registers */           \
            : "rax", "rcx", "rdx", "rsi", "rdi",             \
              "r8",  "r9",  "r10", "r11" );                  \
        multicall_ret(_call);                                \
    })

#define compat_multicall_call(_call)                         \
    ({                                                       \
        __asm__ __volatile__ (                               \
            "    movl  %c1(%0),%%eax; "                      \
            "    leaq  compat_hypercall_table(%%rip),%%rdi; "\
            "    cmpl  $("STR(NR_hypercalls)"),%%eax; "      \
            "    jae   2f; "                                 \
            "    movq  (%%rdi,%%rax,8),%%rax; "              \
            "    movl  %c2+0*%c3(%0),%%edi; "                \
            "    movl  %c2+1*%c3(%0),%%esi; "                \
            "    movl  %c2+2*%c3(%0),%%edx; "                \
            "    movl  %c2+3*%c3(%0),%%ecx; "                \
            "    movl  %c2+4*%c3(%0),%%r8d; "                \
            "    movl  %c2+5*%c3(%0),%%r9d; "                \
            "    callq *%%rax; "                             \
            "1:  movl  %%eax,%c4(%0)\n"                      \
            ".section .fixup,\"ax\"\n"                       \
            "2:  movl  $-"STR(ENOSYS)",%%eax\n"              \
            "    jmp   1b\n"                                 \
            ".previous\n"                                    \
            :                                                \
            : "b" (_call),                                   \
              "i" (offsetof(__typeof__(*_call), op)),        \
              "i" (offsetof(__typeof__(*_call), args)),      \
              "i" (sizeof(*(_call)->args)),                  \
              "i" (offsetof(__typeof__(*_call), result))     \
              /* all the caller-saves registers */           \
            : "rax", "rcx", "rdx", "rsi", "rdi",             \
              "r8",  "r9",  "r10", "r11" );                  \
        multicall_ret(_call);                                \
    })

#endif /* __ASM_X86_MULTICALL_H__ */
