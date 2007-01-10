/******************************************************************************
 * asm-x86/multicall.h
 */

#ifndef __ASM_X86_MULTICALL_H__
#define __ASM_X86_MULTICALL_H__

#include <xen/errno.h>
#include <asm/asm_defns.h>

#ifdef __x86_64__

#define do_multicall_call(_call)                             \
    do {                                                     \
        __asm__ __volatile__ (                               \
            "    movq  "STR(MULTICALL_op)"(%0),%%rax; "      \
            "    cmpq  $("STR(NR_hypercalls)"),%%rax; "      \
            "    jae   2f; "                                 \
            "    leaq  hypercall_table(%%rip),%%rdi; "       \
            "    leaq  (%%rdi,%%rax,8),%%rax; "              \
            "    movq  "STR(MULTICALL_arg0)"(%0),%%rdi; "    \
            "    movq  "STR(MULTICALL_arg1)"(%0),%%rsi; "    \
            "    movq  "STR(MULTICALL_arg2)"(%0),%%rdx; "    \
            "    movq  "STR(MULTICALL_arg3)"(%0),%%rcx; "    \
            "    movq  "STR(MULTICALL_arg4)"(%0),%%r8; "     \
            "    callq *(%%rax); "                           \
            "1:  movq  %%rax,"STR(MULTICALL_result)"(%0)\n"  \
            ".section .fixup,\"ax\"\n"                       \
            "2:  movq  $-"STR(ENOSYS)",%%rax\n"              \
            "    jmp   1b\n"                                 \
            ".previous\n"                                    \
            : : "b" (_call)                                  \
              /* all the caller-saves registers */           \
            : "rax", "rcx", "rdx", "rsi", "rdi",             \
              "r8",  "r9",  "r10", "r11" );                  \
    } while ( 0 )

#define compat_multicall_call(_call)                              \
    do {                                                          \
        __asm__ __volatile__ (                                    \
            "    movl  "STR(COMPAT_MULTICALL_op)"(%0),%%eax; "    \
            "    leaq  compat_hypercall_table(%%rip),%%rdi; "     \
            "    cmpl  $("STR(NR_hypercalls)"),%%eax; "           \
            "    jae   2f; "                                      \
            "    movq  (%%rdi,%%rax,8),%%rax; "                   \
            "    movl  "STR(COMPAT_MULTICALL_arg0)"(%0),%%edi; "  \
            "    movl  "STR(COMPAT_MULTICALL_arg1)"(%0),%%esi; "  \
            "    movl  "STR(COMPAT_MULTICALL_arg2)"(%0),%%edx; "  \
            "    movl  "STR(COMPAT_MULTICALL_arg3)"(%0),%%ecx; "  \
            "    movl  "STR(COMPAT_MULTICALL_arg4)"(%0),%%r8d; "  \
            "    callq *%%rax; "                                  \
            "1:  movl  %%eax,"STR(COMPAT_MULTICALL_result)"(%0)\n"\
            ".section .fixup,\"ax\"\n"                            \
            "2:  movl  $-"STR(ENOSYS)",%%eax\n"                   \
            "    jmp   1b\n"                                      \
            ".previous\n"                                         \
            : : "b" (_call)                                       \
              /* all the caller-saves registers */                \
            : "rax", "rcx", "rdx", "rsi", "rdi",                  \
              "r8",  "r9",  "r10", "r11" );                       \
    } while ( 0 )

#else

#define do_multicall_call(_call)                             \
    do {                                                     \
        __asm__ __volatile__ (                               \
            "    pushl "STR(MULTICALL_arg4)"(%0); "          \
            "    pushl "STR(MULTICALL_arg3)"(%0); "          \
            "    pushl "STR(MULTICALL_arg2)"(%0); "          \
            "    pushl "STR(MULTICALL_arg1)"(%0); "          \
            "    pushl "STR(MULTICALL_arg0)"(%0); "          \
            "    movl  "STR(MULTICALL_op)"(%0),%%eax; "      \
            "    cmpl  $("STR(NR_hypercalls)"),%%eax; "      \
            "    jae   2f; "                                 \
            "    call  *hypercall_table(,%%eax,4); "         \
            "1:  movl  %%eax,"STR(MULTICALL_result)"(%0); "  \
            "    addl  $20,%%esp\n"                          \
            ".section .fixup,\"ax\"\n"                       \
            "2:  movl  $-"STR(ENOSYS)",%%eax\n"              \
            "    jmp   1b\n"                                 \
            ".previous\n"                                    \
            : : "b" (_call)                                  \
              /* all the caller-saves registers */           \
            : "eax", "ecx", "edx" );                         \
    } while ( 0 )

#endif

#endif /* __ASM_X86_MULTICALL_H__ */
