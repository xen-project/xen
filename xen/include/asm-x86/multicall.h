/******************************************************************************
 * asm-x86/multicall.h
 */

#ifndef __ASM_X86_MULTICALL_H__
#define __ASM_X86_MULTICALL_H__

#include <asm/asm_defns.h>

#ifdef __x86_64__

#define do_multicall_call(_call)                         \
    do {                                                 \
        __asm__ __volatile__ (                           \
            "movq  "STR(MULTICALL_op)"(%0),%%rax; "      \
            "andq  $("STR(NR_hypercalls)"-1),%%rax; "    \
            "leaq  "STR(hypercall_table)"(%%rip),%%rdi; "\
            "leaq  (%%rdi,%%rax,8),%%rax; "              \
            "movq  "STR(MULTICALL_arg0)"(%0),%%rdi; "    \
            "movq  "STR(MULTICALL_arg1)"(%0),%%rsi; "    \
            "movq  "STR(MULTICALL_arg2)"(%0),%%rdx; "    \
            "movq  "STR(MULTICALL_arg3)"(%0),%%rcx; "    \
            "movq  "STR(MULTICALL_arg4)"(%0),%%r8; "     \
            "callq *(%%rax); "                           \
            "movq  %%rax,"STR(MULTICALL_result)"(%0); "  \
            : : "b" (_call)                              \
            : "rax", "rdi", "rsi", "rdx", "rcx", "r8" ); \
    } while ( 0 )

#else

#define do_multicall_call(_call)                       \
    do {                                               \
        __asm__ __volatile__ (                         \
            "pushl "STR(MULTICALL_arg4)"(%0); "        \
            "pushl "STR(MULTICALL_arg3)"(%0); "        \
            "pushl "STR(MULTICALL_arg2)"(%0); "        \
            "pushl "STR(MULTICALL_arg1)"(%0); "        \
            "pushl "STR(MULTICALL_arg0)"(%0); "        \
            "movl  "STR(MULTICALL_op)"(%0),%%eax; "    \
            "andl  $("STR(NR_hypercalls)"-1),%%eax; "  \
            "call  *hypercall_table(,%%eax,4); "       \
            "movl  %%eax,"STR(MULTICALL_result)"(%0); "\
            "addl  $20,%%esp; "                        \
            : : "b" (_call) : "eax", "ecx", "edx" );   \
    } while ( 0 )

#endif

#endif /* __ASM_X86_MULTICALL_H__ */
