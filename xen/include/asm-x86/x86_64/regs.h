#ifndef _X86_64_REGS_H
#define _X86_64_REGS_H

#include <asm/types.h>

struct xen_regs
{
    u64 r15;
    u64 r14;
    u64 r13;
    u64 r12;
    u64 rbp;
    u64 rbx;
    u64 r11;
    u64 r10;	
    u64 r9;
    u64 r8;
    u64 rax;
    u64 rcx;
    u64 rdx;
    u64 rsi;
    u64 rdi;
    u32 error_code;
    u32 entry_vector;
    u64 rip;
    u64 cs;
    u64 eflags;
    u64 rsp;
    u64 ss;
} __attribute__ ((packed));

#define VM86_MODE(_r) ((_r)->eflags & EF_VM)
#define RING_0(_r)    (((_r)->cs & 3) == 0)
#define RING_1(_r)    (((_r)->cs & 3) == 1)
#define RING_2(_r)    (((_r)->cs & 3) == 2)
#define RING_3(_r)    (((_r)->cs & 3) == 3)

#endif
