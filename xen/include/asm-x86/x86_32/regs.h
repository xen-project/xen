#ifndef _I386_REGS_H
#define _I386_REGS_H

#include <asm/types.h>

/* So that we can use 'l' modifier in printf-style format strings. */
#define u32 unsigned long

struct xen_regs
{
    /* All saved activations contain the following fields. */
    u32 ebx;
    u32 ecx;
    u32 edx;
    u32 esi;
    u32 edi;
    u32 ebp;
    u32 eax;
    u16 error_code;
    u16 entry_vector;
    u32 eip;
    u32 cs;
    u32 eflags;

    /* Only saved guest activations contain the following fields. */
    u32 esp;
    u32 ss;
    u32 es;
    u32 ds;
    u32 fs;
    u32 gs;
} __attribute__ ((packed));

#undef u32

#define VM86_MODE(_r) ((_r)->eflags & EF_VM)
#define RING_0(_r)    (((_r)->cs & 3) == 0)
#define RING_1(_r)    (((_r)->cs & 3) == 1)
#define RING_2(_r)    (((_r)->cs & 3) == 2)
#define RING_3(_r)    (((_r)->cs & 3) == 3)

#endif
