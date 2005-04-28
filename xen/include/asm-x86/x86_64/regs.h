#ifndef _X86_64_REGS_H
#define _X86_64_REGS_H

#include <xen/types.h>
#include <public/xen.h>

#define VM86_MODE(_r) (0) /* No VM86 support in long mode. */
#define RING_0(_r)    (((_r)->cs & 3) == 0)
#define RING_1(_r)    (((_r)->cs & 3) == 1)
#define RING_2(_r)    (((_r)->cs & 3) == 2)
#define RING_3(_r)    (((_r)->cs & 3) == 3)

#define KERNEL_MODE(_e, _r) ((_e)->arch.flags & TF_kernel_mode)

#define PERMIT_SOFTINT(_dpl, _e, _r) \
    ((_dpl) >= (KERNEL_MODE(_e, _r) ? 1 : 3))

/* Number of bytes of on-stack execution state to be context-switched. */
/* NB. Segment registers and bases are not saved/restored on x86/64 stack. */
#define CTXT_SWITCH_STACK_BYTES (offsetof(struct cpu_user_regs, es))

#endif
