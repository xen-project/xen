#ifndef _X86_64_REGS_H
#define _X86_64_REGS_H

#include <xen/types.h>
#include <public/xen.h>

#define VM86_MODE(_r) (0) /* No VM86 support in long mode. */
#define RING_0(_r)    (((_r)->cs & 3) == 0)
#define RING_1(_r)    (((_r)->cs & 3) == 1)
#define RING_2(_r)    (((_r)->cs & 3) == 2)
#define RING_3(_r)    (((_r)->cs & 3) == 3)

#define GUESTOS_MODE(_e, _r) ((_e)->arch.flags & TF_guestos_mode)

#endif
