#ifndef _I386_REGS_H
#define _I386_REGS_H

#include <xen/types.h>
#include <public/xen.h>

#define VM86_MODE(_r) ((_r)->eflags & EF_VM)
#define RING_0(_r)    (((_r)->cs & 3) == 0)
#define RING_1(_r)    (((_r)->cs & 3) == 1)
#define RING_2(_r)    (((_r)->cs & 3) == 2)
#define RING_3(_r)    (((_r)->cs & 3) == 3)

#define GUESTOS_MODE(_e, _r) (!VM86_MODE(_r) && RING_1(_r))

#endif
