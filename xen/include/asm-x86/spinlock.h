#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#define _raw_read_unlock(l) \
    asm volatile ( "lock; dec%z0 %0" : "+m" ((l)->lock) :: "memory" )

#endif /* __ASM_SPINLOCK_H */
