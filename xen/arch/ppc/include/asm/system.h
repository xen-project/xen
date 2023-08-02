#ifndef _ASM_SYSTEM_H_
#define _ASM_SYSTEM_H_

#define smp_wmb() __asm__ __volatile__ ( "lwsync" : : : "memory" )

#endif /* _ASM_SYSTEM_H */
