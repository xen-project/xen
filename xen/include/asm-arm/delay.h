#ifndef _ARM_DELAY_H
#define _ARM_DELAY_H

extern void __udelay(unsigned long usecs);
#define udelay(n) __udelay(n)

#endif /* defined(_ARM_DELAY_H) */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
