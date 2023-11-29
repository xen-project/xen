#ifndef _LINUX_DELAY_H
#define _LINUX_DELAY_H

/* Copyright (C) 1993 Linus Torvalds */

void udelay(unsigned long usecs);

static inline void mdelay(unsigned long msec)
{
    while ( msec-- )
        udelay(1000);
}

#endif /* defined(_LINUX_DELAY_H) */
