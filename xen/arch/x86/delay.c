/*
 * Precise Delay Loops for i386
 *
 * Copyright (C) 1993 Linus Torvalds
 * Copyright (C) 1997 Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 *
 * The __delay function must _NOT_ be inlined as its execution time
 * depends wildly on alignment on many x86 processors. The additional
 * jump magic is needed to get the timing stable on all the CPU's
 * we have to worry about.
 */

#include <xen/config.h>
#include <xen/delay.h>
#include <xen/time.h>
#include <asm/msr.h>
#include <asm/processor.h>

void __udelay(unsigned long usecs)
{
    unsigned long ticks = usecs * (cpu_khz / 1000);
    unsigned long s, e;

    s = rdtsc();
    do
    {
        rep_nop();
        e = rdtsc();
    } while ((e-s) < ticks);
}
