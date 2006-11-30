/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_FLUSHTLB_H_
#define _ASM_FLUSHTLB_H_

#include <xen/config.h>
#include <xen/percpu.h>
#include <xen/types.h>

/* The current time as shown by the virtual TLB clock. */
extern u32 tlbflush_clock;
#define tlbflush_current_time() tlbflush_clock

/* Time at which each CPU's TLB was last flushed. */
DECLARE_PER_CPU(u32, tlbflush_time);

static inline int NEED_FLUSH(u32 cpu_stamp, u32 lastuse_stamp)
{
    return 0;
}

/*
 * Filter the given set of CPUs, removing those that definitely flushed their
 * TLB since @page_timestamp.
 */
#define tlbflush_filter(mask, page_timestamp)                           \
do {                                                                    \
    unsigned int cpu;                                                   \
    for_each_cpu_mask ( cpu, mask )                                     \
        if ( !NEED_FLUSH(per_cpu(tlbflush_time, cpu), page_timestamp) ) \
            cpu_clear(cpu, mask);                                       \
} while ( 0 )


static inline void tlbiel(unsigned long eaddr)
{
#if 0
    asm volatile("tlbiel %0" : : "r"(eaddr) : "memory");
#else
    asm volatile(".long 0x7c000224 | (%0 << 11)" : : "r"(eaddr) : "memory");
#endif
}

/* Lots of paranoia in flush_tlb_*; could probably be relaxed later. */
static inline void local_flush_tlb_one(unsigned long eaddr)
{
    asm volatile("ptesync" : : : "memory");
    tlbiel(eaddr);
    asm volatile("eieio; tlbsync" : : : "memory");
}

static inline void local_flush_tlb(void)
{
    ulong rb;
    int i;

    asm volatile("ptesync" : : : "memory");

    for (i = 0; i < 256; i++) {
        rb = i;
        rb <<= 12;
        tlbiel(rb);
    }
    asm volatile("eieio": : : "memory");
}

#ifndef CONFIG_SMP
#define flush_tlb_mask(_mask)           local_flush_tlb()
#define flush_tlb_one_mask(_mask,_addr) local_flush_tlb_one(_addr)
#else
extern void __flush_tlb_mask(cpumask_t mask, unsigned long addr);

#define FLUSH_ALL_ADDRS (~0UL)
#define flush_tlb_mask(_mask)           __flush_tlb_mask(_mask,FLUSH_ALL_ADDRS)
#define flush_tlb_one_mask(_mask,_addr) __flush_tlb_mask(_mask,_addr)
#endif /* CONFIG_SMP */

/*
 * Filter the given set of CPUs, returning only those that may not have
 * flushed their TLBs since @page_timestamp.
 */
static inline unsigned long tlbflush_filter_cpuset(
    unsigned long cpuset, u32 page_timestamp)
{
    return 0;
}
#endif
