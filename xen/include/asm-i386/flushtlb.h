/******************************************************************************
 * flushtlb.h
 * 
 * TLB flush macros that count flushes.  Counting is used to enforce 
 * zero-copy safety, particularily for the network code.
 *
 * akw - Jan 21, 2003
 */

#ifndef __FLUSHTLB_H
#define __FLUSHTLB_H

#include <xeno/smp.h>

unsigned long tlb_flush_count[NR_CPUS];
//#if 0 
#define __read_cr3(__var)                                               \
    do {                                                                \
                __asm__ __volatile (                                    \
                        "movl %%cr3, %0;"                               \
                        : "=r" (__var));                                \
    } while (0)
//#endif

#define __write_cr3_counted(__pa)                                       \
    do {                                                                \
                __asm__ __volatile__ (                                  \
                        "movl %0, %%cr3;"                               \
                        :: "r" (__pa)                                    \
                        : "memory");                                    \
                tlb_flush_count[smp_processor_id()]++;                  \
    } while (0)

//#endif
#define __flush_tlb_counted()                                           \
        do {                                                            \
                unsigned int tmpreg;                                    \
                                                                        \
                __asm__ __volatile__(                                   \
                        "movl %%cr3, %0;  # flush TLB \n"               \
                        "movl %0, %%cr3;                "               \
                        : "=r" (tmpreg)                                \
                        :: "memory");                                   \
                tlb_flush_count[smp_processor_id()]++;                  \
        } while (0)

#endif
                           
