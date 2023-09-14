/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Based on arch/powerpc/mm/book3s64/radix_tlb.c from Linux with the following
 * copyright notice:
 *
 * Copyright 2015-2016, Aneesh Kumar K.V, IBM Corporation.
 */
#include <xen/bitops.h>
#include <xen/stringify.h>

#include <asm/msr.h>
#include <asm/processor.h>

/* TLB flush actions. Used as argument to tlbiel_flush() */
enum
{
    TLB_INVAL_SCOPE_LPID,   /* invalidate TLBs for current LPID */
    TLB_INVAL_SCOPE_GLOBAL, /* invalidate all TLBs */
};

#define POWER9_TLB_SETS_RADIX 128 /* # sets in POWER9 TLB Radix mode */

#define RIC_FLUSH_TLB 0
#define RIC_FLUSH_PWC 1
#define RIC_FLUSH_ALL 2

static void tlbiel_radix_set_isa300(unsigned int set, unsigned int is,
                                    unsigned int pid, unsigned int ric,
                                    unsigned int prs)
{
    unsigned long rb;
    unsigned long rs;

    rb = (set << PPC_BITLSHIFT(51)) | (is << PPC_BITLSHIFT(53));
    rs = ((unsigned long) pid << PPC_BITLSHIFT(31));

    asm volatile ( "tlbiel %0, %1, %2, %3, 1"
                   :: "r" (rb), "r" (rs), "i" (ric), "i" (prs)
                   : "memory" );
}

static void tlbiel_all_isa300(unsigned int num_sets, unsigned int is)
{
    unsigned int set;

    asm volatile ( "ptesync" : : : "memory" );

    /*
     * Flush the first set of the TLB, and the entire Page Walk Cache
     * and partition table entries. Then flush the remaining sets of the
     * TLB.
     */

    if ( mfmsr() & MSR_HV )
    {
        /* MSR[HV] should flush partition scope translations first. */
        tlbiel_radix_set_isa300(0, is, 0, RIC_FLUSH_ALL, 0);

        for ( set = 1; set < num_sets; set++ )
            tlbiel_radix_set_isa300(set, is, 0, RIC_FLUSH_TLB, 0);
    }

    /* Flush process scoped entries. */
    tlbiel_radix_set_isa300(0, is, 0, RIC_FLUSH_ALL, 1);

    for ( set = 1; set < num_sets; set++ )
        tlbiel_radix_set_isa300(set, is, 0, RIC_FLUSH_TLB, 1);

    asm volatile ( "ptesync" : : : "memory" );
}

void radix__tlbiel_all(unsigned int action)
{
    unsigned int is;

    switch ( action )
    {
    case TLB_INVAL_SCOPE_GLOBAL:
        is = 3;
        break;
    case TLB_INVAL_SCOPE_LPID:
        is = 2;
        break;
    default:
        die();
    }

    tlbiel_all_isa300(POWER9_TLB_SETS_RADIX, is);

    asm volatile ( "slbia 7; isync" : : : "memory" );
}

void tlbie_all(void)
{
    radix__tlbiel_all(TLB_INVAL_SCOPE_GLOBAL);
}
