/*
 * cacheattr.c: MTRR and PAT initialisation.
 *
 * Copyright (c) 2008, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir.fraser@citrix.com>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "util.h"
#include "config.h"

#define MSR_MTRRphysBase(reg) (0x200 + 2 * (reg))
#define MSR_MTRRphysMask(reg) (0x200 + 2 * (reg) + 1)
#define MSR_MTRRcap          0x00fe
#define MSR_MTRRfix64K_00000 0x0250
#define MSR_MTRRfix16K_80000 0x0258
#define MSR_MTRRfix16K_A0000 0x0259
#define MSR_MTRRfix4K_C0000  0x0268
#define MSR_MTRRfix4K_C8000  0x0269
#define MSR_MTRRfix4K_D0000  0x026a
#define MSR_MTRRfix4K_D8000  0x026b
#define MSR_MTRRfix4K_E0000  0x026c
#define MSR_MTRRfix4K_E8000  0x026d
#define MSR_MTRRfix4K_F0000  0x026e
#define MSR_MTRRfix4K_F8000  0x026f
#define MSR_PAT              0x0277
#define MSR_MTRRdefType      0x02ff

void cacheattr_init(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint64_t mtrr_cap, mtrr_def, content, addr_mask;
    unsigned int i, nr_var_ranges, phys_bits = 36;

    /* Does the CPU support architectural MTRRs? */
    cpuid(0x00000001, &eax, &ebx, &ecx, &edx);
    if ( !(edx & (1u << 12)) )
         return;

    /* Find the physical address size for this CPU. */
    cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
    if ( eax >= 0x80000008 )
    {
        cpuid(0x80000008, &eax, &ebx, &ecx, &edx);
        phys_bits = (uint8_t)eax;
    }

    printf("%u-bit phys ... ", phys_bits);

    addr_mask = ((1ull << phys_bits) - 1) & ~((1ull << 12) - 1);
    mtrr_cap = rdmsr(MSR_MTRRcap);
    mtrr_def = (1u << 11) | 6; /* E, default type WB */

    /* Fixed-range MTRRs supported? */
    if ( mtrr_cap & (1u << 8) )
    {
        /* 0x00000-0x9ffff: Write Back (WB) */
        content = 0x0606060606060606ull;
        wrmsr(MSR_MTRRfix64K_00000, content);
        wrmsr(MSR_MTRRfix16K_80000, content);
        /* 0xa0000-0xbffff: Write Combining (WC) */
        if ( mtrr_cap & (1u << 10) ) /* WC supported? */
            content = 0x0101010101010101ull;
        wrmsr(MSR_MTRRfix16K_A0000, content);
        /* 0xc0000-0xfffff: Write Back (WB) */
        content = 0x0606060606060606ull;
        for ( i = 0; i < 8; i++ )
            wrmsr(MSR_MTRRfix4K_C0000 + i, content);
        mtrr_def |= 1u << 10; /* FE */
        printf("fixed MTRRs ... ");
    }

    /* Variable-range MTRRs supported? */
    nr_var_ranges = (uint8_t)mtrr_cap;
    if ( nr_var_ranges != 0 )
    {
        /* A single UC range covering PCI space. */
        /* pci_mem_start must be of the binary form 1....10....0 */
        BUG_ON(~(pci_mem_start | (pci_mem_start - 1)));
        wrmsr(MSR_MTRRphysBase(0), pci_mem_start);
        wrmsr(MSR_MTRRphysMask(0),
              ((uint64_t)(int32_t)pci_mem_start & addr_mask) | (1u << 11));
        printf("var MTRRs ... ");
    }

    wrmsr(MSR_MTRRdefType, mtrr_def);
}
