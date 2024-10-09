/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM__RISCV__PMAP_H
#define ASM__RISCV__PMAP_H

#include <xen/bug.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/page-size.h>

#include <asm/fixmap.h>
#include <asm/flushtlb.h>
#include <asm/system.h>

static inline void __init arch_pmap_map(unsigned int slot, mfn_t mfn)
{
    pte_t *entry = &xen_fixmap[slot];
    pte_t pte;

    ASSERT(!pte_is_valid(*entry));

    pte = pte_from_mfn(mfn, PAGE_HYPERVISOR_RW);
    write_pte(entry, pte);

    flush_tlb_one_local(FIXMAP_ADDR(slot));
}

static inline void __init arch_pmap_unmap(unsigned int slot)
{
    pte_t pte = {};

    write_pte(&xen_fixmap[slot], pte);

    flush_tlb_one_local(FIXMAP_ADDR(slot));
}

#endif /* ASM__RISCV__PMAP_H */
