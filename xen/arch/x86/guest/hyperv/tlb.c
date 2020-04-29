/******************************************************************************
 * arch/x86/guest/hyperv/tlb.c
 *
 * Support for TLB management using hypercalls
 *
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2020 Microsoft.
 */

#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/errno.h>

#include <asm/guest/hyperv.h>
#include <asm/guest/hyperv-hcall.h>
#include <asm/guest/hyperv-tlfs.h>

#include "private.h"

/*
 * It is possible to encode up to 4096 pages using the lower 12 bits
 * in an element of gva_list
 */
#define HV_TLB_FLUSH_UNIT (4096 * PAGE_SIZE)

static unsigned int fill_gva_list(uint64_t *gva_list, const void *va,
                                  unsigned int order)
{
    unsigned long cur = (unsigned long)va;
    /* end is 1 past the range to be flushed */
    unsigned long end = cur + (PAGE_SIZE << order);
    unsigned int n = 0;

    do {
        unsigned long diff = end - cur;

        gva_list[n] = cur & PAGE_MASK;

        /*
         * Use lower 12 bits to encode the number of additional pages
         * to flush
         */
        if ( diff >= HV_TLB_FLUSH_UNIT )
        {
            gva_list[n] |= ~PAGE_MASK;
            cur += HV_TLB_FLUSH_UNIT;
        }
        else
        {
            gva_list[n] |= (diff - 1) >> PAGE_SHIFT;
            cur = end;
        }

        n++;
    } while ( cur < end );

    return n;
}

static uint64_t flush_tlb_ex(const cpumask_t *mask, const void *va,
                             unsigned int flags)
{
    struct hv_tlb_flush_ex *flush = this_cpu(hv_input_page);
    int nr_banks;
    unsigned int max_gvas, order = (flags - 1) & FLUSH_ORDER_MASK;
    uint64_t *gva_list;

    if ( !flush || local_irq_is_enabled() )
    {
        ASSERT_UNREACHABLE();
        return ~0ULL;
    }

    if ( !(ms_hyperv.hints & HV_X64_EX_PROCESSOR_MASKS_RECOMMENDED) )
        return ~0ULL;

    flush->address_space = 0;
    flush->flags = HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES;
    if ( !(flags & FLUSH_TLB_GLOBAL) )
        flush->flags |= HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY;

    nr_banks = cpumask_to_vpset(&flush->hv_vp_set, mask);
    if ( nr_banks < 0 )
        return ~0ULL;

    max_gvas =
        (PAGE_SIZE - sizeof(*flush) - nr_banks *
         sizeof(flush->hv_vp_set.bank_contents[0])) /
        sizeof(uint64_t);       /* gva is represented as uint64_t */

    /*
     * Flush the entire address space if va is NULL or if there is not
     * enough space for gva_list.
     */
    if ( !va || (PAGE_SIZE << order) / HV_TLB_FLUSH_UNIT > max_gvas )
        return hv_do_rep_hypercall(HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX, 0,
                                   nr_banks, virt_to_maddr(flush), 0);

    /*
     * The calculation of gva_list address requires the structure to
     * be 64 bits aligned.
     */
    BUILD_BUG_ON(sizeof(*flush) % sizeof(uint64_t));
    gva_list = (uint64_t *)flush + sizeof(*flush) / sizeof(uint64_t) + nr_banks;

    return hv_do_rep_hypercall(HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX,
                               fill_gva_list(gva_list, va, order),
                               nr_banks, virt_to_maddr(flush), 0);
}

/* Maximum number of gvas for hv_tlb_flush */
#define MAX_GVAS ((PAGE_SIZE - sizeof(struct hv_tlb_flush)) / sizeof(uint64_t))

int hyperv_flush_tlb(const cpumask_t *mask, const void *va,
                     unsigned int flags)
{
    unsigned long irq_flags;
    struct hv_tlb_flush *flush = this_cpu(hv_input_page);
    unsigned int order = (flags - 1) & FLUSH_ORDER_MASK;
    uint64_t ret;

    if ( !flush || cpumask_empty(mask) )
    {
        ASSERT_UNREACHABLE();
        return -EINVAL;
    }

    /* TODO: may need to check if in #NMI or #MC and fallback to native path */

    local_irq_save(irq_flags);

    flush->address_space = 0;
    flush->flags = HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES;
    flush->processor_mask = 0;
    if ( !(flags & FLUSH_TLB_GLOBAL) )
        flush->flags |= HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY;

    if ( cpumask_equal(mask, &cpu_online_map) )
        flush->flags |= HV_FLUSH_ALL_PROCESSORS;
    else
    {
        unsigned int cpu;

        /*
         * Normally VP indices are in ascending order and match Xen's
         * idea of CPU ids. Check the last index to see if VP index is
         * >= 64. If so, we can skip setting up parameters for
         * non-applicable hypercalls without looking further.
         */
        if ( hv_vp_index(cpumask_last(mask)) >= 64 )
            goto do_ex_hypercall;

        for_each_cpu ( cpu, mask )
        {
            unsigned int vpid = hv_vp_index(cpu);

            if ( vpid > hv_max_vp_index )
            {
                local_irq_restore(irq_flags);
                return -ENXIO;
            }

            if ( vpid >= 64 )
                goto do_ex_hypercall;

            __set_bit(vpid, &flush->processor_mask);
        }
    }

    /*
     * Flush the entire address space if va is NULL or if there is not
     * enough space for gva_list.
     */
    if ( !va || (PAGE_SIZE << order) / HV_TLB_FLUSH_UNIT > MAX_GVAS )
        ret = hv_do_hypercall(HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE,
                              virt_to_maddr(flush), 0);
    else
        ret = hv_do_rep_hypercall(HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST,
                                  fill_gva_list(flush->gva_list, va, order),
                                  0, virt_to_maddr(flush), 0);
    goto done;

 do_ex_hypercall:
    ret = flush_tlb_ex(mask, va, flags);

 done:
    local_irq_restore(irq_flags);

    return ret & HV_HYPERCALL_RESULT_MASK ? -ENXIO : 0;
}

#undef MAX_GVAS

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
