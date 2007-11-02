/*
 * arch/x86/mm/hap/guest_walk.c
 *
 * Guest page table walker
 * Copyright (c) 2007, AMD Corporation (Wei Huang)
 * Copyright (c) 2007, XenSource Inc.
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

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <asm/page.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/domain.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/hap.h>

#include "private.h"

#define _hap_gva_to_gfn(levels) hap_gva_to_gfn_##levels##level
#define hap_gva_to_gfn(levels) _hap_gva_to_gfn(levels)

#if GUEST_PAGING_LEVELS > CONFIG_PAGING_LEVELS

unsigned long hap_gva_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, unsigned long gva, uint32_t *pfec)
{
    gdprintk(XENLOG_ERR,
             "Guest paging level is greater than host paging level!\n");
    domain_crash(v->domain);
    return INVALID_GFN;
}

#else

#if GUEST_PAGING_LEVELS == 2
#include "../page-guest32.h"
#define l1_pgentry_t l1_pgentry_32_t
#define l2_pgentry_t l2_pgentry_32_t
#undef l2e_get_flags
#define l2e_get_flags(x) l2e_get_flags_32(x)
#undef l1e_get_flags
#define l1e_get_flags(x) l1e_get_flags_32(x)
#endif

unsigned long hap_gva_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, unsigned long gva, uint32_t *pfec)
{
    unsigned long gcr3 = v->arch.hvm_vcpu.guest_cr[3];
    int mode = GUEST_PAGING_LEVELS;
    int lev, index;
    paddr_t gpa = 0;
    unsigned long gpfn, mfn;
    p2m_type_t p2mt;
    int success = 1;

    l1_pgentry_t *l1e;
    l2_pgentry_t *l2e;
#if GUEST_PAGING_LEVELS >= 3
    l3_pgentry_t *l3e;
#endif
#if GUEST_PAGING_LEVELS >= 4
    l4_pgentry_t *l4e;
#endif

    gpfn = (gcr3 >> PAGE_SHIFT);
    for ( lev = mode; lev >= 1; lev-- )
    {
        mfn = mfn_x(gfn_to_mfn_current(gpfn, &p2mt));
        if ( !p2m_is_ram(p2mt) )
        {
            HAP_PRINTK("bad pfn=0x%lx from gva=0x%lx at lev%d\n", gpfn, gva,
                       lev);
            success = 0;
            break;
        }
        ASSERT(mfn_valid(mfn));

        index = (gva >> PT_SHIFT[mode][lev]) & (PT_ENTRIES[mode][lev]-1);

#if GUEST_PAGING_LEVELS >= 4
        if ( lev == 4 )
        {
            l4e = map_domain_page(mfn);
            if ( !(l4e_get_flags(l4e[index]) & _PAGE_PRESENT) )
            {
                HAP_PRINTK("Level 4 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l4e_get_pfn(l4e[index]);
            unmap_domain_page(l4e);
        }
#endif

#if GUEST_PAGING_LEVELS >= 3
        if ( lev == 3 )
        {
            l3e = map_domain_page(mfn);
#if GUEST_PAGING_LEVELS == 3
            index += ((gcr3 >> 5) & 127) * 4;
#endif
            if ( !(l3e_get_flags(l3e[index]) & _PAGE_PRESENT) )
            {
                HAP_PRINTK("Level 3 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l3e_get_pfn(l3e[index]);
            unmap_domain_page(l3e);
        }
#endif

        if ( lev == 2 )
        {
            l2e = map_domain_page(mfn);
            if ( !(l2e_get_flags(l2e[index]) & _PAGE_PRESENT) )
            {
                HAP_PRINTK("Level 2 entry not present at index = %d\n", index);
                success = 0;
            }

            if ( l2e_get_flags(l2e[index]) & _PAGE_PSE )
            {
                paddr_t mask = ((paddr_t)1 << PT_SHIFT[mode][2]) - 1;
                HAP_PRINTK("guest page table is PSE\n");
                gpa = (l2e_get_intpte(l2e[index]) & ~mask) + (gva & mask);
                unmap_domain_page(l2e);
                break; /* last level page table, jump out from here */
            }

            gpfn = l2e_get_pfn(l2e[index]);
            unmap_domain_page(l2e);
        }

        if ( lev == 1 )
        {
            l1e = map_domain_page(mfn);
            if ( !(l1e_get_flags(l1e[index]) & _PAGE_PRESENT) )
            {
                HAP_PRINTK("Level 1 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l1e_get_pfn(l1e[index]);
            gpa = (l1e_get_intpte(l1e[index]) & PAGE_MASK) + (gva &~PAGE_MASK);
            unmap_domain_page(l1e);
        }

        if ( success != 1 ) /* error happened, jump out */
            break;
    }

    gpa &= PADDR_MASK;
    HAP_PRINTK("success = %d, gva = %lx, gpa = %lx\n", success, gva, gpa);

    return (!success ? INVALID_GFN : ((paddr_t)gpa >> PAGE_SHIFT));
}

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

