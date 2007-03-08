/*
 * arch/x86/mm/hap/support.c
 * 
 * guest page table walker
 * Copyright (c) 2007, AMD Corporation (Wei Huang)
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
 *
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
#include <asm/shadow.h>
#include <asm/hap.h>

#include "private.h"
#include "../page-guest32.h"

/*******************************************/
/*      Platform Specific Functions        */
/*******************************************/

/* Translate guest virtual address to guest physical address. Specifically
 * for real mode guest. 
 */
unsigned long hap_gva_to_gfn_real_mode(struct vcpu *v, unsigned long gva)
{
    HERE_I_AM;
    return ((paddr_t)gva >> PAGE_SHIFT);
}

/* Translate guest virtual address to guest physical address. Specifically
 * for protected guest. 
 */
unsigned long hap_gva_to_gfn_protected_mode(struct vcpu *v, unsigned long gva)
{
    unsigned long gcr3 = hvm_get_guest_ctrl_reg(v, 3);
    int mode = 2; /* two-level guest */
    int lev, index;
    paddr_t gpa = 0;
    unsigned long gpfn, mfn;
    int success = 1;
    l2_pgentry_32_t *l2e; /* guest page entry size is 32-bit */
    l1_pgentry_32_t *l1e;

    HERE_I_AM;

    gpfn = (gcr3 >> PAGE_SHIFT);
    for ( lev = mode; lev >= 1; lev-- ) {
        mfn = get_mfn_from_gpfn( gpfn );
        if ( mfn == INVALID_MFN ) {
            HAP_PRINTK("bad pfn=0x%lx from gva=0x%lx at lev%d\n", gpfn, gva, 
                       lev);
            success = 0;
            break;
        }
        index = (gva >> PT_SHIFT[mode][lev]) & (PT_ENTRIES[mode][lev]-1);

        if ( lev == 2 ) {
            l2e = map_domain_page( mfn );
            HAP_PRINTK("l2 page table entry is %ulx at index = %d\n", 
                       l2e[index].l2, index);
            if ( !(l2e_get_flags_32(l2e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 2 entry not present at index = %d\n", index);
                success = 0;
            }

            if ( l2e_get_flags_32(l2e[index]) & _PAGE_PSE ) { /* handle PSE */
                HAP_PRINTK("guest page table is PSE\n");
                if ( l2e_get_intpte(l2e[index]) & 0x001FE000UL ) { /*[13:20] */
                    printk("guest physical memory size is too large!\n");
                    domain_crash(v->domain);
                }
                gpa = (l2e_get_intpte(l2e[index]) & PHYSICAL_PAGE_4M_MASK) + 
                    (gva & ~PHYSICAL_PAGE_4M_MASK);
                unmap_domain_page(l2e);
                break; /* last level page table, return from here */
            }
            else {
                gpfn = l2e_get_pfn( l2e[index] );
            }
            unmap_domain_page(l2e);
        }

        if ( lev == 1 ) {
            l1e = map_domain_page( mfn );
            HAP_PRINTK("l1 page table entry is %ulx at index = %d\n", 
                       l1e[index].l1, index);
            if ( !(l1e_get_flags_32(l1e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 1 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l1e_get_pfn( l1e[index] );
            gpa = (l1e_get_intpte(l1e[index]) & PHYSICAL_PAGE_4K_MASK) + 
                (gva & ~PHYSICAL_PAGE_4K_MASK);	    
            unmap_domain_page(l1e);
        }

        if ( !success ) /* error happened, jump out */
            break;
    }

    HAP_PRINTK("success = %d, gva = %lx, gpa = %lx\n", success, gva, gpa);

    if ( !success ) /* error happened */
        return INVALID_GFN;
    else
        return ((paddr_t)gpa >> PAGE_SHIFT);
}



/* Translate guest virtual address to guest physical address. Specifically
 * for PAE mode guest. 
 */
unsigned long hap_gva_to_gfn_pae_mode(struct vcpu *v, unsigned long gva)
{
#if CONFIG_PAGING_LEVELS >= 3
    unsigned long gcr3 = hvm_get_guest_ctrl_reg(v, 3);
    int mode = 3; /* three-level guest */
    int lev, index;
    paddr_t gpa = 0;
    unsigned long gpfn, mfn;
    int success = 1;
    l1_pgentry_t *l1e;
    l2_pgentry_t *l2e;
    l3_pgentry_t *l3e;
    
    HERE_I_AM;

    gpfn = (gcr3 >> PAGE_SHIFT);
    for ( lev = mode; lev >= 1; lev-- ) {
        mfn = get_mfn_from_gpfn( gpfn );
        if ( mfn == INVALID_MFN ) {
            HAP_PRINTK("bad pfn=0x%lx from gva=0x%lx at lev%d\n", gpfn, gva, 
                       lev);
            success = 0;
            break;
        }
        index = (gva >> PT_SHIFT[mode][lev]) & (PT_ENTRIES[mode][lev]-1);

        if ( lev == 3 ) {
            l3e = map_domain_page( mfn );
            index += ( ((gcr3 >> 5 ) & 127 ) * 4 );
            if ( !(l3e_get_flags(l3e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 3 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l3e_get_pfn( l3e[index] );
            unmap_domain_page(l3e);
        }

        if ( lev == 2 ) {
            l2e = map_domain_page( mfn );
            if ( !(l2e_get_flags(l2e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 2 entry not present at index = %d\n", index);
                success = 0;
            }

            if ( l2e_get_flags(l2e[index]) & _PAGE_PSE ) { /* handle PSE */
                HAP_PRINTK("guest page table is PSE\n");
                gpa = (l2e_get_intpte(l2e[index]) & PHYSICAL_PAGE_2M_MASK) + 
                    (gva & ~PHYSICAL_PAGE_2M_MASK);
                unmap_domain_page(l2e);
                break; /* last level page table, jump out from here */
            }
            else { 
                gpfn = l2e_get_pfn(l2e[index]);
            }
            unmap_domain_page(l2e);
        }

        if ( lev == 1 ) {
            l1e = map_domain_page( mfn );
            if ( !(l1e_get_flags(l1e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 1 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l1e_get_pfn( l1e[index] );
            gpa = (l1e_get_intpte(l1e[index]) & PHYSICAL_PAGE_4K_MASK) + 
                (gva & ~PHYSICAL_PAGE_4K_MASK);
            unmap_domain_page(l1e);
        }

        if ( success != 1 ) /* error happened, jump out */
            break;
    }

    gpa &= ~PAGE_NX_BIT; /* clear NX bit of guest physical address */
    HAP_PRINTK("success = %d, gva = %lx, gpa = %lx\n", success, gva, gpa);

    if ( !success )
        return INVALID_GFN;
    else
        return ((paddr_t)gpa >> PAGE_SHIFT);
#else
    HERE_I_AM;
    printk("guest paging level (3) is greater than host paging level!\n");
    domain_crash(v->domain);
    return INVALID_GFN;
#endif
}



/* Translate guest virtual address to guest physical address. Specifically
 * for long mode guest. 
 */
unsigned long hap_gva_to_gfn_long_mode(struct vcpu *v, unsigned long gva)
{
#if CONFIG_PAGING_LEVELS == 4
    unsigned long gcr3 = hvm_get_guest_ctrl_reg(v, 3);
    int mode = 4; /* four-level guest */
    int lev, index;
    paddr_t gpa = 0;
    unsigned long gpfn, mfn;
    int success = 1;
    l4_pgentry_t *l4e;
    l3_pgentry_t *l3e;
    l2_pgentry_t *l2e;
    l1_pgentry_t *l1e;

    HERE_I_AM;

    gpfn = (gcr3 >> PAGE_SHIFT);
    for ( lev = mode; lev >= 1; lev-- ) {
        mfn = get_mfn_from_gpfn( gpfn );
        if ( mfn == INVALID_MFN ) {
            HAP_PRINTK("bad pfn=0x%lx from gva=0x%lx at lev%d\n", gpfn, gva, 
                       lev);
            success = 0;
            break;
        }
        index = (gva >> PT_SHIFT[mode][lev]) & (PT_ENTRIES[mode][lev]-1);

        if ( lev == 4 ) {
            l4e = map_domain_page( mfn );
            if ( !(l4e_get_flags(l4e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 4 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l4e_get_pfn( l4e[index] );
            unmap_domain_page(l4e);
        }

        if ( lev == 3 ) {
            l3e = map_domain_page( mfn );
            if ( !(l3e_get_flags(l3e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 3 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l3e_get_pfn( l3e[index] );
            unmap_domain_page(l3e);
        }

        if ( lev == 2 ) {
            l2e = map_domain_page( mfn );
            if ( !(l2e_get_flags(l2e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 2 entry not present at index = %d\n", index);
                success = 0;
            }

            if ( l2e_get_flags(l2e[index]) & _PAGE_PSE ) { /* handle PSE */
                HAP_PRINTK("guest page table is PSE\n");
                gpa = (l2e_get_intpte(l2e[index]) & PHYSICAL_ADDR_2M_MASK_LM) 
                    + (gva & ~PHYSICAL_PAGE_2M_MASK);
                unmap_domain_page(l2e);
                break; /* last level page table, jump out from here */
            }
            else { 
                gpfn = l2e_get_pfn(l2e[index]);
            }
            unmap_domain_page(l2e);
        }

        if ( lev == 1 ) {
            l1e = map_domain_page( mfn );
            if ( !(l1e_get_flags(l1e[index]) & _PAGE_PRESENT) ) {
                HAP_PRINTK("Level 1 entry not present at index = %d\n", index);
                success = 0;
            }
            gpfn = l1e_get_pfn( l1e[index] );
            gpa = (l1e_get_intpte(l1e[index]) & PHYSICAL_ADDR_4K_MASK_LM) + 
                (gva & ~PHYSICAL_PAGE_4K_MASK);
            unmap_domain_page(l1e);
        }

        if ( success != 1 ) /* error happened, jump out */
            break;
    }

    gpa &= ~PAGE_NX_BIT; /* clear NX bit of guest physical address */
    HAP_PRINTK("success = %d, gva = %lx, gpa = %lx\n", success, gva, gpa);

    if ( !success )
        return INVALID_GFN;
    else
        return ((paddr_t)gpa >> PAGE_SHIFT);
#else
    HERE_I_AM;
    printk("guest paging level (4) is greater than host paging level!\n");
    domain_crash(v->domain);
    return INVALID_GFN;
#endif
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

