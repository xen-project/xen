/*
 * arch/x86/mm/hap/private.h
 *
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
#ifndef __HAP_PRIVATE_H__
#define __HAP_PRIVATE_H__

#include <asm/flushtlb.h>
#include <asm/hvm/support.h>

/********************************************/
/*          GUEST TRANSLATION FUNCS         */
/********************************************/
unsigned long hap_gva_to_gfn_real_mode(struct vcpu *v, unsigned long gva);
unsigned long hap_gva_to_gfn_protected_mode(struct vcpu *v, unsigned long gva);
unsigned long hap_gva_to_gfn_pae_mode(struct vcpu *v, unsigned long gva);
unsigned long hap_gva_to_gfn_long_mode(struct vcpu *v, unsigned long gva);
/********************************************/
/*            MISC DEFINITIONS              */
/********************************************/

/* PT_SHIFT describes the amount by which a virtual address is shifted right 
 * to right justify the portion to be used for indexing into a page 
 * table, given the guest memory model (i.e. number of levels) and the level 
 * of the page table being accessed. The idea is from Virtual Iron's code.
 */
static const int PT_SHIFT[][5] =
  {   /*     ------  level ------           nr_levels  */
    /*         1     2     3     4                   */
    {    0,    0,    0,    0,    0},   /* 0 not used */
    {    0,    0,    0,    0,    0},   /* 1 not used */
    {    0,   12,   22,    0,    0},   /* 2  */
    {    0,   12,   21,   30,    0},   /* 3  */
    {    0,   12,   21,   30,   39}    /* 4  */
  };

/* PT_ENTRIES describes the number of entries in a page table, given the 
 * memory model (i.e. number of levels) and the level of the page table 
 * being considered. This idea from Virtual Iron's shadow code*/
static const int PT_ENTRIES[][5] =
  {   /*     ------  level ------           nr_levels  */
    /*         1     2     3     4                   */
    {    0,    0,    0,    0,    0},   /* 0 not used */
    {    0,    0,    0,    0,    0},   /* 1 not used */
    {    0, 1024, 1024,    0,    0},   /* 2  */
    {    0,  512,  512,    4,    0},   /* 3  */
    {    0,  512,  512,  512,  512}    /* 4  */
  };

/********************************************/
/*       PAGING DEFINITION FOR GUEST        */
/********************************************/
#define PHYSICAL_PAGE_4K_SIZE (1UL << 12)
#define PHYSICAL_PAGE_2M_SIZE (1UL << 21)
#define PHYSICAL_PAGE_4M_SIZE (1UL << 22)
#define PHYSICAL_PAGE_4K_MASK ( ~(PHYSICAL_PAGE_4K_SIZE - 1) )
#define PHYSICAL_PAGE_2M_MASK ( ~(PHYSICAL_PAGE_2M_SIZE - 1) )
#define PHYSICAL_PAGE_4M_MASK ( ~(PHYSICAL_PAGE_4M_SIZE - 1) )

/* long mode physical address mask */
#define PHYSICAL_ADDR_BITS_LM    52
#define PHYSICAL_ADDR_MASK_LM    ((1UL << PHYSICAL_ADDR_BITS_LM)-1)
#define PHYSICAL_ADDR_2M_MASK_LM (PHYSICAL_PAGE_2M_MASK & PHYSICAL_ADDR_MASK_LM)
#define PHYSICAL_ADDR_4K_MASK_LM (PHYSICAL_PAGE_4K_MASK & PHYSICAL_ADDR_MASK_LM)

#define PAGE_NX_BIT      (1ULL << 63)
/************************************************/
/*        PAGETABLE RELATED VARIABLES           */
/************************************************/
#if CONFIG_PAGING_LEVELS == 2
#define HAP_L1_PAGETABLE_ENTRIES    1024
#define HAP_L2_PAGETABLE_ENTRIES    1024
#define HAP_L1_PAGETABLE_SHIFT        12
#define HAP_L2_PAGETABLE_SHIFT        22
#endif

#if CONFIG_PAGING_LEVELS == 3
#define HAP_L1_PAGETABLE_ENTRIES     512
#define HAP_L2_PAGETABLE_ENTRIES     512
#define HAP_L3_PAGETABLE_ENTRIES       4
#define HAP_L1_PAGETABLE_SHIFT        12
#define HAP_L2_PAGETABLE_SHIFT        21
#define HAP_L3_PAGETABLE_SHIFT        30
#endif

#if CONFIG_PAGING_LEVELS == 4
#define HAP_L1_PAGETABLE_ENTRIES     512
#define HAP_L2_PAGETABLE_ENTRIES     512
#define HAP_L3_PAGETABLE_ENTRIES     512
#define HAP_L4_PAGETABLE_ENTRIES     512
#define HAP_L1_PAGETABLE_SHIFT        12
#define HAP_L2_PAGETABLE_SHIFT        21
#define HAP_L3_PAGETABLE_SHIFT        30
#define HAP_L4_PAGETABLE_SHIFT        39
#endif

#endif /* __SVM_NPT_H__ */
