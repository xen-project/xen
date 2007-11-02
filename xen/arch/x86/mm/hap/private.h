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
unsigned long hap_gva_to_gfn_2level(struct vcpu *v, unsigned long gva, 
                                    uint32_t *pfec);
unsigned long hap_gva_to_gfn_3level(struct vcpu *v, unsigned long gva,
                                    uint32_t *pfec);
unsigned long hap_gva_to_gfn_4level(struct vcpu *v, unsigned long gva,
                                    uint32_t *pfec);

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

#endif /* __SVM_NPT_H__ */
