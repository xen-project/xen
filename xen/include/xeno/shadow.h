/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */

#ifndef _XENO_SHADOW_H
#define _XENO_SHADOW_H

#ifdef CONFIG_SHADOW

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/mm.h>

/* Shadow PT flag bits in pfn_info */
#define PSH_shadowed	(1<<31) /* page has a shadow. PFN points to shadow */
#define PSH_shadow	    (1<<30) /* page is a shadow. PFN points to orig page */
#define PSH_pending	    (1<<29) /* page is in the process of being shadowed */
#define PSH_pfn_mask	((1<<21)-1)

/* Shadow PT operation mode : shadowmode variable in mm_struct */
#define SHM_test        (1<<0) /* just run domain on shadow PTs */
#define SHM_logdirty    (1<<1) /* log pages that are dirtied */
#define SHM_cow         (1<<2) /* copy on write all dirtied pages */
#define SHM_translate   (1<<3) /* lookup machine pages in translation table */

#define shadow_linear_pg_table ((l1_pgentry_t *)SH_LINEAR_PT_VIRT_START)
#define shadow_linear_l2_table ((l2_pgentry_t *)(SH_LINEAR_PT_VIRT_START+(SH_LINEAR_PT_VIRT_START>>(L2_PAGETABLE_SHIFT-L1_PAGETABLE_SHIFT))))

extern pagetable_t shadow_mk_pagetable( unsigned long gptbase, unsigned int shadowmode );
extern void unshadow_table( unsigned long gpfn );
extern unsigned long shadow_l2_table( unsigned long gpfn );
extern int shadow_fault( unsigned long va, long error_code );
extern void shadow_l1_normal_pt_update( unsigned long pa, unsigned long gpte, 
										unsigned long *prev_spfn_ptr,
										l1_pgentry_t **prev_spl1e_ptr  );
extern void shadow_l2_normal_pt_update( unsigned long pa, unsigned long gpte );


#define SHADOW_DEBUG 0
#define SHADOW_OPTIMISE 1

#if SHADOW_DEBUG
extern int check_pagetable( pagetable_t pt, char *s );
#else
#define check_pagetable( pt, s )
#endif


#endif
#endif
