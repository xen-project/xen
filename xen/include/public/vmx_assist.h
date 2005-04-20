/*
 * vmx_assist.h: Context definitions for the VMXASSIST world switch.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
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
#ifndef _VMX_ASSIST_H_
#define _VMX_ASSIST_H_

#define	VMXASSIST_BASE		0xE0000
#define	VMXASSIST_MAGIC		0x17101966
#define	VMXASSIST_MAGIC_OFFSET	(VMXASSIST_BASE+8)

#define	VMXASSIST_NEW_CONTEXT	(VMXASSIST_BASE + 12)
#define	VMXASSIST_OLD_CONTEXT	(VMXASSIST_NEW_CONTEXT + 4)

#ifndef __ASSEMBLY__

union vmcs_arbytes {
	struct arbyte_fields {
		unsigned int	seg_type	: 4,
				s		: 1,
				dpl		: 2,
				p		: 1, 
			 	reserved0	: 4,
				avl		: 1,
				reserved1	: 1,     
				default_ops_size: 1,
				g		: 1,
				null_bit	: 1, 
				reserved2	: 15;
	}  __attribute__((packed)) fields;
	unsigned int bytes;
};

/*
 * World switch state
 */
typedef struct vmx_assist_context {
	unsigned long		eip;		/* execution pointer */
	unsigned long		esp;		/* stack point */
	unsigned long		eflags;		/* flags register */
	unsigned long		cr0;
	unsigned long		cr3;		/* page table directory */
	unsigned long		cr4;
	unsigned long		idtr_limit;	/* idt */
	unsigned long		idtr_base;
	unsigned long		gdtr_limit;	/* gdt */
	unsigned long		gdtr_base;
	unsigned long		cs_sel;		/* cs selector */
	unsigned long		cs_limit;
	unsigned long		cs_base;
	union vmcs_arbytes	cs_arbytes;
	unsigned long		ds_sel;		/* ds selector */
	unsigned long		ds_limit;
	unsigned long		ds_base;
	union vmcs_arbytes	ds_arbytes;
	unsigned long		es_sel;		/* es selector */
	unsigned long		es_limit;
	unsigned long		es_base;
	union vmcs_arbytes	es_arbytes;
	unsigned long		ss_sel;		/* ss selector */
	unsigned long		ss_limit;
	unsigned long		ss_base;
	union vmcs_arbytes	ss_arbytes;
	unsigned long		fs_sel;		/* fs selector */
	unsigned long		fs_limit;
	unsigned long		fs_base;
	union vmcs_arbytes	fs_arbytes;
	unsigned long		gs_sel;		/* gs selector */
	unsigned long		gs_limit;
	unsigned long		gs_base;
	union vmcs_arbytes	gs_arbytes;
	unsigned long		tr_sel;		/* task selector */
	unsigned long		tr_limit;
	unsigned long		tr_base;
	union vmcs_arbytes	tr_arbytes;
	unsigned long		ldtr_sel;	/* ldtr selector */
	unsigned long		ldtr_limit;
	unsigned long		ldtr_base;
	union vmcs_arbytes	ldtr_arbytes;
} vmx_assist_context_t;

#endif /* __ASSEMBLY__ */

#endif /* _VMX_ASSIST_H_ */

