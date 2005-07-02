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

#define	VMXASSIST_BASE		0xD0000
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
	} fields;
	unsigned int bytes;
};

/*
 * World switch state
 */
typedef struct vmx_assist_context {
	u32		eip;		/* execution pointer */
	u32		esp;		/* stack point */
	u32		eflags;		/* flags register */
	u32		cr0;
	u32		cr3;		/* page table directory */
	u32		cr4;
	u32		idtr_limit;	/* idt */
	u32		idtr_base;
	u32		gdtr_limit;	/* gdt */
	u32		gdtr_base;
	u32		cs_sel;		/* cs selector */
	u32		cs_limit;
	u32		cs_base;
	union vmcs_arbytes	cs_arbytes;
	u32		ds_sel;		/* ds selector */
	u32		ds_limit;
	u32		ds_base;
	union vmcs_arbytes	ds_arbytes;
	u32		es_sel;		/* es selector */
	u32		es_limit;
	u32		es_base;
	union vmcs_arbytes	es_arbytes;
	u32		ss_sel;		/* ss selector */
	u32		ss_limit;
	u32		ss_base;
	union vmcs_arbytes	ss_arbytes;
	u32		fs_sel;		/* fs selector */
	u32		fs_limit;
	u32		fs_base;
	union vmcs_arbytes	fs_arbytes;
	u32		gs_sel;		/* gs selector */
	u32		gs_limit;
	u32		gs_base;
	union vmcs_arbytes	gs_arbytes;
	u32		tr_sel;		/* task selector */
	u32		tr_limit;
	u32		tr_base;
	union vmcs_arbytes	tr_arbytes;
	u32		ldtr_sel;	/* ldtr selector */
	u32		ldtr_limit;
	u32		ldtr_base;
	union vmcs_arbytes	ldtr_arbytes;
} vmx_assist_context_t;

#endif /* __ASSEMBLY__ */

#endif /* _VMX_ASSIST_H_ */

