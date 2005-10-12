/*
 * gen.c: Generate assembler symbols.
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
 */
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <vm86.h>

int
main(void)
{
	printf("/* MACHINE GENERATED; DO NOT EDIT */\n");
	printf("#define VMX_ASSIST_CTX_GS_SEL	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, gs_sel));
	printf("#define VMX_ASSIST_CTX_FS_SEL	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, fs_sel));
	printf("#define VMX_ASSIST_CTX_DS_SEL	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, ds_sel));
	printf("#define VMX_ASSIST_CTX_ES_SEL	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, es_sel));
	printf("#define VMX_ASSIST_CTX_SS_SEL	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, ss_sel));
	printf("#define VMX_ASSIST_CTX_ESP	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, esp));
	printf("#define VMX_ASSIST_CTX_EFLAGS	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, eflags));
	printf("#define VMX_ASSIST_CTX_CS_SEL	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, cs_sel));
	printf("#define VMX_ASSIST_CTX_EIP	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, eip));

	printf("#define VMX_ASSIST_CTX_CR0	0x%x\n",
		(unsigned int)offsetof(struct vmx_assist_context, cr0));

	return 0;
}
