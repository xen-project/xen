/*
 * Copyright (C) 2005 Jimi Xenidis <jimix@watson.ibm.com>, IBM Corporation
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <asm/config.h>
#include <asm/processor.h>
#include <asm/papr.h>
#include <asm/asm-offsets.h>

#define HSC	.long 0x44000022

	
/* in is unsused */
#define PAPR(in, out, name, func_code)	\
	_GLOBAL(name);	 		\
	std r3,-GPR_WIDTH(r1); 		\
	li r3,func_code; 		\
	HSC;				\
	ld r12,-GPR_WIDTH(r1);		\
	cmpi 0,r12,0;			\
        bne ret	## out;	/* only store regs if r12 != NULL */ \
	b ret0

ret8:	std r11, 7 * GPR_WIDTH(r12)
ret7:	std r10, 6 * GPR_WIDTH(r12)
ret6:	std r9, 5 * GPR_WIDTH(r12)
ret5:	std r8, 4 * GPR_WIDTH(r12)
ret4:	std r7, 3 * GPR_WIDTH(r12)
ret3:	std r6, 2 * GPR_WIDTH(r12)
ret2:	std r5, 1 * GPR_WIDTH(r12)
ret1:	std r4, 0 * GPR_WIDTH(r12)
	nop
ret0:	blr
	
PAPR(5, 2,papr_remove, H_REMOVE)
PAPR(5, 1,papr_clear_mod, H_CLEAR_MOD)
PAPR(5, 1,papr_clear_ref, H_CLEAR_REF)
PAPR(5, 0,papr_protect, H_PROTECT)
PAPR(1, 0,papr_eoi, H_EOI)
PAPR(5, 1,papr_cppr, H_CPPR)
PAPR(5, 2,papr_ipi, H_IPI)
PAPR(5, 1,papr_ipoll, H_IPOLL)
PAPR(5, 1,papr_xirr, H_XIRR)
PAPR(2, 0,papr_interrupt, H_INTERRUPT)
PAPR(5, 1,papr_logical_ci_load_64, H_LOGICAL_CI_LOAD)
PAPR(5, 0,papr_logical_ci_store_64, H_LOGICAL_CI_STORE)
PAPR(5, 1,papr_logical_cache_load_64, H_LOGICAL_CACHE_LOAD)
PAPR(5, 0,papr_logical_cache_store_64, H_LOGICAL_CACHE_STORE)
PAPR(5, 0,papr_logical_icbi, H_LOGICAL_ICBI)
PAPR(5, 0,papr_logical_dcbf, H_LOGICAL_DCBF)
PAPR(5, 1,papr_set_dabr, H_SET_DABR)
PAPR(5, 1,papr_real_to_logical, H_REAL_TO_LOGICAL)
PAPR(5, 1,papr_pci_config_read, H_PCI_CONFIG_READ)
PAPR(5, 0,papr_pci_config_write, H_PCI_CONFIG_WRITE)

	PAPR(5, 1,papr_grant_logical, H_GRANT_LOGICAL)
PAPR(1, 1,papr_accept_logical, H_ACCEPT_LOGICAL)
PAPR(0, 2,papr_rescind_logical, H_RESCIND_LOGICAL)
PAPR(3, 0,papr_register_vterm, H_REGISTER_VTERM)
PAPR(4, 0,papr_vterm_partner_info, H_VTERM_PARTNER_INFO)
PAPR(1, 0,papr_free_vterm, H_FREE_VTERM)

/* Definitions for hypervisor functions. Note that we do not use the
 * first macro arg */

PAPR(x, 1,papr_enter, H_ENTER)
PAPR(x, 8,papr_read, H_READ)
PAPR(x, 1,papr_thread_control, H_THREAD_CONTROL)
PAPR(x, 0,papr_cede, H_CEDE)

PAPR(x, 0,papr_page_init, H_PAGE_INIT)
PAPR(x, 1,papr_set_asr, H_SET_ASR)  /* ISTAR only. */
PAPR(x, 0,papr_asr_on, H_ASR_ON)  /* ISTAR only. */
PAPR(x, 0,papr_asr_off, H_ASR_OFF)  /* ISTAR only. */

PAPR(x, 8,papr_hypervisor_data, H_HYPERVISOR_DATA)

PAPR(x, 2,papr_get_xive, H_GET_XIVE)
PAPR(x, 0,papr_set_xive, H_SET_XIVE)


PAPR(x, 0,papr_put_term_char, H_PUT_TERM_CHAR)
PAPR(x, 3,papr_get_term_char, H_GET_TERM_CHAR)
