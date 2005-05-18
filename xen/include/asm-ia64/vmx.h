/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx.h: prototype for generial vmx related interface
 * Copyright (c) 2004, Intel Corporation.
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
 * 	Kun Tian (Kevin Tian) (kevin.tian@intel.com)
 */

#ifndef _ASM_IA64_VT_H
#define _ASM_IA64_VT_H

extern void identify_vmx_feature(void);
extern unsigned int vmx_enabled;
extern void vmx_init_env(void);
extern void vmx_final_setup_domain(struct domain *d);
extern void vmx_save_state(struct exec_domain *ed);
extern void vmx_load_state(struct exec_domain *ed);
extern vmx_insert_double_mapping(u64,u64,u64,u64,u64);
extern void vmx_purge_double_mapping(u64, u64, u64);
extern void vmx_change_double_mapping(struct exec_domain *ed, u64 oldrr7, u64 newrr7);

#endif /* _ASM_IA64_VT_H */
