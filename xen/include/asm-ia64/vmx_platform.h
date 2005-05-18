/*
 * vmx_platform.h: VMX platform support
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
 */
#ifndef __ASM_IA64_VMX_PLATFORM_H__
#define __ASM_IA64_VMX_PLATFORM_H__

#include <public/xen.h>


struct mmio_list;
typedef struct virutal_platform_def {
    //unsigned long          *real_mode_data; /* E820, etc. */
    //unsigned long          shared_page_va;
    //struct vmx_virpit_t    vmx_pit;
    //struct vmx_handler_t   vmx_handler;
    //struct mi_per_cpu_info mpci;            /* MMIO */
    unsigned long       pib_base;
    unsigned char       xtp;
    struct mmio_list    *mmio;
} vir_plat_t;

#endif
