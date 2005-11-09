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

#define RR7_SWITCH_SHIFT	12	/* 4k enough */
#include <public/io/ioreq.h>

extern void identify_vmx_feature(void);
extern unsigned int vmx_enabled;
extern void vmx_init_env(void);
extern void vmx_final_setup_guest(struct vcpu *v);
extern void vmx_save_state(struct vcpu *v);
extern void vmx_load_state(struct vcpu *v);
extern void vmx_setup_platform(struct domain *d, struct vcpu_guest_context *c);
#ifdef XEN_DBL_MAPPING
extern vmx_insert_double_mapping(u64,u64,u64,u64,u64);
extern void vmx_purge_double_mapping(u64, u64, u64);
extern void vmx_change_double_mapping(struct vcpu *v, u64 oldrr7, u64 newrr7);
extern void vmx_init_double_mapping_stub(void);
#endif

extern void vmx_wait_io(void);
extern void vmx_io_assist(struct vcpu *v);

static inline vcpu_iodata_t *get_vio(struct domain *d, unsigned long cpu)
{
    return &((shared_iopage_t *)d->arch.vmx_platform.shared_page_va)->vcpu_iodata[cpu];
}

static inline int iopacket_port(struct domain *d)
{
    return ((shared_iopage_t *)d->arch.vmx_platform.shared_page_va)->sp_global.eport;
}

static inline shared_iopage_t *get_sp(struct domain *d)
{
    return (shared_iopage_t *)d->arch.vmx_platform.shared_page_va;
}

typedef unsigned long (*vmx_mmio_read_t)(struct vcpu *v,
                                         unsigned long addr,
                                         unsigned long length);

typedef void (*vmx_mmio_write_t)(struct vcpu *v,
                                 unsigned long addr,
                                 unsigned long length,
                                 unsigned long val);

typedef int (*vmx_mmio_check_t)(struct vcpu *v, unsigned long addr);

struct vmx_mmio_handler {
    vmx_mmio_check_t check_handler;
    vmx_mmio_read_t read_handler;
    vmx_mmio_write_t write_handler;
};

#endif /* _ASM_IA64_VT_H */
