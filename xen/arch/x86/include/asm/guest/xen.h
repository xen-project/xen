/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * asm-x86/guest/xen.h
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#ifndef __X86_GUEST_XEN_H__
#define __X86_GUEST_XEN_H__

#include <xen/types.h>

#include <asm/e820.h>
#include <asm/fixmap.h>
#include <asm/guest/hypervisor.h>

#define XEN_shared_info ((struct shared_info *)fix_to_virt(FIX_XEN_SHARED_INFO))

#ifdef CONFIG_XEN_GUEST

extern bool xen_guest;
extern bool pv_console;
extern uint32_t xen_cpuid_base;

const struct hypervisor_ops *xg_probe(void);
int xg_alloc_unused_page(mfn_t *mfn);
int xg_free_unused_page(mfn_t mfn);

DECLARE_PER_CPU(unsigned int, vcpu_id);
DECLARE_PER_CPU(struct vcpu_info *, vcpu_info);

#else

#define xen_guest 0
#define pv_console 0

static inline const struct hypervisor_ops *xg_probe(void) { return NULL; }

#endif /* CONFIG_XEN_GUEST */
#endif /* __X86_GUEST_XEN_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
