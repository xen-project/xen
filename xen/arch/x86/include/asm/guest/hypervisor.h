/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * asm-x86/guest/hypervisor.h
 *
 * Copyright (c) 2019 Microsoft.
 */

#ifndef __X86_HYPERVISOR_H__
#define __X86_HYPERVISOR_H__

#include <xen/cpumask.h>

#include <asm/e820.h>

struct hypervisor_ops {
    /* Name of the hypervisor */
    const char *name;
    /* Main setup routine */
    void (*setup)(void);
    /* AP setup */
    int (*ap_setup)(void);
    /* Resume from suspension */
    void (*resume)(void);
    /* Fix up e820 map */
    void (*e820_fixup)(void);
    /* L0 assisted TLB flush */
    int (*flush_tlb)(const cpumask_t *mask, const void *va, unsigned int flags);
};

#ifdef CONFIG_GUEST

const char *hypervisor_probe(void);
void hypervisor_setup(void);
int hypervisor_ap_setup(void);
void hypervisor_resume(void);
void hypervisor_e820_fixup(void);
/*
 * L0 assisted TLB flush.
 * mask: cpumask of the dirty vCPUs that should be flushed.
 * va: linear address to flush, or NULL for entire address space.
 * flags: flags for flushing, including the order of va.
 */
int hypervisor_flush_tlb(const cpumask_t *mask, const void *va,
                         unsigned int flags);

#else

#include <xen/lib.h>
#include <xen/types.h>

static inline const char *hypervisor_probe(void) { return NULL; }
static inline void hypervisor_setup(void) { ASSERT_UNREACHABLE(); }
static inline int hypervisor_ap_setup(void) { return 0; }
static inline void hypervisor_resume(void) { ASSERT_UNREACHABLE(); }
static inline void hypervisor_e820_fixup(void) {}
static inline int hypervisor_flush_tlb(const cpumask_t *mask, const void *va,
                                       unsigned int flags)
{
    return -EOPNOTSUPP;
}

#endif  /* CONFIG_GUEST */

#endif /* __X86_HYPERVISOR_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
