/******************************************************************************
 * asm-x86/guest/hypervisor.h
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
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
    void (*e820_fixup)(struct e820map *e820);
    /* L0 assisted TLB flush */
    int (*flush_tlb)(const cpumask_t *mask, const void *va, unsigned int order);
};

#ifdef CONFIG_GUEST

const char *hypervisor_probe(void);
void hypervisor_setup(void);
int hypervisor_ap_setup(void);
void hypervisor_resume(void);
void hypervisor_e820_fixup(struct e820map *e820);
/*
 * L0 assisted TLB flush.
 * mask: cpumask of the dirty vCPUs that should be flushed.
 * va: linear address to flush, or NULL for global flushes.
 * order: order of the linear address pointed by va.
 */
int hypervisor_flush_tlb(const cpumask_t *mask, const void *va,
                         unsigned int order);

#else

#include <xen/lib.h>
#include <xen/types.h>

static inline const char *hypervisor_probe(void) { return NULL; }
static inline void hypervisor_setup(void) { ASSERT_UNREACHABLE(); }
static inline int hypervisor_ap_setup(void) { return 0; }
static inline void hypervisor_resume(void) { ASSERT_UNREACHABLE(); }
static inline void hypervisor_e820_fixup(struct e820map *e820) {}
static inline int hypervisor_flush_tlb(const cpumask_t *mask, const void *va,
                                       unsigned int order)
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
