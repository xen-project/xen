/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * asm-x86/guest/shim.h
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#ifndef __X86_PV_SHIM_H__
#define __X86_PV_SHIM_H__

#include <xen/hypercall.h>
#include <xen/types.h>

#if defined(CONFIG_PV_SHIM_EXCLUSIVE)
# define pv_shim 1
#elif defined(CONFIG_PV_SHIM)
extern bool pv_shim;
#else
# define pv_shim 0
#endif /* CONFIG_PV_SHIM{,_EXCLUSIVE} */

#ifdef CONFIG_PV_SHIM

void pv_shim_setup_dom(struct domain *d, l4_pgentry_t *l4start,
                       unsigned long va_start, unsigned long store_va,
                       unsigned long console_va, unsigned long vphysmap,
                       start_info_t *si);
int pv_shim_shutdown(uint8_t reason);
void pv_shim_inject_evtchn(unsigned int port);
long cf_check pv_shim_cpu_up(void *data);
long cf_check pv_shim_cpu_down(void *data);
void pv_shim_online_memory(unsigned int nr, unsigned int order);
void pv_shim_offline_memory(unsigned int nr, unsigned int order);
domid_t get_initial_domain_id(void);
uint64_t pv_shim_mem(uint64_t avail);
void pv_shim_fixup_e820(void);
const struct platform_bad_page *pv_shim_reserved_pages(unsigned int *size);
typeof(do_event_channel_op) pv_shim_event_channel_op;
typeof(do_grant_table_op) pv_shim_grant_table_op;

#else

static inline void pv_shim_setup_dom(struct domain *d, l4_pgentry_t *l4start,
                                     unsigned long va_start,
                                     unsigned long store_va,
                                     unsigned long console_va,
                                     unsigned long vphysmap,
                                     start_info_t *si)
{
    ASSERT_UNREACHABLE();
}
static inline int pv_shim_shutdown(uint8_t reason)
{
    ASSERT_UNREACHABLE();
    return 0;
}
static inline void pv_shim_inject_evtchn(unsigned int port)
{
    ASSERT_UNREACHABLE();
}
static inline long cf_check pv_shim_cpu_up(void *data)
{
    ASSERT_UNREACHABLE();
    return 0;
}
static inline long cf_check pv_shim_cpu_down(void *data)
{
    ASSERT_UNREACHABLE();
    return 0;
}
static inline void pv_shim_online_memory(unsigned int nr, unsigned int order)
{
    ASSERT_UNREACHABLE();
}
static inline void pv_shim_offline_memory(unsigned int nr, unsigned int order)
{
    ASSERT_UNREACHABLE();
}
static inline domid_t get_initial_domain_id(void)
{
    return 0;
}
static inline uint64_t pv_shim_mem(uint64_t avail)
{
    ASSERT_UNREACHABLE();
    return 0;
}
static inline void pv_shim_fixup_e820(void)
{
    ASSERT_UNREACHABLE();
}
static inline const struct platform_bad_page *
pv_shim_reserved_pages(unsigned int *s)
{
    ASSERT_UNREACHABLE();
    return NULL;
}

#endif

#endif /* __X86_PV_SHIM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
