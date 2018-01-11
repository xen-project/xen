/******************************************************************************
 * asm-x86/guest/shim.h
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
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#ifndef __X86_PV_SHIM_H__
#define __X86_PV_SHIM_H__

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
long pv_shim_cpu_up(void *data);
long pv_shim_cpu_down(void *data);
void pv_shim_online_memory(unsigned int nr, unsigned int order);
void pv_shim_offline_memory(unsigned int nr, unsigned int order);
domid_t get_initial_domain_id(void);
uint64_t pv_shim_mem(uint64_t avail);

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
static inline long pv_shim_cpu_up(void *data)
{
    ASSERT_UNREACHABLE();
    return 0;
}
static inline long pv_shim_cpu_down(void *data)
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
