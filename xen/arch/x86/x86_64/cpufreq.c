/******************************************************************************
 * cpufreq.c -- adapt 32b compat guest to 64b hypervisor.
 *
 *  Copyright (C) 2008, Liu Jinsong <jinsong.liu@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <xen/types.h>
#include <xen/xmalloc.h>
#include <xen/guest_access.h>
#include <xen/pmstat.h>
#include <compat/platform.h>

DEFINE_XEN_GUEST_HANDLE(compat_processor_px_t);

int 
compat_set_px_pminfo(uint32_t cpu, struct compat_processor_performance *perf)
{
    struct xen_processor_performance *xen_perf;
    unsigned long xlat_page_current;

    xlat_malloc_init(xlat_page_current);

    xen_perf = xlat_malloc_array(xlat_page_current,
                                  struct xen_processor_performance, 1);
    if ( unlikely(xen_perf == NULL) )
	return -EFAULT;

#define XLAT_processor_performance_HNDL_states(_d_, _s_) do { \
    XEN_GUEST_HANDLE(compat_processor_px_t) states; \
    XEN_GUEST_HANDLE_PARAM(xen_processor_px_t) states_t; \
    if ( unlikely(!compat_handle_okay((_s_)->states, (_s_)->state_count)) ) \
        return -EFAULT; \
    guest_from_compat_handle(states, (_s_)->states); \
    states_t = guest_handle_cast(states, xen_processor_px_t); \
    (_d_)->states = guest_handle_from_param(states_t, xen_processor_px_t); \
} while (0)

    XLAT_processor_performance(xen_perf, perf);
#undef XLAT_processor_performance_HNDL_states

    return set_px_pminfo(cpu, xen_perf);
}
