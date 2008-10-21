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
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <xen/config.h>
#include <xen/types.h>
#include <xen/xmalloc.h>
#include <xen/guest_access.h>
#include <compat/platform.h>

DEFINE_XEN_GUEST_HANDLE(compat_processor_px_t);

#define xlat_page_start ((unsigned long)COMPAT_ARG_XLAT_VIRT_BASE)

#define xlat_malloc_init(xlat_page_current)    do { \
    xlat_page_current = xlat_page_start; \
} while (0)

extern void *xlat_malloc(unsigned long *xlat_page_current, size_t size);

#define xlat_malloc_array(_p, _t, _c) ((_t *) xlat_malloc(&_p, sizeof(_t) * _c))

extern int 
set_px_pminfo(uint32_t cpu, struct xen_processor_performance *perf);

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
    xen_processor_px_t *xen_states = NULL; \
\
    if ( likely((_s_)->state_count > 0) ) \
    { \
        XEN_GUEST_HANDLE(compat_processor_px_t) states; \
        compat_processor_px_t state; \
        int i; \
\
        xen_states = xlat_malloc_array(xlat_page_current, \
                               xen_processor_px_t, (_s_)->state_count); \
        if ( unlikely(xen_states == NULL) ) \
            return -EFAULT; \
\
        if ( unlikely(!compat_handle_okay((_s_)->states, \
                                (_s_)->state_count)) ) \
            return -EFAULT; \
        guest_from_compat_handle(states, (_s_)->states); \
\
        for ( i = 0; i < _s_->state_count; i++ ) \
        { \
           if ( unlikely(copy_from_guest_offset(&state, states, i, 1)) ) \
               return -EFAULT; \
           XLAT_processor_px(&xen_states[i], &state); \
        } \
    } \
\
    set_xen_guest_handle((_d_)->states, xen_states); \
} while (0)
    XLAT_processor_performance(xen_perf, perf);
#undef XLAT_processor_performance_HNDL_states

    return set_px_pminfo(cpu, xen_perf);
}
