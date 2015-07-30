/******************************************************************************
 * cpu_idle.c -- adapt x86/acpi/cpu_idle.c to compat guest.
 *
 *  Copyright (C) 2007, 2008 Intel Corporation
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

#define __XEN_TOOLS__ /* for using get_xen_guest_handle macro */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/xmalloc.h>
#include <xen/guest_access.h>
#include <xen/pmstat.h>
#include <compat/platform.h>

CHECK_processor_csd;

DEFINE_XEN_GUEST_HANDLE(compat_processor_csd_t);
DEFINE_XEN_GUEST_HANDLE(compat_processor_cx_t);

void *xlat_malloc(unsigned long *xlat_page_current, size_t size)
{
    void *ret;

    /* normalize size to be 64 * n */
    size = (size + 0x3fUL) & ~0x3fUL;

    if ( unlikely(size > xlat_page_left_size(*xlat_page_current)) )
        return NULL;

    ret = (void *) *xlat_page_current;
    *xlat_page_current += size;

    return ret;
}

static int copy_from_compat_state(xen_processor_cx_t *xen_state,
                                  compat_processor_cx_t *state)
{
#define XLAT_processor_cx_HNDL_dp(_d_, _s_) do { \
    XEN_GUEST_HANDLE(compat_processor_csd_t) dps; \
    XEN_GUEST_HANDLE_PARAM(xen_processor_csd_t) dps_param; \
    if ( unlikely(!compat_handle_okay((_s_)->dp, (_s_)->dpcnt)) ) \
            return -EFAULT; \
    guest_from_compat_handle(dps, (_s_)->dp); \
    dps_param = guest_handle_cast(dps, xen_processor_csd_t); \
    (_d_)->dp = guest_handle_from_param(dps_param, xen_processor_csd_t); \
} while (0)
    XLAT_processor_cx(xen_state, state);
#undef XLAT_processor_cx_HNDL_dp

    return 0;
}

long compat_set_cx_pminfo(uint32_t cpu, struct compat_processor_power *power)
{
    struct xen_processor_power *xen_power;
    unsigned long xlat_page_current;

    xlat_malloc_init(xlat_page_current);

    xen_power = xlat_malloc_array(xlat_page_current,
                                  struct xen_processor_power, 1);
    if ( unlikely(xen_power == NULL) )
	return -EFAULT;

#define XLAT_processor_power_HNDL_states(_d_, _s_) do { \
    xen_processor_cx_t *xen_states = NULL; \
\
    if ( likely((_s_)->count > 0) ) \
    { \
        XEN_GUEST_HANDLE(compat_processor_cx_t) states; \
        compat_processor_cx_t state; \
        int i; \
\
        xen_states = xlat_malloc_array(xlat_page_current, \
                                       xen_processor_cx_t, (_s_)->count); \
        if ( unlikely(xen_states == NULL) ) \
            return -EFAULT; \
\
        if ( unlikely(!compat_handle_okay((_s_)->states, (_s_)->count)) ) \
            return -EFAULT; \
        guest_from_compat_handle(states, (_s_)->states); \
\
        for ( i = 0; i < _s_->count; i++ ) \
        { \
           if ( unlikely(copy_from_guest_offset(&state, states, i, 1)) ) \
               return -EFAULT; \
           if ( unlikely(copy_from_compat_state(&xen_states[i], &state)) ) \
               return -EFAULT; \
        } \
    } \
\
    set_xen_guest_handle((_d_)->states, xen_states); \
} while (0)
    XLAT_processor_power(xen_power, power);
#undef XLAT_processor_power_HNDL_states

    return set_cx_pminfo(cpu, xen_power);
}
