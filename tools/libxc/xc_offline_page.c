/******************************************************************************
 * xc_offline_page.c
 *
 * Helper functions to offline/online one page
 *
 * Copyright (c) 2003, K A Fraser.
 * Copyright (c) 2009, Intel Corporation.
 */

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "xc_private.h"
#include "xc_dom.h"
#include "xg_private.h"
#include "xg_save_restore.h"

int xc_mark_page_online(int xc, unsigned long start,
                        unsigned long end, uint32_t *status)
{
    DECLARE_SYSCTL;
    int ret = -1;

    if ( !status || (end < start) )
        return -EINVAL;

    if (lock_pages(status, sizeof(uint32_t)*(end - start + 1)))
    {
        ERROR("Could not lock memory for xc_mark_page_online\n");
        return -EINVAL;
    }

    sysctl.cmd = XEN_SYSCTL_page_offline_op;
    sysctl.u.page_offline.start = start;
    sysctl.u.page_offline.cmd = sysctl_page_online;
    sysctl.u.page_offline.end = end;
    set_xen_guest_handle(sysctl.u.page_offline.status, status);
    ret = xc_sysctl(xc, &sysctl);

    unlock_pages(status, sizeof(uint32_t)*(end - start + 1));

    return ret;
}

int xc_mark_page_offline(int xc, unsigned long start,
                          unsigned long end, uint32_t *status)
{
    DECLARE_SYSCTL;
    int ret = -1;

    if ( !status || (end < start) )
        return -EINVAL;

    if (lock_pages(status, sizeof(uint32_t)*(end - start + 1)))
    {
        ERROR("Could not lock memory for xc_mark_page_offline");
        return -EINVAL;
    }

    sysctl.cmd = XEN_SYSCTL_page_offline_op;
    sysctl.u.page_offline.start = start;
    sysctl.u.page_offline.cmd = sysctl_page_offline;
    sysctl.u.page_offline.end = end;
    set_xen_guest_handle(sysctl.u.page_offline.status, status);
    ret = xc_sysctl(xc, &sysctl);

    unlock_pages(status, sizeof(uint32_t)*(end - start + 1));

    return ret;
}

int xc_query_page_offline_status(int xc, unsigned long start,
                                 unsigned long end, uint32_t *status)
{
    DECLARE_SYSCTL;
    int ret = -1;

    if ( !status || (end < start) )
        return -EINVAL;

    if (lock_pages(status, sizeof(uint32_t)*(end - start + 1)))
    {
        ERROR("Could not lock memory for xc_query_page_offline_status\n");
        return -EINVAL;
    }

    sysctl.cmd = XEN_SYSCTL_page_offline_op;
    sysctl.u.page_offline.start = start;
    sysctl.u.page_offline.cmd = sysctl_query_page_offline;
    sysctl.u.page_offline.end = end;
    set_xen_guest_handle(sysctl.u.page_offline.status, status);
    ret = xc_sysctl(xc, &sysctl);

    unlock_pages(status, sizeof(uint32_t)*(end - start + 1));

    return ret;
}
