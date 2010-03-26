/******************************************************************************
 * tools/xenpaging/lib/xc.c
 *
 * libxc-type add-ons for paging support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <errno.h>
#include <string.h>
#include <sys/poll.h>
#include <xc_private.h>
#include <xg_save_restore.h>
#include <xs.h>
#include "xc.h"


int alloc_bitmap(unsigned long **bitmap, unsigned long bitmap_size)
{
    if ( *bitmap == NULL )
    {
        *bitmap = calloc(bitmap_size / BITS_PER_LONG, sizeof(unsigned long));

        if ( *bitmap == NULL )
            return -ENOMEM;
    }

    memset(*bitmap, 0, bitmap_size / 8);

    return 0;
}

int xc_mem_paging_flush_ioemu_cache(domid_t domain_id)
{
    struct xs_handle *xsh = NULL;
    char path[80];
    int rc;

    sprintf(path, "/local/domain/0/device-model/%u/command", domain_id);

    xsh = xs_daemon_open();
    if ( xsh == NULL )
        return -EIO;

    rc = xs_write(xsh, XBT_NULL, path, "flush-cache", strlen("flush-cache")); 

    xs_daemon_close(xsh);

    return rc;
}

int xc_wait_for_event_or_timeout(int xce_handle, unsigned long ms)
{
    struct pollfd fd = { .fd = xce_handle, .events = POLLIN | POLLERR };
    int port;
    int rc;
    
    rc = poll(&fd, 1, ms);
    if ( rc == -1 )
    {
        if (errno == EINTR)
            return 0;

        ERROR("Poll exited with an error");
        goto err;
    }
    
    if ( rc == 1 )
    {
        port = xc_evtchn_pending(xce_handle);
        if ( port == -1 )
        {
            ERROR("Failed to read port from event channel");
            goto err;
        }
        
        rc = xc_evtchn_unmask(xce_handle, port);
        if ( rc != 0 )
        {
            ERROR("Failed to unmask event channel port");
            goto err;
        }
    }
    else
        port = -1;
    
    return port;

 err:
    return -errno;
}

int xc_wait_for_event(int xce_handle)
{
    return xc_wait_for_event_or_timeout(xce_handle, -1);
}

int xc_get_platform_info(int xc_handle, domid_t domain_id,
                         xc_platform_info_t *platform_info)
{
    return get_platform_info(xc_handle, domain_id,
                             &platform_info->max_mfn,
                             &platform_info->hvirt_start,
                             &platform_info->pt_levels,
                             &platform_info->guest_width);
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
