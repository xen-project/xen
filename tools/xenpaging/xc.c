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
#include <stdarg.h>
#include <sys/poll.h>
#include <xc_private.h>
#include <xs.h>
#include "xc.h"




int xc_wait_for_event_or_timeout(xc_interface *xch, xc_evtchn *xce, unsigned long ms)
{
    struct pollfd fd = { .fd = xc_evtchn_fd(xce), .events = POLLIN | POLLERR };
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
        port = xc_evtchn_pending(xce);
        if ( port == -1 )
        {
            ERROR("Failed to read port from event channel");
            goto err;
        }
        
        rc = xc_evtchn_unmask(xce, port);
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




/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
