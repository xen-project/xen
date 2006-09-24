/*
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include "xc_private.h"
#include <xen/domctl.h>

int xc_alloc_real_mode_area(int xc_handle,
                            uint32_t domain,
                            unsigned int log)
{
    DECLARE_DOMCTL;
    int err;

    domctl.cmd = XEN_DOMCTL_real_mode_area;
    domctl.domain = (domid_t)domain;
    domctl.u.real_mode_area.log = log;

    err = do_domctl(xc_handle, &domctl);

    if (err)
        DPRINTF("Failed real mode area allocation for dom %u (log %u)\n",
                domain, log);

    return err;
}
