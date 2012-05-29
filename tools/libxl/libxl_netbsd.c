/*
 * Copyright (C) 2011
 * Author Roger Pau Monne <roger.pau@entel.upc.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */
 
#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

int libxl__try_phy_backend(mode_t st_mode)
{
    if (S_ISREG(st_mode) || S_ISBLK(st_mode))
        return 1;

    return 0;
}

char *libxl__devid_to_localdev(libxl__gc *gc, int devid)
{
    /* TODO */
    return NULL;
}
