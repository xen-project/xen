/*
 * Copyright (C) 2015      Citrix Ltd.
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

#include "libxl_osdeps.h"

#include "libxl_internal.h"

void libxl__conversion_helper_init(libxl__conversion_helper_state *chs)
{
    libxl__ev_child_init(&chs->child);
}

int libxl__convert_legacy_stream(libxl__egc *egc,
                                 libxl__conversion_helper_state *chs)
{
    return ERROR_FAIL;
}

void libxl__conversion_helper_abort(libxl__egc *egc,
                                    libxl__conversion_helper_state *chs,
                                    int rc)
{
    /* no op */
}
