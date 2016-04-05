/*
 * Copyright (C) 2016
 * Author Wei Liu <wei.liu2@citrix.com>
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

void libxl__colo_restore_setup(libxl__egc *egc,
                               libxl__colo_restore_state *crs)
{
    STATE_AO_GC(crs->ao);

    LOG(ERROR, "COLO is not supported");

    crs->callback(egc, crs, ERROR_FAIL);
}

void libxl__colo_restore_teardown(libxl__egc *egc, void *dcs_void,
                                  int ret, int retval, int errnoval)
{
    /* Shouldn't be here because setup already failed */
    abort();
}

void libxl__colo_save_setup(libxl__egc *egc, libxl__colo_save_state *css)
{
    libxl__domain_save_state *dss = CONTAINER_OF(css, *dss, css);
    STATE_AO_GC(dss->ao);

    LOG(ERROR, "COLO is not supported");

    dss->callback(egc, dss, ERROR_FAIL);
}

void libxl__colo_save_teardown(libxl__egc *egc,
                               libxl__colo_save_state *css,
                               int rc)
{
    /* Shouldn't be here because setup already failed */
    abort();
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
