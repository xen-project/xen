/*
 * Copyright (C) 2018      Aporeto
 * Author Stefano Stabellini <stefano@aporeto.com>
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

static int libxl__device_pvcallsif_setdefault(libxl__gc *gc, uint32_t domid,
                                              libxl_device_pvcallsif *pvcallsif,
                                              bool hotplug)
{
    return libxl__resolve_domid(gc, pvcallsif->backend_domname,
                                &pvcallsif->backend_domid);
}

static LIBXL_DEFINE_UPDATE_DEVID(pvcallsif)
static LIBXL_DEFINE_DEVICE_FROM_TYPE(pvcallsif)

#define libxl__add_pvcallsifs NULL
#define libxl_device_pvcallsif_list NULL
#define libxl_device_pvcallsif_compare NULL

LIBXL_DEFINE_DEVICE_REMOVE(pvcallsif)

DEFINE_DEVICE_TYPE_STRUCT(pvcallsif, PVCALLS);
