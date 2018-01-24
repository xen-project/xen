/*
 * Copyright (C) 2017      Aporeto
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

static int libxl__device_p9_setdefault(libxl__gc *gc, uint32_t domid,
                                       libxl_device_p9 *p9, bool hotplug)
{
    return libxl__resolve_domid(gc, p9->backend_domname, &p9->backend_domid);
}

static int libxl__set_xenstore_p9(libxl__gc *gc, uint32_t domid,
                                  libxl_device_p9 *p9,
                                  flexarray_t *back, flexarray_t *front,
                                  flexarray_t *ro_front)
{
    flexarray_append_pair(back, "path", p9->path);
    flexarray_append_pair(back, "security_model", p9->security_model);

    flexarray_append_pair(front, "tag", p9->tag);

    return 0;
}

#define libxl__add_p9s NULL
#define libxl_device_p9_list NULL
#define libxl_device_p9_compare NULL

static LIBXL_DEFINE_UPDATE_DEVID(p9)
static LIBXL_DEFINE_DEVICE_FROM_TYPE(p9)

LIBXL_DEFINE_DEVICE_REMOVE(p9)

DEFINE_DEVICE_TYPE_STRUCT(p9, 9PFS,
    .skip_attach = 1,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_p9,
);
