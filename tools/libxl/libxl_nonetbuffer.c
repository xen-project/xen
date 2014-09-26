/*
 * Copyright (C) 2014
 * Author Shriram Rajagopalan <rshriram@cs.ubc.ca>
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

int libxl__netbuffer_enabled(libxl__gc *gc)
{
    return 0;
}

int init_subkind_nic(libxl__remus_devices_state *rds)
{
    return 0;
}

void cleanup_subkind_nic(libxl__remus_devices_state *rds)
{
    return;
}

static void nic_setup(libxl__egc *egc, libxl__remus_device *dev)
{
    STATE_AO_GC(dev->rds->ao);

    dev->aodev.rc = ERROR_FAIL;
    dev->aodev.callback(egc, &dev->aodev);
}

const libxl__remus_device_instance_ops remus_device_nic = {
    .kind = LIBXL__DEVICE_KIND_VIF,
    .setup = nic_setup,
};

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
