/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include "config.h"
#include <xen/types.h>
#include <xen/xsplice.h>

#include <public/sysctl.h>

static char hello_world_patch_this_fnc[] = "xen_extra_version";
extern const char *xen_hello_world(void);

struct xsplice_patch_func __section(".xsplice.funcs") xsplice_xen_hello_world = {
    .version = XSPLICE_PAYLOAD_VERSION,
    .name = hello_world_patch_this_fnc,
    .new_addr = xen_hello_world,
    .old_addr = (void *)OLD_CODE,
    .new_size = NEW_CODE_SZ,
    .old_size = OLD_CODE_SZ,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
