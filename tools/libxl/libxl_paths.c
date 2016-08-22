/*
 * Copyright (C) 2010      Citrix Ltd.
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

const char *libxl__private_bindir_path(void)
{
    return LIBEXEC_BIN;
}

const char *libxl__xenfirmwaredir_path(void)
{
    return XENFIRMWAREDIR;
}

const char *libxl__xen_script_dir_path(void)
{
    return XEN_SCRIPT_DIR;
}

const char *libxl__run_dir_path(void)
{
    return XEN_RUN_DIR;
}

const char *libxl__seabios_path(void)
{
#ifdef SEABIOS_PATH
    return SEABIOS_PATH;
#else
    return NULL;
#endif
}

const char *libxl__ovmf_path(void)
{
#ifdef OVMF_PATH
    return OVMF_PATH;
#else
    return NULL;
#endif
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
