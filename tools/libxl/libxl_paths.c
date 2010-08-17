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

#include "libxl.h"
#include "_libxl_paths.h"

const char *libxl_sbindir_path(void)
{
    return SBINDIR;
}

const char *libxl_bindir_path(void)
{
    return BINDIR;
}

const char *libxl_libexec_path(void)
{
    return LIBEXEC;
}

const char *libxl_libdir_path(void)
{
    return LIBDIR;
}

const char *libxl_sharedir_path(void)
{
    return SHAREDIR;
}

const char *libxl_private_bindir_path(void)
{
    return PRIVATE_BINDIR;
}

const char *libxl_xenfirmwaredir_path(void)
{
    return XENFIRMWAREDIR;
}

const char *libxl_xen_config_dir_path(void)
{
    return XEN_CONFIG_DIR;
}

const char *libxl_xen_script_dir_path(void)
{
    return XEN_SCRIPT_DIR;
}

