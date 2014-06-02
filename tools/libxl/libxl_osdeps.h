/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
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

/*
 * This header must be included first, before any system headers,
 * so that _GNU_SOURCE takes effect properly.
 */

#ifndef LIBXL_OSDEP
#define LIBXL_OSDEP

#define _GNU_SOURCE

#if defined(__NetBSD__)
#define SYSFS_PCI_DEV          "/sys/bus/pci/devices"
#define SYSFS_PCIBACK_DRIVER   "/kern/xen/pci"
#define NETBACK_NIC_NAME       "xvif%ui%d"
#include <util.h>
#elif defined(__OpenBSD__)
#include <util.h>
#elif defined(__linux__)
#define SYSFS_PCI_DEV          "/sys/bus/pci/devices"
#define SYSFS_PCIBACK_DRIVER   "/sys/bus/pci/drivers/pciback"
#define NETBACK_NIC_NAME       "vif%u.%d"
#include <pty.h>
#elif defined(__sun__)
#include <stropts.h>
#elif defined(__FreeBSD__)
#define SYSFS_PCI_DEV          "/dev/null"
#define SYSFS_PCIBACK_DRIVER   "/dev/null"
#define NETBACK_NIC_NAME       "xnb%u.%d"
#include <libutil.h>
#endif

#ifndef SYSFS_PCIBACK_DRIVER
#error define SYSFS_PCIBACK_DRIVER for your platform
#endif
#ifndef SYSFS_PCI_DEV
#error define SYSFS_PCI_DEV for your platform
#endif

#ifdef NEED_OWN_ASPRINTF
#include <stdarg.h>

int asprintf(char **buffer, char *fmt, ...);
int vasprintf(char **buffer, const char *fmt, va_list ap);
#endif /*NEED_OWN_ASPRINTF*/

#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
