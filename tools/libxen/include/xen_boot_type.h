/*
 * Copyright (c) 2006, XenSource Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef XEN_BOOT_TYPE_H
#define XEN_BOOT_TYPE_H


#include "xen_common.h"


enum xen_boot_type
{
    /**
     * boot an HVM guest using an emulated BIOS
     */
    XEN_BOOT_TYPE_BIOS,

    /**
     * boot from inside the machine using grub
     */
    XEN_BOOT_TYPE_GRUB,

    /**
     * boot from an external kernel
     */
    XEN_BOOT_TYPE_KERNEL_EXTERNAL,

    /**
     * boot from a kernel inside the guest filesystem
     */
    XEN_BOOT_TYPE_KERNEL_INTERNAL
};


typedef struct xen_boot_type_set
{
    size_t size;
    enum xen_boot_type contents[];
} xen_boot_type_set;

/**
 * Allocate a xen_boot_type_set of the given size.
 */
extern xen_boot_type_set *
xen_boot_type_set_alloc(size_t size);

/**
 * Free the given xen_boot_type_set.  The given set must have been
 * allocated by this library.
 */
extern void
xen_boot_type_set_free(xen_boot_type_set *set);


/**
 * Return the name corresponding to the given code.  This string must
 * not be modified or freed.
 */
extern const char *
xen_boot_type_to_string(enum xen_boot_type val);


/**
 * Return the correct code for the given string, or set the session
 * object to failure and return an undefined value if the given string does
 * not match a known code.
 */
extern enum xen_boot_type
xen_boot_type_from_string(xen_session *session, const char *str);


#endif
