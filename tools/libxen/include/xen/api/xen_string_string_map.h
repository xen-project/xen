/*
 * Copyright (c) 2006-2007, XenSource Inc.
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

#ifndef XEN_STRING_STRING_MAP_H
#define XEN_STRING_STRING_MAP_H


#include <xen/api/xen_common.h>


typedef struct xen_string_string_map_contents
{
  char *key;
  char *val;
} xen_string_string_map_contents;


typedef struct xen_string_string_map
{
    size_t size;
    xen_string_string_map_contents contents[];
} xen_string_string_map;

/**
 * Allocate a xen_string_string_map of the given size.
 */
extern xen_string_string_map *
xen_string_string_map_alloc(size_t size);

/**
 * Free the given xen_string_string_map, and all referenced values. 
 * The given map must have been allocated by this library.
 */
extern void
xen_string_string_map_free(xen_string_string_map *map);


#endif
