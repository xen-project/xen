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


#include "xen_common.h"
#include "xen_int_int_map.h"
#include "xen_internal.h"


xen_int_int_map *
xen_int_int_map_alloc(size_t size)
{
    xen_int_int_map *result = calloc(1, sizeof(xen_int_int_map) +
                                     size * sizeof(struct xen_int_int_map_contents));
    result->size = size;
    return result;
}


void
xen_int_int_map_free(xen_int_int_map *map)
{
    free(map);
}
