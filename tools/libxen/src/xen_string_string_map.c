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


#include "xen_common.h"
#include "xen_internal.h"
#include "xen_string_string_map.h"


xen_string_string_map *
xen_string_string_map_alloc(size_t size)
{
    xen_string_string_map *result = calloc(1, sizeof(xen_string_string_map) +
                                           size * sizeof(struct xen_string_string_map_contents));
    result->size = size;
    return result;
}


void
xen_string_string_map_free(xen_string_string_map *map)
{
    if (map == NULL)
    {
        return;
    }

    size_t n = map->size;
    for (size_t i = 0; i < n; i++)
    {
        free(map->contents[i].key);
        free(map->contents[i].val);
    }

    free(map);
}
