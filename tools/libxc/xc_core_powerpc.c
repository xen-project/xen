/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 * Copyright IBM Corp. 2007
 *
 * Authors: Isaku Yamahata <yamahata at valinux co jp>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 *
 */

#include "xg_private.h"
#include "xc_core.h"

int
xc_core_arch_auto_translated_physmap(const xc_dominfo_t *info)
{
	/* All PowerPC domU are autotranslated. */
	return 1;
}

int
xc_core_arch_map_p2m(int xc_handle, xc_dominfo_t *info,
                     shared_info_t *live_shinfo, xen_pfn_t **live_p2m,
                     unsigned long *pfnp)
{
	/* All PowerPC domU are autotranslated. */
    errno = ENOSYS;
    return -1;
}

int
xc_core_arch_memory_map_get(int xc_handle, xc_dominfo_t *info,
                            shared_info_t *live_shinfo,
                            xc_core_memory_map_t **mapp,
                            unsigned int *nr_entries)
{
    xc_core_memory_map_t *map = NULL;

    map = malloc(sizeof(*map));
    if (!map) {
        PERROR("Could not allocate memory");
        goto out;
    }

    map->addr = 0;
    map->size = info->max_memkb * 1024;

    *mapp = map;
    *nr_entries = 1;
    return 0;

out:
    free(map);
    return -1;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
