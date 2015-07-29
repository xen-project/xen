/******************************************************************************
 * xc_physdev.c
 *
 * API for manipulating physical-device access permissions.
 *
 * Copyright (c) 2004, Rolf Neugebauer (Intel Research Cambridge)
 * Copyright (c) 2004, K A Fraser (University of Cambridge)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"

int xc_physdev_pci_access_modify(xc_interface *xch,
                                 uint32_t domid,
                                 int bus,
                                 int dev,
                                 int func,
                                 int enable)
{
    errno = ENOSYS;
    return -1;
}

int xc_physdev_map_pirq(xc_interface *xch,
                        int domid,
                        int index,
                        int *pirq)
{
    int rc;
    struct physdev_map_pirq map;

    if ( !pirq )
    {
        errno = EINVAL;
        return -1;
    }
    memset(&map, 0, sizeof(struct physdev_map_pirq));
    map.domid = domid;
    map.type = MAP_PIRQ_TYPE_GSI;
    map.index = index;
    map.pirq = *pirq < 0 ? index : *pirq;

    rc = do_physdev_op(xch, PHYSDEVOP_map_pirq, &map, sizeof(map));

    if ( !rc )
        *pirq = map.pirq;

    return rc;
}

int xc_physdev_map_pirq_msi(xc_interface *xch,
                            int domid,
                            int index,
                            int *pirq,
                            int devfn,
                            int bus,
                            int entry_nr,
                            uint64_t table_base)
{
    int rc;
    struct physdev_map_pirq map;

    if ( !pirq )
    {
        errno = EINVAL;
        return -1;
    }
    memset(&map, 0, sizeof(struct physdev_map_pirq));
    map.domid = domid;
    map.type = MAP_PIRQ_TYPE_MSI;
    map.index = index;
    map.pirq = *pirq;
    map.bus = bus;
    map.devfn = devfn;
    map.entry_nr = entry_nr;
    map.table_base = table_base;

    rc = do_physdev_op(xch, PHYSDEVOP_map_pirq, &map, sizeof(map));

    if ( !rc )
        *pirq = map.pirq;

    return rc;
}

int xc_physdev_unmap_pirq(xc_interface *xch,
                          int domid,
                          int pirq)
{
    int rc;
    struct physdev_unmap_pirq unmap;

    memset(&unmap, 0, sizeof(struct physdev_unmap_pirq));
    unmap.domid = domid;
    unmap.pirq = pirq;

    rc = do_physdev_op(xch, PHYSDEVOP_unmap_pirq, &unmap, sizeof(unmap));

    return rc;
}

