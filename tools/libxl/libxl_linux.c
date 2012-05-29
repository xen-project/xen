/*
 * Copyright (C) 2011
 * Author Roger Pau Monne <roger.pau@entel.upc.edu>
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
 
int libxl__try_phy_backend(mode_t st_mode)
{
    if (!S_ISBLK(st_mode)) {
        return 0;
    }

    return 1;
}

#define EXT_SHIFT 28
#define EXTENDED (1<<EXT_SHIFT)
#define VDEV_IS_EXTENDED(dev) ((dev)&(EXTENDED))
#define BLKIF_MINOR_EXT(dev) ((dev)&(~EXTENDED))
/* the size of the buffer to store the device name is 32 bytes to match the
 * equivalent buffer in the Linux kernel code */
#define BUFFER_SIZE 32

/* Same as in Linux.
 * encode_disk_name might end up using up to 29 bytes (BUFFER_SIZE - 3)
 * including the trailing \0.
 *
 * The code is safe because 26 raised to the power of 28 (that is the
 * maximum offset that can be stored in the allocated buffer as a
 * string) is far greater than UINT_MAX on 64 bits so offset cannot be
 * big enough to exhaust the available bytes in ret. */
static char *encode_disk_name(char *ptr, unsigned int n)
{
    if (n >= 26)
        ptr = encode_disk_name(ptr, n / 26 - 1);
    *ptr = 'a' + n % 26;
    return ptr + 1;
}

char *libxl__devid_to_localdev(libxl__gc *gc, int devid)
{
    unsigned int minor;
    int offset;
    int nr_parts;
    char *ptr = NULL;
    char *ret = libxl__zalloc(gc, BUFFER_SIZE);

    if (!VDEV_IS_EXTENDED(devid)) {
        minor = devid & 0xff;
        nr_parts = 16;
    } else {
        minor = BLKIF_MINOR_EXT(devid);
        nr_parts = 256;
    }
    offset = minor / nr_parts;

    strcpy(ret, "xvd");
    ptr = encode_disk_name(ret + 3, offset);
    if (minor % nr_parts == 0)
        *ptr = 0;
    else
        /* overflow cannot happen, thanks to the upper bound */
        snprintf(ptr, ret + 32 - ptr,
                "%d", minor & (nr_parts - 1));
    return ret;
}
