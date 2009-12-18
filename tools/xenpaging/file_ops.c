/******************************************************************************
 * tools/xenpaging/file_ops.c
 *
 * Common file operations.
 *
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <unistd.h>
#include <xc_private.h>


#define page_offset(_pfn)     (((off_t)(_pfn)) << PAGE_SHIFT)


static int file_op(int fd, void *page, int i,
                   ssize_t (*fn)(int, const void *, size_t))
{
    off_t seek_ret;
    int total;
    int bytes;
    int ret;

    seek_ret = lseek64(fd, i << PAGE_SHIFT, SEEK_SET);

    total = 0;
    while ( total < PAGE_SIZE )
    {
        bytes = fn(fd, page + total, PAGE_SIZE - total);
        if ( bytes <= 0 )
        {
            ret = -errno;
            goto err;
        }

        total += bytes;
    }

    return 0;

 err:
    return ret;
}

static ssize_t my_read(int fd, const void *buf, size_t count)
{
    return read(fd, (void *)buf, count);
}

int read_page(int fd, void *page, int i)
{
    return file_op(fd, page, i, &my_read);
}

int write_page(int fd, void *page, int i)
{
    return file_op(fd, page, i, &write);
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
