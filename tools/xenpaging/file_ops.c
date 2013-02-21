/******************************************************************************
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

static int file_op(int fd, void *page, int i,
                   ssize_t (*fn)(int, void *, size_t))
{
    off_t offset = i;
    int total = 0;
    int bytes;

    offset = lseek(fd, offset << PAGE_SHIFT, SEEK_SET);
    if ( offset == (off_t)-1 )
        return -1;

    while ( total < PAGE_SIZE )
    {
        bytes = fn(fd, page + total, PAGE_SIZE - total);
        if ( bytes <= 0 )
            return -1;

        total += bytes;
    }

    return 0;
}

static ssize_t my_write(int fd, void *buf, size_t count)
{
    return write(fd, buf, count);
}

int read_page(int fd, void *page, int i)
{
    return file_op(fd, page, i, &read);
}

int write_page(int fd, void *page, int i)
{
    return file_op(fd, page, i, &my_write);
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
