/******************************************************************************
 * xen_refresh_dev.c
 * 
 * Refresh our view of a block device by rereading its partition table. This 
 * is necessary to synchronise with VBD attaches and unattaches in Xen. 
 * Currently there's no automatic plumbing of attach/unattach requests.
 * 
 * Copyright (c) 2003, K A Fraser
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mount.h> /* BLKRRPART */

int main(int argc, char **argv)
{
    int fd;

    if ( argc != 2 )
    {
        fprintf(stderr, "xen_refresh_dev <blkdev>\ne.g., /dev/xvda\n");
        return 1;
    }

    if ( (fd = open(argv[1], O_RDWR)) == -1 )
    {
        fprintf(stderr, "Error opening %s: %s (%d)\n",
                argv[1], strerror(errno), errno);
        return 1;
    }

    if ( ioctl(fd, BLKRRPART) == -1 )
    {
        fprintf(stderr, "Error executing BLKRRPART on %s: %s (%d)\n",
                argv[1], strerror(errno), errno);
        return 1;
    }

    close(fd);

    return 0;
}
