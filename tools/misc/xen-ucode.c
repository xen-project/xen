#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <xenctrl.h>

int main(int argc, char *argv[])
{
    int fd, ret;
    char *filename, *buf;
    size_t len;
    struct stat st;
    xc_interface *xch;

    if ( argc < 2 )
    {
        fprintf(stderr,
                "xen-ucode: Xen microcode updating tool\n"
                "Usage: %s <microcode blob>\n", argv[0]);
        exit(2);
    }

    filename = argv[1];
    fd = open(filename, O_RDONLY);
    if ( fd < 0 )
    {
        fprintf(stderr, "Could not open %s. (err: %s)\n",
                filename, strerror(errno));
        exit(1);
    }

    if ( fstat(fd, &st) != 0 )
    {
        fprintf(stderr, "Could not get the size of %s. (err: %s)\n",
                filename, strerror(errno));
        exit(1);
    }

    len = st.st_size;
    buf = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( buf == MAP_FAILED )
    {
        fprintf(stderr, "mmap failed. (error: %s)\n", strerror(errno));
        exit(1);
    }

    xch = xc_interface_open(NULL, NULL, 0);
    if ( xch == NULL )
    {
        fprintf(stderr, "Error opening xc interface. (err: %s)\n",
                strerror(errno));
        exit(1);
    }

    ret = xc_microcode_update(xch, buf, len);
    if ( ret )
    {
        fprintf(stderr, "Failed to update microcode. (err: %s)\n",
                strerror(errno));
        exit(1);
    }

    xc_interface_close(xch);

    if ( munmap(buf, len) )
    {
        printf("Could not unmap: %d(%s)\n", errno, strerror(errno));
        exit(1);
    }
    close(fd);

    return 0;
}
