/******************************************************************************
 * xg_private.c
 *
 * Helper functions for the rest of the library.
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

#include <stdlib.h>
#include <unistd.h>
#include <zlib.h>

#include "xg_private.h"

char *xc_read_image(xc_interface *xch,
                    const char *filename, unsigned long *size)
{
    int kernel_fd = -1;
    gzFile kernel_gfd = NULL;
    char *image = NULL, *tmp;
    unsigned int bytes;

    if ( (filename == NULL) || (size == NULL) )
        return NULL;

    if ( (kernel_fd = open(filename, O_RDONLY)) < 0 )
    {
        PERROR("Could not open kernel image '%s'", filename);
        goto out;
    }

    if ( (kernel_gfd = gzdopen(kernel_fd, "rb")) == NULL )
    {
        PERROR("Could not allocate decompression state for state file");
        goto out;
    }

    *size = 0;

#define CHUNK 1*1024*1024
    while(1)
    {
        if ( (tmp = realloc(image, *size + CHUNK)) == NULL )
        {
            PERROR("Could not allocate memory for kernel image");
            free(image);
            image = NULL;
            goto out;
        }
        image = tmp;

        bytes = gzread(kernel_gfd, image + *size, CHUNK);
        switch (bytes)
        {
        case -1:
            PERROR("Error reading kernel image");
            free(image);
            image = NULL;
            goto out;
        case 0: /* EOF */
            if ( *size == 0 )
            {
                PERROR("Could not read kernel image");
                free(image);
                image = NULL;
            }
            goto out;
        default:
            *size += bytes;
            break;
        }
    }
#undef CHUNK

 out:
    if ( image )
    {
        /* Shrink allocation to fit image. */
        tmp = realloc(image, *size);
        if ( tmp )
            image = tmp;
    }

    if ( kernel_gfd != NULL )
        gzclose(kernel_gfd);
    else if ( kernel_fd >= 0 )
        close(kernel_fd);
    return image;
}

char *xc_inflate_buffer(xc_interface *xch,
                        const char *in_buf, unsigned long in_size,
                        unsigned long *out_size)
{
    int           sts;
    z_stream      zStream;
    unsigned long out_len;
    char         *out_buf;

    /* Not compressed? Then return the original buffer. */
    if ( ((unsigned char)in_buf[0] != 0x1F) ||
         ((unsigned char)in_buf[1] != 0x8B) )
    {
        if ( out_size != NULL )
            *out_size = in_size;
        return (char *)in_buf;
    }

    out_len = (unsigned char)in_buf[in_size-4] +
        (256 * ((unsigned char)in_buf[in_size-3] +
                (256 * ((unsigned char)in_buf[in_size-2] +
                        (256 * (unsigned char)in_buf[in_size-1])))));

    memset(&zStream, 0, sizeof(zStream));
    out_buf = malloc(out_len + 16);        /* Leave a little extra space */
    if ( out_buf == NULL )
    {
        ERROR("Error mallocing buffer\n");
        return NULL;
    }

    zStream.next_in = (unsigned char *)in_buf;
    zStream.avail_in = in_size;
    zStream.next_out = (unsigned char *)out_buf;
    zStream.avail_out = out_len+16;
    sts = inflateInit2(&zStream, (MAX_WBITS+32)); /* +32 means "handle gzip" */
    if ( sts != Z_OK )
    {
        ERROR("inflateInit failed, sts %d\n", sts);
        free(out_buf);
        return NULL;
    }

    /* Inflate in one pass/call */
    sts = inflate(&zStream, Z_FINISH);
    inflateEnd(&zStream);
    if ( sts != Z_STREAM_END )
    {
        ERROR("inflate failed, sts %d\n", sts);
        free(out_buf);
        return NULL;
    }

    if ( out_size != NULL )
        *out_size = out_len;

    return out_buf;
}

/*******************/

int pin_table(
    xc_interface *xch, unsigned int type, unsigned long mfn, domid_t dom)
{
    struct mmuext_op op;

    op.cmd = type;
    op.arg1.mfn = mfn;

    if ( xc_mmuext_op(xch, &op, 1, dom) < 0 )
        return 1;

    return 0;
}

/* This is shared between save and restore, and may generally be useful. */
unsigned long csum_page(void *page)
{
    int i;
    unsigned long *p = page;
    unsigned long long sum=0;

    for ( i = 0; i < (PAGE_SIZE/sizeof(unsigned long)); i++ )
        sum += p[i];

    return sum ^ (sum>>32);
}

__attribute__((weak)) 
    int xc_hvm_build(xc_interface *xch,
                     uint32_t domid,
                     struct xc_hvm_build_args *hvm_args)
{
    errno = ENOSYS;
    return -1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
