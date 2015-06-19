#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include "mread.h"

mread_handle_t mread_init(int fd)
{
    struct stat s;
    mread_handle_t h;
    
    h=malloc(sizeof(struct mread_ctrl));

    if (!h)
    {
        perror("malloc");
        exit(1);
    }

    bzero(h, sizeof(struct mread_ctrl));

    h->fd = fd;

    fstat(fd, &s);
    h->file_size = s.st_size;

    return h;
}

ssize_t mread64(mread_handle_t h, void *rec, ssize_t len, off_t offset)
{
    /* Idea: have a "cache" of N mmaped regions.  If the offset is
     * in one of the regions, just copy it.  If not, evict one of the
     * regions and map the appropriate range.
     *
     * Basic algorithm:
     *  - See if the offset is in one of the regions
     *    - If not, map it
     *       - evict an old region
     *       - map the new region
     *  - Copy
     */
    char * b=NULL;
    int bind=-1;
    off_t boffset=0;
    ssize_t bsize;

#define dprintf(x...)
//#define dprintf fprintf

    dprintf(warn, "%s: offset %llx len %d\n", __func__,
            offset, len);
    if ( offset > h->file_size )
    {
        dprintf(warn, " offset > file size %llx, returning 0\n",
                h->file_size);
        return 0;
    }
    if ( offset + len > h->file_size )
    {
        dprintf(warn, " offset+len > file size %llx, truncating\n",
                h->file_size);
        len = h->file_size - offset;
    }

    /* Try to find the offset in our range */
    dprintf(warn, " Trying last, %d\n", last);
    if ( h->map[h->last].buffer
         && (offset & MREAD_BUF_MASK) == h->map[h->last].start_offset )
    {
        bind=h->last;
        goto copy;
    }

    /* Scan to see if it's anywhere else */
    dprintf(warn, " Scanning\n");
    for(bind=0; bind<MREAD_MAPS; bind++)
        if ( h->map[bind].buffer
             && (offset & MREAD_BUF_MASK) == h->map[bind].start_offset )
        {
            dprintf(warn, "  Found, index %d\n", bind);
            break;
        }

    /* If we didn't find it, evict someone and map it */
    if ( bind == MREAD_MAPS )
    {
        dprintf(warn, " Clock\n");
        while(1)
        {
            h->clock++;
            if(h->clock >= MREAD_MAPS)
                h->clock=0;
            dprintf(warn, "  %d\n", h->clock);
            if(h->map[h->clock].buffer == NULL)
            {
                dprintf(warn, "  Buffer null, using\n");
                break;
            }
            if(!h->map[h->clock].accessed)
            {
                dprintf(warn, "  Not accessed, using\n");
                break;
            }
            h->map[h->clock].accessed=0;
        }
        if(h->map[h->clock].buffer)
        {
            dprintf(warn, "  Unmapping\n");
            munmap(h->map[h->clock].buffer, MREAD_BUF_SIZE);
        }
        /* FIXME: Try MAP_HUGETLB? */
        /* FIXME: Make sure this works on large files... */
        h->map[h->clock].start_offset = offset & MREAD_BUF_MASK;
        dprintf(warn, "  Mapping %llx from offset %llx\n",
                MREAD_BUF_SIZE, h->map[h->clock].start_offset);
        h->map[h->clock].buffer = mmap(NULL, MREAD_BUF_SIZE, PROT_READ,
                                  MAP_SHARED,
                                  h->fd,
                                  h->map[h->clock].start_offset);
        dprintf(warn, "   mmap returned %p\n", h->map[h->clock].buffer);
        if ( h->map[h->clock].buffer == MAP_FAILED )
        {
            h->map[h->clock].buffer = NULL;
            perror("mmap");
            exit(1);
        }
        bind = h->clock;
    }

    h->last=bind;
copy:
    h->map[bind].accessed=1;
    b=h->map[bind].buffer;
    boffset=offset - h->map[bind].start_offset;
    if ( boffset + len > MREAD_BUF_SIZE )
        bsize = MREAD_BUF_SIZE - boffset;
    else
        bsize = len;
    dprintf(warn, " Using index %d, buffer at %p, buffer offset %llx len %d\n",
            bind, b, boffset, bsize);

    bcopy(b+boffset, rec, bsize);

    /* Handle the boundary case; make sure this is after doing anything
     * with the static variables*/
    if ( len > bsize )
    {
        dprintf(warn, "  Finishing up by reading l %d o %llx\n",
                len-bsize, offset+bsize);
        mread64(h, rec+bsize, len-bsize, offset+bsize);
    }

    /* FIXME: ?? */
    return len;
#undef dprintf
}
