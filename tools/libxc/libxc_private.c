/******************************************************************************
 * libxc_private.c
 * 
 * Helper functions for the rest of the library.
 */

#include "libxc_private.h"

static int devmem_fd = -1;

int init_pfn_mapper(void)
{
    if ( (devmem_fd == -1) &&
         ((devmem_fd = open("/dev/mem", O_RDWR)) < 0) )
    {
        devmem_fd = -1;
        return -1;
    }
    return 0;
}

void *map_pfn(unsigned long pfn)
{
    void *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                       MAP_SHARED, devmem_fd, pfn << PAGE_SHIFT);
    if ( vaddr == MAP_FAILED )
        return NULL;
    return vaddr;
}

void unmap_pfn(void *vaddr)
{
    (void)munmap(vaddr, PAGE_SIZE);
}
