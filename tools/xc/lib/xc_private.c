/******************************************************************************
 * xc_private.c
 * 
 * Helper functions for the rest of the library.
 */

#include "xc_private.h"

int init_pfn_mapper(void)
{
    return open("/dev/mem", O_RDWR);
}

int close_pfn_mapper(int pm_handle)
{
    return close(pm_handle);
}

void *map_pfn_writeable(int pm_handle, unsigned long pfn)
{
    void *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                       MAP_SHARED, pm_handle, pfn << PAGE_SHIFT);
    if ( vaddr == MAP_FAILED )
        return NULL;
    return vaddr;
}

void *map_pfn_readonly(int pm_handle, unsigned long pfn)
{
    void *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ,
                       MAP_SHARED, pm_handle, pfn << PAGE_SHIFT);
    if ( vaddr == MAP_FAILED )
        return NULL;
    return vaddr;
}

void unmap_pfn(int pm_handle, void *vaddr)
{
    (void)munmap(vaddr, PAGE_SIZE);
}

#define FIRST_MMU_UPDATE 2

static int flush_mmu_updates(int xc_handle, mmu_t *mmu)
{
    int err = 0;
    privcmd_hypercall_t hypercall;

    if ( mmu->idx == FIRST_MMU_UPDATE )
        return 0;

    /* The first two requests set the correct subject domain. */
    mmu->updates[0].val  = (unsigned long)(mmu->subject<<16) & ~0xFFFFUL;
    mmu->updates[0].ptr  = (unsigned long)(mmu->subject<< 0) & ~0xFFFFUL;
    mmu->updates[1].val  = (unsigned long)(mmu->subject>>16) & ~0xFFFFUL;
    mmu->updates[1].ptr  = (unsigned long)(mmu->subject>>32) & ~0xFFFFUL;
    mmu->updates[0].ptr |= MMU_EXTENDED_COMMAND;
    mmu->updates[0].val |= MMUEXT_SET_SUBJECTDOM_L;
    mmu->updates[1].ptr |= MMU_EXTENDED_COMMAND;
    mmu->updates[1].val |= MMUEXT_SET_SUBJECTDOM_H;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)mmu->updates;
    hypercall.arg[1] = (unsigned long)mmu->idx;

    if ( mlock(mmu->updates, sizeof(mmu->updates)) != 0 )
    {
        PERROR("Could not lock pagetable update array");
        err = 1;
        goto out;
    }

    if ( do_xen_hypercall(xc_handle, &hypercall) < 0 )
    {
        ERROR("Failure when submitting mmu updates");
        err = 1;
    }

    mmu->idx = FIRST_MMU_UPDATE;
    
    (void)munlock(mmu->updates, sizeof(mmu->updates));

 out:
    return err;
}

mmu_t *init_mmu_updates(int xc_handle, domid_t dom)
{
    mmu_t *mmu = malloc(sizeof(mmu_t));
    if ( mmu == NULL )
        return mmu;
    mmu->idx     = FIRST_MMU_UPDATE;
    mmu->subject = dom;
    return mmu;
}

int add_mmu_update(int xc_handle, mmu_t *mmu, 
                   unsigned long ptr, unsigned long val)
{
    mmu->updates[mmu->idx].ptr = ptr;
    mmu->updates[mmu->idx].val = val;
    if ( ++mmu->idx == MAX_MMU_UPDATES )
        return flush_mmu_updates(xc_handle, mmu);
    return 0;
}

int finish_mmu_updates(int xc_handle, mmu_t *mmu)
{
    return flush_mmu_updates(xc_handle, mmu);
}
