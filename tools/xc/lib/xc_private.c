/******************************************************************************
 * xc_private.c
 * 
 * Helper functions for the rest of the library.
 */

#include "xc_private.h"

int init_pfn_mapper(domid_t domid)
{
    int fd = open("/dev/mem", O_RDWR);
    if ( fd >= 0 )
    {
        (void)ioctl(fd, _IO('M', 1), (unsigned long)(domid>> 0)); /* low  */
        (void)ioctl(fd, _IO('M', 2), (unsigned long)(domid>>32)); /* high */
    }
    return fd;
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

/*******************/

void * mfn_mapper_map_single(int xc_handle, domid_t dom,
			     int size, int prot,
			     unsigned long mfn )
{
    privcmd_mmap_t ioctlx; 
    privcmd_mmap_entry_t entry; 
    void *addr;
    addr = mmap( NULL, size, prot, MAP_SHARED, xc_handle, 0 );
    if (addr)
    {
	ioctlx.num=1;
	ioctlx.dom=dom;
	ioctlx.entry=&entry;
	entry.va=(unsigned long) addr;
	entry.mfn=mfn;
	entry.npages=(size+PAGE_SIZE-1)>>PAGE_SHIFT;
	if ( ioctl( xc_handle, IOCTL_PRIVCMD_MMAP, &ioctlx ) <0 )
	    return 0;
    }
    return addr;
}

mfn_mapper_t * mfn_mapper_init(int xc_handle, domid_t dom, int size, int prot)
{
    mfn_mapper_t * t;
    t = calloc( 1, sizeof(mfn_mapper_t)+
		mfn_mapper_queue_size*sizeof(privcmd_mmap_entry_t) );
    if (!t) return NULL;
    t->xc_handle = xc_handle;
    t->size = size;
    t->prot = prot;
    t->error = 0;
    t->max_queue_size = mfn_mapper_queue_size;
    t->addr = mmap( NULL, size, prot, MAP_SHARED, xc_handle, 0 );
    if (!t->addr)
    {
	free(t);
	return NULL;
    }
    t->ioctl.num = 0;
    t->ioctl.dom = dom;
    t->ioctl.entry = (privcmd_mmap_entry_t *) &t[1];
    return t;
}

void * mfn_mapper_base(mfn_mapper_t *t)
{
    return t->addr;
}

void mfn_mapper_close(mfn_mapper_t *t)
{
    if(t->addr) munmap( t->addr, t->size );
    free(t);    
}

static int __mfn_mapper_flush_queue(mfn_mapper_t *t)
{
    int rc;
    rc = ioctl( t->xc_handle, IOCTL_PRIVCMD_MMAP, &t->ioctl );
    t->ioctl.num = 0;    
    if(rc && !t->error) 
	t->error = rc;
    return rc;
}

int mfn_mapper_flush_queue(mfn_mapper_t *t)
{
    int rc;
    
    rc = __mfn_mapper_flush_queue(t);

    if ( t->error )
    {
	rc = t->error;
    }

    t->error = 0;
    return rc;
}

void * mfn_mapper_queue_entry(mfn_mapper_t *t, int offset, 
			      unsigned long mfn, int size)
{
    privcmd_mmap_entry_t *entry, *prev;
    int pages;

    offset &= PAGE_MASK;
    pages =(size+PAGE_SIZE-1)>>PAGE_SHIFT;
    entry = &t->ioctl.entry[t->ioctl.num];       

    if ( t->ioctl.num > 0 )
    {
	prev = &t->ioctl.entry[t->ioctl.num-1];       

	if ( (prev->va+(prev->npages*PAGE_SIZE)) == 
	     ((unsigned long)t->addr+offset) &&
	     (prev->mfn+prev->npages) == mfn )
	{
	    prev->npages += pages;
	    return t->addr+offset;
	}
    }
     
    entry->va = (unsigned long)t->addr+offset;
    entry->mfn = mfn;
    entry->npages = pages;
    t->ioctl.num++;       

    if(t->ioctl.num == t->max_queue_size)
    {
	if ( __mfn_mapper_flush_queue(t) )
	    return 0;
    }

    return t->addr+offset;
}


/*******************/

typedef struct dom0_op_compact_getpageframeinfo {
    unsigned long cmd;
    unsigned long interface_version; /* DOM0_INTERFACE_VERSION */
    dom0_getpageframeinfo_t getpageframeinfo;
}  dom0_op_compact_getpageframeinfo_t;


typedef struct mfn_typer {
    domid_t dom;
    int max;
    int nr_multicall_ents;
    multicall_entry_t *multicall_list;
    dom0_op_compact_getpageframeinfo_t *gpf_list;
} mfn_typer_t;


mfn_typer_t *mfn_typer_init(int xc_handle, domid_t dom, int num );

void mfn_typer_queue_entry(mfn_typer_t *t, unsigned long mfn );

int mfn_typer_flush_queue(mfn_typer_t *t);

unsigned int mfn_typer_get_result(mfn_typer_t *t, int idx);

mfn_typer_t *mfn_typer_init(int xc_handle, domid_t dom, int num )
{
    mfn_typer_t *t;
    multicall_entry_t *m;
    dom0_op_compact_getpageframeinfo_t *d;

    t = calloc(1, sizeof(mfn_typer_t) );
    m = calloc(1, sizeof(multicall_entry_t)*num );
    d = calloc(1, sizeof(dom0_op_compact_getpageframeinfo_t)*num );

    if (!t || !m || !d)
    {
	if(t) free(t);	
	if(m) free(m);
	if(d) free(d);
	return NULL;
    }

    t->max = num;
    t->nr_multicall_ents=0;
    t->multicall_list=m;
    t->gpf_list=d;
    t->dom = dom;

    return t;
}

void mfn_typer_queue_entry(mfn_typer_t *t, unsigned long mfn )
{
    int i = t->nr_multicall_ents;
    multicall_entry_t *m = &t->multicall_list[i];
    dom0_op_compact_getpageframeinfo_t *d = &t->gpf_list[i];

    d->cmd = DOM0_GETPAGEFRAMEINFO;
    d->interface_version = DOM0_INTERFACE_VERSION;
    d->getpageframeinfo.pfn = mfn;
    d->getpageframeinfo.domain = t->dom;
    d->getpageframeinfo.type = ~0UL;
      
    m->op = __HYPERVISOR_dom0_op;
    m->args[0] = (unsigned long)d;
   
    t->nr_multicall_ents++;
}

int mfn_typer_flush_queue(mfn_typer_t *t)
{
    if (t->nr_multicall_ents == 0) return 0;
    (void)HYPERVISOR_multicall(t->multicall_list, t->nr_multicall_ents);
    t->nr_multicall_ents = 0;
}

unsigned int mfn_typer_get_result(mfn_typer_t *t, int idx)
{
    return t->gpf_list[idx].getpageframeinfo.type;
}



/*******************/

#define FIRST_MMU_UPDATE 2

static int flush_mmu_updates(int xc_handle, mmu_t *mmu)
{
    int err = 0;
    privcmd_hypercall_t hypercall;

    if ( mmu->idx == FIRST_MMU_UPDATE )
        return 0;

    /* The first two requests set the correct subject domain (PTS and GPS). */
    mmu->updates[0].val  = (unsigned long)(mmu->subject<<16) & ~0xFFFFUL;
    mmu->updates[0].ptr  = (unsigned long)(mmu->subject<< 0) & ~0xFFFFUL;
    mmu->updates[1].val  = (unsigned long)(mmu->subject>>16) & ~0xFFFFUL;
    mmu->updates[1].ptr  = (unsigned long)(mmu->subject>>32) & ~0xFFFFUL;
    mmu->updates[0].ptr |= MMU_EXTENDED_COMMAND;
    mmu->updates[0].val |= MMUEXT_SET_SUBJECTDOM_L;
    mmu->updates[1].ptr |= MMU_EXTENDED_COMMAND;
    mmu->updates[1].val |= MMUEXT_SET_SUBJECTDOM_H | SET_PAGETABLE_SUBJECTDOM;

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
