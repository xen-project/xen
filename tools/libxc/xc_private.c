/******************************************************************************
 * xc_private.c
 * 
 * Helper functions for the rest of the library.
 */

#include <zlib.h>
#include "xc_private.h"

void *xc_map_foreign_batch(int xc_handle, u32 dom, int prot,
                           unsigned long *arr, int num )
{
    privcmd_mmapbatch_t ioctlx; 
    void *addr;
    addr = mmap(NULL, num*PAGE_SIZE, prot, MAP_SHARED, xc_handle, 0);
    if ( addr == MAP_FAILED )
	return NULL;

    ioctlx.num=num;
    ioctlx.dom=dom;
    ioctlx.addr=(unsigned long)addr;
    ioctlx.arr=arr;
    if ( ioctl( xc_handle, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx ) < 0 )
    {
	perror("XXXXXXXX");
	munmap(addr, num*PAGE_SIZE);
	return NULL;
    }
    return addr;

}

/*******************/

void *xc_map_foreign_range(int xc_handle, u32 dom,
                            int size, int prot,
                            unsigned long mfn )
{
    privcmd_mmap_t ioctlx; 
    privcmd_mmap_entry_t entry; 
    void *addr;
    addr = mmap(NULL, size, prot, MAP_SHARED, xc_handle, 0);
    if ( addr == MAP_FAILED )
	return NULL;

    ioctlx.num=1;
    ioctlx.dom=dom;
    ioctlx.entry=&entry;
    entry.va=(unsigned long) addr;
    entry.mfn=mfn;
    entry.npages=(size+PAGE_SIZE-1)>>PAGE_SHIFT;
    if ( ioctl( xc_handle, IOCTL_PRIVCMD_MMAP, &ioctlx ) < 0 )
    {
	munmap(addr, size);
	return NULL;
    }
    return addr;
}

/*******************/

/* NB: arr must be mlock'ed */
int get_pfn_type_batch(int xc_handle, 
                       u32 dom, int num, unsigned long *arr)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO2;
    op.u.getpageframeinfo2.domain = (domid_t)dom;
    op.u.getpageframeinfo2.num    = num;
    op.u.getpageframeinfo2.array  = arr;
    return do_dom0_op(xc_handle, &op);
}

#define GETPFN_ERR (~0U)
unsigned int get_pfn_type(int xc_handle, 
                          unsigned long mfn, 
                          u32 dom)
{
    dom0_op_t op;
    op.cmd = DOM0_GETPAGEFRAMEINFO;
    op.u.getpageframeinfo.pfn    = mfn;
    op.u.getpageframeinfo.domain = (domid_t)dom;
    if ( do_dom0_op(xc_handle, &op) < 0 )
    {
        PERROR("Unexpected failure when getting page frame info!");
        return GETPFN_ERR;
    }
    return op.u.getpageframeinfo.type;
}



/*******************/

int pin_table(
    int xc_handle, unsigned int type, unsigned long mfn, domid_t dom)
{
    struct mmuext_op op;

    op.cmd = type;
    op.mfn = mfn;

    if ( do_mmuext_op(xc_handle, &op, 1, dom) < 0 )
        return 1;

    return 0;
}

static int flush_mmu_updates(int xc_handle, mmu_t *mmu)
{
    int err = 0;
    privcmd_hypercall_t hypercall;

    if ( mmu->idx == 0 )
        return 0;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)mmu->updates;
    hypercall.arg[1] = (unsigned long)mmu->idx;
    hypercall.arg[2] = 0;
    hypercall.arg[3] = mmu->subject;

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

    mmu->idx = 0;
    
    (void)munlock(mmu->updates, sizeof(mmu->updates));

 out:
    return err;
}

mmu_t *init_mmu_updates(int xc_handle, domid_t dom)
{
    mmu_t *mmu = malloc(sizeof(mmu_t));
    if ( mmu == NULL )
        return mmu;
    mmu->idx     = 0;
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


long long xc_domain_get_cpu_usage( int xc_handle, domid_t domid, int vcpu )
{
    dom0_op_t op;

    op.cmd = DOM0_GETVCPUCONTEXT;
    op.u.getvcpucontext.domain = (domid_t)domid;
    op.u.getvcpucontext.exec_domain = (u16)vcpu;
    op.u.getvcpucontext.ctxt = NULL;
    if ( (do_dom0_op(xc_handle, &op) < 0) )
    {
        PERROR("Could not get info on domain");
        return -1;
    }
    return op.u.getvcpucontext.cpu_time;
}


/* This is shared between save and restore, and may generally be useful. */
unsigned long csum_page (void * page)
{
    int i;
    unsigned long *p = page;
    unsigned long long sum=0;

    for ( i = 0; i < (PAGE_SIZE/sizeof(unsigned long)); i++ )
        sum += p[i];

    return sum ^ (sum>>32);
}

unsigned long xc_get_m2p_start_mfn ( int xc_handle )
{
    unsigned long mfn;

    if ( ioctl( xc_handle, IOCTL_PRIVCMD_GET_MACH2PHYS_START_MFN, &mfn ) < 0 )
    {
	perror("xc_get_m2p_start_mfn:");
	return 0;
    }
    return mfn;
}

int xc_get_pfn_list(int xc_handle,
		 u32 domid, 
		 unsigned long *pfn_buf, 
		 unsigned long max_pfns)
{
    dom0_op_t op;
    int ret;
    op.cmd = DOM0_GETMEMLIST;
    op.u.getmemlist.domain   = (domid_t)domid;
    op.u.getmemlist.max_pfns = max_pfns;
    op.u.getmemlist.buffer   = pfn_buf;


    if ( mlock(pfn_buf, max_pfns * sizeof(unsigned long)) != 0 )
    {
        PERROR("Could not lock pfn list buffer");
        return -1;
    }    

    ret = do_dom0_op(xc_handle, &op);

    (void)munlock(pfn_buf, max_pfns * sizeof(unsigned long));

#if 0
#ifdef DEBUG
	DPRINTF(("Ret for xc_get_pfn_list is %d\n", ret));
	if (ret >= 0) {
		int i, j;
		for (i = 0; i < op.u.getmemlist.num_pfns; i += 16) {
			fprintf(stderr, "0x%x: ", i);
			for (j = 0; j < 16; j++)
				fprintf(stderr, "0x%lx ", pfn_buf[i + j]);
			fprintf(stderr, "\n");
		}
	}
#endif
#endif

    return (ret < 0) ? -1 : op.u.getmemlist.num_pfns;
}

long xc_get_tot_pages(int xc_handle, u32 domid)
{
    dom0_op_t op;
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    return (do_dom0_op(xc_handle, &op) < 0) ? 
        -1 : op.u.getdomaininfo.tot_pages;
}

int xc_copy_to_domain_page(int xc_handle,
                                   u32 domid,
                                   unsigned long dst_pfn, 
                                   void *src_page)
{
    void *vaddr = xc_map_foreign_range(
        xc_handle, domid, PAGE_SIZE, PROT_WRITE, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memcpy(vaddr, src_page, PAGE_SIZE);
    munmap(vaddr, PAGE_SIZE);
    return 0;
}

unsigned long xc_get_filesz(int fd)
{
    u16 sig;
    u32 _sz = 0;
    unsigned long sz;

    lseek(fd, 0, SEEK_SET);
    if ( read(fd, &sig, sizeof(sig)) != sizeof(sig) )
        return 0;
    sz = lseek(fd, 0, SEEK_END);
    if ( sig == 0x8b1f ) /* GZIP signature? */
    {
        lseek(fd, -4, SEEK_END);
        if ( read(fd, &_sz, 4) != 4 )
            return 0;
        sz = _sz;
    }
    lseek(fd, 0, SEEK_SET);

    return sz;
}

char *xc_read_kernel_image(const char *filename, unsigned long *size)
{
    int kernel_fd = -1;
    gzFile kernel_gfd = NULL;
    char *image = NULL;
    unsigned int bytes;

    if ( (kernel_fd = open(filename, O_RDONLY)) < 0 )
    {
        PERROR("Could not open kernel image");
        goto out;
    }

    if ( (*size = xc_get_filesz(kernel_fd)) == 0 )
    {
        PERROR("Could not read kernel image");
        goto out;
    }

    if ( (kernel_gfd = gzdopen(kernel_fd, "rb")) == NULL )
    {
        PERROR("Could not allocate decompression state for state file");
        goto out;
    }

    if ( (image = malloc(*size)) == NULL )
    {
        PERROR("Could not allocate memory for kernel image");
        goto out;
    }

    if ( (bytes = gzread(kernel_gfd, image, *size)) != *size )
    {
        PERROR("Error reading kernel image, could not"
               " read the whole image (%d != %ld).", bytes, *size);
        free(image);
        image = NULL;
    }

 out:
    if ( kernel_gfd != NULL )
        gzclose(kernel_gfd);
    else if ( kernel_fd >= 0 )
        close(kernel_fd);
    return image;
}

void xc_map_memcpy(unsigned long dst, char *src, unsigned long size,
                   int xch, u32 dom, unsigned long *parray,
                   unsigned long vstart)
{
    char *va;
    unsigned long chunksz, done, pa;

    for ( done = 0; done < size; done += chunksz )
    {
        pa = dst + done - vstart;
        va = xc_map_foreign_range(
            xch, dom, PAGE_SIZE, PROT_WRITE, parray[pa>>PAGE_SHIFT]);
        chunksz = size - done;
        if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
            chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
        memcpy(va + (pa & (PAGE_SIZE-1)), src + done, chunksz);
        munmap(va, PAGE_SIZE);
    }
}
