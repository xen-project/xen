
#include "dom0_defs.h"
#include "mem_defs.h"

/* This string is written to the head of every guest kernel image. */
#define GUEST_SIG   "XenoGues"
#define SIG_LEN    8

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

static char *argv0 = "internal_domain_build";

static long get_tot_pages(int domain_id)
{
    dom0_op_t op;
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdominfo.domain = domain_id;
    return (do_dom0_op(&op) < 0) ? -1 : op.u.getdominfo.tot_pages;
}

static int get_pfn_list(
    int domain_id, unsigned long *pfn_buf, unsigned long max_pfns)
{
    dom0_op_t op;
    int ret;
    op.cmd = DOM0_GETMEMLIST;
    op.u.getmemlist.domain   = domain_id;
    op.u.getmemlist.max_pfns = max_pfns;
    op.u.getmemlist.buffer   = pfn_buf;

    if ( mlock(pfn_buf, max_pfns * sizeof(unsigned long)) != 0 )
    {
        PERROR("Could not lock pfn list buffer");
        return -1;
    }    

    ret = do_dom0_op(&op);

    (void)munlock(pfn_buf, max_pfns * sizeof(unsigned long));

    return (ret < 0) ? -1 : op.u.getmemlist.num_pfns;
}

static int send_pgupdates(mmu_update_t *updates, int nr_updates)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)updates;
    hypercall.arg[1] = (unsigned long)nr_updates;

    if ( mlock(updates, nr_updates * sizeof(*updates)) != 0 )
    {
        PERROR("Could not lock pagetable update array");
        goto out1;
    }

    if ( do_xen_hypercall(&hypercall) < 0 )
        goto out2;

    ret = 0;

 out2: (void)munlock(updates, nr_updates * sizeof(*updates));
 out1: return ret;
}

/* Read the kernel header, extracting the image size and load address. */
static int read_kernel_header(int fd, long dom_size, 
			      unsigned long * load_addr, size_t * ksize)
{
    char signature[8];
    char status[1024];
    struct stat stat;
    
    if ( fstat(fd, &stat) < 0 )
    {
        PERROR("Cannot stat the kernel image");
	return -1;
    }

    /* Double the kernel image size to account for dynamic memory usage etc. */
    if ( (stat.st_size * 2) > (dom_size << 10) )
    {
        sprintf(status, "Kernel image size %ld larger than requested "
                "domain size %ld\n Terminated.\n", stat.st_size, dom_size);
        ERROR(status);
	return -1;
    }
    
    read(fd, signature, SIG_LEN);
    if ( strncmp(signature, GUEST_SIG, SIG_LEN) )
    {
        ERROR("Kernel image does not contain required signature.\n"
              "Terminating.\n");
	return -1;
    }

    /* Read the load address which immediately follows the Xeno signature. */
    read(fd, load_addr, sizeof(unsigned long));

    *ksize = stat.st_size - SIG_LEN - sizeof(unsigned long);

    return 0;
}

static int devmem_fd;

static int init_pfn_mapper(void)
{
    if ( (devmem_fd = open("/dev/mem", O_RDWR)) < 0 )
    {
        PERROR("Could not open /dev/mem");
        return -1;
    }
    return 0;
}

static void *map_pfn(unsigned long pfn)
{
    void *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                       MAP_SHARED, devmem_fd, pfn << PAGE_SHIFT);
    if ( vaddr == MAP_FAILED )
    {
        PERROR("Could not mmap a domain pfn using /dev/mem");
        return NULL;
    }
    return vaddr;
}

static void unmap_pfn(void *vaddr)
{
    (void)munmap(vaddr, PAGE_SIZE);
}

static int copy_to_domain_page(unsigned long dst_pfn, void *src_page)
{
    void *vaddr = map_pfn(dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memcpy(vaddr, src_page, PAGE_SIZE);
    unmap_pfn(vaddr);
    return 0;
}

static int setup_guestos(
    int dom, int kernel_fd, int initrd_fd, unsigned long tot_pages,
    unsigned long virt_load_addr, size_t ksize, 
    dom0_builddomain_t *builddomain)
{
    l1_pgentry_t *vl1tab = NULL, *vl1e = NULL;
    l2_pgentry_t *vl2tab = NULL, *vl2e = NULL;
    unsigned long *page_array = NULL;
    mmu_update_t *pgt_update_arr = NULL, *pgt_updates = NULL;
    int alloc_index, num_pt_pages;
    unsigned long l2tab;
    unsigned long l1tab = 0;
    unsigned long num_pgt_updates = 0;
    unsigned long count, pt_start, i, j;

    memset(builddomain, 0, sizeof(*builddomain));

    if ( init_pfn_mapper() < 0 )
        goto error_out;

    pgt_updates = malloc((tot_pages + 1024) * 3 * sizeof(mmu_update_t));
    page_array = malloc(tot_pages * sizeof(unsigned long));
    pgt_update_arr = pgt_updates;
    if ( (pgt_update_arr == NULL) || (page_array == NULL) )
    {
	PERROR("Could not allocate memory");
	goto error_out;
    }

    if ( get_pfn_list(dom, page_array, tot_pages) != tot_pages )
    {
	PERROR("Could not get the page frame list");
	goto error_out;
    }

    /* Load the guest OS image. */
    for ( i = 0; i < ksize; i += PAGE_SIZE )
    {
        char page[PAGE_SIZE];
        int size = ((ksize-i) < PAGE_SIZE) ? (ksize-i) : PAGE_SIZE;
        if ( read(kernel_fd, page, size) != size )
        {
            PERROR("Error reading kernel image, could not"
                   " read the whole image.");
            goto error_out;
        } 
        copy_to_domain_page(page_array[i>>PAGE_SHIFT], page);
    }

    /* Load the initial ramdisk image. */
    if ( initrd_fd >= 0 )
    {
	struct stat stat;
	unsigned long isize;

	if ( fstat(initrd_fd, &stat) < 0 )
        {
            PERROR("Could not stat the initrd image");
            goto error_out;
	}
	isize = stat.st_size;
        if ( ((isize + ksize) * 2) > (tot_pages << PAGE_SHIFT) )
        {
            ERROR("Kernel + initrd too big to safely fit in domain memory");
            goto error_out;
        }

        /* 'i' is 'ksize' rounded up to a page boundary. */
        builddomain->virt_mod_addr = virt_load_addr + i;
        builddomain->virt_mod_len  = isize;

        for ( j = 0; j < isize; j += PAGE_SIZE, i += PAGE_SIZE )
        {
            char page[PAGE_SIZE];
            int size = ((isize-j) < PAGE_SIZE) ? (isize-j) : PAGE_SIZE;
            if ( read(initrd_fd, page, size) != size )
            {
                PERROR("Error reading initrd image, could not"
                       " read the whole image.");
                goto error_out;
            } 
            copy_to_domain_page(page_array[i>>PAGE_SHIFT], page);
        }
    }

    alloc_index = tot_pages - 1;

    /* Count bottom-level PTs, rounding up. */
    num_pt_pages = (l1_table_offset(virt_load_addr) + tot_pages + 1023) / 1024;

    /* We must also count the page directory. */
    num_pt_pages++;

    /* Index of first PT page. */
    pt_start = tot_pages - num_pt_pages;

    /*
     * First allocate page for page dir. Allocation goes backwards from the end
     * of the allocated physical address space.
     */
    l2tab = page_array[alloc_index] << PAGE_SHIFT;
    alloc_index--;
    builddomain->l2_pgt_addr = l2tab;

    /*
     * Pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */ 
    pgt_updates->ptr = l2tab | MMU_EXTENDED_COMMAND;
    pgt_updates->val = MMUEXT_PIN_L2_TABLE;
    pgt_updates++;
    num_pgt_updates++;

    /* Initialise the page tables. */
    if ( (vl2tab = map_pfn(l2tab >> PAGE_SHIFT)) == NULL )
        goto error_out;
    memset(vl2tab, 0, PAGE_SIZE);
    vl2e = vl2tab + l2_table_offset(virt_load_addr);
    for ( count = 0; count < tot_pages; count++ )
    {    
        if ( ((unsigned long)vl1e & (PAGE_SIZE-1)) == 0 ) 
        {
            l1tab = page_array[alloc_index] << PAGE_SHIFT;
            if ( (vl1tab = map_pfn(l1tab >> PAGE_SHIFT)) == NULL )
                goto error_out;
            memset(vl1tab, 0, PAGE_SIZE);
            alloc_index--;
			
            vl1e = vl1tab + l1_table_offset(virt_load_addr + 
                                            (count << PAGE_SHIFT));

            /* make apropriate entry in the page directory */
            pgt_updates->ptr = (unsigned long)vl2e;
            pgt_updates->val = l1tab | L2_PROT;
            pgt_updates++;
            num_pgt_updates++;
            vl2e++;
        }

        if ( count < pt_start )
        {
            pgt_updates->ptr = (unsigned long)vl1e;
            pgt_updates->val = (page_array[count] << PAGE_SHIFT) | L1_PROT;
            pgt_updates++;
            num_pgt_updates++;
            vl1e++;
        }
        else
        {
            pgt_updates->ptr = (unsigned long)vl1e;
            pgt_updates->val = 
		((page_array[count] << PAGE_SHIFT) | L1_PROT) & ~_PAGE_RW;
            pgt_updates++;
            num_pgt_updates++;
            vl1e++;
        }

        pgt_updates->ptr = 
	    (page_array[count] << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
        pgt_updates->val = count;
        pgt_updates++;
        num_pgt_updates++;
    }

    builddomain->virt_startinfo_addr =
        virt_load_addr + ((alloc_index-1)<<PAGE_SHIFT);

    /* Send the page update requests down to the hypervisor. */
    if ( send_pgupdates(pgt_update_arr, num_pgt_updates) < 0 )
        goto error_out;

    free(page_array);
    free(pgt_update_arr);
    return 0;

 error_out:
    if ( page_array == NULL )
	free(page_array);
    if ( pgt_update_arr == NULL )
	free(pgt_update_arr);
    return -1;
}

int main(int argc, char **argv)
{
    /*
     * NB. 'ksize' is the size in bytes of the main kernel image. It excludes
     * the 8-byte signature and 4-byte load address.
     */
    size_t ksize;
    dom0_op_t launch_op;
    unsigned long load_addr;
    long tot_pages;
    int kernel_fd, initrd_fd = -1;
    int count;
    int cmd_len;
    int args_start = 4;
    char initrd_name[1024];
    int domain_id;
    int rc;

    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( argc < 4 )
    {
        fprintf(stderr, "Usage: %s <domain_id> <image> <num_vifs> "
                "[<initrd=initrd_name>] <boot_params>\n", argv0);
        return 1;
    }

    domain_id = atoi(argv[1]);
    if ( domain_id == 0 )
    {
        ERROR("Did you really mean domain 0?");
        return 1;
    }

    if ( (tot_pages = get_tot_pages(domain_id)) < 0 )
    {
        PERROR("Could not find total pages for domain");
	return 1;
    }

    kernel_fd = open(argv[2], O_RDONLY);
    if ( kernel_fd < 0 )
    {
        PERROR("Could not open kernel image");
	return 1;
    }

    rc = read_kernel_header(kernel_fd,
			    tot_pages << (PAGE_SHIFT - 10), 
			    &load_addr, &ksize);
    if ( rc < 0 )
	return 1;
    
    if( (argc > args_start) && 
        (strncmp("initrd=", argv[args_start], 7) == 0) )
    {
	strncpy( initrd_name, argv[args_start]+7, sizeof(initrd_name) );
	initrd_name[sizeof(initrd_name)-1] = 0;
	printf("initrd present, name = %s\n", initrd_name );
	args_start++;
        
	initrd_fd = open(initrd_name, O_RDONLY);
	if ( initrd_fd < 0 )
        {
            PERROR("Could not open the initial ramdisk image");
	    return 1;
	}
    }

    if ( setup_guestos(domain_id, kernel_fd, initrd_fd, tot_pages,
                       load_addr, ksize, &launch_op.u.builddomain) < 0 )
        return 1;

    if ( initrd_fd >= 0 )
	close(initrd_fd);
    close(kernel_fd);

    launch_op.u.builddomain.domain         = domain_id;
    launch_op.u.builddomain.virt_load_addr = load_addr;
    launch_op.u.builddomain.num_vifs       = atoi(argv[3]);
    launch_op.u.builddomain.cmd_line[0]    = '\0';
    cmd_len = 0;
    for ( count = args_start; count < argc; count++ )
    {
        if ( cmd_len + strlen(argv[count]) > MAX_CMD_LEN - 1 ) 
        {
            ERROR("Size of image boot params too big!\n");
            break;
        }
        strcat(launch_op.u.builddomain.cmd_line, argv[count]);
        strcat(launch_op.u.builddomain.cmd_line, " ");
        cmd_len += strlen(argv[count] + 1);
    }

    launch_op.cmd = DOM0_BUILDDOMAIN;
    rc = do_dom0_op(&launch_op);
    
    return (rc != 0) ? 1 : 0;
}
