/******************************************************************************
 * libxc_linux_build.c
 */

#include "libxc_private.h"
#include <zlib.h>

/* This string is written to the head of every guest kernel image. */
#define GUEST_SIG   "XenoGues"
#define SIG_LEN    8

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

static long get_tot_pages(int xc_handle, int domid)
{
    dom0_op_t op;
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = domid;
    return (do_dom0_op(xc_handle, &op) < 0) ? 
        -1 : op.u.getdomaininfo.tot_pages;
}

static int get_pfn_list(int xc_handle,
                        int domid, 
                        unsigned long *pfn_buf, 
                        unsigned long max_pfns)
{
    dom0_op_t op;
    int ret;
    op.cmd = DOM0_GETMEMLIST;
    op.u.getmemlist.domain   = domid;
    op.u.getmemlist.max_pfns = max_pfns;
    op.u.getmemlist.buffer   = pfn_buf;

    if ( mlock(pfn_buf, max_pfns * sizeof(unsigned long)) != 0 )
        return -1;

    ret = do_dom0_op(xc_handle, &op);

    (void)munlock(pfn_buf, max_pfns * sizeof(unsigned long));

    return (ret < 0) ? -1 : op.u.getmemlist.num_pfns;
}

static int send_pgupdates(int xc_handle, mmu_update_t *updates, int nr_updates)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (unsigned long)updates;
    hypercall.arg[1] = (unsigned long)nr_updates;

    if ( mlock(updates, nr_updates * sizeof(*updates)) != 0 )
        goto out1;

    if ( do_xen_hypercall(xc_handle, &hypercall) < 0 )
        goto out2;

    ret = 0;

 out2: (void)munlock(updates, nr_updates * sizeof(*updates));
 out1: return ret;
}

/* Read the kernel header, extracting the image size and load address. */
static int read_kernel_header(gzFile gfd, long dom_size, 
                              unsigned long *load_addr)
{
    char signature[SIG_LEN];

    gzread(gfd, signature, SIG_LEN);
    if ( strncmp(signature, GUEST_SIG, SIG_LEN) )
    {
        ERROR("Kernel image does not contain required signature");
        return -1;
    }

    /* Read the load address which immediately follows the Xeno signature. */
    gzread(gfd, load_addr, sizeof(unsigned long));

    return 0;
}

static int copy_to_domain_page(int pm_handle,
                               unsigned long dst_pfn, 
                               void *src_page)
{
    void *vaddr = map_pfn(pm_handle, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memcpy(vaddr, src_page, PAGE_SIZE);
    unmap_pfn(pm_handle, vaddr);
    return 0;
}

static int setup_guestos(int xc_handle,
                         int dom, 
                         gzFile kernel_gfd, 
                         int initrd_fd, 
                         unsigned long tot_pages,
                         unsigned long *virt_startinfo_addr, 
                         unsigned long virt_load_addr, 
                         dom0_builddomain_t *builddomain, 
                         const char *cmdline,
                         unsigned long shared_info_frame)
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
    unsigned long initrd_addr = 0, initrd_len = 0;
    start_info_t *start_info;
    shared_info_t *shared_info;
    unsigned long ksize;
    int pm_handle;

    memset(builddomain, 0, sizeof(*builddomain));

    if ( (pm_handle = init_pfn_mapper()) < 0 )
        goto error_out;

    pgt_updates = malloc((tot_pages + 1024) * 3 * sizeof(mmu_update_t));
    page_array = malloc(tot_pages * sizeof(unsigned long));
    pgt_update_arr = pgt_updates;
    if ( (pgt_update_arr == NULL) || (page_array == NULL) )
    {
        PERROR("Could not allocate memory");
        goto error_out;
    }

    if ( get_pfn_list(xc_handle, dom, page_array, tot_pages) != tot_pages )
    {
        PERROR("Could not get the page frame list");
        goto error_out;
    }

    /* Load the guest OS image. Let it take no more than 1/2 memory.*/
    for ( i = 0; i < ((tot_pages/2)*PAGE_SIZE); i += PAGE_SIZE )
    {
        char page[PAGE_SIZE];
        int size;
        if ( (size = gzread(kernel_gfd, page, PAGE_SIZE)) == -1 )
        {
            PERROR("Error reading kernel image, could not"
                   " read the whole image.");
            goto error_out;
        }
        if ( size == 0 )
            goto kernel_copied;
        copy_to_domain_page(pm_handle, page_array[i>>PAGE_SHIFT], page);
    }
    ERROR("Kernel too big to safely fit in domain memory");
    goto error_out;

 kernel_copied:
    /* ksize is kernel-image size rounded up to a page boundary. */
    ksize = i;

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
        if ( (isize + ksize) > ((tot_pages/2) * PAGE_SIZE) )
        {
            ERROR("Kernel/initrd too big to safely fit in domain memory");
            goto error_out;
        }

        initrd_addr = virt_load_addr + ksize;
        initrd_len  = isize;

        for ( j = 0, i = ksize; j < isize; j += PAGE_SIZE, i += PAGE_SIZE )
        {
            char page[PAGE_SIZE];
            int size = ((isize-j) < PAGE_SIZE) ? (isize-j) : PAGE_SIZE;
            if ( read(initrd_fd, page, size) != size )
            {
                PERROR("Error reading initrd image, could not"
                       " read the whole image.");
                goto error_out;
            } 
            copy_to_domain_page(pm_handle, page_array[i>>PAGE_SHIFT], page);
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
    builddomain->ctxt.pt_base = l2tab;

    /*
     * Pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */ 
    pgt_updates->ptr = l2tab | MMU_EXTENDED_COMMAND;
    pgt_updates->val = MMUEXT_PIN_L2_TABLE;
    pgt_updates++;
    num_pgt_updates++;

    /* Initialise the page tables. */
    if ( (vl2tab = map_pfn(pm_handle, l2tab >> PAGE_SHIFT)) == NULL )
        goto error_out;
    memset(vl2tab, 0, PAGE_SIZE);
    vl2e = vl2tab + l2_table_offset(virt_load_addr);
    for ( count = 0; count < tot_pages; count++ )
    {    
        if ( ((unsigned long)vl1e & (PAGE_SIZE-1)) == 0 ) 
        {
            l1tab = page_array[alloc_index] << PAGE_SHIFT;
            if ( (vl1tab = map_pfn(pm_handle, l1tab >> PAGE_SHIFT)) == NULL )
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

    *virt_startinfo_addr =
        virt_load_addr + ((alloc_index-1) << PAGE_SHIFT);

    start_info = map_pfn(pm_handle, page_array[alloc_index-1]);
    memset(start_info, 0, sizeof(*start_info));
    start_info->pt_base     = virt_load_addr + ((tot_pages-1) << PAGE_SHIFT);
    start_info->mod_start   = initrd_addr;
    start_info->mod_len     = initrd_len;
    start_info->nr_pages    = tot_pages;
    start_info->shared_info = shared_info_frame << PAGE_SHIFT;
    start_info->dom_id      = dom;
    start_info->flags       = 0;
    strncpy(start_info->cmd_line, cmdline, MAX_CMD_LEN);
    start_info->cmd_line[MAX_CMD_LEN-1] = '\0';

    unmap_pfn(pm_handle, start_info);

    /* shared_info page starts its life empty. */
    shared_info = map_pfn(pm_handle, shared_info_frame);
    memset(shared_info, 0, PAGE_SIZE);
    unmap_pfn(pm_handle, shared_info);

    /* Send the page update requests down to the hypervisor. */
    if ( send_pgupdates(xc_handle, pgt_update_arr, num_pgt_updates) < 0 )
        goto error_out;

    free(page_array);
    free(pgt_update_arr);
    return 0;

 error_out:
    if ( pm_handle >= 0 )
        (void)close_pfn_mapper(pm_handle);
    if ( page_array == NULL )
        free(page_array);
    if ( pgt_update_arr == NULL )
        free(pgt_update_arr);
    return -1;
}

int xc_linux_build(int xc_handle,
                   unsigned int domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline)
{
    dom0_op_t launch_op, op;
    unsigned long load_addr;
    long tot_pages;
    int kernel_fd, initrd_fd = -1;
    gzFile kernel_gfd;
    int rc, i;
    full_execution_context_t *ctxt;
    unsigned long virt_startinfo_addr;

    if ( (tot_pages = get_tot_pages(xc_handle, domid)) < 0 )
    {
        PERROR("Could not find total pages for domain");
        return 1;
    }

    kernel_fd = open(image_name, O_RDONLY);
    if ( kernel_fd < 0 )
    {
        PERROR("Could not open kernel image");
        return 1;
    }

    if ( (kernel_gfd = gzdopen(kernel_fd, "rb")) == NULL )
    {
        PERROR("Could not allocate decompression state for state file");
        close(kernel_fd);
        return 1;
    }

    rc = read_kernel_header(kernel_gfd,
                            tot_pages << (PAGE_SHIFT - 10), 
                            &load_addr);
    if ( rc < 0 )
        goto error_out;
    
    if ( (load_addr & (PAGE_SIZE-1)) != 0 )
    {
        ERROR("We can only deal with page-aligned load addresses");
        goto error_out;
    }

    if ( (load_addr + (tot_pages << PAGE_SHIFT)) > HYPERVISOR_VIRT_START )
    {
        ERROR("Cannot map all domain memory without hitting Xen space");
        goto error_out;
    }

    if ( ramdisk_name != NULL )
    {
        initrd_fd = open(ramdisk_name, O_RDONLY);
        if ( initrd_fd < 0 )
        {
            PERROR("Could not open the initial ramdisk image");
            goto error_out;
        }
    }

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = domid;
    if ( (do_dom0_op(xc_handle, &op) < 0) || 
         (op.u.getdomaininfo.domain != domid) )
    {
        PERROR("Could not get info on domain");
        goto error_out;
    }
    if ( (op.u.getdomaininfo.state != DOMSTATE_STOPPED) ||
         (op.u.getdomaininfo.ctxt.pt_base != 0) )
    {
        ERROR("Domain is already constructed");
        goto error_out;
    }

    if ( setup_guestos(xc_handle, domid, kernel_gfd, initrd_fd, tot_pages,
                       &virt_startinfo_addr,
                       load_addr, &launch_op.u.builddomain, cmdline,
                       op.u.getdomaininfo.shared_info_frame) < 0 )
    {
        ERROR("Error constructing guest OS");
        goto error_out;
    }

    if ( initrd_fd >= 0 )
        close(initrd_fd);
    gzclose(kernel_gfd);

    ctxt = &launch_op.u.builddomain.ctxt;

    ctxt->flags = 0;

    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_RING1_DS
     *       CS:EIP = FLAT_RING1_CS:start_pc
     *       SS:ESP = FLAT_RING1_DS:start_stack
     *          ESI = start_info
     *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
     *       EFLAGS = IF | 2 (bit 1 is reserved and should always be 1)
     */
    ctxt->i386_ctxt.ds = FLAT_RING1_DS;
    ctxt->i386_ctxt.es = FLAT_RING1_DS;
    ctxt->i386_ctxt.fs = FLAT_RING1_DS;
    ctxt->i386_ctxt.gs = FLAT_RING1_DS;
    ctxt->i386_ctxt.ss = FLAT_RING1_DS;
    ctxt->i386_ctxt.cs = FLAT_RING1_CS;
    ctxt->i386_ctxt.eip = load_addr;
    ctxt->i386_ctxt.esp = virt_startinfo_addr;
    ctxt->i386_ctxt.esi = virt_startinfo_addr;
    ctxt->i386_ctxt.eflags = (1<<9) | (1<<2);

    /* FPU is set up to default initial state. */
    memset(ctxt->i387_ctxt, 0, sizeof(ctxt->i387_ctxt));

    /* Virtual IDT is empty at start-of-day. */
    for ( i = 0; i < 256; i++ )
    {
        ctxt->trap_ctxt[i].vector = i;
        ctxt->trap_ctxt[i].cs     = FLAT_RING1_CS;
    }
    ctxt->fast_trap_idx = 0;

    /* No LDT. */
    ctxt->ldt_ents = 0;
    
    /* Use the default Xen-provided GDT. */
    ctxt->gdt_ents = 0;

    /* Ring 1 stack is the initial stack. */
    ctxt->ring1_ss  = FLAT_RING1_DS;
    ctxt->ring1_esp = virt_startinfo_addr;

    /* No debugging. */
    memset(ctxt->debugreg, 0, sizeof(ctxt->debugreg));

    /* No callback handlers. */
    ctxt->event_callback_cs     = FLAT_RING1_CS;
    ctxt->event_callback_eip    = 0;
    ctxt->failsafe_callback_cs  = FLAT_RING1_CS;
    ctxt->failsafe_callback_eip = 0;

    launch_op.u.builddomain.domain   = domid;
    launch_op.u.builddomain.num_vifs = 1;

    launch_op.cmd = DOM0_BUILDDOMAIN;
    rc = do_dom0_op(xc_handle, &launch_op);
    
    return rc;

 error_out:
    if ( initrd_fd >= 0 )
        close(initrd_fd);
    gzclose(kernel_gfd);
    return -1;
}
