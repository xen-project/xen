/* 
 * XenoDomainBuilder, copyright (c) Boris Dragovic, bd240@cl.cam.ac.uk
 * This code is released under terms and conditions of GNU GPL :).
 * Usage: <executable> <mem_kb> <os image> <num_vifs> 
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "asm-i386/types.h"
#include "hypervisor-ifs/hypervisor-if.h"
#include "dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

#define PERR_STRING "Xeno Domain Builder"

#define GUEST_SIG   "XenoGues"
#define SIG_LEN    8

/*
 * NB. No ring-3 access in initial guestOS pagetables. Note that we allow
 * ring-3 privileges in the page directories, so that the guestOS may later
 * decide to share a 4MB region with applications.
 */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

/* standardized error reporting function */
static void dberr(char *msg)
{
    printf("%s: %s\n", PERR_STRING, msg);
}

/* status reporting function */
static void dbstatus(char * msg)
{
    printf("Domain Builder: %s\n", msg);
}


/* clean up domain's memory allocations */
static void dom_mem_cleanup(dom_mem_t * dom_mem)
{
    char mem_path[MAX_PATH];
    int mem_fd;

    /* open the domain's /proc mem interface */
    sprintf(mem_path, "%s%s%s%s%d%s%s", "/proc/", PROC_XENO_ROOT, "/", 
            PROC_DOM_PREFIX, dom_mem->domain, "/", PROC_DOM_MEM);

    mem_fd = open(mem_path, O_WRONLY);
    if(mem_fd < 0){
        perror(PERR_STRING);
    }
    
    if(write(mem_fd, (dom_mem_t *)dom_mem, sizeof(dom_mem_t)) < 0){
	dbstatus("Error unmapping domain's memory.\n");
    }

    close(mem_fd);
}

/* ask dom0 to export domains memory through /proc */
static int setup_dom_memmap(unsigned long pfn, int pages, int dom)
{
    char cmd_path[MAX_PATH];
    dom0_op_t dop;
    int cmd_fd;

    dop.cmd = MAP_DOM_MEM;
    dop.u.dommem.start_pfn = pfn;
    dop.u.dommem.tot_pages = pages;
    dop.u.dommem.domain = dom;

    /* open the /proc command interface */
    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    cmd_fd = open(cmd_path, O_WRONLY);
    if ( cmd_fd < 0 )
    {
        perror(PERR_STRING);
        return -1;
    }

    write(cmd_fd, &dop, sizeof(dom0_op_t));
    close(cmd_fd);

    return 0;
}
      
/* request the actual mapping from dom0 */
static unsigned long get_vaddr(unsigned int dom)
{
    char mem_path[MAX_PATH];
    unsigned long addr;
    int mem_fd;

    /* open the domain's /proc mem interface */
    sprintf(mem_path, "%s%s%s%s%d%s%s", "/proc/", PROC_XENO_ROOT, "/", 
            PROC_DOM_PREFIX, dom, "/", PROC_DOM_MEM);

    mem_fd = open(mem_path, O_RDONLY);
    if(mem_fd < 0){
        perror(PERR_STRING);
        return 0;
    }

    /* get virtual address of mapped region */
    read(mem_fd, &addr, sizeof(addr));
	
    close(mem_fd);

    return addr;
}

static int map_dom_mem(unsigned long pfn, int pages, int dom, 
                       dom_mem_t * dom_mem)
{

    if(setup_dom_memmap(pfn, pages, dom)){
        perror(PERR_STRING);
        return -1;
    }

    dom_mem->domain = dom;
    dom_mem->start_pfn = pfn;
    dom_mem->tot_pages = pages;
    if((dom_mem->vaddr = get_vaddr(dom)) == 0){
        dberr("Error mapping dom memory.");
        return -1;
    }
    
    return 0;
}

/* open kernel image and do some sanity checks */
static int do_kernel_chcks(char *image, long dom_size, 
                           unsigned long * load_addr, size_t * ksize)
{
    char signature[8];
    char status[MAX_PATH];
    struct stat stat;
    int fd;
    int ret; 
    
    fd = open(image, O_RDONLY);
    if(fd < 0){
        perror(PERR_STRING);
        ret = -1;    
        goto out;
    }

    if(fstat(fd, &stat) < 0){
        perror(PERR_STRING);
        ret = -1;
        close(fd);
        goto out;
    }

    if(stat.st_size > (dom_size << 10)){
        sprintf(status, "Kernel image size %ld larger than requested "
                "domain size %ld\n Terminated.\n", stat.st_size, dom_size);
        dberr(status);
        ret = -1;
        close(fd);
        goto out;
    }
    
    read(fd, signature, SIG_LEN);
    if(strncmp(signature, GUEST_SIG, SIG_LEN)){
        dberr("Kernel image does not contain required signature. "
              "Terminating.\n");
        ret = -1;
        close(fd);
        goto out;
    }

    read(fd, load_addr, sizeof(unsigned long));

    *ksize = stat.st_size - SIG_LEN - sizeof(unsigned long);

    ret = fd;

 out:    
    return ret;
}

/* this is the main guestos setup function,
 * returnes domain descriptor structure to be used when launching
 * the domain by hypervisor to do some last minute initialization.
 * page table initialization is done by making a list of page table
 * requests that are handeled by the hypervisor in the ordinary
 * manner. this way, many potentially messy things are avoided...
 */ 
#define PAGE_TO_VADDR(_pfn) ((void *)(dom_mem->vaddr + ((_pfn) * PAGE_SIZE)))
static dom_meminfo_t *setup_guestos(int dom, int kernel_fd, int initrd_fd,
                                    unsigned long virt_load_addr, size_t ksize, dom_mem_t *dom_mem)
{
    dom_meminfo_t *meminfo;
    unsigned long *page_array;
    page_update_request_t *pgt_updates;
    dom_mem_t mem_map;
    dom_meminfo_t *ret = NULL;
    int alloc_index, num_pt_pages;
    unsigned long l2tab;
    unsigned long l1tab = 0;
    unsigned long num_pgt_updates = 0;
    unsigned long count, pt_start;
    dom0_op_t pgupdate_req;
    char cmd_path[MAX_PATH];
    int cmd_fd;

    meminfo     = (dom_meminfo_t *)malloc(sizeof(dom_meminfo_t));
    page_array  = malloc(dom_mem->tot_pages * 4);
    pgt_updates = (page_update_request_t *)dom_mem->vaddr;
    alloc_index = dom_mem->tot_pages - 1;

    memset(meminfo, 0, sizeof(meminfo));

    memcpy(page_array, (void *)dom_mem->vaddr, dom_mem->tot_pages * 4);

    /* Count bottom-level PTs, rounding up. Include one PTE for shared info. */
    num_pt_pages = 
        (l1_table_offset(virt_load_addr) + dom_mem->tot_pages + 1024) / 1024;

    /* We must also count the page directory. */
    num_pt_pages++;

    /* Index of first PT page. */
    pt_start = dom_mem->tot_pages - num_pt_pages;

    /* first allocate page for page dir. allocation goes backwards from the
     * end of the allocated physical address space.
     */
    l2tab = *(page_array + alloc_index) << PAGE_SHIFT; 
    memset(PAGE_TO_VADDR(alloc_index), 0, PAGE_SIZE);
    alloc_index--;
    meminfo->l2_pgt_addr = l2tab;
    meminfo->virt_shinfo_addr = virt_load_addr + nr_2_page(dom_mem->tot_pages);

    /* pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */ 
    pgt_updates->ptr = l2tab | PGREQ_EXTENDED_COMMAND;
    pgt_updates->val = PGEXT_PIN_L2_TABLE;
    pgt_updates++;
    num_pgt_updates++;

    /*
     * Initialise the page tables. The final iteration is for the shared_info
     * PTE -- we break out before filling in the entry, as that is done by
     * Xen during final setup.
     */
    l2tab += l2_table_offset(virt_load_addr) * sizeof(l2_pgentry_t);
    for ( count = 0; count < (dom_mem->tot_pages + 1); count++ )
    {    
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) ) 
        {
            l1tab = *(page_array + alloc_index) << PAGE_SHIFT;
            memset(PAGE_TO_VADDR(alloc_index), 0, PAGE_SIZE);
            alloc_index--;
			
            l1tab += l1_table_offset(virt_load_addr + nr_2_page(count)) 
                * sizeof(l1_pgentry_t);

            /* make apropriate entry in the page directory */
            pgt_updates->ptr = l2tab;
            pgt_updates->val = l1tab | L2_PROT;
            pgt_updates++;
            num_pgt_updates++;
            l2tab += sizeof(l2_pgentry_t);
        }

        /* The last PTE we consider is filled in later by Xen. */
        if ( count == dom_mem->tot_pages ) break;
		
        if ( count < pt_start )
        {
            pgt_updates->ptr = l1tab;
            pgt_updates->val = (*(page_array + count) << PAGE_SHIFT) | L1_PROT;
            pgt_updates++;
            num_pgt_updates++;
            l1tab += sizeof(l1_pgentry_t);
        }
        else
        {
            pgt_updates->ptr = l1tab;
            pgt_updates->val = 
		((*(page_array + count) << PAGE_SHIFT) | L1_PROT) & ~_PAGE_RW;
            pgt_updates++;
            num_pgt_updates++;
            l1tab += sizeof(l1_pgentry_t);
        }

        pgt_updates->ptr = 
	    (*(page_array + count) << PAGE_SHIFT) | PGREQ_MPT_UPDATE;
        pgt_updates->val = count;
        pgt_updates++;
        num_pgt_updates++;
    }

    meminfo->virt_startinfo_addr = virt_load_addr + nr_2_page(alloc_index - 1);
    meminfo->domain = dom;

    /*
     * Send the page update requests down to the hypervisor.
     * NB. We must do this before loading the guest OS image!
     */
    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    if ( (cmd_fd = open(cmd_path, O_WRONLY)) < 0 ) goto out;
    pgupdate_req.cmd = DO_PGUPDATES;
    pgupdate_req.u.pgupdate.pgt_update_arr  = (unsigned long)dom_mem->vaddr;
    pgupdate_req.u.pgupdate.num_pgt_updates = num_pgt_updates;
    write(cmd_fd, &pgupdate_req, sizeof(dom0_op_t));
    close(cmd_fd);

    /* Load the guest OS image. */
    if( read(kernel_fd, (char *)dom_mem->vaddr, ksize) != ksize )
    {
        dberr("Error reading kernel image, could not"
              " read the whole image. Terminating.\n");
        goto out;
    }

    if( initrd_fd )
    {
	struct stat stat;
	unsigned long isize;

	if(fstat(initrd_fd, &stat) < 0){
            perror(PERR_STRING);
            close(initrd_fd);
            goto out;
	}
	isize = stat.st_size;

	if( read(initrd_fd, ((char *)dom_mem->vaddr)+ksize, isize) != isize )
        {
	    dberr("Error reading initrd image, could not"
		  " read the whole image. Terminating.\n");
	    goto out;
        }

	meminfo->virt_mod_addr = virt_load_addr + ksize;
	meminfo->virt_mod_len  = isize;

    }


    ret = meminfo;
 out:

    return ret;
}

static int launch_domain(dom_meminfo_t  * meminfo)
{
    char cmd_path[MAX_PATH];
    dom0_op_t dop;
    int cmd_fd;

    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    cmd_fd = open(cmd_path, O_WRONLY);
    if(cmd_fd < 0){
        perror(PERR_STRING);
        return -1;
    }

    dop.cmd = DOM0_BUILDDOMAIN;
    memcpy(&dop.u.meminfo, meminfo, sizeof(dom_meminfo_t));
    write(cmd_fd, &dop, sizeof(dom0_op_t));
    close(cmd_fd);

    return 0;
}

static int get_domain_info (int domain_id,
                            int *pg_head,
                            int *tot_pages)
{
    FILE *f; 
    char domains_path[MAX_PATH];
    char domains_line[256];
    int rc = -1;
    int read_id;

    sprintf (domains_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_DOMAINS
        );

    f = fopen (domains_path, "r");
    if (f == NULL) goto out;

    read_id = -1;
    while (fgets (domains_line, 256, f) != 0)
    { 
        int trans;
        trans = sscanf (domains_line, "%d %*d %*d %*d %*d %*d %x %d %*s", &read_id
                        , pg_head, tot_pages);
        if (trans == 3) {
            if (read_id == domain_id) {
                rc = 0;
                break;
            }
        }
    }

    if (read_id == -1) {
        errno = ESRCH;
    }

    fclose (f);

 out:
    return rc;
}


int main(int argc, char **argv)
{

    dom_mem_t dom_os_image;
    dom_mem_t dom_pgt; 
    dom_meminfo_t * meminfo;
    size_t ksize;
    unsigned long load_addr;
    char status[1024];
    int kernel_fd, initrd_fd = 0;
    int count;
    int cmd_len;
    int rc = -1;
    int args_start = 4;
    char initrd_name[1024];
    int domain_id;
    int pg_head;
    int tot_pages;

    unsigned long addr;

    /**** this argument parsing code is really _gross_. rewrite me! ****/

    if(argc < 4) {
        dberr("Usage: dom_builder <domain_id> <image> <num_vifs> "
	      "[<initrd=initrd_name>] <boot_params>\n");
        return -1;
    }

    /* Look up information about the domain */
    domain_id = atol(argv[1]);
    if ( get_domain_info (domain_id, &pg_head, &tot_pages) != 0 ) 
    {
        perror ("Could not find domain information");
        rc = -1;
        goto out;
    }
	     
    kernel_fd = do_kernel_chcks(argv[2], 
                                tot_pages << (PAGE_SHIFT - 10), 
                                &load_addr, &ksize);
    if ( kernel_fd < 0 )
	return -1;
    

    /* map domain's memory */
    if ( map_dom_mem(pg_head, tot_pages,
                     domain_id, &dom_os_image) )
        goto out;

    if( (argc > args_start) && 
        (strncmp("initrd=", argv[args_start], 7) == 0) )
    {
	strncpy( initrd_name, argv[args_start]+7, sizeof(initrd_name) );
	initrd_name[sizeof(initrd_name)-1] = 0;
	printf("initrd present, name = %s\n", initrd_name );
	args_start++;
        
	initrd_fd = open(initrd_name, O_RDONLY);
	if(initrd_fd < 0){
            perror(PERR_STRING);
            goto out;
	}
    }

    /* the following code does the actual domain building */
    meminfo = setup_guestos(domain_id, kernel_fd, initrd_fd, load_addr, 
			    ksize, &dom_os_image); 
    
    /* and unmap the new domain's memory image since we no longer need it */
    dom_mem_cleanup(&dom_os_image);

    if(!meminfo) { 
	printf("Domain Builder: debug: meminfo NULL\n");
        goto out;
    }

    meminfo->virt_load_addr = load_addr;
    meminfo->num_vifs = atoi(argv[3]);
    meminfo->cmd_line[0] = '\0';
    cmd_len = 0;
    for(count = args_start; count < argc; count++){
        if(cmd_len + strlen(argv[count]) > MAX_CMD_LEN - 1){
            dberr("Size of image boot params too big!\n");
            break;
        }
        strcat(meminfo->cmd_line, argv[count]);
        strcat(meminfo->cmd_line, " ");
        cmd_len += strlen(argv[count] + 1);
    }

    /*    sprintf(status, 
          "About to launch new domain %d with folowing parameters:\n"
          " * page table base: %lx \n * load address: %lx \n"
          " * shared info address: %lx \n * start info address: %lx \n"
          " * number of vifs: %d \n * cmd line: %s \n", meminfo->domain, 
          meminfo->l2_pgt_addr, meminfo->virt_load_addr, 
          meminfo->virt_shinfo_addr, meminfo->virt_startinfo_addr, 
          meminfo->num_vifs, meminfo->cmd_line);
          dbstatus(status);*/
    
    /* and launch the domain */
    rc = launch_domain(meminfo); 
    
 out:
    return rc;
}
