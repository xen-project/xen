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

#include "hypervisor_defs.h"
#include "dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

#define PERR_STRING "Xeno Domain Builder"

#define GUEST_SIG   "XenoGues"
#define SIG_LEN    8

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED|_PAGE_DIRTY)

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
    if(cmd_fd < 0){
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

/* create new domain */
static dom0_newdomain_t * create_new_domain(long req_mem)
{
    dom0_newdomain_t * dom_data;
    char cmd_path[MAX_PATH];
    char dom_id_path[MAX_PATH];
    dom0_op_t dop;
    int cmd_fd;
    int id_fd;

    /* open the /proc command interface */
    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    cmd_fd = open(cmd_path, O_WRONLY);
    if(cmd_fd < 0){
        perror(PERR_STRING);
        return 0;
    }

    dop.cmd = DOM0_NEWDOMAIN;
    dop.u.newdomain.memory_kb = req_mem;

    write(cmd_fd, &dop, sizeof(dom0_op_t));
    close(cmd_fd);

    sprintf(dom_id_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", 
        PROC_DOM_DATA);
    while((id_fd = open(dom_id_path, O_RDONLY)) < 0){}
    dom_data = (dom0_newdomain_t *)malloc(sizeof(dom0_newdomain_t));
    read(id_fd, dom_data, sizeof(dom0_newdomain_t));
    close(id_fd);
    
    sprintf(cmd_path, "Reserved %ld kbytes memory and assigned id %d to the"
                    "new domain.", req_mem, dom_data->domain);
    dbstatus(cmd_path);

    return dom_data;
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
    *ksize = stat.st_size - SIG_LEN;
    
    read(fd, signature, SIG_LEN);
    if(strncmp(signature, GUEST_SIG, SIG_LEN)){
        dberr("Kernel image does not contain required signature. "
		"Terminating.\n");
        ret = -1;
		close(fd);
        goto out;
    }

    read(fd, load_addr, sizeof(unsigned long));

    sprintf(status, "Kernel image %s valid, kernel virtual load address %lx", 
        image, *load_addr);
    dbstatus(status);

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
static dom_meminfo_t * setup_guestos(int dom, int kernel_fd, 
    unsigned long virt_load_addr, size_t ksize, dom_mem_t *dom_mem)
{
    dom_meminfo_t * meminfo = (dom_meminfo_t *)malloc(sizeof(dom_meminfo_t));
    unsigned long * page_array = (unsigned long *)(dom_mem->vaddr);
    page_update_request_t * pgt_updates = (page_update_request_t *)
        (dom_mem->vaddr + ((ksize + (PAGE_SIZE-1)) & PAGE_MASK));
    dom_mem_t mem_map;
    dom_meminfo_t * ret = NULL;
    int alloc_index = dom_mem->tot_pages - 1, num_pt_pages;
    unsigned long l2tab;
    unsigned long l1tab = 0;
    unsigned long num_pgt_updates = 0;
    unsigned long pgt_update_arr = (unsigned long)pgt_updates;
    unsigned long count, pt_start;

    /* Count bottom-level PTs. Round up to a whole PT. */
    num_pt_pages = 
        (l1_table_offset(virt_load_addr) + dom_mem->tot_pages + 1023) / 1024;
    /* We must also count the page directory. */
    num_pt_pages++;

    /* Index of first PT page. */
    pt_start = dom_mem->tot_pages - num_pt_pages;

    /* first allocate page for page dir. allocation goes backwards from the
     * end of the allocated physical address space.
     */
    l2tab = *(page_array + alloc_index) << PAGE_SHIFT; 
    alloc_index--;
    meminfo->l2_pgt_addr = l2tab;
    meminfo->virt_shinfo_addr = virt_load_addr + nr_2_page(dom_mem->tot_pages);
    count = ((unsigned long)pgt_updates - (unsigned long)(dom_mem->vaddr)) 
        >> PAGE_SHIFT;

    /* zero out l2 page */
    if(map_dom_mem(l2tab >> PAGE_SHIFT, 1, dom_mem->domain, &mem_map)){
        dberr("Unable to map l2 page into Domain Builder.");
        goto out;
    }
    memset((void *)mem_map.vaddr, 0, PAGE_SIZE);
    dom_mem_cleanup(&mem_map);

    /* pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */ 
    pgt_updates->ptr = l2tab | PGREQ_EXTENDED_COMMAND;
    pgt_updates->val = PGEXT_PIN_L2_TABLE;
    pgt_updates++;
    num_pgt_updates++;

    /* this loop initializes page tables and does one extra entry 
     * to be used by the shared info page. shared info is not in
     * the domains physical address space and is not owned by the
     * domain.
     */
    l2tab += l2_table_offset(virt_load_addr) * sizeof(l2_pgentry_t);
    for(count = 0;
        count < dom_mem->tot_pages + 1; 
        count++){
        
        if(!((unsigned long)l1tab & (PAGE_SIZE-1))){
            l1tab = *(page_array + alloc_index) << PAGE_SHIFT;
            alloc_index--;
			
            /* zero out l1 page */
            if(map_dom_mem(l1tab >> PAGE_SHIFT, 1, dom_mem->domain, &mem_map)){
                dberr("Unable to map l1 page into Domain Builder.");
                goto out;
            }
            memset((void *)mem_map.vaddr, 0, PAGE_SIZE);
            dom_mem_cleanup(&mem_map);

            l1tab += l1_table_offset(virt_load_addr + nr_2_page(count)) 
                * sizeof(l1_pgentry_t);

            /* make apropriate entry in the page directory */
            pgt_updates->ptr = l2tab;
            pgt_updates->val = l1tab | L2_PROT;
            pgt_updates++;
            num_pgt_updates++;
            l2tab += sizeof(l2_pgentry_t);
        }
		
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

    /* copy the guest os image */
    if(!(read(kernel_fd, (char *)dom_mem->vaddr, ksize) > 0)){
        dberr("Error reading kernel image, could not"
              " read the whole image. Terminating.\n");
        goto out;
    }

    {
        dom0_op_t pgupdate_req;
        char cmd_path[MAX_PATH];
        int cmd_fd;

        sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
        if ( (cmd_fd = open(cmd_path, O_WRONLY)) < 0 ) goto out;

        pgupdate_req.cmd = DO_PGUPDATES;
        pgupdate_req.u.pgupdate.pgt_update_arr  = pgt_update_arr;
        pgupdate_req.u.pgupdate.num_pgt_updates = num_pgt_updates;

        write(cmd_fd, &pgupdate_req, sizeof(dom0_op_t));
        close(cmd_fd);
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

    dop.cmd = DOM0_STARTDOM;
    memcpy(&dop.u.meminfo, meminfo, sizeof(dom_meminfo_t));
    write(cmd_fd, &dop, sizeof(dom0_op_t));

    dbstatus("Launched the new domain!");

    close(cmd_fd);
}

int main(int argc, char **argv)
{

    dom0_newdomain_t * dom_data;
    dom_mem_t dom_os_image;
    dom_mem_t dom_pgt; 
    dom_meminfo_t * meminfo;
    size_t ksize;
    unsigned long load_addr;
    char status[1024];
    int kernel_fd;
    int count;
    int cmd_len;
    int ret = 0;

	unsigned long addr;

    if(argc < 4){
        dberr("Usage: dom_builder <kbytes_mem> <image> <num_vifs> "
                        "<boot_params>\n");
        ret = -1;
        goto out;
    }

    /* create new domain and set up all the neccessary mappings */

    kernel_fd = do_kernel_chcks(argv[2], atol(argv[1]), &load_addr, &ksize);
    if(kernel_fd < 0){
        ret = -1;
        goto out;
    }

    /* request the creation of new domain */
    dom_data = create_new_domain(atol(argv[1]));
    if(dom_data == 0){
        ret = -1;
        goto out;
    }

    /* map domain's memory */
    if(map_dom_mem(dom_data->pg_head, dom_data->memory_kb >> (PAGE_SHIFT - 10), 
        dom_data->domain, &dom_os_image)){
        ret = -1;
        goto out;
    }

    /* the following code does the actual domain building */
    meminfo = setup_guestos(dom_data->domain, kernel_fd, load_addr, ksize, 
        &dom_os_image);
    if(meminfo == NULL){
		printf("Domain Builder: debug: meminfo NULL\n");
        ret = -1;
        dom_mem_cleanup(&dom_os_image);
        goto out;
    }

    dom_mem_cleanup(&dom_os_image);

    meminfo->virt_load_addr = load_addr;
    meminfo->num_vifs = atoi(argv[3]);
    meminfo->cmd_line[0] = '\0';
    cmd_len = 0;
    for(count = 4; count < argc; count++){
        if(cmd_len + strlen(argv[count]) > MAX_CMD_LEN - 1){
            dberr("Size of image boot params too big!\n");
            break;
        }
        strcat(meminfo->cmd_line, argv[count]);
        strcat(meminfo->cmd_line, " ");
        cmd_len += strlen(argv[count] + 1);
    }

    sprintf(status, 
	    "About to launch new domain %d with folowing parameters:\n"
	    " * page table base: %lx \n * load address: %lx \n"
	    " * shared info address: %lx \n * start info address: %lx \n"
	    " * number of vifs: %d \n * cmd line: %s \n", meminfo->domain, 
	    meminfo->l2_pgt_addr, meminfo->virt_load_addr, 
	    meminfo->virt_shinfo_addr, meminfo->virt_startinfo_addr, 
	    meminfo->num_vifs, meminfo->cmd_line);
    dbstatus(status);
    
    /* and launch the domain */
    if(launch_domain(meminfo) != 0)
	ret = -1;

    free(meminfo);
out:
    return ret;
}
