/******************************************************************************
 * xc_vmx_build.c
 */

#include "xc_private.h"
#define ELFSIZE 32
#include "xc_elf.h"
#include <stdlib.h>
#include <zlib.h>
#include "linux_boot_params.h"

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

#define LINUX_BOOT_PARAMS_ADDR   0x00090000
#define LINUX_KERNEL_ENTR_ADDR   0x00100000
#define LINUX_PAGE_OFFSET        0xC0000000

struct domain_setup_info
{
    unsigned long v_start;
    unsigned long v_end;
    unsigned long v_kernstart;
    unsigned long v_kernend;
    unsigned long v_kernentry;

    unsigned int use_writable_pagetables;
    unsigned int load_bsd_symtab;

    unsigned long symtab_addr;
    unsigned long symtab_len;
};

static int
parseelfimage(
    char *elfbase, unsigned long elfsize, struct domain_setup_info *dsi);
static int
loadelfimage(
    char *elfbase, int xch, u32 dom, unsigned long *parray,
    unsigned long vstart);
static int
loadelfsymtab(
    char *elfbase, int xch, u32 dom, unsigned long *parray,
    struct domain_setup_info *dsi);

static void build_e820map(struct mem_map *mem_mapp, unsigned long mem_size)
{
    int nr_map = 0;

    /* XXX: Doesn't work for > 4GB yet */
    mem_mapp->map[0].addr = 0x0;
    mem_mapp->map[0].size = 0x9F800;
    mem_mapp->map[0].type = E820_RAM;
    mem_mapp->map[0].caching_attr = MEMMAP_WB;
    nr_map++;

    mem_mapp->map[1].addr = 0x9F800;
    mem_mapp->map[1].size = 0x800;
    mem_mapp->map[1].type = E820_RESERVED;
    mem_mapp->map[1].caching_attr = MEMMAP_UC;
    nr_map++;

    mem_mapp->map[2].addr = 0xA0000;
    mem_mapp->map[2].size = 0x20000;
    mem_mapp->map[2].type = E820_IO;
    mem_mapp->map[2].caching_attr = MEMMAP_UC;
    nr_map++;

    mem_mapp->map[3].addr = 0xF0000;
    mem_mapp->map[3].size = 0x10000;
    mem_mapp->map[3].type = E820_RESERVED;
    mem_mapp->map[3].caching_attr = MEMMAP_UC;
    nr_map++;

    mem_mapp->map[4].addr = 0x100000;
    mem_mapp->map[4].size = mem_size - 0x100000 - PAGE_SIZE;
    mem_mapp->map[4].type = E820_RAM;
    mem_mapp->map[4].caching_attr = MEMMAP_WB;
    nr_map++;

    mem_mapp->map[5].addr = mem_size - PAGE_SIZE;
    mem_mapp->map[5].size = PAGE_SIZE;
    mem_mapp->map[5].type = E820_SHARED;
    mem_mapp->map[5].caching_attr = MEMMAP_WB;
    nr_map++;

    mem_mapp->map[6].addr = mem_size;
    mem_mapp->map[6].size = 0x3 * PAGE_SIZE;
    mem_mapp->map[6].type = E820_NVS;
    mem_mapp->map[6].caching_attr = MEMMAP_UC;
    nr_map++;

    mem_mapp->map[7].addr = mem_size + 0x3 * PAGE_SIZE;
    mem_mapp->map[7].size = 0xA * PAGE_SIZE;
    mem_mapp->map[7].type = E820_ACPI;
    mem_mapp->map[7].caching_attr = MEMMAP_WB;
    nr_map++;

    mem_mapp->map[8].addr = 0xFEC00000;
    mem_mapp->map[8].size = 0x1400000;
    mem_mapp->map[8].type = E820_IO;
    mem_mapp->map[8].caching_attr = MEMMAP_UC;
    nr_map++;

    mem_mapp->nr_map = nr_map;
}

static int zap_mmio_range(int xc_handle, u32 dom,
                            l2_pgentry_t *vl2tab,
                            unsigned long mmio_range_start,
                            unsigned long mmio_range_size)
{
    unsigned long mmio_addr;
    unsigned long mmio_range_end = mmio_range_start + mmio_range_size;
    unsigned long vl2e;
    l1_pgentry_t *vl1tab;

    mmio_addr = mmio_range_start & PAGE_MASK;
    for (; mmio_addr < mmio_range_end; mmio_addr += PAGE_SIZE) {
        vl2e = vl2tab[l2_table_offset(mmio_addr)];
        vl1tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                PROT_READ|PROT_WRITE, vl2e >> PAGE_SHIFT);
	if (vl1tab == 0) {
	    PERROR("Failed zap MMIO range");
	    return -1;
	}
        vl1tab[l1_table_offset(mmio_addr)] = 0;
        munmap(vl1tab, PAGE_SIZE);
    }
    return 0;
}

static int zap_mmio_ranges(int xc_handle, u32 dom,
                            unsigned long l2tab,
                            struct mem_map *mem_mapp)
{
    int i;
    l2_pgentry_t *vl2tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                                PROT_READ|PROT_WRITE,
                                                l2tab >> PAGE_SHIFT);
    if (vl2tab == 0)
    	return -1;
    for (i = 0; i < mem_mapp->nr_map; i++) {
        if ((mem_mapp->map[i].type == E820_IO)
          && (mem_mapp->map[i].caching_attr == MEMMAP_UC))
            if (zap_mmio_range(xc_handle, dom, vl2tab,
	    		mem_mapp->map[i].addr, mem_mapp->map[i].size) == -1)
		return -1;
    }
    munmap(vl2tab, PAGE_SIZE);
    return 0;
}

static int setup_guest(int xc_handle,
                         u32 dom, int memsize,
                         char *image, unsigned long image_size,
                         gzFile initrd_gfd, unsigned long initrd_len,
                         unsigned long nr_pages,
                         full_execution_context_t *ctxt,
                         const char *cmdline,
                         unsigned long shared_info_frame,
                         unsigned int control_evtchn,
                         unsigned long flags,
                         struct mem_map * mem_mapp)
{
    l1_pgentry_t *vl1tab=NULL, *vl1e=NULL;
    l2_pgentry_t *vl2tab=NULL, *vl2e=NULL;
    unsigned long *page_array = NULL;
    unsigned long l2tab;
    unsigned long l1tab;
    unsigned long count, i;
    shared_info_t *shared_info;
    struct linux_boot_params * boot_paramsp;
    __u16 * boot_gdtp;
    mmu_t *mmu = NULL;
    int rc;

    unsigned long nr_pt_pages;
    unsigned long ppt_alloc;

    struct domain_setup_info dsi;
    unsigned long vinitrd_start;
    unsigned long vinitrd_end;
    unsigned long vboot_params_start;
    unsigned long vboot_params_end;
    unsigned long vboot_gdt_start;
    unsigned long vboot_gdt_end;
    unsigned long vpt_start;
    unsigned long vpt_end;
    unsigned long v_end;

    memset(&dsi, 0, sizeof(struct domain_setup_info));

    rc = parseelfimage(image, image_size, &dsi);
    if ( rc != 0 )
        goto error_out;

    if (dsi.use_writable_pagetables)
        xc_domain_setvmassist(xc_handle, dom, VMASST_CMD_enable,
                              VMASST_TYPE_writable_pagetables);

    if (dsi.load_bsd_symtab)
        loadelfsymtab(image, xc_handle, dom, NULL, &dsi);

    if ( (dsi.v_start & (PAGE_SIZE-1)) != 0 )
    {
        PERROR("Guest OS must load to a page boundary.\n");
        goto error_out;
    }

    /*
     * Why do we need this? The number of page-table frames depends on the 
     * size of the bootstrap address space. But the size of the address space 
     * depends on the number of page-table frames (since each one is mapped 
     * read-only). We have a pair of simultaneous equations in two unknowns, 
     * which we solve by exhaustive search.
     */
    vboot_params_start = LINUX_BOOT_PARAMS_ADDR;
    vboot_params_end   = vboot_params_start + PAGE_SIZE;
    vboot_gdt_start    = vboot_params_end;
    vboot_gdt_end      = vboot_gdt_start + PAGE_SIZE;

    /* memsize is in megabytes */
    v_end              = memsize << 20;
    vinitrd_end        = v_end - PAGE_SIZE; /* leaving the top 4k untouched for IO requests page use */
    vinitrd_start      = vinitrd_end - initrd_len;
    vinitrd_start      = vinitrd_start & (~(PAGE_SIZE - 1));

    if(initrd_len == 0)
        vinitrd_start = vinitrd_end = 0;

    nr_pt_pages = 1 + ((memsize + 3) >> 2);
    vpt_start   = v_end;
    vpt_end     = vpt_start + (nr_pt_pages * PAGE_SIZE);

    printf("VIRTUAL MEMORY ARRANGEMENT:\n"
           " Boot_params:   %08lx->%08lx\n"
           " boot_gdt:      %08lx->%08lx\n"
           " Loaded kernel: %08lx->%08lx\n"
           " Init. ramdisk: %08lx->%08lx\n"
           " Page tables:   %08lx->%08lx\n"
           " TOTAL:         %08lx->%08lx\n",
           vboot_params_start, vboot_params_end,
           vboot_gdt_start, vboot_gdt_end,
           dsi.v_kernstart, dsi.v_kernend, 
           vinitrd_start, vinitrd_end,
           vpt_start, vpt_end,
           dsi.v_start, v_end);
    printf(" ENTRY ADDRESS: %08lx\n", dsi.v_kernentry);
    printf(" INITRD LENGTH: %08lx\n", initrd_len);

    if ( (v_end - dsi.v_start) > (nr_pages * PAGE_SIZE) )
    {
        printf("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-dsi.v_start)>>20, (nr_pages<<PAGE_SHIFT)>>20);
        goto error_out;
    }

    if ( (page_array = malloc(nr_pages * sizeof(unsigned long))) == NULL )
    {
        PERROR("Could not allocate memory");
        goto error_out;
    }

    if ( xc_get_pfn_list(xc_handle, dom, page_array, nr_pages) != nr_pages )
    {
        PERROR("Could not get the page frame list");
        goto error_out;
    }

    loadelfimage(image, xc_handle, dom, page_array, dsi.v_start);

    if (dsi.load_bsd_symtab)
        loadelfsymtab(image, xc_handle, dom, page_array, &dsi);

    /* Load the initial ramdisk image. */
    if ( initrd_len != 0 )
    {
        for ( i = (vinitrd_start - dsi.v_start); 
              i < (vinitrd_end - dsi.v_start); i += PAGE_SIZE )
        {
            char page[PAGE_SIZE];
            if ( gzread(initrd_gfd, page, PAGE_SIZE) == -1 )
            {
                PERROR("Error reading initrd image, could not");
                goto error_out;
            }
            xc_copy_to_domain_page(xc_handle, dom,
                                page_array[i>>PAGE_SHIFT], page);
        }
    }

    if ( (mmu = init_mmu_updates(xc_handle, dom)) == NULL )
        goto error_out;

    /* First allocate page for page dir. */
    ppt_alloc = (vpt_start - dsi.v_start) >> PAGE_SHIFT;
    l2tab = page_array[ppt_alloc++] << PAGE_SHIFT;
    ctxt->pt_base = l2tab;

    /* Initialise the page tables. */
    if ( (vl2tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, 
                                        PROT_READ|PROT_WRITE, 
                                        l2tab >> PAGE_SHIFT)) == NULL )
        goto error_out;
    memset(vl2tab, 0, PAGE_SIZE);
    vl2e = &vl2tab[l2_table_offset(dsi.v_start)];
    for ( count = 0; count < ((v_end-dsi.v_start)>>PAGE_SHIFT); count++ )
    {    
        if ( ((unsigned long)vl1e & (PAGE_SIZE-1)) == 0 )
        {
            l1tab = page_array[ppt_alloc++] << PAGE_SHIFT;
            if ( vl1tab != NULL )
                munmap(vl1tab, PAGE_SIZE);
            if ( (vl1tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                                PROT_READ|PROT_WRITE,
                                                l1tab >> PAGE_SHIFT)) == NULL )
            {
                munmap(vl2tab, PAGE_SIZE);
                goto error_out;
            }
            memset(vl1tab, 0, PAGE_SIZE);
            vl1e = &vl1tab[l1_table_offset(dsi.v_start + (count<<PAGE_SHIFT))];
            *vl2e++ = l1tab | L2_PROT;
        }

        *vl1e = (page_array[count] << PAGE_SHIFT) | L1_PROT;
        vl1e++;
    }
    munmap(vl1tab, PAGE_SIZE);
    munmap(vl2tab, PAGE_SIZE);

    /*
     * Pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */ 
    if ( add_mmu_update(xc_handle, mmu,
                        l2tab | MMU_EXTENDED_COMMAND, MMUEXT_PIN_L2_TABLE) )
        goto error_out;

    if ((boot_paramsp = xc_map_foreign_range(
		xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
		page_array[(vboot_params_start-dsi.v_start)>>PAGE_SHIFT])) == 0)
        goto error_out;
    memset(boot_paramsp, 0, sizeof(*boot_paramsp));

    strncpy((char *)boot_paramsp->cmd_line, cmdline, 0x800);
    boot_paramsp->cmd_line[0x800-1] = '\0';
    boot_paramsp->cmd_line_ptr = ((unsigned long) vboot_params_start) + offsetof(struct linux_boot_params, cmd_line);

    boot_paramsp->setup_sects = 0;
    boot_paramsp->mount_root_rdonly = 1;
    boot_paramsp->swapdev = 0x0; 
    boot_paramsp->ramdisk_flags = 0x0; 
    boot_paramsp->root_dev = 0x0; /* We must tell kernel root dev by kernel command line. */

    /* we don't have a ps/2 mouse now.
     * 0xAA means a aux mouse is there.
     * See detect_auxiliary_port() in pc_keyb.c.
     */
    boot_paramsp->aux_device_info = 0x0; 

    boot_paramsp->header_magic[0] = 0x48; /* "H" */
    boot_paramsp->header_magic[1] = 0x64; /* "d" */
    boot_paramsp->header_magic[2] = 0x72; /* "r" */
    boot_paramsp->header_magic[3] = 0x53; /* "S" */

    boot_paramsp->protocol_version = 0x0203; /* 2.03 */
    boot_paramsp->loader_type = 0x71; /* GRUB */
    boot_paramsp->loader_flags = 0x1; /* loaded high */
    boot_paramsp->code32_start = LINUX_KERNEL_ENTR_ADDR; /* 1MB */
    boot_paramsp->initrd_start = vinitrd_start;
    boot_paramsp->initrd_size = initrd_len;

    i = ((memsize - 1) << 10) - 4;
    boot_paramsp->alt_mem_k = i; /* alt_mem_k */
    boot_paramsp->screen.overlap.ext_mem_k = i & 0xFFFF; /* ext_mem_k */

    /*
     * Stuff SCREAN_INFO
     */
    boot_paramsp->screen.info.orig_x = 0;
    boot_paramsp->screen.info.orig_y = 0;
    boot_paramsp->screen.info.orig_video_page = 8;
    boot_paramsp->screen.info.orig_video_mode = 3;
    boot_paramsp->screen.info.orig_video_cols = 80;
    boot_paramsp->screen.info.orig_video_ega_bx = 0;
    boot_paramsp->screen.info.orig_video_lines = 25;
    boot_paramsp->screen.info.orig_video_isVGA = 1;
    boot_paramsp->screen.info.orig_video_points = 0x0010;

    /* seems we may NOT stuff boot_paramsp->apm_bios_info */
    /* seems we may NOT stuff boot_paramsp->drive_info */
    /* seems we may NOT stuff boot_paramsp->sys_desc_table */
    *((unsigned short *) &boot_paramsp->drive_info.dummy[0]) = 800;
    boot_paramsp->drive_info.dummy[2] = 4;
    boot_paramsp->drive_info.dummy[14] = 32;

    /* memsize is in megabytes */
    build_e820map(mem_mapp, memsize << 20);
    if (zap_mmio_ranges(xc_handle, dom, l2tab, mem_mapp) == -1)
    	goto error_out;
    boot_paramsp->e820_map_nr = mem_mapp->nr_map;
    for (i=0; i<mem_mapp->nr_map; i++) {
        boot_paramsp->e820_map[i].addr = mem_mapp->map[i].addr; 
        boot_paramsp->e820_map[i].size = mem_mapp->map[i].size; 
        boot_paramsp->e820_map[i].type = mem_mapp->map[i].type; 
    }
    munmap(boot_paramsp, PAGE_SIZE); 

    if ((boot_gdtp = xc_map_foreign_range(
		xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
		page_array[(vboot_gdt_start-dsi.v_start)>>PAGE_SHIFT])) == 0)
	goto error_out;
    memset(boot_gdtp, 0, PAGE_SIZE);
    boot_gdtp[12*4 + 0] = boot_gdtp[13*4 + 0] = 0xffff; /* limit */
    boot_gdtp[12*4 + 1] = boot_gdtp[13*4 + 1] = 0x0000; /* base */
    boot_gdtp[12*4 + 2] = 0x9a00; boot_gdtp[13*4 + 2] = 0x9200; /* perms */
    boot_gdtp[12*4 + 3] = boot_gdtp[13*4 + 3] = 0x00cf; /* granu + top of limit */
    munmap(boot_gdtp, PAGE_SIZE);

    /* shared_info page starts its life empty. */
    if ((shared_info = xc_map_foreign_range(
		xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
		shared_info_frame)) == 0)
	goto error_out;
    memset(shared_info, 0, sizeof(shared_info_t));
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_data[i].evtchn_upcall_mask = 1;
    munmap(shared_info, PAGE_SIZE);

    /* Send the page update requests down to the hypervisor. */
    if ( finish_mmu_updates(xc_handle, mmu) )
        goto error_out;

    free(mmu);
    free(page_array);

    /*
     * Initial register values:
     */
    ctxt->cpu_ctxt.ds = 0x68;
    ctxt->cpu_ctxt.es = 0x0;
    ctxt->cpu_ctxt.fs = 0x0;
    ctxt->cpu_ctxt.gs = 0x0;
    ctxt->cpu_ctxt.ss = 0x68;
    ctxt->cpu_ctxt.cs = 0x60;
    ctxt->cpu_ctxt.eip = dsi.v_kernentry;
    ctxt->cpu_ctxt.edx = vboot_gdt_start;
    ctxt->cpu_ctxt.eax = 0x800;
    ctxt->cpu_ctxt.esp = vboot_gdt_end;
    ctxt->cpu_ctxt.ebx = 0;	/* startup_32 expects this to be 0 to signal boot cpu */
    ctxt->cpu_ctxt.ecx = mem_mapp->nr_map;
    ctxt->cpu_ctxt.esi = vboot_params_start;
    ctxt->cpu_ctxt.edi = vboot_params_start + 0x2d0;

    ctxt->cpu_ctxt.eflags = (1<<2);

    return 0;

 error_out:
    if ( mmu != NULL )
        free(mmu);
    if ( page_array != NULL )
        free(page_array);
    return -1;
}


#define VMX_FEATURE_FLAG 0x20

int vmx_identify(void)
{
    int eax, ecx;

#ifdef __i386__
    __asm__ __volatile__ ("pushl %%ebx; cpuid; popl %%ebx" 
			  : "=a" (eax), "=c" (ecx) 
			  : "0" (1) 
			  : "dx");
#elif defined __x86_64__
    __asm__ __volatile__ ("pushq %%rbx; cpuid; popq %%rbx"
                          : "=a" (eax), "=c" (ecx)
                          : "0" (1)
                          : "dx");
#endif

    if (!(ecx & VMX_FEATURE_FLAG)) {
        return -1;
    }
    return 0;
}

int xc_vmx_build(int xc_handle,
                   u32 domid,
                   int memsize,
                   const char *image_name,
                   struct mem_map *mem_mapp,
                   const char *ramdisk_name,
                   const char *cmdline,
                   unsigned int control_evtchn,
                   unsigned long flags)
{
    dom0_op_t launch_op, op;
    int initrd_fd = -1;
    gzFile initrd_gfd = NULL;
    int rc, i;
    full_execution_context_t st_ctxt, *ctxt = &st_ctxt;
    unsigned long nr_pages;
    char         *image = NULL;
    unsigned long image_size, initrd_size=0;

    if ( vmx_identify() < 0 )
    {
        PERROR("CPU doesn't support VMX Extensions");
        goto error_out;
    }
    
    if ( (nr_pages = xc_get_tot_pages(xc_handle, domid)) < 0 )
    {
        PERROR("Could not find total pages for domain");
        goto error_out;
    }

    if ( (image = xc_read_kernel_image(image_name, &image_size)) == NULL )
        goto error_out;

    if ( (ramdisk_name != NULL) && (strlen(ramdisk_name) != 0) )
    {
        if ( (initrd_fd = open(ramdisk_name, O_RDONLY)) < 0 )
        {
            PERROR("Could not open the initial ramdisk image");
            goto error_out;
        }

        initrd_size = xc_get_filesz(initrd_fd);

        if ( (initrd_gfd = gzdopen(initrd_fd, "rb")) == NULL )
        {
            PERROR("Could not allocate decompression state for initrd");
            goto error_out;
        }
    }

    if ( mlock(&st_ctxt, sizeof(st_ctxt) ) )
    {   
        PERROR("Unable to mlock ctxt");
        return 1;
    }

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    op.u.getdomaininfo.exec_domain = 0;
    op.u.getdomaininfo.ctxt = ctxt;
    if ( (do_dom0_op(xc_handle, &op) < 0) || 
         ((u16)op.u.getdomaininfo.domain != domid) )
    {
        PERROR("Could not get info on domain");
        goto error_out;
    }
    if ( !(op.u.getdomaininfo.flags & DOMFLAGS_PAUSED) ||
         (ctxt->pt_base != 0) )
    {
        ERROR("Domain is already constructed");
        goto error_out;
    }

    if ( setup_guest(xc_handle, domid, memsize, image, image_size, 
                       initrd_gfd, initrd_size, nr_pages, 
                       ctxt, cmdline,
                       op.u.getdomaininfo.shared_info_frame,
                       control_evtchn, flags, mem_mapp) < 0 )
    {
        ERROR("Error constructing guest OS");
        goto error_out;
    }

    if ( initrd_fd >= 0 )
        close(initrd_fd);
    if ( initrd_gfd )
        gzclose(initrd_gfd);
    if ( image != NULL )
        free(image);

    ctxt->flags = ECF_VMX_GUEST;
    /* FPU is set up to default initial state. */
    memset(ctxt->fpu_ctxt, 0, sizeof(ctxt->fpu_ctxt));

    /* Virtual IDT is empty at start-of-day. */
    for ( i = 0; i < 256; i++ )
    {
        ctxt->trap_ctxt[i].vector = i;
        ctxt->trap_ctxt[i].cs     = FLAT_KERNEL_CS;
    }

#if defined(__i386__)
    ctxt->fast_trap_idx = 0;
#endif

    /* No LDT. */
    ctxt->ldt_ents = 0;
    
    /* Use the default Xen-provided GDT. */
    ctxt->gdt_ents = 0;

    /* Ring 1 stack is the initial stack. */
/*
    ctxt->kernel_ss  = FLAT_KERNEL_DS;
    ctxt->kernel_esp = vstartinfo_start;
*/
    /* No debugging. */
    memset(ctxt->debugreg, 0, sizeof(ctxt->debugreg));

    /* No callback handlers. */
    ctxt->event_callback_cs     = FLAT_KERNEL_CS;
    ctxt->event_callback_eip    = 0;
    ctxt->failsafe_callback_cs  = FLAT_KERNEL_CS;
    ctxt->failsafe_callback_eip = 0;

    memset( &launch_op, 0, sizeof(launch_op) );

    launch_op.u.setdomaininfo.domain   = (domid_t)domid;
    launch_op.u.setdomaininfo.exec_domain = 0;
    launch_op.u.setdomaininfo.ctxt = ctxt;

    launch_op.cmd = DOM0_SETDOMAININFO;
    rc = do_dom0_op(xc_handle, &launch_op);
    return rc;

 error_out:
    if ( initrd_gfd != NULL )
        gzclose(initrd_gfd);
    else if ( initrd_fd >= 0 )
        close(initrd_fd);
    if ( image != NULL )
        free(image);

    return -1;
}

static inline int is_loadable_phdr(Elf_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

static int parseelfimage(char *elfbase, 
                         unsigned long elfsize,
                         struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase;
    Elf_Phdr *phdr;
    Elf_Shdr *shdr;
    unsigned long kernstart = ~0UL, kernend=0UL;
    char *shstrtab;
    int h;

    if ( !IS_ELF(*ehdr) )
    {
        ERROR("Kernel image does not have an ELF header.");
        return -EINVAL;
    }

    if ( (ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize)) > elfsize )
    {
        ERROR("ELF program headers extend beyond end of image.");
        return -EINVAL;
    }

    if ( (ehdr->e_shoff + (ehdr->e_shnum * ehdr->e_shentsize)) > elfsize )
    {
        ERROR("ELF section headers extend beyond end of image.");
        return -EINVAL;
    }

    /* Find the section-header strings table. */
    if ( ehdr->e_shstrndx == SHN_UNDEF )
    {
        ERROR("ELF image has no section-header strings table (shstrtab).");
        return -EINVAL;
    }
    shdr = (Elf_Shdr *)(elfbase + ehdr->e_shoff + 
                        (ehdr->e_shstrndx*ehdr->e_shentsize));
    shstrtab = elfbase + shdr->sh_offset;
    
    for ( h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        if ( phdr->p_paddr < kernstart )
            kernstart = phdr->p_paddr;
        if ( (phdr->p_paddr + phdr->p_memsz) > kernend )
            kernend = phdr->p_paddr + phdr->p_memsz;
    }

    if ( (kernstart > kernend) || 
         (ehdr->e_entry < kernstart) || 
         (ehdr->e_entry > kernend) )
    {
        ERROR("Malformed ELF image.");
        return -EINVAL;
    }

    dsi->v_start = 0x00000000;
    dsi->use_writable_pagetables = 0;
    dsi->load_bsd_symtab = 0;

    dsi->v_kernstart = kernstart - LINUX_PAGE_OFFSET;
    dsi->v_kernend   = kernend - LINUX_PAGE_OFFSET;
    dsi->v_kernentry = LINUX_KERNEL_ENTR_ADDR;

    dsi->v_end       = dsi->v_kernend;

    return 0;
}

static int
loadelfimage(
    char *elfbase, int xch, u32 dom, unsigned long *parray,
    unsigned long vstart)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase;
    Elf_Phdr *phdr;
    int h;

    char         *va;
    unsigned long pa, done, chunksz;

    for ( h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        
        for ( done = 0; done < phdr->p_filesz; done += chunksz )
        {
            pa = (phdr->p_paddr + done) - vstart - LINUX_PAGE_OFFSET;
            if ((va = xc_map_foreign_range(
			xch, dom, PAGE_SIZE, PROT_WRITE,
			parray[pa>>PAGE_SHIFT])) == 0)
		return -1;
            chunksz = phdr->p_filesz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memcpy(va + (pa & (PAGE_SIZE-1)),
                   elfbase + phdr->p_offset + done, chunksz);
            munmap(va, PAGE_SIZE);
        }

        for ( ; done < phdr->p_memsz; done += chunksz )
        {
            pa = (phdr->p_paddr + done) - vstart - LINUX_PAGE_OFFSET;
            if ((va = xc_map_foreign_range(
			xch, dom, PAGE_SIZE, PROT_WRITE,
			parray[pa>>PAGE_SHIFT])) == 0)
		return -1;
            chunksz = phdr->p_memsz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memset(va + (pa & (PAGE_SIZE-1)), 0, chunksz);
            munmap(va, PAGE_SIZE);
        }
    }

    return 0;
}


#define ELFROUND (ELFSIZE / 8)

static int
loadelfsymtab(
    char *elfbase, int xch, u32 dom, unsigned long *parray,
    struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase, *sym_ehdr;
    Elf_Shdr *shdr;
    unsigned long maxva, symva;
    char *p;
    int h, i;

    p = malloc(sizeof(int) + sizeof(Elf_Ehdr) +
               ehdr->e_shnum * sizeof(Elf_Shdr));
    if (p == NULL)
        return 0;

    maxva = (dsi->v_kernend + ELFROUND - 1) & ~(ELFROUND - 1);
    symva = maxva;
    maxva += sizeof(int);
    dsi->symtab_addr = maxva;
    dsi->symtab_len = 0;
    maxva += sizeof(Elf_Ehdr) + ehdr->e_shnum * sizeof(Elf_Shdr);
    maxva = (maxva + ELFROUND - 1) & ~(ELFROUND - 1);

    shdr = (Elf_Shdr *)(p + sizeof(int) + sizeof(Elf_Ehdr));
    memcpy(shdr, elfbase + ehdr->e_shoff, ehdr->e_shnum * sizeof(Elf_Shdr));

    for ( h = 0; h < ehdr->e_shnum; h++ ) 
    {
        if ( shdr[h].sh_type == SHT_STRTAB )
        {
            /* Look for a strtab @i linked to symtab @h. */
            for ( i = 0; i < ehdr->e_shnum; i++ )
                if ( (shdr[i].sh_type == SHT_SYMTAB) &&
                     (shdr[i].sh_link == h) )
                    break;
            /* Skip symtab @h if we found no corresponding strtab @i. */
            if ( i == ehdr->e_shnum )
            {
                shdr[h].sh_offset = 0;
                continue;
            }
        }

        if ( (shdr[h].sh_type == SHT_STRTAB) ||
             (shdr[h].sh_type == SHT_SYMTAB) )
        {
            if ( parray != NULL )
                xc_map_memcpy(maxva, elfbase + shdr[h].sh_offset, shdr[h].sh_size,
                           xch, dom, parray, dsi->v_start);

            /* Mangled to be based on ELF header location. */
            shdr[h].sh_offset = maxva - dsi->symtab_addr;

            dsi->symtab_len += shdr[h].sh_size;
            maxva += shdr[h].sh_size;
            maxva = (maxva + ELFROUND - 1) & ~(ELFROUND - 1);
        }

        shdr[h].sh_name = 0;  /* Name is NULL. */
    }

    if ( dsi->symtab_len == 0 )
    {
        dsi->symtab_addr = 0;
        goto out;
    }

    if ( parray != NULL )
    {
        *(int *)p = maxva - dsi->symtab_addr;
        sym_ehdr = (Elf_Ehdr *)(p + sizeof(int));
        memcpy(sym_ehdr, ehdr, sizeof(Elf_Ehdr));
        sym_ehdr->e_phoff = 0;
        sym_ehdr->e_shoff = sizeof(Elf_Ehdr);
        sym_ehdr->e_phentsize = 0;
        sym_ehdr->e_phnum = 0;
        sym_ehdr->e_shstrndx = SHN_UNDEF;

        /* Copy total length, crafted ELF header and section header table */
        xc_map_memcpy(symva, p, sizeof(int) + sizeof(Elf_Ehdr) +
                   ehdr->e_shnum * sizeof(Elf_Shdr), xch, dom, parray,
                   dsi->v_start);
    }

    dsi->symtab_len = maxva - dsi->symtab_addr;
    dsi->v_end = round_pgup(maxva);

 out:
    if ( p != NULL )
        free(p);

    return 0;
}
