/******************************************************************************
 * xc_linux_build.c
 */

#include "xc_private.h"
#define ELFSIZE 32
#include "xc_elf.h"
#include <zlib.h>

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static int readelfimage_base_and_size(char *elfbase, 
                                      unsigned long elfsize,
                                      unsigned long *pkernstart,
                                      unsigned long *pkernend,
                                      unsigned long *pkernentry);
static int loadelfimage(char *elfbase, int pmh, unsigned long *parray,
                        unsigned long vstart);

static long get_tot_pages(int xc_handle, u64 domid)
{
    dom0_op_t op;
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    op.u.getdomaininfo.ctxt = NULL;
    return (do_dom0_op(xc_handle, &op) < 0) ? 
        -1 : op.u.getdomaininfo.tot_pages;
}

static int get_pfn_list(int xc_handle,
                        u64 domid, 
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
        return -1;

    ret = do_dom0_op(xc_handle, &op);

    (void)munlock(pfn_buf, max_pfns * sizeof(unsigned long));

    return (ret < 0) ? -1 : op.u.getmemlist.num_pfns;
}

static int copy_to_domain_page(int pm_handle,
                               unsigned long dst_pfn, 
                               void *src_page)
{
    void *vaddr = map_pfn_writeable(pm_handle, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memcpy(vaddr, src_page, PAGE_SIZE);
    unmap_pfn(pm_handle, vaddr);
    return 0;
}

static int setup_guestos(int xc_handle,
                         u64 dom,
                         char *image, unsigned long image_size,
                         gzFile initrd_gfd, unsigned long initrd_len,
                         unsigned long nr_pages,
                         unsigned long *pvsi, unsigned long *pvke,
			 full_execution_context_t *ctxt,
                         const char *cmdline,
                         unsigned long shared_info_frame,
                         unsigned int control_evtchn,
                         int io_priv)
{
    l1_pgentry_t *vl1tab=NULL, *vl1e=NULL;
    l2_pgentry_t *vl2tab=NULL, *vl2e=NULL;
    unsigned long *page_array = NULL;
    unsigned long l2tab;
    unsigned long l1tab;
    unsigned long count, i;
    extended_start_info_t *start_info;
    shared_info_t *shared_info;
    mmu_t *mmu = NULL;
    int pm_handle=-1, rc;

    unsigned long nr_pt_pages;
    unsigned long ppt_alloc;
    unsigned long *physmap, *physmap_e, physmap_pfn;

    unsigned long v_start;
    unsigned long vkern_start;
    unsigned long vkern_entry;
    unsigned long vkern_end;
    unsigned long vinitrd_start;
    unsigned long vinitrd_end;
    unsigned long vphysmap_start;
    unsigned long vphysmap_end;
    unsigned long vstartinfo_start;
    unsigned long vstartinfo_end;
    unsigned long vstack_start;
    unsigned long vstack_end;
    unsigned long vpt_start;
    unsigned long vpt_end;
    unsigned long v_end;

    rc = readelfimage_base_and_size(image, image_size, 
                                    &vkern_start, &vkern_end, &vkern_entry);
    if ( rc != 0 )
        goto error_out;
    
    /*
     * Why do we need this? The number of page-table frames depends on the 
     * size of the bootstrap address space. But the size of the address space 
     * depends on the number of page-table frames (since each one is mapped 
     * read-only). We have a pair of simultaneous equations in two unknowns, 
     * which we solve by exhaustive search.
     */
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        v_start          = vkern_start & ~((1<<22)-1);
        vinitrd_start    = round_pgup(vkern_end);
        vinitrd_end      = vinitrd_start + initrd_len;
        vphysmap_start   = round_pgup(vinitrd_end);
        vphysmap_end     = vphysmap_start + (nr_pages * sizeof(unsigned long));
        vpt_start        = round_pgup(vphysmap_end);
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstartinfo_start = vpt_end;
        vstartinfo_end   = vstartinfo_start + PAGE_SIZE;
        vstack_start     = vstartinfo_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1<<22)-1) & ~((1<<22)-1);
        if ( (v_end - vstack_end) < (512 << 10) )
            v_end += 1 << 22; /* Add extra 4MB to get >= 512kB padding. */
        if ( (((v_end - v_start) >> L2_PAGETABLE_SHIFT) + 1) <= nr_pt_pages )
            break;
    }

    if ( (v_end - v_start) > (nr_pages * PAGE_SIZE) )
    {
        printf("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-v_start)>>20, (nr_pages<<PAGE_SHIFT)>>20);
        goto error_out;
    }

    printf("VIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded kernel: %08lx->%08lx\n"
           " Init. ramdisk: %08lx->%08lx\n"
           " Phys-Mach map: %08lx->%08lx\n"
           " Page tables:   %08lx->%08lx\n"
           " Start info:    %08lx->%08lx\n"
           " Boot stack:    %08lx->%08lx\n"
           " TOTAL:         %08lx->%08lx\n",
           vkern_start, vkern_end, 
           vinitrd_start, vinitrd_end,
           vphysmap_start, vphysmap_end,
           vpt_start, vpt_end,
           vstartinfo_start, vstartinfo_end,
           vstack_start, vstack_end,
           v_start, v_end);
    printf(" ENTRY ADDRESS: %08lx\n", vkern_entry);

    if ( (pm_handle = init_pfn_mapper((domid_t)dom)) < 0 )
        goto error_out;

    if ( (page_array = malloc(nr_pages * sizeof(unsigned long))) == NULL )
    {
        PERROR("Could not allocate memory");
        goto error_out;
    }

    if ( get_pfn_list(xc_handle, dom, page_array, nr_pages) != nr_pages )
    {
        PERROR("Could not get the page frame list");
        goto error_out;
    }

    loadelfimage(image, pm_handle, page_array, v_start);

    /* Load the initial ramdisk image. */
    if ( initrd_len != 0 )
    {
        for ( i = (vinitrd_start - v_start); 
              i < (vinitrd_end - v_start); i += PAGE_SIZE )
        {
            char page[PAGE_SIZE];
            if ( gzread(initrd_gfd, page, PAGE_SIZE) == -1 )
            {
                PERROR("Error reading initrd image, could not");
                goto error_out;
            }
            copy_to_domain_page(pm_handle, 
                                page_array[i>>PAGE_SHIFT], page);
        }
    }

    if ( (mmu = init_mmu_updates(xc_handle, dom)) == NULL )
        goto error_out;

    /* First allocate page for page dir. */
    ppt_alloc = (vpt_start - v_start) >> PAGE_SHIFT;
    l2tab = page_array[ppt_alloc++] << PAGE_SHIFT;
    ctxt->pt_base = l2tab;

    /* Initialise the page tables. */
    if ( (vl2tab = map_pfn_writeable(pm_handle, l2tab >> PAGE_SHIFT)) == NULL )
        goto error_out;
    memset(vl2tab, 0, PAGE_SIZE);
    vl2e = &vl2tab[l2_table_offset(v_start)];
    for ( count = 0; count < ((v_end-v_start)>>PAGE_SHIFT); count++ )
    {    
        if ( ((unsigned long)vl1e & (PAGE_SIZE-1)) == 0 )
        {
            l1tab = page_array[ppt_alloc++] << PAGE_SHIFT;
            if ( vl1tab != NULL )
                unmap_pfn(pm_handle, vl1tab);
            if ( (vl1tab = map_pfn_writeable(pm_handle, 
                                             l1tab >> PAGE_SHIFT)) == NULL )
                goto error_out;
            memset(vl1tab, 0, PAGE_SIZE);
            vl1e = &vl1tab[l1_table_offset(v_start + (count<<PAGE_SHIFT))];
            *vl2e++ = l1tab | L2_PROT;
        }

        *vl1e = (page_array[count] << PAGE_SHIFT) | L1_PROT;
        if ( (count >= ((vpt_start-v_start)>>PAGE_SHIFT)) && 
             (count <  ((vpt_end  -v_start)>>PAGE_SHIFT)) )
            *vl1e &= ~_PAGE_RW;
        vl1e++;
    }
    unmap_pfn(pm_handle, vl1tab);
    unmap_pfn(pm_handle, vl2tab);

    /* Write the phys->machine and machine->phys table entries. */
    physmap_pfn = (vphysmap_start - v_start) >> PAGE_SHIFT;
    physmap = physmap_e = 
        map_pfn_writeable(pm_handle, page_array[physmap_pfn++]);
    for ( count = 0; count < nr_pages; count++ )
    {
        if ( add_mmu_update(xc_handle, mmu,
                            (page_array[count] << PAGE_SHIFT) | 
                            MMU_MACHPHYS_UPDATE, count) )
            goto error_out;
        *physmap_e++ = page_array[count];
        if ( ((unsigned long)physmap_e & (PAGE_SIZE-1)) == 0 )
        {
            unmap_pfn(pm_handle, physmap);
            physmap = physmap_e = 
                map_pfn_writeable(pm_handle, page_array[physmap_pfn++]);
        }
    }
    unmap_pfn(pm_handle, physmap);
    
    /*
     * Pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */ 
    if ( add_mmu_update(xc_handle, mmu,
                        l2tab | MMU_EXTENDED_COMMAND, MMUEXT_PIN_L2_TABLE) )
        goto error_out;

    start_info = map_pfn_writeable(
        pm_handle, page_array[(vstartinfo_start-v_start)>>PAGE_SHIFT]);
    memset(start_info, 0, sizeof(*start_info));
    start_info->nr_pages     = nr_pages;
    start_info->shared_info  = shared_info_frame << PAGE_SHIFT;
    start_info->flags        = io_priv ? SIF_PRIVILEGED : 0;
    start_info->pt_base      = vpt_start;
    start_info->nr_pt_frames = nr_pt_pages;
    start_info->mfn_list     = vphysmap_start;
    start_info->domain_controller_evtchn = control_evtchn;
    if ( initrd_len != 0 )
    {
        start_info->mod_start    = vinitrd_start;
        start_info->mod_len      = initrd_len;
    }
    strncpy(start_info->cmd_line, cmdline, MAX_CMDLINE);
    start_info->cmd_line[MAX_CMDLINE-1] = '\0';
    unmap_pfn(pm_handle, start_info);

    /* shared_info page starts its life empty. */
    shared_info = map_pfn_writeable(pm_handle, shared_info_frame);
    memset(shared_info, 0, PAGE_SIZE);
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_data[i].evtchn_upcall_mask = 1;
    unmap_pfn(pm_handle, shared_info);

    /* Send the page update requests down to the hypervisor. */
    if ( finish_mmu_updates(xc_handle, mmu) )
        goto error_out;

    free(mmu);
    (void)close_pfn_mapper(pm_handle);
    free(page_array);

    *pvsi = vstartinfo_start;
    *pvke = vkern_entry;

    return 0;

 error_out:
    if ( mmu != NULL )
        free(mmu);
    if ( pm_handle >= 0 )
        (void)close_pfn_mapper(pm_handle);
    if ( page_array != NULL )
        free(page_array);
    return -1;
}

static unsigned long get_filesz(int fd)
{
    u16 sig;
    u32 _sz = 0;
    unsigned long sz;

    lseek(fd, 0, SEEK_SET);
    read(fd, &sig, sizeof(sig));
    sz = lseek(fd, 0, SEEK_END);
    if ( sig == 0x8b1f ) /* GZIP signature? */
    {
        lseek(fd, -4, SEEK_END);
        read(fd, &_sz, 4);
        sz = _sz;
    }
    lseek(fd, 0, SEEK_SET);

    return sz;
}

static char *read_kernel_image(const char *filename, unsigned long *size)
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

    *size = get_filesz(kernel_fd);

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

int xc_linux_build(int xc_handle,
                   u64 domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   unsigned int control_evtchn,
                   int io_priv)
{
    dom0_op_t launch_op, op;
    int initrd_fd = -1;
    gzFile initrd_gfd = NULL;
    int rc, i;
    full_execution_context_t st_ctxt, *ctxt = &st_ctxt;
    unsigned long nr_pages;
    char         *image = NULL;
    unsigned long image_size, initrd_size=0;
    unsigned long vstartinfo_start, vkern_entry;

    if ( (nr_pages = get_tot_pages(xc_handle, domid)) < 0 )
    {
        PERROR("Could not find total pages for domain");
        goto error_out;
    }

    if ( (image = read_kernel_image(image_name, &image_size)) == NULL )
        goto error_out;

    if ( (ramdisk_name != NULL) && (strlen(ramdisk_name) != 0) )
    {
        if ( (initrd_fd = open(ramdisk_name, O_RDONLY)) < 0 )
        {
            PERROR("Could not open the initial ramdisk image");
            goto error_out;
        }

        initrd_size = get_filesz(initrd_fd);

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
    op.u.getdomaininfo.ctxt = ctxt;
    if ( (do_dom0_op(xc_handle, &op) < 0) || 
         ((u64)op.u.getdomaininfo.domain != domid) )
    {
        PERROR("Could not get info on domain");
        goto error_out;
    }
    if ( (op.u.getdomaininfo.state != DOMSTATE_STOPPED) ||
         (ctxt->pt_base != 0) )
    {
        ERROR("Domain is already constructed");
        goto error_out;
    }

    if ( setup_guestos(xc_handle, domid, image, image_size, 
                       initrd_gfd, initrd_size, nr_pages, 
                       &vstartinfo_start, &vkern_entry,
                       ctxt, cmdline,
                       op.u.getdomaininfo.shared_info_frame,
                       control_evtchn, io_priv) < 0 )
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

    ctxt->flags = 0;

    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_GUESTOS_DS
     *       CS:EIP = FLAT_GUESTOS_CS:start_pc
     *       SS:ESP = FLAT_GUESTOS_DS:start_stack
     *          ESI = start_info
     *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
     *       EFLAGS = IF | 2 (bit 1 is reserved and should always be 1)
     */
    ctxt->cpu_ctxt.ds = FLAT_GUESTOS_DS;
    ctxt->cpu_ctxt.es = FLAT_GUESTOS_DS;
    ctxt->cpu_ctxt.fs = FLAT_GUESTOS_DS;
    ctxt->cpu_ctxt.gs = FLAT_GUESTOS_DS;
    ctxt->cpu_ctxt.ss = FLAT_GUESTOS_DS;
    ctxt->cpu_ctxt.cs = FLAT_GUESTOS_CS;
    ctxt->cpu_ctxt.eip = vkern_entry;
    ctxt->cpu_ctxt.esp = vstartinfo_start;
    ctxt->cpu_ctxt.esi = vstartinfo_start;
    ctxt->cpu_ctxt.eflags = (1<<9) | (1<<2);

    /* FPU is set up to default initial state. */
    memset(ctxt->fpu_ctxt, 0, sizeof(ctxt->fpu_ctxt));

    /* Virtual IDT is empty at start-of-day. */
    for ( i = 0; i < 256; i++ )
    {
        ctxt->trap_ctxt[i].vector = i;
        ctxt->trap_ctxt[i].cs     = FLAT_GUESTOS_CS;
    }
    ctxt->fast_trap_idx = 0;

    /* No LDT. */
    ctxt->ldt_ents = 0;
    
    /* Use the default Xen-provided GDT. */
    ctxt->gdt_ents = 0;

    /* Ring 1 stack is the initial stack. */
    ctxt->guestos_ss  = FLAT_GUESTOS_DS;
    ctxt->guestos_esp = vstartinfo_start;

    /* No debugging. */
    memset(ctxt->debugreg, 0, sizeof(ctxt->debugreg));

    /* No callback handlers. */
    ctxt->event_callback_cs     = FLAT_GUESTOS_CS;
    ctxt->event_callback_eip    = 0;
    ctxt->failsafe_callback_cs  = FLAT_GUESTOS_CS;
    ctxt->failsafe_callback_eip = 0;

    memset( &launch_op, 0, sizeof(launch_op) );

    launch_op.u.builddomain.domain   = (domid_t)domid;
    launch_op.u.builddomain.num_vifs = 1;
    launch_op.u.builddomain.ctxt = ctxt;

    launch_op.cmd = DOM0_BUILDDOMAIN;
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

static int readelfimage_base_and_size(char *elfbase, 
                                      unsigned long elfsize,
                                      unsigned long *pkernstart,
                                      unsigned long *pkernend,
                                      unsigned long *pkernentry)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase;
    Elf_Phdr *phdr;
    Elf_Shdr *shdr;
    unsigned long kernstart = ~0UL, kernend=0UL;
    char *shstrtab, *guestinfo;
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
    
    /* Find the special '__xen_guest' section and check its contents. */
    for ( h = 0; h < ehdr->e_shnum; h++ )
    {
        shdr = (Elf_Shdr *)(elfbase + ehdr->e_shoff + (h*ehdr->e_shentsize));
        if ( strcmp(&shstrtab[shdr->sh_name], "__xen_guest") != 0 )
            continue;
        guestinfo = elfbase + shdr->sh_offset;
        if ( (strstr(guestinfo, "GUEST_OS=linux") == NULL) ||
             (strstr(guestinfo, "XEN_VER=1.3") == NULL) )
        {
            ERROR("Will only load Linux images built for Xen v1.3");
            ERROR("Actually saw: '%s'", guestinfo);
            return -EINVAL;
        }
        break;
    }
    if ( h == ehdr->e_shnum )
    {
        ERROR("Not a Xen-ELF image: '__xen_guest' section not found.");
        return -EINVAL;
    }

    for ( h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        if ( phdr->p_vaddr < kernstart )
            kernstart = phdr->p_vaddr;
        if ( (phdr->p_vaddr + phdr->p_memsz) > kernend )
            kernend = phdr->p_vaddr + phdr->p_memsz;
    }

    if ( (kernstart > kernend) || 
         (ehdr->e_entry < kernstart) || 
         (ehdr->e_entry > kernend) )
    {
        ERROR("Malformed ELF image.");
        return -EINVAL;
    }

    *pkernstart = kernstart;
    *pkernend   = kernend;
    *pkernentry = ehdr->e_entry;

    return 0;
}

static int loadelfimage(char *elfbase, int pmh, unsigned long *parray,
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
            pa = (phdr->p_vaddr + done) - vstart;
            va = map_pfn_writeable(pmh, parray[pa>>PAGE_SHIFT]);
            va += pa & (PAGE_SIZE-1);
            chunksz = phdr->p_filesz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memcpy(va, elfbase + phdr->p_offset + done, chunksz);
            unmap_pfn(pmh, va);
        }

        for ( ; done < phdr->p_memsz; done += chunksz )
        {
            pa = (phdr->p_vaddr + done) - vstart;
            va = map_pfn_writeable(pmh, parray[pa>>PAGE_SHIFT]);
            va += pa & (PAGE_SIZE-1);
            chunksz = phdr->p_memsz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memset(va, 0, chunksz);
            unmap_pfn(pmh, va);            
        }
    }

    return 0;
}

