/******************************************************************************
 * xc_linux_build.c
 */

#include "xc_private.h"
#define ELFSIZE 32
#include "xc_elf.h"
#include <stdlib.h>
#include <zlib.h>

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

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

static int setup_guestos(int xc_handle,
                         u32 dom,
                         char *image, unsigned long image_size,
                         gzFile initrd_gfd, unsigned long initrd_len,
                         unsigned long nr_pages,
                         unsigned long *pvsi, unsigned long *pvke,
                         full_execution_context_t *ctxt,
                         const char *cmdline,
                         unsigned long shared_info_frame,
                         unsigned int control_evtchn,
                         unsigned long flags)
{
    l1_pgentry_t *vl1tab=NULL, *vl1e=NULL;
    l2_pgentry_t *vl2tab=NULL, *vl2e=NULL;
    unsigned long *page_array = NULL;
    unsigned long l2tab;
    unsigned long l1tab;
    unsigned long count, i;
    start_info_t *start_info;
    shared_info_t *shared_info;
    mmu_t *mmu = NULL;
    int rc;

    unsigned long nr_pt_pages;
    unsigned long ppt_alloc;
    unsigned long *physmap, *physmap_e, physmap_pfn;

    struct domain_setup_info dsi;
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

    char *n_vcpus;

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
    vinitrd_start    = round_pgup(dsi.v_end);
    vinitrd_end      = vinitrd_start + initrd_len;
    vphysmap_start   = round_pgup(vinitrd_end);
    vphysmap_end     = vphysmap_start + (nr_pages * sizeof(unsigned long));
    vpt_start        = round_pgup(vphysmap_end);
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstartinfo_start = vpt_end;
        vstartinfo_end   = vstartinfo_start + PAGE_SIZE;
        vstack_start     = vstartinfo_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1<<22)-1) & ~((1<<22)-1);
        if ( (v_end - vstack_end) < (512 << 10) )
            v_end += 1 << 22; /* Add extra 4MB to get >= 512kB padding. */
        if ( (((v_end - dsi.v_start + ((1<<L2_PAGETABLE_SHIFT)-1)) >> 
               L2_PAGETABLE_SHIFT) + 1) <= nr_pt_pages )
            break;
    }

    printf("VIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded kernel: %08lx->%08lx\n"
           " Init. ramdisk: %08lx->%08lx\n"
           " Phys-Mach map: %08lx->%08lx\n"
           " Page tables:   %08lx->%08lx\n"
           " Start info:    %08lx->%08lx\n"
           " Boot stack:    %08lx->%08lx\n"
           " TOTAL:         %08lx->%08lx\n",
           dsi.v_kernstart, dsi.v_kernend, 
           vinitrd_start, vinitrd_end,
           vphysmap_start, vphysmap_end,
           vpt_start, vpt_end,
           vstartinfo_start, vstartinfo_end,
           vstack_start, vstack_end,
           dsi.v_start, v_end);
    printf(" ENTRY ADDRESS: %08lx\n", dsi.v_kernentry);

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
        if ( (count >= ((vpt_start-dsi.v_start)>>PAGE_SHIFT)) && 
             (count <  ((vpt_end  -dsi.v_start)>>PAGE_SHIFT)) )
            *vl1e &= ~_PAGE_RW;
        vl1e++;
    }
    munmap(vl1tab, PAGE_SIZE);
    munmap(vl2tab, PAGE_SIZE);

    /* Write the phys->machine and machine->phys table entries. */
    physmap_pfn = (vphysmap_start - dsi.v_start) >> PAGE_SHIFT;
    physmap = physmap_e = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
        page_array[physmap_pfn++]);
    for ( count = 0; count < nr_pages; count++ )
    {
        if ( add_mmu_update(xc_handle, mmu,
                            (page_array[count] << PAGE_SHIFT) | 
                            MMU_MACHPHYS_UPDATE, count) )
        {
            munmap(physmap, PAGE_SIZE);
            goto error_out;
        }
        *physmap_e++ = page_array[count];
        if ( ((unsigned long)physmap_e & (PAGE_SIZE-1)) == 0 )
        {
            munmap(physmap, PAGE_SIZE);
            physmap = physmap_e = xc_map_foreign_range(
                xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
                page_array[physmap_pfn++]);
        }
    }
    munmap(physmap, PAGE_SIZE);
    
    /*
     * Pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */ 
    if ( add_mmu_update(xc_handle, mmu,
                        l2tab | MMU_EXTENDED_COMMAND, MMUEXT_PIN_L2_TABLE) )
        goto error_out;

    start_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
        page_array[(vstartinfo_start-dsi.v_start)>>PAGE_SHIFT]);
    memset(start_info, 0, sizeof(*start_info));
    start_info->nr_pages     = nr_pages;
    start_info->shared_info  = shared_info_frame << PAGE_SHIFT;
    start_info->flags        = flags;
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
    munmap(start_info, PAGE_SIZE);

    /* shared_info page starts its life empty. */
    shared_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE, shared_info_frame);
    memset(shared_info, 0, sizeof(shared_info_t));
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_data[i].evtchn_upcall_mask = 1;
    n_vcpus = getenv("XEN_VCPUS");
    if ( n_vcpus )
	shared_info->n_vcpu = atoi(n_vcpus);
    else
	shared_info->n_vcpu = 1;
    munmap(shared_info, PAGE_SIZE);

    /* Send the page update requests down to the hypervisor. */
    if ( finish_mmu_updates(xc_handle, mmu) )
        goto error_out;

    free(mmu);
    free(page_array);

    *pvsi = vstartinfo_start;
    *pvke = dsi.v_kernentry;

    return 0;

 error_out:
    if ( mmu != NULL )
        free(mmu);
    if ( page_array != NULL )
        free(page_array);
    return -1;
}

int xc_linux_build(int xc_handle,
                   u32 domid,
                   const char *image_name,
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
    unsigned long vstartinfo_start, vkern_entry;

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

    if ( setup_guestos(xc_handle, domid, image, image_size, 
                       initrd_gfd, initrd_size, nr_pages, 
                       &vstartinfo_start, &vkern_entry,
                       ctxt, cmdline,
                       op.u.getdomaininfo.shared_info_frame,
                       control_evtchn, flags) < 0 )
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
    ctxt->cpu_ctxt.esp = vstartinfo_start + 2*PAGE_SIZE;
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
    ctxt->guestos_esp = vstartinfo_start + 2*PAGE_SIZE;

    /* No debugging. */
    memset(ctxt->debugreg, 0, sizeof(ctxt->debugreg));

    /* No callback handlers. */
    ctxt->event_callback_cs     = FLAT_GUESTOS_CS;
    ctxt->event_callback_eip    = 0;
    ctxt->failsafe_callback_cs  = FLAT_GUESTOS_CS;
    ctxt->failsafe_callback_eip = 0;

    memset( &launch_op, 0, sizeof(launch_op) );

    launch_op.u.builddomain.domain   = (domid_t)domid;
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

static int parseelfimage(char *elfbase, 
                         unsigned long elfsize,
                         struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase;
    Elf_Phdr *phdr;
    Elf_Shdr *shdr;
    unsigned long kernstart = ~0UL, kernend=0UL;
    char *shstrtab, *guestinfo=NULL, *p;
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

        if ( (strstr(guestinfo, "LOADER=generic") == NULL) &&
             (strstr(guestinfo, "GUEST_OS=linux") == NULL) )
        {
            ERROR("Will only load images built for the generic loader "
                  "or Linux images");
            ERROR("Actually saw: '%s'", guestinfo);
            return -EINVAL;
        }

        if ( (strstr(guestinfo, "XEN_VER=2.0") == NULL) )
        {
            ERROR("Will only load images built for Xen v2.0");
            ERROR("Actually saw: '%s'", guestinfo);
            return -EINVAL;
        }

        break;
    }
    if ( guestinfo == NULL )
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

    dsi->v_start = kernstart;
    if ( (p = strstr(guestinfo, "VIRT_BASE=")) != NULL )
        dsi->v_start = strtoul(p+10, &p, 0);

    if ( (p = strstr(guestinfo, "PT_MODE_WRITABLE")) != NULL )
        dsi->use_writable_pagetables = 1;

    if ( (p = strstr(guestinfo, "BSD_SYMTAB")) != NULL )
        dsi->load_bsd_symtab = 1;

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_kernentry = ehdr->e_entry;

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
            pa = (phdr->p_vaddr + done) - vstart;
            va = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_WRITE, parray[pa>>PAGE_SHIFT]);
            chunksz = phdr->p_filesz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memcpy(va + (pa & (PAGE_SIZE-1)),
                   elfbase + phdr->p_offset + done, chunksz);
            munmap(va, PAGE_SIZE);
        }

        for ( ; done < phdr->p_memsz; done += chunksz )
        {
            pa = (phdr->p_vaddr + done) - vstart;
            va = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_WRITE, parray[pa>>PAGE_SHIFT]);
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
