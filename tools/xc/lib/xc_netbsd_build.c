/******************************************************************************
 * xc_netbsd_build.c
 */

#include "xc_private.h"
#define ELFSIZE 32  /* XXX */
#include "xc_elf.h"
#include <zlib.h>

#ifdef DEBUG
#define DPRINTF(x) printf x
#else
#define DPRINTF(x)
#endif

static int loadelfimage(gzFile, int, unsigned long *, unsigned long,
                        unsigned long *, unsigned long *,
                        unsigned long *, unsigned long *);

#define ELFROUND (ELFSIZE / 8)

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

static long get_tot_pages(int xc_handle, u64 domid)
{
    dom0_op_t op;
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
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

static int setup_guestos(int xc_handle,
                         u64 dom, 
                         gzFile kernel_gfd, 
                         unsigned long tot_pages,
                         unsigned long *virt_startinfo_addr, 
                         unsigned long *virt_load_addr, 
                         dom0_builddomain_t *builddomain, 
                         const char *cmdline,
                         unsigned long shared_info_frame)
{
    l1_pgentry_t *vl1tab=NULL, *vl1e=NULL;
    l2_pgentry_t *vl2tab=NULL, *vl2e=NULL;
    unsigned long *page_array = NULL;
    mmu_update_t *pgt_update_arr = NULL, *pgt_updates = NULL;
    int alloc_index, num_pt_pages;
    unsigned long l2tab;
    unsigned long l1tab;
    unsigned long num_pgt_updates = 0;
    unsigned long count, pt_start;
    unsigned long symtab_addr = 0, symtab_len = 0;
    start_info_t *start_info;
    shared_info_t *shared_info;
    unsigned long ksize;
    int pm_handle;

    memset(builddomain, 0, sizeof(*builddomain));

    if ( (pm_handle = init_pfn_mapper()) < 0 )
        goto error_out;

    pgt_updates = malloc((tot_pages + 1) * sizeof(mmu_update_t));
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

    if (loadelfimage(kernel_gfd, pm_handle, page_array, tot_pages,
                     virt_load_addr, &ksize, &symtab_addr, &symtab_len))
        goto error_out;

    /* ksize is kernel-image size rounded up to a page boundary. */

    alloc_index = tot_pages - 1;

    /* Count bottom-level PTs, rounding up. */
    num_pt_pages = (l1_table_offset(*virt_load_addr) + tot_pages + 1023)
        / 1024;

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

    /* Initialise the page tables. */
    if ( (vl2tab = map_pfn_writeable(pm_handle, l2tab >> PAGE_SHIFT)) == NULL )
        goto error_out;
    memset(vl2tab, 0, PAGE_SIZE);
    vl2e = &vl2tab[l2_table_offset(*virt_load_addr)];
    for ( count = 0; count < tot_pages; count++ )
    {
        if ( ((unsigned long)vl1e & (PAGE_SIZE-1)) == 0 )
        {
            l1tab = page_array[alloc_index--] << PAGE_SHIFT;
            if ( vl1tab != NULL )
                unmap_pfn(pm_handle, vl1tab);
            if ( (vl1tab = map_pfn_writeable(pm_handle,
                                             l1tab >> PAGE_SHIFT)) == NULL )
                goto error_out;
            memset(vl1tab, 0, PAGE_SIZE);
            vl1e = &vl1tab[l1_table_offset(*virt_load_addr + 
                                           (count<<PAGE_SHIFT))];
            *vl2e++ = l1tab | L2_PROT;
        }

        *vl1e = (page_array[count] << PAGE_SHIFT) | L1_PROT;
        if ( count >= pt_start )
            *vl1e &= ~_PAGE_RW;
        vl1e++;

        pgt_updates->ptr = 
            (page_array[count] << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
        pgt_updates->val = count;
        pgt_updates++;
        num_pgt_updates++;
    }
    unmap_pfn(pm_handle, vl1tab);
    unmap_pfn(pm_handle, vl2tab);

    /*
     * Pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */ 
    pgt_updates->ptr = l2tab | MMU_EXTENDED_COMMAND;
    pgt_updates->val = MMUEXT_PIN_L2_TABLE;
    pgt_updates++;
    num_pgt_updates++;

    *virt_startinfo_addr =
        *virt_load_addr + ((alloc_index-1) << PAGE_SHIFT);

    start_info = map_pfn_writeable(pm_handle, page_array[alloc_index-1]);
    memset(start_info, 0, sizeof(*start_info));
    start_info->pt_base     = *virt_load_addr + ((tot_pages-1) << PAGE_SHIFT);
    start_info->mod_start   = symtab_addr;
    start_info->mod_len     = symtab_len;
    start_info->nr_pages    = tot_pages;
    start_info->shared_info = shared_info_frame << PAGE_SHIFT;
    start_info->flags       = 0;
    strncpy(start_info->cmd_line, cmdline, MAX_CMD_LEN);
    start_info->cmd_line[MAX_CMD_LEN-1] = '\0';

    unmap_pfn(pm_handle, start_info);

    /* shared_info page starts its life empty. */
    shared_info = map_pfn_writeable(pm_handle, shared_info_frame);
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

int xc_netbsd_build(int xc_handle,
                    u64 domid,
                    const char *image_name,
                    const char *cmdline)
{
    dom0_op_t launch_op, op;
    unsigned long load_addr;
    long tot_pages;
    int kernel_fd = -1;
    gzFile kernel_gfd = NULL;
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

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    if ( (do_dom0_op(xc_handle, &op) < 0) || 
         ((u64)op.u.getdomaininfo.domain != domid) )
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

    if ( setup_guestos(xc_handle, domid, kernel_gfd, tot_pages,
                       &virt_startinfo_addr,
                       &load_addr, &launch_op.u.builddomain, cmdline,
                       op.u.getdomaininfo.shared_info_frame) < 0 )
    {
        ERROR("Error constructing guest OS");
        goto error_out;
    }

    if ( kernel_fd >= 0 )
        close(kernel_fd);
    if( kernel_gfd )
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

    launch_op.u.builddomain.domain   = (domid_t)domid;
    launch_op.u.builddomain.num_vifs = 1;

    launch_op.cmd = DOM0_BUILDDOMAIN;
    rc = do_dom0_op(xc_handle, &launch_op);
    
    return rc;

 error_out:
    if ( kernel_fd >= 0 )
        close(kernel_fd);
    if( kernel_gfd )
        gzclose(kernel_gfd);

    return -1;
}

#define MYSEEK_BUFSIZE 1024
static off_t
myseek(gzFile gfd, off_t offset, int whence)
{
    unsigned char tmp[MYSEEK_BUFSIZE];
    int c;

    if ( offset < 0 )
    {
        ERROR("seek back not supported");
        return -1;
    }

    while ( offset != 0 )
    {
        c = offset;
        if ( c > MYSEEK_BUFSIZE )
            c = MYSEEK_BUFSIZE;
        if ( gzread(gfd, tmp, c) != c )
        {
            PERROR("Error seeking in image.");
            return -1;
        }
        offset -= c;
    }

    return 0;   /* XXX */
}

/* 
 * NetBSD memory layout:
 *
 * ---------------- *virt_load_addr = ehdr.e_entry (0xc0100000)
 * | kernel text  |
 * |              |
 * ----------------
 * | kernel data  |
 * |              |
 * ----------------
 * | kernel bss   |
 * |              |
 * ---------------- *symtab_addr
 * | symtab size  |   = *symtab_len
 * ----------------
 * | elf header   |   offsets to symbol sections mangled to be relative
 * |              |   to headers location
 * ----------------
 * | sym section  |
 * | headers      |
 * ----------------
 * | sym sections |
 * |              |
 * ---------------- *symtab_addr + *symtab_len
 * | padding      |
 * ---------------- ehdr.e_entry + *ksize << PAGE_SHIFT
 */

#define IS_TEXT(p) (p.p_flags & PF_X)
#define IS_DATA(p) (p.p_flags & PF_W)
#define IS_BSS(p) (p.p_filesz < p.p_memsz)

static int
loadelfimage(gzFile kernel_gfd, int pm_handle, unsigned long *page_array,
             unsigned long tot_pages, unsigned long *virt_load_addr,
             unsigned long *ksize, unsigned long *symtab_addr,
             unsigned long *symtab_len)
{
    Elf_Ehdr ehdr;
    Elf_Phdr *phdr;
    Elf_Shdr *shdr;
    void *vaddr;
    char page[PAGE_SIZE], *p;
    unsigned long iva, maxva, symva;
    int c, curpos, h, i, ret, s;

    ret = -1;
    phdr = NULL;
    p = NULL;
    maxva = 0;

    if ( gzread(kernel_gfd, &ehdr, sizeof(Elf_Ehdr)) != sizeof(Elf_Ehdr) )
    {
        PERROR("Error reading kernel image ELF header.");
        goto out;
    }
    curpos = sizeof(Elf_Ehdr);

    if ( !IS_ELF(ehdr) )
    {
        PERROR("Image does not have an ELF header.");
        goto out;
    }

    *virt_load_addr = ehdr.e_entry;

    if ( (*virt_load_addr & (PAGE_SIZE-1)) != 0 )
    {
        ERROR("We can only deal with page-aligned load addresses");
        goto out;
    }

    if ( (*virt_load_addr + (tot_pages << PAGE_SHIFT)) > 
         HYPERVISOR_VIRT_START )
    {
        ERROR("Cannot map all domain memory without hitting Xen space");
        goto out;
    }


    phdr = malloc(ehdr.e_phnum * sizeof(Elf_Phdr));
    if ( phdr == NULL )
    {
        ERROR("Cannot allocate memory for Elf_Phdrs");
        goto out;
    }

    if ( myseek(kernel_gfd, ehdr.e_phoff - curpos, SEEK_SET) == -1 )
    {
        ERROR("Seek to program header failed");
        goto out;
    }
    curpos = ehdr.e_phoff;

    if ( gzread(kernel_gfd, phdr, ehdr.e_phnum * sizeof(Elf_Phdr)) !=
         ehdr.e_phnum * sizeof(Elf_Phdr) )
    {
        PERROR("Error reading kernel image ELF program header.");
        goto out;
    }
    curpos += ehdr.e_phnum * sizeof(Elf_Phdr);

    /* Copy run-time 'load' segments that are writeable and/or executable. */
    for ( h = 0; h < ehdr.e_phnum; h++ ) 
    {
        if ( (phdr[h].p_type != PT_LOAD) ||
             ((phdr[h].p_flags & (PF_W|PF_X)) == 0) )
            continue;

        if ( IS_TEXT(phdr[h]) || IS_DATA(phdr[h]) )
        {
            if ( myseek(kernel_gfd, phdr[h].p_offset - curpos, 
                        SEEK_SET) == -1 )
            {
                ERROR("Seek to section failed");
                goto out;
            }
            curpos = phdr[h].p_offset;

            for ( iva = phdr[h].p_vaddr;
                  iva < phdr[h].p_vaddr + phdr[h].p_filesz; 
                  iva += c)
            {
                c = PAGE_SIZE - (iva & (PAGE_SIZE - 1));
                if (iva + c > phdr[h].p_vaddr + phdr[h].p_filesz)
                    c = phdr[h].p_vaddr + phdr[h].p_filesz - iva;
                if ( gzread(kernel_gfd, page, c) != c )
                {
                    PERROR("Error reading kernel image page.");
                    goto out;
                }
                curpos += c;
                vaddr = map_pfn_writeable(pm_handle, 
                                          page_array[(iva - *virt_load_addr)
                                                    >> PAGE_SHIFT]);
                if ( vaddr == NULL )
                {
                    ERROR("Couldn't map guest memory");
                    goto out;
                }
                DPRINTF(("copy page %p to %p, count 0x%x\n", (void *)iva,
                         vaddr + (iva & (PAGE_SIZE - 1)), c));
                memcpy(vaddr + (iva & (PAGE_SIZE - 1)), page, c);
                unmap_pfn(pm_handle, vaddr);
            }

            if ( phdr[h].p_vaddr + phdr[h].p_filesz > maxva )
                maxva = phdr[h].p_vaddr + phdr[h].p_filesz;
        }

        if ( IS_BSS(phdr[h]) )
        {
            /* XXX maybe clear phdr[h].p_memsz bytes from
               phdr[h].p_vaddr + phdr[h].p_filesz ??? */
            if (phdr[h].p_vaddr + phdr[h].p_memsz > maxva)
                maxva = phdr[h].p_vaddr + phdr[h].p_memsz;
            DPRINTF(("bss from %p to %p, maxva %p\n",
                     (void *)(phdr[h].p_vaddr + phdr[h].p_filesz),
                     (void *)(phdr[h].p_vaddr + phdr[h].p_memsz),
                     (void *)maxva));
        }
    }

    p = malloc(sizeof(int) + sizeof(Elf_Ehdr) +
               ehdr.e_shnum * sizeof(Elf_Shdr));
    if ( p == NULL )
    {
        ERROR("Cannot allocate memory for Elf_Shdrs");
        goto out;
    }

    shdr = (Elf_Shdr *)(p + sizeof(int) + sizeof(Elf_Ehdr));

    if ( myseek(kernel_gfd, ehdr.e_shoff - curpos, SEEK_SET) == -1 )
    {
        ERROR("Seek to symbol header failed");
        goto out;
    }
    curpos = ehdr.e_shoff;

    if ( gzread(kernel_gfd, shdr, ehdr.e_shnum * sizeof(Elf_Shdr)) !=
         ehdr.e_shnum * sizeof(Elf_Shdr) ) 
    {
        PERROR("Error reading kernel image ELF symbol header.");
        goto out;
    }
    curpos += ehdr.e_shnum * sizeof(Elf_Shdr);

    maxva = (maxva + ELFROUND - 1) & ~(ELFROUND - 1);
    symva = maxva;
    maxva += sizeof(int);
    *symtab_addr = maxva;
    *symtab_len = 0;
    maxva += sizeof(Elf_Ehdr) + ehdr.e_shnum * sizeof(Elf_Shdr);
    maxva = (maxva + ELFROUND - 1) & ~(ELFROUND - 1);

    /* Copy kernel string / symbol tables into physical memory */
    for ( h = 0; h < ehdr.e_shnum; h++ )
    {
        if ( shdr[h].sh_type == SHT_STRTAB )
        {
            /* Look for a strtab @i linked to symtab @h. */
            for ( i = 0; i < ehdr.e_shnum; i++ )
                if ( (shdr[i].sh_type == SHT_SYMTAB) &&
                     (shdr[i].sh_link == h) )
                    break;
            /* Skip symtab @h if we found no corresponding strtab @i. */
            if ( i == ehdr.e_shnum )
            {
                shdr[h].sh_offset = 0;
                continue;
            }
        }

        if ( (shdr[h].sh_type == SHT_STRTAB) ||
             (shdr[h].sh_type == SHT_SYMTAB) )
        {
            if ( myseek(kernel_gfd, shdr[h].sh_offset - curpos, 
                        SEEK_SET) == -1 )
            {
                ERROR("Seek to symbol section failed");
                goto out;
            }
            curpos = shdr[h].sh_offset;

            /* Mangled to be based on ELF header location. */
            shdr[h].sh_offset = maxva - *symtab_addr;

            DPRINTF(("copy section %d, size 0x%x\n", h, shdr[h].sh_size));
            for ( i = 0; i < shdr[h].sh_size; i += c, maxva += c )
            {
                c = PAGE_SIZE - (maxva & (PAGE_SIZE - 1));
                if ( c > (shdr[h].sh_size - i) )
                    c = shdr[h].sh_size - i;
                if ( gzread(kernel_gfd, page, c) != c )
                {
                    PERROR("Error reading kernel image page.");
                    goto out;
                }
                curpos += c;

                vaddr = map_pfn_writeable(pm_handle, 
                                          page_array[(maxva - *virt_load_addr)
                                                    >> PAGE_SHIFT]);
                if ( vaddr == NULL )
                {
                    ERROR("Couldn't map guest memory");
                    goto out;
                }
                DPRINTF(("copy page %p to %p, count 0x%x\n", (void *)maxva,
                         vaddr + (maxva & (PAGE_SIZE - 1)), c));
                memcpy(vaddr + (maxva & (PAGE_SIZE - 1)), page, c);
                unmap_pfn(pm_handle, vaddr);
            }

            *symtab_len += shdr[h].sh_size;
            maxva = (maxva + ELFROUND - 1) & ~(ELFROUND - 1);

        }
        shdr[h].sh_name = 0;  /* Name is NULL. */
    }

    if ( *symtab_len == 0 ) 
    {
        DPRINTF(("no symbol table\n"));
        *symtab_addr = 0;
        ret = 0;
        goto out;
    }

    DPRINTF(("sym header va %p from %p/%p size %x/%x\n", (void *)symva,
             shdr, p, ehdr.e_shnum * sizeof(Elf_Shdr),
             ehdr.e_shnum * sizeof(Elf_Shdr) + sizeof(Elf_Ehdr)));
    ehdr.e_phoff = 0;
    ehdr.e_shoff = sizeof(Elf_Ehdr);
    ehdr.e_phentsize = 0;
    ehdr.e_phnum = 0;
    ehdr.e_shstrndx = SHN_UNDEF;
    memcpy(p + sizeof(int), &ehdr, sizeof(Elf_Ehdr));
    *(int *)p = maxva - *symtab_addr;

    /* Copy total length, crafted ELF header and section header table */
    s = sizeof(int) + sizeof(Elf_Ehdr) + ehdr.e_shnum * sizeof(Elf_Shdr);
    for ( i = 0; i < s; i += c, symva += c ) 
    {
        c = PAGE_SIZE - (symva & (PAGE_SIZE - 1));
        if ( c > s - i )
            c = s - i;
        vaddr = map_pfn_writeable(pm_handle, 
                                  page_array[(symva - *virt_load_addr)
                                            >> PAGE_SHIFT]);
        if ( vaddr == NULL )
        {
            ERROR("Couldn't map guest memory");
            goto out;
        }
        DPRINTF(("copy page %p to %p, count 0x%x\n", (void *)symva,
                 vaddr + (symva & (PAGE_SIZE - 1)), c));
        memcpy(vaddr + (symva & (PAGE_SIZE - 1)), p + i,
               c);
        unmap_pfn(pm_handle, vaddr);
    }

    *symtab_len = maxva - *symtab_addr;

    ret = 0;

 out:
    if ( ret == 0 )
    {
        maxva = (maxva + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        *ksize = (maxva - *virt_load_addr) >> PAGE_SHIFT;

        DPRINTF(("virt_addr %p, kpages 0x%lx, symtab_addr %p, symtab_len %p\n",
                 (void *)*virt_load_addr, *ksize, (void *)*symtab_addr,
                 (void *)*symtab_len));
    }

    if ( phdr != NULL )
        free(phdr);
    if ( p != NULL )
        free(p);
    return ret;
}
