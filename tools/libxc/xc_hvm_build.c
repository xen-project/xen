/******************************************************************************
 * xc_hvm_build.c
 */

#include <stddef.h>
#include "xg_private.h"
#define ELFSIZE 32
#include "xc_elf.h"
#include <stdlib.h>
#include <unistd.h>
#include <zlib.h>
#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/ioreq.h>

#define HVM_LOADER_ENTR_ADDR  0x00100000

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#ifdef __x86_64__
#define L3_PROT (_PAGE_PRESENT)
#endif

#define E820MAX     128

#define E820_RAM          1
#define E820_RESERVED     2
#define E820_ACPI         3
#define E820_NVS          4
#define E820_IO          16
#define E820_SHARED_PAGE 17
#define E820_XENSTORE    18

#define E820_MAP_PAGE       0x00090000
#define E820_MAP_NR_OFFSET  0x000001E8
#define E820_MAP_OFFSET     0x000002D0

struct e820entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static int
parseelfimage(
    char *elfbase, unsigned long elfsize, struct domain_setup_info *dsi);
static int
loadelfimage(
    char *elfbase, int xch, uint32_t dom, unsigned long *parray,
    struct domain_setup_info *dsi);

static unsigned char build_e820map(void *e820_page, unsigned long mem_size)
{
    struct e820entry *e820entry =
        (struct e820entry *)(((unsigned char *)e820_page) + E820_MAP_OFFSET);
    unsigned char nr_map = 0;

    /* XXX: Doesn't work for > 4GB yet */
    e820entry[nr_map].addr = 0x0;
    e820entry[nr_map].size = 0x9F800;
    e820entry[nr_map].type = E820_RAM;
    nr_map++;

    e820entry[nr_map].addr = 0x9F800;
    e820entry[nr_map].size = 0x800;
    e820entry[nr_map].type = E820_RESERVED;
    nr_map++;

    e820entry[nr_map].addr = 0xA0000;
    e820entry[nr_map].size = 0x20000;
    e820entry[nr_map].type = E820_IO;
    nr_map++;

    e820entry[nr_map].addr = 0xF0000;
    e820entry[nr_map].size = 0x10000;
    e820entry[nr_map].type = E820_RESERVED;
    nr_map++;

#define STATIC_PAGES    2       /* for ioreq_t and store_mfn */
    /* Most of the ram goes here */
    e820entry[nr_map].addr = 0x100000;
    e820entry[nr_map].size = mem_size - 0x100000 - STATIC_PAGES*PAGE_SIZE;
    e820entry[nr_map].type = E820_RAM;
    nr_map++;

    /* Statically allocated special pages */

    /* Shared ioreq_t page */
    e820entry[nr_map].addr = mem_size - PAGE_SIZE;
    e820entry[nr_map].size = PAGE_SIZE;
    e820entry[nr_map].type = E820_SHARED_PAGE;
    nr_map++;

    /* For xenstore */
    e820entry[nr_map].addr = mem_size - 2*PAGE_SIZE;
    e820entry[nr_map].size = PAGE_SIZE;
    e820entry[nr_map].type = E820_XENSTORE;
    nr_map++;

    e820entry[nr_map].addr = mem_size;
    e820entry[nr_map].size = 0x3 * PAGE_SIZE;
    e820entry[nr_map].type = E820_NVS;
    nr_map++;

    e820entry[nr_map].addr = mem_size + 0x3 * PAGE_SIZE;
    e820entry[nr_map].size = 0xA * PAGE_SIZE;
    e820entry[nr_map].type = E820_ACPI;
    nr_map++;

    e820entry[nr_map].addr = 0xFEC00000;
    e820entry[nr_map].size = 0x1400000;
    e820entry[nr_map].type = E820_IO;
    nr_map++;

    return (*(((unsigned char *)e820_page) + E820_MAP_NR_OFFSET) = nr_map);
}

static void
set_hvm_info_checksum(struct hvm_info_table *t)
{
    uint8_t *ptr = (uint8_t *)t, sum = 0;
    unsigned int i;

    t->checksum = 0;

    for (i = 0; i < t->length; i++)
        sum += *ptr++;

    t->checksum = -sum;
}

/*
 * Use E820 reserved memory 0x9F800 to pass HVM info to vmxloader
 * hvmloader will use this info to set BIOS accordingly
 */
static int set_hvm_info(int xc_handle, uint32_t dom,
                        unsigned long *pfn_list, unsigned int vcpus,
                        unsigned int pae, unsigned int acpi, unsigned int apic)
{
    char *va_map;
    struct hvm_info_table *va_hvm;


    va_map = xc_map_foreign_range(
        xc_handle,
        dom,
        PAGE_SIZE,
        PROT_READ|PROT_WRITE,
        pfn_list[HVM_INFO_PFN]);

    if ( va_map == NULL )
        return -1;

    va_hvm = (struct hvm_info_table *)(va_map + HVM_INFO_OFFSET);
    memset(va_hvm, 0, sizeof(*va_hvm));
    strncpy(va_hvm->signature, "HVM INFO", 8);
    va_hvm->length       = sizeof(struct hvm_info_table);
    va_hvm->acpi_enabled = acpi;
    va_hvm->apic_enabled = apic;
    va_hvm->pae_enabled  = pae;
    va_hvm->nr_vcpus     = vcpus;

    set_hvm_info_checksum(va_hvm);

    munmap(va_map, PAGE_SIZE);

    return 0;
}

static int setup_guest(int xc_handle,
                       uint32_t dom, int memsize,
                       char *image, unsigned long image_size,
                       unsigned long nr_pages,
                       vcpu_guest_context_t *ctxt,
                       unsigned long shared_info_frame,
                       unsigned int vcpus,
                       unsigned int pae,
                       unsigned int acpi,
                       unsigned int apic,
                       unsigned int store_evtchn,
                       unsigned long *store_mfn)
{
    unsigned long *page_array = NULL;

    unsigned long count, i;
    shared_info_t *shared_info;
    void *e820_page;
    unsigned char e820_map_nr;
    xc_mmu_t *mmu = NULL;
    int rc;

    struct domain_setup_info dsi;
    unsigned long v_end;

    unsigned long shared_page_frame = 0;
    shared_iopage_t *sp;

    memset(&dsi, 0, sizeof(struct domain_setup_info));

    if ( (rc = parseelfimage(image, image_size, &dsi)) != 0 )
        goto error_out;

    if ( (dsi.v_start & (PAGE_SIZE-1)) != 0 )
    {
        PERROR("Guest OS must load to a page boundary.\n");
        goto error_out;
    }

    /* memsize is in megabytes */
    v_end              = (unsigned long)memsize << 20;

    printf("VIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded HVM loader: %08lx->%08lx\n"
           " TOTAL:         %08lx->%08lx\n",
           dsi.v_kernstart, dsi.v_kernend,
           dsi.v_start, v_end);
    printf(" ENTRY ADDRESS: %08lx\n", dsi.v_kernentry);

    if ( (v_end - dsi.v_start) > (nr_pages * PAGE_SIZE) )
    {
        ERROR("Initial guest OS requires too much space\n"
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

    loadelfimage(image, xc_handle, dom, page_array, &dsi);

    if ( (mmu = xc_init_mmu_updates(xc_handle, dom)) == NULL )
        goto error_out;

    /* Write the machine->phys table entries. */
    for ( count = 0; count < nr_pages; count++ )
    {
        if ( xc_add_mmu_update(xc_handle, mmu,
                               (page_array[count] << PAGE_SHIFT) |
                               MMU_MACHPHYS_UPDATE, count) )
            goto error_out;
    }

    if ( set_hvm_info(xc_handle, dom, page_array, vcpus, pae, acpi, apic) ) {
        fprintf(stderr, "Couldn't set hvm info for HVM guest.\n");
        goto error_out;
    }

    if ( (e820_page = xc_map_foreign_range(
         xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
         page_array[E820_MAP_PAGE >> PAGE_SHIFT])) == 0 )
        goto error_out;
    memset(e820_page, 0, PAGE_SIZE);
    e820_map_nr = build_e820map(e820_page, v_end);
    munmap(e820_page, PAGE_SIZE);

    /* shared_info page starts its life empty. */
    if ( (shared_info = xc_map_foreign_range(
         xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
         shared_info_frame)) == 0 )
        goto error_out;
    memset(shared_info, 0, sizeof(shared_info_t));
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_info[i].evtchn_upcall_mask = 1;
    munmap(shared_info, PAGE_SIZE);

    /* Populate the event channel port in the shared page */
    shared_page_frame = page_array[(v_end >> PAGE_SHIFT) - 1];
    if ( (sp = (shared_iopage_t *) xc_map_foreign_range(
         xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
         shared_page_frame)) == 0 )
        goto error_out;
    memset(sp, 0, PAGE_SIZE);

    /* FIXME: how about if we overflow the page here? */
    for ( i = 0; i < vcpus; i++ ) {
        unsigned int vp_eport;

        vp_eport = xc_evtchn_alloc_unbound(xc_handle, dom, 0);
        if ( vp_eport < 0 ) {
            fprintf(stderr, "Couldn't get unbound port from VMX guest.\n");
            goto error_out;
        }
        sp->vcpu_iodata[i].vp_eport = vp_eport;
    }

    munmap(sp, PAGE_SIZE);

    *store_mfn = page_array[(v_end >> PAGE_SHIFT) - 2];
    if ( xc_clear_domain_page(xc_handle, dom, *store_mfn) )
        goto error_out;

    /* Send the page update requests down to the hypervisor. */
    if ( xc_finish_mmu_updates(xc_handle, mmu) )
        goto error_out;

    free(mmu);
    free(page_array);

    /*
     * Initial register values:
     */
    ctxt->user_regs.ds = 0;
    ctxt->user_regs.es = 0;
    ctxt->user_regs.fs = 0;
    ctxt->user_regs.gs = 0;
    ctxt->user_regs.ss = 0;
    ctxt->user_regs.cs = 0;
    ctxt->user_regs.eip = dsi.v_kernentry;
    ctxt->user_regs.edx = 0;
    ctxt->user_regs.eax = 0;
    ctxt->user_regs.esp = 0;
    ctxt->user_regs.ebx = 0; /* startup_32 expects this to be 0 to signal boot cpu */
    ctxt->user_regs.ecx = 0;
    ctxt->user_regs.esi = 0;
    ctxt->user_regs.edi = 0;
    ctxt->user_regs.ebp = 0;

    ctxt->user_regs.eflags = 0;

    return 0;

 error_out:
    free(mmu);
    free(page_array);
    return -1;
}

int xc_hvm_build(int xc_handle,
                 uint32_t domid,
                 int memsize,
                 const char *image_name,
                 unsigned int vcpus,
                 unsigned int pae,
                 unsigned int acpi,
                 unsigned int apic,
                 unsigned int store_evtchn,
                 unsigned long *store_mfn)
{
    dom0_op_t launch_op, op;
    int rc, i;
    vcpu_guest_context_t st_ctxt, *ctxt = &st_ctxt;
    unsigned long nr_pages;
    char         *image = NULL;
    unsigned long image_size;
    xen_capabilities_info_t xen_caps;

    if ( (rc = xc_version(xc_handle, XENVER_capabilities, &xen_caps)) != 0 )
    {
        PERROR("Failed to get xen version info");
        goto error_out;
    }

    if ( !strstr(xen_caps, "hvm") )
    {
        PERROR("CPU doesn't support HVM extensions or "
               "the extensions are not enabled");
        goto error_out;
    }

    if ( (nr_pages = xc_get_tot_pages(xc_handle, domid)) < 0 )
    {
        PERROR("Could not find total pages for domain");
        goto error_out;
    }

    if ( (image = xc_read_kernel_image(image_name, &image_size)) == NULL )
        goto error_out;

    if ( mlock(&st_ctxt, sizeof(st_ctxt) ) )
    {
        PERROR("%s: ctxt mlock failed", __func__);
        return 1;
    }

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    if ( (xc_dom0_op(xc_handle, &op) < 0) ||
         ((uint16_t)op.u.getdomaininfo.domain != domid) )
    {
        PERROR("Could not get info on domain");
        goto error_out;
    }

    memset(ctxt, 0, sizeof(*ctxt));

    ctxt->flags = VGCF_HVM_GUEST;
    if ( setup_guest(xc_handle, domid, memsize, image, image_size, nr_pages,
                     ctxt, op.u.getdomaininfo.shared_info_frame,
                     vcpus, pae, acpi, apic, store_evtchn, store_mfn) < 0)
    {
        ERROR("Error constructing guest OS");
        goto error_out;
    }

    free(image);

    /* FPU is set up to default initial state. */
    memset(&ctxt->fpu_ctxt, 0, sizeof(ctxt->fpu_ctxt));

    /* Virtual IDT is empty at start-of-day. */
    for ( i = 0; i < 256; i++ )
    {
        ctxt->trap_ctxt[i].vector = i;
        ctxt->trap_ctxt[i].cs     = FLAT_KERNEL_CS;
    }

    /* No LDT. */
    ctxt->ldt_ents = 0;

    /* Use the default Xen-provided GDT. */
    ctxt->gdt_ents = 0;

    /* No debugging. */
    memset(ctxt->debugreg, 0, sizeof(ctxt->debugreg));

    /* No callback handlers. */
#if defined(__i386__)
    ctxt->event_callback_cs     = FLAT_KERNEL_CS;
    ctxt->event_callback_eip    = 0;
    ctxt->failsafe_callback_cs  = FLAT_KERNEL_CS;
    ctxt->failsafe_callback_eip = 0;
#elif defined(__x86_64__)
    ctxt->event_callback_eip    = 0;
    ctxt->failsafe_callback_eip = 0;
    ctxt->syscall_callback_eip  = 0;
#endif

    memset( &launch_op, 0, sizeof(launch_op) );

    launch_op.u.setvcpucontext.domain = (domid_t)domid;
    launch_op.u.setvcpucontext.vcpu   = 0;
    launch_op.u.setvcpucontext.ctxt   = ctxt;

    launch_op.cmd = DOM0_SETVCPUCONTEXT;
    rc = xc_dom0_op(xc_handle, &launch_op);

    return rc;

 error_out:
    free(image);
    return -1;
}

static inline int is_loadable_phdr(Elf32_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

static int parseelfimage(char *elfbase,
                         unsigned long elfsize,
                         struct domain_setup_info *dsi)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfbase;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
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
    shdr = (Elf32_Shdr *)(elfbase + ehdr->e_shoff +
                          (ehdr->e_shstrndx*ehdr->e_shentsize));
    shstrtab = elfbase + shdr->sh_offset;

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (Elf32_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
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

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_kernentry = HVM_LOADER_ENTR_ADDR;

    dsi->v_end       = dsi->v_kernend;

    return 0;
}

static int
loadelfimage(
    char *elfbase, int xch, uint32_t dom, unsigned long *parray,
    struct domain_setup_info *dsi)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfbase;
    Elf32_Phdr *phdr;
    int h;

    char         *va;
    unsigned long pa, done, chunksz;

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (Elf32_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;

        for ( done = 0; done < phdr->p_filesz; done += chunksz )
        {
            pa = (phdr->p_paddr + done) - dsi->v_start;
            if ((va = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_WRITE,
                parray[pa >> PAGE_SHIFT])) == 0)
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
            pa = (phdr->p_paddr + done) - dsi->v_start;
            if ((va = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_WRITE,
                parray[pa >> PAGE_SHIFT])) == 0)
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
