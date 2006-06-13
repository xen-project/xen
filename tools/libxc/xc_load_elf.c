/******************************************************************************
 * xc_elf_load.c
 */

#include "xg_private.h"
#include "xc_elf.h"
#include <stdlib.h>

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static int
parseelfimage(
    const char *image, unsigned long image_size,
    struct domain_setup_info *dsi);
static int
loadelfimage(
    const char *image, unsigned long image_size, int xch, uint32_t dom,
    xen_pfn_t *parray, struct domain_setup_info *dsi);
static int
loadelfsymtab(
    const char *image, int xch, uint32_t dom, xen_pfn_t *parray,
    struct domain_setup_info *dsi);

/*
 * Elf header attributes we require for each supported host platform.
 * These are checked in parseelfimage().
 */
#if defined(__ia64__)
#define ELFCLASS   ELFCLASS64
#define ELFDATA    ELFDATA2LSB
#define ELFMACHINE EM_IA_64
#elif defined(__i386__)
#define ELFCLASS   ELFCLASS32
#define ELFDATA    ELFDATA2LSB
#define ELFMACHINE EM_386
#elif defined(__x86_64__)
#define ELFCLASS   ELFCLASS64
#define ELFDATA    ELFDATA2LSB
#define ELFMACHINE EM_X86_64
#endif

int probe_elf(const char *image,
              unsigned long image_size,
              struct load_funcs *load_funcs)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)image;

    if ( !IS_ELF(*ehdr) )
        return -EINVAL;

    load_funcs->parseimage = parseelfimage;
    load_funcs->loadimage = loadelfimage;

    return 0;
}

static inline int is_loadable_phdr(Elf_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

static int parseelfimage(const char *image,
                         unsigned long elfsize,
                         struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)image;
    Elf_Phdr *phdr;
    Elf_Shdr *shdr;
    unsigned long kernstart = ~0UL, kernend=0UL, vaddr, virt_base, elf_pa_off;
    const char *shstrtab;
    char *guestinfo=NULL, *p;
    int h, virt_base_defined, elf_pa_off_defined;

    if ( !IS_ELF(*ehdr) )
    {
        ERROR("Kernel image does not have an ELF header.");
        return -EINVAL;
    }

    if ( (ehdr->e_ident[EI_CLASS] != ELFCLASS) ||
         (ehdr->e_machine != ELFMACHINE) ||
         (ehdr->e_ident[EI_DATA] != ELFDATA) ||
         (ehdr->e_type != ET_EXEC) )
    {
        ERROR("Kernel not a Xen-compatible Elf image.");
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
    shdr = (Elf_Shdr *)(image + ehdr->e_shoff +
                        (ehdr->e_shstrndx*ehdr->e_shentsize));
    shstrtab = image + shdr->sh_offset;

    /* Find the special '__xen_guest' section and check its contents. */
    for ( h = 0; h < ehdr->e_shnum; h++ )
    {
        shdr = (Elf_Shdr *)(image + ehdr->e_shoff + (h*ehdr->e_shentsize));
        if ( strcmp(&shstrtab[shdr->sh_name], "__xen_guest") != 0 )
            continue;

        guestinfo = (char *)image + shdr->sh_offset;

        if ( (strstr(guestinfo, "LOADER=generic") == NULL) &&
             (strstr(guestinfo, "GUEST_OS=linux") == NULL) )
        {
            ERROR("Will only load images built for the generic loader "
                  "or Linux images");
            ERROR("Actually saw: '%s'", guestinfo);
            return -EINVAL;
        }

        if ( (strstr(guestinfo, "XEN_VER=xen-3.0") == NULL) )
        {
            ERROR("Will only load images built for Xen v3.0");
            ERROR("Actually saw: '%s'", guestinfo);
            return -EINVAL;
        }

        dsi->pae_kernel = PAEKERN_no;
        p = strstr(guestinfo, "PAE=yes");
        if ( p != NULL )
        {
            dsi->pae_kernel = PAEKERN_yes;
            if ( !strncmp(p+7, "[extended-cr3]", 14) )
                dsi->pae_kernel = PAEKERN_extended_cr3;
        }

        break;
    }

    if ( guestinfo == NULL )
    {
#ifdef __ia64__
        guestinfo = "";
#else
        ERROR("Not a Xen-ELF image: '__xen_guest' section not found.");
        return -EINVAL;
#endif
    }

    dsi->xen_guest_string = guestinfo;

    /* Initial guess for virt_base is 0 if it is not explicitly defined. */
    p = strstr(guestinfo, "VIRT_BASE=");
    virt_base_defined = (p != NULL);
    virt_base = virt_base_defined ? strtoul(p+10, &p, 0) : 0;

    /* Initial guess for elf_pa_off is virt_base if not explicitly defined. */
    p = strstr(guestinfo, "ELF_PADDR_OFFSET=");
    elf_pa_off_defined = (p != NULL);
    elf_pa_off = elf_pa_off_defined ? strtoul(p+17, &p, 0) : virt_base;

    if ( elf_pa_off_defined && !virt_base_defined )
        goto bad_image;

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (Elf_Phdr *)(image + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        vaddr = phdr->p_paddr - elf_pa_off + virt_base;
        if ( (vaddr + phdr->p_memsz) < vaddr )
            goto bad_image;
        if ( vaddr < kernstart )
            kernstart = vaddr;
        if ( (vaddr + phdr->p_memsz) > kernend )
            kernend = vaddr + phdr->p_memsz;
    }

    /*
     * Legacy compatibility and images with no __xen_guest section: assume
     * header addresses are virtual addresses, and that guest memory should be
     * mapped starting at kernel load address.
     */
    dsi->v_start          = virt_base_defined  ? virt_base  : kernstart;
    dsi->elf_paddr_offset = elf_pa_off_defined ? elf_pa_off : dsi->v_start;

    dsi->v_kernentry = ehdr->e_entry;
    if ( (p = strstr(guestinfo, "VIRT_ENTRY=")) != NULL )
        dsi->v_kernentry = strtoul(p+11, &p, 0);

    if ( (kernstart > kernend) ||
         (dsi->v_kernentry < kernstart) ||
         (dsi->v_kernentry > kernend) ||
         (dsi->v_start > kernstart) )
        goto bad_image;

    if ( (p = strstr(guestinfo, "BSD_SYMTAB")) != NULL )
        dsi->load_symtab = 1;

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_end       = dsi->v_kernend;

    loadelfsymtab(image, 0, 0, NULL, dsi);

    return 0;

 bad_image:
    ERROR("Malformed ELF image.");
    return -EINVAL;
}

static int
loadelfimage(
    const char *image, unsigned long elfsize, int xch, uint32_t dom,
    xen_pfn_t *parray, struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)image;
    Elf_Phdr *phdr;
    int h;

    char         *va;
    unsigned long pa, done, chunksz;

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (Elf_Phdr *)(image + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;

        for ( done = 0; done < phdr->p_filesz; done += chunksz )
        {
            pa = (phdr->p_paddr + done) - dsi->elf_paddr_offset;
            va = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_WRITE, parray[pa>>PAGE_SHIFT]);
            if ( va == NULL )
                return -1;
            chunksz = phdr->p_filesz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memcpy(va + (pa & (PAGE_SIZE-1)),
                   image + phdr->p_offset + done, chunksz);
            munmap(va, PAGE_SIZE);
        }

        for ( ; done < phdr->p_memsz; done += chunksz )
        {
            pa = (phdr->p_paddr + done) - dsi->elf_paddr_offset;
            va = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_WRITE, parray[pa>>PAGE_SHIFT]);
            if ( va == NULL )
                return -1;
            chunksz = phdr->p_memsz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memset(va + (pa & (PAGE_SIZE-1)), 0, chunksz);
            munmap(va, PAGE_SIZE);
        }
    }

    loadelfsymtab(image, xch, dom, parray, dsi);

    return 0;
}

#define ELFROUND (ELFSIZE / 8)

static int
loadelfsymtab(
    const char *image, int xch, uint32_t dom, xen_pfn_t *parray,
    struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)image, *sym_ehdr;
    Elf_Shdr *shdr;
    unsigned long maxva, symva;
    char *p;
    int h, i;

    if ( !dsi->load_symtab )
        return 0;

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
    memcpy(shdr, image + ehdr->e_shoff, ehdr->e_shnum * sizeof(Elf_Shdr));

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
                xc_map_memcpy(maxva, image + shdr[h].sh_offset,
                              shdr[h].sh_size,
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
    free(p);

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
