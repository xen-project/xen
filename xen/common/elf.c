/******************************************************************************
 * elf.c
 * 
 * Generic Elf-loading routines.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/elf.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/inttypes.h>

#include <public/elfnote.h>

static void loadelfsymtab(struct domain_setup_info *dsi, int doload);
static inline int is_loadable_phdr(const Elf_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

/*
 * Fallback for kernels containing only the legacy __xen_guest string
 * and no ELF notes.
 */
static int is_xen_guest_section(const Elf_Shdr *shdr, const char *shstrtab)
{
    return strcmp(&shstrtab[shdr->sh_name], "__xen_guest") == 0;
}

static const char *xen_guest_lookup(struct domain_setup_info *dsi, int type)
{
    const char *xenguest_fallbacks[] = {
        [XEN_ELFNOTE_ENTRY] = "VIRT_ENTRY=",
        [XEN_ELFNOTE_HYPERCALL_PAGE] = "HYPERCALL_PAGE=",
        [XEN_ELFNOTE_VIRT_BASE] = "VIRT_BASE=",
        [XEN_ELFNOTE_PADDR_OFFSET] = "ELF_PADDR_OFFSET=",
        [XEN_ELFNOTE_XEN_VERSION] = "XEN_VER=",
        [XEN_ELFNOTE_GUEST_OS] = "GUEST_OS=",
        [XEN_ELFNOTE_GUEST_VERSION] = "GUEST_VER=",
        [XEN_ELFNOTE_LOADER] = "LOADER=",
        [XEN_ELFNOTE_PAE_MODE] = "PAE=",
        [XEN_ELFNOTE_FEATURES] = "FEATURES=",
        [XEN_ELFNOTE_BSD_SYMTAB] = "BSD_SYMTAB=",
    };
    const char *fallback;
    const char *p;

    if ( !dsi->__xen_guest_string )
        return NULL;

    if ( type > sizeof(xenguest_fallbacks) )
        return NULL;

    if ( (fallback = xenguest_fallbacks[type]) == NULL )
        return NULL;

    if ( (p = strstr(dsi->__xen_guest_string,fallback)) == NULL )
        return NULL;

    return p + strlen(fallback);
}

static const char *xen_guest_string(struct domain_setup_info *dsi, int type)
{
    const char *p = xen_guest_lookup(dsi, type);

    /*
     * We special case this since the __xen_guest_section treats the
     * mere precense of the BSD_SYMTAB string as true or false.
     */
    if ( type == XEN_ELFNOTE_BSD_SYMTAB )
        return p ? "yes" : "no";

    return p;
}

static unsigned long long xen_guest_numeric(struct domain_setup_info *dsi,
                                                   int type, int *defined)
{
    const char *p = xen_guest_lookup(dsi, type);
    unsigned long long value;

    if ( p == NULL )
        return 0;

    value = simple_strtoull(p, NULL, 0);

    /* We special case this since __xen_guest_section contains a PFN
     * for this field not a virtual address.
     */
    if (type == XEN_ELFNOTE_HYPERCALL_PAGE)
        value = dsi->v_start + (value<<PAGE_SHIFT);

    *defined = 1;
    return value;
}


static int is_xen_elfnote_section(const char *image, const Elf_Shdr *shdr)
{
    const Elf_Note *note;

    if ( shdr->sh_type != SHT_NOTE )
        return 0;

    for ( note = (const Elf_Note *)(image + shdr->sh_offset);
          note < (const Elf_Note *)(image + shdr->sh_offset + shdr->sh_size);
          note = ELFNOTE_NEXT(note) )
    {
        if ( !strncmp(ELFNOTE_NAME(note), "Xen", 4) )
            return 1;
    }

    return 0;
}

static const Elf_Note *xen_elfnote_lookup(
    struct domain_setup_info *dsi, int type)
{
    const Elf_Note *note;

    if ( !dsi->__elfnote_section )
        return NULL;

    for ( note = (const Elf_Note *)dsi->__elfnote_section;
          note < (const Elf_Note *)dsi->__elfnote_section_end;
          note = ELFNOTE_NEXT(note) )
    {
        if ( strncmp(ELFNOTE_NAME(note), "Xen", 4) )
            continue;

        if ( note->type == type )
            return note;
    }

    return NULL;
}

const char *xen_elfnote_string(struct domain_setup_info *dsi, int type)
{
    const Elf_Note *note;

    if ( !dsi->__elfnote_section )
        return xen_guest_string(dsi, type);

    note = xen_elfnote_lookup(dsi, type);
    if ( note == NULL )
        return NULL;

    return (const char *)ELFNOTE_DESC(note);
}

unsigned long long xen_elfnote_numeric(struct domain_setup_info *dsi,
                                       int type, int *defined)
{
    const Elf_Note *note;

    *defined = 0;

    if ( !dsi->__elfnote_section )
        return xen_guest_numeric(dsi, type, defined);

    note = xen_elfnote_lookup(dsi, type);
    if ( note == NULL )
    {
        return 0;
    }

    switch ( note->descsz )
    {
    case 4:
        *defined = 1;
        return *(const uint32_t*)ELFNOTE_DESC(note);
    case 8:
        *defined = 1;
        return *(const uint64_t*)ELFNOTE_DESC(note);
    default:
        printk("ERROR: unknown data size %#x for numeric type note %#x\n",
               note->descsz, type);
        return 0;
    }
}

int parseelfimage(struct domain_setup_info *dsi)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)dsi->image_addr;
    const Elf_Phdr *phdr;
    const Elf_Shdr *shdr;
    Elf_Addr kernstart = ~0, kernend = 0, vaddr, virt_entry;
    const char *shstrtab, *p;
    const char *image = (char *)dsi->image_addr;
    const unsigned long image_len = dsi->image_len;
    int h, virt_base_defined, elf_pa_off_defined, virt_entry_defined;

    if ( !elf_sanity_check(ehdr) )
        return -ENOSYS;

    if ( (ehdr->e_phoff + (ehdr->e_phnum*ehdr->e_phentsize)) > image_len )
    {
        printk("ELF program headers extend beyond end of image.\n");
        return -EINVAL;
    }

    if ( (ehdr->e_shoff + (ehdr->e_shnum*ehdr->e_shentsize)) > image_len )
    {
        printk("ELF section headers extend beyond end of image.\n");
        return -EINVAL;
    }

    dsi->__elfnote_section = NULL;
    dsi->__xen_guest_string = NULL;

    /* Look for .notes segment containing at least one Xen note */
    for ( h = 0; h < ehdr->e_shnum; h++ )
    {
        shdr = (const Elf_Shdr *)(
            image + ehdr->e_shoff + (h*ehdr->e_shentsize));
        if ( !is_xen_elfnote_section(image, shdr) )
            continue;
        dsi->__elfnote_section = (const char *)image + shdr->sh_offset;
        dsi->__elfnote_section_end =
            (const char *)image + shdr->sh_offset + shdr->sh_size;
        break;
    }

    /* Fall back to looking for the special '__xen_guest' section. */
    if ( dsi->__elfnote_section == NULL )
    {
        /* Find the section-header strings table. */
        if ( ehdr->e_shstrndx == SHN_UNDEF )
        {
            printk("ELF image has no section-header strings table.\n");
            return -EINVAL;
        }
        shdr = (const Elf_Shdr *)(image + ehdr->e_shoff +
                            (ehdr->e_shstrndx*ehdr->e_shentsize));
        shstrtab = image + shdr->sh_offset;

        for ( h = 0; h < ehdr->e_shnum; h++ )
        {
            shdr = (const Elf_Shdr *)(
                image + ehdr->e_shoff + (h*ehdr->e_shentsize));
            if ( is_xen_guest_section(shdr, shstrtab) )
            {
                dsi->__xen_guest_string =
                    (const char *)image + shdr->sh_offset;
                break;
            }
        }
    }

    /* Check the contents of the Xen notes or guest string. */
    if ( dsi->__elfnote_section || dsi->__xen_guest_string )
    {
        const char *loader = xen_elfnote_string(dsi, XEN_ELFNOTE_LOADER);
        const char *guest_os = xen_elfnote_string(dsi, XEN_ELFNOTE_GUEST_OS);
        const char *xen_version =
            xen_elfnote_string(dsi, XEN_ELFNOTE_XEN_VERSION);

        if ( ( loader == NULL || strncmp(loader, "generic", 7) ) &&
             ( guest_os == NULL || strncmp(guest_os, "linux", 5) ) )
        {
            printk("ERROR: Will only load images built for the generic "
                   "loader or Linux images");
            return -EINVAL;
        }

        if ( xen_version == NULL || strncmp(xen_version, "xen-3.0", 7) )
        {
            printk("ERROR: Xen will only load images built for Xen v3.0\n");
        }
    }
    else
    {
#if defined(__x86_64__) || defined(__i386__)
        printk("ERROR: Not a Xen-ELF image: "
               "No ELF notes or '__xen_guest' section found.\n");
        return -EINVAL;
#endif
    }

    /*
     * A "bimodal" ELF note indicates the kernel will adjust to the
     * current paging mode, including handling extended cr3 syntax.
     * If we have ELF notes then PAE=yes implies that we must support
     * the extended cr3 syntax. Otherwise we need to find the
     * [extended-cr3] syntax in the __xen_guest string.
     */
    dsi->pae_kernel = PAEKERN_no;
    if ( dsi->__elfnote_section )
    {
        p = xen_elfnote_string(dsi, XEN_ELFNOTE_PAE_MODE);
        if ( p != NULL && strstr(p, "bimodal") != NULL )
            dsi->pae_kernel = PAEKERN_bimodal;
        else if ( p != NULL && strncmp(p, "yes", 3) == 0 )
            dsi->pae_kernel = PAEKERN_extended_cr3;
    }
    else
    {
        p = xen_guest_lookup(dsi, XEN_ELFNOTE_PAE_MODE);
        if ( p != NULL && strncmp(p, "yes", 3) == 0 )
        {
            dsi->pae_kernel = PAEKERN_yes;
            if ( !strncmp(p+3, "[extended-cr3]", 14) )
                dsi->pae_kernel = PAEKERN_extended_cr3;
        }
    }

    /* Initial guess for v_start is 0 if it is not explicitly defined. */
    dsi->v_start =
        xen_elfnote_numeric(dsi, XEN_ELFNOTE_VIRT_BASE, &virt_base_defined);
    if ( !virt_base_defined )
        dsi->v_start = 0;

    /*
     * If we are using the legacy __xen_guest section then elf_pa_off
     * defaults to v_start in order to maintain compatibility with
     * older hypervisors which set padd in the ELF header to
     * virt_base.
     *
     * If we are using the modern ELF notes interface then the default
     * is 0.
     */
    dsi->elf_paddr_offset = xen_elfnote_numeric(dsi, XEN_ELFNOTE_PADDR_OFFSET,
                                                &elf_pa_off_defined);
    if ( !elf_pa_off_defined )
    {
        if ( dsi->__elfnote_section )
            dsi->elf_paddr_offset = 0;
        else
            dsi->elf_paddr_offset = dsi->v_start;
    }

    if ( elf_pa_off_defined && !virt_base_defined )
    {
        printk("ERROR: Neither ELF_PADDR_OFFSET nor VIRT_BASE found in"
               " Xen ELF notes.\n");
        return -EINVAL;
    }

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (const Elf_Phdr *)(
            image + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        vaddr = phdr->p_paddr - dsi->elf_paddr_offset + dsi->v_start;
        if ( (vaddr + phdr->p_memsz) < vaddr )
        {
            printk("ERROR: ELF program header %d is too large.\n", h);
            return -EINVAL;
        }

        if ( vaddr < kernstart )
            kernstart = vaddr;
        if ( (vaddr + phdr->p_memsz) > kernend )
            kernend = vaddr + phdr->p_memsz;
    }

    dsi->v_kernentry = ehdr->e_entry;

    virt_entry =
        xen_elfnote_numeric(dsi, XEN_ELFNOTE_ENTRY, &virt_entry_defined);
    if ( virt_entry_defined )
        dsi->v_kernentry = virt_entry;

    if ( (kernstart > kernend) ||
         (dsi->v_kernentry < kernstart) ||
         (dsi->v_kernentry > kernend) ||
         (dsi->v_start > kernstart) )
    {
        printk("ERROR: ELF start or entries are out of bounds.\n");
        return -EINVAL;
    }

    p = xen_elfnote_string(dsi, XEN_ELFNOTE_BSD_SYMTAB);
    if ( p != NULL && strncmp(p, "yes", 3) == 0 )
        dsi->load_symtab = 1;

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_end       = dsi->v_kernend;

    loadelfsymtab(dsi, 0);

    return 0;
}

int loadelfimage(struct domain_setup_info *dsi)
{
    char *image = (char *)dsi->image_addr;
    Elf_Ehdr *ehdr = (Elf_Ehdr *)dsi->image_addr;
    Elf_Phdr *phdr;
    unsigned long vaddr;
    int h;
  
    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (Elf_Phdr *)(image + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        vaddr = phdr->p_paddr - dsi->elf_paddr_offset + dsi->v_start;
        if ( phdr->p_filesz != 0 )
            memcpy((char *)vaddr, image + phdr->p_offset, phdr->p_filesz);
        if ( phdr->p_memsz > phdr->p_filesz )
            memset((char *)vaddr + phdr->p_filesz, 0,
                   phdr->p_memsz - phdr->p_filesz);
    }

    loadelfsymtab(dsi, 1);

    return 0;
}

#define ELFROUND (ELFSIZE / 8)

static void loadelfsymtab(struct domain_setup_info *dsi, int doload)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)dsi->image_addr, *sym_ehdr;
    Elf_Shdr *shdr;
    unsigned long maxva, symva;
    char *p, *image = (char *)dsi->image_addr;
    int h, i;

    if ( !dsi->load_symtab )
        return;

    maxva = (dsi->v_kernend + ELFROUND - 1) & ~(ELFROUND - 1);
    symva = maxva;
    maxva += sizeof(int);
    dsi->symtab_addr = maxva;
    dsi->symtab_len = 0;
    maxva += sizeof(Elf_Ehdr) + ehdr->e_shnum * sizeof(Elf_Shdr);
    maxva = (maxva + ELFROUND - 1) & ~(ELFROUND - 1);
    if ( doload )
    {
        p = (void *)symva;
        shdr = (Elf_Shdr *)(p + sizeof(int) + sizeof(Elf_Ehdr));
        memcpy(shdr, image + ehdr->e_shoff, ehdr->e_shnum*sizeof(Elf_Shdr));
    } 
    else
    {
        p = NULL;
        shdr = (Elf_Shdr *)(image + ehdr->e_shoff);
    }

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
                if (doload) {
                    shdr[h].sh_offset = 0;
                }
                continue;
            }
        }

        if ( (shdr[h].sh_type == SHT_STRTAB) ||
             (shdr[h].sh_type == SHT_SYMTAB) )
        {
            if (doload) {
                memcpy((void *)maxva, image + shdr[h].sh_offset,
                       shdr[h].sh_size);

                /* Mangled to be based on ELF header location. */
                shdr[h].sh_offset = maxva - dsi->symtab_addr;

            }
            dsi->symtab_len += shdr[h].sh_size;
            maxva += shdr[h].sh_size;
            maxva = (maxva + ELFROUND - 1) & ~(ELFROUND - 1);
        }

        if ( doload )
            shdr[h].sh_name = 0;  /* Name is NULL. */
    }

    if ( dsi->symtab_len == 0 )
    {
        dsi->symtab_addr = 0;
        return;
    }

    if ( doload )
    {
        *(int *)p = maxva - dsi->symtab_addr;
        sym_ehdr = (Elf_Ehdr *)(p + sizeof(int));
        memcpy(sym_ehdr, ehdr, sizeof(Elf_Ehdr));
        sym_ehdr->e_phoff = 0;
        sym_ehdr->e_shoff = sizeof(Elf_Ehdr);
        sym_ehdr->e_phentsize = 0;
        sym_ehdr->e_phnum = 0;
        sym_ehdr->e_shstrndx = SHN_UNDEF;
    }

    dsi->symtab_len = maxva - dsi->symtab_addr;
    dsi->v_end      = maxva;
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
