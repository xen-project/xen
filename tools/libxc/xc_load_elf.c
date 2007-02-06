/******************************************************************************
 * xc_elf_load.c
 */

#include "xg_private.h"
#include "xc_elf.h"
#include <stdlib.h>
#include <inttypes.h>

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
#define ELFCLASS_DESC "64-bit"

#define ELFDATA    ELFDATA2LSB
#define ELFDATA_DESC "Little-Endian"

#define ELFMACHINE EM_IA_64
#define ELFMACHINE_DESC "ia64"


#elif defined(__i386__)
#define ELFCLASS   ELFCLASS32
#define ELFCLASS_DESC "32-bit"

#define ELFDATA    ELFDATA2LSB
#define ELFDATA_DESC "Little-Endian"

#define ELFMACHINE EM_386
#define ELFMACHINE_DESC "i386"


#elif defined(__x86_64__)
#define ELFCLASS   ELFCLASS64
#define ELFCLASS_DESC "64-bit"

#define ELFDATA    ELFDATA2LSB
#define ELFDATA_DESC "Little-Endian"

#define ELFMACHINE EM_X86_64
#define ELFMACHINE_DESC "x86_64"


#elif defined(__powerpc__)
#define ELFCLASS   ELFCLASS64
#define ELFCLASS_DESC "64-bit"

#define ELFDATA    ELFDATA2MSB
#define ELFDATA_DESC "Big-Endian"

#define ELFMACHINE EM_PPC64
#define ELFMACHINE_DESC "ppc64"
#endif

int probe_elf(const char *image,
              unsigned long image_size,
              struct load_funcs *load_funcs)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)image;

    if ( !IS_ELF(*ehdr) )
        return -EINVAL;

    load_funcs->parseimage = parseelfimage;
    load_funcs->loadimage = loadelfimage;

    return 0;
}

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

static const char *xen_guest_lookup(
    const struct domain_setup_info *dsi, int type)
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

static const char *xen_guest_string(
    const struct domain_setup_info *dsi, int type)
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

static unsigned long long xen_guest_numeric(
    const struct domain_setup_info *dsi, int type, int *defined)
{
    const char *p = xen_guest_lookup(dsi, type);
    unsigned long long value;

    if ( p == NULL )
        return 0;

    errno = 0;
    value = strtoull(p, NULL, 0);
    if ( errno < 0 )
        return 0;

    /* We special case this since __xen_guest_section contains a PFN
     * for this field not a virtual address.
     */
    if (type == XEN_ELFNOTE_HYPERCALL_PAGE)
        value = dsi->v_start + (value<<PAGE_SHIFT);

    *defined = 1;
    return value;
}

/*
 * Interface to the Xen ELF notes.
 */
#define ELFNOTE_NAME(_n_)   ((const char*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_DESC(_n_)   (ELFNOTE_NAME(_n_) + (((_n_)->namesz+3)&~3))
#define ELFNOTE_NEXT(_n_)   (ELFNOTE_DESC(_n_) + (((_n_)->descsz+3)&~3))

static int is_xen_elfnote_section(const char *image, const Elf_Shdr *shdr)
{
    const Elf_Note *note;

    if ( shdr->sh_type != SHT_NOTE )
        return 0;

    for ( note = (const Elf_Note *)(image + shdr->sh_offset);
          note < (const Elf_Note *)(image + shdr->sh_offset + shdr->sh_size);
          note = (const Elf_Note *)ELFNOTE_NEXT(note) )
    {
        if ( !strncmp(ELFNOTE_NAME(note), "Xen", 4) )
            return 1;
    }

    return 0;
}

static const Elf_Note *xen_elfnote_lookup(
    const struct domain_setup_info *dsi, int type)
{
    const Elf_Note *note;

    if ( !dsi->__elfnote_section )
        return NULL;

    for ( note = (const Elf_Note *)dsi->__elfnote_section;
          note < (const Elf_Note *)dsi->__elfnote_section_end;
          note = (const Elf_Note *)ELFNOTE_NEXT(note) )
    {
        if ( strncmp(ELFNOTE_NAME(note), "Xen", 4) )
            continue;

        if ( note->type == type )
            return note;
    }

    return NULL;
}

const char *xen_elfnote_string(const struct domain_setup_info *dsi, int type)
{
    const Elf_Note *note;

    if ( !dsi->__elfnote_section )
        return xen_guest_string(dsi, type);

    note = xen_elfnote_lookup(dsi, type);
    if ( note == NULL )
        return NULL;

    return (const char *)ELFNOTE_DESC(note);
}

unsigned long long xen_elfnote_numeric(const struct domain_setup_info *dsi,
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
        xc_set_error(XC_INVALID_KERNEL,
                     "elfnotes: unknown data size %#x for numeric type note %#x\n",
              note->descsz, type);
        return 0;
    }
}

static int parseelfimage(const char *image,
                         unsigned long image_len,
                         struct domain_setup_info *dsi)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)image;
    const Elf_Phdr *phdr;
    const Elf_Shdr *shdr;
    Elf_Addr kernstart = ~0, kernend = 0, vaddr, virt_entry;
    const char *shstrtab, *p;
    int h, virt_base_defined, elf_pa_off_defined, virt_entry_defined;

    if ( !IS_ELF(*ehdr) )
    {
        xc_set_error(XC_INVALID_KERNEL,
                     "Kernel image does not have an ELF header.");
        return -EINVAL;
    }

    if (ehdr->e_machine != ELFMACHINE)
    {
        xc_set_error(XC_INVALID_KERNEL,
                     "Kernel ELF architecture '%d' does not match Xen architecture '%d' (%s)",
                     ehdr->e_machine, ELFMACHINE, ELFMACHINE_DESC);
        return -EINVAL;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS)
    {
        xc_set_error(XC_INVALID_KERNEL,
                     "Kernel ELF wordsize '%d' does not match Xen wordsize '%d' (%s)",
                     ehdr->e_ident[EI_CLASS], ELFCLASS, ELFCLASS_DESC);
        return -EINVAL;
    }
    if (ehdr->e_ident[EI_DATA] != ELFDATA)
    {
        xc_set_error(XC_INVALID_KERNEL,
                     "Kernel ELF endianness '%d' does not match Xen endianness '%d' (%s)",
                     ehdr->e_ident[EI_DATA], ELFDATA, ELFDATA_DESC);
        return -EINVAL;
    }
    if (ehdr->e_type != ET_EXEC)
    {
        xc_set_error(XC_INVALID_KERNEL,
                     "Kernel ELF type '%d' does not match Xen type '%d'",
                     ehdr->e_type, ET_EXEC);
        return -EINVAL;
    }

    if ( (ehdr->e_phoff + (ehdr->e_phnum*ehdr->e_phentsize)) > image_len )
    {
        xc_set_error(XC_INVALID_KERNEL,
                     "ELF program headers extend beyond end of image.");
        return -EINVAL;
    }

    if ( (ehdr->e_shoff + (ehdr->e_shnum*ehdr->e_shentsize)) > image_len )
    {
        xc_set_error(XC_INVALID_KERNEL,
                     "ELF section headers extend beyond end of image.");
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
            xc_set_error(XC_INVALID_KERNEL,
                         "ELF image has no section-header strings table.");
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
            xc_set_error(XC_INVALID_KERNEL,
                         "Will only load images built for the generic loader "
                         "or Linux images");
            return -EINVAL;
        }

        if ( xen_version == NULL || strncmp(xen_version, "xen-3.0", 7) )
        {
            xc_set_error(XC_INVALID_KERNEL,
                         "Will only load images built for Xen v3.0");
            return -EINVAL;
        }
    }
    else
    {
#if defined(__x86_64__) || defined(__i386__)
        xc_set_error(XC_INVALID_KERNEL,
                     "Not a Xen-ELF image: "
                     "No ELF notes or '__xen_guest' section found.");
        return -EINVAL;
#endif
    }

    /*
     * A "bimodal" ELF note indicates the kernel will adjust to the current
     * paging mode, including handling extended cr3 syntax.  If we have ELF
     * notes then PAE=yes implies that we must support the extended cr3 syntax.
     * Otherwise we need to find the [extended-cr3] syntax in the __xen_guest
     * string. We use strstr() to look for "bimodal" to allow guests to use
     * "yes,bimodal" or "no,bimodal" for compatibility reasons.
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
        xc_set_error(XC_INVALID_KERNEL,
                     "Neither ELF_PADDR_OFFSET nor VIRT_BASE found in ELF "
                     " notes or __xen_guest section.");
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
            xc_set_error(XC_INVALID_KERNEL,
                         "ELF program header %d is too large.", h);
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
        xc_set_error(XC_INVALID_KERNEL,
                     "ELF start or entries are out of bounds.");
        return -EINVAL;
    }

    p = xen_elfnote_string(dsi, XEN_ELFNOTE_BSD_SYMTAB);
    if ( p != NULL && strncmp(p, "yes", 3) == 0 )
        dsi->load_symtab = 1;

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_end       = dsi->v_kernend;

    loadelfsymtab(image, 0, 0, NULL, dsi);

    return 0;
}

static int
loadelfimage(
    const char *image, unsigned long elfsize, int xch, uint32_t dom,
    xen_pfn_t *parray, struct domain_setup_info *dsi)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)image;
    const Elf_Phdr *phdr;
    int h;

    char         *va;
    unsigned long pa, done, chunksz;

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (const Elf_Phdr *)(
            image + ehdr->e_phoff + (h*ehdr->e_phentsize));
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
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)image;
    Elf_Ehdr *sym_ehdr;
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
