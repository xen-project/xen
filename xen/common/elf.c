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
static inline int is_loadable_phdr(Elf_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

/*
 * Interface to the Xen ELF notes.
 */
#define ELFNOTE_NAME(_n_)   ((void*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_DESC(_n_)   (ELFNOTE_NAME(_n_) + (((_n_)->namesz+3)&~3))
#define ELFNOTE_NEXT(_n_)   (ELFNOTE_DESC(_n_) + (((_n_)->descsz+3)&~3))

static int is_xen_elfnote_section(const char *image, Elf_Shdr *shdr)
{
    Elf_Note *note;

    if ( shdr->sh_type != SHT_NOTE )
        return 0;

    for ( note = (Elf_Note *)(image + shdr->sh_offset);
          note < (Elf_Note *)(image + shdr->sh_offset + shdr->sh_size);
          note = ELFNOTE_NEXT(note) )
    {
        if ( !strncmp(ELFNOTE_NAME(note), "Xen", 4) )
            return 1;
    }

    return 0;
}

static Elf_Note *xen_elfnote_lookup(struct domain_setup_info *dsi, int type)
{
    Elf_Note *note;

    if ( !dsi->__elfnote_section )
        return NULL;

    for ( note = (Elf_Note *)dsi->__elfnote_section;
          note < (Elf_Note *)dsi->__elfnote_section_end;
          note = ELFNOTE_NEXT(note) )
    {
        if ( strncmp(ELFNOTE_NAME(note), "Xen", 4) )
            continue;

        if ( note->type == type )
            return note;
    }

    DPRINTK("unable to find Xen ELF note with type %#x\n", type);
    return NULL;
}

const char *xen_elfnote_string(struct domain_setup_info *dsi, int type)
{
    Elf_Note *note;

    note = xen_elfnote_lookup(dsi, type);
    if ( note == NULL )
        return NULL;

    DPRINTK("found Xen ELF note type %#x = \"%s\"\n",
            type, (char *)ELFNOTE_DESC(note));

    return (const char *)ELFNOTE_DESC(note);
}

unsigned long long xen_elfnote_numeric(struct domain_setup_info *dsi,
                                       int type, int *defined)
{
    Elf_Note *note;

    *defined = 0;

    note = xen_elfnote_lookup(dsi, type);
    if ( note == NULL )
    {
        return 0;
    }

    switch ( note->descsz )
    {
    case 4:
        *defined = 1;
        return *(uint32_t*)ELFNOTE_DESC(note);
    case 8:
        *defined = 1;
        return *(uint64_t*)ELFNOTE_DESC(note);
    default:
        return 0;
    }
}

int parseelfimage(struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)dsi->image_addr;
    Elf_Phdr *phdr;
    Elf_Shdr *shdr;
    Elf_Addr kernstart = ~0, kernend = 0, vaddr, virt_entry;
    const char *shstrtab, *p;
    const char *image = (char *)dsi->image_addr;
    const unsigned long image_len = dsi->image_len;
    int h, virt_base_defined, elf_pa_off_defined, virt_entry_defined;

    if ( !elf_sanity_check(ehdr) )
        return -EINVAL;

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

    /* Find the section-header strings table. */
    if ( ehdr->e_shstrndx == SHN_UNDEF )
    {
        printk("ELF image has no section-header strings table (shstrtab).\n");
        return -EINVAL;
    }
    shdr = (Elf_Shdr *)(image + ehdr->e_shoff +
                        (ehdr->e_shstrndx*ehdr->e_shentsize));
    shstrtab = image + shdr->sh_offset;

    dsi->__elfnote_section = NULL;

    /* Look for .notes segment containing at least one Xen note */
    for ( h = 0; h < ehdr->e_shnum; h++ )
    {
        shdr = (Elf_Shdr *)(image + ehdr->e_shoff + (h*ehdr->e_shentsize));
        if ( !is_xen_elfnote_section(image, shdr) )
            continue;
        dsi->__elfnote_section = (void *)image + shdr->sh_offset;
        dsi->__elfnote_section_end =
            (void *)image + shdr->sh_offset + shdr->sh_size;
        break;
    }

    /* Check the contents of the Xen notes. */
    if ( dsi->__elfnote_section )
    {
        const char *loader = xen_elfnote_string(dsi, XEN_ELFNOTE_LOADER);
        const char *guest_os = xen_elfnote_string(dsi, XEN_ELFNOTE_GUEST_OS);
        const char *xen_version =
            xen_elfnote_string(dsi, XEN_ELFNOTE_XEN_VERSION);

        if ( ( loader == NULL || strcmp(loader, "generic") ) &&
             ( guest_os == NULL || strcmp(guest_os, "linux") ) )
        {
            printk("ERROR: Will only load images built for the generic "
                   "loader or Linux images");
            return -EINVAL;
        }

        if ( xen_version == NULL || strcmp(xen_version, "xen-3.0") )
        {
            printk("ERROR: Xen will only load images built for Xen v3.0\n");
        }
    }

    /* Initial guess for v_start is 0 if it is not explicitly defined. */
    dsi->v_start =
        xen_elfnote_numeric(dsi, XEN_ELFNOTE_VIRT_BASE, &virt_base_defined);
    if ( !virt_base_defined )
        dsi->v_start = 0;

    /* We are using the ELF notes interface so the default is 0. */
    dsi->elf_paddr_offset =
        xen_elfnote_numeric(dsi, XEN_ELFNOTE_PADDR_OFFSET, &elf_pa_off_defined);
    if ( !elf_pa_off_defined )
        dsi->elf_paddr_offset = 0;

    if ( elf_pa_off_defined && !virt_base_defined )
    {
        printk("ERROR: Neither ELF_PADDR_OFFSET nor VIRT_BASE found in"
               " Xen ELF notes.\n");
        return -EINVAL;
    }

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (Elf_Phdr *)(image + ehdr->e_phoff + (h*ehdr->e_phentsize));
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
    if ( p != NULL && strcmp(p, "yes") == 0 )
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
