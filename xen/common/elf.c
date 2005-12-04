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

static void loadelfsymtab(struct domain_setup_info *dsi, int doload);
static inline int is_loadable_phdr(Elf_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

int parseelfimage(struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)dsi->image_addr;
    Elf_Phdr *phdr;
    Elf_Shdr *shdr;
    unsigned long kernstart = ~0UL, kernend=0UL;
    char *shstrtab, *guestinfo=NULL, *p;
    char *elfbase = (char *)dsi->image_addr;
    int h;

    if ( !elf_sanity_check(ehdr) )
        return -EINVAL;

    if ( (ehdr->e_phoff + (ehdr->e_phnum*ehdr->e_phentsize)) > dsi->image_len )
    {
        printk("ELF program headers extend beyond end of image.\n");
        return -EINVAL;
    }

    if ( (ehdr->e_shoff + (ehdr->e_shnum*ehdr->e_shentsize)) > dsi->image_len )
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
        printk("Xen-ELF header found: '%s'\n", guestinfo);

        if ( (strstr(guestinfo, "LOADER=generic") == NULL) &&
             (strstr(guestinfo, "GUEST_OS=linux") == NULL) )
        {
            printk("ERROR: Xen will only load images built for the generic "
                   "loader or Linux images\n");
            return -EINVAL;
        }

        if ( (strstr(guestinfo, "XEN_VER=xen-3.0") == NULL) )
        {
            printk("ERROR: Xen will only load images built for Xen v3.0\n");
            return -EINVAL;
        }

        break;
    }

    dsi->xen_section_string = guestinfo;

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
        printk("Malformed ELF image.\n");
        return -EINVAL;
    }

    dsi->v_start = kernstart;

    if ( guestinfo != NULL )
    {
        if ( (p = strstr(guestinfo, "VIRT_BASE=")) != NULL )
            dsi->v_start = simple_strtoul(p+10, &p, 0);

        if ( (p = strstr(guestinfo, "BSD_SYMTAB")) != NULL )
            dsi->load_symtab = 1;
    }

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_kernentry = ehdr->e_entry;
    dsi->v_end       = dsi->v_kernend;

    loadelfsymtab(dsi, 0);

    return 0;
}

int loadelfimage(struct domain_setup_info *dsi)
{
    char *elfbase = (char *)dsi->image_addr;
    Elf_Ehdr *ehdr = (Elf_Ehdr *)dsi->image_addr;
    Elf_Phdr *phdr;
    int h;
  
    for ( h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        if ( phdr->p_filesz != 0 )
            memcpy((char *)phdr->p_paddr, elfbase + phdr->p_offset, 
                   phdr->p_filesz);
        if ( phdr->p_memsz > phdr->p_filesz )
            memset((char *)phdr->p_paddr + phdr->p_filesz, 0, 
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
    char *p, *elfbase = (char *)dsi->image_addr;
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
        memcpy(shdr, elfbase + ehdr->e_shoff, ehdr->e_shnum*sizeof(Elf_Shdr));
    } 
    else
    {
        p = NULL;
        shdr = (Elf_Shdr *)(elfbase + ehdr->e_shoff);
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
                memcpy((void *)maxva, elfbase + shdr[h].sh_offset,
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
