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

#ifdef CONFIG_X86
#define FORCE_XENELF_IMAGE 1
#define ELF_ADDR           p_vaddr
#elif defined(__ia64__)
#define FORCE_XENELF_IMAGE 0
#define ELF_ADDR           p_paddr
#endif

static inline int is_loadable_phdr(Elf_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

int parseelfimage(char *elfbase, 
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
        printk("Kernel image does not have an ELF header.\n");
        return -EINVAL;
    }

    if ( (ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize)) > elfsize )
    {
        printk("ELF program headers extend beyond end of image.\n");
        return -EINVAL;
    }

    if ( (ehdr->e_shoff + (ehdr->e_shnum * ehdr->e_shentsize)) > elfsize )
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

        if ( (strstr(guestinfo, "XEN_VER=2.0") == NULL) )
        {
            printk("ERROR: Xen will only load images built for Xen v2.0\n");
            return -EINVAL;
        }

        break;
    }
    if ( guestinfo == NULL )
    {
        printk("Not a Xen-ELF image: '__xen_guest' section not found.\n");
#ifndef FORCE_XENELF_IMAGE
        return -EINVAL;
#endif
    }

    for ( h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        if ( phdr->ELF_ADDR < kernstart )
            kernstart = phdr->ELF_ADDR;
        if ( (phdr->ELF_ADDR + phdr->p_memsz) > kernend )
            kernend = phdr->ELF_ADDR + phdr->p_memsz;
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
        
        if ( (p = strstr(guestinfo, "PT_MODE_WRITABLE")) != NULL )
            dsi->use_writable_pagetables = 1;
    }

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_kernentry = ehdr->e_entry;

    return 0;
}

int loadelfimage(char *elfbase)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase;
    Elf_Phdr *phdr;
    int h;
  
    for ( h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        if ( phdr->p_filesz != 0 )
            memcpy((char *)phdr->ELF_ADDR, elfbase + phdr->p_offset, 
                   phdr->p_filesz);
        if ( phdr->p_memsz > phdr->p_filesz )
            memset((char *)phdr->ELF_ADDR + phdr->p_filesz, 0, 
                   phdr->p_memsz - phdr->p_filesz);
    }

    return 0;
}
