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
#if FORCE_XENELF_IMAGE
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

        if ( (p = strstr(guestinfo, "BSD_SYMTAB")) != NULL )
            dsi->load_bsd_symtab = 1;

    }

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_kernentry = ehdr->e_entry;

    dsi->v_end       = dsi->v_kernend;

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

#define ELFROUND (ELFSIZE / 8)

int loadelfsymtab(char *elfbase, int doload, struct domain_setup_info *dsi)
{
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elfbase, *sym_ehdr;
    Elf_Shdr *shdr;
    unsigned long maxva, symva;
    char *p;
    int h, i;

    maxva = (dsi->v_kernend + ELFROUND - 1) & ~(ELFROUND - 1);
    symva = maxva;
    maxva += sizeof(int);
    dsi->symtab_addr = maxva;
    dsi->symtab_len = 0;
    maxva += sizeof(Elf_Ehdr) + ehdr->e_shnum * sizeof(Elf_Shdr);
    maxva = (maxva + ELFROUND - 1) & ~(ELFROUND - 1);
    if (doload) {
	p = (void *)symva;

	shdr = (Elf_Shdr *)(p + sizeof(int) + sizeof(Elf_Ehdr));
	memcpy(shdr, elfbase + ehdr->e_shoff, ehdr->e_shnum * sizeof(Elf_Shdr));
    } else {
	shdr = (Elf_Shdr *)(elfbase + ehdr->e_shoff);
	p = NULL; /* XXX: gcc */
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

        if (doload) {
	    shdr[h].sh_name = 0;  /* Name is NULL. */
	}
    }

    if ( dsi->symtab_len == 0 )
    {
        dsi->symtab_addr = 0;
        goto out;
    }

    if (doload) {
	*(int *)p = maxva - dsi->symtab_addr;
	sym_ehdr = (Elf_Ehdr *)(p + sizeof(int));
	memcpy(sym_ehdr, ehdr, sizeof(Elf_Ehdr));
	sym_ehdr->e_phoff = 0;
	sym_ehdr->e_shoff = sizeof(Elf_Ehdr);
	sym_ehdr->e_phentsize = 0;
	sym_ehdr->e_phnum = 0;
	sym_ehdr->e_shstrndx = SHN_UNDEF;
    }

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK) /* XXX */

    dsi->symtab_len = maxva - dsi->symtab_addr;
    dsi->v_end = round_pgup(maxva);

 out:

    return 0;
}
