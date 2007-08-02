/*
 * parse and load elf binaries
 */

#include "libelf-private.h"

/* ------------------------------------------------------------------------ */

int elf_init(struct elf_binary *elf, const char *image, size_t size)
{
    const elf_shdr *shdr;
    uint64_t i, count, section, offset;
    uint64_t low = -1;
    uint64_t high = 0;

    if ( !elf_is_elfbinary(image) )
    {
        elf_err(elf, "%s: not an ELF binary\n", __FUNCTION__);
        return -1;
    }

    memset(elf, 0, sizeof(*elf));
    elf->image = image;
    elf->size = size;
    elf->ehdr = (elf_ehdr *) image;
    elf->class = elf->ehdr->e32.e_ident[EI_CLASS];
    elf->data = elf->ehdr->e32.e_ident[EI_DATA];

#ifdef VERBOSE
    elf_set_verbose(elf);
#endif

    /* Sanity check phdr. */
    offset = elf_uval(elf, elf->ehdr, e_phoff) +
        elf_uval(elf, elf->ehdr, e_phentsize) * elf_phdr_count(elf);
    if ( offset > elf->size )
    {
        elf_err(elf, "%s: phdr overflow (off %" PRIx64 " > size %lx)\n",
                __FUNCTION__, offset, (unsigned long)elf->size);
        return -1;
    }

    /* Sanity check shdr. */
    offset = elf_uval(elf, elf->ehdr, e_shoff) +
        elf_uval(elf, elf->ehdr, e_shentsize) * elf_shdr_count(elf);
    if ( offset > elf->size )
    {
        elf_err(elf, "%s: shdr overflow (off %" PRIx64 " > size %lx)\n",
                __FUNCTION__, offset, (unsigned long)elf->size);
        return -1;
    }

    /* Find section string table. */
    section = elf_uval(elf, elf->ehdr, e_shstrndx);
    shdr = elf_shdr_by_index(elf, section);
    if ( shdr != NULL )
        elf->sec_strtab = elf_section_start(elf, shdr);

    /* Find symbol table and symbol string table. */
    count = elf_shdr_count(elf);
    for ( i = 0; i < count; i++ )
    {
        const char *sh_symend, *sh_strend;

        shdr = elf_shdr_by_index(elf, i);
        if ( elf_uval(elf, shdr, sh_type) != SHT_SYMTAB )
            continue;
        elf->sym_tab = shdr;
        sh_symend = (const char *)elf_section_end(elf, shdr);
        shdr = elf_shdr_by_index(elf, elf_uval(elf, shdr, sh_link));
        if ( shdr == NULL )
        {
            elf->sym_tab = NULL;
            sh_symend = 0;
            continue;
        }
        elf->sym_strtab = elf_section_start(elf, shdr);
        sh_strend = (const char *)elf_section_end(elf, shdr);

        if ( low > (unsigned long)elf->sym_tab )
            low = (unsigned long)elf->sym_tab;
        if ( low > (unsigned long)shdr )
            low = (unsigned long)shdr;

        if ( high < ((unsigned long)sh_symend) )
            high = (unsigned long)sh_symend;
        if ( high < ((unsigned long)sh_strend) )
            high = (unsigned long)sh_strend;

        elf_msg(elf, "%s: shdr: sym_tab=%p size=0x%" PRIx64 "\n",
                __FUNCTION__, elf->sym_tab,
                elf_uval(elf, elf->sym_tab, sh_size));
        elf_msg(elf, "%s: shdr: str_tab=%p size=0x%" PRIx64 "\n",
                __FUNCTION__, elf->sym_strtab, elf_uval(elf, shdr, sh_size));

        elf->sstart = low;
        elf->send = high;
        elf_msg(elf, "%s: symbol map: 0x%" PRIx64 " -> 0x%" PRIx64 "\n",
                __FUNCTION__, elf->sstart, elf->send);
    }

    return 0;
}

#ifndef __XEN__
void elf_set_logfile(struct elf_binary *elf, FILE * log, int verbose)
{
    elf->log = log;
    elf->verbose = verbose;
}
#else
void elf_set_verbose(struct elf_binary *elf)
{
    elf->verbose = 1;
}
#endif

void elf_parse_binary(struct elf_binary *elf)
{
    const elf_phdr *phdr;
    uint64_t low = -1;
    uint64_t high = 0;
    uint64_t i, count, paddr, memsz;

    count = elf_uval(elf, elf->ehdr, e_phnum);
    for ( i = 0; i < count; i++ )
    {
        phdr = elf_phdr_by_index(elf, i);
        if ( !elf_phdr_is_loadable(elf, phdr) )
            continue;
        paddr = elf_uval(elf, phdr, p_paddr);
        memsz = elf_uval(elf, phdr, p_memsz);
        elf_msg(elf, "%s: phdr: paddr=0x%" PRIx64
                " memsz=0x%" PRIx64 "\n", __FUNCTION__, paddr, memsz);
        if ( low > paddr )
            low = paddr;
        if ( high < paddr + memsz )
            high = paddr + memsz;
    }
    elf->pstart = low;
    elf->pend = high;
    elf_msg(elf, "%s: memory: 0x%" PRIx64 " -> 0x%" PRIx64 "\n",
            __FUNCTION__, elf->pstart, elf->pend);
}

void elf_load_binary(struct elf_binary *elf)
{
    const elf_phdr *phdr;
    uint64_t i, count, paddr, offset, filesz, memsz;
    char *dest;

    count = elf_uval(elf, elf->ehdr, e_phnum);
    for ( i = 0; i < count; i++ )
    {
        phdr = elf_phdr_by_index(elf, i);
        if ( !elf_phdr_is_loadable(elf, phdr) )
            continue;
        paddr = elf_uval(elf, phdr, p_paddr);
        offset = elf_uval(elf, phdr, p_offset);
        filesz = elf_uval(elf, phdr, p_filesz);
        memsz = elf_uval(elf, phdr, p_memsz);
        dest = elf_get_ptr(elf, paddr);
        elf_msg(elf, "%s: phdr %" PRIu64 " at 0x%p -> 0x%p\n",
                __func__, i, dest, dest + filesz);
        memcpy(dest, elf->image + offset, filesz);
        memset(dest + filesz, 0, memsz - filesz);
    }
}

void *elf_get_ptr(struct elf_binary *elf, unsigned long addr)
{
    return elf->dest + addr - elf->pstart;
}

uint64_t elf_lookup_addr(struct elf_binary * elf, const char *symbol)
{
    const elf_sym *sym;
    uint64_t value;

    sym = elf_sym_by_name(elf, symbol);
    if ( sym == NULL )
    {
        elf_err(elf, "%s: not found: %s\n", __FUNCTION__, symbol);
        return -1;
    }

    value = elf_uval(elf, sym, st_value);
    elf_msg(elf, "%s: symbol \"%s\" at 0x%" PRIx64 "\n", __FUNCTION__,
            symbol, value);
    return value;
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
