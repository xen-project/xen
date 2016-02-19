/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

const struct xsplice_elf_sec *xsplice_elf_sec_by_name(const struct xsplice_elf *elf,
                                                      const char *name)
{
    unsigned int i;

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( !strcmp(name, elf->sec[i].name) )
            return &elf->sec[i];
    }

    return NULL;
}

static int elf_verify_strtab(const struct xsplice_elf_sec *sec)
{
    const Elf_Shdr *s;
    const char *contents;

    s = sec->sec;

    if ( s->sh_type != SHT_STRTAB )
        return -EINVAL;

    if ( !s->sh_size )
        return -EINVAL;

    contents = sec->data;

    if ( contents[0] || contents[s->sh_size - 1] )
        return -EINVAL;

    return 0;
}

static int elf_resolve_sections(struct xsplice_elf *elf, const void *data)
{
    struct xsplice_elf_sec *sec;
    unsigned int i;
    Elf_Off delta;
    int rc;

    /* xsplice_elf_load sanity checked e_shnum. */
    sec = xmalloc_array(struct xsplice_elf_sec, elf->hdr->e_shnum);
    if ( !sec )
    {
        dprintk(XENLOG_ERR, XSPLICE"%s: Could not allocate memory for section table!\n",
               elf->name);
        return -ENOMEM;
    }

    elf->sec = sec;

    /* e_shoff and e_shnum overflow checks are done in xsplice_header_check. */
    delta = elf->hdr->e_shoff + elf->hdr->e_shnum * elf->hdr->e_shentsize;
    ASSERT(delta <= elf->len);

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        delta = elf->hdr->e_shoff + i * elf->hdr->e_shentsize;

        sec[i].sec = data + delta;

        delta = sec[i].sec->sh_offset;
        /*
         * N.B. elf_resolve_section_names, elf_get_sym skip this check as
         * we do it here.
         */
        if ( delta < sizeof(Elf_Ehdr) ||
             (sec[i].sec->sh_type != SHT_NOBITS && /* Skip SHT_NOBITS */
              (delta > elf->len || (delta + sec[i].sec->sh_size > elf->len))) )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Section [%u] data %s of payload!\n",
                    elf->name, i,
                    delta < sizeof(Elf_Ehdr) ? "at ELF header" : "is past end");
            return -EINVAL;
        }

        sec[i].data = data + delta;
        /* Name is populated in elf_resolve_section_names. */
        sec[i].name = NULL;

        if ( sec[i].sec->sh_type == SHT_SYMTAB )
        {
            if ( elf->symtab )
            {
                dprintk(XENLOG_ERR, XSPLICE "%s: Unsupported multiple symbol tables!\n",
                        elf->name);
                return -EOPNOTSUPP;
            }

            elf->symtab = &sec[i];

            /*
             * elf->symtab->sec->sh_link would point to the right section
             * but we hadn't finished parsing all the sections.
             */
            if ( elf->symtab->sec->sh_link >= elf->hdr->e_shnum )
            {
                dprintk(XENLOG_ERR, XSPLICE
                        "%s: Symbol table idx (%u) to strtab past end (%u)\n",
                        elf->name, elf->symtab->sec->sh_link,
                        elf->hdr->e_shnum);
                return -EINVAL;
            }
        }
    }

    if ( !elf->symtab )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: No symbol table found!\n",
                elf->name);
        return -EINVAL;
    }

    if ( !elf->symtab->sec->sh_size ||
         elf->symtab->sec->sh_entsize < sizeof(Elf_Sym) ||
         elf->symtab->sec->sh_size % elf->symtab->sec->sh_entsize )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Symbol table header is corrupted!\n",
                elf->name);
        return -EINVAL;
    }

    /*
     * There can be multiple SHT_STRTAB (.shstrtab, .strtab) so pick the one
     * associated with the symbol table.
     */
    elf->strtab = &sec[elf->symtab->sec->sh_link];

    rc = elf_verify_strtab(elf->strtab);
    if ( rc )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: String table section is corrupted\n",
                elf->name);
    }

    return rc;
}

static int elf_resolve_section_names(struct xsplice_elf *elf, const void *data)
{
    const char *shstrtab;
    unsigned int i;
    Elf_Off offset, delta;
    struct xsplice_elf_sec *sec;
    int rc;

    /*
     * The elf->sec[0 -> e_shnum] structures have been verified by
     * elf_resolve_sections. Find file offset for section string table
     * (normally called .shstrtab)
     */
    sec = &elf->sec[elf->hdr->e_shstrndx];

    rc = elf_verify_strtab(sec);
    if ( rc )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Section string table is corrupted\n",
                elf->name);
        return rc;
    }

    /* Verified in elf_resolve_sections but just in case. */
    offset = sec->sec->sh_offset;
    ASSERT(offset < elf->len && (offset + sec->sec->sh_size <= elf->len));

    shstrtab = data + offset;

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        delta = elf->sec[i].sec->sh_name;

        /* Boundary check on offset of name within the .shstrtab. */
        if ( delta >= sec->sec->sh_size )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Section %u name is not within .shstrtab!\n",
                    elf->name, i);
            return -EINVAL;
        }

        elf->sec[i].name = shstrtab + delta;
    }

    return 0;
}

static int elf_get_sym(struct xsplice_elf *elf, const void *data)
{
    const struct xsplice_elf_sec *symtab_sec, *strtab_sec;
    struct xsplice_elf_sym *sym;
    unsigned int i, nsym;
    Elf_Off offset;
    Elf_Word delta;

    symtab_sec = elf->symtab;
    strtab_sec = elf->strtab;

    /* Pointers arithmetic to get file offset. */
    offset = strtab_sec->data - data;

    /* Checked already in elf_resolve_sections, but just in case. */
    ASSERT(offset == strtab_sec->sec->sh_offset);
    ASSERT(offset < elf->len && (offset + strtab_sec->sec->sh_size <= elf->len));

    /* symtab_sec->data was computed in elf_resolve_sections. */
    ASSERT((symtab_sec->sec->sh_offset + data) == symtab_sec->data);

    /* No need to check values as elf_resolve_sections did it. */
    nsym = symtab_sec->sec->sh_size / symtab_sec->sec->sh_entsize;

    sym = xmalloc_array(struct xsplice_elf_sym, nsym);
    if ( !sym )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Could not allocate memory for symbols\n",
               elf->name);
        return -ENOMEM;
    }

    /* So we don't leak memory. */
    elf->sym = sym;

    for ( i = 1; i < nsym; i++ )
    {
        const Elf_Sym *s = symtab_sec->data + symtab_sec->sec->sh_entsize * i;

        delta = s->st_name;
        /* Boundary check within the .strtab. */
        if ( delta >= strtab_sec->sec->sh_size )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Symbol [%u] name is not within .strtab!\n",
                    elf->name, i);
            return -EINVAL;
        }

        sym[i].sym = s;
        sym[i].name = strtab_sec->data + delta;
    }
    elf->nsym = nsym;

    return 0;
}

static int xsplice_header_check(const struct xsplice_elf *elf)
{
    const Elf_Ehdr *hdr = elf->hdr;

    if ( sizeof(*elf->hdr) > elf->len )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Section header is bigger than payload!\n",
                elf->name);
        return -EINVAL;
    }

    if ( !IS_ELF(*hdr) )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Not an ELF payload!\n", elf->name);
        return -EINVAL;
    }

    /* EI_CLASS, EI_DATA, and e_flags are platform specific. */
    if ( hdr->e_version != EV_CURRENT ||
         hdr->e_ident[EI_VERSION] != EV_CURRENT ||
         hdr->e_ident[EI_ABIVERSION] != 0 ||
         hdr->e_ident[EI_OSABI] != ELFOSABI_SYSV ||
         hdr->e_type != ET_REL ||
         hdr->e_phnum != 0 )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Invalid ELF payload!\n", elf->name);
        return -EOPNOTSUPP;
    }

    if ( elf->hdr->e_shstrndx == SHN_UNDEF )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Section name idx is undefined!?\n",
                elf->name);
        return -EINVAL;
    }

    /* Arbitrary boundary limit. */
    if ( elf->hdr->e_shnum >= 1024 )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Too many (%u) sections!\n",
                elf->name, elf->hdr->e_shnum);
        return -EOPNOTSUPP;
    }

    /* Check that section name index is within the sections. */
    if ( elf->hdr->e_shstrndx >= elf->hdr->e_shnum )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Section name idx (%u) is past end of sections (%u)!\n",
                elf->name, elf->hdr->e_shstrndx, elf->hdr->e_shnum);
        return -EINVAL;
    }

    if ( elf->hdr->e_shoff >= elf->len )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Bogus e_shoff!\n", elf->name);
        return -EINVAL;
    }

    if ( elf->hdr->e_shentsize < sizeof(Elf_Shdr) )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Section header size is %u! Expected %zu!?\n",
                elf->name, elf->hdr->e_shentsize, sizeof(Elf_Shdr));
        return -EINVAL;
    }

    if ( ((elf->len - elf->hdr->e_shoff) / elf->hdr->e_shentsize) <
         elf->hdr->e_shnum )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Section header size is corrupted!\n",
                elf->name);
        return -EINVAL;
    }

    return 0;
}

int xsplice_elf_load(struct xsplice_elf *elf, const void *data)
{
    int rc;

    elf->hdr = data;

    rc = xsplice_header_check(elf);
    if ( rc )
        return rc;

    rc = elf_resolve_sections(elf, data);
    if ( rc )
        return rc;

    rc = elf_resolve_section_names(elf, data);
    if ( rc )
        return rc;

    rc = elf_get_sym(elf, data);
    if ( rc )
        return rc;

    return 0;
}

void xsplice_elf_free(struct xsplice_elf *elf)
{
    xfree(elf->sec);
    elf->sec = NULL;
    xfree(elf->sym);
    elf->sym = NULL;
    elf->nsym = 0;
    elf->name = NULL;
    elf->len = 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
