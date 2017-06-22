/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/symbols.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>

const struct livepatch_elf_sec *
livepatch_elf_sec_by_name(const struct livepatch_elf *elf,
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

static int elf_verify_strtab(const struct livepatch_elf_sec *sec)
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

static int elf_resolve_sections(struct livepatch_elf *elf, const void *data)
{
    struct livepatch_elf_sec *sec;
    unsigned int i;
    Elf_Off delta;
    int rc;

    /* livepatch_elf_load sanity checked e_shnum. */
    sec = xzalloc_array(struct livepatch_elf_sec, elf->hdr->e_shnum);
    if ( !sec )
    {
        dprintk(XENLOG_ERR, LIVEPATCH"%s: Could not allocate memory for section table!\n",
               elf->name);
        return -ENOMEM;
    }

    elf->sec = sec;

    /* e_shoff and e_shnum overflow checks are done in livepatch_header_check. */
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
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Section [%u] data %s of payload!\n",
                    elf->name, i,
                    delta < sizeof(Elf_Ehdr) ? "at ELF header" : "is past end");
            return -EINVAL;
        }
        else if ( (sec[i].sec->sh_flags & (SHF_WRITE | SHF_ALLOC)) &&
                  sec[i].sec->sh_type == SHT_NOBITS &&
                  sec[i].sec->sh_size > LIVEPATCH_MAX_SIZE )
            return -EINVAL;

        sec[i].data = data + delta;
        /* Name is populated in elf_resolve_section_names. */
        sec[i].name = NULL;

        if ( sec[i].sec->sh_type == SHT_SYMTAB )
        {
            if ( elf->symtab )
            {
                dprintk(XENLOG_ERR, LIVEPATCH "%s: Unsupported multiple symbol tables!\n",
                        elf->name);
                return -EOPNOTSUPP;
            }

            elf->symtab = &sec[i];

            elf->symtab_idx = i;
            /*
             * elf->symtab->sec->sh_link would point to the right section
             * but we hadn't finished parsing all the sections.
             */
            if ( elf->symtab->sec->sh_link >= elf->hdr->e_shnum )
            {
                dprintk(XENLOG_ERR, LIVEPATCH
                        "%s: Symbol table idx (%u) to strtab past end (%u)\n",
                        elf->name, elf->symtab->sec->sh_link,
                        elf->hdr->e_shnum);
                return -EINVAL;
            }
        }
    }

    if ( !elf->symtab )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: No symbol table found!\n",
                elf->name);
        return -EINVAL;
    }

    if ( !elf->symtab->sec->sh_size ||
         elf->symtab->sec->sh_entsize < sizeof(Elf_Sym) ||
         elf->symtab->sec->sh_size % elf->symtab->sec->sh_entsize )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Symbol table header is corrupted!\n",
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
        dprintk(XENLOG_ERR, LIVEPATCH "%s: String table section is corrupted\n",
                elf->name);
    }

    return rc;
}

static int elf_resolve_section_names(struct livepatch_elf *elf, const void *data)
{
    const char *shstrtab;
    unsigned int i;
    Elf_Off offset, delta;
    struct livepatch_elf_sec *sec;
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
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Section string table is corrupted\n",
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
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Section %u name is not within .shstrtab!\n",
                    elf->name, i);
            return -EINVAL;
        }

        elf->sec[i].name = shstrtab + delta;
    }

    return 0;
}

static int elf_get_sym(struct livepatch_elf *elf, const void *data)
{
    const struct livepatch_elf_sec *symtab_sec, *strtab_sec;
    struct livepatch_elf_sym *sym;
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

    sym = xzalloc_array(struct livepatch_elf_sym, nsym);
    if ( !sym )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Could not allocate memory for symbols\n",
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
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Symbol [%u] name is not within .strtab!\n",
                    elf->name, i);
            return -EINVAL;
        }

        sym[i].sym = s;
        sym[i].name = strtab_sec->data + delta;
        if ( arch_livepatch_symbol_deny(elf, &sym[i]) )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Symbol '%s' should not be in payload!\n",
                    elf->name, sym[i].name);
            return -EINVAL;
        }
    }
    elf->nsym = nsym;

    return 0;
}

int livepatch_elf_resolve_symbols(struct livepatch_elf *elf)
{
    unsigned int i;
    int rc = 0;

    ASSERT(elf->sym);

    for ( i = 1; i < elf->nsym; i++ )
    {
        unsigned int idx = elf->sym[i].sym->st_shndx;
        const Elf_Sym *sym = elf->sym[i].sym;
        Elf_Addr st_value = sym->st_value;

        switch ( idx )
        {
        case SHN_COMMON:
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Unexpected common symbol: %s\n",
                    elf->name, elf->sym[i].name);
            rc = -EINVAL;
            break;

        case SHN_UNDEF:
            st_value = symbols_lookup_by_name(elf->sym[i].name);
            if ( !st_value )
            {
                st_value = livepatch_symbols_lookup_by_name(elf->sym[i].name);
                if ( !st_value )
                {
                    dprintk(XENLOG_ERR, LIVEPATCH "%s: Unknown symbol: %s\n",
                            elf->name, elf->sym[i].name);
                    rc = -ENOENT;
                    break;
                }
            }
            dprintk(XENLOG_DEBUG, LIVEPATCH "%s: Undefined symbol resolved: %s => %#"PRIxElfAddr"\n",
                    elf->name, elf->sym[i].name, st_value);
            break;

        case SHN_ABS:
            dprintk(XENLOG_DEBUG, LIVEPATCH "%s: Absolute symbol: %s => %#"PRIxElfAddr"\n",
                    elf->name, elf->sym[i].name, sym->st_value);
            break;

        default:
            /* SHN_COMMON and SHN_ABS are above. */
            if ( idx >= SHN_LORESERVE )
                rc = -EOPNOTSUPP;
            else if ( idx >= elf->hdr->e_shnum )
                rc = -EINVAL;

            if ( rc )
            {
                dprintk(XENLOG_ERR, LIVEPATCH "%s: Out of bounds symbol section %#x\n",
                        elf->name, idx);
                break;
            }

            if ( livepatch_elf_ignore_section(elf->sec[idx].sec) )
                break;

            st_value += (unsigned long)elf->sec[idx].load_addr;
            if ( elf->sym[i].name )
                dprintk(XENLOG_DEBUG, LIVEPATCH "%s: Symbol resolved: %s => %#"PRIxElfAddr" (%s)\n",
                       elf->name, elf->sym[i].name,
                       st_value, elf->sec[idx].name);
        }

        if ( rc )
            break;

        ((Elf_Sym *)sym)->st_value = st_value;
    }

    return rc;
}

int livepatch_elf_perform_relocs(struct livepatch_elf *elf)
{
    struct livepatch_elf_sec *r, *base;
    unsigned int i;
    int rc = 0;
    size_t sz;

    ASSERT(elf->sym);

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        r = &elf->sec[i];

        if ( (r->sec->sh_type != SHT_RELA) &&
             (r->sec->sh_type != SHT_REL) )
            continue;

         /* Is it a valid relocation section? */
         if ( r->sec->sh_info >= elf->hdr->e_shnum )
            continue;

         base = &elf->sec[r->sec->sh_info];

         /* Don't relocate non-allocated sections. */
         if ( !(base->sec->sh_flags & SHF_ALLOC) )
            continue;

        if ( r->sec->sh_link != elf->symtab_idx )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Relative link of %s is incorrect (%d, expected=%d)\n",
                    elf->name, r->name, r->sec->sh_link, elf->symtab_idx);
            rc = -EINVAL;
            break;
        }

        if ( r->sec->sh_type == SHT_RELA )
            sz = sizeof(Elf_RelA);
        else
            sz = sizeof(Elf_Rel);

        if ( !r->sec->sh_size )
            continue;

        if ( r->sec->sh_entsize < sz || r->sec->sh_size % r->sec->sh_entsize )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Section relative header is corrupted!\n",
                    elf->name);
            rc = -EINVAL;
            break;
        }

        if ( r->sec->sh_type == SHT_RELA )
            rc = arch_livepatch_perform_rela(elf, base, r);
        else /* SHT_REL */
            rc = arch_livepatch_perform_rel(elf, base, r);

        if ( rc )
            break;
    }

    return rc;
}

static int livepatch_header_check(const struct livepatch_elf *elf)
{
    const Elf_Ehdr *hdr = elf->hdr;
    int rc;

    if ( sizeof(*elf->hdr) > elf->len )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Section header is bigger than payload!\n",
                elf->name);
        return -EINVAL;
    }

    if ( !IS_ELF(*hdr) )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Not an ELF payload!\n", elf->name);
        return -EINVAL;
    }

    /* EI_CLASS, EI_DATA, and e_flags are platform specific. */
    if ( hdr->e_version != EV_CURRENT ||
         hdr->e_ident[EI_VERSION] != EV_CURRENT ||
         hdr->e_ident[EI_ABIVERSION] != 0 ||
         (hdr->e_ident[EI_OSABI] != ELFOSABI_NONE &&
          hdr->e_ident[EI_OSABI] != ELFOSABI_FREEBSD) ||
         hdr->e_type != ET_REL ||
         hdr->e_phnum != 0 )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Invalid ELF payload!\n", elf->name);
        return -EOPNOTSUPP;
    }

    rc = arch_livepatch_verify_elf(elf);
    if ( rc )
        return rc;

    if ( elf->hdr->e_shstrndx == SHN_UNDEF )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Section name idx is undefined!?\n",
                elf->name);
        return -EINVAL;
    }

    /* Arbitrary boundary limit. */
    if ( elf->hdr->e_shnum >= 1024 )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Too many (%u) sections!\n",
                elf->name, elf->hdr->e_shnum);
        return -EOPNOTSUPP;
    }

    /* Check that section name index is within the sections. */
    if ( elf->hdr->e_shstrndx >= elf->hdr->e_shnum )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Section name idx (%u) is past end of sections (%u)!\n",
                elf->name, elf->hdr->e_shstrndx, elf->hdr->e_shnum);
        return -EINVAL;
    }

    if ( elf->hdr->e_shoff >= elf->len )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Bogus e_shoff!\n", elf->name);
        return -EINVAL;
    }

    if ( elf->hdr->e_shentsize < sizeof(Elf_Shdr) )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Section header size is %u! Expected %zu!?\n",
                elf->name, elf->hdr->e_shentsize, sizeof(Elf_Shdr));
        return -EINVAL;
    }

    if ( ((elf->len - elf->hdr->e_shoff) / elf->hdr->e_shentsize) <
         elf->hdr->e_shnum )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Section header size is corrupted!\n",
                elf->name);
        return -EINVAL;
    }

    return 0;
}

int livepatch_elf_load(struct livepatch_elf *elf, const void *data)
{
    int rc;

    elf->hdr = data;

    rc = livepatch_header_check(elf);
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

void livepatch_elf_free(struct livepatch_elf *elf)
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
