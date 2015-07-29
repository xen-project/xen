/*
 * various helper functions to access elf structures
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "libelf-private.h"

/* ------------------------------------------------------------------------ */

void elf_mark_broken(struct elf_binary *elf, const char *msg)
{
    if ( elf->broken == NULL )
        elf->broken = msg;
}

const char *elf_check_broken(const struct elf_binary *elf)
{
    return elf->broken;
}

static bool elf_ptrval_in_range(elf_ptrval ptrval, uint64_t size,
                               const void *region, uint64_t regionsize)
    /*
     * Returns true if the putative memory area [ptrval,ptrval+size>
     * is completely inside the region [region,region+regionsize>.
     *
     * ptrval and size are the untrusted inputs to be checked.
     * region and regionsize are trusted and must be correct and valid,
     * although it is OK for region to perhaps be maliciously NULL
     * (but not some other malicious value).
     */
{
    elf_ptrval regionp = (elf_ptrval)region;

    if ( (region == NULL) ||
         (ptrval < regionp) ||              /* start is before region */
         (ptrval > regionp + regionsize) || /* start is after region */
         (size > regionsize - (ptrval - regionp)) ) /* too big */
        return 0;
    return 1;
}

bool elf_access_ok(struct elf_binary * elf,
                  uint64_t ptrval, size_t size)
{
    if ( elf_ptrval_in_range(ptrval, size, elf->image_base, elf->size) )
        return 1;
    if ( elf_ptrval_in_range(ptrval, size, elf->dest_base, elf->dest_size) )
        return 1;
    if ( elf_ptrval_in_range(ptrval, size,
                             elf->caller_xdest_base, elf->caller_xdest_size) )
        return 1;
    elf_mark_broken(elf, "out of range access");
    return 0;
}

void elf_memcpy_safe(struct elf_binary *elf, elf_ptrval dst,
                     elf_ptrval src, size_t size)
{
    if ( elf_access_ok(elf, dst, size) &&
         elf_access_ok(elf, src, size) )
    {
        /* use memmove because these checks do not prove that the
         * regions don't overlap and overlapping regions grant
         * permission for compiler malice */
        elf_memmove_unchecked(ELF_UNSAFE_PTR(dst), ELF_UNSAFE_PTR(src), size);
    }
}

void elf_memset_safe(struct elf_binary *elf, elf_ptrval dst, int c, size_t size)
{
    if ( elf_access_ok(elf, dst, size) )
    {
        elf_memset_unchecked(ELF_UNSAFE_PTR(dst), c, size);
    }
}

uint64_t elf_access_unsigned(struct elf_binary * elf, elf_ptrval base,
                             uint64_t moreoffset, size_t size)
{
    elf_ptrval ptrval = base + moreoffset;
    bool need_swap = elf_swap(elf);
    const uint8_t *u8;
    const uint16_t *u16;
    const uint32_t *u32;
    const uint64_t *u64;

    if ( !elf_access_ok(elf, ptrval, size) )
        return 0;

    switch ( size )
    {
    case 1:
        u8 = (const void*)ptrval;
        return *u8;
    case 2:
        u16 = (const void*)ptrval;
        return need_swap ? bswap_16(*u16) : *u16;
    case 4:
        u32 = (const void*)ptrval;
        return need_swap ? bswap_32(*u32) : *u32;
    case 8:
        u64 = (const void*)ptrval;
        return need_swap ? bswap_64(*u64) : *u64;
    default:
        return 0;
    }
}

uint64_t elf_round_up(struct elf_binary *elf, uint64_t addr)
{
    uint64_t elf_round = (elf_64bit(elf) ? 8 : 4) - 1;

    return (addr + elf_round) & ~elf_round;
}

/* ------------------------------------------------------------------------ */

unsigned elf_shdr_count(struct elf_binary *elf)
{
    unsigned count = elf_uval(elf, elf->ehdr, e_shnum);
    uint64_t max = elf->size / sizeof(Elf32_Shdr);
    if (max > ~(unsigned)0)
        max = ~(unsigned)0; /* Xen doesn't have limits.h :-/ */
    if (count > max)
    {
        elf_mark_broken(elf, "far too many section headers");
        count = max;
    }
    return count;
}

unsigned elf_phdr_count(struct elf_binary *elf)
{
    return elf_uval(elf, elf->ehdr, e_phnum);
}

ELF_HANDLE_DECL(elf_shdr) elf_shdr_by_name(struct elf_binary *elf, const char *name)
{
    uint64_t count = elf_shdr_count(elf);
    ELF_HANDLE_DECL(elf_shdr) shdr;
    const char *sname;
    unsigned i;

    for ( i = 0; i < count; i++ )
    {
        shdr = elf_shdr_by_index(elf, i);
        if ( !elf_access_ok(elf, ELF_HANDLE_PTRVAL(shdr), 1) )
            /* input has an insane section header count field */
            break;
        sname = elf_section_name(elf, shdr);
        if ( sname && !strcmp(sname, name) )
            return shdr;
    }
    return ELF_INVALID_HANDLE(elf_shdr);
}

ELF_HANDLE_DECL(elf_shdr) elf_shdr_by_index(struct elf_binary *elf, unsigned index)
{
    uint64_t count = elf_shdr_count(elf);
    elf_ptrval ptr;

    if ( index >= count )
        return ELF_INVALID_HANDLE(elf_shdr);

    ptr = (ELF_IMAGE_BASE(elf)
           + elf_uval(elf, elf->ehdr, e_shoff)
           + elf_uval(elf, elf->ehdr, e_shentsize) * index);
    return ELF_MAKE_HANDLE(elf_shdr, ptr);
}

ELF_HANDLE_DECL(elf_phdr) elf_phdr_by_index(struct elf_binary *elf, unsigned index)
{
    uint64_t count = elf_uval(elf, elf->ehdr, e_phnum);
    elf_ptrval ptr;

    if ( index >= count )
        return ELF_INVALID_HANDLE(elf_phdr);

    ptr = (ELF_IMAGE_BASE(elf)
           + elf_uval(elf, elf->ehdr, e_phoff)
           + elf_uval(elf, elf->ehdr, e_phentsize) * index);
    return ELF_MAKE_HANDLE(elf_phdr, ptr);
}


const char *elf_section_name(struct elf_binary *elf,
                             ELF_HANDLE_DECL(elf_shdr) shdr)
{
    if ( ELF_PTRVAL_INVALID(elf->sec_strtab) )
        return "unknown";

    return elf_strval(elf, elf->sec_strtab + elf_uval(elf, shdr, sh_name));
}

const char *elf_strval(struct elf_binary *elf, elf_ptrval start)
{
    uint64_t length;

    for ( length = 0; ; length++ ) {
        if ( !elf_access_ok(elf, start + length, 1) )
            return NULL;
        if ( !elf_access_unsigned(elf, start, length, 1) )
            /* ok */
            return ELF_UNSAFE_PTR(start);
        if ( length >= ELF_MAX_STRING_LENGTH )
        {
            elf_mark_broken(elf, "excessively long string");
            return NULL;
        }
    }
}

const char *elf_strfmt(struct elf_binary *elf, elf_ptrval start)
{
    const char *str = elf_strval(elf, start);

    if ( str == NULL )
        return "(invalid)";
    return str;
}

elf_ptrval elf_section_start(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr)
{
    return ELF_IMAGE_BASE(elf) + elf_uval(elf, shdr, sh_offset);
}

elf_ptrval elf_section_end(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr)
{
    return ELF_IMAGE_BASE(elf)
        + elf_uval(elf, shdr, sh_offset) + elf_uval(elf, shdr, sh_size);
}

elf_ptrval elf_segment_start(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr)
{
    return ELF_IMAGE_BASE(elf)
        + elf_uval(elf, phdr, p_offset);
}

elf_ptrval elf_segment_end(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr)
{
    return ELF_IMAGE_BASE(elf)
        + elf_uval(elf, phdr, p_offset) + elf_uval(elf, phdr, p_filesz);
}

ELF_HANDLE_DECL(elf_sym) elf_sym_by_name(struct elf_binary *elf, const char *symbol)
{
    elf_ptrval ptr = elf_section_start(elf, elf->sym_tab);
    elf_ptrval end = elf_section_end(elf, elf->sym_tab);
    ELF_HANDLE_DECL(elf_sym) sym;
    uint64_t info, name;
    const char *sym_name;

    for ( ; ptr < end; ptr += elf_size(elf, sym) )
    {
        sym = ELF_MAKE_HANDLE(elf_sym, ptr);
        info = elf_uval(elf, sym, st_info);
        name = elf_uval(elf, sym, st_name);
        if ( ELF32_ST_BIND(info) != STB_GLOBAL )
            continue;
        sym_name = elf_strval(elf, elf->sym_strtab + name);
        if ( sym_name == NULL ) /* out of range, oops */
            return ELF_INVALID_HANDLE(elf_sym);
        if ( strcmp(sym_name, symbol) )
            continue;
        return sym;
    }
    return ELF_INVALID_HANDLE(elf_sym);
}

ELF_HANDLE_DECL(elf_sym) elf_sym_by_index(struct elf_binary *elf, unsigned index)
{
    elf_ptrval ptr = elf_section_start(elf, elf->sym_tab);
    ELF_HANDLE_DECL(elf_sym) sym;

    sym = ELF_MAKE_HANDLE(elf_sym, ptr + index * elf_size(elf, sym));
    return sym;
}

const char *elf_note_name(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note)
{
    return elf_strval(elf, ELF_HANDLE_PTRVAL(note) + elf_size(elf, note));
}

elf_ptrval elf_note_desc(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note)
{
    unsigned namesz = (elf_uval(elf, note, namesz) + 3) & ~3;

    return ELF_HANDLE_PTRVAL(note) + elf_size(elf, note) + namesz;
}

uint64_t elf_note_numeric(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note)
{
    elf_ptrval desc = elf_note_desc(elf, note);
    unsigned descsz = elf_uval(elf, note, descsz);

    switch (descsz)
    {
    case 1:
    case 2:
    case 4:
    case 8:
        return elf_access_unsigned(elf, desc, 0, descsz);
    default:
        return 0;
    }
}

uint64_t elf_note_numeric_array(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note,
                                unsigned int unitsz, unsigned int idx)
{
    elf_ptrval desc = elf_note_desc(elf, note);
    unsigned descsz = elf_uval(elf, note, descsz);

    if ( descsz % unitsz || idx >= descsz / unitsz )
        return 0;
    switch (unitsz)
    {
    case 1:
    case 2:
    case 4:
    case 8:
        return elf_access_unsigned(elf, desc, idx * unitsz, unitsz);
    default:
        return 0;
    }
}

ELF_HANDLE_DECL(elf_note) elf_note_next(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note)
{
    unsigned namesz = (elf_uval(elf, note, namesz) + 3) & ~3;
    unsigned descsz = (elf_uval(elf, note, descsz) + 3) & ~3;

    elf_ptrval ptrval = ELF_HANDLE_PTRVAL(note)
        + elf_size(elf, note) + namesz + descsz;

    if ( ( ptrval <= ELF_HANDLE_PTRVAL(note) || /* wrapped or stuck */
           !elf_access_ok(elf, ELF_HANDLE_PTRVAL(note), 1) ) )
        ptrval = ELF_MAX_PTRVAL; /* terminate caller's loop */

    return ELF_MAKE_HANDLE(elf_note, ptrval);
}

/* ------------------------------------------------------------------------ */

bool elf_is_elfbinary(const void *image_start, size_t image_size)
{
    const Elf32_Ehdr *ehdr = image_start;

    if ( image_size < sizeof(*ehdr) )
        return 0;

    return IS_ELF(*ehdr);
}

bool elf_phdr_is_loadable(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr)
{
    uint64_t p_type = elf_uval(elf, phdr, p_type);
    uint64_t p_flags = elf_uval(elf, phdr, p_flags);

    return ((p_type == PT_LOAD) && (p_flags & (PF_R | PF_W | PF_X)) != 0);
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
