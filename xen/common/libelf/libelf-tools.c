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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "libelf-private.h"

/* ------------------------------------------------------------------------ */

uint64_t elf_access_unsigned(struct elf_binary * elf, const void *ptr,
                             uint64_t offset, size_t size)
{
    int need_swap = elf_swap(elf);
    const uint8_t *u8;
    const uint16_t *u16;
    const uint32_t *u32;
    const uint64_t *u64;

    switch ( size )
    {
    case 1:
        u8 = ptr + offset;
        return *u8;
    case 2:
        u16 = ptr + offset;
        return need_swap ? bswap_16(*u16) : *u16;
    case 4:
        u32 = ptr + offset;
        return need_swap ? bswap_32(*u32) : *u32;
    case 8:
        u64 = ptr + offset;
        return need_swap ? bswap_64(*u64) : *u64;
    default:
        return 0;
    }
}

uint64_t elf_round_up(struct elf_binary *elf, uint64_t addr)
{
    int elf_round = (elf_64bit(elf) ? 8 : 4) - 1;

    return (addr + elf_round) & ~elf_round;
}

/* ------------------------------------------------------------------------ */

int elf_shdr_count(struct elf_binary *elf)
{
    return elf_uval(elf, elf->ehdr, e_shnum);
}

int elf_phdr_count(struct elf_binary *elf)
{
    return elf_uval(elf, elf->ehdr, e_phnum);
}

ELF_HANDLE_DECL(elf_shdr) elf_shdr_by_name(struct elf_binary *elf, const char *name)
{
    uint64_t count = elf_shdr_count(elf);
    ELF_HANDLE_DECL(elf_shdr) shdr;
    const char *sname;
    int i;

    for ( i = 0; i < count; i++ )
    {
        shdr = elf_shdr_by_index(elf, i);
        sname = elf_section_name(elf, shdr);
        if ( sname && !strcmp(sname, name) )
            return shdr;
    }
    return ELF_INVALID_HANDLE(elf_shdr);
}

ELF_HANDLE_DECL(elf_shdr) elf_shdr_by_index(struct elf_binary *elf, int index)
{
    uint64_t count = elf_shdr_count(elf);
    ELF_PTRVAL_CONST_VOID ptr;

    if ( index >= count )
        return ELF_INVALID_HANDLE(elf_shdr);

    ptr = (ELF_IMAGE_BASE(elf)
           + elf_uval(elf, elf->ehdr, e_shoff)
           + elf_uval(elf, elf->ehdr, e_shentsize) * index);
    return ELF_MAKE_HANDLE(elf_shdr, ptr);
}

ELF_HANDLE_DECL(elf_phdr) elf_phdr_by_index(struct elf_binary *elf, int index)
{
    uint64_t count = elf_uval(elf, elf->ehdr, e_phnum);
    ELF_PTRVAL_CONST_VOID ptr;

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

    return elf->sec_strtab + elf_uval(elf, shdr, sh_name);
}

ELF_PTRVAL_CONST_VOID elf_section_start(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr)
{
    return ELF_IMAGE_BASE(elf) + elf_uval(elf, shdr, sh_offset);
}

ELF_PTRVAL_CONST_VOID elf_section_end(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr)
{
    return ELF_IMAGE_BASE(elf)
        + elf_uval(elf, shdr, sh_offset) + elf_uval(elf, shdr, sh_size);
}

ELF_PTRVAL_CONST_VOID elf_segment_start(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr)
{
    return ELF_IMAGE_BASE(elf)
        + elf_uval(elf, phdr, p_offset);
}

ELF_PTRVAL_CONST_VOID elf_segment_end(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr)
{
    return ELF_IMAGE_BASE(elf)
        + elf_uval(elf, phdr, p_offset) + elf_uval(elf, phdr, p_filesz);
}

ELF_HANDLE_DECL(elf_sym) elf_sym_by_name(struct elf_binary *elf, const char *symbol)
{
    ELF_PTRVAL_CONST_VOID ptr = elf_section_start(elf, elf->sym_tab);
    ELF_PTRVAL_CONST_VOID end = elf_section_end(elf, elf->sym_tab);
    ELF_HANDLE_DECL(elf_sym) sym;
    uint64_t info, name;

    for ( ; ptr < end; ptr += elf_size(elf, sym) )
    {
        sym = ELF_MAKE_HANDLE(elf_sym, ptr);
        info = elf_uval(elf, sym, st_info);
        name = elf_uval(elf, sym, st_name);
        if ( ELF32_ST_BIND(info) != STB_GLOBAL )
            continue;
        if ( strcmp(elf->sym_strtab + name, symbol) )
            continue;
        return sym;
    }
    return ELF_INVALID_HANDLE(elf_sym);
}

ELF_HANDLE_DECL(elf_sym) elf_sym_by_index(struct elf_binary *elf, int index)
{
    ELF_PTRVAL_CONST_VOID ptr = elf_section_start(elf, elf->sym_tab);
    ELF_HANDLE_DECL(elf_sym) sym;

    sym = ELF_MAKE_HANDLE(elf_sym, ptr + index * elf_size(elf, sym));
    return sym;
}

const char *elf_note_name(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note)
{
    return ELF_HANDLE_PTRVAL(note) + elf_size(elf, note);
}

ELF_PTRVAL_CONST_VOID elf_note_desc(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note)
{
    int namesz = (elf_uval(elf, note, namesz) + 3) & ~3;

    return ELF_HANDLE_PTRVAL(note) + elf_size(elf, note) + namesz;
}

uint64_t elf_note_numeric(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note)
{
    ELF_PTRVAL_CONST_VOID desc = elf_note_desc(elf, note);
    int descsz = elf_uval(elf, note, descsz);

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
    ELF_PTRVAL_CONST_VOID desc = elf_note_desc(elf, note);
    int descsz = elf_uval(elf, note, descsz);

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
    int namesz = (elf_uval(elf, note, namesz) + 3) & ~3;
    int descsz = (elf_uval(elf, note, descsz) + 3) & ~3;

    return ELF_MAKE_HANDLE(elf_note, ELF_HANDLE_PTRVAL(note) + elf_size(elf, note) + namesz + descsz);
}

/* ------------------------------------------------------------------------ */

int elf_is_elfbinary(const void *image)
{
    const Elf32_Ehdr *ehdr = image;

    return IS_ELF(*ehdr); /* fixme unchecked */
}

int elf_phdr_is_loadable(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr)
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
