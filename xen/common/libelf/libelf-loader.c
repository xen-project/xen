/*
 * parse and load elf binaries
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

#ifdef __XEN__
#include <asm/guest_access.h>
#endif

#include "libelf-private.h"

/* ------------------------------------------------------------------------ */

/* Number of section header needed in order to fit the SYMTAB and STRTAB. */
#define ELF_BSDSYM_SECTIONS 3
struct elf_sym_header {
    uint32_t size;
    struct {
        elf_ehdr header;
        elf_shdr section[ELF_BSDSYM_SECTIONS];
    } elf_header;
} __attribute__((packed));

elf_errorstatus elf_init(struct elf_binary *elf, const char *image_input, size_t size)
{
    ELF_HANDLE_DECL(elf_shdr) shdr;
    unsigned i, count, section, link;
    uint64_t offset;

    if ( !elf_is_elfbinary(image_input, size) )
    {
        elf_err(elf, "ELF: not an ELF binary\n");
        return -1;
    }

    elf_memset_unchecked(elf, 0, sizeof(*elf));
    elf->image_base = image_input;
    elf->size = size;
    elf->ehdr = ELF_MAKE_HANDLE(elf_ehdr, (elf_ptrval)image_input);
    elf->class = elf_uval_3264(elf, elf->ehdr, e32.e_ident[EI_CLASS]);
    elf->data = elf_uval_3264(elf, elf->ehdr, e32.e_ident[EI_DATA]);

    /* Sanity check phdr. */
    offset = elf_uval(elf, elf->ehdr, e_phoff) +
        elf_uval(elf, elf->ehdr, e_phentsize) * elf_phdr_count(elf);
    if ( offset > elf->size )
    {
        elf_err(elf, "ELF: phdr overflow (off %" PRIx64 " > size %lx)\n",
                offset, (unsigned long)elf->size);
        return -1;
    }

    /* Sanity check shdr. */
    offset = elf_uval(elf, elf->ehdr, e_shoff) +
        elf_uval(elf, elf->ehdr, e_shentsize) * elf_shdr_count(elf);
    if ( offset > elf->size )
    {
        elf_err(elf, "ELF: shdr overflow (off %" PRIx64 " > size %lx)\n",
                offset, (unsigned long)elf->size);
        return -1;
    }

    /* Find section string table. */
    section = elf_uval(elf, elf->ehdr, e_shstrndx);
    shdr = elf_shdr_by_index(elf, section);
    if ( ELF_HANDLE_VALID(shdr) )
        elf->sec_strtab = elf_section_start(elf, shdr);

    /* Find symbol table and symbol string table. */
    count = elf_shdr_count(elf);
    for ( i = 1; i < count; i++ )
    {
        shdr = elf_shdr_by_index(elf, i);
        if ( !elf_access_ok(elf, ELF_HANDLE_PTRVAL(shdr), 1) )
            /* input has an insane section header count field */
            break;
        if ( elf_uval(elf, shdr, sh_type) != SHT_SYMTAB )
            continue;

        link = elf_uval(elf, shdr, sh_link);
        if ( link == SHN_UNDEF || link >= count )
            /* out-of-bounds link value. */
            break;

        elf->sym_tab = shdr;
        shdr = elf_shdr_by_index(elf, link);
        if ( !ELF_HANDLE_VALID(shdr) )
        {
            elf->sym_tab = ELF_INVALID_HANDLE(elf_shdr);
            continue;
        }
        elf->sym_strtab = elf_section_start(elf, shdr);
        break;
    }

    return 0;
}

#ifndef __XEN__
void elf_call_log_callback(struct elf_binary *elf, bool iserr,
                           const char *fmt,...) {
    va_list al;

    if (!elf->log_callback)
        return;
    if (!(iserr || elf->verbose))
        return;

    va_start(al,fmt);
    elf->log_callback(elf, elf->log_caller_data, iserr, fmt, al);
    va_end(al);
}
    
void elf_set_log(struct elf_binary *elf, elf_log_callback *log_callback,
                 void *log_caller_data, bool verbose)
{
    elf->log_callback = log_callback;
    elf->log_caller_data = log_caller_data;
    elf->verbose = verbose;
}

static elf_errorstatus elf_load_image(struct elf_binary *elf,
                          elf_ptrval dst, elf_ptrval src,
                          uint64_t filesz, uint64_t memsz)
{
    elf_memcpy_safe(elf, dst, src, filesz);
    elf_memset_safe(elf, dst + filesz, 0, memsz - filesz);
    return 0;
}
#else

void elf_set_verbose(struct elf_binary *elf)
{
    elf->verbose = 1;
}

static elf_errorstatus elf_memcpy(struct vcpu *v, void *dst, void *src,
                                  uint64_t size)
{
    unsigned int res;

#ifdef CONFIG_X86
    if ( is_hvm_vcpu(v) )
    {
        enum hvm_translation_result rc;

        rc = hvm_copy_to_guest_phys((paddr_t)dst, src, size, v);
        return rc != HVMTRANS_okay ? -1 : 0;
    }
#endif

    res = src ? raw_copy_to_guest(dst, src, size) :
                raw_clear_guest(dst, size);

    return res ? -1 : 0;
}

static elf_errorstatus elf_load_image(struct elf_binary *elf, elf_ptrval dst, elf_ptrval src, uint64_t filesz, uint64_t memsz)
{
    elf_errorstatus rc;
    if ( filesz > ULONG_MAX || memsz > ULONG_MAX )
        return -1;
    /* We trust the dom0 kernel image completely, so we don't care
     * about overruns etc. here. */
    rc = elf_memcpy(elf->vcpu, ELF_UNSAFE_PTR(dst), ELF_UNSAFE_PTR(src),
                    filesz);
    if ( rc != 0 )
        return -1;
    rc = elf_memcpy(elf->vcpu, ELF_UNSAFE_PTR(dst + filesz), NULL,
                    memsz - filesz);
    if ( rc != 0 )
        return -1;
    return 0;
}
#endif

/* Calculate the required additional kernel space for the elf image */
void elf_parse_bsdsyms(struct elf_binary *elf, uint64_t pstart)
{
    uint64_t sz;
    ELF_HANDLE_DECL(elf_shdr) shdr;

    if ( !ELF_HANDLE_VALID(elf->sym_tab) )
    {
        elf_mark_broken(elf, "invalid ELF handle for symtab section");
        return;
    }

    pstart = elf_round_up(elf, pstart);

    /* Space to store the size of the elf image */
    sz = sizeof(uint32_t);

    /* Space for the ELF header and section headers */
    sz += offsetof(struct elf_sym_header, elf_header.section) +
          ELF_BSDSYM_SECTIONS * (elf_64bit(elf) ? sizeof(Elf64_Shdr) :
                                                  sizeof(Elf32_Shdr));
    sz = elf_round_up(elf, sz);

    /*
     * No need to search for the symtab section header again, it's handler
     * is stored in elf->sym_tab by the elf_init function.
     */

    /* Space for the symbol and string tables. */
    sz = elf_round_up(elf, sz + elf_uval(elf, elf->sym_tab, sh_size));

    shdr = elf_shdr_by_index(elf, elf_uval(elf, elf->sym_tab, sh_link));

    if ( !elf_access_ok(elf, ELF_HANDLE_PTRVAL(shdr), 1) )
        /* input has an insane section header count field */
        return;

    if ( elf_uval(elf, shdr, sh_type) != SHT_STRTAB )
        /* Invalid symtab -> strtab link */
        return;

    sz = elf_round_up(elf, sz + elf_uval(elf, shdr, sh_size));

    elf->bsd_symtab_pstart = pstart;
    elf->bsd_symtab_pend   = pstart + sz;
}

static void elf_load_bsdsyms(struct elf_binary *elf)
{
    /*
     * Header that is placed at the end of the kernel and allows
     * the OS to find where the symtab and strtab have been loaded.
     * It mimics a valid ELF file header, although it only contains
     * a symtab and a strtab section. The layout in memory is the
     * following:
     *
     * +------------------------+
     * |                        |
     * | KERNEL                 |
     * |                        |
     * +------------------------+ pend
     * | ALIGNMENT              |
     * +------------------------+ bsd_symtab_pstart
     * |                        |
     * | size                   | bsd_symtab_pend - bsd_symtab_pstart
     * |                        |
     * +------------------------+ bsd_symtab_pstart + 4
     * |                        |
     * | ELF header             |
     * |                        |
     * +------------------------+
     * |                        |
     * | ELF section header 0   | Undefined section header
     * |                        |
     * +------------------------+
     * |                        |
     * | ELF section header 1   | SYMTAB section header
     * |                        |
     * +------------------------+
     * |                        |
     * | ELF section header 2   | STRTAB section header
     * |                        |
     * +------------------------+
     * |                        |
     * | SYMTAB                 |
     * |                        |
     * +------------------------+
     * |                        |
     * | STRTAB                 |
     * |                        |
     * +------------------------+ bsd_symtab_pend
     *
     * NB: according to the ELF spec there's only ONE symtab per ELF
     * file, and accordingly we will only load the corresponding
     * strtab, so we only need three section headers in our fake ELF
     * header (first section header is always the undefined section).
     */
    struct elf_sym_header header;
    ELF_HANDLE_DECL(elf_ehdr) header_handle;
    unsigned long shdr_size, ehdr_size, header_size;
    ELF_HANDLE_DECL(elf_shdr) section_handle;
    unsigned int link, rc, i;
    elf_ptrval header_base;
    elf_ptrval elf_header_base;
    elf_ptrval symtab_base;
    elf_ptrval strtab_base;

    if ( !elf->bsd_symtab_pstart )
        return;

#define elf_store_field_bitness(_elf, _hdr, _elm, _val)             \
do {                                                                \
    if ( elf_64bit(_elf) )                                          \
        elf_store_field(_elf, _hdr, e64._elm, _val);                \
    else                                                            \
        elf_store_field(_elf, _hdr, e32._elm, _val);                \
} while ( 0 )

#define SYMTAB_INDEX    1
#define STRTAB_INDEX    2

    /* Allow elf_memcpy_safe to write to header. */
    elf_set_xdest(elf, &header, sizeof(header));

    /*
     * Calculate the position of the various elements in GUEST MEMORY SPACE.
     * This addresses MUST only be used with elf_load_image.
     *
     * NB: strtab_base cannot be calculated at this point because we don't
     * know the size of the symtab yet, and the strtab will be placed after it.
     */
    header_base = elf_get_ptr(elf, elf->bsd_symtab_pstart);
    elf_header_base = elf_get_ptr(elf, elf->bsd_symtab_pstart) +
                      sizeof(uint32_t);
    symtab_base = elf_round_up(elf, header_base + sizeof(header));

    /*
     * Set the size of the ELF header and the section headers, based on the
     * size of our local copy.
     */
    ehdr_size = elf_64bit(elf) ? sizeof(header.elf_header.header.e64) :
                                 sizeof(header.elf_header.header.e32);
    shdr_size = elf_64bit(elf) ? sizeof(header.elf_header.section[0].e64) :
                                 sizeof(header.elf_header.section[0].e32);

    /* Fill the ELF header, copied from the original ELF header. */
    header_handle = ELF_MAKE_HANDLE(elf_ehdr,
                                ELF_REALPTR2PTRVAL(&header.elf_header.header));
    elf_memcpy_safe(elf, ELF_HANDLE_PTRVAL(header_handle),
                    ELF_HANDLE_PTRVAL(elf->ehdr), ehdr_size);

    /*
     * Set the ELF header size, section header entry size and version
     * (in case we are dealing with an input ELF header that has extensions).
     */
    elf_store_field_bitness(elf, header_handle, e_ehsize, ehdr_size);
    elf_store_field_bitness(elf, header_handle, e_shentsize, shdr_size);
    elf_store_field_bitness(elf, header_handle, e_version, EV_CURRENT);

    /* Set the offset to the shdr array. */
    elf_store_field_bitness(elf, header_handle, e_shoff,
                            offsetof(typeof(header.elf_header), section));

    /* Set the right number of section headers. */
    elf_store_field_bitness(elf, header_handle, e_shnum, ELF_BSDSYM_SECTIONS);

    /* Clear a couple of fields we don't use. */
    elf_store_field_bitness(elf, header_handle, e_phoff, 0);
    elf_store_field_bitness(elf, header_handle, e_phentsize, 0);
    elf_store_field_bitness(elf, header_handle, e_phnum, 0);
    elf_store_field_bitness(elf, header_handle, e_shstrndx, 0);

    /*
     * The symtab section header is going to reside in section[SYMTAB_INDEX],
     * while the corresponding strtab is going to be placed in
     * section[STRTAB_INDEX]. sh_offset is mangled so it points to the offset
     * where the sections are actually loaded (relative to the ELF header
     * location).
     */
    section_handle = ELF_MAKE_HANDLE(elf_shdr,
                ELF_REALPTR2PTRVAL(&header.elf_header.section[SYMTAB_INDEX]));

    elf_memcpy_safe(elf, ELF_HANDLE_PTRVAL(section_handle),
                    ELF_HANDLE_PTRVAL(elf->sym_tab),
                    shdr_size);

    /* Copy the original sh_link field before mangling it. */
    link = elf_uval(elf, section_handle, sh_link);

    /* Load symtab into guest memory. */
    rc = elf_load_image(elf, symtab_base,
                        elf_section_start(elf, section_handle),
                        elf_uval(elf, section_handle, sh_size),
                        elf_uval(elf, section_handle, sh_size));
    if ( rc != 0 )
    {
        elf_mark_broken(elf, "unable to load symtab into guest memory");
        return;
    }

    /* Adjust the sh_offset and sh_link of the copied section header. */
    elf_store_field_bitness(elf, section_handle, sh_offset,
                            symtab_base - elf_header_base);
    elf_store_field_bitness(elf, section_handle, sh_link,
                            STRTAB_INDEX);

    /* Calculate the guest address where strtab is loaded. */
    strtab_base = elf_round_up(elf, symtab_base +
                               elf_uval(elf, section_handle, sh_size));

    /* Load strtab section header. */
    section_handle = ELF_MAKE_HANDLE(elf_shdr,
            ELF_REALPTR2PTRVAL(&header.elf_header.section[STRTAB_INDEX]));
    elf_memcpy_safe(elf, ELF_HANDLE_PTRVAL(section_handle),
                    ELF_HANDLE_PTRVAL(elf_shdr_by_index(elf, link)),
                    shdr_size);

    if ( elf_uval(elf, section_handle, sh_type) != SHT_STRTAB )
    {
        elf_mark_broken(elf, "strtab not found");
        return;
    }

    /* Load strtab into guest memory. */
    rc = elf_load_image(elf, strtab_base,
                        elf_section_start(elf, section_handle),
                        elf_uval(elf, section_handle, sh_size),
                        elf_uval(elf, section_handle, sh_size));
    if ( rc != 0 )
    {
        elf_mark_broken(elf, "unable to load strtab into guest memory");
        return;
    }

    elf_store_field_bitness(elf, section_handle, sh_offset,
                            strtab_base - elf_header_base);

    /* Store the whole size (including headers and loaded sections). */
    header.size = strtab_base + elf_uval(elf, section_handle, sh_size) -
                  elf_header_base;

    /* Load the size plus ELF header. */
    header_size = offsetof(typeof(header), elf_header.section);
    rc = elf_load_image(elf, header_base, ELF_REALPTR2PTRVAL(&header),
                        header_size, header_size);
    if ( rc != 0 )
    {
        elf_mark_broken(elf, "unable to load ELF headers into guest memory");
        return;
    }

    /*
     * Load the section headers.
     *
     * NB: this _must_ be done one by one, and taking the bitness into account,
     * so that the guest can treat this as an array of type Elf{32/64}_Shdr.
     */
    for ( i = 0; i < ELF_BSDSYM_SECTIONS; i++ )
    {
        rc = elf_load_image(elf, header_base + header_size + shdr_size * i,
                            ELF_REALPTR2PTRVAL(&header.elf_header.section[i]),
                            shdr_size, shdr_size);
        if ( rc != 0 )
        {
            elf_mark_broken(elf,
                        "unable to load ELF section header into guest memory");
            return;
        }
    }

    /* Remove permissions from elf_memcpy_safe. */
    elf_set_xdest(elf, NULL, 0);

#undef SYMTAB_INDEX
#undef STRTAB_INDEX
#undef elf_store_field_bitness
}

void elf_parse_binary(struct elf_binary *elf)
{
    ELF_HANDLE_DECL(elf_phdr) phdr;
    uint64_t low = -1, high = 0, paddr, memsz;
    unsigned i, count;

    count = elf_phdr_count(elf);
    for ( i = 0; i < count; i++ )
    {
        phdr = elf_phdr_by_index(elf, i);
        if ( !elf_access_ok(elf, ELF_HANDLE_PTRVAL(phdr), 1) )
            /* input has an insane program header count field */
            break;
        if ( !elf_phdr_is_loadable(elf, phdr) )
            continue;
        paddr = elf_uval(elf, phdr, p_paddr);
        memsz = elf_uval(elf, phdr, p_memsz);
        elf_msg(elf, "ELF: phdr: paddr=%#" PRIx64 " memsz=%#" PRIx64 "\n",
                paddr, memsz);
        if ( low > paddr )
            low = paddr;
        if ( high < paddr + memsz )
            high = paddr + memsz;
    }
    elf->pstart = low;
    elf->pend = high;
    elf_msg(elf, "ELF: memory: %#" PRIx64 " -> %#" PRIx64 "\n",
            elf->pstart, elf->pend);
}

elf_errorstatus elf_load_binary(struct elf_binary *elf)
{
    ELF_HANDLE_DECL(elf_phdr) phdr;
    uint64_t paddr, offset, filesz, memsz;
    unsigned i, count;
    elf_ptrval dest;
    /*
     * Let bizarre ELFs write the output image up to twice; this
     * calculation is just to ensure our copying loop is no worse than
     * O(domain_size).
     */
    uint64_t remain_allow_copy = (uint64_t)elf->dest_size * 2;

    count = elf_phdr_count(elf);
    for ( i = 0; i < count; i++ )
    {
        phdr = elf_phdr_by_index(elf, i);
        if ( !elf_access_ok(elf, ELF_HANDLE_PTRVAL(phdr), 1) )
            /* input has an insane program header count field */
            break;
        if ( !elf_phdr_is_loadable(elf, phdr) )
            continue;
        paddr = elf_uval(elf, phdr, p_paddr);
        offset = elf_uval(elf, phdr, p_offset);
        filesz = elf_uval(elf, phdr, p_filesz);
        memsz = elf_uval(elf, phdr, p_memsz);
        dest = elf_get_ptr(elf, paddr);

        /*
         * We need to check that the input image doesn't have us copy
         * the whole image zillions of times, as that could lead to
         * O(n^2) time behaviour and possible DoS by a malicous ELF.
         */
        if ( remain_allow_copy < memsz )
        {
            elf_mark_broken(elf, "program segments total to more"
                            " than the input image size");
            break;
        }
        remain_allow_copy -= memsz;

        elf_msg(elf,
                "ELF: phdr %u at %#"ELF_PRPTRVAL" -> %#"ELF_PRPTRVAL"\n",
                i, dest, (elf_ptrval)(dest + filesz));
        if ( elf_load_image(elf, dest, ELF_IMAGE_BASE(elf) + offset, filesz, memsz) != 0 )
            return -1;
    }

    elf_load_bsdsyms(elf);
    return 0;
}

elf_ptrval elf_get_ptr(struct elf_binary *elf, unsigned long addr)
{
    return ELF_REALPTR2PTRVAL(elf->dest_base) + addr - elf->pstart;
}

uint64_t elf_lookup_addr(struct elf_binary * elf, const char *symbol)
{
    ELF_HANDLE_DECL(elf_sym) sym;
    uint64_t value;

    sym = elf_sym_by_name(elf, symbol);
    if ( !ELF_HANDLE_VALID(sym) )
    {
        elf_err(elf, "%s: not found: %s\n", __func__, symbol);
        return -1;
    }

    value = elf_uval(elf, sym, st_value);
    elf_msg(elf, "%s: symbol \"%s\" at 0x%" PRIx64 "\n", __func__,
            symbol, value);
    return value;
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
