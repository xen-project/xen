/*
 * Elf format, (pfn, gmfn) table, IA64 support.
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
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

/*
 * xen dump-core file format follows ELF format specification.
 * Analisys tools shouldn't depends on the order of sections.
 * They should follow elf header and check section names.
 *
 *  +--------------------------------------------------------+
 *  |ELF header                                              |
 *  +--------------------------------------------------------+
 *  |section headers                                         |
 *  |    null section header                                 |
 *  |    .shstrtab                                           |
 *  |    .note.Xen                                           |
 *  |    .xen_prstatus                                       |
 *  |    .xen_shared_info if present                         |
 *  |    .xen_pages                                          |
 *  |    .xen_p2m or .xen_pfn                                |
 *  +--------------------------------------------------------+
 *  |.note.Xen:note section                                  |
 *  |    "Xen" is used as note name,                         |
 *  |    types are defined in xen/include/public/elfnote.h   |
 *  |    and descriptors are defined in xc_core.h.           |
 *  |    dumpcore none                                       |
 *  |    dumpcore header                                     |
 *  |    dumpcore xen version                                |
 *  |    dumpcore format version                             |
 *  +--------------------------------------------------------+
 *  |.xen_prstatus                                           |
 *  |       vcpu_guest_context_t[nr_vcpus]                   |
 *  +--------------------------------------------------------+
 *  |.xen_shared_info if possible                            |
 *  +--------------------------------------------------------+
 *  |.xen_pages                                              |
 *  |    page * nr_pages                                     |
 *  +--------------------------------------------------------+
 *  |.xen_p2m or .xen_pfn                                    |
 *  |    .xen_p2m: struct xen_dumpcore_p2m[nr_pages]         |
 *  |    .xen_pfn: uint64_t[nr_pages]                        |
 *  +--------------------------------------------------------+
 *  |.shstrtab: section header string table                  |
 *  +--------------------------------------------------------+
 *
 */

#include "xg_private.h"
#include "xc_core.h"
#include "xc_dom.h"
#include <stdlib.h>
#include <unistd.h>

/* number of pages to write at a time */
#define DUMP_INCREMENT (4 * 1024)

/* string table */
struct xc_core_strtab {
    char       *strings;
    uint16_t    length;
    uint16_t    max;
};

static struct xc_core_strtab*
xc_core_strtab_init(xc_interface *xch)
{
    struct xc_core_strtab *strtab;
    char *strings;
    strtab = malloc(sizeof(*strtab));
    if ( strtab == NULL )
        return NULL;

    strings = malloc(PAGE_SIZE);
    if ( strings == NULL )
    {
        PERROR("Could not allocate string table init");
        free(strtab);
        return NULL;
    }
    strtab->strings = strings;
    strtab->max = PAGE_SIZE;

    /* index 0 represents none */
    strtab->strings[0] = '\0';
    strtab->length = 1;

    return strtab;
}

static void
xc_core_strtab_free(struct xc_core_strtab *strtab)
{
    free(strtab->strings);
    free(strtab);
}

static uint16_t
xc_core_strtab_get(xc_interface *xch, struct xc_core_strtab *strtab, const char *name)
{
    uint16_t ret = 0;
    uint16_t len = strlen(name) + 1;

    if ( strtab->length > UINT16_MAX - len )
    {
        PERROR("too long string table");
        errno = E2BIG;
        return ret;
    }
    
    if ( strtab->length + len > strtab->max )
    {
        char *tmp;
        if ( strtab->max > UINT16_MAX / 2 )
        {
            PERROR("too long string table");
            errno = ENOMEM;
            return ret;
        }

        tmp = realloc(strtab->strings, strtab->max * 2);
        if ( tmp == NULL )
        {
            PERROR("Could not allocate string table");
            return ret;
        }

        strtab->strings = tmp;
        strtab->max *= 2;
    }

    ret = strtab->length;
    strcpy(strtab->strings + strtab->length, name);
    strtab->length += len;
    return ret;
}


/* section headers */
struct xc_core_section_headers {
    uint16_t    num;
    uint16_t    num_max;

    Elf64_Shdr  *shdrs;
};
#define SHDR_INIT       ((uint16_t)16)
#define SHDR_INC        ((uint16_t)4)

static struct xc_core_section_headers*
xc_core_shdr_init(xc_interface *xch)
{
    struct xc_core_section_headers *sheaders;
    sheaders = malloc(sizeof(*sheaders));
    if ( sheaders == NULL )
        return NULL;

    sheaders->num = 0;
    sheaders->num_max = SHDR_INIT;
    sheaders->shdrs = malloc(sizeof(sheaders->shdrs[0]) * sheaders->num_max);
    if ( sheaders->shdrs == NULL )
    {
        free(sheaders);
        return NULL;
    }
    return sheaders;
}

static void
xc_core_shdr_free(struct xc_core_section_headers *sheaders)
{
    free(sheaders->shdrs);
    free(sheaders);
}

Elf64_Shdr*
xc_core_shdr_get(xc_interface *xch,
                 struct xc_core_section_headers *sheaders)
{
    Elf64_Shdr *shdr;

    if ( sheaders->num == sheaders->num_max )
    {
        Elf64_Shdr *shdrs;
        if ( sheaders->num_max > UINT16_MAX - SHDR_INC )
        {
            errno = E2BIG;
            return NULL;
        }
        sheaders->num_max += SHDR_INC;
        shdrs = realloc(sheaders->shdrs,
                        sizeof(sheaders->shdrs[0]) * sheaders->num_max);
        if ( shdrs == NULL )
            return NULL;
        sheaders->shdrs = shdrs;
    }

    shdr = &sheaders->shdrs[sheaders->num];
    sheaders->num++;
    memset(shdr, 0, sizeof(*shdr));
    return shdr;
}

int
xc_core_shdr_set(xc_interface *xch,
                 Elf64_Shdr *shdr,
                 struct xc_core_strtab *strtab,
                 const char *name, uint32_t type,
                 uint64_t offset, uint64_t size,
                 uint64_t addralign, uint64_t entsize)
{
    uint64_t name_idx = xc_core_strtab_get(xch, strtab, name);
    if ( name_idx == 0 )
        return -1;

    shdr->sh_name = name_idx;
    shdr->sh_type = type;
    shdr->sh_offset = offset;
    shdr->sh_size = size;
    shdr->sh_addralign = addralign;
    shdr->sh_entsize = entsize;
    return 0;
}

static void
xc_core_ehdr_init(Elf64_Ehdr *ehdr)
{
    memset(ehdr, 0, sizeof(*ehdr));
    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELF_ARCH_DATA;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;
    ehdr->e_ident[EI_ABIVERSION] = EV_CURRENT;

    ehdr->e_type = ET_CORE;
    /* e_machine will be filled in later */
    ehdr->e_version = EV_CURRENT;
    ehdr->e_entry = 0;
    ehdr->e_phoff = 0;
    ehdr->e_shoff = sizeof(*ehdr);
    ehdr->e_flags = ELF_CORE_EFLAGS;
    ehdr->e_ehsize = sizeof(*ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = 0;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);
    /* ehdr->e_shnum and ehdr->e_shstrndx aren't known here yet.
     * fill it later */
}

static int
elfnote_fill_xen_version(xc_interface *xch,
                         struct xen_dumpcore_elfnote_xen_version_desc
                         *xen_version)
{
    int rc;
    memset(xen_version, 0, sizeof(*xen_version));

    rc = xc_version(xch, XENVER_version, NULL);
    if ( rc < 0 )
        return rc;
    xen_version->major_version = rc >> 16;
    xen_version->minor_version = rc & ((1 << 16) - 1);

    rc = xc_version(xch, XENVER_extraversion,
                    &xen_version->extra_version);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xch, XENVER_compile_info,
                    &xen_version->compile_info);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xch,
                    XENVER_capabilities, &xen_version->capabilities);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xch, XENVER_changeset, &xen_version->changeset);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xch, XENVER_platform_parameters,
                    &xen_version->platform_parameters);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xch, XENVER_pagesize, NULL);
    if ( rc < 0 )
        return rc;
    xen_version->pagesize = rc;

    return 0;
}

static void
elfnote_fill_format_version(struct xen_dumpcore_elfnote_format_version_desc
                            *format_version)
{
    format_version->version = XEN_DUMPCORE_FORMAT_VERSION_CURRENT;
}

static void
elfnote_init(struct elfnote *elfnote)
{
    /* elf note section */
    memset(elfnote, 0, sizeof(*elfnote));
    elfnote->namesz = strlen(XEN_DUMPCORE_ELFNOTE_NAME) + 1;
    strncpy(elfnote->name, XEN_DUMPCORE_ELFNOTE_NAME, sizeof(elfnote->name));
}

static int
elfnote_dump_none(xc_interface *xch, void *args, dumpcore_rtn_t dump_rtn)
{
    int sts;
    struct elfnote elfnote;
    struct xen_dumpcore_elfnote_none_desc none;

    elfnote_init(&elfnote);
    /* Avoid compile warning about constant-zero-sized memset(). */
    /*memset(&none, 0, sizeof(none));*/

    elfnote.descsz = sizeof(none);
    elfnote.type = XEN_ELFNOTE_DUMPCORE_NONE;
    sts = dump_rtn(xch, args, (char*)&elfnote, sizeof(elfnote));
    if ( sts != 0 )
        return sts;
    return dump_rtn(xch, args, (char*)&none, sizeof(none));
}

static int
elfnote_dump_core_header(
    xc_interface *xch,
    void *args, dumpcore_rtn_t dump_rtn, const xc_dominfo_t *info,
    int nr_vcpus, unsigned long nr_pages)
{
    int sts;
    struct elfnote elfnote;
    struct xen_dumpcore_elfnote_header_desc header;
    
    elfnote_init(&elfnote);
    memset(&header, 0, sizeof(header));
    
    elfnote.descsz = sizeof(header);
    elfnote.type = XEN_ELFNOTE_DUMPCORE_HEADER;
    header.xch_magic = info->hvm ? XC_CORE_MAGIC_HVM : XC_CORE_MAGIC;
    header.xch_nr_vcpus = nr_vcpus;
    header.xch_nr_pages = nr_pages;
    header.xch_page_size = PAGE_SIZE;
    sts = dump_rtn(xch, args, (char*)&elfnote, sizeof(elfnote));
    if ( sts != 0 )
        return sts;
    return dump_rtn(xch, args, (char*)&header, sizeof(header));
}

static int
elfnote_dump_xen_version(xc_interface *xch, void *args,
                         dumpcore_rtn_t dump_rtn, unsigned int guest_width)
{
    int sts;
    struct elfnote elfnote;
    struct xen_dumpcore_elfnote_xen_version_desc xen_version;

    elfnote_init(&elfnote);
    memset(&xen_version, 0, sizeof(xen_version));

    elfnote.descsz = sizeof(xen_version);
    elfnote.type = XEN_ELFNOTE_DUMPCORE_XEN_VERSION;
    elfnote_fill_xen_version(xch, &xen_version);
    if (guest_width < sizeof(unsigned long))
    {
        // 32 bit elf file format differs in pagesize's alignment
        char *p = (char *)&xen_version.pagesize;
        memmove(p - 4, p, sizeof(xen_version.pagesize));
    }
    sts = dump_rtn(xch, args, (char*)&elfnote, sizeof(elfnote));
    if ( sts != 0 )
        return sts;
    return dump_rtn(xch, args, (char*)&xen_version, sizeof(xen_version));
}

static int
elfnote_dump_format_version(xc_interface *xch,
                            void *args, dumpcore_rtn_t dump_rtn)
{
    int sts;
    struct elfnote elfnote;
    struct xen_dumpcore_elfnote_format_version_desc format_version;

    elfnote_init(&elfnote);
    memset(&format_version, 0, sizeof(format_version));
    
    elfnote.descsz = sizeof(format_version);
    elfnote.type = XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION;
    elfnote_fill_format_version(&format_version);
    sts = dump_rtn(xch, args, (char*)&elfnote, sizeof(elfnote));
    if ( sts != 0 )
        return sts;
    return dump_rtn(xch, args, (char*)&format_version, sizeof(format_version));
}

int
xc_domain_dumpcore_via_callback(xc_interface *xch,
                                uint32_t domid,
                                void *args,
                                dumpcore_rtn_t dump_rtn)
{
    xc_dominfo_t info;
    shared_info_any_t *live_shinfo = NULL;
    struct domain_info_context _dinfo = {};
    struct domain_info_context *dinfo = &_dinfo;

    int nr_vcpus = 0;
    char *dump_mem, *dump_mem_start = NULL;
    vcpu_guest_context_any_t *ctxt = NULL;
    struct xc_core_arch_context arch_ctxt;
    char dummy[PAGE_SIZE];
    int dummy_len;
    int sts = -1;

    unsigned long i;
    unsigned long j;
    unsigned long nr_pages;

    xc_core_memory_map_t *memory_map = NULL;
    unsigned int nr_memory_map;
    unsigned int map_idx;

    int auto_translated_physmap;
    xen_pfn_t *p2m = NULL;
    struct xen_dumpcore_p2m *p2m_array = NULL;

    uint64_t *pfn_array = NULL;

    Elf64_Ehdr ehdr;
    uint64_t filesz;
    uint64_t offset;
    uint64_t fixup;

    struct xc_core_strtab *strtab = NULL;
    uint16_t strtab_idx;
    struct xc_core_section_headers *sheaders = NULL;
    Elf64_Shdr *shdr;
 
    if ( xc_domain_get_guest_width(xch, domid, &dinfo->guest_width) != 0 )
    {
        PERROR("Could not get address size for domain");
        return sts;
    }

    xc_core_arch_context_init(&arch_ctxt);
    if ( (dump_mem_start = malloc(DUMP_INCREMENT*PAGE_SIZE)) == NULL )
    {
        PERROR("Could not allocate dump_mem");
        goto out;
    }

    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 )
    {
        PERROR("Could not get info for domain");
        goto out;
    }
    /* Map the shared info frame */
    live_shinfo = xc_map_foreign_range(xch, domid, PAGE_SIZE,
                                       PROT_READ, info.shared_info_frame);
    if ( !live_shinfo && !info.hvm )
    {
        PERROR("Couldn't map live_shinfo");
        goto out;
    }
    auto_translated_physmap = xc_core_arch_auto_translated_physmap(&info);

    if ( domid != info.domid )
    {
        PERROR("Domain %d does not exist", domid);
        goto out;
    }

    ctxt = calloc(sizeof(*ctxt), info.max_vcpu_id + 1);
    if ( !ctxt )
    {
        PERROR("Could not allocate vcpu context array", domid);
        goto out;
    }

    for ( i = 0; i <= info.max_vcpu_id; i++ )
    {
        if ( xc_vcpu_getcontext(xch, domid, i, &ctxt[nr_vcpus]) == 0 )
        {
            if ( xc_core_arch_context_get(&arch_ctxt, &ctxt[nr_vcpus],
                                          xch, domid) )
                continue;
            nr_vcpus++;
        }
    }
    if ( nr_vcpus == 0 )
    {
        PERROR("No VCPU context could be grabbed");
        goto out;
    }

    /* obtain memory map */
    sts = xc_core_arch_memory_map_get(xch, &arch_ctxt, &info,
                                      live_shinfo, &memory_map,
                                      &nr_memory_map);
    if ( sts != 0 )
        goto out;

    /*
     * Note: this is the *current* number of pages and may change under
     * a live dump-core.  We'll just take this value, and if more pages
     * exist, we'll skip them.  If there's less, then we'll just not use
     * all the array...
     *
     * We don't want to use the total potential size of the memory map
     * since that is usually much higher than info.nr_pages.
     */
    nr_pages = info.nr_pages;

    if ( !auto_translated_physmap )
    {
        /* obtain p2m table */
        p2m_array = malloc(nr_pages * sizeof(p2m_array[0]));
        if ( p2m_array == NULL )
        {
            PERROR("Could not allocate p2m array");
            goto out;
        }

        sts = xc_core_arch_map_p2m(xch, dinfo->guest_width, &info, live_shinfo,
                                   &p2m, &dinfo->p2m_size);
        if ( sts != 0 )
            goto out;
    }
    else
    {
        pfn_array = malloc(nr_pages * sizeof(pfn_array[0]));
        if ( pfn_array == NULL )
        {
            PERROR("Could not allocate pfn array");
            goto out;
        }
    }

    /* ehdr.e_shnum and ehdr.e_shstrndx aren't known here yet. fill it later*/
    xc_core_ehdr_init(&ehdr);

    /* create section header */
    strtab = xc_core_strtab_init(xch);
    if ( strtab == NULL )
    {
        PERROR("Could not allocate string table");
        goto out;
    }
    sheaders = xc_core_shdr_init(xch);
    if ( sheaders == NULL )
    {
        PERROR("Could not allocate section headers");
        goto out;
    }
    /* null section */
    shdr = xc_core_shdr_get(xch,sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for null section");
        goto out;
    }

    /* .shstrtab */
    shdr = xc_core_shdr_get(xch,sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for shstrtab");
        goto out;
    }
    strtab_idx = shdr - sheaders->shdrs;
    /* strtab_shdr.sh_offset, strtab_shdr.sh_size aren't unknown.
     * fill it later
     */
    sts = xc_core_shdr_set(xch, shdr, strtab, ELF_SHSTRTAB, SHT_STRTAB, 0, 0, 0, 0);
    if ( sts != 0 )
        goto out;

    /* elf note section */
    /* here the number of section header is unknown. fix up offset later. */
    offset = sizeof(ehdr);
    filesz =
        sizeof(struct xen_dumpcore_elfnote_none) +         /* none */
        sizeof(struct xen_dumpcore_elfnote_header) +       /* core header */
        sizeof(struct xen_dumpcore_elfnote_xen_version) +  /* xen version */
        sizeof(struct xen_dumpcore_elfnote_format_version);/* format version */
    shdr = xc_core_shdr_get(xch,sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for note section");
        goto out;
    }
    sts = xc_core_shdr_set(xch, shdr, strtab, XEN_DUMPCORE_SEC_NOTE, SHT_NOTE,
                           offset, filesz, 0, 0);
    if ( sts != 0 )
        goto out;
    offset += filesz;

    /* prstatus */
    shdr = xc_core_shdr_get(xch,sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for .xen_prstatus");
        goto out;
    }
    filesz = sizeof(*ctxt) * nr_vcpus;
    sts = xc_core_shdr_set(xch, shdr, strtab, XEN_DUMPCORE_SEC_PRSTATUS,
                           SHT_PROGBITS, offset, filesz,
                           __alignof__(*ctxt), sizeof(*ctxt));
    if ( sts != 0 )
        goto out;
    offset += filesz;

    /* arch context */
    sts = xc_core_arch_context_get_shdr(xch, &arch_ctxt, sheaders, strtab,
                                        &filesz, offset);
    if ( sts != 0 )
        goto out;
    offset += filesz;

    /* shared_info */
    if ( live_shinfo != NULL )
    {
        shdr = xc_core_shdr_get(xch,sheaders);
        if ( shdr == NULL )
        {
            PERROR("Could not get section header for .xen_shared_info");
            goto out;
        }
        filesz = PAGE_SIZE;
        sts = xc_core_shdr_set(xch, shdr, strtab, XEN_DUMPCORE_SEC_SHARED_INFO,
                               SHT_PROGBITS, offset, filesz,
                               __alignof__(*live_shinfo), PAGE_SIZE);
        if ( sts != 0 )
            goto out;
        offset += filesz;
    }

    /*
     * pages and p2m/pfn are the last section to allocate section headers
     * so that we know the number of section headers here.
     * 2 = pages section and p2m/pfn table section
     */
    fixup = (sheaders->num + 2) * sizeof(*shdr);
    /* zeroth section should have zero offset */
    for ( i = 1; i < sheaders->num; i++ )
        sheaders->shdrs[i].sh_offset += fixup;
    offset += fixup;
    dummy_len = ROUNDUP(offset, PAGE_SHIFT) - offset; /* padding length */
    offset += dummy_len;

    /* pages */
    shdr = xc_core_shdr_get(xch,sheaders);
    if ( shdr == NULL )
    {
        PERROR("could not get section headers for .xen_pages");
        goto out;
    }
    filesz = (uint64_t)nr_pages * PAGE_SIZE;
    sts = xc_core_shdr_set(xch, shdr, strtab, XEN_DUMPCORE_SEC_PAGES, SHT_PROGBITS,
                           offset, filesz, PAGE_SIZE, PAGE_SIZE);
    if ( sts != 0 )
        goto out;
    offset += filesz;

    /* p2m/pfn table */
    shdr = xc_core_shdr_get(xch,sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for .xen_{p2m, pfn} table");
        goto out;
    }
    if ( !auto_translated_physmap )
    {
        filesz = (uint64_t)nr_pages * sizeof(p2m_array[0]);
        sts = xc_core_shdr_set(xch, shdr, strtab, XEN_DUMPCORE_SEC_P2M,
                               SHT_PROGBITS,
                               offset, filesz, __alignof__(p2m_array[0]),
                               sizeof(p2m_array[0]));
    }
    else
    {
        filesz = (uint64_t)nr_pages * sizeof(pfn_array[0]);
        sts = xc_core_shdr_set(xch, shdr, strtab, XEN_DUMPCORE_SEC_PFN,
                               SHT_PROGBITS,
                               offset, filesz, __alignof__(pfn_array[0]),
                               sizeof(pfn_array[0]));
    }
    if ( sts != 0 )
        goto out;
    offset += filesz;

    /* fixing up section header string table section header */
    filesz = strtab->length;
    sheaders->shdrs[strtab_idx].sh_offset = offset;
    sheaders->shdrs[strtab_idx].sh_size = filesz;

    /* write out elf header */
    ehdr.e_shnum = sheaders->num;
    ehdr.e_shstrndx = strtab_idx;
    ehdr.e_machine = ELF_ARCH_MACHINE;
    sts = dump_rtn(xch, args, (char*)&ehdr, sizeof(ehdr));
    if ( sts != 0 )
        goto out;

    /* section headers */
    sts = dump_rtn(xch, args, (char*)sheaders->shdrs,
                   sheaders->num * sizeof(sheaders->shdrs[0]));
    if ( sts != 0 )
        goto out;

    /* elf note section: xen core header */
    sts = elfnote_dump_none(xch, args, dump_rtn);
    if ( sts != 0 )
        goto out;

    /* elf note section: xen core header */
    sts = elfnote_dump_core_header(xch, args, dump_rtn, &info, nr_vcpus, nr_pages);
    if ( sts != 0 )
        goto out;

    /* elf note section: xen version */
    sts = elfnote_dump_xen_version(xch, args, dump_rtn, dinfo->guest_width);
    if ( sts != 0 )
        goto out;

    /* elf note section: format version */
    sts = elfnote_dump_format_version(xch, args, dump_rtn);
    if ( sts != 0 )
        goto out;

    /* prstatus: .xen_prstatus */
    sts = dump_rtn(xch, args, (char *)ctxt, sizeof(*ctxt) * nr_vcpus);
    if ( sts != 0 )
        goto out;

    if ( live_shinfo != NULL )
    {
        /* shared_info: .xen_shared_info */
        sts = dump_rtn(xch, args, (char*)live_shinfo, PAGE_SIZE);
        if ( sts != 0 )
            goto out;
    }

    /* arch specific context */
    sts = xc_core_arch_context_dump(xch, &arch_ctxt, args, dump_rtn);
    if ( sts != 0 )
        goto out;

    /* Pad the output data to page alignment. */
    memset(dummy, 0, PAGE_SIZE);
    sts = dump_rtn(xch, args, dummy, dummy_len);
    if ( sts != 0 )
        goto out;

    /* dump pages: .xen_pages */
    j = 0;
    dump_mem = dump_mem_start;
    for ( map_idx = 0; map_idx < nr_memory_map; map_idx++ )
    {
        uint64_t pfn_start;
        uint64_t pfn_end;

        pfn_start = memory_map[map_idx].addr >> PAGE_SHIFT;
        pfn_end = pfn_start + (memory_map[map_idx].size >> PAGE_SHIFT);
        for ( i = pfn_start; i < pfn_end; i++ )
        {
            uint64_t gmfn;
            void *vaddr;
            
            if ( j >= nr_pages )
            {
                /*
                 * When live dump-mode (-L option) is specified,
                 * guest domain may increase memory.
                 */
                IPRINTF("exceeded nr_pages (%ld) losing pages", nr_pages);
                goto copy_done;
            }

            if ( !auto_translated_physmap )
            {
                if ( dinfo->guest_width >= sizeof(unsigned long) )
                {
                    if ( dinfo->guest_width == sizeof(unsigned long) )
                        gmfn = p2m[i];
                    else
                        gmfn = ((uint64_t *)p2m)[i];
                    if ( gmfn == INVALID_P2M_ENTRY )
                        continue;
                }
                else
                {
                    gmfn = ((uint32_t *)p2m)[i];
                    if ( gmfn == (uint32_t)INVALID_P2M_ENTRY )
                       continue;
                }

                p2m_array[j].pfn = i;
                p2m_array[j].gmfn = gmfn;
            }
            else
            {
                if ( !xc_core_arch_gpfn_may_present(&arch_ctxt, i) )
                    continue;

                gmfn = i;
                pfn_array[j] = i;
            }

            vaddr = xc_map_foreign_range(
                xch, domid, PAGE_SIZE, PROT_READ, gmfn);
            if ( vaddr == NULL )
                continue;
            memcpy(dump_mem, vaddr, PAGE_SIZE);
            munmap(vaddr, PAGE_SIZE);
            dump_mem += PAGE_SIZE;
            if ( (j + 1) % DUMP_INCREMENT == 0 )
            {
                sts = dump_rtn(
                    xch, args, dump_mem_start, dump_mem - dump_mem_start);
                if ( sts != 0 )
                    goto out;
                dump_mem = dump_mem_start;
            }

            j++;
        }
    }

copy_done:
    sts = dump_rtn(xch, args, dump_mem_start, dump_mem - dump_mem_start);
    if ( sts != 0 )
        goto out;
    if ( j < nr_pages )
    {
        /* When live dump-mode (-L option) is specified,
         * guest domain may reduce memory. pad with zero pages.
         */
        IPRINTF("j (%ld) != nr_pages (%ld)", j, nr_pages);
        memset(dump_mem_start, 0, PAGE_SIZE);
        for (; j < nr_pages; j++) {
            sts = dump_rtn(xch, args, dump_mem_start, PAGE_SIZE);
            if ( sts != 0 )
                goto out;
            if ( !auto_translated_physmap )
            {
                p2m_array[j].pfn = XC_CORE_INVALID_PFN;
                p2m_array[j].gmfn = XC_CORE_INVALID_GMFN;
            }
            else
                pfn_array[j] = XC_CORE_INVALID_PFN;
        }
    }

    /* p2m/pfn table: .xen_p2m/.xen_pfn */
    if ( !auto_translated_physmap )
        sts = dump_rtn(
            xch, args, (char *)p2m_array, sizeof(p2m_array[0]) * nr_pages);
    else
        sts = dump_rtn(
            xch, args, (char *)pfn_array, sizeof(pfn_array[0]) * nr_pages);
    if ( sts != 0 )
        goto out;

    /* elf section header string table: .shstrtab */
    sts = dump_rtn(xch, args, strtab->strings, strtab->length);
    if ( sts != 0 )
        goto out;

    sts = 0;

out:
    if ( memory_map != NULL )
        free(memory_map);
    if ( p2m != NULL )
        munmap(p2m, PAGE_SIZE * P2M_FL_ENTRIES);
    if ( p2m_array != NULL )
        free(p2m_array);
    if ( pfn_array != NULL )
        free(pfn_array);
    if ( sheaders != NULL )
        xc_core_shdr_free(sheaders);
    if ( strtab != NULL )
        xc_core_strtab_free(strtab);
    if ( ctxt != NULL )
        free(ctxt);
    if ( dump_mem_start != NULL )
        free(dump_mem_start);
    if ( live_shinfo != NULL )
        munmap(live_shinfo, PAGE_SIZE);
    xc_core_arch_context_free(&arch_ctxt);

    return sts;
}

/* Callback args for writing to a local dump file. */
struct dump_args {
    int     fd;
};

/* Callback routine for writing to a local dump file. */
static int local_file_dump(xc_interface *xch,
                           void *args, char *buffer, unsigned int length)
{
    struct dump_args *da = args;

    if ( write_exact(da->fd, buffer, length) == -1 )
    {
        PERROR("Failed to write buffer");
        return -errno;
    }

    if ( length >= (DUMP_INCREMENT * PAGE_SIZE) )
    {
        // Now dumping pages -- make sure we discard clean pages from
        // the cache after each write
        discard_file_cache(xch, da->fd, 0 /* no flush */);
    }

    return 0;
}

int
xc_domain_dumpcore(xc_interface *xch,
                   uint32_t domid,
                   const char *corename)
{
    struct dump_args da;
    int sts;

    if ( (da.fd = open(corename, O_CREAT|O_RDWR|O_TRUNC, S_IWUSR|S_IRUSR)) < 0 )
    {
        PERROR("Could not open corefile %s", corename);
        return -errno;
    }

    sts = xc_domain_dumpcore_via_callback(
        xch, domid, &da, &local_file_dump);

    /* flush and discard any remaining portion of the file from cache */
    discard_file_cache(xch, da.fd, 1/* flush first*/);

    close(da.fd);

    return sts;
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
