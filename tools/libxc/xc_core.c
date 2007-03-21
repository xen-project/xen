/*
 * Elf format, (pfn, gmfn) table, IA64 support.
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
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
 *  |    .xen_ia64_mmapped_regs if ia64                      |
 *  |    .xen_shared_info if present                         |
 *  |    .xen_p2m or .xen_pfn                                |
 *  |    .xen_pages                                          |
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
 *  |.xen_ia64_mmapped_regs if ia64                          |
 *  |       mmapped_regs_t[nr_vcpus]                         |
 *  +--------------------------------------------------------+
 *  |.xen_shared_info if possible                            |
 *  +--------------------------------------------------------+
 *  |.xen_p2m or .xen_pfn                                    |
 *  |    .xen_p2m: struct xen_dumpcore_p2m[nr_pages]         |
 *  |    .xen_pfn: uint64_t[nr_pages]                        |
 *  +--------------------------------------------------------+
 *  |.xen_pages                                              |
 *  |    page * nr_pages                                     |
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

static int
copy_from_domain_page(int xc_handle,
                      uint32_t domid,
                      unsigned long mfn,
                      void *dst_page)
{
    void *vaddr = xc_map_foreign_range(
        xc_handle, domid, PAGE_SIZE, PROT_READ, mfn);
    if ( vaddr == NULL )
        return -1;
    memcpy(dst_page, vaddr, PAGE_SIZE);
    munmap(vaddr, PAGE_SIZE);
    return 0;
}

/* string table */
struct xc_core_strtab {
    char       *strings;
    uint16_t    current;
    uint16_t    max;
};

static struct xc_core_strtab*
xc_core_strtab_init(void)
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
    strtab->current = 1;

    return strtab;
}

static void
xc_core_strtab_free(struct xc_core_strtab *strtab)
{
    free(strtab->strings);
    free(strtab);
}

static uint16_t
xc_core_strtab_get(struct xc_core_strtab *strtab, const char *name)
{
    uint16_t ret = 0;
    uint16_t len = strlen(name) + 1;

    if ( strtab->current + len > strtab->max )
    {
        char *tmp;
        if ( strtab->max * 2 < strtab->max )
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

    ret = strtab->current;
    strcpy(strtab->strings + strtab->current, name);
    strtab->current += len;
    return ret;
}


/* section headers */
struct xc_core_section_headers {
    uint16_t    num;
    uint16_t    num_max;

    Elf64_Shdr  *shdrs;
};
#define SHDR_INIT       16
#define SHDR_INC        4

static struct xc_core_section_headers*
xc_core_shdr_init(void)
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
xc_core_shdr_get(struct xc_core_section_headers *sheaders)
{
    Elf64_Shdr *shdr;

    if ( sheaders->num == sheaders->num_max )
    {
        Elf64_Shdr *shdrs;
        if ( sheaders->num_max + SHDR_INC < sheaders->num_max )
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
xc_core_shdr_set(Elf64_Shdr *shdr,
                 struct xc_core_strtab *strtab,
                 const char *name, uint32_t type,
                 uint64_t offset, uint64_t size,
                 uint64_t addralign, uint64_t entsize)
{
    uint64_t name_idx = xc_core_strtab_get(strtab, name);
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

static int
elfnote_fill_xen_version(int xc_handle,
                         struct xen_dumpcore_elfnote_xen_version_desc
                         *xen_version)
{
    int rc;
    memset(xen_version, 0, sizeof(*xen_version));

    rc = xc_version(xc_handle, XENVER_version, NULL);
    if ( rc < 0 )
        return rc;
    xen_version->major_version = rc >> 16;
    xen_version->minor_version = rc & ((1 << 16) - 1);

    rc = xc_version(xc_handle, XENVER_extraversion,
                    &xen_version->extra_version);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xc_handle, XENVER_compile_info,
                    &xen_version->compile_info);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xc_handle,
                    XENVER_capabilities, &xen_version->capabilities);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xc_handle, XENVER_changeset, &xen_version->changeset);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xc_handle, XENVER_platform_parameters,
                    &xen_version->platform_parameters);
    if ( rc < 0 )
        return rc;

    rc = xc_version(xc_handle, XENVER_pagesize, NULL);
    if ( rc < 0 )
        return rc;
    xen_version->pagesize = rc;

    return 0;
}

static int
elfnote_fill_format_version(struct xen_dumpcore_elfnote_format_version_desc
                            *format_version)
{
    format_version->version = XEN_DUMPCORE_FORMAT_VERSION_CURRENT;
    return 0;
}

int
xc_domain_dumpcore_via_callback(int xc_handle,
                                uint32_t domid,
                                void *args,
                                dumpcore_rtn_t dump_rtn)
{
    xc_dominfo_t info;
    shared_info_t *live_shinfo = NULL;

    int nr_vcpus = 0;
    char *dump_mem, *dump_mem_start = NULL;
    vcpu_guest_context_t  ctxt[MAX_VIRT_CPUS];
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
    unsigned long max_pfn = 0;
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

    /* elf notes */
    struct elfnote elfnote;
    struct xen_dumpcore_elfnote_none_desc none;
    struct xen_dumpcore_elfnote_header_desc header;
    struct xen_dumpcore_elfnote_xen_version_desc xen_version;
    struct xen_dumpcore_elfnote_format_version_desc format_version;

    xc_core_arch_context_init(&arch_ctxt);
    if ( (dump_mem_start = malloc(DUMP_INCREMENT*PAGE_SIZE)) == NULL )
    {
        PERROR("Could not allocate dump_mem");
        goto out;
    }

    if ( xc_domain_getinfo(xc_handle, domid, 1, &info) != 1 )
    {
        PERROR("Could not get info for domain");
        goto out;
    }
    /* Map the shared info frame */
    live_shinfo = xc_map_foreign_range(xc_handle, domid, PAGE_SIZE,
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

    for ( i = 0; i <= info.max_vcpu_id; i++ )
    {
        if ( xc_vcpu_getcontext(xc_handle, domid, i, &ctxt[nr_vcpus]) == 0 )
        {
            if ( xc_core_arch_context_get(&arch_ctxt, &ctxt[nr_vcpus],
                                          xc_handle, domid) )
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
    sts = xc_core_arch_memory_map_get(xc_handle, &info, live_shinfo,
                                      &memory_map, &nr_memory_map);
    if ( sts != 0 )
        goto out;

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

        sts = xc_core_arch_map_p2m(xc_handle, &info, live_shinfo,
                                   &p2m, &max_pfn);
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

    /* create .xen_p2m or .xen_pfn */
    j = 0;
    for ( map_idx = 0; map_idx < nr_memory_map; map_idx++ )
    {
        uint64_t pfn_start;
        uint64_t pfn_end;

        pfn_start = memory_map[map_idx].addr >> PAGE_SHIFT;
        pfn_end = pfn_start + (memory_map[map_idx].size >> PAGE_SHIFT);
        for ( i = pfn_start; i < pfn_end; i++ )
        {
            if ( !auto_translated_physmap )
            {
                if ( p2m[i] == INVALID_P2M_ENTRY )
                    continue;
                p2m_array[j].pfn = i;
                p2m_array[j].gmfn = p2m[i];
            }
            else
            {
                /* try to map page to determin wheter it has underlying page */
                void *vaddr = xc_map_foreign_range(xc_handle, domid,
                                                   PAGE_SIZE, PROT_READ, i);
                if ( vaddr == NULL )
                    continue;
                munmap(vaddr, PAGE_SIZE);
                pfn_array[j] = i;
            }

            j++;
        }
    }
    if ( j != nr_pages )
    {
        PERROR("j (%ld) != nr_pages (%ld)", j , nr_pages);
        /* When live dump-mode (-L option) is specified,
         * guest domain may change its mapping.
         */
        nr_pages = j;
    }

    memset(&ehdr, 0, sizeof(ehdr));
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELF_ARCH_DATA;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    ehdr.e_ident[EI_ABIVERSION] = EV_CURRENT;

    ehdr.e_type = ET_CORE;
    ehdr.e_machine = ELF_ARCH_MACHINE;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry = 0;
    ehdr.e_phoff = 0;
    ehdr.e_shoff = sizeof(ehdr);
    ehdr.e_flags = ELF_CORE_EFLAGS;
    ehdr.e_ehsize = sizeof(ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 0;
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    /* ehdr.e_shnum and ehdr.e_shstrndx aren't known here yet. fill it later*/

    /* create section header */
    strtab = xc_core_strtab_init();
    if ( strtab == NULL )
    {
        PERROR("Could not allocate string table");
        goto out;
    }
    sheaders = xc_core_shdr_init();
    if ( sheaders == NULL )
    {
        PERROR("Could not allocate section headers");
        goto out;
    }
    /* null section */
    shdr = xc_core_shdr_get(sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for null section");
        goto out;
    }

    /* .shstrtab */
    shdr = xc_core_shdr_get(sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for shstrtab");
        goto out;
    }
    strtab_idx = shdr - sheaders->shdrs;
    /* strtab_shdr.sh_offset, strtab_shdr.sh_size aren't unknown.
     * fill it later
     */
    sts = xc_core_shdr_set(shdr, strtab, ELF_SHSTRTAB, SHT_STRTAB, 0, 0, 0, 0);
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
    shdr = xc_core_shdr_get(sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for note section");
        goto out;
    }
    sts = xc_core_shdr_set(shdr, strtab, XEN_DUMPCORE_SEC_NOTE, SHT_NOTE,
                           offset, filesz, 0, 0);
    if ( sts != 0 )
        goto out;
    offset += filesz;

    /* prstatus */
    shdr = xc_core_shdr_get(sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for .xen_prstatus");
        goto out;
    }
    filesz = sizeof(ctxt[0]) * nr_vcpus;
    sts = xc_core_shdr_set(shdr, strtab, XEN_DUMPCORE_SEC_PRSTATUS,
                           SHT_PROGBITS, offset, filesz,
                           __alignof__(ctxt[0]), sizeof(ctxt[0]));
    if ( sts != 0 )
        goto out;
    offset += filesz;

    /* arch context */
    sts = xc_core_arch_context_get_shdr(&arch_ctxt, sheaders, strtab,
                                        &filesz, offset);
    if ( sts != 0)
        goto out;
    offset += filesz;

    /* shared_info */
    if ( live_shinfo != NULL )
    {
        shdr = xc_core_shdr_get(sheaders);
        if ( shdr == NULL )
        {
            PERROR("Could not get section header for .xen_shared_info");
            goto out;
        }
        filesz = PAGE_SIZE;
        sts = xc_core_shdr_set(shdr, strtab, XEN_DUMPCORE_SEC_SHARED_INFO,
                               SHT_PROGBITS, offset, filesz,
                               __alignof__(*live_shinfo), PAGE_SIZE);
        if ( sts != 0 )
            goto out;
        offset += filesz;
    }

    /* p2m/pfn table */
    shdr = xc_core_shdr_get(sheaders);
    if ( shdr == NULL )
    {
        PERROR("Could not get section header for .xen_{p2m, pfn} table");
        goto out;
    }
    if ( !auto_translated_physmap )
    {
        filesz = nr_pages * sizeof(p2m_array[0]);
        sts = xc_core_shdr_set(shdr, strtab, XEN_DUMPCORE_SEC_P2M,
                               SHT_PROGBITS,
                               offset, filesz, __alignof__(p2m_array[0]),
                               sizeof(p2m_array[0]));
        if ( sts != 0 )
            goto out;
    }
    else
    {
        filesz = nr_pages * sizeof(pfn_array[0]);
        sts = xc_core_shdr_set(shdr, strtab, XEN_DUMPCORE_SEC_PFN,
                               SHT_PROGBITS,
                               offset, filesz, __alignof__(pfn_array[0]),
                               sizeof(pfn_array[0]));
        if ( sts != 0 )
            goto out;
    }
    offset += filesz;

    /* pages */
    shdr = xc_core_shdr_get(sheaders);
    if ( shdr == NULL )
    {
        PERROR("could not get section headers for .xen_pages");
        goto out;
    }

    /*
     * pages are the last section to allocate section headers
     * so that we know the number of section headers here.
     */
    fixup = sheaders->num * sizeof(*shdr);
    /* zeroth section should have zero offset */
    for ( i = 1; i < sheaders->num; i++ )
        sheaders->shdrs[i].sh_offset += fixup;
    offset += fixup;
    dummy_len = ROUNDUP(offset, PAGE_SHIFT) - offset; /* padding length */
    offset += dummy_len;

    filesz = nr_pages * PAGE_SIZE;
    sts = xc_core_shdr_set(shdr, strtab, XEN_DUMPCORE_SEC_PAGES, SHT_PROGBITS,
                           offset, filesz, PAGE_SIZE, PAGE_SIZE);
    if ( sts != 0 )
        goto out;
    offset += filesz;

    /* fixing up section header string table section header */
    filesz = strtab->current;
    sheaders->shdrs[strtab_idx].sh_offset = offset;
    sheaders->shdrs[strtab_idx].sh_size = filesz;

    /* write out elf header */
    ehdr.e_shnum = sheaders->num;
    ehdr.e_shstrndx = strtab_idx;
    sts = dump_rtn(args, (char*)&ehdr, sizeof(ehdr));
    if ( sts != 0 )
        goto out;

    /* section headers */
    sts = dump_rtn(args, (char*)sheaders->shdrs,
                   sheaders->num * sizeof(sheaders->shdrs[0]));
    if ( sts != 0 )
        goto out;

    /* elf note section */
    memset(&elfnote, 0, sizeof(elfnote));
    elfnote.namesz = strlen(XEN_DUMPCORE_ELFNOTE_NAME) + 1;
    strncpy(elfnote.name, XEN_DUMPCORE_ELFNOTE_NAME, sizeof(elfnote.name));

    /* elf note section:xen core header */
    elfnote.descsz = sizeof(none);
    elfnote.type = XEN_ELFNOTE_DUMPCORE_NONE;
    sts = dump_rtn(args, (char*)&elfnote, sizeof(elfnote));
    if ( sts != 0 )
        goto out;
    sts = dump_rtn(args, (char*)&none, sizeof(none));
    if ( sts != 0 )
        goto out;

    /* elf note section:xen core header */
    elfnote.descsz = sizeof(header);
    elfnote.type = XEN_ELFNOTE_DUMPCORE_HEADER;
    header.xch_magic = info.hvm ? XC_CORE_MAGIC_HVM : XC_CORE_MAGIC;
    header.xch_nr_vcpus = nr_vcpus;
    header.xch_nr_pages = nr_pages;
    header.xch_page_size = PAGE_SIZE;
    sts = dump_rtn(args, (char*)&elfnote, sizeof(elfnote));
    if ( sts != 0 )
        goto out;
    sts = dump_rtn(args, (char*)&header, sizeof(header));
    if ( sts != 0 )
        goto out;

    /* elf note section: xen version */
    elfnote.descsz = sizeof(xen_version);
    elfnote.type = XEN_ELFNOTE_DUMPCORE_XEN_VERSION;
    elfnote_fill_xen_version(xc_handle, &xen_version);
    sts = dump_rtn(args, (char*)&elfnote, sizeof(elfnote));
    if ( sts != 0 )
        goto out;
    sts = dump_rtn(args, (char*)&xen_version, sizeof(xen_version));
    if ( sts != 0 )
        goto out;

    /* elf note section: format version */
    elfnote.descsz = sizeof(format_version);
    elfnote.type = XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION;
    elfnote_fill_format_version(&format_version);
    sts = dump_rtn(args, (char*)&elfnote, sizeof(elfnote));
    if ( sts != 0 )
        goto out;
    sts = dump_rtn(args, (char*)&format_version, sizeof(format_version));
    if ( sts != 0 )
        goto out;

    /* prstatus: .xen_prstatus */
    sts = dump_rtn(args, (char *)&ctxt, sizeof(ctxt[0]) * nr_vcpus);
    if ( sts != 0 )
        goto out;

    if ( live_shinfo != NULL )
    {
        /* shared_info: .xen_shared_info */
        sts = dump_rtn(args, (char*)live_shinfo, PAGE_SIZE);
        if ( sts != 0 )
            goto out;
    }

    /* arch specific context */
    sts = xc_core_arch_context_dump(&arch_ctxt, args, dump_rtn);
    if ( sts != 0 )
        goto out;

    /* p2m/pfn table: .xen_p2m/.xen_pfn */
    if ( !auto_translated_physmap )
        sts = dump_rtn(args, (char *)p2m_array,
                       sizeof(p2m_array[0]) * nr_pages);
    else
        sts = dump_rtn(args, (char *)pfn_array,
                       sizeof(pfn_array[0]) * nr_pages);
    if ( sts != 0 )
        goto out;

    /* Pad the output data to page alignment. */
    memset(dummy, 0, PAGE_SIZE);
    sts = dump_rtn(args, dummy, dummy_len);
    if ( sts != 0 )
        goto out;

    /* dump pages: .xen_pages */
    for ( dump_mem = dump_mem_start, i = 0; i < nr_pages; i++ )
    {
        uint64_t gmfn;
        if ( !auto_translated_physmap )
            gmfn = p2m_array[i].gmfn;
        else
            gmfn = pfn_array[i];

        copy_from_domain_page(xc_handle, domid, gmfn, dump_mem);
        dump_mem += PAGE_SIZE;
        if ( ((i + 1) % DUMP_INCREMENT == 0) || ((i + 1) == nr_pages) )
        {
            sts = dump_rtn(args, dump_mem_start, dump_mem - dump_mem_start);
            if ( sts != 0 )
                goto out;
            dump_mem = dump_mem_start;
        }
    }

    /* elf section header string table: .shstrtab */
    sts = dump_rtn(args, strtab->strings, strtab->current);
    if ( sts != 0 )
        goto out;

    sts = 0;

out:
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
static int local_file_dump(void *args, char *buffer, unsigned int length)
{
    struct dump_args *da = args;
    int bytes, offset;

    for ( offset = 0; offset < length; offset += bytes )
    {
        bytes = write(da->fd, &buffer[offset], length-offset);
        if ( bytes <= 0 )
        {
            PERROR("Failed to write buffer");
            return -errno;
        }
    }

    if (length >= DUMP_INCREMENT*PAGE_SIZE) {
        // Now dumping pages -- make sure we discard clean pages from
        // the cache after each write
        discard_file_cache(da->fd, 0 /* no flush */);
    }

    return 0;
}

int
xc_domain_dumpcore(int xc_handle,
                   uint32_t domid,
                   const char *corename)
{
    struct dump_args da;
    int sts;

    if ( (da.fd = open(corename, O_CREAT|O_RDWR, S_IWUSR|S_IRUSR)) < 0 )
    {
        PERROR("Could not open corefile %s", corename);
        return -errno;
    }

    sts = xc_domain_dumpcore_via_callback(
        xc_handle, domid, &da, &local_file_dump);

    /* flush and discard any remaining portion of the file from cache */
    discard_file_cache(da.fd, 1/* flush first*/);

    close(da.fd);

    return sts;
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
