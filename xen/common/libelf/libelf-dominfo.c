/*
 * parse xen-specific informations out of elf kernel binaries.
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
/* xen features                                                             */

static const char *const elf_xen_feature_names[] = {
    [XENFEAT_writable_page_tables] = "writable_page_tables",
    [XENFEAT_writable_descriptor_tables] = "writable_descriptor_tables",
    [XENFEAT_auto_translated_physmap] = "auto_translated_physmap",
    [XENFEAT_supervisor_mode_kernel] = "supervisor_mode_kernel",
    [XENFEAT_pae_pgdir_above_4gb] = "pae_pgdir_above_4gb",
    [XENFEAT_hvm_callback_vector] = "hvm_callback_vector",
    [XENFEAT_dom0] = "dom0"
};
static const unsigned elf_xen_features =
sizeof(elf_xen_feature_names) / sizeof(elf_xen_feature_names[0]);

elf_errorstatus elf_xen_parse_features(const char *features,
                           uint32_t *supported,
                           uint32_t *required)
{
    unsigned char feature[64];
    unsigned pos, len, i;

    if ( features == NULL )
        return 0;

    for ( pos = 0; features[pos] != '\0'; pos += len )
    {
        elf_memset_unchecked(feature, 0, sizeof(feature));
        for ( len = 0;; len++ )
        {
            if ( len >= sizeof(feature)-1 )
                break;
            if ( features[pos + len] == '\0' )
                break;
            if ( features[pos + len] == '|' )
            {
                len++;
                break;
            }
            feature[len] = features[pos + len];
        }

        for ( i = 0; i < elf_xen_features; i++ )
        {
            if ( !elf_xen_feature_names[i] )
                continue;
            if ( feature[0] == '!' )
            {
                /* required */
                if ( !strcmp(feature + 1, elf_xen_feature_names[i]) )
                {
                    elf_xen_feature_set(i, supported);
                    if ( required )
                        elf_xen_feature_set(i, required);
                    break;
                }
            }
            else
            {
                /* supported */
                if ( !strcmp(feature, elf_xen_feature_names[i]) )
                {
                    elf_xen_feature_set(i, supported);
                    break;
                }
            }
        }
        if ( i == elf_xen_features && required && feature[0] == '!' )
            return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------------ */
/* xen elf notes                                                            */

elf_errorstatus elf_xen_parse_note(struct elf_binary *elf,
                       struct elf_dom_parms *parms,
                       ELF_HANDLE_DECL(elf_note) note)
{
/* *INDENT-OFF* */
    static const struct {
        char *name;
        bool str;
    } note_desc[] = {
        [XEN_ELFNOTE_ENTRY] = { "ENTRY", 0},
        [XEN_ELFNOTE_HYPERCALL_PAGE] = { "HYPERCALL_PAGE", 0},
        [XEN_ELFNOTE_VIRT_BASE] = { "VIRT_BASE", 0},
        [XEN_ELFNOTE_INIT_P2M] = { "INIT_P2M", 0},
        [XEN_ELFNOTE_PADDR_OFFSET] = { "PADDR_OFFSET", 0},
        [XEN_ELFNOTE_HV_START_LOW] = { "HV_START_LOW", 0},
        [XEN_ELFNOTE_XEN_VERSION] = { "XEN_VERSION", 1},
        [XEN_ELFNOTE_GUEST_OS] = { "GUEST_OS", 1},
        [XEN_ELFNOTE_GUEST_VERSION] = { "GUEST_VERSION", 1},
        [XEN_ELFNOTE_LOADER] = { "LOADER", 1},
        [XEN_ELFNOTE_PAE_MODE] = { "PAE_MODE", 1},
        [XEN_ELFNOTE_FEATURES] = { "FEATURES", 1},
        [XEN_ELFNOTE_SUPPORTED_FEATURES] = { "SUPPORTED_FEATURES", 0},
        [XEN_ELFNOTE_BSD_SYMTAB] = { "BSD_SYMTAB", 1},
        [XEN_ELFNOTE_SUSPEND_CANCEL] = { "SUSPEND_CANCEL", 0 },
        [XEN_ELFNOTE_MOD_START_PFN] = { "MOD_START_PFN", 0 },
        [XEN_ELFNOTE_PHYS32_ENTRY] = { "PHYS32_ENTRY", 0 },
    };
/* *INDENT-ON* */

    const char *str = NULL;
    uint64_t val = 0;
    unsigned int i;
    unsigned type = elf_uval(elf, note, type);

    if ( (type >= sizeof(note_desc) / sizeof(note_desc[0])) ||
         (note_desc[type].name == NULL) )
    {
        elf_msg(elf, "ELF: note: unknown (%#x)\n", type);
        return 0;
    }

    if ( note_desc[type].str )
    {
        str = elf_strval(elf, elf_note_desc(elf, note));
        if (str == NULL)
            /* elf_strval will mark elf broken if it fails so no need to log */
            return 0;
        elf_msg(elf, "ELF: note: %s = \"%s\"\n", note_desc[type].name, str);
        parms->elf_notes[type].type = XEN_ENT_STR;
        parms->elf_notes[type].data.str = str;
    }
    else
    {
        val = elf_note_numeric(elf, note);
        elf_msg(elf, "ELF: note: %s = %#" PRIx64 "\n", note_desc[type].name, val);
        parms->elf_notes[type].type = XEN_ENT_LONG;
        parms->elf_notes[type].data.num = val;
    }
    parms->elf_notes[type].name = note_desc[type].name;

    switch ( type )
    {
    case XEN_ELFNOTE_LOADER:
        safe_strcpy(parms->loader, str);
        break;
    case XEN_ELFNOTE_GUEST_OS:
        safe_strcpy(parms->guest_os, str);
        break;
    case XEN_ELFNOTE_GUEST_VERSION:
        safe_strcpy(parms->guest_ver, str);
        break;
    case XEN_ELFNOTE_XEN_VERSION:
        safe_strcpy(parms->xen_ver, str);
        break;
    case XEN_ELFNOTE_PAE_MODE:
        if ( !strcmp(str, "yes") )
            parms->pae = XEN_PAE_EXTCR3;
        if ( strstr(str, "bimodal") )
            parms->pae = XEN_PAE_BIMODAL;
        break;
    case XEN_ELFNOTE_BSD_SYMTAB:
        if ( !strcmp(str, "yes") )
            parms->bsd_symtab = 1;
        break;

    case XEN_ELFNOTE_VIRT_BASE:
        parms->virt_base = val;
        break;
    case XEN_ELFNOTE_ENTRY:
        parms->virt_entry = val;
        break;
    case XEN_ELFNOTE_INIT_P2M:
        parms->p2m_base = val;
        break;
    case XEN_ELFNOTE_MOD_START_PFN:
        parms->unmapped_initrd = !!val;
        break;
    case XEN_ELFNOTE_PADDR_OFFSET:
        parms->elf_paddr_offset = val;
        break;
    case XEN_ELFNOTE_HYPERCALL_PAGE:
        parms->virt_hypercall = val;
        break;
    case XEN_ELFNOTE_HV_START_LOW:
        parms->virt_hv_start_low = val;
        break;

    case XEN_ELFNOTE_FEATURES:
        if ( elf_xen_parse_features(str, parms->f_supported,
                                    parms->f_required) )
            return -1;
        break;

    case XEN_ELFNOTE_SUPPORTED_FEATURES:
        for ( i = 0; i < XENFEAT_NR_SUBMAPS; ++i )
            parms->f_supported[i] |= elf_note_numeric_array(
                elf, note, sizeof(*parms->f_supported), i);
        break;

    case XEN_ELFNOTE_PHYS32_ENTRY:
        parms->phys_entry = val;
        break;
    }
    return 0;
}

#define ELF_NOTE_INVALID (~0U)

static unsigned elf_xen_parse_notes(struct elf_binary *elf,
                               struct elf_dom_parms *parms,
                               elf_ptrval start,
                               elf_ptrval end,
                               unsigned *total_note_count)
{
    unsigned xen_elfnotes = 0;
    ELF_HANDLE_DECL(elf_note) note;
    const char *note_name;

    parms->elf_note_start = start;
    parms->elf_note_end   = end;
    for ( note = ELF_MAKE_HANDLE(elf_note, parms->elf_note_start);
          ELF_HANDLE_PTRVAL(note) < parms->elf_note_end;
          note = elf_note_next(elf, note) )
    {
#ifdef __XEN__
        process_pending_softirqs();
#endif

        if ( *total_note_count >= ELF_MAX_TOTAL_NOTE_COUNT )
        {
            elf_mark_broken(elf, "too many ELF notes");
            break;
        }
        (*total_note_count)++;
        note_name = elf_note_name(elf, note);
        if ( note_name == NULL )
            continue;
        if ( strcmp(note_name, "Xen") )
            continue;
        if ( elf_xen_parse_note(elf, parms, note) )
            return ELF_NOTE_INVALID;
        xen_elfnotes++;
    }
    return xen_elfnotes;
}

/* ------------------------------------------------------------------------ */
/* __xen_guest section                                                      */

elf_errorstatus elf_xen_parse_guest_info(struct elf_binary *elf,
                             struct elf_dom_parms *parms)
{
    elf_ptrval h;
    unsigned char name[32], value[128];
    unsigned len;

    h = parms->guest_info;
#define STAR(h) (elf_access_unsigned(elf, (h), 0, 1))
    while ( STAR(h) )
    {
        elf_memset_unchecked(name, 0, sizeof(name));
        elf_memset_unchecked(value, 0, sizeof(value));
        for ( len = 0;; len++, h++ )
        {
            if ( len >= sizeof(name)-1 )
                break;
            if ( STAR(h) == '\0' )
                break;
            if ( STAR(h) == ',' )
            {
                h++;
                break;
            }
            if ( STAR(h) == '=' )
            {
                h++;
                for ( len = 0;; len++, h++ )
                {
                    if ( len >= sizeof(value)-1 )
                        break;
                    if ( STAR(h) == '\0' )
                        break;
                    if ( STAR(h) == ',' )
                    {
                        h++;
                        break;
                    }
                    value[len] = STAR(h);
                }
                break;
            }
            name[len] = STAR(h);
        }
        elf_msg(elf, "ELF: %s=\"%s\"\n", name, value);

        /* strings */
        if ( !strcmp(name, "LOADER") )
            safe_strcpy(parms->loader, value);
        if ( !strcmp(name, "GUEST_OS") )
            safe_strcpy(parms->guest_os, value);
        if ( !strcmp(name, "GUEST_VER") )
            safe_strcpy(parms->guest_ver, value);
        if ( !strcmp(name, "XEN_VER") )
            safe_strcpy(parms->xen_ver, value);
        if ( !strcmp(name, "PAE") )
        {
            if ( !strcmp(value, "yes[extended-cr3]") )
                parms->pae = XEN_PAE_EXTCR3;
            else if ( !strncmp(value, "yes", 3) )
                parms->pae = XEN_PAE_YES;
        }
        if ( !strcmp(name, "BSD_SYMTAB") )
            parms->bsd_symtab = 1;

        /* longs */
        if ( !strcmp(name, "VIRT_BASE") )
            parms->virt_base = strtoull(value, NULL, 0);
        if ( !strcmp(name, "VIRT_ENTRY") )
            parms->virt_entry = strtoull(value, NULL, 0);
        if ( !strcmp(name, "ELF_PADDR_OFFSET") )
            parms->elf_paddr_offset = strtoull(value, NULL, 0);
        if ( !strcmp(name, "HYPERCALL_PAGE") )
            parms->virt_hypercall = (strtoull(value, NULL, 0) << 12) +
                parms->virt_base;

        /* other */
        if ( !strcmp(name, "FEATURES") )
            if ( elf_xen_parse_features(value, parms->f_supported,
                                        parms->f_required) )
                return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* sanity checks                                                            */

static elf_errorstatus elf_xen_note_check(struct elf_binary *elf,
                              struct elf_dom_parms *parms)
{
    if ( (ELF_PTRVAL_INVALID(parms->elf_note_start)) &&
         (ELF_PTRVAL_INVALID(parms->guest_info)) )
    {
        unsigned machine = elf_uval(elf, elf->ehdr, e_machine);
        if ( (machine == EM_386) || (machine == EM_X86_64) )
        {
            elf_err(elf, "ERROR: Not a Xen-ELF image: "
                    "No ELF notes or '__xen_guest' section found\n");
            return -1;
        }
        return 0;
    }

    if ( elf_uval(elf, elf->ehdr, e_machine) == EM_ARM )
    {
         elf_msg(elf, "ELF: Not bothering with notes on ARM\n");
         return 0;
    }

    /* Check the contents of the Xen notes or guest string. */
    if ( ((strlen(parms->loader) == 0) ||
          strncmp(parms->loader, "generic", 7)) &&
         ((strlen(parms->guest_os) == 0) ||
          strncmp(parms->guest_os, "linux", 5)) )
    {
        elf_err(elf,
                "ERROR: Will only load images built for the generic loader or Linux images"
                " (Not '%.*s' and '%.*s')\n",
                (int)sizeof(parms->loader), parms->loader,
                (int)sizeof(parms->guest_os), parms->guest_os);
        return -1;
    }

    if ( (strlen(parms->xen_ver) == 0) ||
         strncmp(parms->xen_ver, "xen-3.0", 7) )
    {
        elf_err(elf, "ERROR: Xen will only load images built for Xen v3.0 "
                "(Not '%.*s')\n",
                (int)sizeof(parms->xen_ver), parms->xen_ver);
        return -1;
    }
    return 0;
}

static elf_errorstatus elf_xen_addr_calc_check(struct elf_binary *elf,
                                   struct elf_dom_parms *parms)
{
    uint64_t virt_offset;

    if ( (parms->elf_paddr_offset != UNSET_ADDR) &&
         (parms->virt_base == UNSET_ADDR) )
    {
        elf_err(elf, "ERROR: ELF_PADDR_OFFSET set, VIRT_BASE unset\n");
        return -1;
    }

    /* Initial guess for virt_base is 0 if it is not explicitly defined. */
    if ( parms->virt_base == UNSET_ADDR )
    {
        parms->virt_base = 0;
        elf_msg(elf, "ELF: VIRT_BASE unset, using %#" PRIx64 "\n",
                parms->virt_base);
    }

    /*
     * If we are using the legacy __xen_guest section then elf_pa_off
     * defaults to v_start in order to maintain compatibility with
     * older hypervisors which set padd in the ELF header to
     * virt_base.
     *
     * If we are using the modern ELF notes interface then the default
     * is 0.
     */
    if ( parms->elf_paddr_offset == UNSET_ADDR )
    {
        if ( parms->elf_note_start )
            parms->elf_paddr_offset = 0;
        else
            parms->elf_paddr_offset = parms->virt_base;
        elf_msg(elf, "ELF_PADDR_OFFSET unset, using %#" PRIx64 "\n",
                parms->elf_paddr_offset);
    }

    virt_offset = parms->virt_base - parms->elf_paddr_offset;
    parms->virt_kstart = elf->pstart + virt_offset;
    parms->virt_kend   = elf->pend   + virt_offset;

    if ( parms->virt_entry == UNSET_ADDR )
        parms->virt_entry = elf_uval(elf, elf->ehdr, e_entry);

    if ( parms->bsd_symtab )
    {
        elf_parse_bsdsyms(elf, elf->pend);
        if ( elf->bsd_symtab_pend )
            parms->virt_kend = elf->bsd_symtab_pend + virt_offset;
    }

    elf_msg(elf, "ELF: addresses:\n");
    elf_msg(elf, "    virt_base        = 0x%" PRIx64 "\n", parms->virt_base);
    elf_msg(elf, "    elf_paddr_offset = 0x%" PRIx64 "\n", parms->elf_paddr_offset);
    elf_msg(elf, "    virt_offset      = 0x%" PRIx64 "\n", virt_offset);
    elf_msg(elf, "    virt_kstart      = 0x%" PRIx64 "\n", parms->virt_kstart);
    elf_msg(elf, "    virt_kend        = 0x%" PRIx64 "\n", parms->virt_kend);
    elf_msg(elf, "    virt_entry       = 0x%" PRIx64 "\n", parms->virt_entry);
    elf_msg(elf, "    p2m_base         = 0x%" PRIx64 "\n", parms->p2m_base);

    if ( (parms->virt_kstart > parms->virt_kend) ||
         (parms->virt_entry < parms->virt_kstart) ||
         (parms->virt_entry > parms->virt_kend) ||
         (parms->virt_base > parms->virt_kstart) )
    {
        elf_err(elf, "ERROR: ELF start or entries are out of bounds\n");
        return -1;
    }

    if ( (parms->p2m_base != UNSET_ADDR) &&
         (parms->p2m_base >= parms->virt_kstart) &&
         (parms->p2m_base < parms->virt_kend) )
    {
        elf_err(elf, "ERROR: P->M table base is out of bounds\n");
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------------ */
/* glue it all together ...                                                 */

elf_errorstatus elf_xen_parse(struct elf_binary *elf,
                  struct elf_dom_parms *parms)
{
    ELF_HANDLE_DECL(elf_shdr) shdr;
    ELF_HANDLE_DECL(elf_phdr) phdr;
    unsigned xen_elfnotes = 0;
    unsigned i, count, more_notes;
    unsigned total_note_count = 0;

    elf_memset_unchecked(parms, 0, sizeof(*parms));
    parms->virt_base = UNSET_ADDR;
    parms->virt_entry = UNSET_ADDR;
    parms->virt_hypercall = UNSET_ADDR;
    parms->virt_hv_start_low = UNSET_ADDR;
    parms->p2m_base = UNSET_ADDR;
    parms->elf_paddr_offset = UNSET_ADDR;
    parms->phys_entry = UNSET_ADDR32;

    /* Find and parse elf notes. */
    count = elf_phdr_count(elf);
    for ( i = 0; i < count; i++ )
    {
        phdr = elf_phdr_by_index(elf, i);
        if ( !elf_access_ok(elf, ELF_HANDLE_PTRVAL(phdr), 1) )
            /* input has an insane program header count field */
            break;
        if ( elf_uval(elf, phdr, p_type) != PT_NOTE )
            continue;

        /*
         * Some versions of binutils do not correctly set p_offset for
         * note segments.
         */
        if (elf_uval(elf, phdr, p_offset) == 0)
             continue;

        more_notes = elf_xen_parse_notes(elf, parms,
                                 elf_segment_start(elf, phdr),
                                 elf_segment_end(elf, phdr),
                                 &total_note_count);
        if ( more_notes == ELF_NOTE_INVALID )
            return -1;

        xen_elfnotes += more_notes;
    }

    /*
     * Fall back to any SHT_NOTE sections if no valid note segments
     * were found.
     */
    if ( xen_elfnotes == 0 )
    {
        count = elf_shdr_count(elf);
        for ( i = 1; i < count; i++ )
        {
            shdr = elf_shdr_by_index(elf, i);
            if ( !elf_access_ok(elf, ELF_HANDLE_PTRVAL(shdr), 1) )
                /* input has an insane section header count field */
                break;

            if ( elf_uval(elf, shdr, sh_type) != SHT_NOTE )
                continue;

            more_notes = elf_xen_parse_notes(elf, parms,
                                     elf_section_start(elf, shdr),
                                     elf_section_end(elf, shdr),
                                     &total_note_count);

            if ( more_notes == ELF_NOTE_INVALID )
                return -1;

            if ( xen_elfnotes == 0 && more_notes > 0 )
                elf_msg(elf, "ELF: using notes from SHT_NOTE section\n");

            xen_elfnotes += more_notes;
        }

    }

    /*
     * Finally fall back to the __xen_guest section.
     */
    if ( xen_elfnotes == 0 )
    {
        shdr = elf_shdr_by_name(elf, "__xen_guest");
        if ( ELF_HANDLE_VALID(shdr) )
        {
            parms->guest_info = elf_section_start(elf, shdr);
            parms->elf_note_start = ELF_INVALID_PTRVAL;
            parms->elf_note_end   = ELF_INVALID_PTRVAL;
            elf_msg(elf, "ELF: __xen_guest: \"%s\"\n",
                    elf_strfmt(elf, parms->guest_info));
            elf_xen_parse_guest_info(elf, parms);
        }
    }

    if ( elf_xen_note_check(elf, parms) != 0 )
        return -1;
    if ( elf_xen_addr_calc_check(elf, parms) != 0 )
        return -1;
    return 0;
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
