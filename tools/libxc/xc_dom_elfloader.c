/*
 * Xen domain builder -- ELF bits.
 *
 * Parse and load ELF kernel images.
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
 *
 * written 2006 by Gerd Hoffmann <kraxel@suse.de>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom.h"
#include "xc_bitops.h"

#define XEN_VER "xen-3.0"

/* ------------------------------------------------------------------------ */

static void log_callback(struct elf_binary *elf, void *caller_data,
                         bool iserr, const char *fmt, va_list al) {
    xc_interface *xch = caller_data;

    xc_reportv(xch,
          xch->dombuild_logger ? xch->dombuild_logger : xch->error_handler,
                       iserr ? XTL_ERROR : XTL_DETAIL,
                       iserr ? XC_INVALID_KERNEL : XC_ERROR_NONE,
                       fmt, al);
}

void xc_elf_set_logfile(xc_interface *xch, struct elf_binary *elf,
                        int verbose) {
    elf_set_log(elf, log_callback, xch, verbose /* convert to bool */);
}

/* ------------------------------------------------------------------------ */

static char *xc_dom_guest_type(struct xc_dom_image *dom,
                               struct elf_binary *elf)
{
    uint64_t machine = elf_uval(elf, elf->ehdr, e_machine);

    switch ( machine )
    {
    case EM_386:
        switch ( dom->parms.pae )
        {
        case 3 /* PAEKERN_bimodal */:
            if ( strstr(dom->xen_caps, "xen-3.0-x86_32p") )
                return "xen-3.0-x86_32p";
            return "xen-3.0-x86_32";
        case PAEKERN_extended_cr3:
        case PAEKERN_yes:
            return "xen-3.0-x86_32p";
        case PAEKERN_no:
        default:
            return "xen-3.0-x86_32";
        }
    case EM_X86_64:
        return "xen-3.0-x86_64";
    default:
        return "xen-3.0-unknown";
    }
}

/* ------------------------------------------------------------------------ */
/* parse elf binary                                                         */

static elf_negerrnoval check_elf_kernel(struct xc_dom_image *dom, bool verbose)
{
    if ( dom->kernel_blob == NULL )
    {
        if ( verbose )
            xc_dom_panic(dom->xch,
                         XC_INTERNAL_ERROR, "%s: no kernel image loaded",
                         __FUNCTION__);
        return -EINVAL;
    }

    if ( !elf_is_elfbinary(dom->kernel_blob, dom->kernel_size) )
    {
        if ( verbose )
            xc_dom_panic(dom->xch,
                         XC_INVALID_KERNEL, "%s: kernel is not an ELF image",
                         __FUNCTION__);
        return -EINVAL;
    }
    return 0;
}

static elf_negerrnoval xc_dom_probe_elf_kernel(struct xc_dom_image *dom)
{
    return check_elf_kernel(dom, 0);
}

static elf_errorstatus xc_dom_load_elf_symtab(struct xc_dom_image *dom,
                                  struct elf_binary *elf, bool load)
{
    struct elf_binary syms;
    ELF_HANDLE_DECL(elf_shdr) shdr; ELF_HANDLE_DECL(elf_shdr) shdr2;
    xen_vaddr_t symtab, maxaddr;
    elf_ptrval hdr;
    size_t size;
    unsigned h, count, type, i, tables = 0;
    unsigned long *strtab_referenced = NULL;

    if ( elf_swap(elf) )
    {
        DOMPRINTF("%s: non-native byte order, bsd symtab not supported",
                  __FUNCTION__);
        return 0;
    }

    if ( load )
    {
        char *hdr_ptr;
        size_t allow_size;

        if ( !dom->bsd_symtab_start )
            return 0;
        size = dom->kernel_seg.vend - dom->bsd_symtab_start;
        hdr_ptr = xc_dom_vaddr_to_ptr(dom, dom->bsd_symtab_start, &allow_size);
        if ( hdr_ptr == NULL )
        {
            DOMPRINTF("%s/load: xc_dom_vaddr_to_ptr(dom,dom->bsd_symtab_start"
                      " => NULL", __FUNCTION__);
            return -1;
        }
        elf->caller_xdest_base = hdr_ptr;
        elf->caller_xdest_size = allow_size;
        hdr = ELF_REALPTR2PTRVAL(hdr_ptr);
        elf_store_val(elf, unsigned, hdr, size - sizeof(unsigned));
    }
    else
    {
        char *hdr_ptr;

        size = sizeof(unsigned) + elf_size(elf, elf->ehdr) +
            elf_shdr_count(elf) * elf_size(elf, shdr);
        hdr_ptr = xc_dom_malloc(dom, size);
        if ( hdr_ptr == NULL )
            return 0;
        elf->caller_xdest_base = hdr_ptr;
        elf->caller_xdest_size = size;
        hdr = ELF_REALPTR2PTRVAL(hdr_ptr);
        dom->bsd_symtab_start = elf_round_up(elf, dom->kernel_seg.vend);
    }

    elf_memcpy_safe(elf, hdr + sizeof(unsigned),
           ELF_IMAGE_BASE(elf),
           elf_size(elf, elf->ehdr));
    elf_memcpy_safe(elf, hdr + sizeof(unsigned) + elf_size(elf, elf->ehdr),
           ELF_IMAGE_BASE(elf) + elf_uval(elf, elf->ehdr, e_shoff),
           elf_shdr_count(elf) * elf_size(elf, shdr));
    if ( elf_64bit(elf) )
    {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)(hdr + sizeof(unsigned));
        ehdr->e_phoff = 0;
        ehdr->e_phentsize = 0;
        ehdr->e_phnum = 0;
        ehdr->e_shoff = elf_size(elf, elf->ehdr);
        ehdr->e_shstrndx = SHN_UNDEF;
    }
    else
    {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(hdr + sizeof(unsigned));
        ehdr->e_phoff = 0;
        ehdr->e_phentsize = 0;
        ehdr->e_phnum = 0;
        ehdr->e_shoff = elf_size(elf, elf->ehdr);
        ehdr->e_shstrndx = SHN_UNDEF;
    }
    if ( elf->caller_xdest_size < sizeof(unsigned) )
    {
        DOMPRINTF("%s/%s: header size %"PRIx64" too small",
                  __FUNCTION__, load ? "load" : "parse",
                  (uint64_t)elf->caller_xdest_size);
        return -1;
    }
    if ( elf_init(&syms, elf->caller_xdest_base + sizeof(unsigned),
                  elf->caller_xdest_size - sizeof(unsigned)) )
        return -1;

    /*
     * The caller_xdest_{base,size} and dest_{base,size} need to
     * remain valid so long as each struct elf_image does.  The
     * principle we adopt is that these values are set when the
     * memory is allocated or mapped, and cleared when (and if)
     * they are unmapped.
     *
     * Mappings of the guest are normally undone by xc_dom_unmap_all
     * (directly or via xc_dom_release).  We do not explicitly clear
     * these because in fact that happens only at the end of
     * xc_dom_boot_image, at which time all of these ELF loading
     * functions have returned.  No relevant struct elf_binary*
     * escapes this file.
     */

    xc_elf_set_logfile(dom->xch, &syms, 1);

    symtab = dom->bsd_symtab_start + sizeof(unsigned);
    maxaddr = elf_round_up(&syms, symtab + elf_size(&syms, syms.ehdr) +
                           elf_shdr_count(&syms) * elf_size(&syms, shdr));

    DOMPRINTF("%s/%s: bsd_symtab_start=%" PRIx64 ", kernel.end=0x%" PRIx64
              " -- symtab=0x%" PRIx64 ", maxaddr=0x%" PRIx64 "",
              __FUNCTION__, load ? "load" : "parse",
              dom->bsd_symtab_start, dom->kernel_seg.vend,
              symtab, maxaddr);

    count = elf_shdr_count(&syms);
    /* elf_shdr_count guarantees that count is reasonable */

    strtab_referenced = xc_dom_malloc(dom, bitmap_size(count));
    if ( strtab_referenced == NULL )
        return -1;
    bitmap_clear(strtab_referenced, count);
    /* Note the symtabs @h linked to by any strtab @i. */
    for ( i = 0; i < count; i++ )
    {
        shdr2 = elf_shdr_by_index(&syms, i);
        if ( elf_uval(&syms, shdr2, sh_type) == SHT_SYMTAB )
        {
            h = elf_uval(&syms, shdr2, sh_link);
            if (h < count)
                set_bit(h, strtab_referenced);
        }
    }

    for ( h = 0; h < count; h++ )
    {
        shdr = elf_shdr_by_index(&syms, h);
        if ( !elf_access_ok(elf, ELF_HANDLE_PTRVAL(shdr), 1) )
            /* input has an insane section header count field */
            break;
        type = elf_uval(&syms, shdr, sh_type);
        if ( type == SHT_STRTAB )
        {
            /* Skip symtab @h if we found no corresponding strtab @i. */
            if ( !test_bit(h, strtab_referenced) )
            {
                if ( elf_64bit(&syms) )
                    elf_store_field(elf, shdr, e64.sh_offset, 0);
                else
                    elf_store_field(elf, shdr, e32.sh_offset, 0);
                continue;
            }
        }

        if ( (type == SHT_STRTAB) || (type == SHT_SYMTAB) )
        {
            /* Mangled to be based on ELF header location. */
            if ( elf_64bit(&syms) )
                elf_store_field(elf, shdr, e64.sh_offset, maxaddr - symtab);
            else
                elf_store_field(elf, shdr, e32.sh_offset, maxaddr - symtab);
            size = elf_uval(&syms, shdr, sh_size);
            maxaddr = elf_round_up(&syms, maxaddr + size);
            tables++;
            DOMPRINTF("%s: h=%u %s, size=0x%zx, maxaddr=0x%" PRIx64 "",
                      __FUNCTION__, h,
                      type == SHT_SYMTAB ? "symtab" : "strtab",
                      size, maxaddr);

            if ( load )
            {
                shdr2 = elf_shdr_by_index(elf, h);
                elf_memcpy_safe(elf, elf_section_start(&syms, shdr),
                       elf_section_start(elf, shdr2),
                       size);
            }
        }

        /* Name is NULL. */
        if ( elf_64bit(&syms) )
            elf_store_field(elf, shdr, e64.sh_name, 0);
        else
            elf_store_field(elf, shdr, e32.sh_name, 0);
    }

    if ( elf_check_broken(&syms) )
        DOMPRINTF("%s: symbols ELF broken: %s", __FUNCTION__,
                  elf_check_broken(&syms));
    if ( elf_check_broken(elf) )
        DOMPRINTF("%s: ELF broken: %s", __FUNCTION__,
                  elf_check_broken(elf));

    if ( tables == 0 )
    {
        DOMPRINTF("%s: no symbol table present", __FUNCTION__);
        dom->bsd_symtab_start = 0;
        return 0;
    }
    if ( !load )
        dom->kernel_seg.vend = maxaddr;
    return 0;
}

static elf_errorstatus xc_dom_parse_elf_kernel(struct xc_dom_image *dom)
    /*
     * This function sometimes returns -1 for error and sometimes
     * an errno value.  ?!?!
     */
{
    struct elf_binary *elf;
    elf_errorstatus rc;

    rc = check_elf_kernel(dom, 1);
    if ( rc != 0 )
        return rc;

    elf = xc_dom_malloc(dom, sizeof(*elf));
    if ( elf == NULL )
        return -1;
    dom->private_loader = elf;
    rc = elf_init(elf, dom->kernel_blob, dom->kernel_size);
    xc_elf_set_logfile(dom->xch, elf, 1);
    if ( rc != 0 )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL, "%s: corrupted ELF image",
                     __FUNCTION__);
        return rc;
    }

    /* Find the section-header strings table. */
    if ( ELF_PTRVAL_INVALID(elf->sec_strtab) )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL, "%s: ELF image"
                     " has no shstrtab", __FUNCTION__);
        rc = -EINVAL;
        goto out;
    }

    /* parse binary and get xen meta info */
    elf_parse_binary(elf);
    if ( (rc = elf_xen_parse(elf, &dom->parms)) != 0 )
    {
        goto out;
    }

    if ( elf_xen_feature_get(XENFEAT_dom0, dom->parms.f_required) )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL, "%s: Kernel does not"
                     " support unprivileged (DomU) operation", __FUNCTION__);
        rc = -EINVAL;
        goto out;
    }

    /* find kernel segment */
    dom->kernel_seg.vstart = dom->parms.virt_kstart;
    dom->kernel_seg.vend   = dom->parms.virt_kend;

    if ( dom->parms.bsd_symtab )
        xc_dom_load_elf_symtab(dom, elf, 0);

    dom->guest_type = xc_dom_guest_type(dom, elf);
    DOMPRINTF("%s: %s: 0x%" PRIx64 " -> 0x%" PRIx64 "",
              __FUNCTION__, dom->guest_type,
              dom->kernel_seg.vstart, dom->kernel_seg.vend);
    rc = 0;
out:
    if ( elf_check_broken(elf) )
        DOMPRINTF("%s: ELF broken: %s", __FUNCTION__,
                  elf_check_broken(elf));

    return rc;
}

static elf_errorstatus xc_dom_load_elf_kernel(struct xc_dom_image *dom)
{
    struct elf_binary *elf = dom->private_loader;
    elf_errorstatus rc;
    xen_pfn_t pages;

    elf->dest_base = xc_dom_seg_to_ptr_pages(dom, &dom->kernel_seg, &pages);
    if ( elf->dest_base == NULL )
    {
        DOMPRINTF("%s: xc_dom_vaddr_to_ptr(dom,dom->kernel_seg)"
                  " => NULL", __FUNCTION__);
        return -1;
    }
    elf->dest_size = pages * XC_DOM_PAGE_SIZE(dom);

    rc = elf_load_binary(elf);
    if ( rc < 0 )
    {
        DOMPRINTF("%s: failed to load elf binary", __FUNCTION__);
        return rc;
    }
    if ( dom->parms.bsd_symtab )
        xc_dom_load_elf_symtab(dom, elf, 1);
    return 0;
}

/* ------------------------------------------------------------------------ */

struct xc_dom_loader elf_loader = {
    .name = "ELF-generic",
    .probe = xc_dom_probe_elf_kernel,
    .parser = xc_dom_parse_elf_kernel,
    .loader = xc_dom_load_elf_kernel,
};

static void __init register_loader(void)
{
    xc_dom_register_loader(&elf_loader);
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
