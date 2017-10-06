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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
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

    if ( dom->container_type == XC_DOM_HVM_CONTAINER &&
         dom->parms.phys_entry != UNSET_ADDR32 )
        return "hvm-3.0-x86_32";
    if ( dom->container_type == XC_DOM_HVM_CONTAINER )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                     "%s: image not capable of booting inside a HVM container",
                     __FUNCTION__);
        return "xen-3.0-unknown";
    }

    switch ( machine )
    {
    case EM_386:
        switch ( dom->parms.pae )
        {
        case XEN_PAE_BIMODAL:
            if ( strstr(dom->xen_caps, "xen-3.0-x86_32p") )
                return "xen-3.0-x86_32p";
            return "xen-3.0-x86_32";
        case XEN_PAE_EXTCR3:
        case XEN_PAE_YES:
            return "xen-3.0-x86_32p";
        case XEN_PAE_NO:
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
    struct elf_binary elf;
    int rc;

    rc = check_elf_kernel(dom, 0);
    if ( rc != 0 )
        return rc;

    rc = elf_init(&elf, dom->kernel_blob, dom->kernel_size);
    if ( rc != 0 )
        return rc;

    /*
     * We need to check that it contains Xen ELFNOTES,
     * or else we might be trying to load a plain ELF.
     */
    elf_parse_binary(&elf);
    rc = elf_xen_parse(&elf, &dom->parms);
    if ( rc != 0 )
        return rc;

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
