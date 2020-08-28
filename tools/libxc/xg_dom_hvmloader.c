/*
 * Xen domain builder -- HVM specific bits.
 *
 * Parse and load ELF firmware images for HVM domains.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <assert.h>

#include "xg_private.h"
#include "xc_dom.h"
#include "xc_bitops.h"

/* ------------------------------------------------------------------------ */
/* parse elf binary                                                         */

static elf_negerrnoval check_elf_kernel(struct xc_dom_image *dom, bool verbose)
{
    if ( dom->kernel_blob == NULL )
    {
        if ( verbose )
            xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                         "%s: no kernel image loaded", __func__);
        return -EINVAL;
    }

    if ( !elf_is_elfbinary(dom->kernel_blob, dom->kernel_size) )
    {
        if ( verbose )
            xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                         "%s: kernel is not an ELF image", __func__);
        return -EINVAL;
    }
    return 0;
}

static elf_negerrnoval xc_dom_probe_hvm_kernel(struct xc_dom_image *dom)
{
    struct elf_binary elf;
    int rc;

    /* This loader is designed for HVM guest firmware. */
    if ( dom->container_type != XC_DOM_HVM_CONTAINER )
        return -EINVAL;

    rc = check_elf_kernel(dom, 0);
    if ( rc != 0 )
        return rc;

    rc = elf_init(&elf, dom->kernel_blob, dom->kernel_size);
    if ( rc != 0 )
        return rc;

    /*
     * We need to check that there are no Xen ELFNOTES, or
     * else we might be trying to load a PV kernel.
     */
    elf_parse_binary(&elf);
    rc = elf_xen_parse(&elf, &dom->parms);
    if ( rc == 0 )
        return -EINVAL;

    return 0;
}

static elf_errorstatus xc_dom_parse_hvm_kernel(struct xc_dom_image *dom)
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
                     __func__);
        return rc;
    }

    if ( !elf_32bit(elf) )
    {
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL, "%s: ELF image is not 32bit",
                     __func__);
        return -EINVAL;
    }

    /* parse binary and get xen meta info */
    elf_parse_binary(elf);

    /* find kernel segment */
    dom->kernel_seg.vstart = elf->pstart;
    dom->kernel_seg.vend   = elf->pend;

    dom->guest_type = "hvm-3.0-x86_32";

    if ( elf_check_broken(elf) )
        DOMPRINTF("%s: ELF broken: %s", __func__, elf_check_broken(elf));

    return rc;
}

static int module_init_one(struct xc_dom_image *dom,
                           struct xc_hvm_firmware_module *module,
                           char *name)
{
    struct xc_dom_seg seg;
    void *dest;

    if ( module->length && !module->guest_addr_out )
    {
        if ( xc_dom_alloc_segment(dom, &seg, name, 0, module->length) )
            goto err;
        dest = xc_dom_seg_to_ptr(dom, &seg);
        if ( dest == NULL )
        {
            DOMPRINTF("%s: xc_dom_seg_to_ptr(dom, &seg) => NULL",
                      __FUNCTION__);
            goto err;
        }
        memcpy(dest, module->data, module->length);
        module->guest_addr_out = seg.vstart;

        assert(dom->mmio_start > 0 && dom->mmio_start < UINT32_MAX);
        if ( module->guest_addr_out > dom->mmio_start ||
             module->guest_addr_out + module->length > dom->mmio_start )
        {
            DOMPRINTF("%s: Module %s would be loaded abrove 4GB",
                      __FUNCTION__, name);
            goto err;
        }
    }

    return 0;
err:
    return -1;
}

static int modules_init(struct xc_dom_image *dom)
{
    int rc;

    rc = module_init_one(dom, &dom->system_firmware_module,
                         "System Firmware module");
    if ( rc ) goto err;
    /* Only one module can be added */
    rc = module_init_one(dom, &dom->acpi_modules[0], "ACPI module");
    if ( rc ) goto err;
    rc = module_init_one(dom, &dom->smbios_module, "SMBIOS module");
    if ( rc ) goto err;

    return 0;
err:
    return -1;
}

static elf_errorstatus xc_dom_load_hvm_kernel(struct xc_dom_image *dom)
{
    struct elf_binary *elf = dom->private_loader;
    privcmd_mmap_entry_t *entries = NULL;
    size_t pages = (elf->pend - elf->pstart + PAGE_SIZE - 1) >> PAGE_SHIFT;
    elf_errorstatus rc;
    int i;

    /* Map address space for initial elf image. */
    entries = calloc(pages, sizeof(privcmd_mmap_entry_t));
    if ( entries == NULL )
        return -ENOMEM;

    for ( i = 0; i < pages; i++ )
        entries[i].mfn = (elf->pstart >> PAGE_SHIFT) + i;

    elf->dest_base = xc_map_foreign_ranges(
        dom->xch, dom->guest_domid, pages << PAGE_SHIFT,
        PROT_READ | PROT_WRITE, 1 << PAGE_SHIFT,
        entries, pages);
    if ( elf->dest_base == NULL )
    {
        DOMPRINTF("%s: unable to map guest memory space", __func__);
        rc = -EFAULT;
        goto error;
    }

    elf->dest_size = pages * XC_DOM_PAGE_SIZE(dom);

    rc = elf_load_binary(elf);
    if ( rc < 0 )
    {
        DOMPRINTF("%s: failed to load elf binary", __func__);
        goto error;
    }

    munmap(elf->dest_base, elf->dest_size);

    rc = modules_init(dom);
    if ( rc != 0 )
    {
        DOMPRINTF("%s: unable to load modules.", __func__);
        goto error;
    }

    dom->parms.phys_entry = elf_uval(elf, elf->ehdr, e_entry);

    free(entries);
    return 0;

 error:
    assert(rc != 0);
    free(entries);
    return rc;
}

/* ------------------------------------------------------------------------ */

struct xc_dom_loader hvm_loader = {
    .name = "HVM-generic",
    .probe = xc_dom_probe_hvm_kernel,
    .parser = xc_dom_parse_hvm_kernel,
    .loader = xc_dom_load_hvm_kernel,
};

static void __init register_loader(void)
{
    xc_dom_register_loader(&hvm_loader);
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
