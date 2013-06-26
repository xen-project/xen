/*
 * Xen domain builder -- ARM zImage bits
 *
 * Parse and load ARM zImage kernel images.
 *
 * Copyright (C) 2012, Citrix Systems.
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
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom.h"

#include <arpa/inet.h> /* XXX ntohl is not the right function... */

/*
 * Guest virtual RAM starts here. This must be consistent with the DTB
 * appended to the guest kernel.
 */
#define GUEST_RAM_BASE 0x80000000

#define ZIMAGE_MAGIC_OFFSET 0x24
#define ZIMAGE_START_OFFSET 0x28
#define ZIMAGE_END_OFFSET   0x2c

#define ZIMAGE_MAGIC 0x016f2818

struct minimal_dtb_header {
    uint32_t magic;
    uint32_t total_size;
    /* There are other fields but we don't use them yet. */
};

#define DTB_MAGIC 0xd00dfeed

static int xc_dom_probe_zimage_kernel(struct xc_dom_image *dom)
{
    uint32_t *zimage;
    uint32_t end;

    if ( dom->kernel_blob == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: no kernel image loaded", __FUNCTION__);
        return -EINVAL;
    }

    if ( dom->kernel_size < 0x30 /*sizeof(struct setup_header)*/ )
    {
        xc_dom_printf(dom->xch, "%s: kernel image too small", __FUNCTION__);
        return -EINVAL;
    }

    zimage = (uint32_t *)dom->kernel_blob;
    if ( zimage[ZIMAGE_MAGIC_OFFSET/4] != ZIMAGE_MAGIC )
    {
        xc_dom_printf(dom->xch, "%s: kernel is not a bzImage", __FUNCTION__);
        return -EINVAL;
    }

    end = zimage[ZIMAGE_END_OFFSET/4];

    /*
     * Check for an appended DTB.
     */
    if ( end + sizeof(struct minimal_dtb_header) < dom->kernel_size ) {
        struct minimal_dtb_header *dtb_hdr;
        dtb_hdr = (struct minimal_dtb_header *)(dom->kernel_blob + end);
        if (ntohl/*be32_to_cpu*/(dtb_hdr->magic) == DTB_MAGIC) {
            xc_dom_printf(dom->xch, "%s: found an appended DTB", __FUNCTION__);
            end += ntohl/*be32_to_cpu*/(dtb_hdr->total_size);
        }
    }

    dom->kernel_size = end;

    return 0;
}

static int xc_dom_parse_zimage_kernel(struct xc_dom_image *dom)
{
    uint32_t *zimage;
    uint32_t start, entry_addr;
    uint64_t v_start, v_end;
    uint64_t rambase = GUEST_RAM_BASE;

    DOMPRINTF_CALLED(dom->xch);

    zimage = (uint32_t *)dom->kernel_blob;

    dom->rambase_pfn = rambase >> XC_PAGE_SHIFT;

    /* Do not load kernel at the very first RAM address */
    v_start = rambase + 0x8000;
    v_end = v_start + dom->kernel_size;

    start = zimage[ZIMAGE_START_OFFSET/4];

    if (start == 0)
        entry_addr = v_start;
    else
        entry_addr = start;

    /* find kernel segment */
    dom->kernel_seg.vstart = v_start;
    dom->kernel_seg.vend   = v_end;

    dom->parms.virt_entry = entry_addr;
    dom->parms.virt_base = rambase;

    dom->guest_type = "xen-3.0-armv7l";
    DOMPRINTF("%s: %s: RAM starts at %"PRI_xen_pfn,
              __FUNCTION__, dom->guest_type, dom->rambase_pfn);
    DOMPRINTF("%s: %s: 0x%" PRIx64 " -> 0x%" PRIx64 "",
              __FUNCTION__, dom->guest_type,
              dom->kernel_seg.vstart, dom->kernel_seg.vend);
    return 0;
}

static int xc_dom_load_zimage_kernel(struct xc_dom_image *dom)
{
    void *dst;

    DOMPRINTF_CALLED(dom->xch);

    dst = xc_dom_seg_to_ptr(dom, &dom->kernel_seg);
    if ( dst == NULL )
    {
        DOMPRINTF("%s: xc_dom_seg_to_ptr(dom, &dom->kernel_seg) => NULL",
                  __func__);
        return -1;
    }

    DOMPRINTF("%s: kernel sed %#"PRIx64"-%#"PRIx64,
              __func__, dom->kernel_seg.vstart, dom->kernel_seg.vend);
    DOMPRINTF("%s: copy %zd bytes from blob %p to dst %p",
              __func__, dom->kernel_size, dom->kernel_blob, dst);

    memcpy(dst, dom->kernel_blob, dom->kernel_size);

    return 0;
}

static struct xc_dom_loader zimage_loader = {
    .name = "Linux zImage (ARM)",
    .probe = xc_dom_probe_zimage_kernel,
    .parser = xc_dom_parse_zimage_kernel,
    .loader = xc_dom_load_zimage_kernel,
};

static void __init register_loader(void)
{
    xc_dom_register_loader(&zimage_loader);
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
